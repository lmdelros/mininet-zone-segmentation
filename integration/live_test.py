#!/usr/bin/env python3
"""Live end-to-end test: real packets through Mininet, POX, and the daemon.

The pytest suite (tests/) proves firewall_rules.py matches the README
policy table and that the C++ daemon matches firewall_rules.py. This
script proves the last link: that the running controller actually
enforces that policy on real traffic, routes what it allows, and drops
spoofed packets.

Needs root and a running POX controller (with controller.py) on
127.0.0.1:6633. Easiest via Docker, which sets all of that up:

    docker build -t zone-seg-live docker/
    docker run --rm --privileged -v "$PWD:/src:ro" zone-seg-live

Expected verdicts come from firewall_rules.firewall_allowed(), checked
in BOTH directions: the firewall is stateless, so a ping or TCP
handshake only succeeds if the reply direction is allowed too (e.g.
Dept B -> Trust ICMP is allowed, but the echo reply Trust -> Dept B is
blocked by rule 4, so Dept B can't ping Trust).
"""

import argparse
import functools
import os
import re
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from mininet.log import setLogLevel  # noqa: E402
from mininet.node import OVSSwitch  # noqa: E402

from firewall_rules import ZONES, firewall_allowed, zone_for_ip  # noqa: E402
from topology import build_network  # noqa: E402

# One representative host per zone for the cross-zone matrix.
ZONE_HOSTS = {
    'DeptA': 'h101',
    'DeptB': 'h201',
    'DataCenter': 'h_server',
    'Trust': 'h_trust',
    'Untrust': 'h_untrust',
}

# Same-zone pairs: same leaf switch, and across two leaves via the core.
SAME_ZONE_PAIRS = [('h101', 'h102'), ('h101', 'h103'), ('h201', 'h204')]

TCP_PORT = 5001

SEND_ARP = r'''
import socket, struct, sys
intf, mac, sender_ip, target_ip = sys.argv[1:5]
m = bytes.fromhex(mac.replace(':', ''))
frame = (b'\xff' * 6 + m + b'\x08\x06'
         + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)  # Ethernet/IPv4, request
         + m + socket.inet_aton(sender_ip)
         + b'\x00' * 6 + socket.inet_aton(target_ip))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((intf, 0))
for _ in range(3):
    s.send(frame)
'''


class Results(object):
    def __init__(self):
        self.failures = 0

    def check(self, ok, label, detail=''):
        print('  [{}] {}{}'.format('PASS' if ok else 'FAIL', label,
                                   '  ({})'.format(detail) if detail else ''))
        if not ok:
            self.failures += 1
        return ok


# -- traffic helpers -----------------------------------------------------

def ping_ok(src, dst_ip):
    out = src.cmd('ping -c 3 -i 0.2 -W 1 {}'.format(dst_ip))
    m = re.search(r'(\d+) received', out)
    return bool(m) and int(m.group(1)) > 0


def tcp_ok(src, dst_ip):
    out = src.cmd('nc -z -w 2 {} {}; echo "rc=$?"'.format(dst_ip, TCP_PORT))
    return 'rc=0' in out


def expected(src, dst, is_icmp):
    a, b = zone_for_ip(src.IP()), zone_for_ip(dst.IP())
    return firewall_allowed(a, b, is_icmp) and firewall_allowed(b, a, is_icmp)


class Capture(object):
    """tcpdump on a host's interface, counting packets matching a filter."""

    def __init__(self, host, bpf):
        self.host = host
        self.path = '/tmp/capture_{}_{}.txt'.format(host.name, id(self))
        host.cmd('tcpdump -l -n -i {} "{}" > {} 2>/dev/null &'.format(
            host.defaultIntf(), bpf, self.path))
        self.pid = host.cmd('echo $!').strip()
        time.sleep(1)  # let tcpdump attach before traffic starts

    def stop(self):
        time.sleep(0.5)
        self.host.cmd('kill {}; wait {} 2>/dev/null'.format(self.pid, self.pid))
        out = self.host.cmd('cat {}; rm -f {}'.format(self.path, self.path))
        return len([line for line in out.splitlines() if line.strip()])


# -- test sections -------------------------------------------------------

def test_policy_matrix(net, results):
    print('\n*** Zone policy matrix (ping = ICMP, tcp = TCP connect)')
    matrix = {}
    for src_zone, src_name in ZONE_HOSTS.items():
        for dst_zone, dst_name in ZONE_HOSTS.items():
            if src_zone == dst_zone:
                continue
            src, dst = net[src_name], net[dst_name]
            cell = []
            for proto, is_icmp, probe in [('ping', True, ping_ok),
                                          ('tcp', False, tcp_ok)]:
                want = expected(src, dst, is_icmp)
                got = probe(src, dst.IP())
                results.check(got == want,
                              '{:9s} -> {:9s} {:4s} {}'.format(
                                  src_name, dst_name, proto,
                                  'allowed' if got else 'blocked'),
                              '' if got == want else 'expected {}'.format(
                                  'allowed' if want else 'blocked'))
                cell.append(('ok' if got else '--') + ('' if got == want else '!'))
            matrix[src_zone, dst_zone] = ' / '.join(cell)
    return matrix


def test_same_zone(net, results):
    print('\n*** Same-zone delivery (L2, same leaf and across leaves)')
    for a, b in SAME_ZONE_PAIRS:
        results.check(ping_ok(net[a], net[b].IP()), '{} -> {} ping'.format(a, b))
        results.check(tcp_ok(net[a], net[b].IP()), '{} -> {} tcp'.format(a, b))


def test_ip_spoofing(net, results):
    """h_untrust forges a Trust source IP to dodge rule 2: Trust may ping
    Dept A, Untrust may not."""
    print('\n*** IP spoofing: h_untrust forges a Trust source IP toward h101')
    attacker, victim, honest = net['h_untrust'], net['h101'], net['h_trust']
    spoofed = str(ZONES['Trust']['subnet'].network_address + 50)
    intf = attacker.defaultIntf()

    # Positive control: the capture really does see allowed Trust traffic.
    cap = Capture(victim, 'icmp and src host {}'.format(honest.IP()))
    honest.cmd('ping -c 2 -W 1 {}'.format(victim.IP()))
    results.check(cap.stop() > 0, 'control: honest Trust ping reaches h101')

    # Static neighbor entry for the gateway, so the attacker's kernel
    # never needs to ARP (which would carry the spoofed IP and be dropped
    # for a different reason, making the test pass vacuously).
    gw = ZONES['Untrust']
    attacker.cmd('ip addr add {}/32 dev {}'.format(spoofed, intf))
    attacker.cmd('ip neigh replace {} lladdr {} dev {} nud permanent'.format(
        gw['gateway'], gw['gateway_mac'], intf))

    sent = Capture(attacker, 'icmp and src host {}'.format(spoofed))
    recv = Capture(victim, 'icmp and src host {}'.format(spoofed))
    attacker.cmd('ping -c 3 -W 1 -I {} {}'.format(spoofed, victim.IP()))
    n_recv, n_sent = recv.stop(), sent.stop()

    attacker.cmd('ip addr del {}/32 dev {}'.format(spoofed, intf))
    results.check(n_sent > 0, 'attacker emitted spoofed packets', '{} sent'.format(n_sent))
    results.check(n_recv == 0, 'none reached h101', '{} received'.format(n_recv))


def test_arp_spoofing(net, results, pox_log):
    """h101 ARPs for its gateway claiming h_server's IP. Without
    anti-spoofing the controller would record h_server as living behind
    s1 and send the server's traffic to the attacker."""
    print("\n*** ARP spoofing: h101 claims h_server's IP")
    attacker, server, client = net['h101'], net['h_server'], net['h201']
    results.check(ping_ok(client, server.IP()), 'before: h201 reaches h_server')

    script = '/tmp/send_arp.py'
    attacker.cmd("cat > {} <<'EOF'\n{}\nEOF".format(script, SEND_ARP))
    attacker.cmd('python3 {} {} {} {} {}'.format(
        script, attacker.defaultIntf(), attacker.MAC(), server.IP(),
        ZONES['DeptA']['gateway']))
    time.sleep(0.5)

    results.check(ping_ok(client, server.IP()),
                  'after: h201 still reaches the real h_server')
    if os.path.exists(pox_log):
        with open(pox_log) as f:
            logged = 'DROP spoofed ARP' in f.read()
        results.check(logged, 'controller logged the spoofed ARP drop')


# -- main ----------------------------------------------------------------

def print_matrix(matrix):
    zones = list(ZONE_HOSTS)
    print('\n*** Reachability matrix (row = source, column = destination;'
          ' ping / tcp; "!" = differs from policy)\n')
    print('| src \\ dst | ' + ' | '.join(zones) + ' |')
    print('|---|' + '---|' * len(zones))
    for s in zones:
        cells = ['same zone' if s == d else matrix[s, d] for d in zones]
        print('| {} | {} |'.format(s, ' | '.join(cells)))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--datapath', choices=['kernel', 'user'], default='kernel',
                        help="OVS datapath; 'user' needs no OVS kernel module")
    parser.add_argument('--pox-log', default='/tmp/pox.log',
                        help='POX log file to check for spoof-drop entries')
    args = parser.parse_args()

    setLogLevel('warning')
    net = build_network(switch=functools.partial(OVSSwitch, datapath=args.datapath))
    net.build()
    net.start()
    results = Results()
    try:
        if not net.waitConnected(timeout=20):
            print('Switches never connected to the controller -- is POX running?')
            return 1
        for host in net.hosts:
            if args.datapath == 'user':
                # veth leaves TCP checksums for "hardware" to fill in.
                # The kernel datapath handles that; OVS's userspace
                # datapath doesn't, so L2-forwarded TCP arrives with a
                # bad checksum and is dropped. (Routed packets survive
                # only because POX re-packs them.) Have the hosts'
                # kernels compute checksums themselves.
                host.cmd('ethtool -K {} tx off >/dev/null 2>&1'.format(
                    host.defaultIntf()))
            host.cmd('nc -lk {} >/dev/null 2>&1 &'.format(TCP_PORT))

        matrix = test_policy_matrix(net, results)
        test_same_zone(net, results)
        test_ip_spoofing(net, results)
        test_arp_spoofing(net, results, args.pox_log)
        print_matrix(matrix)
    finally:
        net.stop()

    print('\n*** {}'.format('ALL CHECKS PASSED' if results.failures == 0
                            else '{} CHECK(S) FAILED'.format(results.failures)))
    return 0 if results.failures == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
