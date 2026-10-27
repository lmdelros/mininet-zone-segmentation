#!/usr/bin/env python3
"""Throughput and latency of routed vs. same-zone traffic.

Compares two paths that each cross three switches:

  - routed:    h201 -> h_server (Dept B -> Data Center, allowed). Every
               packet goes to the controller, which checks the firewall
               and sends the packet back out (no flow rules today).
  - same zone: h101 -> h103 (Dept A, across the core). The switches
               forward these at layer 2 using flow rules the controller
               installed, so after the first packet the controller is
               out of the loop.

The gap between the two shows what sending every routed packet through
the controller costs. Absolute numbers depend on the machine and on the
OVS datapath (userspace in Docker), so compare paths within one run.

Needs root and a running POX controller. Easiest via Docker:

    docker build -t zone-seg-live docker/
    docker run --rm --privileged -v "$PWD:/src:ro" \
        -e TEST_SCRIPT=perf_test.py zone-seg-live
"""

import argparse
import functools
import json
import os
import re
import statistics
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from mininet.log import setLogLevel  # noqa: E402
from mininet.node import OVSSwitch  # noqa: E402

from topology import build_network  # noqa: E402

PATHS = [
    ('routed (Dept B -> Data Center)', 'h201', 'h_server'),
    ('same zone (Dept A, across core)', 'h101', 'h103'),
]


def iperf_mbps(client, server_ip, seconds):
    out = client.cmd('iperf3 -c {} -t {} -J'.format(server_ip, seconds))
    try:
        result = json.loads(out)
    except ValueError:
        return None, 'unparseable iperf3 output: {!r}'.format(out[-200:])
    if 'error' in result:
        return None, result['error']
    return result['end']['sum_received']['bits_per_second'] / 1e6, None


def ping_rtt(client, server_ip, count):
    out = client.cmd('ping -q -c {} -i 0.2 {}'.format(count, server_ip))
    m = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/', out)
    loss = re.search(r'([\d.]+)% packet loss', out)
    if not m:
        return None
    return {'min': float(m.group(1)), 'avg': float(m.group(2)),
            'max': float(m.group(3)), 'loss': loss.group(1) if loss else '?'}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--datapath', choices=['kernel', 'user'], default='kernel')
    parser.add_argument('--duration', type=int, default=10,
                        help='seconds per iperf3 run (default 10)')
    parser.add_argument('--runs', type=int, default=3,
                        help='iperf3 runs per path (default 3)')
    parser.add_argument('--pings', type=int, default=20,
                        help='pings per path for latency (default 20)')
    args = parser.parse_args()

    setLogLevel('warning')
    net = build_network(switch=functools.partial(OVSSwitch, datapath=args.datapath))
    net.build()
    net.start()
    try:
        if not net.waitConnected(timeout=20):
            print('Switches never connected to the controller -- is POX running?')
            return 1
        for host in net.hosts:
            if args.datapath == 'user':
                # Same reason as live_test.py: the userspace datapath
                # leaves TCP checksums unfilled for L2-forwarded traffic.
                host.cmd('ethtool -K {} tx off >/dev/null 2>&1'.format(host.defaultIntf()))

        rows = []
        for label, src_name, dst_name in PATHS:
            src, dst = net[src_name], net[dst_name]
            dst.cmd('iperf3 -s -D')
            # Warm up: let the controller learn both hosts' locations so
            # the measurements don't include first-contact ARP handling.
            src.cmd('ping -c 2 -W 1 {}'.format(dst.IP()))

            print('\n*** {}: {} -> {}'.format(label, src_name, dst_name))
            rtt = ping_rtt(src, dst.IP(), args.pings)
            print('  ping: {}'.format(
                'min/avg/max = {min:.3f}/{avg:.3f}/{max:.3f} ms, {loss}% loss'.format(**rtt)
                if rtt else 'no replies'))

            speeds = []
            for i in range(args.runs):
                mbps, err = iperf_mbps(src, dst.IP(), args.duration)
                print('  iperf3 run {}: {}'.format(
                    i + 1, '{:.2f} Mbit/s'.format(mbps) if err is None else 'ERROR ' + err))
                if err is None:
                    speeds.append(mbps)
            rows.append((label, speeds, rtt))
            dst.cmd('pkill -f "iperf3 -s"')

        print('\n*** Summary ({}s x {} iperf3 runs, {} pings per path)\n'.format(
            args.duration, args.runs, args.pings))
        print('| Path | Throughput (median) | Throughput (runs) | Ping avg (min-max) |')
        print('|---|---|---|---|')
        for label, speeds, rtt in rows:
            median = '{:.2f} Mbit/s'.format(statistics.median(speeds)) if speeds else 'n/a'
            runs = ', '.join('{:.1f}'.format(s) for s in speeds) or 'n/a'
            ping = ('{avg:.3f} ms ({min:.3f}-{max:.3f})'.format(**rtt) if rtt else 'n/a')
            print('| {} | {} | {} | {} |'.format(label, median, runs, ping))
    finally:
        net.stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
