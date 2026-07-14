#!/usr/bin/env python3
"""POX controller: router + firewall for the zone-segmentation network.

Topology recap (see topology.py): switches s1-s5 each serve exactly one
zone/subnet (s1+s2 = Dept A, s3+s4 = Dept B, s5 = Data Center), so they
never need to make a routing decision -- every port on those switches is
the same zone, and they behave as plain learning switches. s6 (the core)
is the only switch that touches more than one zone (both floor pairs,
the data center, and the two external hosts wired straight to it), so
it's the only place a packet's source zone and destination zone can ever
differ. That's where this controller does its work: it owns the virtual
gateway IP for every zone (answering ARP on their behalf, since no real
host holds those addresses), enforces the 8 firewall rules below when a
packet crosses a zone boundary, and otherwise routes it -- decrementing
TTL and rewriting MACs like a real router hop.

Firewall policy (src zone -> dst zone):
    1. Untrust  -> Data Center : block ALL IP
    2. Untrust  -> Dept A/B/DC : block ICMP
    3. Trust    -> Data Center : block ALL IP
    4. Trust    -> Dept B      : block ICMP
    5. Trust    -> Dept A      : allowed, unrestricted
    6. Dept A  <-> Dept B      : block ICMP both directions
    7. non-IP traffic (e.g. ARP): flood within the source zone
    8. everything else: forward

Note: this uses ipv4.ICMP_PROTOCOL from POX's own packet library rather
than a hand-rolled constant, which sidesteps the classic
"ICMP_PROTOCOL vs CMP_PROTOCOL" typo bug from the original coursework
version of this project.

Host discovery: a host's IP/MAC/location is learned the moment it ARPs
for its zone's gateway (which every host must do before its first
cross-zone packet), so by the time a routed packet needs to reach it,
the core switch already knows which port it's behind. The exception is
a host that receives inbound traffic before ever transmitting anything
(e.g. an unsolicited connection to h_server) -- for that case the router
actively ARPs into the destination zone, queues the pending packet, and
retries a few times before giving up.
"""

import ipaddress

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
from pox.lib.recoco import Timer

log = core.getLogger()

# ---------------------------------------------------------------------------
# Static network configuration, derived from topology.py
# ---------------------------------------------------------------------------

CORE_DPID = 6

ZONES = {
    'DeptA': {
        'subnet': ipaddress.ip_network('10.1.1.0/24'),
        'gateway': '10.1.1.1',
        'gateway_mac': '02:00:00:00:00:01',
    },
    'DeptB': {
        'subnet': ipaddress.ip_network('10.1.2.0/24'),
        'gateway': '10.1.2.1',
        'gateway_mac': '02:00:00:00:00:02',
    },
    'DataCenter': {
        'subnet': ipaddress.ip_network('10.1.3.0/24'),
        'gateway': '10.1.3.1',
        'gateway_mac': '02:00:00:00:00:03',
    },
    'Trust': {
        'subnet': ipaddress.ip_network('192.47.38.0/24'),
        'gateway': '192.47.38.1',
        'gateway_mac': '02:00:00:00:00:04',
    },
    'Untrust': {
        'subnet': ipaddress.ip_network('108.35.24.0/24'),
        'gateway': '108.35.24.1',
        'gateway_mac': '02:00:00:00:00:05',
    },
}

# Leaf switches (dpid 1-5): every port belongs to the same zone.
SWITCH_ZONE = {
    1: 'DeptA', 2: 'DeptA',
    3: 'DeptB', 4: 'DeptB',
    5: 'DataCenter',
}

# Core switch (dpid 6): zone depends on which port, per the link order in
# topology.py (addLink order -> port number): s1, s2, s3, s4, s5,
# h_trust, h_untrust.
CORE_PORT_ZONES = {
    1: 'DeptA', 2: 'DeptA',
    3: 'DeptB', 4: 'DeptB',
    5: 'DataCenter',
    6: 'Trust',
    7: 'Untrust',
}

# Inverse of the above, for scoped intra-zone flooding at the core.
ZONE_CORE_PORTS = {}
for _port, _zone in CORE_PORT_ZONES.items():
    ZONE_CORE_PORTS.setdefault(_zone, []).append(_port)

BLOCK_ALL_IP = {
    ('Untrust', 'DataCenter'),
    ('Trust', 'DataCenter'),
}

BLOCK_ICMP = {
    ('Untrust', 'DeptA'),
    ('Untrust', 'DeptB'),
    ('Untrust', 'DataCenter'),
    ('Trust', 'DeptB'),
    ('DeptA', 'DeptB'),
    ('DeptB', 'DeptA'),
}

ARP_RETRY_INTERVAL = 1  # seconds
ARP_MAX_RETRIES = 3

ICMP_DEST_UNREACH = 3
ICMP_CODE_HOST_UNREACH = 1
ICMP_TIME_EXCEEDED = 11
ICMP_CODE_TTL_EXCEEDED = 0


def zone_of_port(dpid, port):
    if dpid == CORE_DPID:
        return CORE_PORT_ZONES.get(port)
    return SWITCH_ZONE.get(dpid)


def zone_for_ip(ip):
    addr = ipaddress.ip_address(str(ip))
    for name, zone in ZONES.items():
        if addr in zone['subnet']:
            return name
    return None


def firewall_allowed(src_zone, dst_zone, is_icmp):
    if (src_zone, dst_zone) in BLOCK_ALL_IP:
        return False
    if is_icmp and (src_zone, dst_zone) in BLOCK_ICMP:
        return False
    return True


class ZoneRouter(object):

    def __init__(self):
        self.connections = {}          # dpid -> Connection
        self.mac_table = {}            # dpid -> {mac: port}
        self.ip_to_loc = {}            # ip -> (dpid, port, mac, zone)
        self.pending = {}              # ip -> {zone, queue, retries, timer}
        core.openflow.addListeners(self)
        log.info("Zone-segmentation router/firewall started")

    # -- connection bookkeeping ------------------------------------------

    def _handle_ConnectionUp(self, event):
        self.connections[event.dpid] = event.connection
        self.mac_table.setdefault(event.dpid, {})
        log.info("Switch dpid=%s connected", event.dpid)

    # -- packet-in dispatch ------------------------------------------------

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        dpid = event.dpid
        in_port = event.port

        if packet.type == ethernet.LLDP_TYPE:
            return
        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event, packet, dpid, in_port)
        elif packet.type == ethernet.IP_TYPE:
            self._handle_ip(event, packet, dpid, in_port)
        else:
            # Rule 7: flood any other non-IP traffic within the source zone.
            self._flood_in_zone(event, dpid, in_port)

    # -- ARP handling --------------------------------------------------

    def _handle_arp(self, event, packet, dpid, in_port):
        arp_pkt = packet.next
        src_zone = zone_of_port(dpid, in_port)
        if src_zone is None:
            return

        is_gateway_target = any(str(arp_pkt.protodst) == z['gateway']
                                 for z in ZONES.values())

        if arp_pkt.opcode == arp.REQUEST and is_gateway_target:
            # Every host ARPs for its gateway before its first cross-zone
            # packet -- this is how we learn most hosts' locations.
            self._learn(dpid, in_port, arp_pkt.protosrc, arp_pkt.hwsrc, src_zone)
            gw_mac = ZONES[src_zone]['gateway_mac']
            self._send_arp_reply(event.connection, in_port,
                                  sender_ip=arp_pkt.protodst, sender_mac=gw_mac,
                                  target_ip=arp_pkt.protosrc, target_mac=arp_pkt.hwsrc)
            return

        if arp_pkt.opcode == arp.REPLY and is_gateway_target:
            # A reply to a probe the router itself sent while resolving a route.
            self._learn(dpid, in_port, arp_pkt.protosrc, arp_pkt.hwsrc, src_zone)
            self._resolve_pending(arp_pkt.protosrc, arp_pkt.hwsrc)
            return

        # Ordinary intra-zone ARP between two real hosts.
        self._learn(dpid, in_port, arp_pkt.protosrc, arp_pkt.hwsrc, src_zone)
        self._flood_in_zone(event, dpid, in_port)

    def _send_arp_reply(self, connection, out_port, sender_ip, sender_mac,
                         target_ip, target_mac):
        reply = arp()
        reply.opcode = arp.REPLY
        reply.hwsrc = sender_mac
        reply.hwdst = target_mac
        reply.protosrc = sender_ip
        reply.protodst = target_ip
        eth = ethernet(type=ethernet.ARP_TYPE, src=sender_mac, dst=target_mac)
        eth.payload = reply
        self._packet_out(connection, eth, out_port)

    def _send_arp_probe(self, dst_ip, dst_zone):
        connection = self.connections.get(CORE_DPID)
        if connection is None:
            return
        gw = ZONES[dst_zone]
        req = arp()
        req.opcode = arp.REQUEST
        req.hwsrc = gw['gateway_mac']
        req.hwdst = ETHER_BROADCAST
        req.protosrc = gw['gateway']
        req.protodst = dst_ip
        eth = ethernet(type=ethernet.ARP_TYPE, src=gw['gateway_mac'], dst=ETHER_BROADCAST)
        eth.payload = req
        for port in ZONE_CORE_PORTS.get(dst_zone, []):
            self._packet_out(connection, eth, port)

    # -- IP handling ------------------------------------------------------

    def _handle_ip(self, event, packet, dpid, in_port):
        ip_pkt = packet.next
        src_zone = zone_of_port(dpid, in_port)
        if src_zone is None:
            return

        self._learn(dpid, in_port, ip_pkt.srcip, packet.src, src_zone)

        if any(str(ip_pkt.dstip) == z['gateway'] for z in ZONES.values()):
            return  # addressed to a virtual gateway; no real host to deliver to

        dst_zone = zone_for_ip(ip_pkt.dstip)
        if dst_zone is None:
            return  # destination outside every known zone

        is_icmp = ip_pkt.protocol == ipv4.ICMP_PROTOCOL

        if dst_zone == src_zone:
            # Same subnet: plain L2 delivery, no firewall/routing involved.
            self._l2_forward(event, dpid, in_port, packet.dst)
            return

        if not firewall_allowed(src_zone, dst_zone, is_icmp):
            log.info("DROP %s -> %s (%s): %s -> %s", src_zone, dst_zone,
                      "ICMP" if is_icmp else "IP", ip_pkt.srcip, ip_pkt.dstip)
            return

        self._route(event, packet, ip_pkt, dst_zone)

    def _route(self, event, packet, ip_pkt, dst_zone):
        loc = self.ip_to_loc.get(ip_pkt.dstip)
        if loc is not None and loc[0] == CORE_DPID:
            _, out_port, dst_mac, _zone = loc
            self._forward_ip(event.dpid, event.port, dst_zone, packet, ip_pkt,
                              out_port, dst_mac)
        else:
            self._queue_and_resolve(event.dpid, event.port, packet, ip_pkt, dst_zone)

    def _forward_ip(self, orig_dpid, orig_port, dst_zone, packet, ip_pkt,
                     out_port, dst_mac):
        if ip_pkt.ttl <= 1:
            self._send_icmp_error(packet, ip_pkt, orig_dpid, orig_port,
                                   ICMP_TIME_EXCEEDED, ICMP_CODE_TTL_EXCEEDED)
            return
        connection = self.connections.get(CORE_DPID)
        if connection is None:
            return
        ip_pkt.ttl -= 1
        gw_mac = ZONES[dst_zone]['gateway_mac']
        eth = ethernet(type=ethernet.IP_TYPE, src=gw_mac, dst=dst_mac)
        eth.payload = ip_pkt
        self._packet_out(connection, eth, out_port)

    # -- pending-packet queue / ARP resolution -----------------------------

    def _queue_and_resolve(self, orig_dpid, orig_port, packet, ip_pkt, dst_zone):
        dst_ip = ip_pkt.dstip
        entry = self.pending.get(dst_ip)
        if entry is None:
            entry = {'zone': dst_zone, 'queue': [], 'retries': 1, 'timer': None}
            self.pending[dst_ip] = entry
            self._send_arp_probe(dst_ip, dst_zone)
            entry['timer'] = Timer(ARP_RETRY_INTERVAL, self._retry_arp,
                                    args=[dst_ip], recurring=True)
        entry['queue'].append((orig_dpid, orig_port, packet, ip_pkt))

    def _retry_arp(self, dst_ip):
        entry = self.pending.get(dst_ip)
        if entry is None:
            return
        if entry['retries'] >= ARP_MAX_RETRIES:
            entry['timer'].cancel()
            del self.pending[dst_ip]
            for (orig_dpid, orig_port, packet, ip_pkt) in entry['queue']:
                self._send_icmp_error(packet, ip_pkt, orig_dpid, orig_port,
                                       ICMP_DEST_UNREACH, ICMP_CODE_HOST_UNREACH)
            return
        self._send_arp_probe(dst_ip, entry['zone'])
        entry['retries'] += 1

    def _resolve_pending(self, ip, mac):
        entry = self.pending.pop(ip, None)
        if entry is None:
            return
        if entry['timer']:
            entry['timer'].cancel()
        out_port = self.ip_to_loc[ip][1]
        for (orig_dpid, orig_port, packet, ip_pkt) in entry['queue']:
            self._forward_ip(orig_dpid, orig_port, entry['zone'], packet, ip_pkt,
                              out_port, mac)

    # -- ICMP error generation --------------------------------------------

    def _send_icmp_error(self, packet, ip_pkt, orig_dpid, orig_port,
                          icmp_type, icmp_code):
        connection = self.connections.get(orig_dpid)
        if connection is None:
            return
        src_zone = zone_of_port(orig_dpid, orig_port)
        if src_zone is None:
            return
        gw = ZONES[src_zone]

        err = icmp()
        err.type = icmp_type
        err.code = icmp_code
        # RFC 792: original IP header + first 8 bytes of its payload.
        err.payload = ip_pkt.pack()[:28]

        reply_ip = ipv4()
        reply_ip.protocol = ipv4.ICMP_PROTOCOL
        reply_ip.srcip = gw['gateway']
        reply_ip.dstip = ip_pkt.srcip
        reply_ip.payload = err

        eth = ethernet(type=ethernet.IP_TYPE, src=gw['gateway_mac'], dst=packet.src)
        eth.payload = reply_ip
        self._packet_out(connection, eth, orig_port)

    # -- plain L2 forwarding (leaf switches, and intra-zone at the core) --

    def _learn(self, dpid, port, ip, mac, zone):
        self.mac_table.setdefault(dpid, {})[mac] = port
        self.ip_to_loc[ip] = (dpid, port, mac, zone)

    def _l2_forward(self, event, dpid, in_port, dst_mac):
        out_port = self.mac_table.get(dpid, {}).get(dst_mac)
        if out_port is None:
            self._flood_in_zone(event, dpid, in_port)
            return
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(event.parsed, in_port)
        msg.idle_timeout = 30
        msg.hard_timeout = 60
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.data = event.ofp
        event.connection.send(msg)

    def _flood_in_zone(self, event, dpid, in_port):
        if dpid == CORE_DPID:
            zone = CORE_PORT_ZONES.get(in_port)
            for port in ZONE_CORE_PORTS.get(zone, []):
                if port == in_port:
                    continue
                self._packet_out_data(event.connection, event.data, port)
        else:
            # Every port on a leaf switch is the same zone, so a plain
            # OFPP_FLOOD is already correctly scoped.
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)

    # -- low-level packet_out helpers --------------------------------------

    def _packet_out(self, connection, eth_packet, out_port):
        msg = of.ofp_packet_out()
        msg.data = eth_packet.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        connection.send(msg)

    def _packet_out_data(self, connection, data, out_port):
        msg = of.ofp_packet_out()
        msg.data = data
        msg.actions.append(of.ofp_action_output(port=out_port))
        connection.send(msg)


def launch():
    core.registerNew(ZoneRouter)
