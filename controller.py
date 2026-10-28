#!/usr/bin/env python3
"""POX controller: router + firewall for the zone-segmentation network.

Topology recap (see topology.py): switches s1-s5 each serve exactly one
zone/subnet (s1+s2 = Dept A, s3+s4 = Dept B, s5 = Data Center), and s6
(the core) connects them plus the two external hosts. The controller
owns the virtual gateway IP for every zone (answering ARP on their
behalf, since no real host holds those addresses). When a host sends a
packet to its gateway, the controller sees it as a packet-in on the
host's own switch, enforces the 8 firewall rules below, and routes it
-- decrementing TTL and rewriting MACs like a real router hop -- by
injecting it at the core switch out the port toward the destination.

Leaf uplinks: a packet arriving on a leaf switch's port to the core was
put there by the controller (a routed packet or an ARP probe) or by the
core's own intra-zone L2 forwarding, so it has already been firewalled
and spoof-checked at its real ingress. Those packets are delivered as
plain L2 transit, without re-running the zone checks or learning host
locations from them (see _handle_transit).

Firewall policy (src zone -> dst zone):
    1. Untrust  -> Data Center : block ALL IP
    2. Untrust  -> Dept A/B/DC : block ICMP
    3. Trust    -> Data Center : block ALL IP
    4. Trust    -> Dept B      : block ICMP
    5. Trust    -> Dept A      : allowed, unrestricted
    6. Dept A  <-> Dept B      : block ICMP both directions
    7. Data Center -> Trust/Untrust : block ALL IP
    8. non-IP traffic (e.g. ARP): flood within the source zone
    9. everything else: forward

The firewall is stateful: the rules above decide who may *start* a
connection, and conntrack.py remembers allowed connections so their
replies get through even when the rules block that direction (e.g.
the echo reply to a Dept B -> Trust ping, despite rule 4).

Note: this uses ipv4.ICMP_PROTOCOL from POX's own packet library rather
than a hand-rolled constant, which sidesteps the classic
"ICMP_PROTOCOL vs CMP_PROTOCOL" typo bug from the original coursework
version of this project.

Host discovery: a host's IP/MAC/location is learned the moment it ARPs
for its zone's gateway (which every host must do before its first
cross-zone packet). Locations are stored as the *core* port the host is
reached through (for a host behind a leaf, the core port facing that
leaf), since routed packets are always injected at the core. The
exception is a host that receives inbound traffic before ever
transmitting anything (e.g. an unsolicited connection to h_server) --
for that case the router actively ARPs into the destination zone,
queues the pending packet, and retries a few times before giving up.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.openflow.nicira as nx
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp, unreach
from pox.lib.recoco import Timer

import conntrack
from firewall_rules import (ZONES, zone_for_ip, firewall_allowed,
                            source_ip_valid_for_zone)
from firewall_client import FirewallClient, IPPROTO_ICMP
from network import load_network, port_maps

log = core.getLogger()

# Set to False to use the pure-Python firewall_allowed() (firewall_rules.py)
# instead of the C++ daemon. Flip this for a live A/B demo, or as a
# fallback if the daemon isn't running -- see ZoneRouter._firewall_allowed.
USE_CPP_FIREWALL = True

# ---------------------------------------------------------------------------
# Network layout, derived from network.json (the same file topology.py
# builds the Mininet network from), so these can't disagree with the
# real wiring. A packet's zone comes from these maps, which makes them
# the base that anti-spoofing and the firewall rules rest on.
# ---------------------------------------------------------------------------

_PORT_MAPS = port_maps(load_network())

# The core switch: the only one that touches more than one zone.
CORE_DPID = _PORT_MAPS['core_dpid']

# Leaf switch dpid -> its zone; every port on a leaf is in that zone.
SWITCH_ZONE = _PORT_MAPS['switch_zone']

# Leaf dpid -> its uplink port, and -> the core port at the other end.
LEAF_UPLINK_PORT = _PORT_MAPS['leaf_uplink_port']
LEAF_CORE_PORT = _PORT_MAPS['leaf_core_port']

# Core port -> the zone behind it (a leaf's zone, or a host's zone).
CORE_PORT_ZONES = _PORT_MAPS['core_port_zones']

# Inverse of the above, for scoped intra-zone flooding at the core.
ZONE_CORE_PORTS = {}
for _port, _zone in CORE_PORT_ZONES.items():
    ZONE_CORE_PORTS.setdefault(_zone, []).append(_port)

# Routed connections get switch flow rules after their first packet, so
# the rest of the connection skips the controller. The idle timeout
# clears rules for finished connections; the hard timeout sends even a
# long-lived connection back through the firewall once a minute.
ROUTED_FLOW_IDLE_TIMEOUT = 30  # seconds
ROUTED_FLOW_HARD_TIMEOUT = 60

# Blocked connections get a drop rule on the switch they entered, so a
# flood of blocked packets stays off the controller. Shorter than the
# routed timeouts: if the other side later opens a connection that
# reuses exactly the same addresses and ports, its replies would hit
# this rule until it expires.
DROP_FLOW_IDLE_TIMEOUT = 10  # seconds
DROP_FLOW_HARD_TIMEOUT = 30

CONN_EXPIRE_INTERVAL = 30  # seconds between sweeps of idle connections

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


def is_leaf_uplink(dpid, port):
    return LEAF_UPLINK_PORT.get(dpid) == port


def core_port_for(dpid, port):
    """The core-switch port that a host seen at (dpid, port) is reached
    through: the port itself at the core, else the core port facing
    that leaf."""
    if dpid == CORE_DPID:
        return port
    return LEAF_CORE_PORT.get(dpid)


class ZoneRouter(object):

    def __init__(self):
        self.connections = {}          # dpid -> Connection
        self.mac_table = {}            # dpid -> {mac: port}
        self.ip_to_loc = {}            # ip -> (core_port, mac, zone)
        self.pending = {}              # ip -> {zone, queue, retries, timer}
        self._fw_client = FirewallClient() if USE_CPP_FIREWALL else None
        self._fw_fallback_warned = False
        self.conns = conntrack.ConnectionTable()
        # Lookups check expiry themselves; this only frees memory.
        Timer(CONN_EXPIRE_INTERVAL, self.conns.expire, recurring=True)
        core.openflow.addListeners(self)
        log.info("Zone-segmentation router/firewall started (firewall backend: %s)",
                  "C++ daemon" if USE_CPP_FIREWALL else "Python")

    # -- firewall dispatch --------------------------------------------------

    def _firewall_allowed(self, src_zone, dst_zone, is_icmp, ip_pkt):
        """Ask the C++ daemon for a verdict; fall back to the in-process
        Python implementation if the daemon is unreachable, so a dead
        daemon degrades the controller instead of breaking it outright.
        """
        if self._fw_client is not None:
            try:
                allowed, _rule_id = self._fw_client.is_allowed(
                    ip_pkt.srcip, ip_pkt.dstip,
                    IPPROTO_ICMP if is_icmp else 0)
                return allowed
            except OSError:
                if not self._fw_fallback_warned:
                    log.warning("C++ firewall daemon unreachable; "
                                "falling back to Python firewall_allowed()")
                    self._fw_fallback_warned = True
        return firewall_allowed(src_zone, dst_zone, is_icmp)

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
        if is_leaf_uplink(dpid, in_port):
            self._handle_transit(event, packet, dpid, in_port)
        elif packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event, packet, dpid, in_port)
        elif packet.type == ethernet.IP_TYPE:
            self._handle_ip(event, packet, dpid, in_port)
        else:
            # Rule 8: flood any other non-IP traffic within the source zone.
            self._flood_in_zone(event, dpid, in_port)

    def _handle_transit(self, event, packet, dpid, in_port):
        """A packet coming down a leaf's uplink from the core: already
        firewalled and spoof-checked at its real ingress (see module
        docstring). Its source host isn't behind this leaf, so learning
        its location here would send that host's traffic to the wrong
        core port, and re-running the checks would misfire -- a routed
        packet's source IP is from another zone, and an ARP probe's is
        the gateway IP. Learn only the MAC and deliver it at L2."""
        self.mac_table.setdefault(dpid, {})[packet.src] = in_port
        if packet.dst.is_multicast:
            self._flood_in_zone(event, dpid, in_port)
        else:
            self._l2_forward(event, dpid, in_port, packet.dst)

    # -- ARP handling --------------------------------------------------

    def _handle_arp(self, event, packet, dpid, in_port):
        arp_pkt = packet.next
        src_zone = zone_of_port(dpid, in_port)
        if src_zone is None:
            return

        # Anti-spoofing: ARP is how this controller learns host
        # locations, so a forged sender IP (e.g. a Dept A host claiming
        # to be h_server) would redirect that IP's traffic to the
        # attacker. Drop it before anything gets learned.
        if not source_ip_valid_for_zone(arp_pkt.protosrc, src_zone):
            log.warning("DROP spoofed ARP from %s port %s: claims %s, port is %s",
                         dpid, in_port, arp_pkt.protosrc, src_zone)
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
        # Neither arp's hwsrc/hwdst/protosrc/protodst nor ethernet's
        # src/dst do any implicit conversion -- packing later calls
        # .toRaw() only if the value is already exactly an EthAddr
        # (ethernet.hdr() checks `type(x) is EthAddr`), so a plain str
        # passed straight from the ZONES table crashes at pack() time.
        # Wrap explicitly rather than relying on the constructor.
        reply.hwsrc = EthAddr(sender_mac)
        reply.hwdst = EthAddr(target_mac)
        reply.protosrc = IPAddr(str(sender_ip))
        reply.protodst = IPAddr(str(target_ip))
        eth = ethernet(type=ethernet.ARP_TYPE, src=EthAddr(sender_mac), dst=EthAddr(target_mac))
        eth.payload = reply
        self._packet_out(connection, eth, out_port)

    def _send_arp_probe(self, dst_ip, dst_zone):
        connection = self.connections.get(CORE_DPID)
        if connection is None:
            return
        gw = ZONES[dst_zone]
        req = arp()
        req.opcode = arp.REQUEST
        req.hwsrc = EthAddr(gw['gateway_mac'])
        req.hwdst = ETHER_BROADCAST
        req.protosrc = IPAddr(gw['gateway'])
        req.protodst = dst_ip
        eth = ethernet(type=ethernet.ARP_TYPE, src=EthAddr(gw['gateway_mac']), dst=ETHER_BROADCAST)
        eth.payload = req
        for port in ZONE_CORE_PORTS.get(dst_zone, []):
            self._packet_out(connection, eth, port)

    # -- IP handling ------------------------------------------------------

    def _handle_ip(self, event, packet, dpid, in_port):
        ip_pkt = packet.next
        src_zone = zone_of_port(dpid, in_port)
        if src_zone is None:
            return

        # Anti-spoofing: the source IP must belong to the zone of the
        # port the packet arrived on. Checked before _learn() so a forged
        # source can't poison ip_to_loc, and before the firewall so the
        # C++ daemon (which classifies by IP) always sees an honest one.
        if not source_ip_valid_for_zone(ip_pkt.srcip, src_zone):
            log.warning("DROP spoofed IP from %s port %s: claims %s, port is %s",
                         dpid, in_port, ip_pkt.srcip, src_zone)
            return

        self._learn(dpid, in_port, ip_pkt.srcip, packet.src, src_zone)

        if any(str(ip_pkt.dstip) == z['gateway'] for z in ZONES.values()):
            return  # addressed to a virtual gateway; no real host to deliver to

        dst_zone = zone_for_ip(ip_pkt.dstip)
        if dst_zone is None:
            # Default-deny: destination outside every known zone.
            log.info("DROP %s -> unknown zone: %s -> %s", src_zone,
                      ip_pkt.srcip, ip_pkt.dstip)
            return

        is_icmp = ip_pkt.protocol == ipv4.ICMP_PROTOCOL

        if dst_zone == src_zone:
            # Same subnet: plain L2 delivery, no firewall/routing involved.
            self._l2_forward(event, dpid, in_port, packet.dst)
            return

        policy_allowed = self._firewall_allowed(src_zone, dst_zone, is_icmp, ip_pkt)
        # Stateful check: a packet the rules block still passes if it's a
        # reply to a connection the rules allowed (see conntrack.py).
        if self.conns.check(policy_allowed, self._tracked(ip_pkt)) is None:
            log.info("DROP %s -> %s (%s): %s -> %s", src_zone, dst_zone,
                      "ICMP" if is_icmp else "IP", ip_pkt.srcip, ip_pkt.dstip)
            self._install_drop_flow(event)
            return

        self._route(event, packet, ip_pkt, dst_zone)

    @staticmethod
    def _tracked(ip_pkt):
        """The packet's connection-tracking description, or None if POX
        couldn't parse its TCP/UDP/ICMP header or the kind isn't tracked."""
        l4 = ip_pkt.payload
        if ip_pkt.protocol in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
            if not hasattr(l4, 'srcport'):
                return None
            return conntrack.tracked_packet(ip_pkt.srcip, ip_pkt.dstip,
                                            ip_pkt.protocol, l4.srcport, l4.dstport)
        if ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
            if not hasattr(l4, 'type'):
                return None
            echo_id = getattr(l4.payload, 'id', 0)  # set for echo request/reply
            return conntrack.tracked_packet(ip_pkt.srcip, ip_pkt.dstip,
                                            ip_pkt.protocol, icmp_type=l4.type,
                                            icmp_id=echo_id)
        return None

    def _route(self, event, packet, ip_pkt, dst_zone):
        loc = self.ip_to_loc.get(ip_pkt.dstip)
        if loc is not None:
            out_port, dst_mac, _zone = loc
            if ip_pkt.ttl > 1:
                self._install_route_flows(event, dst_zone, out_port, dst_mac)
            self._forward_ip(event.dpid, event.port, dst_zone, packet, ip_pkt,
                              out_port, dst_mac)
        else:
            self._queue_and_resolve(event.dpid, event.port, packet, ip_pkt, dst_zone)

    def _install_drop_flow(self, event):
        """Have the switch the packet entered drop the rest of this
        connection itself. Like the routed rules, it matches the exact
        connection, and a flow_mod with no actions means drop."""
        msg = of.ofp_flow_mod(match=of.ofp_match.from_packet(event.parsed, event.port),
                              idle_timeout=DROP_FLOW_IDLE_TIMEOUT,
                              hard_timeout=DROP_FLOW_HARD_TIMEOUT)
        event.connection.send(msg)

    def _install_route_flows(self, event, dst_zone, out_port, dst_mac):
        """Install switch rules so the rest of this connection is routed
        without the controller: the core does the router hop (rewrite
        MACs, decrement TTL, forward), and a host's leaf passes the
        connection's packets up to the core.

        Rules match the exact connection the first packet belongs to
        (ingress port, MACs, IPs, protocol, and TCP/UDP ports or ICMP
        type), so a spoofed packet can't ride an allowed connection's
        rules: its source IP doesn't match, so it still comes to the
        controller for the anti-spoofing check."""
        core_conn = self.connections.get(CORE_DPID)
        if core_conn is None:
            return
        match = of.ofp_match.from_packet(event.parsed, event.port)

        # Core first, so packets sent up by the leaf rule find it there.
        core_match = match.clone()
        core_match.in_port = core_port_for(event.dpid, event.port)
        msg = of.ofp_flow_mod(match=core_match,
                              idle_timeout=ROUTED_FLOW_IDLE_TIMEOUT,
                              hard_timeout=ROUTED_FLOW_HARD_TIMEOUT)
        msg.actions.append(of.ofp_action_dl_addr.set_src(
            EthAddr(ZONES[dst_zone]['gateway_mac'])))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        # OpenFlow 1.0 has no TTL action; Open vSwitch's Nicira
        # extension provides one.
        msg.actions.append(nx.nx_action_dec_ttl())
        msg.actions.append(of.ofp_action_output(port=out_port))
        core_conn.send(msg)

        if event.dpid != CORE_DPID:
            msg = of.ofp_flow_mod(match=match,
                                  idle_timeout=ROUTED_FLOW_IDLE_TIMEOUT,
                                  hard_timeout=ROUTED_FLOW_HARD_TIMEOUT)
            msg.actions.append(of.ofp_action_output(
                port=LEAF_UPLINK_PORT[event.dpid]))
            event.connection.send(msg)

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
        gw_mac = EthAddr(ZONES[dst_zone]['gateway_mac'])
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
        out_port = self.ip_to_loc[ip][0]
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
        # RFC 792: 4 unused bytes, then the original IP header + first 8
        # bytes of its payload. POX's icmp only packs type/code/checksum,
        # so the unused word has to come from an unreach body (its layout
        # is the same for Time Exceeded) -- raw bytes here would shift the
        # quoted header 4 bytes early and receivers couldn't parse it.
        body = unreach()
        body.payload = ip_pkt.pack()[:28]
        err.payload = body

        reply_ip = ipv4()
        reply_ip.protocol = ipv4.ICMP_PROTOCOL
        reply_ip.srcip = IPAddr(gw['gateway'])
        reply_ip.dstip = ip_pkt.srcip
        reply_ip.payload = err

        eth = ethernet(type=ethernet.IP_TYPE, src=EthAddr(gw['gateway_mac']), dst=packet.src)
        eth.payload = reply_ip
        self._packet_out(connection, eth, orig_port)

    # -- plain L2 forwarding (leaf switches, and intra-zone at the core) --

    def _learn(self, dpid, port, ip, mac, zone):
        self.mac_table.setdefault(dpid, {})[mac] = port
        core_port = core_port_for(dpid, port)
        if core_port is not None:
            self.ip_to_loc[ip] = (core_port, mac, zone)

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
