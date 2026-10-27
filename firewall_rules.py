#!/usr/bin/env python3
"""Pure zone/firewall rule logic -- no POX, no sockets, no I/O.

Extracted from controller.py so this logic can be imported standalone
(controller.py can't be, since it does `from pox.core import core` at
module level, which only resolves inside a running POX instance). Two
things import this module:

  - controller.py: the live POX component, as its Python-path firewall
    implementation (and as the fallback if the C++ daemon is unreachable).
  - bench_firewall.py: benchmarks this implementation against the
    equivalent decision made by cpp/firewall_daemon.cpp.

This is the single source of truth for zone/subnet/rule definitions;
cpp/firewall_daemon.cpp hand-mirrors the same tables (see the comment
at the top of that file for why they're duplicated rather than shared).
"""

import ipaddress

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

BLOCK_ALL_IP = {
    ('Untrust', 'DataCenter'),
    ('Trust', 'DataCenter'),
    # The data center can't start connections to either outside zone,
    # so the LLM server stays isolated from them in both directions.
    ('DataCenter', 'Trust'),
    ('DataCenter', 'Untrust'),
}

BLOCK_ICMP = {
    ('Untrust', 'DeptA'),
    ('Untrust', 'DeptB'),
    ('Untrust', 'DataCenter'),
    ('Trust', 'DeptB'),
    ('DeptA', 'DeptB'),
    ('DeptB', 'DeptA'),
}


def zone_for_ip(ip):
    addr = ipaddress.ip_address(str(ip))
    for name, zone in ZONES.items():
        if addr in zone['subnet']:
            return name
    return None


def source_ip_valid_for_zone(src_ip, ingress_zone):
    """Anti-spoofing check: a packet's claimed source IP must fall inside
    the subnet of the zone it physically arrived from (derived from the
    switch port, which a host can't forge). Anything else -- an IP from
    another zone, or one outside every zone -- is treated as spoofed.
    The zone's gateway IP is also rejected: it belongs to the controller,
    so no real host may send from it.
    """
    if ingress_zone not in ZONES:
        return False
    if str(src_ip) == ZONES[ingress_zone]['gateway']:
        return False
    return zone_for_ip(src_ip) == ingress_zone


def firewall_allowed(src_zone, dst_zone, is_icmp):
    # Default-deny for anything outside the known zones (zone_for_ip
    # returns None): an address the policy doesn't know about can't be
    # granted access by any rule below.
    if src_zone not in ZONES or dst_zone not in ZONES:
        return False
    if (src_zone, dst_zone) in BLOCK_ALL_IP:
        return False
    if is_icmp and (src_zone, dst_zone) in BLOCK_ICMP:
        return False
    return True
