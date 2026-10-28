#!/usr/bin/env python3
"""Zone/firewall rule logic -- no POX, no sockets.

Extracted from controller.py so this logic can be imported standalone
(controller.py can't be, since it does `from pox.core import core` at
module level, which only resolves inside a running POX instance). Two
things import this module:

  - controller.py: the live POX component, as its Python-path firewall
    implementation (and as the fallback if the C++ daemon is unreachable).
  - bench_firewall.py: benchmarks this implementation against the
    equivalent decision made by cpp/firewall_daemon.cpp.

The zones and block rules come from policy.json, next to this file
(override the path with the ZONE_POLICY environment variable).
cpp/firewall_daemon.cpp hand-mirrors the same tables (see the comment
at the top of that file for why they're duplicated rather than shared).
"""

import ipaddress
import json
import os
import re

POLICY_PATH = os.environ.get(
    'ZONE_POLICY', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'policy.json'))

BLOCK_KINDS = ('all', 'icmp')
_MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')


class PolicyError(ValueError):
    """policy.json is malformed or inconsistent."""


def load_policy(path=POLICY_PATH):
    """Read and validate a policy file. Returns (zones, block_all_ip,
    block_icmp): zones maps name -> {'subnet', 'gateway', 'gateway_mac'},
    and the block sets hold (src_zone, dst_zone) pairs. Raises PolicyError
    with a specific message instead of loading a policy that would
    misroute traffic or silently block nothing."""
    with open(path) as f:
        try:
            raw = json.load(f)
        except ValueError as exc:
            raise PolicyError('{}: not valid JSON: {}'.format(path, exc))

    zones = {}
    for name, z in raw.get('zones', {}).items():
        try:
            subnet = ipaddress.ip_network(z['subnet'])
            gateway = ipaddress.ip_address(z['gateway'])
        except (KeyError, ValueError) as exc:
            raise PolicyError('zone {}: bad subnet or gateway: {}'.format(name, exc))
        if gateway not in subnet:
            raise PolicyError('zone {}: gateway {} is outside {}'.format(name, gateway, subnet))
        mac = str(z.get('gateway_mac', '')).lower()
        if not _MAC_RE.match(mac):
            raise PolicyError('zone {}: bad gateway_mac {!r}'.format(name, mac))
        for other, oz in zones.items():
            if subnet.overlaps(oz['subnet']):
                raise PolicyError('zones {} and {} overlap'.format(other, name))
            if mac == oz['gateway_mac']:
                raise PolicyError('zones {} and {} share gateway_mac {}'.format(other, name, mac))
        zones[name] = {'subnet': subnet, 'gateway': str(gateway), 'gateway_mac': mac}
    if not zones:
        raise PolicyError('{}: no zones defined'.format(path))

    blocks = {kind: set() for kind in BLOCK_KINDS}
    for i, rule in enumerate(raw.get('rules', [])):
        label = 'rule {}'.format(rule.get('rule', '#{}'.format(i + 1)))
        if rule.get('block') not in BLOCK_KINDS:
            raise PolicyError('{}: block must be one of {}'.format(label, BLOCK_KINDS))
        for field in ('from', 'to'):
            unknown = [z for z in rule.get(field, []) if z not in zones]
            if unknown or not rule.get(field):
                raise PolicyError('{}: "{}" needs known zones, got {}'.format(
                    label, field, rule.get(field)))
        for src in rule['from']:
            for dst in rule['to']:
                blocks[rule['block']].add((src, dst))
    return zones, blocks['all'], blocks['icmp']


ZONES, BLOCK_ALL_IP, BLOCK_ICMP = load_policy()


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
