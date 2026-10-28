#!/usr/bin/env python3
"""Network layout from network.json -- no POX, no Mininet.

The controller decides a packet's zone from the switch port it arrived
on, so the port-to-zone map is what anti-spoofing and the firewall rest
on. network.json states every switch, uplink, and host port explicitly;
topology.py builds the Mininet network from it, and controller.py takes
its port maps from port_maps() below, so the two can't disagree.

Host zones aren't written in the file: they come from each host's IP
via policy.json, so the layout can't contradict the policy.
"""

import collections
import ipaddress
import json
import os

from firewall_rules import ZONES, zone_for_ip

NETWORK_PATH = os.environ.get(
    'ZONE_NETWORK', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network.json'))

Network = collections.namedtuple('Network', 'core switches uplinks hosts')


class NetworkError(ValueError):
    """network.json is malformed or inconsistent with policy.json."""


def load_network(path=NETWORK_PATH, zones=ZONES):
    """Read network.json, check it, and return a Network."""
    with open(path) as f:
        try:
            raw = json.load(f)
        except ValueError as exc:
            raise NetworkError('{}: not valid JSON: {}'.format(path, exc))
    core, switches = _load_switches(raw, zones)
    uplinks = _load_uplinks(raw, switches, core)
    hosts = _load_hosts(raw, switches, core, zones)
    _check_ports_unique(core, uplinks, hosts)
    return Network(core, switches, uplinks, hosts)


def _load_switches(raw, zones):
    """Check the switches and return (core switch name, {name: {'dpid', 'zone'}})."""
    switches, cores, dpids = {}, [], set()
    for name, s in raw.get('switches', {}).items():
        dpid = s.get('dpid')
        if not isinstance(dpid, int) or dpid <= 0 or dpid in dpids:
            raise NetworkError('switch {}: dpid must be a unique positive integer'.format(name))
        dpids.add(dpid)
        if s.get('core'):
            cores.append(name)
            zone = None
        else:
            zone = s.get('zone')
            if zone not in zones:
                raise NetworkError('switch {}: zone {!r} is not in policy.json '
                                   '(the core switch needs "core": true instead)'.format(name, zone))
        switches[name] = {'dpid': dpid, 'zone': zone}
    if len(cores) != 1:
        raise NetworkError('need exactly one core switch, found {}'.format(cores or 'none'))
    return cores[0], switches


def _load_uplinks(raw, switches, core):
    """Check that every leaf has exactly one uplink to the core and return {leaf: link}."""
    uplinks = {}
    for link in raw.get('uplinks', []):
        leaf = link.get('leaf')
        if leaf not in switches or leaf == core:
            raise NetworkError('uplink: {!r} is not a leaf switch'.format(leaf))
        if leaf in uplinks:
            raise NetworkError('leaf {} has more than one uplink'.format(leaf))
        uplinks[leaf] = {'leaf_port': link.get('leaf_port'), 'core_port': link.get('core_port')}
    missing = sorted(name for name in switches if name != core and name not in uplinks)
    if missing:
        raise NetworkError('leaf switches without an uplink: {}'.format(', '.join(missing)))
    return uplinks


def _load_hosts(raw, switches, core, zones):
    """Check each host's IP and attachment point and return {name: host}."""
    hosts, ips = {}, set()
    for name, h in raw.get('hosts', {}).items():
        try:
            ip = ipaddress.ip_address(h.get('ip'))
        except ValueError as exc:
            raise NetworkError('host {}: {}'.format(name, exc))
        zone = zone_for_ip(ip)
        if zone is None:
            raise NetworkError('host {}: {} is outside every zone in policy.json'.format(name, ip))
        subnet = zones[zone]['subnet']
        if str(ip) == zones[zone]['gateway'] or ip in (subnet.network_address,
                                                       subnet.broadcast_address):
            raise NetworkError('host {}: {} is reserved in {}'.format(name, ip, subnet))
        if ip in ips:
            raise NetworkError('host {}: {} is used by another host'.format(name, ip))
        ips.add(ip)
        switch = h.get('switch')
        if switch not in switches:
            raise NetworkError('host {}: unknown switch {!r}'.format(name, switch))
        if switch != core and switches[switch]['zone'] != zone:
            raise NetworkError('host {}: {} is in {} but plugged into {} ({})'.format(
                name, ip, zone, switch, switches[switch]['zone']))
        hosts[name] = {'ip': str(ip), 'prefix_len': subnet.prefixlen, 'zone': zone,
                       'switch': switch, 'port': h.get('port')}
    return hosts


def _check_ports_unique(core, uplinks, hosts):
    """Make sure no switch port is used twice and every port is a positive integer."""
    used = collections.defaultdict(dict)  # switch -> {port: what's plugged in}
    attachments = [(h['switch'], h['port'], 'host ' + name) for name, h in hosts.items()]
    for leaf, link in uplinks.items():
        attachments.append((leaf, link['leaf_port'], 'uplink to core'))
        attachments.append((core, link['core_port'], 'uplink from ' + leaf))
    for switch, port, what in attachments:
        if not isinstance(port, int) or port <= 0:
            raise NetworkError('{}: port on {} must be a positive integer'.format(what, switch))
        if port in used[switch]:
            raise NetworkError('{} port {} is used by both {} and {}'.format(
                switch, port, used[switch][port], what))
        used[switch][port] = what


def port_maps(net):
    """Derive the port maps the controller routes and classifies traffic with."""
    core_ports = {link['core_port']: net.switches[leaf]['zone'] for leaf, link in net.uplinks.items()}
    core_ports.update({h['port']: h['zone'] for h in net.hosts.values() if h['switch'] == net.core})
    return {
        'core_dpid': net.switches[net.core]['dpid'],
        'switch_zone': {s['dpid']: s['zone'] for name, s in net.switches.items() if name != net.core},
        'leaf_uplink_port': {net.switches[leaf]['dpid']: link['leaf_port']
                             for leaf, link in net.uplinks.items()},
        'leaf_core_port': {net.switches[leaf]['dpid']: link['core_port']
                           for leaf, link in net.uplinks.items()},
        'core_port_zones': core_ports,
    }
