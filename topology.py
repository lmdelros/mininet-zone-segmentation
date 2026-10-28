#!/usr/bin/env python3
"""Mininet topology for the zone-segmentation network.

Six OpenFlow switches, no host-side routing: every host's default route
points at a "virtual" gateway IP for its zone, and the POX controller
(controller.py) owns all of those gateway IPs. It answers ARP for them
and routes between zones in software, so this file only wires up
switches, hosts, links, and IP addressing -- no L3 logic lives here.

The layout comes from network.json (switches, uplinks, hosts, and the
exact port each cable uses) and each host's gateway from its zone in
policy.json. The controller takes its port maps from the same file, so
the order links are created in no longer matters.
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info

from firewall_rules import ZONES
from network import load_network


def build_network(switch=OVSSwitch, layout=None):
    # `switch` is overridable so environments without the OVS kernel
    # module (Docker on WSL2, most CI runners) can pass
    # partial(OVSSwitch, datapath='user') for the userspace datapath.
    # `layout` defaults to network.json.
    layout = layout or load_network()
    net = Mininet(controller=RemoteController, switch=switch,
                   link=TCLink, autoSetMacs=True, build=False)

    info('*** Adding controller\n')
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info('*** Adding switches\n')
    for name, s in layout.switches.items():
        net.addSwitch(name, dpid='{:016x}'.format(s['dpid']))

    info('*** Adding hosts\n')
    for name, h in layout.hosts.items():
        net.addHost(name, ip='{}/{}'.format(h['ip'], h['prefix_len']),
                    defaultRoute='via {}'.format(ZONES[h['zone']]['gateway']))

    info('*** Creating links\n')
    # Explicit port numbers on the switch side: the controller's port
    # maps are derived from these, not from the order of these calls.
    for name, h in layout.hosts.items():
        net.addLink(net[name], net[h['switch']], port2=h['port'])
    for leaf, link in layout.uplinks.items():
        net.addLink(net[leaf], net[layout.core],
                    port1=link['leaf_port'], port2=link['core_port'])

    return net


def main():
    setLogLevel('info')
    net = build_network()
    net.build()
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()
