#!/usr/bin/env python3
"""Mininet topology for the zone-segmentation network.

Six OpenFlow switches, no host-side routing: every host's default route
points at a "virtual" gateway IP for its zone, and the POX controller
(controller.py) owns all of those gateway IPs. It answers ARP for them
and routes between zones in software, so the topology below only wires
up switches/hosts/links and IP addressing -- no L3 logic lives here.

Zones and subnets:
    Dept A   (Floor 1, s1 + s2) -> 10.1.1.0/24, gateway 10.1.1.1
    Dept B   (Floor 2, s3 + s4) -> 10.1.2.0/24, gateway 10.1.2.1
    Data Center (s5)            -> 10.1.3.0/24, gateway 10.1.3.1
    Trust boundary (h_trust)    -> 192.47.38.0/24, gateway 192.47.38.1
    Untrust boundary (h_untrust)-> 108.35.24.0/24, gateway 108.35.24.1

s1/s2 and s3/s4 each share one subnet across two switches (hosts on the
same floor can reach each other via plain L2 learning); s6 (the core) is
where the controller routes between zones.
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info


def build_network():
    net = Mininet(controller=RemoteController, switch=OVSSwitch,
                   link=TCLink, autoSetMacs=True, build=False)

    info('*** Adding controller\n')
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info('*** Adding switches\n')
    s1 = net.addSwitch('s1')  # Floor 1 / Dept A - h101, h102
    s2 = net.addSwitch('s2')  # Floor 1 / Dept A - h103, h104
    s3 = net.addSwitch('s3')  # Floor 2 / Dept B - h201, h202
    s4 = net.addSwitch('s4')  # Floor 2 / Dept B - h203, h204
    s5 = net.addSwitch('s5')  # Data Center - h_server
    s6 = net.addSwitch('s6')  # Core

    info('*** Adding hosts\n')
    # Dept A - Floor 1 (10.1.1.0/24, gateway 10.1.1.1)
    h101 = net.addHost('h101', ip='10.1.1.101/24', defaultRoute='via 10.1.1.1')
    h102 = net.addHost('h102', ip='10.1.1.102/24', defaultRoute='via 10.1.1.1')
    h103 = net.addHost('h103', ip='10.1.1.103/24', defaultRoute='via 10.1.1.1')
    h104 = net.addHost('h104', ip='10.1.1.104/24', defaultRoute='via 10.1.1.1')

    # Dept B - Floor 2 (10.1.2.0/24, gateway 10.1.2.1)
    h201 = net.addHost('h201', ip='10.1.2.201/24', defaultRoute='via 10.1.2.1')
    h202 = net.addHost('h202', ip='10.1.2.202/24', defaultRoute='via 10.1.2.1')
    h203 = net.addHost('h203', ip='10.1.2.203/24', defaultRoute='via 10.1.2.1')
    h204 = net.addHost('h204', ip='10.1.2.204/24', defaultRoute='via 10.1.2.1')

    # Data Center (10.1.3.0/24, gateway 10.1.3.1)
    h_server = net.addHost('h_server', ip='10.1.3.178/24', defaultRoute='via 10.1.3.1')

    # External trust boundaries, connected directly to the core
    h_trust = net.addHost('h_trust', ip='192.47.38.109/24', defaultRoute='via 192.47.38.1')
    h_untrust = net.addHost('h_untrust', ip='108.35.24.113/24', defaultRoute='via 108.35.24.1')

    info('*** Creating links\n')
    # Dept A hosts -> their floor switches
    net.addLink(h101, s1)
    net.addLink(h102, s1)
    net.addLink(h103, s2)
    net.addLink(h104, s2)

    # Dept B hosts -> their floor switches
    net.addLink(h201, s3)
    net.addLink(h202, s3)
    net.addLink(h203, s4)
    net.addLink(h204, s4)

    # Data center host -> data center switch
    net.addLink(h_server, s5)

    # Core connects both floors, the data center, and both trust boundaries
    net.addLink(s1, s6)
    net.addLink(s2, s6)
    net.addLink(s3, s6)
    net.addLink(s4, s6)
    net.addLink(s5, s6)
    net.addLink(h_trust, s6)
    net.addLink(h_untrust, s6)

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
