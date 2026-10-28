"""Unit tests for network.py: the layout must produce the port maps the
controller depends on, and a layout that contradicts itself or
policy.json must be rejected instead of misrouting traffic."""

import copy
import json

import pytest

from network import NETWORK_PATH, NetworkError, load_network, port_maps

# Typed out by hand (from topology.py's original link order), not
# derived from network.json: a wrong entry in the file fails this test.
EXPECTED_MAPS = {
    'core_dpid': 6,
    'switch_zone': {1: 'DeptA', 2: 'DeptA', 3: 'DeptB', 4: 'DeptB', 5: 'DataCenter'},
    'leaf_uplink_port': {1: 3, 2: 3, 3: 3, 4: 3, 5: 2},
    'leaf_core_port': {1: 1, 2: 2, 3: 3, 4: 4, 5: 5},
    'core_port_zones': {1: 'DeptA', 2: 'DeptA', 3: 'DeptB', 4: 'DeptB',
                        5: 'DataCenter', 6: 'Trust', 7: 'Untrust'},
}

with open(NETWORK_PATH) as f:
    SHIPPED = json.load(f)


def write(tmp_path, layout):
    path = tmp_path / 'network.json'
    path.write_text(layout if isinstance(layout, str) else json.dumps(layout))
    return str(path)


def broken(change):
    layout = copy.deepcopy(SHIPPED)
    change(layout)
    return layout


def test_shipped_network_produces_expected_port_maps():
    assert port_maps(load_network()) == EXPECTED_MAPS


def test_adding_hosts_needs_only_a_network_json_edit(tmp_path):
    """The point of network.json: new hosts get the right zones in the
    controller's maps without touching any code."""
    def add_hosts(n):
        n['hosts']['h105'] = {'ip': '10.1.1.105', 'switch': 's1', 'port': 4}
        n['hosts']['h_trust2'] = {'ip': '192.47.38.110', 'switch': 's6', 'port': 8}
    net = load_network(write(tmp_path, broken(add_hosts)))
    maps = port_maps(net)

    assert net.hosts['h105']['zone'] == 'DeptA'
    assert net.hosts['h_trust2']['zone'] == 'Trust'
    # A new core port appears, mapped to the new host's zone...
    assert maps['core_port_zones'][8] == 'Trust'
    # ...and nothing else changes (a leaf host adds no map entries).
    maps['core_port_zones'].pop(8)
    assert maps == EXPECTED_MAPS


def test_host_zone_comes_from_its_ip():
    hosts = load_network().hosts
    assert hosts['h_server']['zone'] == 'DataCenter'
    assert hosts['h_trust']['zone'] == 'Trust'
    assert hosts['h101']['prefix_len'] == 24


@pytest.mark.parametrize('change, message', [
    (lambda n: n['switches']['s6'].update(core=False, zone='DeptA'), 'exactly one core'),
    (lambda n: n['switches']['s6'].pop('core'), 'needs "core": true'),
    (lambda n: n['switches']['s1'].update(core=True), 'exactly one core'),
    (lambda n: n['switches']['s2'].update(dpid=1), 'unique positive integer'),
    (lambda n: n['switches']['s1'].update(zone='DeptC'), 'not in policy.json'),
    (lambda n: n['uplinks'].pop(0), 'without an uplink'),
    (lambda n: n['uplinks'].append(dict(n['uplinks'][0])), 'more than one uplink'),
    (lambda n: n['uplinks'][0].update(leaf='s6'), 'not a leaf switch'),
    (lambda n: n['hosts']['h102'].update(port=1), 's1 port 1 is used by both'),
    (lambda n: n['uplinks'][1].update(core_port=1), 's6 port 1 is used by both'),
    (lambda n: n['hosts']['h_trust'].update(port=5), 's6 port 5 is used by both'),
    (lambda n: n['hosts']['h101'].update(port='1'), 'positive integer'),
    (lambda n: n['hosts']['h101'].update(ip='10.1.2.150'), 'plugged into s1'),
    (lambda n: n['hosts']['h101'].update(ip='8.8.8.8'), 'outside every zone'),
    (lambda n: n['hosts']['h101'].update(ip='10.1.1.1'), 'reserved'),
    (lambda n: n['hosts']['h102'].update(ip='10.1.1.101'), 'used by another host'),
    (lambda n: n['hosts']['h101'].update(switch='s9'), 'unknown switch'),
], ids=['no-core', 'core-flag-missing', 'two-cores', 'duplicate-dpid', 'unknown-zone', 'missing-uplink',
        'two-uplinks', 'core-as-leaf', 'host-port-clash', 'core-port-clash',
        'host-uplink-clash', 'non-integer-port', 'host-in-wrong-zone',
        'host-outside-zones', 'host-on-gateway-ip', 'duplicate-ip', 'unknown-switch'])
def test_inconsistent_network_is_rejected(tmp_path, change, message):
    with pytest.raises(NetworkError, match=message):
        load_network(write(tmp_path, broken(change)))


def test_invalid_json_is_rejected(tmp_path):
    with pytest.raises(NetworkError, match='not valid JSON'):
        load_network(write(tmp_path, '{"switches": '))
