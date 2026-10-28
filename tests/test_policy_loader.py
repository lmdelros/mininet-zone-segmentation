"""Unit tests for load_policy(): broken policy files must be rejected
with a clear error instead of loading a policy that misroutes traffic
or silently blocks nothing. The policy's actual content is checked by
test_firewall_rules.py against the README's table."""

import copy
import json

import pytest

from firewall_rules import POLICY_PATH, PolicyError, load_policy

GOOD = {
    'zones': {
        'A': {'subnet': '10.0.1.0/24', 'gateway': '10.0.1.1', 'gateway_mac': '02:00:00:00:00:01'},
        'B': {'subnet': '10.0.2.0/24', 'gateway': '10.0.2.1', 'gateway_mac': '02:00:00:00:00:02'},
    },
    'rules': [
        {'rule': 1, 'from': ['A'], 'to': ['B'], 'block': 'all'},
        {'rule': 2, 'from': ['B'], 'to': ['A'], 'block': 'icmp'},
    ],
}


def write(tmp_path, policy):
    path = tmp_path / 'policy.json'
    path.write_text(policy if isinstance(policy, str) else json.dumps(policy))
    return str(path)


def broken(change):
    policy = copy.deepcopy(GOOD)
    change(policy)
    return policy


def test_shipped_policy_loads():
    zones, block_all, block_icmp = load_policy(POLICY_PATH)
    assert len(zones) == 5 and block_all and block_icmp


def test_valid_policy_loads(tmp_path):
    zones, block_all, block_icmp = load_policy(write(tmp_path, GOOD))
    assert list(zones) == ['A', 'B']
    assert block_all == {('A', 'B')}
    assert block_icmp == {('B', 'A')}


def test_rule_expands_every_from_to_pair(tmp_path):
    policy = broken(lambda p: p['rules'].append(
        {'rule': 3, 'from': ['A', 'B'], 'to': ['A', 'B'], 'block': 'icmp'}))
    _, _, block_icmp = load_policy(write(tmp_path, policy))
    assert block_icmp == {('A', 'A'), ('A', 'B'), ('B', 'A'), ('B', 'B')}


def test_mac_is_normalized_to_lowercase(tmp_path):
    policy = broken(lambda p: p['zones']['A'].update(gateway_mac='02:00:00:00:00:AA'))
    zones, _, _ = load_policy(write(tmp_path, policy))
    assert zones['A']['gateway_mac'] == '02:00:00:00:00:aa'


@pytest.mark.parametrize('change, message', [
    (lambda p: p['zones']['A'].update(subnet='10.0.1.0/33'), 'bad subnet'),
    (lambda p: p['zones']['A'].update(gateway='10.0.9.1'), 'outside'),
    (lambda p: p['zones']['A'].pop('gateway'), 'bad subnet or gateway'),
    (lambda p: p['zones']['A'].update(gateway_mac='02:00:00:00:01'), 'bad gateway_mac'),
    (lambda p: p['zones']['B'].update(subnet='10.0.0.0/16', gateway='10.0.0.1'), 'overlap'),
    (lambda p: p['zones']['B'].update(gateway_mac='02:00:00:00:00:01'), 'share gateway_mac'),
    (lambda p: p.update(zones={}), 'no zones'),
    (lambda p: p['rules'][0].update(to=['C']), 'needs known zones'),
    (lambda p: p['rules'][0].update(**{'from': []}), 'needs known zones'),
    (lambda p: p['rules'][0].update(block='tcp'), 'block must be one of'),
], ids=['bad-subnet', 'gateway-outside-subnet', 'missing-gateway', 'bad-mac',
        'overlapping-subnets', 'duplicate-mac', 'no-zones', 'unknown-zone-in-rule',
        'empty-from', 'unknown-block-kind'])
def test_broken_policy_is_rejected(tmp_path, change, message):
    with pytest.raises(PolicyError, match=message):
        load_policy(write(tmp_path, broken(change)))


def test_invalid_json_is_rejected(tmp_path):
    with pytest.raises(PolicyError, match='not valid JSON'):
        load_policy(write(tmp_path, '{"zones": '))
