"""Unit tests for firewall_rules.py -- pure logic, runs on any OS.

The expected policy below is written out by hand from the README's
policy table, NOT derived from BLOCK_ALL_IP / BLOCK_ICMP. A test that
reads the same tables as the code it's testing can't catch a wrong
entry in those tables.
"""

import ipaddress

import pytest

from firewall_rules import ZONES, firewall_allowed, zone_for_ip

# One representative host per zone (same addresses topology.py and
# bench_firewall.py use).
HOSTS = {
    'DeptA': '10.1.1.101',
    'DeptB': '10.1.2.201',
    'DataCenter': '10.1.3.178',
    'Trust': '192.47.38.109',
    'Untrust': '108.35.24.113',
}

# (src_zone, dst_zone) -> (non-ICMP allowed, ICMP allowed).
# Every one of the 25 zone pairs is listed so a newly added block can't
# silently go untested.
EXPECTED_POLICY = {
    ('DeptA', 'DeptA'):           (True,  True),
    ('DeptA', 'DeptB'):           (True,  False),  # rule 6
    ('DeptA', 'DataCenter'):      (True,  True),
    ('DeptA', 'Trust'):           (True,  True),
    ('DeptA', 'Untrust'):         (True,  True),

    ('DeptB', 'DeptA'):           (True,  False),  # rule 6
    ('DeptB', 'DeptB'):           (True,  True),
    ('DeptB', 'DataCenter'):      (True,  True),
    ('DeptB', 'Trust'):           (True,  True),
    ('DeptB', 'Untrust'):         (True,  True),

    ('DataCenter', 'DeptA'):      (True,  True),
    ('DataCenter', 'DeptB'):      (True,  True),
    ('DataCenter', 'DataCenter'): (True,  True),
    ('DataCenter', 'Trust'):      (True,  True),
    ('DataCenter', 'Untrust'):    (True,  True),

    ('Trust', 'DeptA'):           (True,  True),   # rule 5
    ('Trust', 'DeptB'):           (True,  False),  # rule 4
    ('Trust', 'DataCenter'):      (False, False),  # rule 3
    ('Trust', 'Trust'):           (True,  True),
    ('Trust', 'Untrust'):         (True,  True),

    ('Untrust', 'DeptA'):         (True,  False),  # rule 2
    ('Untrust', 'DeptB'):         (True,  False),  # rule 2
    ('Untrust', 'DataCenter'):    (False, False),  # rules 1 + 2
    ('Untrust', 'Trust'):         (True,  True),
    ('Untrust', 'Untrust'):       (True,  True),
}


# -- zone_for_ip ---------------------------------------------------------

@pytest.mark.parametrize('zone, ip', HOSTS.items())
def test_zone_for_ip_classifies_each_host(zone, ip):
    assert zone_for_ip(ip) == zone


@pytest.mark.parametrize('zone', ZONES)
def test_zone_for_ip_subnet_boundaries(zone):
    subnet = ZONES[zone]['subnet']
    assert zone_for_ip(subnet.network_address) == zone
    assert zone_for_ip(subnet.broadcast_address) == zone
    assert zone_for_ip(ZONES[zone]['gateway']) == zone


@pytest.mark.parametrize('ip', [
    '10.1.4.1',      # just past the last internal /24
    '10.1.0.255',    # just before the first internal /24
    '8.8.8.8',
    '0.0.0.0',
    '255.255.255.255',
])
def test_zone_for_ip_outside_every_subnet_is_none(ip):
    assert zone_for_ip(ip) is None


def test_zone_for_ip_accepts_non_string_addresses():
    # controller.py passes POX IPAddr objects; anything that str()s to a
    # dotted quad should work.
    assert zone_for_ip(ipaddress.IPv4Address('10.1.3.5')) == 'DataCenter'


def test_zone_for_ip_rejects_garbage():
    with pytest.raises(ValueError):
        zone_for_ip('not-an-ip')


def test_zone_subnets_do_not_overlap():
    # zone_for_ip returns the first match, so overlapping subnets would
    # make classification depend on dict order.
    subnets = [z['subnet'] for z in ZONES.values()]
    for i, a in enumerate(subnets):
        for b in subnets[i + 1:]:
            assert not a.overlaps(b), '{} overlaps {}'.format(a, b)


def test_gateway_macs_are_unique():
    macs = [z['gateway_mac'] for z in ZONES.values()]
    assert len(macs) == len(set(macs))


# -- firewall_allowed ----------------------------------------------------

def test_expected_policy_covers_every_zone_pair():
    assert set(EXPECTED_POLICY) == {(s, d) for s in ZONES for d in ZONES}


@pytest.mark.parametrize('pair, expected', EXPECTED_POLICY.items(),
                         ids=['{}->{}'.format(*p) for p in EXPECTED_POLICY])
def test_policy_matrix(pair, expected):
    src, dst = pair
    other_allowed, icmp_allowed = expected
    assert firewall_allowed(src, dst, is_icmp=False) == other_allowed
    assert firewall_allowed(src, dst, is_icmp=True) == icmp_allowed


@pytest.mark.parametrize('src', ['Trust', 'Untrust'])
def test_llm_server_unreachable_from_outside(src):
    """The README's headline guarantee: the data center is fully
    isolated from both external zones, for every protocol."""
    assert not firewall_allowed(src, 'DataCenter', is_icmp=False)
    assert not firewall_allowed(src, 'DataCenter', is_icmp=True)


@pytest.mark.parametrize('zone', ZONES)
def test_same_zone_traffic_always_allowed(zone):
    assert firewall_allowed(zone, zone, is_icmp=False)
    assert firewall_allowed(zone, zone, is_icmp=True)


@pytest.mark.parametrize('zone', ZONES)
@pytest.mark.parametrize('is_icmp', [False, True])
def test_unknown_zone_is_default_deny(zone, is_icmp):
    # An address outside every subnet (zone None) is denied in both
    # directions, even toward zones that are otherwise wide open.
    assert not firewall_allowed(None, zone, is_icmp)
    assert not firewall_allowed(zone, None, is_icmp)
    assert not firewall_allowed(None, None, is_icmp)


def test_unrecognized_zone_name_is_denied():
    # Guards against a typo'd zone name slipping through as "no rule
    # matched, so allow".
    assert not firewall_allowed('DeptC', 'DeptA', is_icmp=False)


@pytest.mark.parametrize('ip', ['8.8.8.8', '10.1.4.1', '172.16.0.1'])
def test_unknown_ip_denied_end_to_end(ip):
    for dst in HOSTS.values():
        assert not firewall_allowed(zone_for_ip(ip), zone_for_ip(dst), is_icmp=False)
        assert not firewall_allowed(zone_for_ip(dst), zone_for_ip(ip), is_icmp=False)


# -- end to end: raw IPs -> verdict (what bench_firewall.py times) -------

@pytest.mark.parametrize('pair, expected', EXPECTED_POLICY.items(),
                         ids=['{}->{}'.format(*p) for p in EXPECTED_POLICY])
def test_ip_level_decision(pair, expected):
    src_ip, dst_ip = HOSTS[pair[0]], HOSTS[pair[1]]
    verdict = firewall_allowed(zone_for_ip(src_ip), zone_for_ip(dst_ip),
                               is_icmp=True)
    assert verdict == expected[1]

