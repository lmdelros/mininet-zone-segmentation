"""Unit tests for conntrack.py -- connection tracking, runs on any OS.

A fake clock drives expiry, so no test sleeps.
"""

import pytest

from conntrack import (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, IDLE_TIMEOUT,
                       IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP,
                       ConnectionTable, Flow, tracked_packet)
from firewall_rules import firewall_allowed, zone_for_ip

DEPT_B = '10.1.2.201'
TRUST = '192.47.38.109'
SERVER = '10.1.3.178'
UNTRUST = '108.35.24.113'


class FakeClock(object):
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def table(clock):
    return ConnectionTable(clock=clock)


def tcp(src, dst, sport, dport):
    return tracked_packet(src, dst, IPPROTO_TCP, sport, dport)


def echo_request(src, dst, ident):
    return tracked_packet(src, dst, IPPROTO_ICMP, icmp_type=ICMP_ECHO_REQUEST, icmp_id=ident)


def echo_reply(src, dst, ident):
    return tracked_packet(src, dst, IPPROTO_ICMP, icmp_type=ICMP_ECHO_REPLY, icmp_id=ident)


def policy(src_ip, dst_ip, is_icmp):
    return firewall_allowed(zone_for_ip(src_ip), zone_for_ip(dst_ip), is_icmp)


# -- tracked_packet ----------------------------------------------------------

@pytest.mark.parametrize('proto', [IPPROTO_TCP, IPPROTO_UDP])
def test_tcp_and_udp_can_open_and_reply(proto):
    p = tracked_packet(DEPT_B, TRUST, proto, 40000, 443)
    assert p.flow == Flow(DEPT_B, TRUST, proto, 40000, 443)
    assert p.may_open and p.may_reply


def test_echo_request_opens_but_is_never_a_reply():
    p = echo_request(DEPT_B, TRUST, 7)
    assert p.may_open and not p.may_reply


def test_echo_reply_is_only_a_reply():
    p = echo_reply(TRUST, DEPT_B, 7)
    assert p.may_reply and not p.may_open


@pytest.mark.parametrize('icmp_type', [3, 11])  # unreachable, time exceeded
def test_other_icmp_is_not_tracked(icmp_type):
    assert tracked_packet(DEPT_B, TRUST, IPPROTO_ICMP, icmp_type=icmp_type) is None


def test_other_ip_protocols_are_not_tracked():
    assert tracked_packet(DEPT_B, TRUST, 47) is None  # GRE


def test_addresses_are_normalized_to_strings():
    import ipaddress
    p = tracked_packet(ipaddress.IPv4Address(DEPT_B), TRUST, IPPROTO_TCP, 1, 2)
    assert p.flow.src == DEPT_B


# -- ConnectionTable ---------------------------------------------------------

def test_reply_to_tracked_connection(table):
    table.track(tcp(DEPT_B, TRUST, 40000, 443).flow)
    assert table.is_reply(tcp(TRUST, DEPT_B, 443, 40000).flow)


def test_reply_must_match_ports_exactly(table):
    table.track(tcp(DEPT_B, TRUST, 40000, 443).flow)
    assert not table.is_reply(tcp(TRUST, DEPT_B, 443, 40001).flow)
    assert not table.is_reply(tcp(TRUST, DEPT_B, 444, 40000).flow)


def test_same_direction_is_not_a_reply(table):
    table.track(tcp(DEPT_B, TRUST, 40000, 443).flow)
    assert not table.is_reply(tcp(DEPT_B, TRUST, 40000, 443).flow)


def test_no_reply_without_tracked_connection(table):
    assert not table.is_reply(tcp(TRUST, DEPT_B, 443, 40000).flow)


def test_connection_expires_after_idle_timeout(table, clock):
    table.track(tcp(DEPT_B, TRUST, 40000, 443).flow)
    clock.now += IDLE_TIMEOUT
    assert not table.is_reply(tcp(TRUST, DEPT_B, 443, 40000).flow)


def test_replies_keep_connection_alive(table, clock):
    table.track(tcp(DEPT_B, TRUST, 40000, 443).flow)
    reply = tcp(TRUST, DEPT_B, 443, 40000).flow
    for _ in range(3):
        clock.now += IDLE_TIMEOUT - 1
        assert table.is_reply(reply)


def test_expire_removes_only_idle_connections(table, clock):
    table.track(tcp(DEPT_B, TRUST, 1, 443).flow)
    clock.now += IDLE_TIMEOUT - 1
    table.track(tcp(DEPT_B, TRUST, 2, 443).flow)
    clock.now += 1
    assert table.expire() == 1
    assert len(table) == 1


# -- check(): policy + connection state, with the real policy ---------------

def test_dept_b_can_ping_trust_and_get_the_reply(table):
    """Rule 4 blocks Trust -> Dept B ICMP, so without tracking the echo
    reply is dropped."""
    assert table.check(policy(DEPT_B, TRUST, True), echo_request(DEPT_B, TRUST, 7)) == 'new'
    assert table.check(policy(TRUST, DEPT_B, True), echo_reply(TRUST, DEPT_B, 7)) == 'reply'


def test_trust_still_cannot_ping_dept_b_after_dept_b_pinged_it(table):
    table.check(policy(DEPT_B, TRUST, True), echo_request(DEPT_B, TRUST, 7))
    # Same echo id, but a request: it can't pass as a reply.
    assert table.check(policy(TRUST, DEPT_B, True), echo_request(TRUST, DEPT_B, 7)) is None


def test_echo_reply_with_different_id_is_dropped(table):
    table.check(policy(DEPT_B, TRUST, True), echo_request(DEPT_B, TRUST, 7))
    assert table.check(policy(TRUST, DEPT_B, True), echo_reply(TRUST, DEPT_B, 8)) is None


def test_unsolicited_echo_reply_is_dropped(table):
    assert table.check(policy(TRUST, DEPT_B, True), echo_reply(TRUST, DEPT_B, 7)) is None


@pytest.mark.parametrize('outside', [TRUST, UNTRUST])
def test_server_cannot_open_connections_outward(table, outside):
    """Rule 7: the data center can't start traffic to either outside
    zone, so no entry is created and the outside host's answer is
    dropped too."""
    assert table.check(policy(SERVER, outside, False), tcp(SERVER, outside, 40000, 443)) is None
    assert table.check(policy(outside, SERVER, False), tcp(outside, SERVER, 443, 40000)) is None
    assert len(table) == 0


@pytest.mark.parametrize('outside', [TRUST, UNTRUST])
def test_outside_cannot_open_connections_to_server(table, outside):
    assert table.check(policy(outside, SERVER, False), tcp(outside, SERVER, 40000, 22)) is None
    assert len(table) == 0


def test_allowed_both_ways_needs_no_tracking_to_pass(table):
    # Dept B <-> data center TCP is allowed in both directions by policy.
    assert table.check(policy(DEPT_B, SERVER, False), tcp(DEPT_B, SERVER, 40000, 22)) == 'new'
    assert table.check(policy(SERVER, DEPT_B, False), tcp(SERVER, DEPT_B, 22, 40000)) == 'new'


def test_untracked_packets_follow_policy_only(table):
    # An ICMP error isn't tracked: allowed only if the policy allows it.
    err = tracked_packet(TRUST, DEPT_B, IPPROTO_ICMP, icmp_type=3)
    assert table.check(True, err) == 'new'
    assert table.check(False, err) is None
    assert len(table) == 0
