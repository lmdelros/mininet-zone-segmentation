#!/usr/bin/env python3
"""Connection tracking for the zone firewall -- pure Python, no POX.

The policy rules (firewall_rules.py) decide who may *start* a
connection. This table remembers connections that were allowed to
start, so their replies can come back even when the policy blocks that
direction on its own. Example: Dept B may ping Trust, but Trust ->
Dept B ICMP is blocked by rule 4. With tracking, the echo reply to
Dept B's ping is let through, while a ping that Trust starts is still
blocked.

A connection is identified by its addresses, protocol, and ports (for
ICMP echo, the echo identifier stands in for both ports). Entries can
only be created by packets the policy allows, and the controller's
anti-spoofing check guarantees those packets' source IPs are real, so
a host can't plant an entry that opens a path into another zone.

Imported by controller.py (inside POX) and by the unit tests.
"""

import collections
import time

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8

# Forget a connection after this long without a packet reaching the
# controller in either direction. Must exceed the controller's routed
# flow-rule hard timeout (60 s): while switch rules carry a connection,
# the controller only sees its packets when those rules expire.
IDLE_TIMEOUT = 120.0  # seconds


class Flow(collections.namedtuple('Flow', 'src dst proto sport dport')):
    """One direction of a connection."""

    __slots__ = ()

    def reversed(self):
        return Flow(self.dst, self.src, self.proto, self.dport, self.sport)


# flow: the packet's Flow. may_open: the packet can start a connection.
# may_reply: the packet can be a reply to one.
TrackedPacket = collections.namedtuple('TrackedPacket', 'flow may_open may_reply')


def tracked_packet(src, dst, proto, sport=0, dport=0, icmp_type=None, icmp_id=0):
    """Describe a packet for connection tracking, or return None if its
    kind isn't tracked (e.g. ICMP errors, other IP protocols).

    TCP and UDP packets can both open connections and be replies. For
    ICMP only echo is tracked, and direction matters: an echo request
    can open a connection but never counts as a reply, and an echo
    reply can only be a reply. Without that distinction, a host could
    send an echo *request* back along a tracked ping and have it pass
    as a reply."""
    src, dst = str(src), str(dst)
    if proto in (IPPROTO_TCP, IPPROTO_UDP):
        return TrackedPacket(Flow(src, dst, proto, sport, dport), True, True)
    if proto == IPPROTO_ICMP and icmp_type == ICMP_ECHO_REQUEST:
        return TrackedPacket(Flow(src, dst, proto, icmp_id, icmp_id), True, False)
    if proto == IPPROTO_ICMP and icmp_type == ICMP_ECHO_REPLY:
        return TrackedPacket(Flow(src, dst, proto, icmp_id, icmp_id), False, True)
    return None


class ConnectionTable(object):
    """Connections that the policy allowed to start, with idle expiry."""

    def __init__(self, idle_timeout=IDLE_TIMEOUT, clock=time.monotonic):
        self._idle_timeout = idle_timeout
        self._clock = clock
        self._last_seen = {}  # Flow (opening direction) -> timestamp

    def __len__(self):
        return len(self._last_seen)

    def _alive(self, flow):
        seen = self._last_seen.get(flow)
        return seen is not None and self._clock() - seen < self._idle_timeout

    def track(self, flow):
        """Record (or refresh) a connection opened in `flow`'s direction."""
        self._last_seen[flow] = self._clock()

    def is_reply(self, flow):
        """True if `flow` answers a live tracked connection. A hit
        refreshes the connection, so replies alone keep it alive."""
        opening = flow.reversed()
        if not self._alive(opening):
            return False
        self._last_seen[opening] = self._clock()
        return True

    def expire(self):
        """Drop idle connections; returns how many were removed."""
        stale = [f for f in self._last_seen if not self._alive(f)]
        for flow in stale:
            del self._last_seen[flow]
        return len(stale)

    def check(self, policy_allowed, packet):
        """Combine the stateless policy verdict with connection state.

        Returns 'new' if the policy allows the packet (tracking it when
        it can open a connection), 'reply' if the policy blocks it but
        it answers a tracked connection, or None if it should be
        dropped. `packet` is a TrackedPacket, or None if untracked."""
        if policy_allowed:
            if packet is not None and packet.may_open:
                self.track(packet.flow)
            return 'new'
        if packet is not None and packet.may_reply and self.is_reply(packet.flow):
            return 'reply'
        return None
