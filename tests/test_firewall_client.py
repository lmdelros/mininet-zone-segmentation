"""Unit tests for firewall_client.py's wire protocol -- no daemon needed.

The client's real socket is swapped for one end of an in-memory
socketpair; the test plays the daemon on the other end, so we can check
the exact bytes sent and feed back whatever response we want.
"""

import socket
import struct

import pytest

from firewall_client import (IPPROTO_ICMP, IPPROTO_TCP, FirewallClient,
                             _REQUEST_SIZE, _RESPONSE_SIZE)


@pytest.fixture
def client_and_daemon():
    client_end, daemon_end = socket.socketpair()
    daemon_end.settimeout(2)
    client = FirewallClient(socket_path='/unused')
    client._sock = client_end  # skip the AF_UNIX connect
    yield client, daemon_end
    client.close()
    daemon_end.close()


def test_wire_sizes_match_cpp_static_asserts():
    # firewall_daemon.cpp: static_assert(sizeof(FilterRequest) == 13)
    # and static_assert(sizeof(FilterResponse) == 2).
    assert _REQUEST_SIZE == 13
    assert _RESPONSE_SIZE == 2


def test_request_bytes_are_network_byte_order(client_and_daemon):
    client, daemon = client_and_daemon
    daemon.sendall(b'\x01\x00')  # queue the reply before the call blocks

    client.is_allowed('10.1.1.101', '192.47.38.109', IPPROTO_TCP,
                      src_port=0x1234, dst_port=443)

    expected = (bytes([10, 1, 1, 101])       # src_ip
                + bytes([192, 47, 38, 109])  # dst_ip
                + b'\x12\x34'                # src_port, big-endian
                + struct.pack('!H', 443)     # dst_port
                + bytes([IPPROTO_TCP]))      # protocol
    assert daemon.recv(64) == expected


@pytest.mark.parametrize('response, expected', [
    (b'\x01\x00', (True, 0)),   # allow, no rule
    (b'\x00\x01', (False, 1)),  # deny, BLOCK_ALL_IP
    (b'\x00\x02', (False, 2)),  # deny, BLOCK_ICMP
])
def test_response_parsing(client_and_daemon, response, expected):
    client, daemon = client_and_daemon
    daemon.sendall(response)
    assert client.is_allowed('10.1.1.1', '10.1.2.1', IPPROTO_ICMP) == expected


def test_reuses_one_connection_for_many_requests(client_and_daemon):
    client, daemon = client_and_daemon
    sock = client._sock
    for _ in range(3):
        daemon.sendall(b'\x01\x00')
        client.is_allowed('10.1.1.1', '10.1.1.2', IPPROTO_TCP)
        assert len(daemon.recv(64)) == _REQUEST_SIZE
    assert client._sock is sock


def test_accepts_non_string_addresses(client_and_daemon):
    import ipaddress
    client, daemon = client_and_daemon
    daemon.sendall(b'\x01\x00')
    client.is_allowed(ipaddress.IPv4Address('10.1.1.1'),
                      ipaddress.IPv4Address('10.1.3.1'), IPPROTO_TCP)
    assert daemon.recv(64)[:8] == bytes([10, 1, 1, 1, 10, 1, 3, 1])


class _TrickleSocket:
    """Returns at most one byte per recv() -- simulates a short read."""

    def __init__(self, data):
        self._data = data

    def sendall(self, _):
        pass

    def recv(self, n):
        chunk, self._data = self._data[:1], self._data[1:]
        return chunk

    def close(self):
        pass


def test_handles_short_reads():
    client = FirewallClient(socket_path='/unused')
    client._sock = _TrickleSocket(b'\x00\x02')
    assert client.is_allowed('1.1.1.1', '2.2.2.2', IPPROTO_ICMP) == (False, 2)


def test_daemon_disconnect_raises_and_resets_socket(client_and_daemon):
    client, daemon = client_and_daemon
    daemon.close()  # daemon dies mid-session
    with pytest.raises(ConnectionError):
        client.is_allowed('10.1.1.1', '10.1.2.1', IPPROTO_TCP)
    # Dropped so the next call reconnects instead of reusing a dead fd.
    assert client._sock is None


def test_invalid_ip_raises_before_sending(client_and_daemon):
    client, daemon = client_and_daemon
    with pytest.raises(ValueError):
        client.is_allowed('10.1.1.999', '10.1.2.1', IPPROTO_TCP)
    daemon.setblocking(False)
    with pytest.raises(BlockingIOError):
        daemon.recv(64)  # nothing was written


def test_close_is_idempotent():
    client = FirewallClient(socket_path='/unused')
    client.close()
    client.close()
