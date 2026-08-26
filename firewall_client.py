#!/usr/bin/env python3
"""Client for the C++ zone-firewall daemon (cpp/firewall_daemon.cpp).

Talks to the daemon over a Unix domain socket using a small fixed-size
binary protocol: a 13-byte request (src_ip, dst_ip, src_port, dst_port,
protocol -- all network byte order) gets back a 2-byte response
(verdict, rule_id). No POX dependency, so this can be imported by
controller.py (inside POX) and bench_firewall.py (standalone) alike.
"""

import ipaddress
import socket
import struct

SOCKET_PATH = "/tmp/zone_firewall.sock"

# '!' = network byte order, standard sizes, no alignment padding --
# matches the C++ side's #pragma pack(1) struct exactly, byte for byte.
_REQUEST_FMT = "!IIHHB"   # src_ip, dst_ip, src_port, dst_port, protocol
_RESPONSE_FMT = "!BB"     # verdict, rule_id
_REQUEST_SIZE = struct.calcsize(_REQUEST_FMT)
_RESPONSE_SIZE = struct.calcsize(_RESPONSE_FMT)

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17


class FirewallClient:
    """Persistent connection to the C++ firewall daemon.

    Meant to be instantiated once and reused for the caller's lifetime
    (e.g. once per ZoneRouter) rather than reconnecting per packet --
    connection setup is exactly the kind of per-call overhead this
    benchmark is trying to measure honestly, not hide.
    """

    def __init__(self, socket_path=SOCKET_PATH):
        self._socket_path = socket_path
        self._sock = None

    def _ensure_connected(self):
        if self._sock is not None:
            return
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self._socket_path)
        self._sock = sock

    def is_allowed(self, src_ip, dst_ip, protocol, src_port=0, dst_port=0):
        """Ask the daemon for a verdict.

        src_ip/dst_ip accept anything that stringifies to a dotted-quad
        (str, ipaddress.IPv4Address, or POX's IPAddr). Returns
        (allowed: bool, rule_id: int).
        """
        src_u32 = int(ipaddress.IPv4Address(str(src_ip)))
        dst_u32 = int(ipaddress.IPv4Address(str(dst_ip)))
        request = struct.pack(_REQUEST_FMT, src_u32, dst_u32,
                               src_port, dst_port, protocol)

        self._ensure_connected()
        try:
            self._sock.sendall(request)
            response = self._recv_exact(_RESPONSE_SIZE)
        except OSError:
            # Daemon restarted or the connection otherwise dropped --
            # drop the stale socket so the next call reconnects.
            self._sock = None
            raise

        verdict, rule_id = struct.unpack(_RESPONSE_FMT, response)
        return verdict == 1, rule_id

    def _recv_exact(self, n):
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = self._sock.recv(remaining)
            if not chunk:
                raise ConnectionError("firewall daemon closed the connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def close(self):
        if self._sock is not None:
            self._sock.close()
            self._sock = None
