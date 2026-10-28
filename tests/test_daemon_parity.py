"""Python vs. C++ parity: both firewalls must give the same verdicts.

Both read policy.json (Python at import, C++ through the header that
tools/gen_policy_header.py generates), so this checks the two loaders
and the two decision functions agree. Builds the daemon from a fresh
copy in a temp dir, runs it on a private socket path (so it never
touches a daemon you already have running on /tmp/zone_firewall.sock),
and checks every zone pair x protocol against firewall_rules.py.
Requires Linux (AF_UNIX + the daemon's POSIX headers) and g++; skipped
otherwise.
"""

import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

from firewall_client import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, FirewallClient
from firewall_rules import BLOCK_ALL_IP, ZONES, firewall_allowed, zone_for_ip

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith('linux') or shutil.which('g++') is None,
    reason='needs Linux and g++ to build and run the C++ daemon')

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAEMON_SRC = os.path.join(REPO_ROOT, 'cpp', 'firewall_daemon.cpp')
GENERATOR = os.path.join(REPO_ROOT, 'tools', 'gen_policy_header.py')
POLICY = os.path.join(REPO_ROOT, 'policy.json')

# Must match the kRule* constants in firewall_daemon.cpp.
RULE_NONE, RULE_BLOCK_ALL_IP, RULE_BLOCK_ICMP, RULE_UNKNOWN_ZONE = 0, 1, 2, 3


@pytest.fixture(scope='module')
def daemon_socket(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('daemon')
    binary = str(tmp / 'firewall_daemon')
    sock_path = str(tmp / 'fw.sock')

    # Compile a copy next to a freshly generated header: the compiler
    # looks for "policy_generated.h" beside the source first, so building
    # in place could pick up a stale header left in cpp/ by an old make.
    src = str(tmp / 'firewall_daemon.cpp')
    shutil.copy(DAEMON_SRC, src)
    subprocess.run([sys.executable, GENERATOR, POLICY,
                    '-o', str(tmp / 'policy_generated.h')], check=True)
    subprocess.run(['g++', '-std=c++11', '-Wall', '-Wextra', '-Werror',
                    '-O2', '-pthread', '-o', binary, src], check=True)
    proc = subprocess.Popen([binary, sock_path], stderr=subprocess.PIPE)

    deadline = time.monotonic() + 5
    while not os.path.exists(sock_path):
        if proc.poll() is not None or time.monotonic() > deadline:
            proc.kill()
            pytest.fail('daemon did not start: {}'.format(
                proc.stderr.read().decode()))
        time.sleep(0.02)

    yield sock_path

    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture
def client(daemon_socket):
    c = FirewallClient(socket_path=daemon_socket)
    yield c
    c.close()


def _sample_ip(zone):
    return str(ZONES[zone]['subnet'].network_address + 50)


ZONE_PAIRS = [(s, d) for s in ZONES for d in ZONES]
PROTOCOLS = [IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP]


@pytest.mark.parametrize('protocol', PROTOCOLS)
@pytest.mark.parametrize('src, dst', ZONE_PAIRS)
def test_cpp_matches_python(client, src, dst, protocol):
    src_ip, dst_ip = _sample_ip(src), _sample_ip(dst)
    is_icmp = protocol == IPPROTO_ICMP

    py_allowed = firewall_allowed(zone_for_ip(src_ip), zone_for_ip(dst_ip), is_icmp)
    cpp_allowed, rule_id = client.is_allowed(src_ip, dst_ip, protocol)

    assert cpp_allowed == py_allowed

    # The rule id should explain the verdict.
    if py_allowed:
        assert rule_id == RULE_NONE
    elif (src, dst) in BLOCK_ALL_IP:
        assert rule_id == RULE_BLOCK_ALL_IP
    else:
        assert rule_id == RULE_BLOCK_ICMP


@pytest.mark.parametrize('protocol', PROTOCOLS)
@pytest.mark.parametrize('zone', ZONES)
@pytest.mark.parametrize('ip', ['8.8.8.8', '10.1.4.1'])
def test_unknown_zone_denied_by_both(client, ip, zone, protocol):
    is_icmp = protocol == IPPROTO_ICMP
    known = _sample_ip(zone)
    for src, dst in [(ip, known), (known, ip)]:
        assert not firewall_allowed(zone_for_ip(src), zone_for_ip(dst), is_icmp)
        assert client.is_allowed(src, dst, protocol) == (False, RULE_UNKNOWN_ZONE)


def test_concurrent_clients(daemon_socket):
    # Daemon is thread-per-connection; several open clients must each
    # get their own correct answers.
    clients = [FirewallClient(socket_path=daemon_socket) for _ in range(8)]
    try:
        for c in clients:
            assert c.is_allowed(_sample_ip('Untrust'), _sample_ip('DataCenter'),
                                IPPROTO_TCP) == (False, RULE_BLOCK_ALL_IP)
    finally:
        for c in clients:
            c.close()


def test_malformed_short_request_closes_connection(daemon_socket):
    # Sending half a request then hanging up must not crash the daemon.
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(daemon_socket)
    s.sendall(b'\x00' * 5)
    s.close()

    c = FirewallClient(socket_path=daemon_socket)
    try:
        assert c.is_allowed('10.1.1.5', '10.1.1.6', IPPROTO_TCP) == (True, RULE_NONE)
    finally:
        c.close()
