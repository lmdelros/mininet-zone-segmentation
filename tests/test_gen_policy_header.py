"""Unit tests for tools/gen_policy_header.py. Whether the generated C++
gives the same verdicts as Python is checked by test_daemon_parity.py."""

import ipaddress
import os
import subprocess
import sys

import pytest

from firewall_rules import POLICY_PATH, PolicyError, load_policy

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, 'tools'))
from gen_policy_header import render  # noqa: E402

GENERATOR = os.path.join(REPO_ROOT, 'tools', 'gen_policy_header.py')


def zone(subnet, mac):
    net = ipaddress.ip_network(subnet)
    return {'subnet': net, 'gateway': str(net.network_address + 1), 'gateway_mac': mac}


def test_shipped_policy_renders_every_zone_and_rule():
    zones, block_all, block_icmp = load_policy(POLICY_PATH)
    header = render(zones, block_all, block_icmp)
    assert 'enum class Zone : uint8_t { DeptA, DeptB, DataCenter, Trust, Untrust, Unknown };' in header
    assert 'constexpr size_t kBlockAllIpCount = {};'.format(len(block_all)) in header
    assert 'constexpr size_t kBlockIcmpCount = {};'.format(len(block_icmp)) in header
    assert '{Zone::Trust, 0xC02F2600u, 24, "Trust"},  // 192.47.38.0/24' in header


@pytest.mark.parametrize('name', ['Dept-A', '2ndFloor', 'Unknown'])
def test_zone_names_must_be_usable_in_cpp(name):
    zones = {name: zone('10.0.1.0/24', '02:00:00:00:00:01')}
    with pytest.raises(PolicyError, match='C\\+\\+ identifier'):
        render(zones, set(), set())


def test_empty_rule_table_still_compiles_as_cpp():
    header = render({'A': zone('10.0.1.0/24', '02:00:00:00:00:01')}, set(), set())
    assert 'kBlockIcmp[1] = {};' in header
    assert 'constexpr size_t kBlockIcmpCount = 0;' in header


def test_output_file_is_only_rewritten_when_content_changes(tmp_path):
    out = tmp_path / 'policy_generated.h'
    cmd = [sys.executable, GENERATOR, POLICY_PATH, '-o', str(out)]
    subprocess.run(cmd, check=True)
    os.utime(out, (1, 1))  # an old timestamp, easy to spot if touched
    subprocess.run(cmd, check=True)
    assert out.stat().st_mtime == 1


def test_bad_policy_fails_the_build_with_a_message(tmp_path):
    bad = tmp_path / 'policy.json'
    bad.write_text('{"zones": {}}')
    result = subprocess.run([sys.executable, GENERATOR, str(bad)],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert 'policy error' in result.stderr
