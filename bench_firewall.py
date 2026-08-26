#!/usr/bin/env python3
"""Benchmark: in-process Python firewall_allowed() (firewall_rules.py)
vs. the C++ daemon over a Unix domain socket (cpp/firewall_daemon.cpp),
for the same set of zone-firewall decisions.

Standalone -- no Mininet or POX needed. Start the daemon first:

    cd cpp && make && ./firewall_daemon &
    python3 bench_firewall.py

Both paths are timed end-to-end from raw packet fields (src IP, dst IP,
protocol) to a verdict, so the comparison is apples-to-apples: zone
classification is included in both timings, not just the rule lookup.
"""

import statistics
import time

from firewall_rules import zone_for_ip, firewall_allowed
from firewall_client import FirewallClient, IPPROTO_ICMP

# A representative mix of cross-zone decisions covering every rule in
# the policy table (README.md), so neither path always takes the same
# branch. (src_ip, dst_ip, protocol)
SAMPLE_PACKETS = [
    ("108.35.24.113", "10.1.3.178", 6),   # untrust -> DC, TCP: blocked (rule 1)
    ("108.35.24.113", "10.1.1.101", 1),   # untrust -> DeptA, ICMP: blocked (rule 2)
    ("192.47.38.109", "10.1.3.178", 6),   # trust -> DC, TCP: blocked (rule 3)
    ("192.47.38.109", "10.1.2.201", 1),   # trust -> DeptB, ICMP: blocked (rule 4)
    ("192.47.38.109", "10.1.1.101", 6),   # trust -> DeptA: allowed (rule 5)
    ("10.1.1.101", "10.1.2.201", 1),      # DeptA -> DeptB, ICMP: blocked (rule 6)
    ("10.1.1.101", "10.1.2.201", 6),      # DeptA -> DeptB, TCP: allowed (rule 8)
]

ITERATIONS = 20000  # per sample packet, so total decisions = ITERATIONS * len(SAMPLE_PACKETS)


def bench_python():
    samples = []
    for _ in range(ITERATIONS):
        for src_ip, dst_ip, protocol in SAMPLE_PACKETS:
            is_icmp = protocol == IPPROTO_ICMP
            start = time.perf_counter()
            src_zone = zone_for_ip(src_ip)
            dst_zone = zone_for_ip(dst_ip)
            firewall_allowed(src_zone, dst_zone, is_icmp)
            samples.append(time.perf_counter() - start)
    return samples


def bench_cpp():
    client = FirewallClient()
    samples = []
    for _ in range(ITERATIONS):
        for src_ip, dst_ip, protocol in SAMPLE_PACKETS:
            start = time.perf_counter()
            client.is_allowed(src_ip, dst_ip, protocol)
            samples.append(time.perf_counter() - start)
    client.close()
    return samples


def report(name, samples_seconds):
    us = sorted(s * 1e6 for s in samples_seconds)
    mean = statistics.mean(us)
    p50 = us[len(us) // 2]
    p99 = us[int(len(us) * 0.99)]
    print("{:>22}: mean={:9.3f}us  p50={:9.3f}us  p99={:9.3f}us  n={}".format(
        name, mean, p50, p99, len(us)))
    return mean


def main():
    total = ITERATIONS * len(SAMPLE_PACKETS)
    print("Running {} decisions per path...\n".format(total))

    py_mean = report("Python (in-process)", bench_python())

    try:
        cpp_mean = report("C++ (UDS round trip)", bench_cpp())
    except OSError as exc:
        print("\nCould not reach the C++ daemon at /tmp/zone_firewall.sock: {}".format(exc))
        print("Start it first: cd cpp && make && ./firewall_daemon &")
        return

    ratio = cpp_mean / py_mean
    print("\nC++ daemon is {:.1f}x the per-decision latency of in-process Python.".format(ratio))
    print("Expected direction: this ruleset is two small set-membership checks, so")
    print("IPC (socket write + context switch + socket read) costs more than the")
    print("computation it wraps saves. The C++ path would start winning once the")
    print("per-decision work is heavier than the IPC cost -- e.g. deep packet")
    print("inspection, a much larger rule set, or batching many packets per call.")


if __name__ == "__main__":
    main()
