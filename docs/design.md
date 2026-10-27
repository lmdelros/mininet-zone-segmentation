# Design notes

This document explains how the controller routes and filters traffic, why the firewall decision runs in a separate C++ process, what the benchmark measured, and which bugs the tests found. For setup and usage, see the [README](../README.md).

- [How a packet gets routed](#how-a-packet-gets-routed)
- [Firewall backends](#firewall-backends)
- [Wire protocol](#wire-protocol)
- [Anti-spoofing](#anti-spoofing)
- [Why some allowed traffic still fails: a stateless firewall](#why-some-allowed-traffic-still-fails-a-stateless-firewall)
- [Benchmark: C++ daemon vs. in-process Python](#benchmark-c-daemon-vs-in-process-python)
- [Bugs found by testing](#bugs-found-by-testing)

## How a packet gets routed

The network has no real router. Every host's default gateway (for example `10.1.1.1` for Dept A) is a virtual address that exists only inside the POX controller ([`controller.py`](../controller.py)).

1. **ARP.** Before a host's first packet to another zone, it asks "who has `10.1.1.1`?" The question reaches the controller as an OpenFlow *packet-in*, and the controller answers with a made-up gateway MAC address. The controller also records where that host lives.
2. **Packet-in on the host's own switch.** The host sends its packet to the gateway MAC. The host's switch has no rule for it, so it hands the packet to the controller.
3. **Checks.** The controller works out the source zone from the switch port the packet arrived on, drops the packet if its source IP doesn't belong to that zone ([anti-spoofing](#anti-spoofing)), and asks the firewall whether this zone pair and protocol is allowed.
4. **Routing.** If allowed, the controller decrements the TTL, rewrites the MAC addresses like a real router hop, and injects the packet at the core switch (`s6`) out the port that leads to the destination.

Host locations are stored as *core switch ports*, because routed packets always leave from the core. A host behind leaf switch `s5` is recorded as "core port 5". If the controller doesn't know where a destination is yet, it sends ARP probes into the destination zone, queues the packet, and replies with an ICMP Host Unreachable error after three failed attempts.

Packets that arrive on a leaf switch's uplink were put there by the controller or by the core's same-zone forwarding. They have already been checked at their real ingress, so they're delivered as plain layer-2 transit: no zone checks and no location learning.

Traffic within one zone is forwarded at layer 2. The controller installs an OpenFlow flow rule so later packets of that flow stay in the switch.

## Firewall backends

The firewall decision (given a source zone, destination zone, and whether the packet is ICMP: allow or deny) exists twice:

- **Python**, [`firewall_rules.py`](../firewall_rules.py): the reference implementation and the controller's fallback.
- **C++**, [`cpp/firewall_daemon.cpp`](../cpp/firewall_daemon.cpp): a standalone daemon the controller queries over a Unix domain socket.

The controller uses the daemon when `USE_CPP_FIREWALL = True` in `controller.py` (the default) and falls back to Python if the daemon isn't reachable.

**Why a separate process instead of a Python C extension?** A [pybind11](https://pybind11.readthedocs.io/) module would have lower call overhead, but it would be linked into the Python process instead of being an independent component. As a separate binary, the daemon has its own concurrency model (one thread per connection) and its own binary wire protocol, at the cost of an inter-process round trip for every decision. The [benchmark](#benchmark-c-daemon-vs-in-process-python) measures that cost.

Both implementations deny traffic to or from an address outside all five zone subnets, before any other rule is checked.

The rule tables are duplicated by hand in the two languages. [`tests/test_daemon_parity.py`](../tests/test_daemon_parity.py) compiles the daemon and checks that both give the same verdict for every zone pair and protocol, so the copies can't drift apart unnoticed.

## Wire protocol

Each request is 13 bytes and each response 2 bytes, all in network byte order. The C++ structs use `#pragma pack(1)` so their layout matches Python's `struct.pack("!IIHHB", ...)` byte for byte.

| Request field | Size | Notes |
|---|---|---|
| `src_ip` | 4 bytes | IPv4 address |
| `dst_ip` | 4 bytes | IPv4 address |
| `src_port` | 2 bytes | Carried for future port-based rules; unused today |
| `dst_port` | 2 bytes | Same |
| `protocol` | 1 byte | 1 = ICMP, 6 = TCP, 17 = UDP |

| Response field | Size | Values |
|---|---|---|
| `verdict` | 1 byte | 0 = deny, 1 = allow |
| `rule_id` | 1 byte | 0 = no rule matched (allowed), 1 = block all IP, 2 = block ICMP, 3 = unknown zone |

## Anti-spoofing

A host can put any source IP in a packet, but it can't fake which switch port it's plugged into. The controller therefore drops any IP or ARP packet whose source IP isn't inside the subnet of the zone its ingress port belongs to, or that claims a gateway IP (`source_ip_valid_for_zone()` in `firewall_rules.py`). The check runs before the controller learns anything from the packet and before it consults the firewall.

This blocks two attacks, both exercised by the live test:

- **IP spoofing:** `h_untrust` forges a Trust source IP to get Trust's more generous policy toward Dept A.
- **ARP spoofing:** a Dept A host announces `h_server`'s IP so the controller would deliver the server's traffic to it.

It also means the C++ daemon, which only sees IP addresses, always receives a source IP that agrees with the packet's real zone.

## Why some allowed traffic still fails: a stateless firewall

The firewall judges each packet on its own, with no memory of earlier packets. A ping or TCP connection works only if **both directions** are allowed. The live test's reachability matrix shows the effect:

- Dept B → Trust ICMP is allowed, but the echo reply (Trust → Dept B ICMP) is blocked by rule 4, so Dept B can't ping Trust.
- The data center can't open connections to either external zone, because the replies are blocked by rules 1 and 3.

A stateful firewall with connection tracking would let replies to allowed connections back in. It's on the roadmap.

## Benchmark: C++ daemon vs. in-process Python

[`bench_firewall.py`](../bench_firewall.py) times the same decision (raw source IP, destination IP, and protocol in, verdict out) both ways, 140,000 decisions per path. Three runs on WSL 2 (Ubuntu, Python 3.12, 12-core ARM laptop), without CPU pinning:

| Path | Median (p50) | Mean | p99 |
|---|---|---|---|
| Python, in-process | 4.9–5.6 µs | 5.6–6.6 µs | 11.8–14.2 µs |
| C++ daemon, Unix socket round trip | 12.4–55.3 µs | 34.5–67.5 µs | 203–250 µs |

The C++ path is **5–11x slower** on average. The rule check itself is two small set lookups, so the cost is dominated by the round trip: a socket write, a context switch to the daemon, and a socket read. The wide spread in the C++ numbers comes from the operating system scheduling the two processes on different cores from run to run.

The daemon would start to pay off when each decision does more work than the round trip costs: a much larger rule set, deep packet inspection, or batching many packets into one request.

```bash
cd cpp && make && ./firewall_daemon &
cd .. && python3 bench_firewall.py
```

## Bugs found by testing

- **The daemon ignored Ctrl-C and `kill`** (found by the parity tests). glibc's `signal()` installs handlers with `SA_RESTART`, so the kernel restarted the blocked `accept()` call after a signal and the shutdown flag was never checked. Fixed by installing the handlers with `sigaction()` without that flag.
- **Routed packets left through the wrong port** (found by the first live run). Host locations were recorded as leaf switch ports, but routed packets leave from the core, so traffic for `h_server` (port 1 of `s5`) went out core port 1, toward Dept A. Fixed by storing locations as core ports.
- **ICMP error messages were malformed** (found by the first live run). POX's `icmp` class packs only 4 header bytes, so the 4 unused bytes that come before the quoted IP header were missing and receivers couldn't parse the message. Fixed by wrapping the quoted header in POX's `unreach` body.
- **Anti-spoofing rejected transit traffic** (found by a live run during development, before it was committed). Packets coming down a leaf's uplink were re-checked as if a host had sent them, which flagged routed packets and the controller's own ARP probes as spoofed. Fixed by delivering uplink traffic as transit.
- **Userspace Open vSwitch drops forwarded TCP** (an environment issue, not a code bug). The userspace datapath doesn't fill in TCP checksums that the kernel leaves for the network card, so the live test turns off checksum offload on the hosts when running in that mode.
