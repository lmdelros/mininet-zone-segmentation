# Design notes

This document explains how the controller routes and filters traffic, why the firewall decision runs in a separate C++ process, what the benchmark measured, and which bugs the tests found. For setup and usage, see the [README](../README.md).

- [How a packet gets routed](#how-a-packet-gets-routed)
- [Flow rules for routed traffic](#flow-rules-for-routed-traffic)
- [Firewall backends](#firewall-backends)
- [Wire protocol](#wire-protocol)
- [Anti-spoofing](#anti-spoofing)
- [Connection tracking](#connection-tracking)
- [Benchmark: C++ daemon vs. in-process Python](#benchmark-c-daemon-vs-in-process-python)
- [Bugs found by testing](#bugs-found-by-testing)

## How a packet gets routed

The network has no real router. Every host's default gateway (for example `10.1.1.1` for Dept A) is a virtual address that exists only inside the POX controller ([`controller.py`](../controller.py)).

1. **ARP.** Before a host's first packet to another zone, it asks "who has `10.1.1.1`?" The question reaches the controller as an OpenFlow *packet-in*, and the controller answers with a made-up gateway MAC address. The controller also records where that host lives.
2. **Packet-in on the host's own switch.** The host sends its packet to the gateway MAC. The host's switch has no rule for it, so it hands the packet to the controller.
3. **Checks.** The controller works out the source zone from the switch port the packet arrived on, drops the packet if its source IP doesn't belong to that zone ([anti-spoofing](#anti-spoofing)), and asks the firewall whether this zone pair and protocol is allowed. A blocked packet still passes if it's a reply to a connection the firewall allowed ([connection tracking](#connection-tracking)).
4. **Routing.** If allowed, the controller decrements the TTL, rewrites the MAC addresses like a real router hop, and injects the packet at the core switch (`s6`) out the port that leads to the destination. It also installs switch rules so the rest of the connection skips steps 2–4 ([below](#flow-rules-for-routed-traffic)).

Host locations are stored as *core switch ports*, because routed packets always leave from the core. A host behind leaf switch `s5` is recorded as "core port 5". If the controller doesn't know where a destination is yet, it sends ARP probes into the destination zone, queues the packet, and replies with an ICMP Host Unreachable error after three failed attempts.

Packets that arrive on a leaf switch's uplink were put there by the controller or by the core's same-zone forwarding. They have already been checked at their real ingress, so they're delivered as plain layer-2 transit: no zone checks and no location learning.

Traffic within one zone is forwarded at layer 2. The controller installs an OpenFlow flow rule so later packets of that flow stay in the switch.

## Flow rules for routed traffic

Without switch rules, every routed packet would make the trip in steps 2–4: switch to controller, a firewall round trip to the C++ daemon, and back out. The controller is a single Python process, so it caps throughput.

When the controller allows a routed packet, it installs two OpenFlow rules for that packet's connection:

- **Core switch:** rewrite the source MAC to the destination zone's gateway and the destination MAC to the destination host, decrement the TTL, and send the packet out the port toward the destination. OpenFlow 1.0 has no TTL action, so this uses Open vSwitch's Nicira `dec_ttl` extension.
- **Sender's leaf switch** (when the sender isn't directly on the core): send the connection's packets up the uplink to the core.

The destination's leaf already gets a rule from the transit handling described above.

Each rule matches the exact connection: ingress port, MAC addresses, IP addresses, protocol, and TCP/UDP ports or ICMP type. A spoofed packet carries a different source IP, so it doesn't match an allowed connection's rules and still reaches the controller's anti-spoofing check. Rules expire after 30 seconds idle or 60 seconds total, so even a long-lived connection goes back through the firewall once a minute.

The live test checks the result directly: the core holds a rule with `dec_ttl` for a routed connection, that rule's packet counter shows the switch forwarded later packets itself, and every ping reply arrives with TTL 63 (sent as 64, one router hop).

**Results.** [`integration/perf_test.py`](../integration/perf_test.py) measures `h201 → h_server` (routed) and `h101 → h103` (same zone, across the core). Both paths cross three switches. Each row is one run in Docker on WSL 2, with throughput as the median of three 10-second iperf3 runs and latency as the average of 20 pings:

| Run | Routed throughput | Same-zone throughput | Routed as % of same zone | Routed ping avg |
|---|---|---|---|---|
| Before, run 1 | 14.9 Mbit/s | 425 Mbit/s | 3.5% | 9.6 ms |
| Before, run 2 | 18.7 Mbit/s | 221 Mbit/s | 8.5% | 9.1 ms |
| After, run 1 | 616 Mbit/s | 618 Mbit/s | 100% | 2.5 ms |
| After, run 2 | 199 Mbit/s | 214 Mbit/s | 93% | 0.9 ms |

Absolute throughput swings between runs on this machine (same-zone traffic, whose code didn't change, ranged from 214 to 618 Mbit/s), so the fair comparison is routed vs. same-zone within a run. Routed traffic went from 4–9% of same-zone throughput to 93–100%. In the two runs with similar conditions (same-zone about 215–220 Mbit/s), routed throughput went from 18.7 to 199 Mbit/s, about 11x. Worst-case routed ping dropped from 38–48 ms to 3–5 ms.

**Drop rules for blocked traffic.** When the controller blocks a connection, it installs a rule with no actions (OpenFlow's way of saying "drop") on the switch the packet entered, matching the exact connection. The rest of a blocked flood dies at the attacker's own switch instead of costing the controller a firewall check and a log line per packet.

These rules expire sooner than routed ones: after 10 seconds idle or 30 seconds total. Blocked traffic is never legitimate, so a short rule costs little, and it limits one edge case: if the other side later opens a connection that reuses exactly the same addresses and ports, its replies would hit the drop rule until it expires. Packets dropped for spoofing don't get drop rules, so each one is still logged as a security warning.

In the flood test (`perf_test.py`, 500 pings from `h_untrust` to `h_server` at 2 ms intervals), **500 of 500** blocked packets reached the controller before this change and **1 of 500** after. The live test clears any existing rule for that connection, floods 200 blocked pings, and checks that the first one reaches the controller, at most 10 do, and the attacker's switch holds the drop rule.

## Firewall backends

The firewall decision (given a source zone, destination zone, and whether the packet is ICMP: allow or deny) exists twice:

- **Python**, [`firewall_rules.py`](../firewall_rules.py): the reference implementation and the controller's fallback.
- **C++**, [`cpp/firewall_daemon.cpp`](../cpp/firewall_daemon.cpp): a standalone daemon the controller queries over a Unix domain socket.

The controller uses the daemon when `USE_CPP_FIREWALL = True` in `controller.py` (the default) and falls back to Python if the daemon isn't reachable.

**Why a separate process instead of a Python C extension?** A [pybind11](https://pybind11.readthedocs.io/) module would have lower call overhead, but it would be linked into the Python process instead of being an independent component. As a separate binary, the daemon has its own concurrency model (one thread per connection) and its own binary wire protocol, at the cost of an inter-process round trip for every decision. The [benchmark](#benchmark-c-daemon-vs-in-process-python) measures that cost.

Both implementations deny traffic to or from an address outside all five zone subnets, before any other rule is checked.

Both give a stateless verdict for one packet. The controller layers [connection tracking](#connection-tracking) on top, so the daemon and its wire protocol didn't need to change.

**One policy file.** Both implementations get their zones and rules from [`policy.json`](../policy.json). The Python side loads it at import through `load_policy()`, which rejects a broken file instead of running with it:
- malformed subnets, gateways or MAC addresses, or a gateway outside its own subnet;
- overlapping subnets or duplicate gateway MACs, which would make routing ambiguous;
- a rule naming a zone that doesn't exist (a typo would otherwise make the rule silently block nothing), or an unknown block type.

The C++ daemon doesn't parse JSON. At build time, `make` runs [`tools/gen_policy_header.py`](../tools/gen_policy_header.py), which reads the file through the same `load_policy()` and writes `cpp/policy_generated.h`: the zone enum, subnet table and block-rule tables, compiled straight into the daemon. This keeps the daemon free of dependencies and puts both languages behind one validation step. The cost is that a policy change needs a rebuild, which `make` handles; the generator only rewrites the header when the policy changed, so unchanged builds don't recompile. The header is generated, not committed.

[`tests/test_daemon_parity.py`](../tests/test_daemon_parity.py) builds the daemon from a freshly generated header and checks it gives the same verdict as Python for every zone pair and protocol, which tests both loaders and both decision functions together.

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

## Connection tracking

The policy rules decide who may **start** a connection. [`conntrack.py`](../conntrack.py) remembers connections they allowed, so replies get back in even where a rule blocks that direction. Without it, a connection works only if both directions are allowed: Dept B → Trust ICMP is allowed, but rule 4 blocks Trust → Dept B ICMP, so Dept B's pings went unanswered.

For each IP packet that crosses zones, the controller gets the stateless verdict from the firewall and then asks the connection table:

- **Allowed by the rules:** route it. If it can start a connection, record it.
- **Blocked by the rules, but a reply to a recorded connection:** route it.
- **Anything else:** drop it.

A connection is identified by source and destination IP, protocol, and TCP/UDP ports, or the echo identifier for ping. A reply must match the recorded connection exactly, with addresses and ports swapped.

**Ping direction matters.** Any TCP or UDP packet can start a connection or be a reply. For ICMP, only an echo request can start one and only an echo reply can answer it. Otherwise, after Dept B pings Trust, Trust could send an echo *request* with the same identifier and have it pass as a reply. ICMP error messages aren't tracked; they follow the rules alone.

**Entries can't be planted.** An entry is created only by a packet the rules allow, from the side allowed to start the connection. Anti-spoofing runs first, so that packet's source IP is guaranteed to belong to the zone it came from. An outside host can't create an entry that would open a path into a protected zone.

**Expiry.** An entry is forgotten after 120 seconds without a packet of the connection reaching the controller, in either direction. While flow rules carry a connection, the controller only sees its packets when those rules expire (at most 60 seconds), so active connections stay recorded. A timer clears expired entries every 30 seconds to free memory; lookups check expiry themselves.

**Isolating the server needed its own rule.** Before tracking, the data center could send to Trust and Untrust but never got replies, which isolated it in practice. Tracking would have let those replies in, so rule 7 now blocks the data center from starting traffic to either outside zone.

**Known limitation.** Replies get flow rules like any routed traffic, and OpenFlow 1.0 rules can't match the echo identifier. Once a ping's reply rule is installed, any echo reply between those two hosts passes for up to 60 seconds, not only replies to that ping. The controller's own check is exact, and TCP and UDP rules match ports exactly, so this affects only echo replies.

The live test checks both sides: Dept B can ping Trust and Dept A can ping Untrust, while Trust and Untrust still can't start those pings.

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
