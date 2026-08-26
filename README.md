# mininet-zone-segmentation

A simulated enterprise network built with [Mininet](http://mininet.org/) and [POX](https://github.com/noxrepo/pox), implementing SDN-based routing and firewall zone segmentation between department subnets, a protected server zone, and external trust boundaries.

The network models a small company (an LLM startup) with two office floors, a data center hosting the LLM server, and explicit trusted/untrusted external zones. A custom POX controller acts as the network's router *and* firewall: it owns the gateway IP for every zone, answers ARP for those gateways, routes between zones, and enforces zone-segmentation policy while doing it — no traditional firewall appliance, no static ACLs on switches.

## Architecture

- **6 switches total:** `s1`–`s4` split each floor into two switches, `s5` fronts the data center, `s6` is the network core.
- **5 zones, 5 subnets:** Dept A (`10.1.1.0/24`, spanning `s1`+`s2`), Dept B (`10.1.2.0/24`, spanning `s3`+`s4`), Data Center (`10.1.3.0/24`), trust boundary (`192.47.38.0/24`), untrust boundary (`108.35.24.0/24`). Every host's default route points at its zone's `.1` gateway — an IP that only exists virtually, inside the controller.
- `h_trust` and `h_untrust` connect **directly** to the core switch — they represent external trust boundaries, not internal departments, so they don't sit behind a departmental switch.
- `h_server` (the LLM server) sits behind the data center switch, isolated from every other zone by policy.

## Zone & Access Policy

All enforcement happens in the POX controller (`controller.py`), which inspects each flow and either drops, floods, or forwards it based on source/destination zone.

| # | Source          | Destination         | Policy                        |
|---|------------------|----------------------|--------------------------------|
| 1 | Untrusted (`h_untrust`) | LLM server (`h_server`) | Block all IP traffic |
| 2 | Untrusted (`h_untrust`) | Any internal host (Floor 1, Floor 2, server) | Block ICMP |
| 3 | Trusted (`h_trust`)     | LLM server (`h_server`) | Block all IP traffic |
| 4 | Trusted (`h_trust`)     | Dept B (Floor 2)        | Block ICMP |
| 5 | Trusted (`h_trust`)     | Dept A (Floor 1)        | Allowed, no restriction |
| 6 | Dept A (Floor 1)        | Dept B (Floor 2)        | Block ICMP (both directions) |
| 7 | Any host                | Any host (non-IP, e.g. ARP) | Flood |
| 8 | Any host                | Any host (other IP traffic) | Forward via specific port |

The intent: the LLM server is the crown jewel and is fully isolated from both trust boundaries; the untrusted zone gets the least access of any zone; departments can be segmented from each other (ICMP block) without cutting off legitimate IP traffic needed for real services.

## C++ Firewall Daemon

The zone-firewall decision (`firewall_allowed()`: given a source zone, destination zone, and whether the packet is ICMP, allow or deny) is implemented twice:

- **Python**, in `firewall_rules.py` — the reference implementation, and the controller's fallback.
- **C++**, in `cpp/firewall_daemon.cpp` — a standalone daemon the controller talks to over a Unix domain socket.

**Why a separate process instead of a Python C extension:** a pybind11 module would have lower call overhead, but it'd be linked into the Python process rather than an independently running component — there'd be nothing to point at and say "that's the real, standalone systems code." A Unix domain socket keeps the C++ side a genuine standalone binary with its own concurrency model (thread-per-connection) and its own wire protocol (a 13-byte fixed binary request → 2-byte response, `#pragma pack(1)` on the C++ side matched byte-for-byte against Python's `struct.pack("!IIHHB", ...)`), at the cost of real IPC overhead (socket write, context switch, socket read) per decision.

That overhead is real and worth stating plainly: for a rule set this cheap (two set-membership checks), `bench_firewall.py` shows the C++ daemon is **slower per decision** than calling the Python function in-process — IPC cost dominates a computation this trivial. See [Benchmark](#benchmark) below. The controller (`controller.py`) can use either backend — flip `USE_CPP_FIREWALL` — and falls back to the Python path automatically if the daemon isn't running.

One deliberate behavior difference: the original controller classifies a packet's *source* zone by which switch port it arrived on (spoof-resistant — a host can lie about its IP, not about its physical port), while the C++ daemon classifies both source and destination zone from the IP addresses in the request, since that's all the wire protocol carries. In this topology every host's IP already falls inside its own zone's subnet, so the verdicts are identical in practice; a production version would pass the port-derived zone across the socket instead of re-deriving it from a spoofable IP.

### Building and running the daemon

```bash
cd cpp
make
./firewall_daemon &        # listens on /tmp/zone_firewall.sock
```

If your Linux VM doesn't have a C++ toolchain yet:

```bash
sudo apt-get update
sudo apt-get install -y build-essential   # provides g++ and make
```

### Benchmark

```bash
python3 bench_firewall.py   # standalone -- no Mininet/POX required, daemon must be running
```

Times the same decision (raw src/dst IP + protocol → allow/deny) end-to-end on both paths and reports mean/p50/p99 latency in microseconds, plus the ratio between them.

## Tech Stack

- **[Mininet](http://mininet.org/)** — network emulation, defines hosts/switches/links (`topology.py`)
- **[POX](https://github.com/noxrepo/pox)** — Python-based OpenFlow SDN controller, implements the firewall/forwarding logic (`controller.py`)
- **OpenFlow 1.0** — protocol used between Mininet's virtual switches and the POX controller
- **C++17** — standalone firewall daemon (`cpp/firewall_daemon.cpp`), talking to the controller over a Unix domain socket
- Python 3

## Project Structure

```
.
├── topology.py         # Mininet network topology (6 switches, 10 hosts)
├── controller.py        # POX controller: routing, ARP, firewall dispatch (Python or C++ backend)
├── firewall_rules.py     # Pure Python zone/firewall rule logic (no POX dependency)
├── firewall_client.py     # Python client for the C++ firewall daemon (Unix domain socket)
├── bench_firewall.py       # Latency benchmark: Python in-process vs. C++ daemon
├── cpp/
│   ├── firewall_daemon.cpp  # Standalone C++ firewall daemon
│   └── Makefile
└── README.md
```

## Setup & Usage

Requires Mininet, Open vSwitch, and a Python-3-compatible build of POX (this project targets Python 3; older POX branches like `carp` predate Python 3 support and won't run it) — typically run inside a Linux VM, since Mininet needs real Linux network namespaces.

1. Put `controller.py` where POX can find it as a component, e.g. copy it into POX's `ext/` folder — along with `firewall_rules.py` and `firewall_client.py`, since `controller.py` imports them as siblings:
   ```bash
   cp controller.py firewall_rules.py firewall_client.py <path-to-pox>/ext/
   ```
2. Build and start the C++ firewall daemon (see [C++ Firewall Daemon](#c-firewall-daemon) above). Skip this step if you set `USE_CPP_FIREWALL = False` in `controller.py` — it'll use the pure-Python path instead:
   ```bash
   cd cpp && make && ./firewall_daemon &
   ```
3. Start the POX controller with the custom module:
   ```bash
   cd <path-to-pox> && ./pox.py controller
   ```
4. In a separate terminal, launch the topology, pointing it at the controller:
   ```bash
   sudo python3 topology.py
   ```
5. From the Mininet CLI, test connectivity between zones, e.g.:
   ```
   mininet> h_untrust ping h_server      # should fail (rule 1)
   mininet> h101 ping h102               # should succeed (same switch)
   mininet> h_trust ping h101            # should succeed (rule 5)
   mininet> h101 ping h201               # ICMP blocked (rule 6)
   ```

## Testing & Verification

Not yet run end-to-end in Mininet — `topology.py` and `controller.py` are written and pass a static syntax check, but haven't been exercised in a live environment. Once that happens, each policy rule above should be verified via `ping`/`pingall` from the Mininet CLI in both directions per zone pair. Planned follow-up: replace manual verification with an automated test script that drives Mininet's Python API directly and asserts expected pass/fail results per zone.

## Roadmap

- Move firewall rules into a config file (YAML/JSON) instead of hardcoded IPs
- Automated test suite (see Testing & Verification above)
- Logging/metrics for rule hits and drop counts
- Containerize the environment (Docker/Vagrant) for reproducibility
- Second core switch for redundancy; NAT for external hosts
