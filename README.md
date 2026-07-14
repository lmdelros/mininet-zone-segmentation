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

## Tech Stack

- **[Mininet](http://mininet.org/)** — network emulation, defines hosts/switches/links (`topology.py`)
- **[POX](https://github.com/noxrepo/pox)** — Python-based OpenFlow SDN controller, implements the firewall/forwarding logic (`controller.py`)
- **OpenFlow 1.0** — protocol used between Mininet's virtual switches and the POX controller
- Python 3

## Project Structure

```
.
├── topology.py     # Mininet network topology (6 switches, 10 hosts)
├── controller.py   # POX controller: firewall + forwarding logic
└── README.md
```

## Setup & Usage

Requires Mininet, Open vSwitch, and a Python-3-compatible build of POX (this project targets Python 3; older POX branches like `carp` predate Python 3 support and won't run it) — typically run inside a Linux VM, since Mininet needs real Linux network namespaces.

1. Put `controller.py` where POX can find it as a component, e.g. copy it into POX's `ext/` folder:
   ```bash
   cp controller.py <path-to-pox>/ext/controller.py
   ```
2. Start the POX controller with the custom module:
   ```bash
   cd <path-to-pox> && ./pox.py controller
   ```
3. In a separate terminal, launch the topology, pointing it at the controller:
   ```bash
   sudo python3 topology.py
   ```
4. From the Mininet CLI, test connectivity between zones, e.g.:
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
