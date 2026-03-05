# MTU Forensics Script Usage

This document details how to use the `mtu_forensics.py` script to diagnose IPv6 Path MTU Discovery (PMTUD) issues and silent black holes.

## What the Script Does

The script automates a sequence of network forensics against a predefined list of target domains (focused heavily on AI endpoints, container registries, and developer tooling):

1. **Baseline Test (1280 bytes):** Verifies the endpoint is reachable via IPv6 and accepts the absolute minimum required IPv6 MTU.
2. **Standard MTU Test (1500 bytes):** Verifies if a standard 1500-byte payload can successfully traverse the entire route without fragmentation.
3. **Blackhole Isolation (Traceroute):** If the 1500-byte payload drops silently, it performs an ICMPv6 traceroute using oversized packets to identify the exact router hop where the packet vanishes.
4. **Binary Search MTU Calculation:** Automatically calculates the exact maximum packet size the broken link will accept before dropping.
5. **Wiretap Verification (Optional):** Uses raw socket sniffing (`tcpdump`) to definitively prove whether the transit router is returning the required `ICMPv6 Type 2 (Packet Too Big)` messages.

## Prerequisites & OS Support

The Python script natively auto-detects your operating system (`darwin` vs `linux`) and adjusts its underlying shell commands accordingly. 

* **Python 3.x** is required.
* **Root Privileges:** Required *only* if you want to use the wiretap (`--verify-ptb`) feature.

### macOS (Native)
macOS environments are fully supported out-of-the-box. The script utilizes native Darwin networking binaries (`ping6` and `traceroute6`).
* *Note: The wiretap feature automatically binds to the `pktap,any` pseudo-interface to guarantee capture across all logical and physical interfaces.*

### Linux (Debian/Ubuntu/RHEL)
Linux environments are fully supported, but require standard networking utilities to be installed. The script dynamically switches to `ping -6` and `traceroute -6` with specific flags for the Linux IP stack.
* **Dependencies:** Ensure the following packages are installed:
  ```bash
  sudo apt update
  sudo apt install iputils-ping traceroute tcpdump
  ```
* *Note: The wiretap feature binds to the `any` interface on Linux.*

## Running the Diagnostics

### Standard Mode
Runs the full suite of MTU discovery, binary search, and traceroute isolation without requiring root privileges.

```bash
python3 mtu_forensics.py
```

### Forensic "Wiretap" Mode (Recommended)

Spins up a background sniffer on your physical network interfaces to monitor for ICMPv6 Type 2 messages. This provides the "smoking gun" evidence that upstream routers are dropping packets silently.

```bash
sudo python3 mtu_forensics.py --verify-ptb
```

### Outputs and Telemetry

The script outputs real-time forensic data to the console and generates two files in the execution directory:

* `mtu_diagnostic.log`: A detailed, human-readable execution log containing all routing decisions, drop hops, and binary search results.
* `mtu_history.json`: A structured telemetry file containing historical scan data, sorted by the severity of the MTU restriction. Useful for long-term monitoring or programmatic analysis.
