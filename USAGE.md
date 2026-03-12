# MTU Forensics Script Usage (v9)

This document explains how to use `mtu_forensics_v9.py` to investigate IPv6 Path MTU Discovery (PMTUD) behavior across ICMP, UDP, and TCP.

The workflow is designed for evidence gathering: confirm what is happening on your path, then decide whether symptoms indicate a real network fault or expected endpoint/network policy.

## What v9 Does

The script runs per-target diagnostics across three protocols:

1. **ICMP test path:** baseline + ceiling check (binary-search fallback when 1500 fails).
2. **UDP test path:** sends 1500-sized probes with don't-fragment behavior and optional PTB sniffing.
3. **TCP test path:** reads negotiated MSS and path MTU from kernel state (`TCP_INFO` on Linux, MSS-derived estimate on macOS).

This multi-signal approach helps distinguish:
- ICMP control-plane quirks,
- endpoint MSS clamping,
- and genuine PMTUD breakage.

## Prerequisites & OS Support

The script auto-detects your OS (`darwin` or `linux`) and selects platform-appropriate socket and probe behavior.

* **Python 3.x** is required.
* **Root Privileges:** Required *only* if you want to use the wiretap (`--verify-ptb`) feature.

### macOS (Native)
macOS is supported out-of-the-box.

- Uses native Darwin probing behavior.
- Wiretap mode binds to `pktap,any` for inbound ICMPv6 PTB capture.
- TCP path MTU is estimated from MSS (`MSS + 60`) because exact PMTU is not exposed in the same way as Linux.

### Linux (Debian/Ubuntu/RHEL/Fedora)
Linux is fully supported and provides the strongest signal quality because v9 can read PMTU from `TCP_INFO`.

- **Dependencies:** ensure standard networking tools are installed:
  ```bash
  sudo apt update
  sudo apt install iputils-ping traceroute tcpdump
  ```

  Fedora/RHEL example equivalents are also fine (`iputils`, `traceroute`, `tcpdump`).

- Wiretap mode binds to `any` on Linux.

## Running the Diagnostics

### Standard Mode
Runs the full suite of MTU discovery, binary search, and traceroute isolation without requiring root privileges.

```bash
python3 mtu_forensics_v9.py
```

### Forensic "Wiretap" Mode (Recommended)

Spins up a background sniffer on your physical network interfaces to monitor for ICMPv6 Type 2 messages. This provides the "smoking gun" evidence that upstream routers are dropping packets silently.

```bash
sudo python3 mtu_forensics_v9.py --verify-ptb
```

### Optional Output File Overrides

```bash
python3 mtu_forensics_v9.py --log-file custom.log --json-file custom.json
```

### Outputs and Telemetry

The script prints a per-domain summary and writes two artifacts:

- `mtu_diagnostic_v9.log`: detailed run log.
- `mtu_history_v9.json`: appended structured telemetry for trend/history analysis.

## Interpreting Results (Important)

Use all three protocols together before concluding there is a blackhole:

- **If TCP PMTU is exact 1500 and UDP 1500 succeeds** while ICMP appears lower, this often indicates ICMP handling/policy differences, not necessarily broken data-plane PMTUD.
- **If PTB is not seen**, that can still be normal on an unconstrained path (no router needed to send PTB).
- **If large payloads consistently fail across protocols and no PTB is ever observed**, then a silent-drop/blackhole hypothesis becomes stronger and should be escalated with logs.

Recommended escalation bundle:
- latest `mtu_diagnostic_v9.log`
- latest `mtu_history_v9.json`
- test timestamp, source ASN/location, and affected destinations
