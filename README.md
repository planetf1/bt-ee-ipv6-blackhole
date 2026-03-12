# BT/EE IPv6 PMTUD Investigation Notes

This repository tracks ongoing IPv6 MTU/PMTUD diagnostics for BT/EE paths using repeatable telemetry from `mtu_forensics_v9.py`.

The original working hypothesis was a potential IPv6 PMTUD blackhole. Current v9 evidence suggests a more nuanced position: we still monitor for faults, but we do **not** yet have definitive proof of an ISP-side RFC violation for the tested targets.

📖 **Want to run the diagnostic tool yourself? See the [Usage Guide](USAGE.md).**

---

## Current Position (March 2026)

- **Suspicion raised:** intermittent hangs and ICMP ceilings prompted a blackhole investigation.
- **What we observe now:** for most tested destinations, UDP and kernel-level TCP telemetry indicate an effective path MTU of **1500**.
- **PTB status:** in current v9 runs we have seen **no ICMPv6 Type 2 (Packet Too Big)** messages during probes.
- **Interpretation:** absence of PTB messages alone is **not** proof of breakage; on an unconstrained 1500 path, no PTB is expected.

In short: there may still be edge-case behavior worth investigating, but the latest evidence does not prove systemic BT/EE IPv6 MTU failure.

## Why v9 Is More Reliable

`mtu_forensics_v9.py` correlates three signal types:

1. **ICMP probe behavior** (reachability and packet-size tolerance).
2. **UDP DF-style probes** with PTB sniffing.
3. **TCP kernel introspection** (`TCP_INFO`) on Linux for per-destination PMTU, with MSS fallback on macOS.

For Linux/Fedora environments, v9 reads kernel PMTU from `tcp_info` (verified offset `60` for this environment), giving destination-cache visibility that simple `ping` cannot provide.

## Snapshot from `mtu_diagnostic_v9.log` / `mtu_history_v9.json`

Run timestamp: `2026-03-12 08:21:16` (host: `fedora`)

- **TCP PMTU:** `1500` (exact) across all successful TCP probes in this run.
- **MSS range observed:** approximately `1328` to `1428` depending on destination.
- **ICMP divergence:** `huggingface.co` and `aws.amazon.com` showed ICMP ceiling around `1400`, while UDP and TCP still indicated `1500` path capability.
- **PTB capture:** no inbound PTB packets seen during verify mode for tested traffic.

This pattern is consistent with ICMP policy/rate behavior and/or conservative MSS negotiation at remote edges, not necessarily a broken data-plane path.

## The PTB Question: Where Are the "Packet Too Big" Messages?

The most striking observation across all v9 runs is the **complete absence of ICMPv6 Type 2 (Packet Too Big) responses**—even when intentionally probing with oversized payloads.

This raises a critical question:

**Are ICMP Type 2 messages being filtered or rate-limited at the BT/EE edge or transit backbone?**

### Why This Matters

If `ICMPv6 Type 2` is selectively filtered while data-plane TCP/UDP traffic flows normally:

1. **PMTUD is broken by design:** Clients cannot learn path MTU constraints via the standard mechanism.
2. **Modern TCP survives but at cost:** TCP Blackhole Detection and fallback mechanisms (RFC 8305) work *eventually*, but impose real latency penalties and timeout delays.
3. **Older/embedded systems fail silently:** Many IoT, mobile, and legacy devices do not implement aggressive ICMP fallback strategies and will hang indefinitely.
4. **Conservative MSS negotiation emerges as workaround:** If endpoints cannot trust PMTUD, they negotiate smaller MSS values (1328–1348) to avoid hitting unknown ceilings. This is visible in the v9 data and represents a *symptom* of broken PMTUD, not a solution.

### What We Need to Know

We are not claiming a proof of fault—we are asking for clarity:

- **Are ICMPv6 Type 2 messages intentionally filtered?** If so, by which BT/EE network component (edge, transit, peering)?
- **If filtering is intentional, what is the documented policy?** And does it account for impact on PMTUD-dependent services?
- **If filtering is not intentional, can it be investigated?** Silent packet loss on a critical signaling protocol should be visible in BT/EE's own telemetry.

The collateral evidence—conservative MSS clamping, ICMP-only ceilings, no PTB ever observed—suggests this is structural rather than transient. **That requires an answer from the network operator.**

## Files in This Repo

- `mtu_forensics_v9.py` — current multi-protocol forensics tool.
- `mtu_diagnostic_v9.log` — human-readable execution log.
- `mtu_history_v9.json` — structured historical telemetry.
- `mtu_forensics.py`, `mtu_diagnostic.log`, `mtu_history.json` — legacy generation kept for comparison.
