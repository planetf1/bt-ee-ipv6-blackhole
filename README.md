# IPv6 PMTUD Blackhole Forensics

A lightweight, automated diagnostic tool for identifying, isolating, and logging IPv6 Path MTU Discovery (PMTUD) black holes across ISP transit networks. 

This repository contains the forensic data and tooling used to diagnose severe TCP hangs affecting AI and software engineering workflows. 

📖 **Want to run the diagnostic tool yourself? See the [Usage Guide](USAGE.md).**

## The Problem: RFC 8200 Non-Compliance

Modern dual-stack and IPv6-only environments rely on **Path MTU Discovery (PMTUD)** to negotiate packet sizes. If a packet is too large for a specific router along a path, that router must drop the packet and return an `ICMPv6 Type 2 (Packet Too Big)` message to the sender, allowing the connection to gracefully resize its payload.

**The Symptom:** Small packets (SSH, DNS) work perfectly. Large TCP streams (Docker pulls, AI model weight downloads, large JSON API responses) hang indefinitely.

**The Cause:** Upstream transit routers are routing IPv6 traffic over legacy infrastructure or tunnels, reducing the link MTU below the standard 1500 bytes. Crucially, these routers are dropping oversized packets **without returning the required ICMPv6 Type 2 errors.**

[Image of IPv6 Path MTU Discovery mechanism and ICMPv6 Type 2 error]

## March 2026 Observations

Following a complete verification of local hardware transparency (confirming a "True 1500" MTU path from the local LAN through to the ISP gateway), the following forensic data was captured. 

### 1. The "True 1500" Control Group
The following destinations successfully negotiated a full **1500-byte MTU**. This proves the local gateway and physical link are correctly configured for Baby Jumbo Frames (RFC 4638) and are **not** the source of the bottleneck:
* `api.x.ai`
* `cloudflare.com`
* `gitlab.com`
* `www.apple.com`
* `repo1.maven.org`
* `crates.io`
* `www.theguardian.com`

### 2. Verified Upstream Black Holes (Silent Drops)
These endpoints fail standard Ethernet MTU (1500 bytes). Diagnostics confirm the packets leave the local network but vanish in the transit core. Binary search calculates the effective MTU ceiling and identifies the last responding router before the "Black Hole."

| Target Domain | Path MTU | Last Responding Hop (The "Drop Hop") | Status |
| :--- | :--- | :--- | :--- |
| `huggingface.co` | **1280** | *Unknown (Silent Drop)* | **Critical** |
| `cloud.google.com` | **1280** | `2001:4860:0:1::7e80` | **Critical** |
| `www.google.com` | **1280** | `2a00:2380:2015:3000::1d` | **Critical** |
| `proxy.golang.org` | **1280** | `2a00:2380:106::99` | **Critical** |
| `pypi.org` | **1321** | `2a00:2380:106::a7` | **Anomalous** |
| `www.spotify.com` | **1372** | `2a00:2380:106::ef` | **Anomalous** |
| `news.ycombinator.com`| **1280** | `2a00:2000:2066::73` | **Critical** |
| `www.wikipedia.org` | **1280** | `2a11:4140:5002::d` | **Critical** |

### 3. Baseline Failures (Filtered/Down)
The following services are currently dropping even minimum-size (1280-byte) IPv6 probes, suggesting strict ICMPv6 filtering or service-specific IPv6 routing issues:
* `registry-1.docker.io`
* `quay.io`
* `www.netflix.com`

[Image of ICMPv6 packet headers and data payload]

## Forensic Evidence: The "Smoking Gun"

Using the `--verify-ptb` (Wiretap) mode, raw packet captures were performed on the physical interface during 1500-byte transmissions. 

**Observations:**
1. **Zero ICMPv6 Type 2 Messages:** For all "Critical" paths listed above, the local interface verified the complete absence of "Packet Too Big" responses. 
2. **Immediate Vanishing:** Traceroute diagnostics confirm that packets vanish immediately after entering specific prefixes (notably `2a00:2380::`), associated with core transit infrastructure.
3. **PMTUD Failure:** Because no PTB message is returned, the client OS continues to attempt 1500-byte transmissions, leading to the observed TCP hangs.

## Reproduction for Network Providers

To reproduce these observations from a terminal on this link:

1. **Verify Local Transparency (Success):**
   `ping6 -D -s 1452 api.x.ai` (Expected: 0% loss)

2. **Demonstrate Upstream Black Hole (Failure):**
   `ping6 -D -s 1452 huggingface.co` (Expected: 100% loss / Request Timeout)

3. **Isolate the Ceiling:**
   `ping6 -D -s 1232 huggingface.co` (Expected: 0% loss at 1280 MTU)

**Conclusion:** The infrastructure at `2a00:2380::` and related peering points is failing to signal MTU constraints via ICMPv6 Type 2, violating RFC 8200 and breaking standard Path MTU Discovery.
