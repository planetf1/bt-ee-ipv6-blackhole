# IPv6 PMTUD Blackhole Forensics

A lightweight, automated diagnostic tool for identifying, isolating, and logging IPv6 Path MTU Discovery (PMTUD) black holes across ISP transit networks. 

This script is specifically tuned for AI and software engineering workflows, targeting container registries, language package managers, and AI model endpoints where large payload transfers are highly susceptible to MTU-related TCP hangs.

## The Hypothesis & The Problem

Modern dual-stack and IPv6-only environments rely on **Path MTU Discovery (PMTUD)** to negotiate packet sizes. If a packet is too large for a specific router along a path, that router must drop the packet and return an `ICMPv6 Type 2 (Packet Too Big)` message to the sender, allowing the connection to gracefully resize its payload.



However, many major transit ISPs are routing IPv6 traffic over legacy infrastructure or IPv6-in-IPv4 tunnels. This reduces the link MTU below the standard 1500 bytes. Crucially, misconfigured routers on these peering links are dropping oversized packets **but failing to return the required ICMPv6 Type 2 errors.**

**The Result:** Small packets (like standard web browsing or SSH) work perfectly. Large TCP streams (like pulling a Docker image layer, downloading model weights, or fetching large JSON payloads from AI APIs) hang indefinitely without error.

This tool automatically performs binary search MTU discovery and raw wire sniffing to definitively prove RFC 8200 non-compliance on upstream ISP routers.

## Repository Contents
* [`mtu_forensics.py`](./mtu_forensics.py) - The primary diagnostic and packet-sniffing script.
* [`mtu_diagnostic.log`](./mtu_diagnostic.log) - Human-readable forensic output from the latest run.
* [`mtu_history.json`](./mtu_history.json) - Machine-readable JSON telemetry mapping the exact MTU boundaries and broken routing nodes.

## Setup and Installation

This tool requires Python 3. No external third-party libraries are required, keeping the environment clean.

**1. Clone the repository and navigate to the directory:**
bash
git clone https://github.com/yourusername/ipv6-pmtud-forensics.git
cd ipv6-pmtud-forensics


**2. Create and activate a Python virtual environment:**
*For macOS / Linux:*
bash
python3 -m venv .venv
source .venv/bin/activate


**3. Execution Modes:**
* **Standard Mode (User Space):** Maps out the broken paths and calculates MTU limits.
    bash
    python mtu_forensics.py
    
* **Forensic Mode (Requires Root):** Activates raw interface sniffing to generate definitive proof of missing ICMPv6 packets.
    bash
    sudo python mtu_forensics.py --verify-ptb
    

---

## Latest Findings (2026-03-03 22:21)

Extensive diagnostics run against a UK-based FTTP connection revealed systemic PMTUD failures isolated entirely to the ISP core network.

### 1. The "Smoking Gun" (Wiretap Verification)
Using the `--verify-ptb` flag, the script bound to the local interface (`tcpdump -ni any -c 1 icmp6 and icmp6[0] == 2`) and verified the complete absence of ICMPv6 Type 2 messages on the wire when transmitting 1500-byte packets to failing routes. The local network and firewall configuration were cleared of fault; the packets are being silently dropped by upstream infrastructure.

### 2. Verified Black Holes (AI & Cloud Infrastructure)
Traffic directed to major AI and cloud providers is hitting unadvertised tunnels (dropping the MTU to 1280 bytes) deep inside the ISP core. The following routers were caught silently dropping traffic without ICMPv6 responses:
* **Google Cloud & GCP:** Fails at `2a00:2380:2001:7000::19` and `2a00:2380:2010:3000::3d`
* **AWS / Amazon:** Fails at `2a01:578:0:12::44`
* **Go Modules (`proxy.golang.org`):** Fails at `2001:4860:0:1::632`
* **HuggingFace:** Upstream failure confirmed by missing PTB on the wire.

### 3. Clean 1500-Byte Paths
Not all peering links are broken. Full 1500-byte frames successfully negotiated the ISP transit network to the following destinations, proving the local equipment handles standard MTUs flawlessly:
* `api.x.ai`
* `gitlab.com`
* `cloudflare.com`
* `www.apple.com`
* `repo1.maven.org`

### 4. IPv4 Fallback
Several critical services currently do not resolve AAAA records from this location, falling back to IPv4. This bypasses the IPv6 MTU black hole entirely, masking the routing degradation on dual-stack machines. These include:
* `watsonx.ai`
* `research.ibm.com`
* `github.com` and `api.github.com`
* `ghcr.io`
