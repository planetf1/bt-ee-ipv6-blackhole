import subprocess
import platform
import socket
import json
import os
import re
import time
import logging
import argparse
import sys
import shutil
from datetime import datetime

# --- Configuration ---
TARGET_SITES = [
    "api.openai.com",
    "api.x.ai",
    "huggingface.co",
    "cloud.google.com",
    "aws.amazon.com",
    "watsonx.ai",
    "research.ibm.com",
    "registry-1.docker.io",
    "ghcr.io",
    "quay.io",
    "pypi.org",
    "repo1.maven.org",
    "proxy.golang.org",
    "crates.io",
    "github.com",
    "api.github.com",
    "gitlab.com",
    "www.youtube.com",
    "www.netflix.com",
    "www.spotify.com",
    "www.twitch.tv",
    "www.bbc.co.uk",
    "www.theguardian.com",
    "news.ycombinator.com",
    "www.wikipedia.org",
    "www.google.com",
    "cloudflare.com",
    "www.apple.com",
]

def setup_logging(log_file):
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

def resolve_ipv6(domain):
    try:
        clean_domain = (
            domain.replace("http://", "").replace("https://", "").split("/")[0]
        )
        info = socket.getaddrinfo(clean_domain, None, socket.AF_INET6)
        return info[0][4][0]
    except socket.gaierror:
        return None

def ping_v6(ip, payload_size, os_name):
    if os_name == "darwin":
        cmd = ["ping6", "-c", "1", "-s", str(payload_size), ip]
    else:
        cmd = [
            "ping",
            "-6",
            "-M",
            "do",
            "-c",
            "1",
            "-W",
            "1",
            "-s",
            str(payload_size),
            ip,
        ]

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False

def get_blackhole_hop(ip, os_name):
    if os_name == "darwin":
        cmd = ["traceroute6", "-I", "-q", "1", "-w", "1", "-m", "20", ip, "1500"]
    else:
        # Uses -I to force ICMPv6 Echo Requests instead of UDP
        cmd = ["traceroute", "-6", "-I", "-q", "1", "-w", "1", "-m", "20", ip, "1500"]

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=30
        )

        output = result.stdout
        last_valid_ip = None
        ipv6_pattern = re.compile(r"([0-9a-fA-F:]+:[0-9a-fA-F:]+)")

        for line in output.splitlines():
            matches = ipv6_pattern.findall(line)
            if matches:
                last_valid_ip = matches[0]

        return last_valid_ip if last_valid_ip else "Unknown"

    except subprocess.TimeoutExpired:
        return "Trace Timed Out"
    except Exception as e:
        return f"Trace Failed: {str(e)}"

def verify_ptb_missing(ip, os_name):
    """
    Spins up a background sniffer to explicitly listen for ICMPv6 Type 2 packets.
    """
    interface = "any" if os_name != "darwin" else "pktap,any"

    dump_cmd = [
        "tcpdump",
        "-ni",
        interface,
        "-c",
        "1",
        "icmp6 and icmp6[0] == 2",
        "-Q",
        "in",
    ]

    try:
        sniffer = subprocess.Popen(
            dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        time.sleep(0.5)

        if os_name == "darwin":
            ping_cmd = ["ping6", "-c", "1", "-s", "1452", ip]
        else:
            ping_cmd = [
                "ping",
                "-6",
                "-M",
                "do",
                "-c",
                "1",
                "-W",
                "1",
                "-s",
                "1452",
                ip,
            ]

        subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        try:
            out, _ = sniffer.communicate(timeout=2.0)
            if out:
                return True
        except subprocess.TimeoutExpired:
            sniffer.kill()
            return False

    except Exception as e:
        logging.error(f"Packet capture failed: {e}")
        return None

def analyze_path(domain, args, os_name):
    logging.info(f"--- Initiating diagnostics for {domain} ---")

    ip = resolve_ipv6(domain)
    if not ip or ip.startswith("::ffff:"):
        logging.warning(f"[{domain}] IPv6 unavailable or IPv4-mapped. Skipping.")
        return {"domain": domain, "ip": ip, "mtu": "No IPv6", "drop_hop": None}

    logging.info(f"[{domain}] Target resolved to {ip}")

    min_payload = 1232
    max_payload = 1452
    overhead = 48

    logging.info(f"[{domain}] Testing absolute minimum IPv6 MTU (1280 bytes)...")
    if not ping_v6(ip, min_payload, os_name):
        logging.error(
            f"[{domain}] PROOF: Baseline 1280 byte packet dropped. Host is down or ICMPv6 is strictly filtered."
        )
        return {"domain": domain, "ip": ip, "mtu": "Blocked/Down", "drop_hop": "N/A"}

    logging.info(
        f"[{domain}] Baseline passed. Testing standard Ethernet MTU (1500 bytes)..."
    )
    if ping_v6(ip, max_payload, os_name):
        logging.info(
            f"[{domain}] PROOF: 1500 byte packet succeeded. The routing path and PMTUD are completely healthy."
        )
        return {"domain": domain, "ip": ip, "mtu": 1500, "drop_hop": None}

    logging.error(
        f"[{domain}] PROOF: 1500 byte packet dropped silently. PMTUD is broken on this route."
    )

    if args.verify_ptb:
        logging.info(
            f"[{domain}] [WIRETAP] Sniffing raw interface for ICMPv6 Type 2 packets..."
        )
        ptb_seen = verify_ptb_missing(ip, os_name)
        if ptb_seen is False:
            logging.critical(
                f"[{domain}] [WIRETAP] FORENSIC PROOF: Complete absence of PTB messages verified on the wire."
            )
        elif ptb_seen is True:
            logging.warning(
                f"[{domain}] [WIRETAP] ANOMALY: PTB packet was actually received, but OS dropped it."
            )

    logging.info(f"[{domain}] Cooling down local firewall state for 3 seconds...")
    time.sleep(3)

    logging.info(
        f"[{domain}] Initiating ICMPv6 traceroute to isolate the non-compliant router..."
    )
    drop_hop = get_blackhole_hop(ip, os_name)
    logging.error(f"[{domain}] PROOF: Packets vanish immediately after hop {drop_hop}.")

    logging.info(
        f"[{domain}] Executing binary search to calculate exact MTU ceiling of the broken link..."
    )
    low, high = min_payload, max_payload - 1
    best_payload = low

    while low <= high:
        mid = (low + high) // 2
        if ping_v6(ip, mid, os_name):
            best_payload = mid
            low = mid + 1
        else:
            high = mid - 1

    final_mtu = best_payload + overhead
    logging.warning(
        f"[{domain}] PROOF: Maximum allowed packet size calculated at exactly {final_mtu} bytes."
    )

    return {"domain": domain, "ip": ip, "mtu": final_mtu, "drop_hop": drop_hop}

def main():
    parser = argparse.ArgumentParser(
        description="MTU Forensics and PMTUD Diagnostic Tool"
    )
    parser.add_argument(
        "--verify-ptb",
        action="store_true",
        help="Run raw packet capture to verify absence of ICMPv6 PTB messages (Requires sudo)",
    )
    parser.add_argument(
        "--log-file",
        default="mtu_diagnostic.log",
        help="Output filename for the human-readable log",
    )
    parser.add_argument(
        "--json-file",
        default="mtu_history.json",
        help="Output filename for the JSON telemetry data",
    )
    args = parser.parse_args()

    os_name = platform.system().lower()

    # --- Pre-flight Dependency Check ---
    missing_deps = []
    if os_name == "darwin":
        if not shutil.which("ping6"): missing_deps.append("ping6")
        if not shutil.which("traceroute6"): missing_deps.append("traceroute6")
    else:
        if not shutil.which("ping"): missing_deps.append("ping")
        if not shutil.which("traceroute"): missing_deps.append("traceroute")

    if args.verify_ptb and not shutil.which("tcpdump"):
        missing_deps.append("tcpdump")

    if missing_deps:
        print(f"CRITICAL ERROR: Missing required system utilities: {', '.join(missing_deps)}")
        if os_name != "darwin":
            print("-> Fix on Debian/Ubuntu with: sudo apt install iputils-ping traceroute tcpdump")
        sys.exit(1)

    if args.verify_ptb and os.geteuid() != 0:
        print(
            "ERROR: The --verify-ptb flag requires raw socket access. Please run with sudo."
        )
        sys.exit(1)

    setup_logging(args.log_file)

    logging.info("===================================================")
    logging.info("Starting scheduled MTU and PMTUD diagnostic routine")
    logging.info("===================================================")

    scan_results = []

    for domain in TARGET_SITES:
        result = analyze_path(domain, args, os_name)
        scan_results.append(result)
        time.sleep(1.0)

    scan_results.sort(key=lambda x: (isinstance(x["mtu"], int), x["mtu"]), reverse=True)

    run_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": scan_results,
    }

    history = []
    if os.path.exists(args.json_file):
        with open(args.json_file, "r") as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                pass

    history.append(run_data)
    with open(args.json_file, "w") as f:
        json.dump(history, f, indent=2)

    logging.info(f"Diagnostic routine complete. Telemetry saved to {args.json_file}")

if __name__ == "__main__":
    main()
