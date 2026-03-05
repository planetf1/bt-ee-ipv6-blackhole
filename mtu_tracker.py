import subprocess
import platform
import socket
import concurrent.futures
import json
import os
import re
from datetime import datetime

HISTORY_FILE = "mtu_history.json"

TARGET_SITES = [
    # AI Models, Agents & APIs
    "api.openai.com",  # OpenAI endpoints
    "chatgpt.com",  # ChatGPT web interface
    "huggingface.co",  # Model weights and datasets
    "x.com",  # Grok / Twitter ecosystem
    "cloud.google.com",  # Vertex AI and GCP infrastructure
    "aws.amazon.com",  # Bedrock and AWS infrastructure
    # Software Engineering & Repositories
    "www.ibm.com",  # Corporate and research infrastructure
    "github.com",  # Source control (Web)
    "api.github.com",  # GitHub Actions and API
    "gitlab.com",  # Alternative source control
    "pypi.org",  # Python package registry
    "crates.io",  # Rust package registry
    "go.dev",  # Go modules and documentation
    "hub.docker.com",  # Container images
    "stackoverflow.com",  # Developer Q&A
    # Media, Video & Music
    "www.youtube.com",  # Video streaming
    "music.youtube.com",  # Music streaming
    "www.netflix.com",  # Video streaming
    "www.spotify.com",  # Music streaming
    "www.twitch.tv",  # Live streaming
    # UK News & General Browsing
    "www.bbc.co.uk",  # UK News and iPlayer
    "www.theguardian.com",  # UK News
    "www.reddit.com",  # Forums and discussion
    "news.ycombinator.com",  # Hacker News
    "www.wikipedia.org",  # Reference
    # Core Infrastructure & Comms
    "www.google.com",  # Search
    "cloudflare.com",  # Edge routing
    "www.apple.com",  # macOS ecosystem
    "slack.com",  # Team communication
    "discord.com",  # Community communication
]


def resolve_ipv6(domain):
    try:
        info = socket.getaddrinfo(domain, None, socket.AF_INET6)
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
    """Fires a massive 1500-byte trace to find the exact router dropping the packet."""
    if os_name == "darwin":
        # macOS uses traceroute6. -I forces ICMPv6 to match our ping tests.
        cmd = ["traceroute6", "-I", "-q", "1", "-w", "1", "-m", "20", ip, "1500"]
    else:
        # Linux traceroute. -M do prevents local fragmentation.
        cmd = ["traceroute", "-6", "-q", "1", "-w", "1", "-m", "20", ip, "1500"]

    try:
        output = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, universal_newlines=True
        )
        last_valid_ip = None

        # Regex to match IPv6 addresses in the traceroute output
        ipv6_pattern = re.compile(r"([0-9a-fA-F:]+:[0-9a-fA-F:]+)")

        for line in output.splitlines():
            # Stop updating if we hit consecutive timeouts
            if "* * *" in line or line.strip().endswith("*"):
                break

            matches = ipv6_pattern.findall(line)
            if matches:
                last_valid_ip = matches[0]

        return last_valid_ip if last_valid_ip else "Unknown (Local Drop)"
    except Exception:
        return "Trace Failed"


def find_path_mtu(domain):
    os_name = platform.system().lower()
    ip = resolve_ipv6(domain)

    if not ip:
        return {"domain": domain, "ip": None, "mtu": "No IPv6", "drop_hop": None}

    min_payload = 1232
    max_payload = 1452
    overhead = 48

    # 1. Check if the baseline minimum works.
    if not ping_v6(ip, min_payload, os_name):
        return {"domain": domain, "ip": ip, "mtu": "Blocked/Down", "drop_hop": "N/A"}

    # 2. Check if the full 1500 works.
    if ping_v6(ip, max_payload, os_name):
        return {"domain": domain, "ip": ip, "mtu": 1500, "drop_hop": None}

    # 3. If 1500 fails, we have a black hole. Find the drop hop.
    drop_hop = get_blackhole_hop(ip, os_name)

    # 4. Binary Search for the exact workable MTU
    low = min_payload
    high = max_payload - 1
    best_payload = low

    while low <= high:
        mid = (low + high) // 2
        if ping_v6(ip, mid, os_name):
            best_payload = mid
            low = mid + 1
        else:
            high = mid - 1

    return {
        "domain": domain,
        "ip": ip,
        "mtu": best_payload + overhead,
        "drop_hop": drop_hop,
    }


def main():
    # Use standard 24-hour clock and YYYY-MM-DD format
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Starting scan at {timestamp}...\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        scan_results = list(executor.map(find_path_mtu, TARGET_SITES))

    # Sort by MTU (highest first)
    scan_results.sort(key=lambda x: (isinstance(x["mtu"], int), x["mtu"]), reverse=True)

    # Print terminal output
    print(f"{'Domain':<20} | {'Max MTU':<12} | {'Blackhole Router (Last Hop)'}")
    print("-" * 75)
    for res in scan_results:
        mtu_str = (
            f"{res['mtu']} bytes" if isinstance(res["mtu"], int) else str(res["mtu"])
        )
        hop_str = res["drop_hop"] if res["drop_hop"] else "Clean Path"
        print(f"{res['domain']:<20} | {mtu_str:<12} | {hop_str}")

    # Append to JSON file
    run_data = {"timestamp": timestamp, "results": scan_results}

    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                pass

    history.append(run_data)

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

    print(f"\nScan complete. Results appended to {HISTORY_FILE}")


if __name__ == "__main__":
    main()
