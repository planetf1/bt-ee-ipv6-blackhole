import subprocess
import platform
import socket
import json
import os
import time
import logging
import argparse
import sys
from datetime import datetime

# --- Restored IPv6-Capable Configuration ---
TARGET_SITES = [
    "api.x.ai",
    "huggingface.co",
    "cloud.google.com",
    "aws.amazon.com",
    "registry-1.docker.io",
    "ipv6.he.net",  # Known for 1480 MTU tunnels
    "quay.io",
    "pypi.org",
    "repo1.maven.org",
    "proxy.golang.org",
    "crates.io",
    "gitlab.com",
    "www.youtube.com",
    "www.netflix.com",
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


class MTUTester:
    def __init__(self, os_name):
        self.os_name = os_name
        self.min_mtu = 1280
        self.max_mtu = 1500


class ICMPTester(MTUTester):
    def test_size(self, ip, payload_size):
        cmd = (
            ["ping6", "-c", "1", "-s", str(payload_size), ip]
            if self.os_name == "darwin"
            else [
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
        )
        try:
            return (
                subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1.5,
                ).returncode
                == 0
            )
        except subprocess.TimeoutExpired:
            return False


class UDPTester(MTUTester):
    def test_size(self, ip, payload_size):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            if self.os_name == "linux":
                sock.setsockopt(socket.IPPROTO_IPV6, 23, 2)
            elif self.os_name == "darwin":
                sock.setsockopt(socket.IPPROTO_IPV6, 62, 1)
            sock.sendto(b"X" * payload_size, (ip, 33434))
            return True
        except OSError:
            return False
        finally:
            sock.close()


class TCPTester(MTUTester):
    def get_pmtu(self, ip, port=443):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((ip, port))
            mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)

            if self.os_name == "linux":
                # 41 is IPPROTO_IPV6, 68 is IPV6_MTU on Linux
                try:
                    exact_mtu = sock.getsockopt(41, 68)
                    return {"mss": mss, "mtu": exact_mtu, "exact": True}
                except OSError:
                    # Fallback if kernel rejects IPV6_MTU query
                    return {"mss": mss, "mtu": mss + 60, "exact": False}
            else:
                # macOS Darwin fallback
                return {"mss": mss, "mtu": mss + 60, "exact": False}
        except Exception:
            return None
        finally:
            sock.close()


def verify_ptb_missing(ip, tester, payload_size):
    interface = "any" if tester.os_name != "darwin" else "pktap,any"
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
        tester.test_size(ip, payload_size)
        try:
            out, _ = sniffer.communicate(timeout=2.0)
            return True if out else False
        except subprocess.TimeoutExpired:
            sniffer.kill()
            return False
    except Exception:
        return None


def analyze_path(domain, tester, protocol_name, verify_ptb):
    logging.info(f"--- [{protocol_name}] Probing {domain} ---")
    ip = resolve_ipv6(domain)
    if not ip or ip.startswith("::ffff:"):
        logging.warning(
            f"[{domain}] [{protocol_name}] No IPv6 address found. Skipping."
        )
        return {
            "domain": domain,
            "protocol": protocol_name,
            "mtu": "No IPv6",
            "ptb_seen": "N/A",
            "exact_tcp": False,
        }

    if protocol_name == "TCP":
        tcp_data = tester.get_pmtu(ip)
        if tcp_data:
            logging.info(
                f"[{domain}] [{protocol_name}] Success: MSS {tcp_data['mss']}, MTU {tcp_data['mtu']} (Exact: {tcp_data['exact']})"
            )
            return {
                "domain": domain,
                "protocol": protocol_name,
                "mtu": tcp_data["mtu"],
                "mss": tcp_data["mss"],
                "ptb_seen": "N/A",
                "exact_tcp": tcp_data["exact"],
            }
        logging.error(f"[{domain}] [{protocol_name}] Connection failed.")
        return {
            "domain": domain,
            "protocol": protocol_name,
            "mtu": "Failed",
            "mss": "Failed",
            "ptb_seen": "N/A",
            "exact_tcp": False,
        }

    overhead = 48
    min_payload, max_payload = tester.min_mtu - overhead, tester.max_mtu - overhead
    ptb_seen = "N/A"

    # UDP specific logic - sniff max payload but do not binary search
    if protocol_name == "UDP":
        if verify_ptb:
            logging.info(
                f"[{domain}] [{protocol_name}] Sniffing for PTB on 1500 byte probe..."
            )
            ptb_res = verify_ptb_missing(ip, tester, max_payload)
            ptb_seen = "Yes" if ptb_res else "No"
            if ptb_res:
                logging.warning(
                    f"[{domain}] [{protocol_name}] FORENSIC: PTB seen! UDP packet was dropped by a router."
                )
            else:
                logging.info(
                    f"[{domain}] [{protocol_name}] No PTB seen. Packet likely reached target."
                )
        else:
            tester.test_size(ip, max_payload)

        return {
            "domain": domain,
            "protocol": protocol_name,
            "mtu": 1500,
            "ptb_seen": ptb_seen,
            "exact_tcp": False,
        }

    # ICMP specific logic - complete active probing
    if not tester.test_size(ip, min_payload):
        logging.error(
            f"[{domain}] [{protocol_name}] Baseline {tester.min_mtu} dropped."
        )
        return {
            "domain": domain,
            "protocol": protocol_name,
            "mtu": "Blocked",
            "ptb_seen": ptb_seen,
            "exact_tcp": False,
        }

    if tester.test_size(ip, max_payload):
        logging.info(
            f"[{domain}] [{protocol_name}] 1500 byte packet succeeded immediately."
        )
        return {
            "domain": domain,
            "protocol": protocol_name,
            "mtu": 1500,
            "ptb_seen": ptb_seen,
            "exact_tcp": False,
        }

    logging.warning(
        f"[{domain}] [{protocol_name}] 1500 byte dropped. Calculating ceiling..."
    )

    if verify_ptb:
        logging.info(f"[{domain}] [{protocol_name}] Sniffing for PTB messages...")
        ptb_res = verify_ptb_missing(ip, tester, max_payload)
        ptb_seen = "Yes" if ptb_res else "No"
        if not ptb_res:
            logging.critical(
                f"[{domain}] [{protocol_name}] FORENSIC: No PTB seen on wire."
            )

    low, high, best = min_payload, max_payload - 1, min_payload
    while low <= high:
        mid = (low + high) // 2
        if tester.test_size(ip, mid):
            best, low = mid, mid + 1
        else:
            high = mid - 1

    logging.warning(
        f"[{domain}] [{protocol_name}] Max size calculated at {best + overhead} bytes."
    )
    return {
        "domain": domain,
        "protocol": protocol_name,
        "mtu": best + overhead,
        "ptb_seen": ptb_seen,
        "exact_tcp": False,
    }


def print_summary(results):
    print("\n" + "=" * 105)
    print(
        f"{'DOMAIN':<25} | {'ICMP MTU':<10} | {'ICMP PTB':<10} | {'UDP (LOCAL)':<12} | {'UDP PTB':<10} | {'TCP MSS':<8} | {'TCP MTU'}"
    )
    print("-" * 105)

    summary = {}
    has_estimates = False

    for r in results:
        d = r["domain"]
        if d not in summary:
            summary[d] = {
                "ICMP_MTU": "-",
                "ICMP_PTB": "-",
                "UDP_MTU": "-",
                "UDP_PTB": "-",
                "TCP_MSS": "-",
                "TCP_MTU": "-",
            }

        if r["protocol"] == "TCP":
            summary[d]["TCP_MSS"] = str(r.get("mss", "-"))
            mtu_val = str(r["mtu"])
            if r.get("exact_tcp") is False and r["mtu"] != "Failed":
                mtu_val += "*"
                has_estimates = True
            summary[d]["TCP_MTU"] = mtu_val
        elif r["protocol"] == "ICMP":
            summary[d]["ICMP_MTU"] = str(r["mtu"])
            if r.get("ptb_seen") != "N/A":
                summary[d]["ICMP_PTB"] = r["ptb_seen"]
        elif r["protocol"] == "UDP":
            summary[d]["UDP_MTU"] = str(r["mtu"])
            if r.get("ptb_seen") != "N/A":
                summary[d]["UDP_PTB"] = r["ptb_seen"]

    for d, data in summary.items():
        print(
            f"{d:<25} | {data['ICMP_MTU']:<10} | {data['ICMP_PTB']:<10} | {data['UDP_MTU']:<12} | {data['UDP_PTB']:<10} | {data['TCP_MSS']:<8} | {data['TCP_MTU']}"
        )
    print("=" * 105)

    if has_estimates:
        print(
            "* Estimated (MSS + 60). macOS does not expose exact PMTU via socket options."
        )
        print(
            "  Note: If TCP Timestamps are active, true MTU is exactly 12 bytes higher."
        )
        print(
            "  Run this script on Linux to extract true PMTU telemetry directly from the kernel."
        )
        print("=" * 105)
    print("\n")


def main():
    parser = argparse.ArgumentParser(description="Multi-Protocol MTU Forensics Tool V9")
    parser.add_argument(
        "--verify-ptb",
        action="store_true",
        help="Run packet capture to verify PTB messages (Requires sudo)",
    )
    parser.add_argument(
        "--log-file", default="mtu_diagnostic_v9.log", help="Output log"
    )
    parser.add_argument(
        "--json-file", default="mtu_history_v9.json", help="Output JSON telemetry"
    )
    args = parser.parse_args()

    os_name = platform.system().lower()
    if args.verify_ptb and os_name == "darwin" and os.geteuid() != 0:
        print("ERROR: --verify-ptb requires sudo on macOS.")
        sys.exit(1)
    elif args.verify_ptb and os_name == "linux" and os.geteuid() != 0:
        print(
            "ERROR: --verify-ptb requires sudo (or CAP_NET_RAW/CAP_NET_ADMIN) on Linux."
        )
        sys.exit(1)

    setup_logging(args.log_file)
    logging.info(f"Starting diagnostic routine V9 on {os_name.upper()}.")

    scan_results = []
    testers = [
        ("ICMP", ICMPTester(os_name)),
        ("UDP", UDPTester(os_name)),
        ("TCP", TCPTester(os_name)),
    ]

    for domain in TARGET_SITES:
        for proto_name, tester in testers:
            scan_results.append(
                analyze_path(domain, tester, proto_name, args.verify_ptb)
            )
            time.sleep(1.0)

    print_summary(scan_results)

    # --- Cross-Platform JSON Telemetry Appending ---
    run_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "os": os_name,
        "hostname": platform.node(),
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

    try:
        with open(args.json_file, "w") as f:
            json.dump(history, f, indent=2)
        logging.info(f"Telemetry successfully appended to {args.json_file}")
    except Exception as e:
        logging.error(f"Failed to save JSON telemetry: {e}")


if __name__ == "__main__":
    main()
