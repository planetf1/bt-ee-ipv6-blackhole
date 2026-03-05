import random
from scapy.all import (
    Ether,
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6PacketTooBig,
    srp1,
    conf,
)

# Suppress scapy's default verbose terminal output
conf.verb = 0

target_ip = "2001:4860:4860::8888"
gateway_mac = "bc:24:11:ca:52:d6"  # Hardcoded from your RA capture
interface = "en6"
payload_size = 1452  # 1452 Payload + 8 ICMPv6 + 40 IPv6 = 1500 Bytes on the wire
payload = b"X" * payload_size
iterations = 50

print(f"Testing ECMP MTU to {target_ip} with {iterations} randomized flows...")
print(f"Packet size: {payload_size} (Payload) + 8 (ICMPv6) + 40 (IPv6) = 1500 bytes")
print(f"Routing via {interface} directly to gateway MAC {gateway_mac}\n")

results = {"success": 0, "blackhole": 0, "too_big": 0}

for i in range(iterations):
    # Randomize the flow identifiers to force different physical ECMP paths
    flow_id = random.randint(1, 65535)
    flow_label = random.randint(1, 1048575)

    # Construct the frame explicitly from Layer 2 to avoid macOS BPF routing bugs
    pkt = (
        Ether(dst=gateway_mac)
        / IPv6(dst=target_ip, fl=flow_label)
        / ICMPv6EchoRequest(id=flow_id, seq=i)
        / payload
    )

    # Send at Layer 2 (srp1) to bypass local OS routing tables
    reply = srp1(pkt, iface=interface, timeout=1.5, verbose=False)

    if reply is None:
        print(
            f"[ Flow {flow_id:05d} | FL {flow_label:07d} ] : Timeout (MTU Black Hole)"
        )
        results["blackhole"] += 1
    elif reply.haslayer(ICMPv6EchoReply):
        print(
            f"[ Flow {flow_id:05d} | FL {flow_label:07d} ] : Success (Clean 1500 MTU Path)"
        )
        results["success"] += 1
    elif reply.haslayer(ICMPv6PacketTooBig):
        mtu = reply[ICMPv6PacketTooBig].mtu
        print(
            f"[ Flow {flow_id:05d} | FL {flow_label:07d} ] : Packet Too Big (Reported MTU: {mtu})"
        )
        results["too_big"] += 1
    else:
        print(f"[ Flow {flow_id:05d} | FL {flow_label:07d} ] : Unexpected reply type")

print("\n--- Final ECMP Path Statistics ---")
print(f"Healthy 1500 Paths  : {results['success']}")
print(f"Broken Paths (Drop) : {results['blackhole']}")
print(f"Clean Drops (Type 2): {results['too_big']}")
print(f"Total Packet Loss   : {(results['blackhole'] / iterations) * 100:.1f}%")
