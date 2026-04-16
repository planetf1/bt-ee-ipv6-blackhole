<!--
This repository is now archived. The original README has been moved to ARCHIVE_README.md for reference.
-->

# BT/EE IPv6 Path MTU Blackhole Investigation – Status: Resolved/Archived

## Summary

**2026-04-16:** This repository is now archived. The original issue (suspected IPv6 Path MTU blackhole on BT/EE) is no longer reproducible. BT/EE engineering confirmed that Path MTU Discovery (P2B) should function as expected, aside from normal rate limiting.

### Retesting Results

- Retested with both OpnSense (MTU 1500) and EE router (MTU 1492).
- Consistently observed ICMPv6 Type 2 (Packet Too Big) messages across Linux, macOS, and FreeBSD.
- Example commands and output for each OS are included below.
- Some v9 script bugs were found and fixed, but the core issue is resolved.


#### Example: FreeBSD/macOS
```sh
sudo ping6 -v -D -c 50 -s 1452 mtu1280.test-ipv6.com
```
```
Output (truncated):
1240 bytes from 2600:3c0e:e001:d1::6666: Packet too big mtu = 1280
ICMP6: type = 128, code = 0
```

#### Example: Linux
```sh
ping6 mtu1280.test-ipv6.com -Mdo -v -c 50 -s 1452
```
```
Output (truncated):
From 2600:3c0e:e001:d1::6666 icmp_seq=1 Packet too big: mtu=1280
ping6: sendmsg: Message too long
```

**Note:** On Linux, the route MTU is updated after the first ping, so subsequent errors are locally generated.

### Remaining Edge Cases

- Some hosts (e.g., AWS, HuggingFace) still do not respond, but this is also observed on non-BT/EE networks, indicating the issue is specific to those networks, not BT/EE.

### Closure

- The original problem is no longer reproducible.
- Possible causes for the earlier issue: user error, device firmware/software updates, or unreported network changes.
- For historical details, see [ARCHIVE_README.md](./ARCHIVE_README.md).

---


**This repository is now archived and read-only.**

---

### Thanks

Special thanks to the BT/EE engineering staff for their investigation and confirmation of correct P2B/PMTUD behavior.

---

For any future reference, please consult the archive or open a new issue if a regression is observed.
