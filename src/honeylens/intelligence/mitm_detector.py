#!/usr/bin/env python3
"""
mitm_detector.py — MiTM Attack Detection Engine
================================================
Detects ARP spoofing, DNS poisoning, and other MiTM attacks.

Uses hybrid approach:
- Userspace ARP monitoring via /proc/net/arp (always works)
- eBPF kprobe on arp_rcv (if available)
- DNS monitoring via tcpdump
- DHCP monitoring via tcpdump (rogue DHCP server detection)
- ICMP redirect monitoring via tcpdump
- LLMNR/NBT-NS poisoning detection via tcpdump
- SSL stripping detection via tcpdump (HTTP 301/302 to HTTPS downgrade)

Detected Attacks:
- ARP Spoofing / Cache Poisoning
- Gratuitous ARP Floods
- DNS Spoofing / Untrusted Servers
- DHCP Spoofing (rogue DHCP servers)
- ICMP Redirect Attacks
- LLMNR / NBT-NS Poisoning
- SSL Stripping (HTTP redirect interception)

Requirements: psycopg2, optionally bcc for eBPF

Usage:
    sudo python mitm_detector.py
    sudo python mitm_detector.py -i eth0
    sudo python mitm_detector.py --gateway 192.168.1.1
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import logging
import os
import signal
import socket
import struct
import subprocess  # nosec B404 — fixed system commands (dig, whois, ip, tcpdump), args as a list, no shell
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Thread
from typing import Any

# Optional BCC
try:
    from bcc import BPF

    HAS_BCC = True
except ImportError:
    HAS_BCC = False

# Optional psycopg2
from psycopg2.extras import Json

# =============================================================================
# Configuration
# =============================================================================
from honeylens.config import (
    DB_CONFIG,
    INTERFACE,
    MITM_ARP_CHANGE_THRESHOLD,
    MITM_GATEWAY_IPS,
    MITM_LLMNR_BROAD_QUERIERS,
    MITM_LLMNR_COOLDOWN,
    MITM_LLMNR_MIN_REPLIES,
    MITM_LOG_FILE,
    MITM_TRUSTED_DHCP,
    MITM_TRUSTED_DNS,
)
from honeylens.database import legacy_get_db as _db_connect

# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("mitm-detector")

# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class MitmEvent:
    """Represents a detected MiTM attack."""

    event_id: str
    timestamp: datetime
    attack_type: str
    severity: str
    confidence: int
    src_mac: str
    dst_mac: str | None
    src_ip: str
    dst_ip: str | None
    src_port: int | None = None
    dst_port: int | None = None
    original_mac: str | None = None
    spoofed_mac: str | None = None
    dns_query: str | None = None
    dns_answer: str | None = None
    interface: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def generate_event_id(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:32]


def mac_to_str(mac_bytes) -> str:
    if isinstance(mac_bytes, (list, tuple)):
        return ":".join(f"{b:02x}" for b in mac_bytes)
    return ":".join(f"{b:02x}" for b in bytes(mac_bytes))


# =============================================================================
# ARP Monitor (Userspace - /proc/net/arp)
# =============================================================================


class ArpMonitor:
    """Monitor ARP table changes using /proc/net/arp polling."""

    def __init__(self, interface: str, gateway_ips: list[str], threshold: int, callback, db=None):
        self.interface = interface
        self.gateway_ips = set(gateway_ips or [])
        self.threshold = threshold
        self.callback = callback
        self.db = db
        self.running = False
        self.cache: dict[str, dict] = {}

    def parse_arp_table(self) -> dict[str, str]:
        """Parse /proc/net/arp and return IP->MAC mapping."""
        result = {}
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip, mac, iface = parts[0], parts[3].lower(), parts[5]
                        if self.interface and iface != self.interface:
                            continue
                        if mac != "00:00:00:00:00:00":
                            result[ip] = mac
        except Exception as e:
            logger.error("Error reading ARP table: %s", e)
        return result

    def check_for_changes(self) -> list[MitmEvent]:
        """Check ARP table for changes."""
        events = []
        now = datetime.now(UTC)
        current_arp = self.parse_arp_table()

        for ip, mac in current_arp.items():
            if ip in self.cache:
                entry = self.cache[ip]
                old_mac = entry["mac"]

                if old_mac != mac:
                    entry["prev_macs"].append(old_mac)
                    entry["change_count"] += 1
                    entry["mac"] = mac
                    entry["last_seen"] = now

                    is_gw = ip in self.gateway_ips

                    if entry["change_count"] >= self.threshold or is_gw:
                        events.append(
                            MitmEvent(
                                event_id=generate_event_id(f"{ip}-{mac}-{now.isoformat()}"),
                                timestamp=now,
                                attack_type="ARP_SPOOF",
                                severity="CRITICAL" if is_gw else "HIGH",
                                confidence=min(95, 60 + entry["change_count"] * 10),
                                src_mac=mac,
                                dst_mac=None,
                                src_ip=ip,
                                dst_ip=None,
                                original_mac=old_mac,
                                spoofed_mac=mac,
                                metadata={
                                    "change_count": entry["change_count"],
                                    "previous_macs": entry["prev_macs"][-5:],
                                    "is_gateway": is_gw,
                                },
                            )
                        )
                    else:
                        events.append(
                            MitmEvent(
                                event_id=generate_event_id(f"{ip}-{mac}-chg-{now.isoformat()}"),
                                timestamp=now,
                                attack_type="ARP_MAC_CHANGE",
                                severity="MEDIUM",
                                confidence=50,
                                src_mac=mac,
                                dst_mac=None,
                                src_ip=ip,
                                dst_ip=None,
                                original_mac=old_mac,
                                spoofed_mac=mac,
                                metadata={"change_count": entry["change_count"]},
                            )
                        )
                else:
                    entry["last_seen"] = now
            else:
                self.cache[ip] = {
                    "mac": mac,
                    "first_seen": now,
                    "last_seen": now,
                    "change_count": 0,
                    "prev_macs": [],
                }
        # Persist current ARP state to DB
        if self.db and current_arp:
            db_entries = []
            for ip, mac in current_arp.items():
                db_entries.append(
                    {
                        "ip": ip,
                        "mac": mac,
                        "interface": self.interface or "unknown",
                        "is_gateway": ip in self.gateway_ips,
                        "trust_score": 90 if ip in self.gateway_ips else 50,
                    }
                )
            self.db.upsert_arp_cache(db_entries)
        return events

    def run(self, poll_interval: float = 1.0):
        self.running = True
        logger.info("ARP monitor started (polling /proc/net/arp every %.1fs)", poll_interval)
        while self.running:
            try:
                for event in self.check_for_changes():
                    self.callback(event)
            except Exception as e:
                logger.error("ARP monitor error: %s", e)
            time.sleep(poll_interval)

    def stop(self):
        self.running = False


# =============================================================================
# DNS Monitor (tcpdump-based)
# =============================================================================


class DnsMonitor:
    """Monitor DNS traffic for spoofing."""

    def __init__(self, interface: str, trusted_servers: list[str], callback):
        self.interface = interface
        # Trust the host's own configured resolvers so we don't flag every
        # legitimate DNS reply (systemd-resolved, router, corporate DNS).
        self.trusted = set(trusted_servers or MITM_TRUSTED_DNS) | self._system_resolvers()
        self.callback = callback
        self.running = False
        self.proc: subprocess.Popen[str] | None = None

    @staticmethod
    def _system_resolvers() -> set[str]:
        res: set[str] = set()
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            res.add(parts[1])
        except OSError as exc:
            logger.debug("resolv.conf not readable (%s) — optional", exc)
        return res

    def run(self):
        self.running = True
        logger.info("DNS monitor started (tcpdump)")

        try:
            cmd = [
                "tcpdump",
                "-i",
                self.interface,
                "-l",
                "-nn",
                "-Q",
                "in",
                "udp",
                "src",
                "port",
                "53",
                "-v",
            ]
            self.proc = subprocess.Popen(  # noqa: S603 # nosec B603 — fixed tcpdump command, args as a list
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            assert self.proc.stdout is not None  # nosec B101 — type narrowing; stdout=PIPE yields a stream

            while self.running and self.proc.poll() is None:
                line = self.proc.stdout.readline()
                if line:
                    self.parse_line(line)
        except FileNotFoundError:
            logger.warning("tcpdump not found, DNS monitoring disabled")
        except Exception as e:
            logger.error("DNS monitor error: %s", e)

    def parse_line(self, line: str):
        """Parse tcpdump output for DNS responses."""
        try:
            # Extract source IP from tcpdump output
            # Format: "14:30:00.123 IP src.port > dst.port: ..."
            if " > " not in line:
                return
            parts = line.split()
            for i, p in enumerate(parts):
                if p == ">":
                    src = parts[i - 1].rsplit(".", 1)[0]
                    if src and src not in self.trusted:
                        now = datetime.now(UTC)
                        self.callback(
                            MitmEvent(
                                event_id=generate_event_id(f"dns-{src}-{now.isoformat()}"),
                                timestamp=now,
                                attack_type="DNS_UNTRUSTED_SERVER",
                                severity="MEDIUM",
                                confidence=50,
                                src_mac="",
                                dst_mac=None,
                                src_ip=src,
                                dst_ip=None,
                                metadata={"note": "DNS response from untrusted server"},
                            )
                        )
                    break
        except Exception as e:
            logger.debug("DNS line parse error: %s", e)

    def stop(self):
        self.running = False
        if self.proc:
            self.proc.terminate()


# =============================================================================
# DHCP Monitor (tcpdump-based — rogue DHCP server detection)
# =============================================================================


class DhcpMonitor:
    """Detect rogue DHCP servers offering leases on the network."""

    def __init__(self, interface: str, trusted_dhcp: list[str], callback):
        self.interface = interface
        self.trusted = set(trusted_dhcp or MITM_TRUSTED_DHCP)
        self.callback = callback
        self.running = False
        self.proc: subprocess.Popen[str] | None = None
        self._seen: dict[str, float] = {}  # ip -> last_alert_ts (dedup)
        self.learned: set[str] = set()  # TOFU-learned legitimate DHCP servers

    def run(self):
        self.running = True
        logger.info("DHCP monitor started (tcpdump)")
        try:
            # Capture DHCP Offer/ACK packets (src port 67 = server)
            cmd = [
                "tcpdump",
                "-i",
                self.interface,
                "-l",
                "-nn",
                "-Q",
                "in",
                "udp",
                "src",
                "port",
                "67",
                "-v",
            ]
            self.proc = subprocess.Popen(  # noqa: S603 # nosec B603 — fixed tcpdump command, args as a list
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            assert self.proc.stdout is not None  # nosec B101 — type narrowing; stdout=PIPE yields a stream
            while self.running and self.proc.poll() is None:
                line = self.proc.stdout.readline()
                if line:
                    self._parse(line)
        except FileNotFoundError:
            logger.warning("tcpdump not found, DHCP monitoring disabled")
        except Exception as e:
            logger.error("DHCP monitor error: %s", e)

    def _parse(self, line: str):
        try:
            if " > " not in line:
                return
            parts = line.split()
            for i, p in enumerate(parts):
                if p == ">":
                    src = parts[i - 1].rsplit(".", 1)[0]
                    if not src:
                        break
                    if src in self.trusted or src in self.learned:
                        break  # configured or TOFU-learned legitimate server
                    now = time.time()
                    if now - self._seen.get(src, 0) < 60:
                        break  # dedup within 60s
                    self._seen[src] = now
                    ts = datetime.now(UTC)
                    # Trust-on-first-use: with no configured trusted DHCP server,
                    # learn the first one observed (the sensor's own DHCP) rather
                    # than crying "rogue CRITICAL". Only a *second* distinct server
                    # (or a mismatch against a configured/learned one) is a rogue.
                    if not self.trusted and not self.learned:
                        self.learned.add(src)
                        self.callback(
                            MitmEvent(
                                event_id=generate_event_id(f"dhcp-obs-{src}-{ts.isoformat()}"),
                                timestamp=ts,
                                attack_type="DHCP_SERVER_OBSERVED",
                                severity="MEDIUM",
                                confidence=40,
                                src_mac="",
                                dst_mac=None,
                                src_ip=src,
                                dst_ip="255.255.255.255",
                                metadata={
                                    "note": "First DHCP server observed — learned as legitimate "
                                    "(baseline candidate). A second distinct server would "
                                    "indicate a rogue DHCP."
                                },
                            )
                        )
                        break
                    self.callback(
                        MitmEvent(
                            event_id=generate_event_id(f"dhcp-{src}-{ts.isoformat()}"),
                            timestamp=ts,
                            attack_type="DHCP_ROGUE_SERVER",
                            severity="CRITICAL",
                            confidence=85,
                            src_mac="",
                            dst_mac=None,
                            src_ip=src,
                            dst_ip="255.255.255.255",
                            metadata={
                                "trusted_servers": list(self.trusted or self.learned),
                                "note": "DHCP response from a server that is neither trusted "
                                "nor the learned legitimate server — possible rogue DHCP",
                            },
                        )
                    )
                    break
        except Exception as e:
            logger.debug("DHCP line parse error: %s", e)

    def stop(self):
        self.running = False
        if self.proc:
            self.proc.terminate()


# =============================================================================
# ICMP Redirect Monitor (tcpdump-based)
# =============================================================================


class IcmpRedirectMonitor:
    """Detect ICMP redirect messages used to reroute traffic."""

    def __init__(self, interface: str, callback):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.proc: subprocess.Popen[str] | None = None
        self._seen: dict[str, float] = {}

    def run(self):
        self.running = True
        logger.info("ICMP redirect monitor started (tcpdump)")
        try:
            cmd = ["tcpdump", "-i", self.interface, "-l", "-nn", "icmp", "and", "icmp[icmptype]==5"]
            self.proc = subprocess.Popen(  # noqa: S603 # nosec B603 — fixed tcpdump command, args as a list
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            assert self.proc.stdout is not None  # nosec B101 — type narrowing; stdout=PIPE yields a stream
            while self.running and self.proc.poll() is None:
                line = self.proc.stdout.readline()
                if line:
                    self._parse(line)
        except FileNotFoundError:
            logger.warning("tcpdump not found, ICMP redirect monitoring disabled")
        except Exception as e:
            logger.error("ICMP redirect monitor error: %s", e)

    def _parse(self, line: str):
        try:
            if "redirect" not in line.lower():
                return
            parts = line.split()
            for i, p in enumerate(parts):
                if p == ">":
                    src = parts[i - 1]
                    now_t = time.time()
                    if now_t - self._seen.get(src, 0) < 30:
                        return
                    self._seen[src] = now_t
                    ts = datetime.now(UTC)
                    self.callback(
                        MitmEvent(
                            event_id=generate_event_id(f"icmp-redir-{src}-{ts.isoformat()}"),
                            timestamp=ts,
                            attack_type="ICMP_REDIRECT",
                            severity="HIGH",
                            confidence=80,
                            src_mac="",
                            dst_mac=None,
                            src_ip=src,
                            dst_ip=None,
                            metadata={
                                "raw": line.strip(),
                                "note": "ICMP redirect can reroute traffic through attacker",
                            },
                        )
                    )
                    break
        except Exception as e:
            logger.debug("ICMP redirect line parse error: %s", e)

    def stop(self):
        self.running = False
        if self.proc:
            self.proc.terminate()


# =============================================================================
# LLMNR / NBT-NS Poisoning Monitor (tcpdump-based)
# =============================================================================


class LlmnrNbtnsMonitor:
    """Detect LLMNR and NBT-NS poisoning (Responder/Inveigh-style attacks)."""

    def __init__(self, interface: str, callback):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.proc: subprocess.Popen[str] | None = None
        # ip -> {count, queriers:set, last_emit:float, port:str}
        self._responders: dict[str, dict] = {}

    @staticmethod
    def _split_ip_port(token: str):
        """Split a tcpdump 'ip.port' token (IPv4 a.b.c.d.port or IPv6 ::x.port)."""
        token = token.rstrip(":")
        if "." in token:
            ip, port = token.rsplit(".", 1)
            if port.isdigit():
                return ip, port
        return token, ""

    def run(self):
        self.running = True
        logger.info("LLMNR/NBT-NS monitor started (tcpdump)")
        try:
            # LLMNR = UDP 5355, NBT-NS = UDP 137
            cmd = [
                "tcpdump",
                "-i",
                self.interface,
                "-l",
                "-nn",
                "-Q",
                "in",
                "udp",
                "and",
                "(",
                "src",
                "port",
                "5355",
                "or",
                "src",
                "port",
                "137",
                ")",
            ]
            self.proc = subprocess.Popen(  # noqa: S603 # nosec B603 — fixed tcpdump command, args as a list
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            assert self.proc.stdout is not None  # nosec B101 — type narrowing; stdout=PIPE yields a stream
            while self.running and self.proc.poll() is None:
                line = self.proc.stdout.readline()
                if line:
                    self._parse(line)
        except FileNotFoundError:
            logger.warning("tcpdump not found, LLMNR/NBT-NS monitoring disabled")
        except Exception as e:
            logger.error("LLMNR/NBT-NS monitor error: %s", e)

    def _parse(self, line: str):
        try:
            if " > " not in line:
                return
            parts = line.split()
            if ">" not in parts:
                return
            gt = parts.index(">")
            if gt <= 0 or gt + 1 >= len(parts):
                return
            src_ip, src_port = self._split_ip_port(parts[gt - 1])
            dst_ip, _ = self._split_ip_port(parts[gt + 1])
            if not src_ip:
                return
            st = self._responders.get(src_ip)
            if st is None:
                st = {"count": 0, "queriers": set(), "last_emit": 0.0, "port": src_port}
                self._responders[src_ip] = st
            st["count"] += 1
            if dst_ip:
                st["queriers"].add(dst_ip)
            if src_port:
                st["port"] = src_port
            now_t = time.time()
            # Legit hosts answer name queries all day. Emit at most one event per
            # responder per cooldown, only past a reply floor. Default MEDIUM;
            # escalate to HIGH only for the broad-responder shape (one host
            # answering many distinct queriers — Responder/Inveigh).
            if (
                st["count"] >= MITM_LLMNR_MIN_REPLIES
                and (now_t - st["last_emit"]) >= MITM_LLMNR_COOLDOWN
            ):
                st["last_emit"] = now_t
                proto = "LLMNR" if st["port"] == "5355" else "NBT-NS"
                nq = len(st["queriers"])
                broad = nq >= MITM_LLMNR_BROAD_QUERIERS
                ts = datetime.now(UTC)
                self.callback(
                    MitmEvent(
                        event_id=generate_event_id(f"llmnr-{src_ip}-{int(now_t)}"),
                        timestamp=ts,
                        attack_type=f"{proto}_POISONING",
                        severity="HIGH" if broad else "MEDIUM",
                        confidence=min(90, 40 + nq * 5),
                        src_mac="",
                        dst_mac=None,
                        src_ip=src_ip,
                        dst_ip=None,
                        metadata={
                            "protocol": proto,
                            "reply_count": st["count"],
                            "distinct_queriers": nq,
                            "note": (
                                f"{proto}: host answered {st['count']} name queries to {nq} "
                                + (
                                    "distinct hosts — broad responder pattern (possible "
                                    "Responder/Inveigh)"
                                    if broad
                                    else "host(s) — likely benign name resolution; confirm or "
                                    "add to baseline"
                                )
                            ),
                        },
                    )
                )
        except Exception as e:
            logger.debug("LLMNR/NBT-NS line parse error: %s", e)

    def stop(self):
        self.running = False
        if self.proc:
            self.proc.terminate()


# =============================================================================
# SSL Stripping Monitor (tcpdump-based — HTTP redirect interception)
# =============================================================================


class SslStripMonitor:
    """Detect SSL stripping by monitoring for HTTP→HTTPS redirect tampering.

    Watches for HTTP 301/302 responses where Location header was changed
    from https:// to http:// (characteristic of sslstrip/bettercap).
    Also detects unexpected HTTP traffic on port 80 to known HTTPS-only hosts.
    """

    def __init__(self, interface: str, callback):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.proc: subprocess.Popen[str] | None = None
        self._seen: dict[str, float] = {}

    def run(self):
        self.running = True
        logger.info("SSL strip monitor started (tcpdump)")
        try:
            # Capture any TCP traffic on port 80 with payload content
            cmd = ["tcpdump", "-i", self.interface, "-l", "-nn", "-A", "tcp", "port", "80"]
            self.proc = subprocess.Popen(  # noqa: S603 # nosec B603 — fixed tcpdump command, args as a list
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            assert self.proc.stdout is not None  # nosec B101 — type narrowing; stdout=PIPE yields a stream
            buf = ""
            while self.running and self.proc.poll() is None:
                line = self.proc.stdout.readline()
                if line:
                    buf += line
                    # Process when we see a full HTTP response header
                    if "\r\n\r\n" in buf or len(buf) > 4096:
                        self._parse(buf)
                        buf = ""
        except FileNotFoundError:
            logger.warning("tcpdump not found, SSL strip monitoring disabled")
        except Exception as e:
            logger.error("SSL strip monitor error: %s", e)

    def _parse(self, data: str):
        try:
            # Look for HTTP 301/302 with Location: http:// (downgrade from https)
            lines = data.split("\n")
            src_ip = ""
            for line in lines:
                if " > " in line and "HTTP" not in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == ">":
                            src_ip = parts[i - 1].rsplit(".", 1)[0]
                            break
                low = line.lower().strip()
                if low.startswith("location:") and "http://" in low:
                    # HTTP redirect to http:// — could be legitimate or sslstrip
                    # Flag if it looks like a downgrade (common HTTPS sites)
                    location = line.split(":", 1)[1].strip()
                    now_t = time.time()
                    key = f"{src_ip}-{location}"
                    if now_t - self._seen.get(key, 0) < 120:
                        return
                    self._seen[key] = now_t
                    ts = datetime.now(UTC)
                    self.callback(
                        MitmEvent(
                            event_id=generate_event_id(f"sslstrip-{key}-{ts.isoformat()}"),
                            timestamp=ts,
                            attack_type="SSL_STRIP",
                            severity="HIGH",
                            confidence=65,
                            src_mac="",
                            dst_mac=None,
                            src_ip=src_ip or "unknown",
                            dst_ip=None,
                            metadata={
                                "location": location,
                                "note": "HTTP redirect may indicate SSL stripping",
                            },
                        )
                    )
        except Exception as e:
            logger.debug("SSL strip parse error: %s", e)

    def stop(self):
        self.running = False
        if self.proc:
            self.proc.terminate()


# =============================================================================
# eBPF Monitor (optional, kprobe-based)
# =============================================================================


class EbpfArpMonitor:
    """eBPF-based ARP monitor using kprobe."""

    BPF_CODE = r"""
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>

struct event_t {
    u64 ts;
    u32 sip;
    u32 tip;
    u8 sha[6];
    u16 op;
};

BPF_PERF_OUTPUT(events);

int kprobe__arp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    unsigned char *head;
    u16 nh_off;

    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&nh_off, sizeof(nh_off), &skb->network_header);

    unsigned char *arp_ptr = head + nh_off;

    struct arphdr ah;
    bpf_probe_read_kernel(&ah, sizeof(ah), arp_ptr);

    if (ntohs(ah.ar_hrd) != ARPHRD_ETHER || ntohs(ah.ar_pro) != ETH_P_IP)
        return 0;

    struct event_t e = {};
    e.ts = bpf_ktime_get_ns();
    e.op = ntohs(ah.ar_op);

    // ARP payload: SHA(6) + SIP(4) + THA(6) + TIP(4)
    bpf_probe_read_kernel(e.sha, 6, arp_ptr + sizeof(struct arphdr));
    bpf_probe_read_kernel(&e.sip, 4, arp_ptr + sizeof(struct arphdr) + 6);
    bpf_probe_read_kernel(&e.tip, 4, arp_ptr + sizeof(struct arphdr) + 16);

    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

    def __init__(self, callback):
        self.callback = callback
        self.bpf = None
        self.running = False
        self.cache: dict[int, bytes] = {}  # IP -> last seen MAC

    def load(self) -> bool:
        if not HAS_BCC:
            return False
        try:
            self.bpf = BPF(text=self.BPF_CODE)
            logger.info("eBPF ARP monitor loaded")
            return True
        except Exception as e:
            logger.warning("eBPF load failed: %s", e)
            return False

    def handle_event(self, cpu, data, size):
        class Event(ctypes.Structure):
            _fields_ = [
                ("ts", ctypes.c_uint64),
                ("sip", ctypes.c_uint32),
                ("tip", ctypes.c_uint32),
                ("sha", ctypes.c_uint8 * 6),
                ("op", ctypes.c_uint16),
            ]

        ev = ctypes.cast(data, ctypes.POINTER(Event)).contents
        sip = ev.sip
        sha = bytes(ev.sha)

        # Check for MAC change
        if sip in self.cache and self.cache[sip] != sha:
            now = datetime.now(UTC)
            old_mac = mac_to_str(self.cache[sip])
            new_mac = mac_to_str(sha)
            ip_str = socket.inet_ntoa(struct.pack("<I", sip))

            self.callback(
                MitmEvent(
                    event_id=generate_event_id(f"ebpf-{ip_str}-{new_mac}-{now.isoformat()}"),
                    timestamp=now,
                    attack_type="ARP_SPOOF",
                    severity="HIGH",
                    confidence=80,
                    src_mac=new_mac,
                    dst_mac=None,
                    src_ip=ip_str,
                    dst_ip=None,
                    original_mac=old_mac,
                    spoofed_mac=new_mac,
                    metadata={"source": "ebpf", "arp_op": ev.op},
                )
            )

        self.cache[sip] = sha

        # Detect gratuitous ARP
        if ev.sip == ev.tip:
            now = datetime.now(UTC)
            ip_str = socket.inet_ntoa(struct.pack("<I", sip))
            self.callback(
                MitmEvent(
                    event_id=generate_event_id(f"grat-{ip_str}-{now.isoformat()}"),
                    timestamp=now,
                    attack_type="ARP_GRATUITOUS",
                    severity="LOW",
                    confidence=30,
                    src_mac=mac_to_str(sha),
                    dst_mac=None,
                    src_ip=ip_str,
                    dst_ip=ip_str,
                    metadata={"source": "ebpf"},
                )
            )

    def run(self):
        if not self.bpf:
            return
        self.running = True
        self.bpf["events"].open_perf_buffer(self.handle_event)
        logger.info("eBPF ARP monitor running")
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except Exception as e:
                if self.running:
                    logger.error("eBPF poll error: %s", e)
                break

    def stop(self):
        self.running = False


# =============================================================================
# Database Handler
# =============================================================================


class MitmDatabase:
    def __init__(self, config: dict):
        self.config = config
        self._baseline_rules: list = []
        self._baseline_ts: float = 0.0
        self._ensure_tables()

    def _get_conn(self):
        return _db_connect()

    def _load_baseline(self) -> list:
        """Load baseline suppression rules (cached 60s)."""
        now = time.time()
        if self._baseline_ts and (now - self._baseline_ts) < 60:
            return self._baseline_rules
        try:
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute("SELECT attack_type, host(src_ip), src_mac::text FROM mitm_baseline")
            self._baseline_rules = [(a, i, m) for a, i, m in cur.fetchall()]
            conn.close()
            self._baseline_ts = now
        except Exception as exc:
            logger.debug("mitm_baseline unavailable: %s", exc)
        return self._baseline_rules

    def is_baselined(self, event: MitmEvent) -> bool:
        """True if the event matches a known-good baseline rule (NULL field = wildcard)."""
        for at, ip, mac in self._load_baseline():
            if at and at != event.attack_type:
                continue
            if ip and ip != event.src_ip:
                continue
            if mac and (event.src_mac or "").lower() != mac.lower():
                continue
            return True
        return False

    def _ensure_tables(self):
        try:
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS mitm_events (
                    id BIGSERIAL PRIMARY KEY,
                    event_id VARCHAR(64) UNIQUE NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    attack_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(10) NOT NULL,
                    confidence SMALLINT NOT NULL,
                    src_mac MACADDR, dst_mac MACADDR,
                    src_ip INET, dst_ip INET,
                    original_mac MACADDR, spoofed_mac MACADDR,
                    dns_query VARCHAR(255), dns_answer INET,
                    interface VARCHAR(50), metadata JSONB,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    false_positive BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS mitm_arp_cache (
                    id BIGSERIAL PRIMARY KEY,
                    ip_address INET NOT NULL, mac_address MACADDR NOT NULL,
                    interface VARCHAR(50),
                    first_seen TIMESTAMPTZ DEFAULT NOW(),
                    last_seen TIMESTAMPTZ DEFAULT NOW(),
                    seen_count BIGINT DEFAULT 1,
                    is_gateway BOOLEAN DEFAULT FALSE,
                    trust_score SMALLINT DEFAULT 50,
                    UNIQUE(ip_address, interface)
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_mitm_ts ON mitm_events(timestamp DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_mitm_type ON mitm_events(attack_type)")
            # Baseline suppression: operator-marked known-good patterns. Matching
            # events are flagged baseline=TRUE (hidden from the main dashboard and
            # excluded from alert counts, filed under the "baseline events" view).
            cur.execute(
                "ALTER TABLE mitm_events ADD COLUMN IF NOT EXISTS baseline BOOLEAN DEFAULT FALSE"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_mitm_baseline_flag ON mitm_events(baseline)"
            )
            cur.execute("""
                CREATE TABLE IF NOT EXISTS mitm_baseline (
                    id BIGSERIAL PRIMARY KEY,
                    attack_type VARCHAR(50),
                    src_ip INET,
                    src_mac MACADDR,
                    note TEXT,
                    created_by VARCHAR(128),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_mitm_baseline_match ON mitm_baseline(attack_type, src_ip)"
            )
            conn.commit()
            conn.close()
            logger.info("Database tables ready")
        except Exception as e:
            logger.error("Database setup error: %s", e)

    def insert(self, event: MitmEvent) -> bool:
        try:
            conn = self._get_conn()
            cur = conn.cursor()
            baselined = self.is_baselined(event)
            cur.execute(
                """
                INSERT INTO mitm_events (event_id, timestamp, attack_type, severity,
                    confidence, src_mac, src_ip, original_mac, spoofed_mac, metadata, baseline)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
            """,
                (
                    event.event_id,
                    event.timestamp,
                    event.attack_type,
                    event.severity,
                    event.confidence,
                    event.src_mac or None,
                    event.src_ip,
                    event.original_mac,
                    event.spoofed_mac,
                    Json(event.metadata),
                    baselined,
                ),
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error("DB insert error: %s", e)
            return False

    def upsert_arp_cache(self, entries: list) -> bool:
        """Upsert ARP cache entries into mitm_arp_cache DB table."""
        if not entries:
            return False
        try:
            conn = self._get_conn()
            cur = conn.cursor()
            for entry in entries:
                cur.execute(
                    """
                    INSERT INTO mitm_arp_cache
                        (ip_address, mac_address, interface,
                         first_seen, last_seen, seen_count,
                         is_gateway, trust_score)
                    VALUES (%s, %s, %s, NOW(), NOW(), 1, %s, %s)
                    ON CONFLICT (ip_address, interface) DO UPDATE SET
                        mac_address = EXCLUDED.mac_address,
                        last_seen   = NOW(),
                        seen_count  = mitm_arp_cache.seen_count + 1,
                        is_gateway  = EXCLUDED.is_gateway,
                        trust_score = EXCLUDED.trust_score
                """,
                    (
                        entry["ip"],
                        entry["mac"],
                        entry["interface"],
                        entry.get("is_gateway", False),
                        entry.get("trust_score", 50),
                    ),
                )
            conn.commit()
            conn.close()
            return True
        except Exception as ex:
            logger.error("ARP cache upsert error: %s", ex)
            return False


# =============================================================================
# JSON Logger
# =============================================================================


class JsonLogger:
    def __init__(self, path: str):
        self.path = path
        self._file = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self._file = open(path, "a", buffering=1)
        except Exception as e:
            logger.debug("Could not open MITM log file %s: %s", path, e)

    def log(self, event: MitmEvent):
        if not self._file:
            return
        try:
            self._file.write(
                json.dumps(
                    {
                        "timestamp": event.timestamp.isoformat(),
                        "event_id": event.event_id,
                        "attack_type": event.attack_type,
                        "severity": event.severity,
                        "confidence": event.confidence,
                        "src_mac": event.src_mac,
                        "src_ip": event.src_ip,
                        "original_mac": event.original_mac,
                        "spoofed_mac": event.spoofed_mac,
                        "metadata": event.metadata,
                    }
                )
                + "\n"
            )
            self._file.flush()
        except Exception as e:
            logger.debug("MITM log write error: %s", e)

    def close(self):
        if self._file:
            self._file.close()


# =============================================================================
# Main Detector
# =============================================================================


class MitmDetector:
    def __init__(
        self,
        interface: str,
        gateway_ips: list[str] | None = None,
        trusted_dns: list[str] | None = None,
        trusted_dhcp: list[str] | None = None,
        use_ebpf: bool = True,
    ):
        self.interface = interface
        self.gateway_ips = gateway_ips or MITM_GATEWAY_IPS or self._detect_gateways()
        self.trusted_dns = trusted_dns or MITM_TRUSTED_DNS
        self.trusted_dhcp = trusted_dhcp or MITM_TRUSTED_DHCP
        self.use_ebpf = use_ebpf

        self.db = MitmDatabase(DB_CONFIG)
        self.json_logger = JsonLogger(MITM_LOG_FILE)

        self.running = False
        self.alert_count = 0
        self.threads: list[tuple[threading.Thread, Any]] = []

    @staticmethod
    def _detect_gateways() -> list[str]:
        """Auto-detect default gateway IPs from routing table."""
        gateways = []
        try:
            out = subprocess.check_output(["ip", "route"], text=True, timeout=5)  # noqa: S607 # nosec B603 B607
            for line in out.splitlines():
                if line.startswith("default via "):
                    gw = line.split()[2]
                    gateways.append(gw)
        except Exception as e:
            logger.debug("Gateway detection failed: %s", e)
        return gateways

    def handle_event(self, event: MitmEvent):
        self.alert_count += 1
        colors = {
            "CRITICAL": "\033[91m",
            "HIGH": "\033[93m",
            "MEDIUM": "\033[94m",
            "LOW": "\033[90m",
        }
        c = colors.get(event.severity, "")
        logger.warning(
            "%s[%s]\033[0m %s: %s (MAC: %s) conf=%d%%",
            c,
            event.severity,
            event.attack_type,
            event.src_ip,
            event.src_mac,
            event.confidence,
        )
        self.json_logger.log(event)
        self.db.insert(event)

    def run(self):
        logger.info("=" * 60)
        logger.info("MiTM Detector Starting")
        logger.info("=" * 60)
        logger.info("Interface: %s", self.interface)
        logger.info("Gateways: %s", self.gateway_ips or "none")
        logger.info("Trusted DNS: %s", self.trusted_dns)
        logger.info("eBPF: %s", "enabled" if self.use_ebpf and HAS_BCC else "disabled")
        logger.info("=" * 60)

        self.running = True

        # ARP monitor (userspace, always works)
        arp = ArpMonitor(
            self.interface,
            self.gateway_ips,
            MITM_ARP_CHANGE_THRESHOLD,
            self.handle_event,
            db=self.db,
        )
        t = Thread(target=arp.run, daemon=True)
        t.start()
        self.threads.append((t, arp))

        # eBPF monitor (optional)
        if self.use_ebpf and HAS_BCC:
            ebpf = EbpfArpMonitor(self.handle_event)
            if ebpf.load():
                t = Thread(target=ebpf.run, daemon=True)
                t.start()
                self.threads.append((t, ebpf))

        # DNS monitor
        dns = DnsMonitor(self.interface, self.trusted_dns, self.handle_event)
        t = Thread(target=dns.run, daemon=True)
        t.start()
        self.threads.append((t, dns))

        # DHCP rogue server monitor
        dhcp = DhcpMonitor(self.interface, self.trusted_dhcp, self.handle_event)
        t = Thread(target=dhcp.run, daemon=True)
        t.start()
        self.threads.append((t, dhcp))

        # ICMP redirect monitor
        icmp = IcmpRedirectMonitor(self.interface, self.handle_event)
        t = Thread(target=icmp.run, daemon=True)
        t.start()
        self.threads.append((t, icmp))

        # LLMNR/NBT-NS poisoning monitor
        llmnr = LlmnrNbtnsMonitor(self.interface, self.handle_event)
        t = Thread(target=llmnr.run, daemon=True)
        t.start()
        self.threads.append((t, llmnr))

        # SSL stripping monitor
        sslstrip = SslStripMonitor(self.interface, self.handle_event)
        t = Thread(target=sslstrip.run, daemon=True)
        t.start()
        self.threads.append((t, sslstrip))

        logger.info("Detector running. Press Ctrl+C to stop.")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass  # silent: graceful shutdown
        finally:
            self.stop()

    def stop(self):
        self.running = False
        for _, monitor in self.threads:
            if hasattr(monitor, "stop"):
                monitor.stop()
        self.json_logger.close()
        logger.info("=" * 60)
        logger.info("Detector stopped. Alerts: %d", self.alert_count)
        logger.info("=" * 60)


# =============================================================================
# Main
# =============================================================================


def main():
    from honeylens.logging_setup import setup_logging

    setup_logging()
    parser = argparse.ArgumentParser(description="MiTM Attack Detector")
    parser.add_argument("-i", "--interface", default=INTERFACE)
    parser.add_argument("--gateway", action="append", dest="gateways")
    parser.add_argument("--dns", action="append", dest="dns_servers")
    parser.add_argument(
        "--dhcp", action="append", dest="dhcp_servers", help="Trusted DHCP server IPs"
    )
    parser.add_argument("--no-ebpf", action="store_true")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Must run as root", file=sys.stderr)
        sys.exit(1)

    detector = MitmDetector(
        interface=args.interface,
        gateway_ips=args.gateways,
        trusted_dns=args.dns_servers,
        trusted_dhcp=args.dhcp_servers,
        use_ebpf=not args.no_ebpf,
    )

    signal.signal(signal.SIGINT, lambda s, f: detector.stop())
    signal.signal(signal.SIGTERM, lambda s, f: detector.stop())

    detector.run()


if __name__ == "__main__":
    main()
