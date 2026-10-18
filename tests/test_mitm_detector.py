"""Offline tests for the MiTM detector FP fixes + baseline matching.

No network / no DB: monitors' _parse/parse_line are driven with synthetic
tcpdump lines and a capturing callback; baseline matching is a pure function.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import honeylens.intelligence.mitm_detector as md
from honeylens.intelligence.mitm_detector import (
    DhcpMonitor,
    DnsMonitor,
    LlmnrNbtnsMonitor,
    MitmDatabase,
    MitmEvent,
)


def _collector():
    ev = []
    return ev, ev.append


# --- LLMNR / NBT-NS: legit responders must not spam CRITICAL --------------


def test_nbtns_cooldown_one_event_medium():
    """A busy legit responder (many replies) yields ONE MEDIUM event, not a flood."""
    ev, cb = _collector()
    m = LlmnrNbtnsMonitor("eth0", cb)
    # 8 NBT-NS (port 137) replies from one host to 5 distinct queriers
    dsts = ["192.168.0.10", "192.168.0.11", "192.168.0.12", "192.168.0.13", "192.168.0.14"]
    for i in range(8):
        dst = dsts[i % len(dsts)]
        m._parse(f"12:00:0{i} IP 192.168.0.242.137 > {dst}.137: UDP, length 50")
    assert len(ev) == 1, f"expected 1 throttled event, got {len(ev)}"
    assert ev[0].attack_type == "NBT-NS_POISONING"
    assert ev[0].severity == "MEDIUM"  # not CRITICAL — ambiguous by default
    assert ev[0].metadata["reply_count"] >= 5


def test_llmnr_broad_responder_escalates_high(monkeypatch):
    """One host answering many DISTINCT queriers is the poisoning shape -> HIGH."""
    monkeypatch.setattr(md, "MITM_LLMNR_COOLDOWN", 0)  # allow repeat emits in-test
    ev, cb = _collector()
    m = LlmnrNbtnsMonitor("eth0", cb)
    for i in range(9):  # 9 distinct queriers, LLMNR (5355)
        m._parse(f"12:00:0{i} IP 10.0.0.5.5355 > 10.0.0.{100 + i}.5355: UDP, length 40")
    assert ev, "expected at least one event"
    assert ev[-1].attack_type == "LLMNR_POISONING"
    assert ev[-1].severity == "HIGH"
    assert ev[-1].metadata["distinct_queriers"] >= md.MITM_LLMNR_BROAD_QUERIERS


# --- DHCP: trust-on-first-use, only a 2nd distinct server is rogue ---------


def test_dhcp_tofu_first_learned_second_rogue():
    ev, cb = _collector()
    m = DhcpMonitor("eth0", [], cb)  # no trusted configured
    m._parse("12:00:00 IP 192.168.0.1.67 > 255.255.255.255.68: BOOTP/DHCP")
    m._parse("12:00:01 IP 192.168.0.1.67 > 255.255.255.255.68: BOOTP/DHCP")  # same -> silent
    m._parse("12:00:02 IP 192.168.0.99.67 > 255.255.255.255.68: BOOTP/DHCP")  # 2nd -> rogue
    types = [e.attack_type for e in ev]
    assert types == ["DHCP_SERVER_OBSERVED", "DHCP_ROGUE_SERVER"]
    assert ev[0].severity == "MEDIUM" and ev[1].severity == "CRITICAL"


def test_dhcp_configured_trusted_not_flagged():
    ev, cb = _collector()
    m = DhcpMonitor("eth0", ["192.168.0.1"], cb)
    m._parse("12:00:00 IP 192.168.0.1.67 > 255.255.255.255.68: BOOTP/DHCP")
    assert ev == []  # trusted server = silent


# --- DNS: only untrusted responders flagged --------------------------------


def test_dns_trusted_vs_untrusted():
    ev, cb = _collector()
    m = DnsMonitor("eth0", ["8.8.8.8"], cb)
    m.parse_line("12:00:00 IP 8.8.8.8.53 > 192.168.0.10.40000: 12345 1/0/0 A 1.2.3.4")
    assert ev == []  # trusted resolver
    m.parse_line("12:00:01 IP 203.0.113.9.53 > 192.168.0.10.40000: 12346 1/0/0 A 1.2.3.4")
    assert len(ev) == 1 and ev[0].attack_type == "DNS_UNTRUSTED_SERVER"


# --- Baseline matching (pure) ----------------------------------------------


def _mk(attack_type, src_ip, src_mac=""):
    return MitmEvent(
        event_id="x",
        timestamp=None,
        attack_type=attack_type,
        severity="MEDIUM",
        confidence=50,
        src_mac=src_mac,
        dst_mac=None,
        src_ip=src_ip,
        dst_ip=None,
    )


def test_is_baselined_matches_type_and_ip():
    dbh = object.__new__(MitmDatabase)  # skip __init__/DB
    dbh._baseline_rules = [("NBT-NS_POISONING", "192.168.0.242", None)]
    dbh._baseline_ts = time.time()
    assert dbh.is_baselined(_mk("NBT-NS_POISONING", "192.168.0.242")) is True
    assert dbh.is_baselined(_mk("NBT-NS_POISONING", "192.168.0.99")) is False
    assert dbh.is_baselined(_mk("LLMNR_POISONING", "192.168.0.242")) is False


def test_is_baselined_wildcards():
    dbh = object.__new__(MitmDatabase)
    dbh._baseline_rules = [(None, "10.0.0.5", None)]  # any attack_type from this IP
    dbh._baseline_ts = time.time()
    assert dbh.is_baselined(_mk("ARP_SPOOF", "10.0.0.5")) is True
    assert dbh.is_baselined(_mk("ARP_SPOOF", "10.0.0.6")) is False
