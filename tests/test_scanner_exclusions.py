#!/usr/bin/env python3
"""Known-scanner exclusion: identify research scanners so they are never published.

The gate matches on ASN, AS-org substring and the reverse-DNS hostname. In production the
stored enrichment (asn/as_org/hostname) is often empty, so the live PTR lookup is what actually
catches Censys and Shodan — these tests pin both the static matching and the rDNS fallback
(with the resolver mocked, so no network).
"""

from __future__ import annotations

import pytest

from honeylens.intelligence import scanner_exclusions as se


@pytest.fixture(autouse=True)
def _no_db(monkeypatch):
    # The IP path first does a DB lookup; keep tests off any database.
    monkeypatch.setattr(se, "_lookup_ip_profile", lambda ip: None)
    se.reload_config()


def test_hostname_suffix_matches_censys_and_shodan():
    assert se.is_known_scanner(hostname="49.146.94.167.censys-scanner.com")
    assert se.is_known_scanner(hostname="mango.census.shodan.io")
    assert se.is_known_scanner(hostname="scan-01.shadowserver.org")


def test_censys_scanner_com_suffix_is_present():
    # The real Censys PTR domain is censys-scanner.com, not censys.io — the gate must carry it.
    assert ".censys-scanner.com" in se._DEFAULT_HOSTNAME_SUFFIXES


def test_plain_hostname_is_not_a_scanner():
    assert not se.is_known_scanner(hostname="mail.example.com")


def test_asn_match():
    assert se.is_known_scanner(asn=398722)  # Censys
    assert se.is_known_scanner(asn=20473)  # Shodan (AS-CHOOPA)
    assert not se.is_known_scanner(asn=13335)  # Cloudflare — not a scanner


def test_org_substring_match():
    assert se.is_known_scanner(as_org="CENSYS-ARIN-01")
    assert se.is_known_scanner(as_org="Shodan LLC")
    assert not se.is_known_scanner(as_org="Comcast Cable")


def test_rdns_fallback_catches_scanner_when_enrichment_empty(monkeypatch):
    # No asn/org/hostname in the DB (the real production state): the live PTR must still catch it.
    monkeypatch.setattr(
        se, "_reverse_dns", lambda ip, timeout=2.0: "33.146.94.167.censys-scanner.com"
    )
    assert se.is_known_scanner(ip="167.94.146.33")


def test_rdns_fallback_does_not_flag_normal_host(monkeypatch):
    monkeypatch.setattr(se, "_reverse_dns", lambda ip, timeout=2.0: "mta-12.someisp.net")
    assert not se.is_known_scanner(ip="203.0.113.7")


def test_rdns_disabled_by_config(monkeypatch):
    # With rDNS off and no stored enrichment, there is nothing to match — the gate returns False.
    from honeylens import config as cfgmod

    monkeypatch.setitem(cfgmod.SCANNER_EXCLUSIONS, "rdns_lookup", False)
    se.reload_config()
    called = {"n": 0}

    def _should_not_run(ip, timeout=2.0):
        called["n"] += 1
        return "x.censys-scanner.com"

    monkeypatch.setattr(se, "_reverse_dns", _should_not_run)
    assert not se.is_known_scanner(ip="167.94.146.33")
    assert called["n"] == 0  # rDNS must not be called when disabled
    se.reload_config()
