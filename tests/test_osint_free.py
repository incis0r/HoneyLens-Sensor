"""Offline tests for the keyless OSINT module (intelligence/osint_free.py).

No network: HTTP providers are driven with a fake aiohttp session, the Cymru
subprocess is monkeypatched, and normalize/merge is a pure function.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from honeylens.intelligence import osint_free as F


# The shared TokenBucket creates an asyncio.Lock() at provider __init__ (needs a
# current loop on 3.9). Other test modules run asyncio.run(), which unsets the
# loop — so give every test in this module a fresh, current loop.
@pytest.fixture(autouse=True)
def _fresh_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield loop
    finally:
        loop.close()
        asyncio.set_event_loop(None)


# --- fake aiohttp session ---------------------------------------------------
class _Resp:
    def __init__(self, status=200, payload=None, text=""):
        self.status = status
        self._p = payload if payload is not None else {}
        self._t = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self):
        return self._p

    async def text(self):
        return self._t


class _Session:
    def __init__(self, resp):
        self._resp = resp

    def get(self, *a, **k):
        return self._resp


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# --- normalize_osint (the source-of-truth merge) ----------------------------
def _sample():
    return {
        "cymru": {
            "status": "ok",
            "asn": "15169",
            "bgp_prefix": "8.8.8.0/24",
            "country": "US",
            "registry": "arin",
            "as_name": "GOOGLE, US",
        },
        "rdap": {
            "status": "ok",
            "org": "Google LLC",
            "country": "US",
            "cidr": "8.8.8.0/24",
            "abuse_contact": "abuse@google.com",
            "registered": "1992-12-01",
        },
        "internetdb": {
            "status": "ok",
            "found": True,
            "ports": [53, 443],
            "vulns": ["CVE-2021-0001"],
            "cpes": ["cpe:/a:x"],
            "tags": ["cdn"],
            "hostnames": ["dns.google"],
        },
        "tor": {"status": "ok", "tor_exit": True},
        "hostrecon": {
            "status": "ok",
            "ptr": "dns.google",
            "asn": "15169",
            "org": "Google",
            "netname": "GOOGLE",
            "country": "US",
        },
        "abuseipdb": {"status": "ok", "abuse_score": 12, "is_tor": False},
    }


def test_normalize_prefers_keyless_sources():
    c = F.normalize_osint(_sample())
    assert c["asn"] == "15169"  # cymru
    assert c["org"] == "Google LLC"  # rdap
    assert c["ports"] == [53, 443]  # internetdb
    assert c["cves"] == ["CVE-2021-0001"]
    assert c["tor_exit"] is True  # tor provider
    assert c["abuse_contact"] == "abuse@google.com"
    assert c["ptr"] == "dns.google"
    assert c["cidr"] == "8.8.8.0/24"
    assert c["registry"] == "arin"
    assert "cymru" in c["sources"] and "rdap" in c["sources"]


def test_normalize_tor_falls_back_to_abuseipdb():
    d = _sample()
    d["tor"] = {"status": "ok", "tor_exit": None, "note": "exit list unavailable"}
    d["abuseipdb"]["is_tor"] = True
    assert F.normalize_osint(d)["tor_exit"] is True


def test_normalize_empty_is_safe():
    c = F.normalize_osint({})
    assert c["asn"] == "" and c["ports"] == [] and c["tor_exit"] is False


# --- RDAP abuse-contact extraction ------------------------------------------
def test_rdap_abuse_email_nested():
    entities = [
        {
            "roles": ["registrant"],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["email", {}, "text", "abuse@example.net"],
                        ],
                    ],
                }
            ],
        }
    ]
    assert F.RDAPProvider._abuse_email(entities) == "abuse@example.net"


# --- InternetDB provider (fake HTTP) ----------------------------------------
def test_internetdb_parses_payload():
    resp = _Resp(
        200,
        {
            "ports": [22, 80],
            "cpes": ["cpe:/o:linux"],
            "hostnames": ["h"],
            "tags": ["scanner"],
            "vulns": ["CVE-2023-1234"],
        },
    )
    r = _run(F.ShodanInternetDBProvider().lookup("8.8.8.8", _Session(resp)))
    assert r["found"] and r["ports"] == [22, 80] and r["vulns"] == ["CVE-2023-1234"]


def test_internetdb_404_not_found():
    r = _run(F.ShodanInternetDBProvider().lookup("8.8.8.8", _Session(_Resp(404))))
    assert r == {"found": False}


# --- Cymru parsing (monkeypatched whois) ------------------------------------
def test_cymru_parses_whois(monkeypatch):
    out = (
        "AS      | IP        | BGP Prefix   | CC | Registry | Allocated  | AS Name\n"
        "15169   | 8.8.8.8   | 8.8.8.0/24   | US | arin     | 2023-12-28 | GOOGLE, US\n"
    )
    monkeypatch.setattr(F.CymruASNProvider, "_cymru_whois", staticmethod(lambda ip: out))
    r = _run(F.CymruASNProvider().lookup("8.8.8.8", None))
    assert (
        r["found"] and r["asn"] == "15169" and r["country"] == "US" and r["as_name"] == "GOOGLE, US"
    )


# --- registration: keyless providers are always enabled ---------------------
def test_free_providers_are_keyless_and_enabled():
    for cls in F.FREE_PROVIDERS:
        p = cls()
        assert p.requires_key is False and p.enabled is True


def test_build_providers_includes_keyless_set():
    from honeylens.intelligence.osint_providers import build_providers

    names = {p.name for p in build_providers({})}
    assert {"internetdb", "rdap", "cymru", "tor", "hostrecon"} <= names
