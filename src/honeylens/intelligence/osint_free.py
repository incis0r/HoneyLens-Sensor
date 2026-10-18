"""
intelligence/osint_free.py — keyless OSINT providers (the hunting source of truth)

These run by default with no API key. They form the base of every attacker
profile; the key-gated providers in osint_providers.py only *extend* what these
already establish.

Providers:
  - internetdb : Shodan InternetDB (https://internetdb.shodan.io/<ip>) — open
                 ports, CPEs, known CVEs, tags, hostnames. Anonymous, no key.
  - rdap       : RDAP (https://rdap.org/ip/<ip>) — netblock, org, country,
                 abuse contact, allocation dates. Structured registration data.
  - cymru      : Team Cymru IP->ASN (whois.cymru.com) — ASN, BGP prefix,
                 registry, country, AS name.
  - tor        : Tor exit-node membership (bulk exit list, cached).
  - hostrecon  : system whois + reverse DNS (wraps intelligence.host_recon).

`normalize_osint()` folds a full osint_data dict into a single canonical record
(asn/org/country/ports/cves/tor_exit/ptr/abuse_contact) that the profiler and the
/attacker_hunting UI treat as authoritative.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import subprocess  # nosec B404 — fixed system commands (dig, whois, ip, tcpdump), args as a list, no shell
import time
from typing import Any, ClassVar

from honeylens.intelligence.osint_providers import OsintProvider

logger = logging.getLogger("sensor.osint")


class ShodanInternetDBProvider(OsintProvider):
    """Shodan InternetDB — keyless JSON: ports, CPEs, CVEs, tags, hostnames."""

    name = "internetdb"
    requires_key = False

    def __init__(self):
        super().__init__("", {"requests": 60, "period": 60})

    async def lookup(self, ip: str, session) -> dict[str, Any]:
        url = f"https://internetdb.shodan.io/{ip}"
        async with session.get(url, timeout=15) as resp:
            if resp.status == 404:
                return {"found": False}
            data = await resp.json()
            return {
                "found": True,
                "ports": data.get("ports", []),
                "cpes": data.get("cpes", []),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", []),
                "vulns": data.get("vulns", []),
            }


class RDAPProvider(OsintProvider):
    """RDAP registration data — netblock, org, country, abuse contact."""

    name = "rdap"
    requires_key = False

    def __init__(self):
        super().__init__("", {"requests": 60, "period": 60})

    @staticmethod
    def _abuse_email(entities: list) -> str:
        """Walk RDAP entities for an abuse role's email (vCard)."""
        for ent in entities or []:
            roles = ent.get("roles") or []
            nested = ent.get("entities") or []
            if "abuse" in roles:
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if isinstance(item, list) and item and item[0] == "email":
                        return str(item[-1])
            got = RDAPProvider._abuse_email(nested)
            if got:
                return got
        return ""

    async def lookup(self, ip: str, session) -> dict[str, Any]:
        url = f"https://rdap.org/ip/{ip}"
        async with session.get(url, timeout=15, allow_redirects=True) as resp:
            if resp.status >= 400:
                return {"found": False, "http_status": resp.status}
            data = await resp.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in (data.get("events") or [])}
        return {
            "found": True,
            "handle": data.get("handle", ""),
            "name": data.get("name", ""),
            "org": data.get("name", ""),
            "country": data.get("country", ""),
            "cidr": data.get("cidr")
            or (
                f"{data.get('startAddress', '')} - {data.get('endAddress', '')}"
                if data.get("startAddress")
                else ""
            ),
            "type": data.get("type", ""),
            "abuse_contact": self._abuse_email(data.get("entities")),
            "registered": events.get("registration", ""),
            "last_changed": events.get("last changed", ""),
        }


class CymruASNProvider(OsintProvider):
    """Team Cymru IP->ASN via whois.cymru.com (no key). Runs whois in an executor."""

    name = "cymru"
    requires_key = False

    def __init__(self):
        super().__init__("", {"requests": 120, "period": 60})

    @staticmethod
    def _cymru_whois(ip: str) -> str:
        ipaddress.ip_address(
            ip
        )  # address from the database, but it is what reaches the process arguments
        r = subprocess.run(  # noqa: S603 # nosec B603 B607 — fixed command, args as a list, no shell
            ["whois", "-h", "whois.cymru.com", f" -v {ip}"],  # noqa: S607 # nosec B607
            capture_output=True,
            text=True,
            timeout=12,
        )
        return r.stdout

    async def lookup(self, ip: str, session) -> dict[str, Any]:
        loop = asyncio.get_event_loop()
        try:
            out = await loop.run_in_executor(None, self._cymru_whois, ip)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return {"found": False}
        lines = [ln for ln in out.splitlines() if "|" in ln]
        if len(lines) < 2:
            return {"found": False}
        f = [c.strip() for c in lines[1].split("|")]
        # AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
        if len(f) < 7:
            return {"found": False}
        return {
            "found": True,
            "asn": f[0],
            "bgp_prefix": f[2],
            "country": f[3],
            "registry": f[4],
            "allocated": f[5],
            "as_name": f[6],
        }


class TorExitProvider(OsintProvider):
    """Tor exit-node membership against the bulk exit list (fetched + cached)."""

    name = "tor"
    requires_key = False

    _exits: ClassVar[set] = set()
    _fetched_at: float = 0.0
    _ttl = 6 * 3600
    _lock = None  # created lazily inside the running loop (avoids import-time loop binding)

    def __init__(self):
        super().__init__("", {"requests": 600, "period": 60})

    async def _ensure_list(self, session) -> None:
        if TorExitProvider._lock is None:
            TorExitProvider._lock = asyncio.Lock()
        async with TorExitProvider._lock:
            if TorExitProvider._exits and (time.time() - TorExitProvider._fetched_at) < self._ttl:
                return
            try:
                url = "https://check.torproject.org/torbulkexitlist"
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        TorExitProvider._exits = {
                            ln.strip()
                            for ln in text.splitlines()
                            if ln.strip() and not ln.startswith("#")
                        }
                        TorExitProvider._fetched_at = time.time()
                        logger.info(
                            "Tor exit list refreshed: %d nodes", len(TorExitProvider._exits)
                        )
            except Exception as e:
                logger.warning("Tor exit list fetch failed: %s", e)

    async def lookup(self, ip: str, session) -> dict[str, Any]:
        await self._ensure_list(session)
        if not TorExitProvider._exits:
            return {"tor_exit": None, "note": "exit list unavailable"}
        return {"tor_exit": ip in TorExitProvider._exits}


class HostReconProvider(OsintProvider):
    """System whois + reverse DNS via intelligence.host_recon (executor)."""

    name = "hostrecon"
    requires_key = False

    def __init__(self):
        super().__init__("", {"requests": 120, "period": 60})

    @staticmethod
    def _recon(ip: str) -> dict[str, Any]:
        from honeylens.intelligence import host_recon

        r = host_recon.recon_ip(ip)
        w = r.get("whois", {}) or {}
        return {
            "ptr": r.get("reverse_dns") or r.get("ptr") or "",
            "asn": r.get("asn") or w.get("asn", ""),
            "org": r.get("org_whois") or w.get("org_name", ""),
            "netname": r.get("netname") or w.get("netname", ""),
            "country": r.get("country_whois") or w.get("country", ""),
            "abuse_contact": w.get("abuse_email", "") or w.get("abuse", ""),
        }

    async def lookup(self, ip: str, session) -> dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._recon, ip)


# Order matters: authoritative registration first.
FREE_PROVIDERS = [
    HostReconProvider,
    CymruASNProvider,
    RDAPProvider,
    ShodanInternetDBProvider,
    TorExitProvider,
]


def _first(*vals) -> Any:
    for v in vals:
        if v:
            return v
    last = vals[-1] if vals else ""
    return last if last is not None else ""


def normalize_osint(osint: dict[str, Any]) -> dict[str, Any]:
    """Fold a full osint_data dict into one canonical, authoritative record.

    Keyless registration sources (Cymru/RDAP/whois) win for asn/org/country;
    InternetDB is authoritative for ports/CVEs; Tor for the exit flag. Keyed
    providers only fill gaps.
    """
    cymru = osint.get("cymru", {}) or {}
    rdap = osint.get("rdap", {}) or {}
    host = osint.get("hostrecon", {}) or {}
    idb = osint.get("internetdb", {}) or {}
    tor = osint.get("tor", {}) or {}
    abuse = osint.get("abuseipdb", {}) or {}
    shodan = osint.get("shodan", {}) or {}

    tor_exit = tor.get("tor_exit")
    if tor_exit is None:
        tor_exit = bool(abuse.get("is_tor"))

    return {
        "asn": _first(cymru.get("asn"), host.get("asn")),
        "as_name": _first(cymru.get("as_name"), rdap.get("org"), host.get("org"), abuse.get("isp")),
        "org": _first(rdap.get("org"), host.get("org"), abuse.get("isp")),
        "netname": _first(host.get("netname"), rdap.get("name")),
        "cidr": _first(cymru.get("bgp_prefix"), rdap.get("cidr")),
        "country": _first(
            cymru.get("country"), rdap.get("country"), host.get("country"), abuse.get("country")
        ),
        "registry": cymru.get("registry", ""),
        "registered": rdap.get("registered", ""),
        "abuse_contact": _first(rdap.get("abuse_contact"), host.get("abuse_contact")),
        "ptr": host.get("ptr", ""),
        "ports": _first(idb.get("ports"), shodan.get("open_ports"), []),
        "cves": idb.get("vulns", []),
        "cpes": idb.get("cpes", []),
        "tags": idb.get("tags", []),
        "hostnames": _first(idb.get("hostnames"), shodan.get("hostnames"), []),
        "tor_exit": bool(tor_exit),
        "abuse_score": abuse.get("abuse_score"),
        "sources": sorted(
            k for k, v in osint.items() if isinstance(v, dict) and v.get("status") == "ok"
        ),
    }
