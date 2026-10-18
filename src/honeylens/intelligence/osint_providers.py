#!/usr/bin/env python3
"""
osint_providers.py — OSINT Provider Classes for Attacker Profiling (Idea 22)
Hybrid Intelligence Sensor

Each provider implements the OsintProvider interface:
    async def lookup(self, ip: str) -> dict

All providers include per-instance rate limiting (token bucket) and
graceful error handling. Missing API keys → provider auto-disables.

Compatible with Python 3.9+ (no X|Y union syntax).
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

import aiohttp

logger = logging.getLogger("sensor.osint")

# ---------------------------------------------------------------------------
# Rate limiter (token bucket)
# ---------------------------------------------------------------------------


class TokenBucket:
    """Simple async-aware token bucket rate limiter."""

    def __init__(self, max_tokens: int, refill_period: float):
        self.max_tokens = max_tokens
        self.refill_period = refill_period  # seconds
        self.tokens = float(max_tokens)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            # Refill tokens proportionally
            self.tokens = min(
                self.max_tokens, self.tokens + (elapsed / self.refill_period) * self.max_tokens
            )
            self.last_refill = now

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    async def wait_and_acquire(self, timeout: float = 120.0) -> bool:  # noqa: ASYNC109 — provider API from 0.9
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if await self.acquire():
                return True
            await asyncio.sleep(0.5)
        return False


# ---------------------------------------------------------------------------
# Base provider
# ---------------------------------------------------------------------------


class OsintProvider(ABC):
    """Abstract base class for OSINT providers."""

    name: str = "base"
    requires_key: bool = True

    def __init__(self, api_key: str = "", rate_limit: dict[str, int] | None = None):
        self.api_key = api_key.strip()
        self.enabled = True

        if self.requires_key and not self.api_key:
            self.enabled = False
            logger.info("Provider %s disabled — no API key configured", self.name)

        rl = rate_limit or {"requests": 60, "period": 60}
        self.limiter = TokenBucket(rl["requests"], rl["period"])

    @abstractmethod
    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        """Query provider for IP intelligence. Returns normalized dict."""
        ...

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if IP is private/loopback/link-local to prevent SSRF."""
        try:
            import ipaddress

            addr = ipaddress.ip_address(ip_str)
            return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
        except ValueError:
            return True  # reject invalid IPs

    async def safe_lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        """Wrapper with rate limiting, error handling, and logging."""
        if not self.enabled:
            return {"provider": self.name, "status": "disabled"}

        if self._is_private_ip(ip):
            return {"provider": self.name, "status": "rejected", "reason": "private_ip"}

        if not await self.limiter.wait_and_acquire(timeout=30):
            logger.warning("Rate limit timeout for %s on IP %s", self.name, ip)
            return {"provider": self.name, "status": "rate_limited"}

        try:
            result = await self.lookup(ip, session)
            result["provider"] = self.name
            result["status"] = "ok"
            result["queried_at"] = time.time()
            return result
        except TimeoutError:
            logger.warning("Timeout querying %s for %s", self.name, ip)
            return {"provider": self.name, "status": "timeout"}
        except Exception as e:
            # Sanitize error message to avoid leaking API keys
            err_msg = str(e)
            if hasattr(self, "api_key") and self.api_key:
                err_msg = err_msg.replace(self.api_key, "***REDACTED***")
            if hasattr(self, "api_secret") and self.api_secret:
                err_msg = err_msg.replace(self.api_secret, "***REDACTED***")
            logger.error("Error querying %s for %s: %s", self.name, ip, err_msg)
            return {"provider": self.name, "status": "error", "error": "Provider query failed"}


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------


class AbuseIPDBProvider(OsintProvider):
    """
    https://docs.abuseipdb.com/
    Free: 1,000 checks/day
    Returns: abuse confidence score, ISP, usage type, country, reports.
    """

    name = "abuseipdb"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key, {"requests": 1000, "period": 86400})

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params: dict[str, str] = {
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": "",
        }
        async with session.get(
            url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            data = await resp.json()
            d = data.get("data", {})
            return {
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "usage_type": d.get("usageType", ""),
                "domain": d.get("domain", ""),
                "is_tor": d.get("isTor", False),
                "is_whitelisted": d.get("isWhitelisted", False),
                "total_reports": d.get("totalReports", 0),
                "num_distinct_users": d.get("numDistinctUsers", 0),
                "last_reported_at": d.get("lastReportedAt", ""),
                "report_categories": list(
                    set(
                        cat
                        for report in d.get("reports", [])
                        for cat in report.get("categories", [])
                    )
                ),
            }


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------


class ShodanProvider(OsintProvider):
    """
    https://developer.shodan.io/api
    Free account: /shodan/host/{ip} — 1 request/sec, no search credits needed.
    Returns: open ports, banners, OS, hostnames, vulns (if membership).
    """

    name = "shodan"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key, {"requests": 1, "period": 1})

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": self.api_key, "minify": "true"}
        async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status == 404:
                return {"found": False}
            data = await resp.json()
            return {
                "found": True,
                "open_ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "os": data.get("os", ""),
                "country": data.get("country_code", ""),
                "city": data.get("city", ""),
                "org": data.get("org", ""),
                "asn": data.get("asn", ""),
                "isp": data.get("isp", ""),
                "vulns": data.get("vulns", []),
                "last_update": data.get("last_update", ""),
                "tags": data.get("tags", []),
            }


# ---------------------------------------------------------------------------
# Censys (Free lookup API — since Oct 2025)
# ---------------------------------------------------------------------------


class CensysProvider(OsintProvider):
    """
    https://docs.censys.com/reference/get-started
    Free: host lookup API (Personal Access Token).
    Returns: services, ports, TLS certs, AS info, location.
    """

    name = "censys"

    def __init__(self, api_id: str = "", api_secret: str = ""):  # nosec B107 — empty key = provider without authentication, not a secret
        # Censys uses id + secret for auth
        self.api_id = api_id.strip()
        self.api_secret = api_secret.strip()
        key = f"{self.api_id}:{self.api_secret}" if self.api_id else ""
        super().__init__(key, {"requests": 60, "period": 60})

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        url = f"https://search.censys.io/api/v2/hosts/{ip}"
        auth = aiohttp.BasicAuth(self.api_id, self.api_secret)
        async with session.get(url, auth=auth, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status == 404:
                return {"found": False}
            data = await resp.json()
            result = data.get("result", {})
            services = result.get("services", [])
            return {
                "found": True,
                "services_count": len(services),
                "open_ports": [s.get("port") for s in services if s.get("port")],
                "service_names": list(
                    set(s.get("service_name", "") for s in services if s.get("service_name"))
                ),
                "as_name": result.get("autonomous_system", {}).get("name", ""),
                "asn": result.get("autonomous_system", {}).get("asn"),
                "country": result.get("location", {}).get("country_code", ""),
                "city": result.get("location", {}).get("city", ""),
                "os_vendor": result.get("operating_system", {}).get("vendor", ""),
                "os_product": result.get("operating_system", {}).get("product", ""),
            }


# ---------------------------------------------------------------------------
# GreyNoise (Community API)
# ---------------------------------------------------------------------------


class GreyNoiseProvider(OsintProvider):
    """
    https://docs.greynoise.io/docs/using-the-greynoise-community-api
    Free community: 50 requests/day.
    Returns: classification (benign/malicious/unknown), noise, riot, tags.
    """

    name = "greynoise"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key, {"requests": 50, "period": 86400})

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {
            "key": self.api_key,
            "Accept": "application/json",
        }
        async with session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            data = await resp.json()
            return {
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification", "unknown"),
                "name": data.get("name", ""),
                "link": data.get("link", ""),
                "last_seen": data.get("last_seen", ""),
                "message": data.get("message", ""),
            }


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------


class OTXProvider(OsintProvider):
    """
    https://otx.alienvault.com/api
    Free: unlimited (community).
    Returns: pulses, malware hashes, passive DNS, geo, reputation.
    """

    name = "otx"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key, {"requests": 100, "period": 60})

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        base = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}"
        headers = {"X-OTX-API-KEY": self.api_key}
        result: dict[str, Any] = {}

        # General info
        async with session.get(
            f"{base}/general", headers=headers, timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            data = await resp.json()
            result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
            result["reputation"] = data.get("reputation", 0)
            result["country"] = data.get("country_code", "")
            result["asn"] = data.get("asn", "")
            # Extract pulse names (first 10)
            pulses = data.get("pulse_info", {}).get("pulses", [])
            result["pulse_names"] = [p.get("name", "") for p in pulses[:10]]
            result["pulse_tags"] = list(set(tag for p in pulses[:10] for tag in p.get("tags", [])))[
                :20
            ]

        # Malware
        try:
            async with session.get(
                f"{base}/malware", headers=headers, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                data = await resp.json()
                malware = data.get("data", [])
                result["malware_count"] = len(malware)
                result["malware_hashes"] = [m.get("hash", "") for m in malware[:5]]
        except Exception as e:
            logger.debug("OTX malware endpoint failed for %s: %s", ip, e)
            result["malware_count"] = 0
            result["malware_hashes"] = []

        return result


# ---------------------------------------------------------------------------
# IPinfo.io
# ---------------------------------------------------------------------------


class IPinfoProvider(OsintProvider):
    """
    https://ipinfo.io/developers
    Free: 50,000 req/month.
    Returns: geo, ASN, org, hostname, VPN/proxy/Tor detection.
    """

    name = "ipinfo"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key, {"requests": 50000, "period": 2592000})

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        url = f"https://ipinfo.io/{ip}/json"
        params = {"token": self.api_key} if self.api_key else {}
        async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            data = await resp.json()
            privacy = data.get("privacy", {})
            return {
                "hostname": data.get("hostname", ""),
                "city": data.get("city", ""),
                "region": data.get("region", ""),
                "country": data.get("country", ""),
                "org": data.get("org", ""),
                "asn": data.get("asn", {}).get("asn", "")
                if isinstance(data.get("asn"), dict)
                else "",
                "is_vpn": privacy.get("vpn", False),
                "is_proxy": privacy.get("proxy", False),
                "is_tor": privacy.get("tor", False),
                "is_relay": privacy.get("relay", False),
                "is_hosting": privacy.get("hosting", False),
            }


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------


class VirusTotalProvider(OsintProvider):
    """
    https://developers.virustotal.com/reference
    Free: 4 req/min, 500/day.
    Returns: detection stats, communicating files, passive DNS, WHOIS.
    """

    name = "virustotal"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key, {"requests": 4, "period": 60})

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}
        async with session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)
        ) as resp:
            data = await resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner", ""),
                "country": attrs.get("country", ""),
                "continent": attrs.get("continent", ""),
                "network": attrs.get("network", ""),
                "whois": (attrs.get("whois", "") or "")[:500],  # truncate
                "tags": attrs.get("tags", []),
            }


# ---------------------------------------------------------------------------
# ThreatFox (abuse.ch) — Auth-Key required
# ---------------------------------------------------------------------------


class ThreatFoxProvider(OsintProvider):
    """
    https://threatfox.abuse.ch/api/
    Community API requires an Auth-Key.
    Returns: IOCs, malware families, botnet C2.
    """

    name = "threatfox"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key, {"requests": 60, "period": 60})

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search_term": ip}
        async with session.post(
            url,
            json=payload,
            headers={"Auth-Key": self.api_key},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            if data.get("query_status") == "no_result":
                return {"found": False, "iocs": []}
            if data.get("query_status") != "ok":
                raise ValueError("ThreatFox returned an unsuccessful query status")
            iocs = data.get("data", []) or []
            return {
                "found": len(iocs) > 0,
                "ioc_count": len(iocs),
                "malware_families": list(
                    set(i.get("malware_printable", "") for i in iocs if i.get("malware_printable"))
                ),
                "threat_types": list(
                    set(i.get("threat_type", "") for i in iocs if i.get("threat_type"))
                ),
                "tags": list(set(tag for i in iocs for tag in (i.get("tags") or [])))[:20],
                "first_seen": iocs[0].get("first_seen_utc", "") if iocs else "",
                "confidence_levels": list(set(i.get("confidence_level", 0) for i in iocs)),
            }


# ---------------------------------------------------------------------------
# Feodo Tracker (abuse.ch) — no API key required
# ---------------------------------------------------------------------------


class FeodoProvider(OsintProvider):
    """
    https://feodotracker.abuse.ch/
    Free: public JSON feed of botnet C2 IPs.
    Checks: Dridex, Emotet, TrickBot, QakBot, BazarLoader, etc.
    """

    name = "feodo"
    requires_key = False

    # Cache the feed to avoid re-downloading every lookup
    _cache: dict[str, dict] | None = None
    _cache_ts = 0.0

    def __init__(self):
        # Lookups use a local cache; the feed itself is downloaded at most once
        # per hour after a successful refresh. Do not exhaust a ten-IP quota
        # while reading that cache during the first profiler batch.
        super().__init__("", {"requests": 1000, "period": 3600})

    async def _refresh_feed(self, session: "aiohttp.ClientSession") -> None:
        now = time.monotonic()
        if FeodoProvider._cache is not None and (now - FeodoProvider._cache_ts) < 3600:
            return  # cache valid for 1 hour

        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
                if not isinstance(data, list) or any(not isinstance(e, dict) for e in data):
                    raise ValueError("Invalid Feodo feed schema")
                # Build IP lookup dict
                feed: dict[str, dict] = {}
                for entry in data:
                    ip = entry.get("ip_address", "")
                    if ip:
                        feed[ip] = {
                            "port": entry.get("port", entry.get("dst_port")),
                            "malware": entry.get("malware", ""),
                            "status": entry.get("status", ""),
                            "first_seen": entry.get("first_seen", ""),
                            "last_online": entry.get("last_online", ""),
                        }
                FeodoProvider._cache = feed
                FeodoProvider._cache_ts = now
                logger.info("Feodo feed refreshed: %d C2 IPs", len(feed))
        except Exception as e:
            logger.warning("Failed to refresh Feodo feed: %s", e)
            # A failed refresh must not become a successful negative lookup,
            # even if an older cache exists. safe_lookup exposes the failure.
            raise

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        await self._refresh_feed(session)
        entry = (FeodoProvider._cache or {}).get(ip)
        if entry:
            return {
                "found": True,
                "is_botnet_c2": True,
                "malware": entry.get("malware", ""),
                "c2_port": entry.get("port"),
                "c2_status": entry.get("status", ""),
                "first_seen": entry.get("first_seen", ""),
                "last_online": entry.get("last_online", ""),
            }
        return {"found": False, "is_botnet_c2": False}


# ---------------------------------------------------------------------------
# Pulsedive
# ---------------------------------------------------------------------------


class PulsediveProvider(OsintProvider):
    """
    https://pulsedive.com/api/
    Free: 30 req/day.
    Returns: risk score, threats, feeds, properties.
    """

    name = "pulsedive"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key, {"requests": 30, "period": 86400})

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        url = "https://pulsedive.com/api/info.php"
        params: dict[str, str] = {
            "indicator": ip,
            "key": self.api_key,
        }
        async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            data = await resp.json()
            return {
                "risk": data.get("risk", "unknown"),
                "risk_recommended": data.get("risk_recommended", "unknown"),
                "threats": [t.get("name", "") for t in data.get("threats", [])][:10],
                "feeds": [f.get("name", "") for f in data.get("feeds", [])][:10],
                "properties": {
                    p.get("key", ""): p.get("value", "")
                    for p in data.get("properties", {}).get("dns", [])
                },
            }


# ---------------------------------------------------------------------------
# URLScan.io
# ---------------------------------------------------------------------------


class URLScanProvider(OsintProvider):
    """
    https://urlscan.io/docs/api/
    Free: 5,000 searches/day (public results only).
    Returns: related scans, technologies, verdicts.
    """

    name = "urlscan"

    def __init__(self, api_key: str = ""):
        super().__init__(api_key, {"requests": 100, "period": 60})

    async def lookup(self, ip: str, session: "aiohttp.ClientSession") -> dict[str, Any]:
        url = "https://urlscan.io/api/v1/search/"
        headers = {"API-Key": self.api_key} if self.api_key else {}
        params: dict[str, str] = {"q": f"ip:{ip}", "size": "5"}
        async with session.get(
            url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            data = await resp.json()
            results = data.get("results", [])
            return {
                "scan_count": len(results),
                "urls_scanned": [r.get("page", {}).get("url", "") for r in results[:5]],
                "verdicts": [
                    r.get("verdicts", {}).get("overall", {}).get("malicious", False)
                    for r in results[:5]
                ],
                "countries": list(
                    set(
                        r.get("page", {}).get("country", "")
                        for r in results
                        if r.get("page", {}).get("country")
                    )
                ),
            }


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


def build_providers(config: dict[str, Any]) -> list[OsintProvider]:
    """
    Build and return a list of enabled OSINT providers based on config.

    config = {
        "api_keys": {"abuseipdb": "...", "shodan": "...", ...},
        "providers_enabled": ["abuseipdb", "shodan", ...],
    }
    """
    keys = config.get("api_keys", {})
    enabled = set(config.get("providers_enabled", []))

    all_providers: list[tuple[str, OsintProvider]] = []

    # Keyed providers
    all_providers.append(("abuseipdb", AbuseIPDBProvider(keys.get("abuseipdb", ""))))
    all_providers.append(("shodan", ShodanProvider(keys.get("shodan", ""))))
    all_providers.append(
        ("censys", CensysProvider(keys.get("censys_id", ""), keys.get("censys_secret", "")))
    )
    all_providers.append(("greynoise", GreyNoiseProvider(keys.get("greynoise", ""))))
    all_providers.append(("otx", OTXProvider(keys.get("otx", ""))))
    all_providers.append(("ipinfo", IPinfoProvider(keys.get("ipinfo", ""))))
    all_providers.append(("virustotal", VirusTotalProvider(keys.get("virustotal", ""))))
    all_providers.append(("urlscan", URLScanProvider(keys.get("urlscan", ""))))
    all_providers.append(("pulsedive", PulsediveProvider(keys.get("pulsedive", ""))))

    # Keyless providers
    all_providers.append(("threatfox", ThreatFoxProvider(keys.get("threatfox", ""))))
    all_providers.append(("feodo", FeodoProvider()))

    result: list[OsintProvider] = []

    # Keyless "source of truth" providers (InternetDB/RDAP/Cymru/Tor/host-recon) are ALWAYS on,
    # independent of providers_enabled. They need no API key and are what actually fills
    # asn/as_org/hostname/ptr — the fields the scanner-exclusion and profiling logic rely on.
    # (Previously they were appended to the gated list below, so a non-empty providers_enabled
    # that did not name them silently dropped all keyless enrichment.) Lazy import avoids the
    # osint_free <-> osint_providers circular import.
    from honeylens.intelligence.osint_free import FREE_PROVIDERS

    free_names = set()
    for cls in FREE_PROVIDERS:
        p = cls()  # type: ignore[abstract]  # the list contains only concrete classes
        free_names.add(p.name)
        if p.enabled:
            result.append(p)
            logger.info("OSINT provider enabled (keyless, always-on): %s", p.name)

    # Keyed and optional providers: gated by providers_enabled, or auto-enabled (those that
    # have a key) when no explicit list is configured.
    auto_enable = not enabled
    for name, provider in all_providers:
        if name in free_names:
            continue  # already added above, unconditionally
        if (name in enabled or auto_enable) and provider.enabled:
            result.append(provider)
            logger.info("OSINT provider enabled: %s", name)
        elif name in enabled and not provider.enabled:
            logger.warning("OSINT provider %s in enabled list but missing API key", name)

    return result


async def collect_osint(
    ip: str,
    providers: list[OsintProvider],
    cooldown: float = 2.0,
) -> dict[str, Any]:
    """
    Query all enabled providers for a given IP.
    Returns merged dict keyed by provider name.

    Uses sequential calls with cooldown to respect rate limits.
    For high-throughput scenarios, switch to asyncio.gather with semaphore.
    """
    if aiohttp is None:
        raise ImportError("aiohttp is required: pip install aiohttp --break-system-packages")

    merged: dict[str, Any] = {}
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for provider in providers:
            result = await provider.safe_lookup(ip, session)
            merged[provider.name] = result

            if cooldown > 0 and provider != providers[-1]:
                await asyncio.sleep(cooldown)

    return merged
