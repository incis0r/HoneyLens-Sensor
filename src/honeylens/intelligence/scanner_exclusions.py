"""
scanner_exclusions.py — Known Scanner / Research Scanner Exclusion
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Shared module for skipping known benign internet scanners from:
  - Blog publishing
  - Attacker hunting (OSINT profiling)
  - AI analysis triggers

Known scanners are identified by:
  - AS number (ASN)
  - AS organisation name substring (case-insensitive)
  - Reverse DNS / hostname patterns (suffix match)

Configuration lives in config.py under SCANNER_EXCLUSIONS.
This module provides a single function: is_known_scanner(ip_or_profile)

Usage:
    from honeylens.intelligence.scanner_exclusions import is_known_scanner

    # With a profile dict (from attacker_profiles table)
    if is_known_scanner(profile=profile_row):
        return  # skip

    # With individual fields
    if is_known_scanner(asn=19551, hostname="scan-42.shadowserver.org"):
        return  # skip

    # Quick check with just IP (does DB lookup)
    if is_known_scanner(ip="167.94.138.41"):
        return  # skip
"""

import argparse
import functools
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

logger = logging.getLogger("scanner_exclusions")


@functools.lru_cache(maxsize=4096)
def _reverse_dns(ip: str, timeout: float = 2.0) -> str:
    """Best-effort reverse DNS with a hard timeout. Returns the PTR hostname or ''.

    The attacker_profiles enrichment often has no hostname (the keyless OSINT sources are
    not always populated), yet the scanner PTRs — ``*.censys-scanner.com``, ``*.shodan.io``,
    ``*.shadowserver.org`` — are the single most reliable scanner tell. Resolving here makes
    the gate work without depending on stored enrichment. gethostbyaddr can hang on the system
    resolver, so it runs in a thread we abandon after ``timeout``."""

    def _lookup() -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            return ""

    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(_lookup).result(timeout=timeout)
    except Exception:  # timeout or any resolver error — best-effort only
        return ""


# ---------------------------------------------------------------------------
# Crawler claims: the user-agent against the PTR
# ---------------------------------------------------------------------------
# A forged Googlebot is the single busiest user-agent in the fleet's secrets sweep: 7,833
# `SENSITIVE_FILE` and 7,472 `SCANNER` requests claim
# `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)` while asking for
# `/.env` and `/.git/config` (the 4 Oct-4 Nov fleet review §5.4). Google does not request
# dotfiles.
#
# This cannot be a text rule, and that is the whole design constraint: the detection is "the
# claimed agent does not match the PTR", and a PTR lookup is a network call. At those row counts
# it cannot live in `classify_event_row`, which is why it lives here, beside `_reverse_dns`,
# cached once per ADDRESS rather than once per event, on the enrichment path.
#
# Each operator publishes the PTR suffixes its crawlers resolve to, and the check is the one
# those operators themselves document: resolve the PTR, require the suffix.
_CRAWLER_PTR_SUFFIXES: dict[str, tuple[str, ...]] = {
    "googlebot": (".googlebot.com", ".google.com", ".googleusercontent.com"),
    "google-inspectiontool": (".googlebot.com", ".google.com"),
    "storebot-google": (".googlebot.com", ".google.com"),
    "bingbot": (".search.msn.com",),
    "bingpreview": (".search.msn.com",),
    "yandexbot": (".yandex.ru", ".yandex.net", ".yandex.com"),
    "baiduspider": (".baidu.com", ".baidu.jp"),
    "duckduckbot": (".duckduckgo.com",),
    "applebot": (".applebot.apple.com",),
    "petalbot": (".petalsearch.com", ".aspiegel.com"),
}

# Resolved once per address, for every claim on that address. `_reverse_dns` has its own
# lru_cache, but the resolver is injectable for tests and the cache must hold either way.
_ptr_cache: dict[str, str] = {}

CLAIM_NONE = "none"
CLAIM_GENUINE = "genuine"
CLAIM_FORGED = "forged"
CLAIM_UNPROVEN = "unproven"


def claimed_crawler(user_agent: str | None) -> str | None:
    """The crawler a user-agent claims to be, or None. Lowercased token from the table above."""
    if not user_agent:
        return None
    ua = user_agent.lower()
    for name in _CRAWLER_PTR_SUFFIXES:
        if name in ua:
            return name
    return None


def crawler_claim(user_agent: str | None, ip: str | None, resolver=None) -> str:
    """Judge a crawler claim against the address's PTR.

    Four outcomes, and the fourth is the point: `CLAIM_UNPROVEN` when no PTR comes back.
    Absence of proof is not proof — a resolver timeout, a missing PTR or a broken resolver must
    never produce a forgery verdict, because the busiest hours are exactly when the resolver is
    slowest and a honeypot under load would start accusing real crawlers.
    """
    name = claimed_crawler(user_agent)
    if name is None or not ip:
        return CLAIM_NONE
    if ip in _ptr_cache:
        ptr = _ptr_cache[ip]
    else:
        resolve = resolver or _reverse_dns
        try:
            ptr = (resolve(ip) or "").strip().rstrip(".").lower()
        except Exception:  # a resolver is a network call; it never decides the verdict
            ptr = ""
        _ptr_cache[ip] = ptr
    if not ptr:
        return CLAIM_UNPROVEN
    if ptr.endswith(_CRAWLER_PTR_SUFFIXES[name]):
        return CLAIM_GENUINE
    return CLAIM_FORGED


def crawler_claim_with_hostname(
    user_agent: str | None, ip: str | None, hostname: str | None, resolver=None
) -> str:
    """`crawler_claim`, but using a PTR the enrichment already stored when there is one.

    The profiler has usually resolved the address before this runs, so the common case costs no
    lookup. When `hostname` is empty -- which the `osint-enrichment-empty` finding says is the
    normal case on this fleet -- it falls through to the cached resolver.
    """
    name = claimed_crawler(user_agent)
    if name is None:
        return CLAIM_NONE
    ptr = (hostname or "").strip().rstrip(".").lower()
    if not ptr:
        return crawler_claim(user_agent, ip, resolver=resolver)
    return CLAIM_GENUINE if ptr.endswith(_CRAWLER_PTR_SUFFIXES[name]) else CLAIM_FORGED


def is_self_identifying_scanner(user_agent: str | None) -> bool:
    """True when a user-agent names a scanner that identifies itself honestly.

    **Informational only, and deliberately not part of `is_known_scanner`.** That function gates
    hunting and deep AI analysis, and a user-agent is a string the sender chooses: wiring this
    into it would let anyone switch off our own follow-up work by sending
    `User-Agent: l9explore/1.2.2`. It also buys nothing there -- a real Censys or Shodan node is
    already excluded by its ASN and its PTR, which the sender cannot choose -- so the only thing
    the header would add to an exclusion gate is the bypass.

    It is worth a name because the window review is right that honest self-identification is
    cheap signal: it becomes a profile tag, and a human or a query can use it. If it is ever to
    suppress anything, it must be corroborated by the ASN or the PTR, which is what
    `is_known_scanner` already tests.
    """
    if not user_agent:
        return False
    ua_lower = str(user_agent).lower()
    return any(p in ua_lower for p in _get_config()["user_agent_substrings"])


def crawler_tags(
    user_agents, ip: str | None, hostname: str | None = None, resolver=None
) -> list[str]:
    """Profile tags for the agents one address claimed: at most one of each, in a fixed order.

    `FORGED_CRAWLER` only when a claim is positively contradicted by the PTR.
    `CRAWLER_CLAIM_UNVERIFIED` when no PTR came back at all, which is a weaker and separate
    statement -- and the measurement says it is the common one. Of 7,564 Googlebot-claiming rows
    on sensor-a from 41 sources, measured 2026-11-05 by resolving each claimant from the sensor,
    NOT ONE could be contradicted: every address has no PTR whatsoever. On sensor-b 601 of 1,192
    rows were positively forged (`ip-58-82.superbithost.com` for 600 of them) and the rest were
    unproven.

    So the "three-line reverse-DNS detection" the review asked for would have been right about
    601 rows and wrong by construction about 7,564 if a missing PTR were read as a forgery. The
    two tags keep them apart: one says the claim is contradicted, the other that it could not be
    checked. Google documents that its crawlers always resolve, so an unverified claim is still
    worth a name -- it is just not the same claim.

    `SELF_IDENTIFYING_SCANNER` is the opposite behaviour and needs no lookup at all.
    """
    tags: list[str] = []
    agents = [ua for ua in (user_agents or []) if ua]
    claims = {crawler_claim_with_hostname(ua, ip, hostname, resolver) for ua in agents}
    if CLAIM_FORGED in claims:
        tags.append("FORGED_CRAWLER")
    elif CLAIM_UNPROVEN in claims:
        tags.append("CRAWLER_CLAIM_UNVERIFIED")
    if any(is_self_identifying_scanner(ua) for ua in agents):
        tags.append("SELF_IDENTIFYING_SCANNER")
    return tags


def reset_ptr_cache() -> None:
    """Drop the per-address PTR cache (tests, and a long-running profiler between cycles)."""
    _ptr_cache.clear()


# ---------------------------------------------------------------------------
# Default known scanners (built-in, always applied)
# ---------------------------------------------------------------------------
# These are well-known legitimate internet scanning / research organisations.
# They generate massive volumes of scan traffic but are not threats.

_DEFAULT_ASNS = {
    19551,  # Shadowserver Foundation
    398722,  # Censys (formerly within UMich)
    398705,  # Censys
    20473,  # Shodan (AS-CHOOPA / Vultr — partial, check org name too)
    16276,  # OVH (PaloAlto Cortex Xpanse scans from OVH — check hostname)
    396982,  # Google Cloud (various research scanners)
    15169,  # Google LLC
    14061,  # DigitalOcean (Recyber, BinaryEdge, etc.)
    174,  # Cogent (Rapid7 Sonar)
    10439,  # CariNet (Shodan)
    8075,  # Microsoft (Defender TI scanning)
}

_DEFAULT_ORG_SUBSTRINGS = [
    "shadowserver",
    "censys",
    "shodan",
    "palo alto",
    "paloalto",
    "rapid7",
    "binaryedge",
    "qualys",
    "tenable",
    "recyber",
    "internet-measurement",
    "internet measurement",
    "stretchoid",
    "ipip.net",
    "alpha strike",
    "alphastrike",
    "intrinsec",
    "onyphe",
    "netlas",
    "criminalip",
    "zoomeye",
]

_DEFAULT_HOSTNAME_SUFFIXES = [
    ".shadowserver.org",
    ".censys.io",
    ".censys-scanner.com",  # Censys scan nodes' actual PTR domain (not .censys.io)
    ".shodan.io",
    ".criminalip.com",
    ".intrinsec.com",
    ".internet-measurement.com",
    ".binaryedge.ninja",
    ".binaryedge.io",
    ".rwth-aachen.de",
    ".recyber.net",
    ".stretchoid.com",
    ".alphastrike.io",
    ".paloaltonetworks.com",
    ".rapid7.com",
    ".qualys.com",
    ".tenable.com",
    ".onyphe.net",
    ".netlas.io",
    ".criminalip.io",
    ".zoomeye.org",
    ".internet-census.org",
    ".kudelskisecurity.com",
    ".security.ipip.net",
]

# ---------------------------------------------------------------------------
# Load config overrides
# ---------------------------------------------------------------------------


# Scanners that name themselves in the user-agent. §5.4: `l9explore/1.2.2` sent 1,204 requests
# and `WebSiphon/next-0.1` 2,210, both identifying honestly -- the cheapest possible exclusion,
# and kept separate from the forged claims above because the two are opposite behaviours.
#
# Read by `is_self_identifying_scanner` and by nothing that gates anything. The first draft put
# this inside `is_known_scanner`, which is what suppresses hunting and deep AI analysis -- so a
# sender who wrote `User-Agent: l9explore/1.2.2` would have switched off our own follow-up work
# on themselves. A header is the sender's to choose; an ASN and a PTR are not, and a real scanner
# is already excluded by those. The list earns a profile tag and nothing more.
_DEFAULT_UA_SUBSTRINGS = [
    "l9explore",
    "l9tcpid",
    "websiphon",
    "censysinspect",
    "shodan",
    "zgrab",
    "masscan",
    "internet-measurement.com",
    "paloaltonetworks.com/corporate/",
    "expanse, a palo alto networks company",
    "leakix.net",
    "netsystemsresearch.com",
    "cortex.xpanse",
    "scan.aizhan.com",
    "security.ipip.net",
    "stretchoid.com",
    "openportstats.com",
]


def _load_config() -> dict[str, Any]:
    """Load SCANNER_EXCLUSIONS from config.py, merge with defaults."""
    from honeylens.config import SCANNER_EXCLUSIONS

    cfg_asns = set(SCANNER_EXCLUSIONS.get("asns", []))
    cfg_orgs = SCANNER_EXCLUSIONS.get("org_substrings", [])
    cfg_hosts = SCANNER_EXCLUSIONS.get("hostname_suffixes", [])
    cfg_extra_asns = set(SCANNER_EXCLUSIONS.get("extra_asns", []))
    cfg_extra_orgs = SCANNER_EXCLUSIONS.get("extra_org_substrings", [])
    cfg_extra_hosts = SCANNER_EXCLUSIONS.get("extra_hostname_suffixes", [])

    # If config provides full lists, use those; otherwise merge extras with defaults
    if cfg_asns:
        asns = cfg_asns
    else:
        asns = _DEFAULT_ASNS | cfg_extra_asns

    if cfg_orgs:
        orgs = [o.lower() for o in cfg_orgs]
    else:
        orgs = _DEFAULT_ORG_SUBSTRINGS + [o.lower() for o in cfg_extra_orgs]

    if cfg_hosts:
        hosts = [h.lower() for h in cfg_hosts]
    else:
        hosts = _DEFAULT_HOSTNAME_SUFFIXES + [h.lower() for h in cfg_extra_hosts]

    cfg_uas = SCANNER_EXCLUSIONS.get("user_agent_substrings", [])
    cfg_extra_uas = SCANNER_EXCLUSIONS.get("extra_user_agent_substrings", [])
    if cfg_uas:
        uas = [u.lower() for u in cfg_uas]
    else:
        uas = _DEFAULT_UA_SUBSTRINGS + [u.lower() for u in cfg_extra_uas]

    enabled = SCANNER_EXCLUSIONS.get("enabled", True)

    return {
        "enabled": enabled,
        "rdns": SCANNER_EXCLUSIONS.get("rdns_lookup", True),
        "rdns_timeout": SCANNER_EXCLUSIONS.get("rdns_timeout_sec", 2.0),
        "asns": asns,
        "org_substrings": orgs,
        "hostname_suffixes": hosts,
        "user_agent_substrings": uas,
    }


# Cache config on first load
_config: dict[str, Any] | None = None


def _get_config() -> dict[str, Any]:
    global _config
    if _config is None:
        _config = _load_config()
    return _config


def reload_config():
    """Force reload of scanner exclusion config (e.g. after config change)."""
    global _config
    _config = None


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------


def is_known_scanner(
    ip: str | None = None,
    asn: int | None = None,
    as_org: str | None = None,
    hostname: str | None = None,
    profile: dict[str, Any] | None = None,
) -> bool:
    """
    Check if an IP / attacker profile belongs to a known scanner.

    Can be called with:
      - profile dict (from attacker_profiles DB row)
      - individual fields (asn, as_org, hostname)
      - just an IP (will do a DB lookup)

    Returns True if the source is a known scanner and should be excluded.
    """
    cfg = _get_config()
    if not cfg["enabled"]:
        return False

    # Extract fields from profile dict if provided
    if profile:
        asn = asn or profile.get("asn")
        as_org = as_org or profile.get("as_org") or ""
        hostname = hostname or profile.get("hostname") or ""
        # Also check osint_data for greynoise/rdns
        osint = profile.get("osint_data") or {}
        if isinstance(osint, str):
            try:
                import json

                osint = json.loads(osint)
            except Exception as e:
                logger.debug("Failed to parse osint_data JSON: %s", e)
                osint = {}
        if not hostname:
            hostname = osint.get("rdns", "") or ""

    # If only IP provided, try DB lookup
    if ip and not asn and not as_org and not hostname:
        try:
            _profile = _lookup_ip_profile(ip)
            if _profile:
                asn = _profile.get("asn")
                as_org = _profile.get("as_org") or ""
                hostname = _profile.get("hostname") or ""
        except Exception as e:
            logger.debug("IP profile lookup failed for %s: %s", ip, e)

    # Still no hostname (enrichment empty)? Resolve the PTR live — the scanner PTR is the most
    # reliable tell, and without this the gate silently passes every scanner (Censys, Shodan).
    if ip and not hostname and cfg.get("rdns", True):
        hostname = _reverse_dns(ip, cfg.get("rdns_timeout", 2.0))
        if hostname:
            logger.debug("scanner_exclusions: resolved %s -> %s via rDNS", ip, hostname)

    # A self-identifying user-agent is NOT checked here. See `is_self_identifying_scanner`:
    # this function gates hunting and AI analysis, and a header is the attacker's to write.

    # --- Check ASN ---
    if asn:
        try:
            asn_int = int(asn)
            if asn_int in cfg["asns"]:
                logger.debug(
                    "scanner_exclusions: %s matched ASN %d", ip or hostname or "?", asn_int
                )
                return True
        except (ValueError, TypeError):
            pass  # silent: non-numeric ASN value

    # --- Check AS org name ---
    if as_org:
        org_lower = str(as_org).lower()
        for pattern in cfg["org_substrings"]:
            if pattern in org_lower:
                logger.debug(
                    "scanner_exclusions: %s matched org '%s'", ip or hostname or "?", pattern
                )
                return True

    # --- Check hostname / reverse DNS ---
    if hostname:
        host_lower = str(hostname).lower()
        for suffix in cfg["hostname_suffixes"]:
            if host_lower.endswith(suffix):
                logger.debug(
                    "scanner_exclusions: %s matched hostname suffix '%s'",
                    ip or hostname or "?",
                    suffix,
                )
                return True

    return False


def _lookup_ip_profile(ip: str) -> dict | None:
    """Quick DB lookup to get ASN/org/hostname for an IP."""
    try:
        from honeylens.database import db_cursor

        with db_cursor(dict_cursor=True) as cur:
            cur.execute(
                "SELECT asn, as_org, hostname FROM attacker_profiles WHERE host(ip) = %s", (ip,)
            )
            row = cur.fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.debug("DB lookup failed for IP %s: %s", ip, e)
        return None


# ---------------------------------------------------------------------------
# Utility: human-readable report
# ---------------------------------------------------------------------------


def scanner_report() -> str:
    """Return a human-readable summary of active exclusions."""
    cfg = _get_config()
    lines = [
        f"Scanner Exclusions: {'ENABLED' if cfg['enabled'] else 'DISABLED'}",
        f"ASNs: {len(cfg['asns'])} entries",
        f"Org patterns: {len(cfg['org_substrings'])} entries",
        f"Hostname suffixes: {len(cfg['hostname_suffixes'])} entries",
        "",
        "ASNs: {}".format(", ".join(str(a) for a in sorted(cfg["asns"]))),
        "Orgs: {}".format(", ".join(cfg["org_substrings"])),
        "Hostnames: {}".format(", ".join(cfg["hostname_suffixes"])),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------


def main() -> int:
    """Check scanner exclusions from the shell."""

    from honeylens.logging_setup import setup_logging

    setup_logging(level="DEBUG")

    parser = argparse.ArgumentParser(description="Test scanner exclusion")
    parser.add_argument("--ip", help="Check if IP is a known scanner")
    parser.add_argument("--asn", type=int, help="Check ASN directly")
    parser.add_argument("--hostname", help="Check hostname directly")
    parser.add_argument("--report", action="store_true", help="Show active exclusion config")
    args = parser.parse_args()

    if args.report:
        print(scanner_report())
    elif args.ip:
        result = is_known_scanner(ip=args.ip)
        print("IP {}: {}".format(args.ip, "KNOWN SCANNER — excluded" if result else "not excluded"))
    elif args.asn:
        result = is_known_scanner(asn=args.asn)
        print(f"ASN {args.asn}: {'KNOWN SCANNER — excluded' if result else 'not excluded'}")
    elif args.hostname:
        result = is_known_scanner(hostname=args.hostname)
        print(
            "Host {}: {}".format(
                args.hostname, "KNOWN SCANNER — excluded" if result else "not excluded"
            )
        )
    else:
        print(scanner_report())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
