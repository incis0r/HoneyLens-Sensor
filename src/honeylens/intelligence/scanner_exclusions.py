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

    enabled = SCANNER_EXCLUSIONS.get("enabled", True)

    return {
        "enabled": enabled,
        "rdns": SCANNER_EXCLUSIONS.get("rdns_lookup", True),
        "rdns_timeout": SCANNER_EXCLUSIONS.get("rdns_timeout_sec", 2.0),
        "asns": asns,
        "org_substrings": orgs,
        "hostname_suffixes": hosts,
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
