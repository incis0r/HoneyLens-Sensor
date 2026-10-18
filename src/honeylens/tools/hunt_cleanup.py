#!/usr/bin/env python3
"""
hunt_cleanup.py — Remove Known Scanners from Hunting List
==========================================================
Scans all attacker_profiles with hunt_status = 'ACTIVE', checks each IP
against scanner_exclusions.is_known_scanner(), and also applies its own
DB-level checks (ASN org, hostname, GreyNoise classification).

Scanners are marked as FINISHED with an explanatory note.
Optionally deletes their blog posts from blog.honeylens.io.

Usage:
    python hunt_cleanup.py                  # dry-run by default (safe)
    python hunt_cleanup.py --apply          # actually mark scanners as FINISHED
    python hunt_cleanup.py --apply --blog   # also delete blog posts for scanners
    python hunt_cleanup.py --verbose        # show per-IP details
    python hunt_cleanup.py --report         # just show stats, no changes

Requires: psycopg2, scanner_exclusions.py (optional but recommended)
"""

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

import psycopg2.extras

from honeylens.database import legacy_get_db

try:
    from honeylens.config import BLOG as BLOG_CFG
except ImportError:
    BLOG_CFG = {}

logger = logging.getLogger("hunt_cleanup")

# ═══════════════════════════════════════════════════════════════════════
# Colours
# ═══════════════════════════════════════════════════════════════════════
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


# ═══════════════════════════════════════════════════════════════════════
# Known scanner detection — built-in checks + scanner_exclusions module
# ═══════════════════════════════════════════════════════════════════════

# ASN org substrings that identify research/commercial scanners
_SCANNER_ORG_KEYWORDS = [
    "shadowserver",
    "censys",
    "shodan",
    "binaryedge",
    "paloalto",
    "rapid7",
    "qualys",
    "tenable",
    "security trails",
    "recyber",
    "project sonar",
    "internet census",
    "internet measurement",
    "stretchoid",
    "alpha strike",
    "intrinsec",
    "onyphe",
    "netcraft",
    "bit discovery",
    "criminalip",
    "zoomeye",
]

# Hostname suffix patterns
_SCANNER_HOSTNAME_SUFFIXES = [
    ".shadowserver.org",
    ".censys-scanner.com",
    ".shodan.io",
    ".binaryedge.io",
    ".binaryedge.ninja",
    ".rwth-aachen.de",
    ".internet-census.org",
    ".intrinsec.com",
    ".stretchoid.com",
    ".alphastrike.io",
    ".internet-measurement.com",
    ".onyphe.net",
    ".criminalip.com",
    ".natlas.io",
    ".rapid7.com",
    ".qualys.com",
]

# GreyNoise classifications that indicate scanner
_NOISE_CLASSIFICATIONS = ["benign", "unknown"]


def _check_scanner_from_profile(profile: dict[str, Any]) -> str | None:
    """
    Check if an attacker profile looks like a known scanner based on
    DB fields (as_org, hostname, osint_data). Returns reason string or None.
    """
    # --- ASN org match ---
    as_org = (profile.get("as_org") or "").lower()
    for kw in _SCANNER_ORG_KEYWORDS:
        if kw in as_org:
            return "ASN org match: '%s' contains '%s'" % (profile.get("as_org", ""), kw)

    # --- Hostname suffix match ---
    hostname = (profile.get("hostname") or "").lower()
    for suffix in _SCANNER_HOSTNAME_SUFFIXES:
        if hostname.endswith(suffix):
            return "Hostname match: '%s' ends with '%s'" % (profile.get("hostname", ""), suffix)

    # --- GreyNoise benign classification ---
    osint = profile.get("osint_data") or {}
    if isinstance(osint, str):
        try:
            osint = json.loads(osint)
        except Exception:
            osint = {}

    gn = osint.get("greynoise", {})
    if isinstance(gn, dict):
        classification = (gn.get("classification") or "").lower()
        if classification == "benign":
            gn_name = gn.get("name") or gn.get("actor") or "unnamed"
            return "GreyNoise benign: '%s'" % gn_name

    # --- is_noise flag from OSINT ---
    if profile.get("is_noise") is True:
        return "OSINT is_noise=True"

    return None


def _check_scanner_exclusions_module(ip: str) -> str | None:
    """
    Use scanner_exclusions.is_known_scanner() if available.
    Returns reason string or None.
    """
    try:
        from honeylens.intelligence.scanner_exclusions import is_known_scanner

        if is_known_scanner(ip=ip):
            return "scanner_exclusions.is_known_scanner() match"
    except ImportError as _exc:  # silent: optional scanner_exclusions module
        logging.getLogger(__name__).debug("ignored: %s", _exc)
    except Exception as exc:
        logger.debug("scanner_exclusions check failed for %s: %s", ip, exc)
    return None


# ═══════════════════════════════════════════════════════════════════════
# Database operations
# ═══════════════════════════════════════════════════════════════════════


def _get_conn():
    conn = legacy_get_db()
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    return conn


def get_active_hunting_profiles(conn) -> list[dict[str, Any]]:
    """Fetch all ACTIVE hunting profiles with scanner-relevant fields."""
    cur = conn.cursor()
    cur.execute("""
        SELECT
            host(ip)        AS ip_str,
            country,
            asn,
            as_org,
            hostname,
            is_noise,
            abuse_score,
            total_events,
            total_attacks,
            hunt_status,
            osint_data,
            internal_tags,
            cluster_tags,
            first_seen,
            last_seen
        FROM attacker_profiles
        WHERE hunt_status = 'ACTIVE'
        ORDER BY last_seen DESC NULLS LAST
    """)
    return [dict(r) for r in cur.fetchall()]


def finish_scanner(conn, ip: str, reason: str) -> bool:
    """Mark an IP as FINISHED in attacker_profiles."""
    cur = conn.cursor()
    note = "Auto-cleaned by hunt_cleanup.py: %s [%s]" % (
        reason,
        datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    )
    cur.execute(
        """
        UPDATE attacker_profiles
        SET hunt_status  = 'FINISHED',
            finished_at  = NOW(),
            finish_notes = %s
        WHERE host(ip) = %s
          AND hunt_status = 'ACTIVE'
    """,
        (note, ip),
    )
    conn.commit()
    return cur.rowcount > 0


# ═══════════════════════════════════════════════════════════════════════
# Blog post deletion (optional)
# ═══════════════════════════════════════════════════════════════════════


def delete_blog_post(ip: str) -> str | None:
    """Delete a blog post for a scanner IP. Returns status or None."""
    import requests

    blog_url = BLOG_CFG.get("blog_url", "").rstrip("/")
    api_key = BLOG_CFG.get("api_key", "")
    basic_user = BLOG_CFG.get("basic_user", "sensor")
    basic_pass = BLOG_CFG.get("basic_pass", "")
    verify_tls = BLOG_CFG.get("verify_tls", True)

    if not blog_url or not api_key:
        return None

    slug = ip.replace(".", "-").replace(":", "-")
    url = "%s/api/post/%s" % (blog_url, slug)

    try:
        resp = requests.delete(
            url,
            headers={"X-API-Key": api_key},
            auth=(basic_user, basic_pass),
            verify=verify_tls,
            timeout=15,
        )
        if resp.status_code in (200, 204):
            return "deleted"
        elif resp.status_code == 404:
            return "not_found"
        else:
            return "error:%d" % resp.status_code
    except Exception as exc:
        return "error:%s" % str(exc)[:60]


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════


def main():
    parser = argparse.ArgumentParser(
        description="Remove known research scanners from the ACTIVE hunting list."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually mark scanners as FINISHED (default is dry-run)",
    )
    parser.add_argument(
        "--blog",
        action="store_true",
        help="Also delete blog posts for identified scanners (requires --apply)",
    )
    parser.add_argument("--report", action="store_true", help="Show statistics only, no changes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show per-IP details")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    conn = _get_conn()

    print()
    print("%s%s══════════════════════════════════════════════════════════%s" % (BOLD, CYAN, RESET))
    print("%s%s  Hunt Cleanup — Scanner Removal Tool%s" % (BOLD, CYAN, RESET))
    print("%s%s══════════════════════════════════════════════════════════%s" % (BOLD, CYAN, RESET))
    print()

    profiles = get_active_hunting_profiles(conn)

    if not profiles:
        print("  %s[INFO]%s  No ACTIVE hunting profiles found." % (CYAN, RESET))
        conn.close()
        return 0

    print("  %s[INFO]%s  %d ACTIVE hunting profiles loaded" % (CYAN, RESET, len(profiles)))
    print()

    scanners: list[tuple[dict, str]] = []
    real_threats: list[dict] = []

    for p in profiles:
        ip = p["ip_str"]

        # Check 1: scanner_exclusions module (ASN/org/hostname from live lookup)
        reason = _check_scanner_exclusions_module(ip)

        # Check 2: profile-level DB fields (as_org, hostname, osint_data)
        if reason is None:
            reason = _check_scanner_from_profile(p)

        if reason:
            scanners.append((p, reason))
        else:
            real_threats.append(p)

    # ── Report ──
    print("  %s%sScanners detected:%s  %s%d%s" % (BOLD, RED, RESET, BOLD, len(scanners), RESET))
    print(
        "  %s%sReal threats:%s      %s%d%s" % (BOLD, GREEN, RESET, BOLD, len(real_threats), RESET)
    )
    print()

    if scanners:
        print("  %s%s── Scanners ──%s" % (BOLD, RED, RESET))
        for p, reason in scanners:
            ip = p["ip_str"]
            org = p.get("as_org") or "?"
            country = p.get("country") or "??"
            events = p.get("total_events") or 0
            hostname = p.get("hostname") or ""
            print(
                "  %s%-18s%s  %s  AS(%s)  events=%-6d  %s%s%s"
                % (
                    RED,
                    ip,
                    RESET,
                    country,
                    org[:30],
                    events,
                    DIM,
                    reason,
                    RESET,
                )
            )
            if args.verbose and hostname:
                print("  %s%s  hostname: %s%s" % (DIM, " " * 18, hostname, RESET))
        print()

    if args.verbose and real_threats:
        print("  %s%s── Real Threats (kept) ──%s" % (BOLD, GREEN, RESET))
        for p in real_threats[:20]:
            ip = p["ip_str"]
            org = p.get("as_org") or "?"
            country = p.get("country") or "??"
            events = p.get("total_events") or 0
            abuse = p.get("abuse_score")
            abuse_str = "abuse=%d" % abuse if abuse is not None else ""
            print(
                "  %s%-18s%s  %s  AS(%s)  events=%-6d  %s"
                % (GREEN, ip, RESET, country, org[:30], events, abuse_str)
            )
        if len(real_threats) > 20:
            print("  %s... and %d more%s" % (DIM, len(real_threats) - 20, RESET))
        print()

    if args.report:
        conn.close()
        return 0

    if not scanners:
        print("  %s[OK]%s  No scanners found — hunting list is clean." % (GREEN, RESET))
        conn.close()
        return 0

    # ── Apply or dry-run ──
    if not args.apply:
        print(
            "  %s%s[DRY RUN]%s  Would mark %d scanners as FINISHED."
            % (BOLD, YELLOW, RESET, len(scanners))
        )
        print("  %sRun with --apply to execute.%s" % (DIM, RESET))
        print()
        conn.close()
        return 0

    # Actually do it
    finished = 0
    blog_deleted = 0
    blog_errors = 0

    for p, reason in scanners:
        ip = p["ip_str"]

        ok = finish_scanner(conn, ip, reason)
        if ok:
            finished += 1
            print("  %s[FINISHED]%s  %-18s  %s" % (RED, RESET, ip, reason[:60]))
        else:
            print("  %s[SKIP]%s     %-18s  already finished or not found" % (YELLOW, RESET, ip))

        # Delete blog post if requested
        if args.blog:
            result = delete_blog_post(ip)
            if result == "deleted":
                blog_deleted += 1
                print("  %s[BLOG]%s     %-18s  post deleted" % (CYAN, RESET, ip))
            elif result == "not_found":
                pass  # no post to delete, that's fine
            elif result:
                blog_errors += 1
                print("  %s[BLOG]%s     %-18s  %s" % (YELLOW, RESET, ip, result))

    print()
    print("  %s%s── Summary ──%s" % (BOLD, CYAN, RESET))
    print("  Profiles scanned:   %d" % len(profiles))
    print("  Scanners found:     %d" % len(scanners))
    print("  Marked FINISHED:    %d" % finished)
    if args.blog:
        print("  Blog posts deleted: %d" % blog_deleted)
        if blog_errors:
            print("  Blog delete errors: %d" % blog_errors)
    print("  Real threats kept:  %d" % len(real_threats))
    print()

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
