#!/usr/bin/env python3
"""
circl_enricher.py — CIRCL Vulnerability-Lookup Integration
===========================================================
Enriches detected CVEs with intelligence from CIRCL's public API.
No authentication required.

API: https://vulnerability.circl.lu/api
Data: NVD, CVE Program, CISA KEV, CSAF advisories, VARIoT

Features:
  - CVE lookup with CVSS scoring (v3.1 > v4.0 > v3.0 > v2.0 priority)
  - CISA KEV (Known Exploited Vulnerabilities) correlation
  - CWE/CAPEC extraction
  - Vendor/product browsing
  - Local SQLite cache (configurable TTL)
  - Rate limiting (max 2 req/sec)

Usage:
    python circl_enricher.py --cve CVE-2024-3400
    python circl_enricher.py --cve CVE-2017-0144 CVE-2019-11043
    python circl_enricher.py --search librenms
    python circl_enricher.py --recent 10
    python circl_enricher.py --kev-check CVE-2024-3400
    python circl_enricher.py --vendor siemens
    python circl_enricher.py --dbinfo
    python circl_enricher.py --enrich-existing   # backfill DB
    python circl_enricher.py --test              # run self-tests
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
from honeylens.config import CIRCL_INTEGRATION, DATA_DIR

BASE_URL = CIRCL_INTEGRATION.get("base_url", "https://vulnerability.circl.lu/api")
_DEFAULT_CACHE = str(DATA_DIR / "circl_cache.db")
CACHE_DB = CIRCL_INTEGRATION.get("cache_db", _DEFAULT_CACHE)
CVE_CACHE_TTL = CIRCL_INTEGRATION.get("cve_cache_ttl_hours", 24) * 3600
KEV_CACHE_TTL = CIRCL_INTEGRATION.get("kev_cache_ttl_hours", 6) * 3600
MAX_RPS = CIRCL_INTEGRATION.get("max_requests_per_sec", 2)
REQUEST_TIMEOUT = 10

logger = logging.getLogger("circl-enricher")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class _RateLimiter:
    def __init__(self, max_rps: float):
        self._interval = 1.0 / max_rps if max_rps > 0 else 0
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            wait_time = self._interval - (now - self._last)
            if wait_time > 0:
                time.sleep(wait_time)
            self._last = time.monotonic()


_limiter = _RateLimiter(MAX_RPS)

# ---------------------------------------------------------------------------
# SQLite Cache
# ---------------------------------------------------------------------------


class _Cache:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        try:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        except OSError as exc:
            # Importing the module must not fail if /opt/honeylens is missing (tools, tests, dev).
            # The cache lands in a temp directory — with a warning, because that is not what
            # production wants.
            fallback = str(Path(tempfile.gettempdir()) / "honeylens-circl_cache.db")
            logger.warning(
                "CIRCL cache dir %s unusable (%s) — using %s", self._db_path, exc, fallback
            )
            self._db_path = fallback
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    ts    REAL NOT NULL
                )
            """)
            conn.commit()
            conn.close()

    def get(self, key: str, ttl: float) -> dict | None:
        with self._lock:
            try:
                conn = sqlite3.connect(self._db_path)
                row = conn.execute("SELECT value, ts FROM cache WHERE key = ?", (key,)).fetchone()
                conn.close()
                if row and (time.time() - row[1]) < ttl:
                    return json.loads(row[0])
            except Exception as e:
                logger.debug("Cache read error for key %s: %s", key, e)
        return None

    def put(self, key: str, value: dict):
        with self._lock:
            try:
                conn = sqlite3.connect(self._db_path)
                conn.execute(
                    "INSERT OR REPLACE INTO cache (key, value, ts) VALUES (?, ?, ?)",
                    (key, json.dumps(value), time.time()),
                )
                conn.commit()
                conn.close()
            except Exception as e:
                logger.warning("Cache write error: %s", e)


_cache = _Cache(CACHE_DB)

# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------


def _get(path: str) -> dict | None:
    """GET request to CIRCL API with rate limiting and error handling."""
    _limiter.wait()
    url = f"{BASE_URL}{path}"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("CIRCL API %s returned %d", path, resp.status_code)
    except requests.Timeout:
        logger.warning("CIRCL API timeout: %s", path)
    except requests.ConnectionError:
        logger.warning("CIRCL API connection error: %s", path)
    except Exception as e:
        logger.warning("CIRCL API error: %s — %s", path, e)
    return None


# ---------------------------------------------------------------------------
# CVSS parsing
# ---------------------------------------------------------------------------


def _extract_cvss(data: dict) -> dict:
    """Extract best CVSS score from CVE data. Priority: v3.1 > v4.0 > v3.0 > v2.0."""
    result: dict[str, Any] = {"cvss_score": None, "cvss_vector": None, "cvss_severity": None}

    # Try containers.cna.metrics first, then containers.adp[].metrics
    metrics = []
    try:
        cna = data.get("containers", {}).get("cna", {})
        metrics = cna.get("metrics", [])
    except (AttributeError, TypeError):
        pass  # silent: malformed CVE data structure

    # Check ADP containers (NVD enrichment often lives here)
    if not metrics:
        try:
            adp_list = data.get("containers", {}).get("adp", [])
            for adp in adp_list:
                if isinstance(adp, dict) and "metrics" in adp:
                    metrics = adp["metrics"]
                    break
        except (AttributeError, TypeError):
            pass  # silent: malformed ADP container structure

    # Also check root-level metrics
    if not metrics:
        metrics = data.get("metrics", [])
        if isinstance(metrics, dict):
            metrics = [metrics]

    for m in metrics:
        if not isinstance(m, dict):
            continue
        for key in ["cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0"]:
            if key in m:
                cvss = m[key]
                score = cvss.get("baseScore")
                vector = cvss.get("vectorString")
                severity = cvss.get("baseSeverity", "")
                if score is not None:
                    result["cvss_score"] = float(score)
                    result["cvss_vector"] = vector
                    result["cvss_severity"] = (
                        severity.upper() if severity else _score_to_severity(float(score))
                    )
                    return result

    # Fallback: check for score in different location
    for key in ["cvss-v3.1", "cvss-v4.0", "cvss-v3.0", "cvss-v2.0"]:
        if key in data:
            try:
                score = float(data[key].get("score", 0))
                if score > 0:
                    result["cvss_score"] = score
                    result["cvss_severity"] = _score_to_severity(score)
                    return result
            except (TypeError, ValueError):
                pass  # silent: non-numeric CVSS score in CVE data

    return result


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# CVE parsing
# ---------------------------------------------------------------------------


def _parse_cve(data: dict) -> dict | None:
    """Parse CIRCL CVE response into CVEDetail dict."""
    if not data:
        return None

    cve_id = ""
    try:
        cve_id = data.get("cveMetadata", {}).get("cveId", "")
        if not cve_id:
            cve_id = data.get("id", data.get("cve_id", ""))
    except (AttributeError, TypeError):
        pass  # silent: malformed CVE metadata

    if not cve_id:
        return None

    cna = {}
    try:
        cna = data.get("containers", {}).get("cna", {})
    except (AttributeError, TypeError):
        pass  # silent: malformed CNA container

    # Title
    title = ""
    try:
        titles = cna.get("title", "")
        if not titles:
            descs = cna.get("descriptions", [])
            for d in descs:
                if isinstance(d, dict) and d.get("lang", "").startswith("en"):
                    title = d.get("value", "")[:200]
                    break
            if not title and descs:
                title = descs[0].get("value", "")[:200] if isinstance(descs[0], dict) else ""
        else:
            title = titles
    except (AttributeError, TypeError, IndexError):
        pass  # silent: malformed CVE title/description

    # CVSS
    cvss = _extract_cvss(data)

    # CWE
    cwes = []
    try:
        problems = cna.get("problemTypes", [])
        for pt in problems:
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId", "")
                if cwe_id and cwe_id.startswith("CWE-"):
                    cwes.append(cwe_id)
    except (AttributeError, TypeError):
        pass  # silent: malformed CWE data

    # Affected products
    vendor = ""
    product = ""
    affected_versions = []
    try:
        affected = cna.get("affected", [])
        if affected:
            first = affected[0]
            vendor = first.get("vendor", "")
            product = first.get("product", "")
            for v in first.get("versions", []):
                affected_versions.append(
                    {
                        "version": v.get("version", ""),
                        "status": v.get("status", ""),
                    }
                )
    except (AttributeError, TypeError, IndexError):
        pass  # silent: malformed affected products data

    # References
    refs = []
    try:
        for r in cna.get("references", []):
            if isinstance(r, dict):
                refs.append(r.get("url", ""))
    except (AttributeError, TypeError):
        pass  # silent: malformed references data

    # Published date
    published = ""
    try:
        published = data.get("cveMetadata", {}).get("datePublished", "")[:10]
    except (AttributeError, TypeError):
        pass  # silent: malformed date metadata

    return {
        "cve_id": cve_id,
        "title": title,
        "cvss_score": cvss["cvss_score"],
        "cvss_severity": cvss["cvss_severity"],
        "cvss_vector": cvss["cvss_vector"],
        "cwe": cwes,
        "vendor": vendor,
        "product": product,
        "affected_versions": affected_versions,
        "references": refs[:10],
        "published": published,
        "is_kev": False,  # Set by KEV check separately
        "kev_date_added": None,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def enrich_cve(cve_id: str, cache_only: bool = False) -> dict | None:
    """Fetch and parse CVE details from CIRCL. Returns CVEDetail dict or None.

    cache_only=True: return whatever is in the local SQLite cache (or None on
    miss) without making any network calls. Use this on user-facing request
    paths — circl.lu can be slow (a cold KEV-list pagination has been observed
    at ~3 minutes), and a synchronous fetch on the request handler blocks the
    HTTP response. Cache warming is the responsibility of a separate periodic
    job (e.g. cron-driven `enrich_existing_db()` or the bulk-hunt pipeline).
    """
    if not cve_id or not CVE_PATTERN.match(cve_id):
        return None

    cached = _cache.get(f"cve:{cve_id}", CVE_CACHE_TTL)
    if cached:
        return cached

    if cache_only:
        return None

    data = _get(f"/cve/{cve_id}")
    if not data:
        return None
    result = _parse_cve(data)
    if result:
        # Check KEV status (live fetch path; cache_only path skipped above)
        result["is_kev"] = is_kev(cve_id)
        _cache.put(f"cve:{cve_id}", result)
    return result


def is_kev(cve_id: str, cache_only: bool = False) -> bool:
    """Check if a CVE is in the CISA Known Exploited Vulnerabilities list.

    cache_only=True: return False on cache miss (no network fetch). Same
    rationale as `enrich_cve` — this is a request-path sentinel.
    """
    kev_list = get_kev_list(cache_only=cache_only)
    return cve_id in kev_list


def get_kev_list(cache_only: bool = False) -> set:
    """Fetch CISA KEV list from CIRCL. Cached for 6 hours.

    The CIRCL /api/kev endpoint returns paginated results:
    {"metadata": {"count": N, "page": 1, "per_page": 100}, "data": [...]}
    Each entry has vulnerability.vulnId with the CVE ID.

    cache_only=True: return the cached list or an empty set on miss; never
    paginate the live CIRCL endpoint (~17 pages x 10 s each as of 2026-05-10).
    """
    cached = _cache.get("kev:list", KEV_CACHE_TTL)
    if cached:
        return set(cached.get("cves", []))

    if cache_only:
        return set()

    cve_ids = []
    page = 1
    total = None

    while True:
        data = _get(f"/kev?page={page}&per_page=100")
        if not data or not isinstance(data, dict):
            break

        meta = data.get("metadata", {})
        if total is None:
            total = meta.get("count", 0)

        entries = data.get("data", [])
        if not entries:
            break

        for entry in entries:
            if isinstance(entry, dict):
                # Try vulnerability.vulnId first (CIRCL format)
                vuln = entry.get("vulnerability", {})
                cve_id = ""
                if isinstance(vuln, dict):
                    cve_id = vuln.get("vulnId", "")
                if not cve_id:
                    cve_id = str(entry.get("cveID", entry.get("cve_id", "")) or "")
                if cve_id and cve_id.startswith("CVE-"):
                    cve_ids.append(cve_id)

        if len(cve_ids) >= (total or 0) or len(entries) < 100:
            break
        page += 1

    if cve_ids:
        _cache.put("kev:list", {"cves": cve_ids})
        logger.info("KEV list loaded: %d CVEs (from %d pages)", len(cve_ids), page)
    else:
        logger.warning("KEV list fetch failed or empty")

    return set(cve_ids)


def browse_vendor(vendor: str) -> list | None:
    """Browse products for a vendor."""
    cached = _cache.get(f"vendor:{vendor}", 3600)
    if cached:
        return cached.get("products", [])
    data = _get(f"/browse/{vendor}")
    if data and isinstance(data, (list, dict)):
        products = data if isinstance(data, list) else data.get("product", [])
        _cache.put(f"vendor:{vendor}", {"products": products})
        return products
    return None


def browse_product(vendor: str, product: str) -> list | None:
    """Browse CVEs for a vendor/product."""
    cached = _cache.get(f"product:{vendor}:{product}", 3600)
    if cached:
        return cached.get("cves", [])
    data = _get(f"/browse/{vendor}/{product}")
    if data and isinstance(data, list):
        _cache.put(f"product:{vendor}:{product}", {"cves": data})
        return data
    return None


def get_recent_cves(count: int = 30) -> list | None:
    """Get latest published CVEs."""
    data = _get(f"/last/{min(count, 100)}")
    return data if isinstance(data, list) else None


def search_cves(keyword: str) -> list | None:
    """Full-text search for CVEs."""
    data = _get(f"/search/{keyword}")
    return data if isinstance(data, list) else None


def get_db_info() -> dict | None:
    """Get CIRCL database update timestamps."""
    return _get("/dbInfo")


# ---------------------------------------------------------------------------
# ICS Vendor Advisory Monitoring (Phase D)
# ---------------------------------------------------------------------------


def check_ics_advisories() -> list:
    """Check recent CVEs for ICS vendor matches and cross-reference with sensor protocols.

    Uses /api/last/ to get recent CVEs and filters for ICS vendor keywords
    in the affected products section.

    Returns list of advisory dicts: {cve_id, vendor, product, cvss_score, protocols, title}
    """
    from honeylens.config import CIRCL_INTEGRATION, ICS_PROTOCOL_VENDORS

    vendors = set(CIRCL_INTEGRATION.get("ics_vendor_watch", []))
    if not vendors:
        return []

    # Invert protocol→vendor map to vendor→protocols
    vendor_protocols: dict[str, list[str]] = {}
    for proto, vlist in ICS_PROTOCOL_VENDORS.items():
        for v in vlist:
            vendor_protocols.setdefault(v, []).append(proto)

    # Fetch recent CVEs (last 100)
    recent = get_recent_cves(100) or []
    advisories = []

    for entry in recent:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cveMetadata", {}).get("cveId", "")
        if not cve_id:
            continue

        # Check if any affected vendor matches our ICS watch list
        cna = entry.get("containers", {}).get("cna", {})
        affected = cna.get("affected", [])
        matched_vendor = None
        matched_product = ""

        for af in affected:
            if not isinstance(af, dict):
                continue
            v = (af.get("vendor", "") or "").lower().replace(" ", "_")
            p = af.get("product", "") or ""
            for watch_v in vendors:
                if watch_v in v or v in watch_v:
                    matched_vendor = watch_v
                    matched_product = p
                    break
            if matched_vendor:
                break

        if not matched_vendor:
            continue

        detail = enrich_cve(cve_id)
        if detail:
            protocols = vendor_protocols.get(matched_vendor, [])
            advisories.append(
                {
                    "cve_id": cve_id,
                    "vendor": matched_vendor,
                    "product": matched_product,
                    "cvss_score": detail.get("cvss_score"),
                    "cvss_severity": detail.get("cvss_severity"),
                    "is_kev": detail.get("is_kev", False),
                    "title": detail.get("title", ""),
                    "protocols": protocols,
                    "published": detail.get("published", ""),
                }
            )

    # Also check KEV list for ICS vendor matches
    kev = get_kev_list()
    for cve_id in list(kev)[:200]:
        detail = enrich_cve(cve_id)
        if not detail:
            continue
        v = (detail.get("vendor", "") or "").lower().replace(" ", "_")
        for watch_v in vendors:
            if watch_v in v or v in watch_v:
                if not any(a["cve_id"] == cve_id for a in advisories):
                    protocols = vendor_protocols.get(watch_v, [])
                    advisories.append(
                        {
                            "cve_id": cve_id,
                            "vendor": watch_v,
                            "product": detail.get("product", ""),
                            "cvss_score": detail.get("cvss_score"),
                            "cvss_severity": detail.get("cvss_severity"),
                            "is_kev": True,
                            "title": detail.get("title", ""),
                            "protocols": protocols,
                            "published": detail.get("published", ""),
                        }
                    )
                break

    # Sort by CVSS descending, dedup
    seen = set()
    deduped = []
    for a in advisories:
        if a["cve_id"] not in seen:
            seen.add(a["cve_id"])
            deduped.append(a)
    deduped.sort(key=lambda a: a.get("cvss_score") or 0, reverse=True)
    logger.info("ICS advisory check: %d advisories from %d vendors", len(deduped), len(vendors))
    return deduped


def get_ics_advisories_cached(max_per_vendor: int = 10) -> list:
    """Get ICS advisories with caching (6h TTL)."""
    from honeylens.config import CIRCL_INTEGRATION

    ttl = CIRCL_INTEGRATION.get("ics_check_interval_hours", 6) * 3600

    cached = _cache.get("ics:advisories", ttl)
    if cached:
        return cached.get("advisories", [])

    advisories = check_ics_advisories()
    if advisories:
        _cache.put("ics:advisories", {"advisories": advisories[:50]})
    return advisories[:50]


# ---------------------------------------------------------------------------
# CVE Intelligence tracking (cve_intelligence table)
# ---------------------------------------------------------------------------


def track_cve(cve_id: str, conn=None):
    """Upsert CVE into cve_intelligence table. Enriches from CIRCL if new."""
    from psycopg2.extras import Json

    close_conn = False
    if conn is None:
        from honeylens.database import legacy_get_db

        conn = legacy_get_db()
        close_conn = True

    try:
        cur = conn.cursor()
        # Check if exists
        cur.execute("SELECT times_seen FROM cve_intelligence WHERE cve_id = %s", (cve_id,))
        row = cur.fetchone()
        if row:
            cur.execute(
                """
                UPDATE cve_intelligence
                SET times_seen = times_seen + 1, last_seen_on_sensor = NOW()
                WHERE cve_id = %s
            """,
                (cve_id,),
            )
        else:
            detail = enrich_cve(cve_id)
            if detail:
                cur.execute(
                    """
                    INSERT INTO cve_intelligence (
                        cve_id, title, cvss_score, cvss_severity, cvss_vector,
                        cwe, vendor, product, is_kev,
                        affected_json, references_json,
                        first_seen_on_sensor, last_seen_on_sensor, fetched_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW(),NOW())
                    ON CONFLICT (cve_id) DO UPDATE SET
                        times_seen = cve_intelligence.times_seen + 1,
                        last_seen_on_sensor = NOW()
                """,
                    (
                        cve_id,
                        detail.get("title"),
                        detail.get("cvss_score"),
                        detail.get("cvss_severity"),
                        detail.get("cvss_vector"),
                        detail.get("cwe", []),
                        detail.get("vendor"),
                        detail.get("product"),
                        detail.get("is_kev", False),
                        Json(detail.get("affected_versions", [])),
                        Json(detail.get("references", [])),
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO cve_intelligence (cve_id, first_seen_on_sensor, last_seen_on_sensor)
                    VALUES (%s, NOW(), NOW())
                    ON CONFLICT (cve_id) DO UPDATE SET
                        times_seen = cve_intelligence.times_seen + 1,
                        last_seen_on_sensor = NOW()
                """,
                    (cve_id,),
                )
        conn.commit()
    except Exception as e:
        logger.warning("track_cve error: %s", e)
        try:
            conn.rollback()
        except Exception as e:
            logger.debug("Rollback failed: %s", e)
    finally:
        if close_conn:
            conn.close()


def enrich_and_track(cve_id: str, conn=None):
    """Enrich a CVE via CIRCL and track it in cve_intelligence. Returns CVEDetail or None."""
    detail = enrich_cve(cve_id)
    if cve_id and CVE_PATTERN.match(cve_id):
        track_cve(cve_id, conn)
    return detail


# ---------------------------------------------------------------------------
# KEV escalation helper
# ---------------------------------------------------------------------------


def check_kev_escalation(cve_ids: list) -> dict:
    """Check if any CVE in the list is in CISA KEV. Returns escalation info.

    Returns: {"should_escalate": bool, "kev_cves": [...], "max_cvss": float}
    """
    if not cve_ids:
        return {"should_escalate": False, "kev_cves": [], "max_cvss": 0}

    kev = get_kev_list()
    kev_hits = [c for c in cve_ids if c in kev]
    max_cvss = 0

    for cve_id in kev_hits:
        detail = enrich_cve(cve_id)
        if detail and detail.get("cvss_score"):
            max_cvss = max(max_cvss, detail["cvss_score"])

    return {
        "should_escalate": len(kev_hits) > 0,
        "kev_cves": kev_hits,
        "max_cvss": max_cvss,
    }


# ---------------------------------------------------------------------------
# PostgreSQL integration (for backfill)
# ---------------------------------------------------------------------------


def enrich_existing_db():
    """Backfill cve_details for existing ai_analysis rows with CVE IDs."""
    from psycopg2.extras import Json

    from honeylens.database import legacy_get_db

    conn = legacy_get_db()
    cur = conn.cursor()

    # Ensure column exists
    try:
        cur.execute("ALTER TABLE ai_analysis ADD COLUMN IF NOT EXISTS cve_details JSONB")
        conn.commit()
    except Exception as e:
        logger.debug("ALTER TABLE cve_details column: %s", e)
        conn.rollback()

    # Find rows with CVE but no enrichment. The key is `event_id`: ai_analysis has no `id`
    # column, so this raised UndefinedColumn on every run and the backfill never did
    # anything. Same family as the `claude_cve`/`cve` mix-up in attacker_profiler's KEV
    # escalation — the AI tables do not share a column vocabulary, so never assume one.
    cur.execute("""
        SELECT event_id, claude_cve FROM ai_analysis
        WHERE claude_cve IS NOT NULL AND claude_cve != '' AND claude_cve != 'None'
          AND (cve_details IS NULL)
        ORDER BY event_id DESC
    """)
    rows = cur.fetchall()
    logger.info("Found %d rows to enrich", len(rows))

    enriched = 0
    for row_id, cve_id in rows:
        detail = enrich_cve(cve_id)
        if detail:
            cur.execute(
                "UPDATE ai_analysis SET cve_details = %s WHERE event_id = %s",
                (Json(detail), row_id),
            )
            enriched += 1
            if enriched % 10 == 0:
                conn.commit()
                logger.info("Enriched %d/%d", enriched, len(rows))

    conn.commit()
    cur.close()
    conn.close()
    logger.info("Enrichment complete: %d/%d rows updated", enriched, len(rows))


# ---------------------------------------------------------------------------
# Self-test (using real sensor CVEs)
# ---------------------------------------------------------------------------


def run_tests():
    """Run Phase A acceptance tests using real CVEs from sensor data."""
    test_cves = [
        ("CVE-2017-0144", "EternalBlue"),
        ("CVE-2019-11043", "PHP-FPM"),
        ("CVE-2024-43799", "Next.js"),
        ("CVE-2021-31805", "Struts2"),
        ("CVE-2022-22947", "Spring Cloud"),
        ("CVE-2020-3452", "Cisco ASA"),
        ("CVE-2021-22502", "Micro Focus"),
        ("CVE-2024-20353", "Cisco ASA"),
        ("CVE-2018-18264", "K8s Dashboard"),
        ("CVE-2021-46422", "Telesquare"),
        ("CVE-2018-0296", "Cisco ASA"),
    ]

    passed = 0
    failed = 0
    total = 0

    def check(name, condition, detail=""):
        nonlocal passed, failed, total
        total += 1
        if condition:
            passed += 1
            print(f"  PASS  {name}")
        else:
            failed += 1
            print(f"  FAIL  {name}  {detail}")

    print("=" * 60)
    print("CIRCL Enricher — Phase A Acceptance Tests")
    print("=" * 60)

    # A.1 — API Client Tests
    print("\n--- A.1: API Client ---")
    for cve_id, _label in test_cves[:5]:
        detail = enrich_cve(cve_id)
        check(
            f"A.1 enrich_cve({cve_id})",
            detail is not None and detail.get("cve_id") == cve_id,
            f"got: {detail}",
        )

    # Invalid CVE
    check("A.1 invalid CVE returns None", enrich_cve("CVE-9999-99999") is None)
    check("A.1 malformed ID returns None", enrich_cve("not-a-cve") is None)
    check("A.1 empty string returns None", enrich_cve("") is None)

    # A.2 — CVE Parsing Tests
    print("\n--- A.2: CVE Parsing ---")
    d = enrich_cve("CVE-2017-0144")
    if d:
        check("A.2 cve_id present", d.get("cve_id") == "CVE-2017-0144")
        check(
            "A.2 cvss_score is float",
            isinstance(d.get("cvss_score"), (int, float)),
            f"got: {d.get('cvss_score')}",
        )
        check(
            "A.2 cvss_severity present",
            d.get("cvss_severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW", None),
        )
        check("A.2 title not empty", bool(d.get("title")), f"title: {d.get('title', '')[:50]}")
        check("A.2 cwe is list", isinstance(d.get("cwe"), list))
        check("A.2 references is list", isinstance(d.get("references"), list))
        check("A.2 published present", bool(d.get("published")))
    else:
        for _ in range(7):
            check("A.2 SKIP — CVE-2017-0144 fetch failed", False)

    # Parse more CVEs for field coverage
    for cve_id, label in test_cves[1:4]:
        d2 = enrich_cve(cve_id)
        check(f"A.2 parse {cve_id} ({label})", d2 is not None and d2.get("cve_id") == cve_id)

    # A.3 — Cache Tests
    print("\n--- A.3: Cache ---")
    t0 = time.time()
    enrich_cve("CVE-2017-0144")  # should be cached from A.1
    t1 = time.time()
    check("A.3 cache hit (< 0.1s)", (t1 - t0) < 0.1, f"took {t1 - t0:.3f}s")

    # Verify cache DB exists
    check("A.3 cache DB exists", os.path.exists(CACHE_DB))

    # B.1 — KEV Tests
    print("\n--- B.1: CISA KEV ---")
    kev = get_kev_list()
    check("B.1 KEV list not empty", len(kev) > 0, f"got {len(kev)} entries")
    check("B.1 KEV list has 100+ entries", len(kev) > 100, f"got {len(kev)}")

    # Check known KEV CVEs
    check("B.1 CVE-2017-0144 in KEV (EternalBlue)", "CVE-2017-0144" in kev)
    check("B.1 CVE-2024-43799 NOT in KEV", "CVE-2024-43799" not in kev)

    # KEV enrichment in CVE detail
    d3 = enrich_cve("CVE-2017-0144")
    if d3:
        check("B.1 is_kev flag in CVEDetail", d3.get("is_kev") is True)

    # B.2 — Escalation Tests
    print("\n--- B.2: KEV Escalation ---")
    esc = check_kev_escalation(["CVE-2017-0144", "CVE-2024-43799"])
    check("B.2 escalation with KEV CVE", esc["should_escalate"] is True)
    check("B.2 kev_cves contains CVE-2017-0144", "CVE-2017-0144" in esc["kev_cves"])
    check("B.2 max_cvss > 0", esc["max_cvss"] > 0, f"got: {esc['max_cvss']}")

    esc2 = check_kev_escalation(["CVE-2024-43799"])
    check("B.2 no escalation without KEV", esc2["should_escalate"] is False)
    check("B.2 empty kev_cves", len(esc2["kev_cves"]) == 0)

    esc3 = check_kev_escalation([])
    check("B.2 empty input returns no escalation", esc3["should_escalate"] is False)

    # API info
    print("\n--- Misc ---")
    dbinfo = get_db_info()
    check("dbInfo endpoint responds", dbinfo is not None)

    recent = get_recent_cves(5)
    check("recent CVEs returns list", isinstance(recent, list) and len(recent) > 0)

    # Summary
    print("\n" + "=" * 60)
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print("=" * 60)
    return failed == 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    from honeylens.logging_setup import setup_logging

    setup_logging()
    parser = argparse.ArgumentParser(description="CIRCL Vulnerability-Lookup Enricher")
    parser.add_argument("--cve", nargs="+", help="Lookup CVE IDs")
    parser.add_argument("--search", help="Full-text search")
    parser.add_argument("--recent", type=int, help="Get N latest CVEs")
    parser.add_argument("--vendor", help="Browse vendor products")
    parser.add_argument(
        "--product", nargs=2, metavar=("VENDOR", "PRODUCT"), help="Browse product CVEs"
    )
    parser.add_argument("--kev-check", nargs="+", help="Check if CVEs are in CISA KEV")
    parser.add_argument("--dbinfo", action="store_true", help="CIRCL database info")
    parser.add_argument(
        "--enrich-existing", action="store_true", help="Backfill CVE details in PostgreSQL"
    )
    parser.add_argument("--test", action="store_true", help="Run self-tests")
    args = parser.parse_args()

    if args.test:
        ok = run_tests()
        sys.exit(0 if ok else 1)

    if args.cve:
        for cve_id in args.cve:
            result = enrich_cve(cve_id)
            if result:
                print(json.dumps(result, indent=2))
            else:
                print(f"{cve_id}: not found or API error")

    elif args.search:
        results = search_cves(args.search)
        if results:
            print(json.dumps(results[:20], indent=2))
        else:
            print("No results")

    elif args.recent:
        results = get_recent_cves(args.recent)
        if results:
            for r in results:
                cve_id = r.get("cveMetadata", {}).get("cveId", r.get("id", "?"))
                print(cve_id)
        else:
            print("No results")

    elif args.vendor:
        products = browse_vendor(args.vendor)
        if products:
            print(json.dumps(products[:30], indent=2))
        else:
            print("No products found")

    elif args.product:
        cves = browse_product(args.product[0], args.product[1])
        if cves:
            print(json.dumps(cves[:20], indent=2))
        else:
            print("No CVEs found")

    elif args.kev_check:
        kev = get_kev_list()
        for cve_id in args.kev_check:
            status = "IN KEV" if cve_id in kev else "not in KEV"
            print(f"{cve_id}: {status}")

    elif args.dbinfo:
        info = get_db_info()
        if info:
            print(json.dumps(info, indent=2))
        else:
            print("API unavailable")

    elif args.enrich_existing:
        enrich_existing_db()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
