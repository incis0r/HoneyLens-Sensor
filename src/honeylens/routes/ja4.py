"""
routes/ja4.py — JA3/JA4+ TLS Fingerprinting Routes
=====================================================
Extracted from api.py (Phase 1 refactor).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from honeylens.database import db_cursor
from honeylens.routes._helpers import db, html_response, wants_html

logger = logging.getLogger("api")

router = APIRouter(tags=["JA3/JA4+ Fingerprinting"])


# JA4 database helpers — in 0.9 they lived in api.py and the route did `import api` (that
# name does not exist in the 1.0 package: four JA4 endpoints would have ended with 500). The
# ja4_database table is optional (import_ja4_db.py), hence the cached existence check.
_JA4_DB_TABLE_EXISTS = None  # Cached check


def _check_ja4_db_table() -> bool:
    """Check if ja4_database table exists."""
    global _JA4_DB_TABLE_EXISTS
    if _JA4_DB_TABLE_EXISTS is not None:
        return _JA4_DB_TABLE_EXISTS

    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'ja4_database'
            )
        """)
        _JA4_DB_TABLE_EXISTS = cur.fetchone()[0]

        if _JA4_DB_TABLE_EXISTS:
            cur.execute("SELECT COUNT(*) FROM ja4_database")
            count = cur.fetchone()[0]
            if count > 0:
                logging.getLogger("api").info("JA4+ database table found: %d fingerprints", count)
            else:
                _JA4_DB_TABLE_EXISTS = False
                logging.getLogger("api").info("JA4+ database table empty - run import_ja4_db.py")

        conn.close()
    except Exception as e:
        logger.debug("JA4+ DB table check failed: %s", e)
        _JA4_DB_TABLE_EXISTS = False

    return _JA4_DB_TABLE_EXISTS


def lookup_ja4_fingerprint(fingerprint: str) -> dict:
    """Look up application info for a JA4+ fingerprint from database."""
    if not fingerprint or not _check_ja4_db_table():
        return {}

    try:
        conn = db()
        cur = conn.cursor()

        # Direct lookup
        cur.execute(
            """
            SELECT application, library, device, os, user_agent,
                   certificate_authority, verified, notes, fingerprint_type
            FROM ja4_database
            WHERE fingerprint = %s
            LIMIT 1
        """,
            (fingerprint,),
        )

        row = cur.fetchone()

        # Try partial match if not found
        if not row and "_" in fingerprint:
            fp_a = fingerprint.split("_")[0]
            cur.execute(
                """
                SELECT application, library, device, os, user_agent,
                       certificate_authority, verified, notes, fingerprint_type
                FROM ja4_database
                WHERE fingerprint = %s OR fingerprint LIKE %s
                LIMIT 1
            """,
                (fp_a, f"{fp_a}%"),
            )
            row = cur.fetchone()

        conn.close()

        if row:
            return {
                "application": row[0],
                "library": row[1],
                "device": row[2],
                "os": row[3],
                "user_agent": row[4],
                "certificate_authority": row[5],
                "verified": row[6],
                "notes": row[7],
                "fp_type": row[8],
            }
    except Exception as e:
        logger.debug("JA4+ fingerprint lookup failed: %s", e)

    return {}


def get_ja4_db_stats() -> dict:
    """Get JA4+ database statistics."""
    if not _check_ja4_db_table():
        return {"loaded": False}

    try:
        conn = db()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM ja4_database")
        total = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM ja4_database WHERE verified = TRUE")
        verified = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(DISTINCT application)
            FROM ja4_database
            WHERE application IS NOT NULL
        """)
        unique_apps = cur.fetchone()[0]

        cur.execute("""
            SELECT fingerprint_type, COUNT(*)
            FROM ja4_database
            GROUP BY fingerprint_type
            ORDER BY COUNT(*) DESC
        """)
        by_type = {row[0]: row[1] for row in cur.fetchall()}

        conn.close()

        return {
            "loaded": True,
            "total_fingerprints": total,
            "verified_count": verified,
            "unique_applications": unique_apps,
            "fingerprint_types": by_type,
        }
    except Exception as e:
        logger.debug("JA4+ DB stats query failed: %s", e)
        return {"loaded": False}


# WebUI imports (lazy)
def _ja3_stats_html(data):
    from honeylens.webui.dashboard_ja4 import ja3_stats_html

    return ja3_stats_html(data)


def _ja4_stats_html(data):
    from honeylens.webui.dashboard_ja4 import ja4_stats_html

    return ja4_stats_html(data)


def _ja4_detected_html(data):
    from honeylens.webui.dashboard_ja4 import ja4_detected_html

    return ja4_detected_html(data)


def _ja4_lookup_html(data):
    from honeylens.webui.dashboard_ja4 import ja4_lookup_html

    return ja4_lookup_html(data)


def _ja4_events_html(data):
    from honeylens.webui.dashboard_ja4 import ja4_events_html

    return ja4_events_html(data)


def _ja4_app_detail_html(data):
    from honeylens.webui.dashboard_ja4 import ja4_app_detail_html

    return ja4_app_detail_html(data)


def _ja4s_stats_html(data):
    from honeylens.webui.dashboard_ja4 import ja4s_stats_html

    return ja4s_stats_html(data)


def _ja4h_stats_html(data):
    from honeylens.webui.dashboard_ja4 import ja4h_stats_html

    return ja4h_stats_html(data)

    # (second, poorer copy of the ja4_database table check removed — the one above, from api.py 0.9)
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ja4_database')"
        )
        _JA4_DB_TABLE_EXISTS = cur.fetchone()[0]
        conn.close()
    except Exception:
        _JA4_DB_TABLE_EXISTS = False  # silent: table existence check
    return _JA4_DB_TABLE_EXISTS


# Routes — JA3
# ---------------------------------------------------------------------------


@router.get("/ja3_stats")
def ja3_stats(request: Request):
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT ja3, COUNT(*)
        FROM sensor_events
        WHERE ja3 IS NOT NULL
        GROUP BY ja3
        ORDER BY COUNT(*) DESC
        LIMIT 15
    """)
    rows = cur.fetchall()
    conn.close()

    # Return array for JSON (dashboard), dict for HTML view
    if wants_html(request):
        result: list[dict[str, Any]] = [{"ja3_hash": r[0], "count": r[1]} for r in rows]
        return HTMLResponse(content=_ja3_stats_html(result))
    return rows  # Original array format [[ja3, count], ...]


# 1.0: the ja4_fingerprints table comes from migrations that honeylens-migrate runs before the API.
_HAS_JA4_TABLE = True


@router.get("/ja4_stats")
def ja4_stats(request: Request):
    """JA4+ fingerprint statistics with decoded metadata."""

    def decode_ja4(fingerprint: str) -> dict:
        """Decode JA4 fingerprint 'a' section to extract readable metadata."""
        if not fingerprint or "_" not in fingerprint:
            return {}

        parts = fingerprint.split("_")
        if not parts:
            return {}

        fp_a = parts[0]
        if len(fp_a) < 10:
            return {}

        result: dict[str, Any] = {}

        try:
            # Protocol (position 0): 't' = TCP, 'q' = QUIC
            proto_char = fp_a[0] if len(fp_a) > 0 else ""
            if proto_char == "t":
                result["transport"] = "TCP"
            elif proto_char == "q":
                result["transport"] = "QUIC"
            else:
                result["transport"] = proto_char.upper()

            # TLS version (positions 1-2)
            if len(fp_a) >= 3:
                tls_ver = fp_a[1:3]
                tls_versions = {
                    "10": "TLS 1.0",
                    "11": "TLS 1.1",
                    "12": "TLS 1.2",
                    "13": "TLS 1.3",
                    "00": "Unknown",
                    "s1": "SSL 1.0",
                    "s2": "SSL 2.0",
                    "s3": "SSL 3.0",
                }
                result["tls_version"] = tls_versions.get(tls_ver, f"v{tls_ver}")

            # SNI indicator (position 3)
            if len(fp_a) >= 4:
                sni_char = fp_a[3]
                result["has_sni"] = sni_char != "d"

            # Cipher count (positions 4-5, 2 hex digits)
            if len(fp_a) >= 6:
                try:
                    result["ciphers"] = int(fp_a[4:6], 16)
                except ValueError:
                    pass  # silent: invalid hex in fingerprint

            # Extension count (positions 6-7, 2 hex digits)
            if len(fp_a) >= 8:
                try:
                    result["extensions"] = int(fp_a[6:8], 16)
                except ValueError:
                    pass  # silent: invalid hex in fingerprint

            # ALPN (positions 8-9)
            if len(fp_a) >= 10:
                alpn = fp_a[8:10]
                alpn_map = {"00": "None", "h2": "HTTP/2", "h3": "HTTP/3"}
                result["alpn"] = alpn_map.get(alpn, alpn)

            # Build summary string
            parts = [result.get("tls_version", "")]
            if result.get("ciphers"):
                parts.append(f"{result['ciphers']}c")
            if result.get("extensions"):
                parts.append(f"{result['extensions']}e")
            if result.get("alpn") and result["alpn"] != "None":
                parts.append(result["alpn"])
            result["summary"] = "/".join(p for p in parts if p)

        except Exception as e:
            logger.debug("JA4 fingerprint decode failed: %s", e)

        return result

    if not _HAS_JA4_TABLE:
        if wants_html(request):
            return html_response(
                "JA4+ Stats",
                {"error": "ja4_fingerprints table not found. Run setup_db.py to enable JA4+."},
                request,
                "record",
            )
        return {"error": "ja4_fingerprints table not found"}

    conn = db()
    cur = conn.cursor()

    # Get JA4 fingerprint frequency
    cur.execute("""
        SELECT fingerprint, fingerprint_type, identified, COUNT(*) as cnt
        FROM ja4_fingerprints
        GROUP BY fingerprint, fingerprint_type, identified
        ORDER BY cnt DESC
        LIMIT 50
    """)
    rows = cur.fetchall()

    # Get summary stats
    cur.execute("""
        SELECT
            fingerprint_type,
            COUNT(*) as total,
            COUNT(DISTINCT fingerprint) as unique_fps,
            COUNT(DISTINCT sni) as unique_snis,
            COUNT(CASE WHEN identified IS NOT NULL THEN 1 END) as identified_count
        FROM ja4_fingerprints
        GROUP BY fingerprint_type
        ORDER BY total DESC
    """)
    summary = cur.fetchall()

    # Get top identified fingerprints (malware/tools)
    cur.execute("""
        SELECT fingerprint, identified, COUNT(*) as cnt
        FROM ja4_fingerprints
        WHERE identified IS NOT NULL
        GROUP BY fingerprint, identified
        ORDER BY cnt DESC
        LIMIT 20
    """)
    identified = cur.fetchall()

    # Get top SNIs
    cur.execute("""
        SELECT sni, COUNT(*) as cnt
        FROM ja4_fingerprints
        WHERE sni IS NOT NULL AND sni != ''
        GROUP BY sni
        ORDER BY cnt DESC
        LIMIT 20
    """)
    top_snis = cur.fetchall()

    conn.close()

    # Enhance with JA4+ database lookups
    def enrich_fingerprint(fp_data: dict) -> dict:
        """Enrich fingerprint data with JA4+ database lookup."""
        fp = fp_data.get("fingerprint", "")
        db_info = lookup_ja4_fingerprint(fp)

        if db_info:
            # Add application info from database
            fp_data["db_application"] = db_info.get("application")
            fp_data["db_library"] = db_info.get("library")
            fp_data["db_device"] = db_info.get("device")
            fp_data["db_os"] = db_info.get("os")
            fp_data["db_notes"] = db_info.get("notes")
            fp_data["db_verified"] = db_info.get("verified", False)

            # Use database identification if not already identified
            if not fp_data.get("identified") and db_info.get("application"):
                fp_data["identified"] = db_info["application"]

        return fp_data

    ja4_db_stats = get_ja4_db_stats()

    result = {
        "ja4_db_loaded": ja4_db_stats.get("loaded", False),
        "ja4_db_count": ja4_db_stats.get("total_fingerprints", 0),
        "fingerprints": [
            enrich_fingerprint(
                {
                    "fingerprint": r[0],
                    "type": r[1],
                    "identified": r[2],
                    "count": r[3],
                    "decoded": decode_ja4(r[0]),
                }
            )
            for r in rows
        ],
        "summary": [
            {
                "type": r[0],
                "total": r[1],
                "unique_fingerprints": r[2],
                "unique_snis": r[3],
                "identified_count": r[4],
            }
            for r in summary
        ],
        "identified_threats": [
            enrich_fingerprint(
                {
                    "fingerprint": r[0],
                    "identified": r[1],
                    "count": r[2],
                    "decoded": decode_ja4(r[0]),
                }
            )
            for r in identified
        ],
        "top_snis": [{"sni": r[0], "count": r[1]} for r in top_snis],
    }

    if wants_html(request):
        return HTMLResponse(content=_ja4_stats_html(result))
    return result


@router.get("/ja4/lookup/{fingerprint}")
def ja4_lookup(fingerprint: str, request: Request):
    """Look up a JA4+ fingerprint in the database."""
    if not _check_ja4_db_table():
        result = {"fingerprint": fingerprint, "found": False, "message": "JA4+ database not loaded"}
        if wants_html(request):
            return HTMLResponse(content=_ja4_lookup_html(result))
        return result

    db_info = lookup_ja4_fingerprint(fingerprint)

    if not db_info:
        result = {
            "fingerprint": fingerprint,
            "found": False,
            "message": "Fingerprint not found in JA4+ database",
        }
        if wants_html(request):
            return HTMLResponse(content=_ja4_lookup_html(result))
        return result

    result = {"fingerprint": fingerprint, "found": True, **db_info}

    if wants_html(request):
        return HTMLResponse(content=_ja4_lookup_html(result))
    return result


@router.get("/ja4/database")
def ja4_database_stats(request: Request):
    """Get JA4+ database statistics."""
    stats = get_ja4_db_stats()

    if not stats.get("loaded"):
        return {
            "loaded": False,
            "error": "JA4+ database not loaded",
            "hint": "Run: python import_ja4_db.py ja4+_db.json",
        }

    # Get top applications
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
            SELECT application, COUNT(*)
            FROM ja4_database
            WHERE application IS NOT NULL
            GROUP BY application
            ORDER BY COUNT(*) DESC
            LIMIT 30
        """)
        top_apps = [(row[0], row[1]) for row in cur.fetchall()]
        conn.close()
        stats["top_applications"] = top_apps
    except Exception as e:
        logger.debug("JA4 database top_applications query failed: %s", e)
        stats["top_applications"] = []

    if wants_html(request):
        return html_response("JA4+ Database Stats", stats, request, "stats")
    return stats


@router.get("/ja4/detected")
def ja4_detected_applications(request: Request, limit: int = 100):
    """
    Show applications detected in traffic by matching captured fingerprints
    against the JA4+ database.
    """
    if not _check_ja4_db_table():
        return {"error": "JA4+ database not loaded. Run: python import_ja4_db.py"}

    if not _HAS_JA4_TABLE:
        return {"error": "ja4_fingerprints table not found"}

    try:
        conn = db()
        cur = conn.cursor()

        # Get detected applications with event counts
        # Match on: exact fingerprint, fingerprint_a prefix, or case-insensitive type
        cur.execute(
            """
            WITH matched AS (
                SELECT f.event_id, f.fingerprint AS f_fp, d.application, d.library,
                       d.device, d.os, d.verified, d.fingerprint_type, d.fingerprint AS d_fp
                FROM ja4_fingerprints f
                JOIN ja4_database d ON f.fingerprint = d.fingerprint
                WHERE d.application IS NOT NULL
                UNION
                SELECT f.event_id, f.fingerprint, d.application, d.library,
                       d.device, d.os, d.verified, d.fingerprint_type, d.fingerprint
                FROM ja4_fingerprints f
                JOIN ja4_database d ON f.fingerprint_a = d.fingerprint
                WHERE d.application IS NOT NULL
                UNION
                SELECT f.event_id, f.fingerprint, d.application, d.library,
                       d.device, d.os, d.verified, d.fingerprint_type, d.fingerprint
                FROM ja4_fingerprints f
                JOIN ja4_database d ON f.fingerprint_a = SPLIT_PART(d.fingerprint, '_', 1)
                WHERE d.application IS NOT NULL
                  AND d.fingerprint LIKE '%%_%%'
            )
            SELECT m.application, m.library, m.device, m.os, m.verified,
                   m.fingerprint_type,
                   COUNT(DISTINCT m.event_id) as event_count,
                   COUNT(DISTINCT e.src_ip) as unique_ips,
                   MIN(e.timestamp) as first_seen,
                   MAX(e.timestamp) as last_seen,
                   m.d_fp as fingerprint
            FROM matched m
            JOIN sensor_events e ON m.event_id = e.event_id
            GROUP BY m.application, m.library, m.device, m.os, m.verified,
                     m.fingerprint_type, m.d_fp
            ORDER BY event_count DESC
            LIMIT %s
        """,
            (limit,),
        )

        detected = [
            {
                "application": row[0],
                "library": row[1],
                "device": row[2],
                "os": row[3],
                "verified": row[4],
                "fingerprint_type": row[5],
                "event_count": row[6],
                "unique_ips": row[7],
                "first_seen": row[8].isoformat() if row[8] else None,
                "last_seen": row[9].isoformat() if row[9] else None,
                "fingerprint": row[10],
            }
            for row in cur.fetchall()
        ]

        # Get summary by application (aggregated)
        cur.execute("""
            WITH matched AS (
                SELECT f.event_id, d.application, d.fingerprint, d.verified
                FROM ja4_fingerprints f
                JOIN ja4_database d ON f.fingerprint = d.fingerprint
                WHERE d.application IS NOT NULL
                UNION
                SELECT f.event_id, d.application, d.fingerprint, d.verified
                FROM ja4_fingerprints f
                JOIN ja4_database d ON f.fingerprint_a = d.fingerprint
                WHERE d.application IS NOT NULL
                UNION
                SELECT f.event_id, d.application, d.fingerprint, d.verified
                FROM ja4_fingerprints f
                JOIN ja4_database d ON f.fingerprint_a = SPLIT_PART(d.fingerprint, '_', 1)
                WHERE d.application IS NOT NULL
                  AND d.fingerprint LIKE '%%_%%'
            )
            SELECT
                m.application,
                COUNT(DISTINCT m.event_id) as total_events,
                COUNT(DISTINCT e.src_ip) as unique_ips,
                COUNT(DISTINCT m.fingerprint) as fingerprint_variants,
                bool_or(m.verified) as any_verified
            FROM matched m
            JOIN sensor_events e ON m.event_id = e.event_id
            GROUP BY m.application
            ORDER BY total_events DESC
            LIMIT 50
        """)

        summary = [
            {
                "application": row[0],
                "total_events": row[1],
                "unique_ips": row[2],
                "fingerprint_variants": row[3],
                "verified": row[4],
            }
            for row in cur.fetchall()
        ]

        # Highlight threats (known malware/tools)
        threat_keywords = [
            "cobalt",
            "strike",
            "metasploit",
            "empire",
            "sliver",
            "havoc",
            "brute",
            "scan",
            "nmap",
            "masscan",
            "zmap",
        ]
        threats = [
            d
            for d in detected
            if any(
                kw in (d["application"] or "").lower()
                or kw in (d["notes"] if "notes" in d else "").lower()
                for kw in threat_keywords
            )
        ]

        conn.close()

        result = {
            "total_detected": len(detected),
            "summary_by_app": summary,
            "threats_detected": threats,
            "all_detected": detected,
        }

        if wants_html(request):
            return HTMLResponse(content=_ja4_detected_html(result))
        return result

    except Exception as e:
        logger.error("Error in ja4/detected: %s", e)
        return {"error": "An internal error occurred"}


@router.get("/ja4/detected/{application}")
def ja4_detected_app_events(application: str, request: Request, limit: int = 200):
    """Get all events for a specific detected application."""
    if not _check_ja4_db_table() or not _HAS_JA4_TABLE:
        return {"error": "Required tables not available"}

    try:
        conn = db()
        cur = conn.cursor()

        # Get events matching this application
        cur.execute(
            """
            SELECT
                e.event_id,
                e.timestamp,
                e.src_ip::text,
                e.dst_ip::text,
                e.dst_port,
                e.protocol,
                f.fingerprint,
                f.fingerprint_type,
                f.sni,
                d.application,
                d.library,
                d.os,
                d.verified
            FROM ja4_fingerprints f
            JOIN ja4_database d ON (
                f.fingerprint = d.fingerprint
                OR f.fingerprint_a = d.fingerprint
                OR f.fingerprint LIKE d.fingerprint || '%%'
            )
            JOIN sensor_events e ON f.event_id = e.event_id
            WHERE LOWER(d.application) = LOWER(%s)
            ORDER BY e.timestamp DESC
            LIMIT %s
        """,
            (application, limit),
        )

        events = [
            {
                "event_id": row[0],
                "timestamp": row[1].isoformat() if row[1] else None,
                "src_ip": row[2],
                "dst_ip": row[3],
                "dst_port": row[4],
                "protocol": row[5],
                "fingerprint": row[6],
                "fingerprint_type": row[7],
                "sni": row[8],
                "application": row[9],
                "library": row[10],
                "os": row[11],
                "verified": row[12],
            }
            for row in cur.fetchall()
        ]

        # Get unique source IPs
        cur.execute(
            """
            SELECT DISTINCT e.src_ip::text
            FROM ja4_fingerprints f
            JOIN ja4_database d ON (
                f.fingerprint = d.fingerprint
                OR f.fingerprint_a = d.fingerprint
            )
            JOIN sensor_events e ON f.event_id = e.event_id
            WHERE LOWER(d.application) = LOWER(%s)
            LIMIT 100
        """,
            (application,),
        )
        unique_ips = [row[0] for row in cur.fetchall()]

        conn.close()

        result = {
            "application": application,
            "event_count": len(events),
            "unique_ips": unique_ips,
            "unique_ip_count": len(unique_ips),
            "events": events,
        }

        if wants_html(request):
            return HTMLResponse(content=_ja4_app_detail_html(result))
        return result

    except Exception as e:
        logger.error("Error in ja4/detected/%s: %s", application, e)
        return {"error": "An internal error occurred"}


@router.get("/ja4/search")
def ja4_search(request: Request, app: str | None = None, q: str | None = None):
    """Search JA4+ database by application name."""
    if not _check_ja4_db_table():
        return {"error": "JA4+ database not loaded. Run: python import_ja4_db.py"}

    query = (app or q or "").strip()
    if not query or len(query) < 2:
        return {"error": "Search query too short (min 2 chars)", "results": []}

    try:
        conn = db()
        cur = conn.cursor()

        search_pattern = f"%{query.lower()}%"
        cur.execute(
            """
            SELECT fingerprint, fingerprint_type, application, library,
                   device, os, verified, notes
            FROM ja4_database
            WHERE LOWER(application) LIKE %s
               OR LOWER(library) LIKE %s
               OR LOWER(device) LIKE %s
               OR LOWER(notes) LIKE %s
            ORDER BY application, fingerprint_type
            LIMIT 100
        """,
            (search_pattern, search_pattern, search_pattern, search_pattern),
        )

        results = [
            {
                "fingerprint": row[0],
                "fingerprint_type": row[1],
                "application": row[2],
                "library": row[3],
                "device": row[4],
                "os": row[5],
                "verified": row[6],
                "notes": row[7],
            }
            for row in cur.fetchall()
        ]

        conn.close()

        response = {"query": query, "count": len(results), "results": results}

        if wants_html(request):
            return html_response(f"JA4 Search: {query}", response, request, "stats")
        return response

    except Exception:
        return {"error": "An internal error occurred", "results": []}


@router.post("/ja4/compare")
async def ja4_compare(request: Request):
    """Compare a JA4 fingerprint hash against the database and captured events.
    Body: {"fingerprint": "t13d..."}
    Returns: matching DB entries + events using this fingerprint."""
    body = await request.json()
    fp = (body.get("fingerprint") or "").strip()
    if not fp or len(fp) < 4:
        return {"error": "Fingerprint too short", "db_matches": [], "events": []}
    try:
        db_matches = []
        events = []
        with db_cursor() as cur:
            # Check JA4 database
            try:
                cur.execute(
                    """
                    SELECT fingerprint, fingerprint_type, application, library, device, os, verified, notes
                    FROM ja4_database WHERE fingerprint = %s OR fingerprint LIKE %s
                """,
                    (fp, fp + "%"),
                )
                db_matches = [
                    {
                        "fingerprint": r[0],
                        "type": r[1],
                        "application": r[2],
                        "library": r[3],
                        "device": r[4],
                        "os": r[5],
                        "verified": r[6],
                        "notes": r[7],
                    }
                    for r in cur.fetchall()
                ]
            except Exception as e:
                logger.debug("JA4 database lookup failed: %s", e)
            # Check captured events
            try:
                cur.execute(
                    """
                    SELECT jf.fingerprint, jf.fingerprint_type, jf.identified, jf.sni,
                           jf.tls_version, se.src_ip::text, se.dst_port, se.timestamp,
                           jf.event_id
                    FROM ja4_fingerprints jf
                    LEFT JOIN sensor_events se ON se.event_id = jf.event_id
                    WHERE jf.fingerprint = %s OR jf.fingerprint LIKE %s
                    ORDER BY se.timestamp DESC LIMIT 50
                """,
                    (fp, fp + "%"),
                )
                events = [
                    {
                        "fingerprint": r[0],
                        "type": r[1],
                        "identified": r[2],
                        "sni": r[3],
                        "tls_version": r[4],
                        "src_ip": r[5],
                        "dst_port": r[6],
                        "timestamp": r[7].isoformat() if r[7] else None,
                        "event_id": r[8],
                    }
                    for r in cur.fetchall()
                ]
            except Exception as e:
                logger.debug("JA4 fingerprint events query failed: %s", e)
        # Check for known malicious
        is_malicious = any(_is_threat_fp(m.get("application", "")) for m in db_matches)
        return {
            "fingerprint": fp,
            "db_matches": db_matches,
            "events": events,
            "is_malicious": is_malicious,
            "db_count": len(db_matches),
            "event_count": len(events),
        }
    except Exception as e:
        return {"error": str(e), "db_matches": [], "events": []}


def _is_threat_fp(name):
    n = (name or "").lower()
    return any(
        kw in n
        for kw in [
            "cobalt",
            "strike",
            "metasploit",
            "empire",
            "sliver",
            "havoc",
            "brute",
            "scan",
            "nmap",
            "masscan",
        ]
    )


@router.get("/ja4/stats/ja4s")
def ja4s_stats(request: Request):
    """JA4S (server fingerprint) statistics."""
    if not _HAS_JA4_TABLE:
        return {"error": "ja4_fingerprints table not found"}
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT jf.fingerprint, jf.identified, jf.tls_version, jf.sni,
                   COUNT(*) AS cnt, COUNT(DISTINCT se.src_ip) AS unique_ips,
                   MAX(se.timestamp) AS last_seen
            FROM ja4_fingerprints jf
            LEFT JOIN sensor_events se ON se.event_id = jf.event_id
            WHERE jf.fingerprint_type = 'ja4s'
            GROUP BY jf.fingerprint, jf.identified, jf.tls_version, jf.sni
            ORDER BY cnt DESC LIMIT 100
        """)
        rows = [
            {
                "fingerprint": r[0],
                "identified": r[1],
                "tls_version": r[2],
                "sni": r[3],
                "count": r[4],
                "unique_ips": r[5],
                "last_seen": r[6].isoformat() if r[6] else None,
            }
            for r in cur.fetchall()
        ]
        cur.execute(
            "SELECT COUNT(*), COUNT(DISTINCT fingerprint) FROM ja4_fingerprints WHERE fingerprint_type = 'ja4s'"
        )
        total, unique = cur.fetchone()
        conn.close()
        result = {"total": total or 0, "unique": unique or 0, "fingerprints": rows}
        if wants_html(request):
            return HTMLResponse(_ja4s_stats_html(result))
        return result
    except Exception as e:
        conn.close()
        return {"error": str(e)}


@router.get("/ja4/stats/ja4h")
def ja4h_stats(request: Request):
    """JA4H (HTTP fingerprint) statistics."""
    if not _HAS_JA4_TABLE:
        return {"error": "ja4_fingerprints table not found"}
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT jf.fingerprint, jf.identified, jf.sni,
                   COUNT(*) AS cnt, COUNT(DISTINCT se.src_ip) AS unique_ips,
                   MAX(se.timestamp) AS last_seen
            FROM ja4_fingerprints jf
            LEFT JOIN sensor_events se ON se.event_id = jf.event_id
            WHERE jf.fingerprint_type = 'ja4h'
            GROUP BY jf.fingerprint, jf.identified, jf.sni
            ORDER BY cnt DESC LIMIT 100
        """)
        rows = [
            {
                "fingerprint": r[0],
                "identified": r[1],
                "sni": r[2],
                "count": r[3],
                "unique_ips": r[4],
                "last_seen": r[5].isoformat() if r[5] else None,
            }
            for r in cur.fetchall()
        ]
        cur.execute(
            "SELECT COUNT(*), COUNT(DISTINCT fingerprint) FROM ja4_fingerprints WHERE fingerprint_type = 'ja4h'"
        )
        total, unique = cur.fetchone()
        conn.close()
        result = {"total": total or 0, "unique": unique or 0, "fingerprints": rows}
        if wants_html(request):
            return HTMLResponse(_ja4h_stats_html(result))
        return result
    except Exception as e:
        conn.close()
        return {"error": str(e)}


# This route MUST come AFTER all /ja4/... specific routes
# because {fingerprint} is a catch-all parameter
@router.get("/ja4/{fingerprint}")
def ja4_events(fingerprint: str, request: Request, limit: int = 100):
    """Get events by JA4 fingerprint."""
    if not _HAS_JA4_TABLE:
        raise HTTPException(status_code=404, detail="ja4_fingerprints table not found")

    # Validate fingerprint format (a_b_c with hex parts) or longer formats
    if not re.match(r"^[a-z0-9_]+$", fingerprint):
        raise HTTPException(status_code=400, detail="Invalid JA4 fingerprint format")

    conn = db()
    cur = conn.cursor()

    # Try exact match first, then partial match
    cur.execute(
        """
        SELECT j.event_id, j.fingerprint, j.fingerprint_type, j.sni, j.identified,
               j.tls_version, j.alpn, j.cipher_count, j.extension_count,
               e.timestamp::text, e.src_ip::text, e.dst_ip::text, e.dst_port
        FROM ja4_fingerprints j
        JOIN sensor_events e ON j.event_id = e.event_id
        WHERE j.fingerprint = %s
           OR j.fingerprint_a = %s
           OR j.fingerprint LIKE %s
        ORDER BY e.timestamp DESC
        LIMIT %s
    """,
        (fingerprint, fingerprint, f"{fingerprint}%", limit),
    )

    rows = cur.fetchall()
    conn.close()

    # Lookup fingerprint in JA4+ database
    db_info = lookup_ja4_fingerprint(fingerprint)

    result = {
        "fingerprint": fingerprint,
        "db_match": db_info if db_info else None,
        "event_count": len(rows),
        "events": [
            {
                "event_id": r[0],
                "fingerprint": r[1],
                "type": r[2],
                "sni": r[3],
                "identified": r[4] or (db_info.get("application") if db_info else None),
                "tls_version": r[5],
                "alpn": r[6],
                "cipher_count": r[7],
                "extension_count": r[8],
                "timestamp": r[9],
                "src_ip": r[10],
                "dst_ip": r[11],
                "dst_port": r[12],
            }
            for r in rows
        ],
    }

    if wants_html(request):
        return HTMLResponse(content=_ja4_events_html(result))
    return result


# ---------------------------------------------------------------------------
