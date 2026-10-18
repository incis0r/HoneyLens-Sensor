"""
routes/export.py — Archive & Blog Publishing Routes
=====================================================
Extracted from api.py (Phase 1 refactor).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import psycopg2.sql as psycopg2_sql
from fastapi import APIRouter, HTTPException, Request

from honeylens.intelligence.scanner_exclusions import is_known_scanner
from honeylens.routes._helpers import db, html_response, valid_event_id, wants_html

logger = logging.getLogger("api")

router = APIRouter(tags=["Archive & Blog"])

# Blog publisher (lazy import from api.py config)
try:
    from honeylens.config import BLOG as _BLOG_CFG
    from honeylens.publishing.blog_publisher import BlogPublisher

    _HAS_BLOG = _BLOG_CFG.get("enabled", False)
    _blog_publisher = BlogPublisher(_BLOG_CFG) if _HAS_BLOG else None
except ImportError:
    _HAS_BLOG = False
    _BLOG_CFG = {}
    _blog_publisher = None


def _get_archive_tables() -> list:
    """Get list of archive tables."""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name LIKE 'archive_events_%'
            ORDER BY table_name DESC
        """)
        tables = [row[0] for row in cur.fetchall()]
        conn.close()
        return tables
    except Exception as e:
        logger.debug("Archive tables query failed: %s", e)
        return []


@router.get("/archive/tables")
def archive_tables(request: Request):
    """List available archive tables."""
    tables = _get_archive_tables()

    if not tables:
        return {"tables": [], "message": "No archive tables found"}

    conn = db()
    cur = conn.cursor()

    result = []
    for table in tables:
        # Get count and size
        try:
            cur.execute(
                psycopg2_sql.SQL("SELECT COUNT(*) FROM {}").format(psycopg2_sql.Identifier(table))
            )
            count = cur.fetchone()[0]

            cur.execute("SELECT pg_size_pretty(pg_total_relation_size(%s))", (table,))
            size = cur.fetchone()[0]

            # Parse year/month from table name
            parts = table.split("_")
            year, month = int(parts[2]), int(parts[3])

            result.append(
                {
                    "table": table,
                    "year": year,
                    "month": month,
                    "events": count,
                    "size": size,
                }
            )
        except Exception as e:
            logger.debug("Archive table %s stats failed: %s", table, e)

    conn.close()

    if wants_html(request):
        return html_response("Archive Tables", {"tables": result}, request, "stats")
    return {"tables": result, "count": len(result)}


@router.get("/archive/search")
def archive_search(
    request: Request,
    src_ip: str | None = None,
    attack_type: str | None = None,
    q: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    limit: int = 100,
):
    """
    Search archived events.

    Parameters:
    - src_ip: Filter by source IP
    - attack_type: Filter by attack type (e.g., SQLI, XSS)
    - q: Search in payload
    - start_date: Start date (YYYY-MM-DD)
    - end_date: End date (YYYY-MM-DD)
    - limit: Max results (default 100, max 1000)
    """
    archive_tables = _get_archive_tables()

    if not archive_tables:
        return {"events": [], "searched_tables": [], "message": "No archives available"}

    limit = min(max(limit, 1), 1000)

    # Filter tables by date range if specified
    tables_to_search = []
    for table in archive_tables:
        parts = table.split("_")
        year, month = int(parts[2]), int(parts[3])

        if start_date:
            try:
                start = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=UTC)
                if year < start.year or (year == start.year and month < start.month):
                    continue
            except ValueError:
                pass  # silent: ignore invalid date filter, include all tables

        if end_date:
            try:
                end = datetime.strptime(end_date, "%Y-%m-%d").replace(tzinfo=UTC)
                if year > end.year or (year == end.year and month > end.month):
                    continue
            except ValueError:
                pass  # silent: ignore invalid date filter, include all tables

        tables_to_search.append(table)

    if not tables_to_search:
        return {"events": [], "searched_tables": [], "message": "No matching archive tables"}

    # Limit to 12 months max
    tables_to_search = tables_to_search[:12]

    conn = db()
    cur = conn.cursor()

    # Build UNION query across archive tables
    union_parts = []
    params = []

    for table in tables_to_search:
        query = psycopg2_sql.SQL("""
            SELECT event_id, timestamp, source, protocol,
                   src_ip::text, src_port, dst_ip::text, dst_port,
                   attack_types, %s as archive_table
            FROM {}
            WHERE 1=1
        """).format(psycopg2_sql.Identifier(table))
        table_params = [table]

        if src_ip:
            query += psycopg2_sql.SQL(" AND src_ip::text = %s")
            table_params.append(src_ip)

        if attack_type:
            query += psycopg2_sql.SQL(" AND attack_types LIKE %s")
            table_params.append(f"%{attack_type}%")

        if q:
            query += psycopg2_sql.SQL(" AND payload ILIKE %s")
            table_params.append(f"%{q}%")

        if start_date:
            query += psycopg2_sql.SQL(" AND timestamp >= %s")
            table_params.append(start_date)

        if end_date:
            query += psycopg2_sql.SQL(" AND timestamp <= %s")
            table_params.append(end_date + " 23:59:59")

        union_parts.append(query)
        params.extend(table_params)

    full_query = psycopg2_sql.SQL(" UNION ALL ").join(union_parts)
    full_query += psycopg2_sql.SQL(" ORDER BY timestamp DESC LIMIT %s")
    params.append(limit)

    try:
        cur.execute(full_query, params)
        rows = cur.fetchall()
    except Exception as e:
        logger.error("archive_search error: %s", e)
        conn.close()
        return {"error": "An internal error occurred", "events": []}

    conn.close()

    events = [
        {
            "event_id": r[0],
            "timestamp": r[1].isoformat() if r[1] else None,
            "source": r[2],
            "protocol": r[3],
            "src_ip": r[4],
            "src_port": r[5],
            "dst_ip": r[6],
            "dst_port": r[7],
            "attack_types": r[8],
            "archive_table": r[9],
            "archived": True,
        }
        for r in rows
    ]

    result = {
        "events": events,
        "count": len(events),
        "searched_tables": tables_to_search,
    }

    if wants_html(request):
        return html_response("Archive Search", result, request, "events")
    return result


@router.get("/archive/event/{event_id}")
def archive_event_detail(event_id: str, request: Request):
    """Get full event detail from archive."""
    if not valid_event_id(event_id):
        raise HTTPException(status_code=400, detail="Invalid event_id format")

    archive_tables = _get_archive_tables()

    if not archive_tables:
        raise HTTPException(status_code=404, detail="No archives available")

    conn = db()
    cur = conn.cursor()

    for table in archive_tables:
        try:
            cur.execute(
                psycopg2_sql.SQL("""
                SELECT event_id, timestamp, source, protocol,
                       src_ip::text, src_port, dst_ip::text, dst_port,
                       payload, payload_hash, attack_types,
                       scan_score, port_entropy, ja3, metadata
                FROM {}
                WHERE event_id = %s
            """).format(psycopg2_sql.Identifier(table)),
                (event_id,),
            )

            row = cur.fetchone()
            if row:
                conn.close()
                result = {
                    "event_id": row[0],
                    "timestamp": row[1].isoformat() if row[1] else None,
                    "source": row[2],
                    "protocol": row[3],
                    "src_ip": row[4],
                    "src_port": row[5],
                    "dst_ip": row[6],
                    "dst_port": row[7],
                    "payload": row[8],
                    "payload_hash": row[9],
                    "attack_types": row[10],
                    "scan_score": row[11],
                    "port_entropy": row[12],
                    "ja3": row[13],
                    "metadata": row[14],
                    "archived": True,
                    "archive_table": table,
                }

                if wants_html(request):
                    return html_response(
                        f"Archived Event: {event_id}", result, request, "event_detail"
                    )
                return result
        except Exception as e:
            logger.debug("Archive event lookup in %s failed: %s", table, e)

    conn.close()
    raise HTTPException(status_code=404, detail="Event not found in archives")


@router.get("/archive/stats")
def archive_stats(request: Request):
    """Get archive statistics."""
    archive_tables = _get_archive_tables()

    if not archive_tables:
        return {
            "archive_tables": 0,
            "archived_events": 0,
            "tables": [],
            "message": "No archives found",
        }

    conn = db()
    cur = conn.cursor()

    tables = []
    total_events = 0
    total_size = 0

    for table in archive_tables:
        try:
            # Use n_live_tup estimate from pg_stat_user_tables instead of
            # COUNT(*). On a 100M-row, 109 GB archive_events_2026_03 the
            # COUNT(*) hits the default statement_timeout under load
            # (measured in production). The estimate is exact for read-only archive
            # tables once autoanalyze has settled — and updated by every
            # archive_month run anyway. Falls back to 0 if pg_stat returns
            # no row (table newly created, autoanalyze not yet run).
            cur.execute(
                "SELECT n_live_tup FROM pg_stat_user_tables WHERE relname = %s",
                (table,),
            )
            row = cur.fetchone()
            count = int(row[0]) if row and row[0] is not None else 0

            cur.execute("SELECT pg_total_relation_size(%s)", (table,))
            size_bytes = cur.fetchone()[0]

            cur.execute("SELECT pg_size_pretty(%s::bigint)", (size_bytes,))
            size_pretty = cur.fetchone()[0]

            parts = table.split("_")
            year, month = int(parts[2]), int(parts[3])

            tables.append(
                {
                    "table": table,
                    "year": year,
                    "month": month,
                    "events": count,
                    "size": size_pretty,
                    "size_bytes": size_bytes,
                }
            )

            total_events += count
            total_size += size_bytes
        except Exception as e:
            logger.debug("Archive stats for %s failed: %s", table, e)

    # Get main table stats. COUNT(*) on the live sensor_events would hit
    # statement_timeout (78 GB / 73M rows in production); n_live_tup
    # is an estimate but accurate enough for an "Archive Statistics" page.
    # MIN/MAX timestamp use idx_se_timestamp (returns first/last leaf
    # entry) so they're cheap.
    try:
        cur.execute(
            "SELECT n_live_tup FROM pg_stat_user_tables WHERE relname = %s",
            ("sensor_events",),
        )
        row = cur.fetchone()
        active_events = int(row[0]) if row and row[0] is not None else 0

        cur.execute("SELECT pg_size_pretty(pg_total_relation_size('sensor_events'))")
        active_size = cur.fetchone()[0]

        cur.execute("SELECT MIN(timestamp), MAX(timestamp) FROM sensor_events")
        date_range = cur.fetchone()
    except Exception as e:
        logger.debug("Active events stats query failed: %s", e)
        active_events = 0
        active_size = "0 bytes"
        date_range = (None, None)

    conn.close()

    result = {
        "archive_tables": len(tables),
        "archived_events": total_events,
        "archived_size": f"{total_size / 1024 / 1024:.2f} MB",
        "active_events": active_events,
        "active_size": active_size,
        "active_date_range": {
            "min": date_range[0].isoformat() if date_range[0] else None,
            "max": date_range[1].isoformat() if date_range[1] else None,
        },
        "tables": tables,
    }

    if wants_html(request):
        return html_response("Archive Statistics", result, request, "stats")
    return result


# ---------------------------------------------------------------------------
@router.get("/blog/status")
async def blog_status():
    """Check if blog publishing is available and configured."""
    return {
        "available": _HAS_BLOG and _blog_publisher is not None,
        "enabled": _BLOG_CFG.get("enabled", False) if _BLOG_CFG else False,
        "blog_url": _BLOG_CFG.get("blog_url", "") if _BLOG_CFG else "",
    }


@router.post("/blog/publish/{ip}")
async def blog_publish(ip: str, request: Request):
    """
    Publish or update a threat advisory for the given IP to the external blog.
    Triggered manually from dashboard buttons.
    """
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    import ipaddress as _ipa

    try:
        _ipa.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None

    if not _HAS_BLOG or not _blog_publisher:
        raise HTTPException(
            status_code=503,
            detail="Blog publishing not configured. Set BLOG.enabled=True in config.py",
        )

    # Skip known research scanners
    if is_known_scanner(ip=ip):
        raise HTTPException(
            status_code=422, detail=f"Skipped: {ip} is a known research scanner — not publishing"
        )

    try:
        result = _blog_publisher.publish(ip=ip, trigger="manual")
    except Exception as exc:
        logger.error("blog_publish: %s — %s", ip, exc)
        raise HTTPException(status_code=500, detail=f"Publish failed: {exc!s}") from exc

    status = result.get("status", "error")
    if status in ("created", "updated"):
        blog_url = _BLOG_CFG.get("blog_url", "").rstrip("/")
        result["post_url"] = f"{blog_url}/ip/{ip}"
        return result
    elif status == "disabled":
        raise HTTPException(status_code=503, detail=result.get("msg", "Blog disabled"))
    elif status == "rejected":
        raise HTTPException(status_code=400, detail=result.get("msg", "Rejected"))
    elif status == "skipped":
        raise HTTPException(status_code=404, detail=result.get("msg", "No data for IP"))
    else:
        raise HTTPException(status_code=500, detail=result.get("msg", f"Publish failed: {status}"))
