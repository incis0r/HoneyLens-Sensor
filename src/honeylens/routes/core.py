"""
routes/core.py — Core Event & Dashboard Routes
=================================================
Extracted from api.py (Phase 1 refactor).
Dashboard, events, event detail, payload, PCAP, scanners, GeoIP.
"""

from __future__ import annotations

import html
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg2.sql as psycopg2_sql
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

from honeylens.config import API_PCAP_DIR
from honeylens.geoip import get_country_code, lookup_ip
from honeylens.intelligence.whitelist import is_whitelisted
from honeylens.routes._helpers import (
    EXCLUDED_SUBNETS,
    db,
    html_response,
    strip_cidr,
    valid_event_id,
    valid_ip,
    valid_protocol,
    wants_html,
)

logger = logging.getLogger("api")

router = APIRouter(tags=["Core Events"])

# 1.0: the attack_types column and the attack_patterns table come from migrations 0001/0002,
# which honeylens-migrate runs before the API — no probing of the database at module import.
_HAS_ATTACK_COL = True
_HAS_ATTACK_TBL = True


# Import shared query builders from api.py (they stay there as shared utils)
def _get_shared():
    """Lazy import of shared functions still in api.py.

    Lazy import because ``honeylens.api`` imports this module — a circular dependency at
    startup. 0.9 had a flat ``import api`` here (sys.path bootstrap), which in 1.0 raised
    ``ModuleNotFoundError`` only on the event-list code path.
    """
    import honeylens.api as _api

    return _api


def _dashboard_html():
    from honeylens.webui.dashboard_main import render_dashboard

    return render_dashboard()


def _event_detail_html(*args, **kwargs):
    from honeylens.webui.endpoint_generic import event_detail_html

    return event_detail_html(*args, **kwargs)


def _get_country(ip):
    if not ip:
        return "??"
    if is_whitelisted(ip):
        return "PIRATE"
    return get_country_code(ip)


# Routes — Dashboard
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(content=_dashboard_html())


@router.get("/stats/summary")
def stats_summary():
    """Fast dashboard KPIs from materialised view (no COUNT(*) on 25M rows)."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM mv_event_stats")
        r = cur.fetchone()
        cols = [d[0] for d in cur.description]
        result = dict(zip(cols, r, strict=False)) if r else {}
        for k, v in result.items():
            if hasattr(v, "isoformat"):
                result[k] = v.isoformat()
        conn.close()
        return result
    except Exception as e:
        logger.debug("Event stats query failed: %s", e)
        conn.close()
        return {
            "total_events": 0,
            "latest_event": None,
            "recent_5m": 0,
            "recent_1h": 0,
            "recent_24h": 0,
            "unique_ips_24h": 0,
        }


@router.get("/status")
def system_status(request: Request):
    """Get overall system status including all sensors."""
    conn = db()
    cur = conn.cursor()

    status: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "database": "ok",
        "sensors": {},
    }

    # Main sensor status — use materialised view if available (avoids COUNT(*) on 25M+ rows)
    try:
        cur.execute("SELECT total_events, latest_event, recent_5m FROM mv_event_stats")
        row = cur.fetchone()
    except Exception as e:
        logger.debug("mv_event_stats fallback to direct query: %s", e)
        conn.rollback()
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*), MAX(timestamp),
                   COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '5 minutes')
            FROM sensor_events
        """)
        row = cur.fetchone()
    status["sensors"]["ebpf_sensor"] = {
        "total_events": row[0],
        "last_event": row[1].isoformat() if row[1] else None,
        "events_5min": row[2],
        "status": "active" if row[2] > 0 else "idle",
    }

    # Honeypot status
    cur.execute("""
        SELECT source, COUNT(*), MAX(timestamp),
               COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '5 minutes')
        FROM sensor_events
        WHERE source IN ('honeypotng', 'k8s-honeypot', 'fortigate-honeypot')
        GROUP BY source
    """)
    honeypots = {}
    for row in cur.fetchall():
        honeypots[row[0]] = {
            "total_events": row[1],
            "last_event": row[2].isoformat() if row[2] else None,
            "events_5min": row[3],
            "status": "active" if row[3] > 0 else "idle",
        }
    status["sensors"]["honeypots"] = honeypots

    # MiTM detector status
    try:
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'mitm_events'
            )
        """)
        if cur.fetchone()[0]:
            cur.execute("""
                SELECT COUNT(*), MAX(timestamp),
                       COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '5 minutes'),
                       COUNT(*) FILTER (WHERE acknowledged = FALSE AND severity IN ('CRITICAL', 'HIGH')
                                        AND COALESCE(baseline, FALSE) = FALSE)
                FROM mitm_events
            """)
            row = cur.fetchone()
            status["sensors"]["mitm_detector"] = {
                "enabled": True,
                "total_events": row[0],
                "last_event": row[1].isoformat() if row[1] else None,
                "events_5min": row[2],
                "unacked_critical": row[3],
                "status": "active" if row[2] > 0 else "idle",
            }
        else:
            status["sensors"]["mitm_detector"] = {"enabled": False, "status": "not_configured"}
    except Exception as e:
        logger.debug("MiTM detector status check failed: %s", e)
        status["sensors"]["mitm_detector"] = {"enabled": False, "status": "error"}

    conn.close()

    if wants_html(request):
        return html_response("System Status", status, request, "stats")
    return status


# ---------------------------------------------------------------------------
# Routes — Events
# ---------------------------------------------------------------------------


@router.get("/events")
def get_events(
    request: Request,
    limit: int = 50,
    page: int = 1,
    ip: str | None = None,
    protocol: str | None = None,
    rule: str | None = None,
    attack_type: str | None = None,
    port: int | None = None,
    ja4: str | None = None,
    q: str | None = None,
):
    limit = min(max(limit, 1), 100)
    page = max(page, 1)
    offset = (page - 1) * limit

    conn = db()
    cur = conn.cursor()

    cols = _get_shared()._build_events_query()
    where_parts = [
        "timestamp IS NOT NULL",
        "src_ip IS NOT NULL",
        "NOT (src_ip <<= ANY(%s::inet[]))",
        "source != 'suricata'",
    ]
    params: list[Any] = [EXCLUDED_SUBNETS]

    if ip:
        where_parts.append("src_ip::text LIKE %s")
        params.append(f"%{ip}%")
    if protocol:
        where_parts.append("LOWER(protocol) = LOWER(%s)")
        params.append(protocol)
    if rule:
        where_parts.append("attack_types ILIKE %s")
        params.append(f"%{rule}%")
    if attack_type:
        where_parts.append("attack_types ILIKE %s")
        params.append(f"%{attack_type}%")
    if port:
        where_parts.append("(dst_port = %s OR src_port = %s)")
        params.extend([port, port])
    if ja4:
        where_parts.append("payload ILIKE %s")
        params.append(f"%{ja4}%")
    if q:
        where_parts.append("(payload ILIKE %s OR attack_types ILIKE %s OR src_ip::text LIKE %s)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

    where_sql = " AND ".join(where_parts)
    has_filters = any([ip, protocol, rule, attack_type, port, ja4, q])

    # Count total — use fast estimate for unfiltered queries (avoid full table scan)
    if has_filters:
        cur.execute(
            psycopg2_sql.SQL("SELECT COUNT(*) FROM sensor_events WHERE {}").format(
                psycopg2_sql.SQL(where_sql)
            ),
            params,
        )
        total = cur.fetchone()[0]
    else:
        cur.execute("SELECT reltuples::bigint FROM pg_class WHERE relname = 'sensor_events'")
        row = cur.fetchone()
        total = row[0] if row and row[0] > 0 else 0

    # Fetch page
    params_page = [*params, limit, offset]
    cur.execute(
        psycopg2_sql.SQL("""
        SELECT {}
        FROM sensor_events
        WHERE {}
        ORDER BY timestamp DESC
        LIMIT %s OFFSET %s
    """).format(psycopg2_sql.SQL(cols), psycopg2_sql.SQL(where_sql)),
        params_page,
    )

    rows = cur.fetchall()
    conn.close()
    result = []
    for r in rows:
        src_ip = strip_cidr(r[2])
        country_code = _get_country(src_ip)
        d = {
            "event_id": r[0],
            "source": r[1],
            "src_ip": src_ip,
            "src_port": r[3],
            "protocol": r[4],
            "dst_port": r[5],
            "timestamp": r[6],
            "scan_score": r[7],
            "port_entropy": r[8],
            "attack_types": r[9] if _HAS_ATTACK_COL else None,
            "country_code": country_code,
        }
        result.append(d)

    total_pages = max(1, (total + limit - 1) // limit)

    # HTML response with search bar
    if wants_html(request):
        search_bar = _get_shared()._events_search_bar_html(
            ip=ip,
            protocol=protocol,
            rule=rule,
            attack_type=attack_type,
            port=port,
            ja4=ja4,
            q=q,
            limit=limit,
            page=page,
            total=total,
            total_pages=total_pages,
            base_url="/events",
        )
        return html_response(
            f"Events — Page {page}/{total_pages} ({total:,} total)",
            result,
            request,
            "events",
            extra_html_top=search_bar,
        )
    # JSON: return flat array for backward compat (dashboard expects array)
    return result


# ---------------------------------------------------------------------------
# Routes — Events by IP
# ---------------------------------------------------------------------------


@router.get("/events_ip/{ip}")
def events_by_ip(ip: str, request: Request, limit: int = 500):
    if not valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    limit = min(max(limit, 1), 2000)
    conn = db()
    cur = conn.cursor()

    cols = _get_shared()._build_events_query_with_ja3()
    cur.execute(
        psycopg2_sql.SQL("""
        SELECT {}
        FROM sensor_events
        WHERE src_ip = %s::inet
        ORDER BY timestamp DESC
        LIMIT %s
    """).format(psycopg2_sql.SQL(cols)),
        (ip, limit),
    )

    rows = cur.fetchall()
    conn.close()
    result = []
    for r in rows:
        src_ip = strip_cidr(r[2])
        d = {
            "event_id": r[0],
            "source": r[1],
            "src_ip": src_ip,
            "src_port": r[3],
            "protocol": r[4],
            "dst_port": r[5],
            "timestamp": r[6],
            "scan_score": r[7],
            "port_entropy": r[8],
            "ja3": r[9],
            "attack_types": r[10] if _HAS_ATTACK_COL else None,
            "country_code": _get_country(src_ip),
        }
        result.append(d)
    return html_response(f"Events from IP: {ip}", result, request, "events")


# ---------------------------------------------------------------------------
# Routes — Events by Protocol
# ---------------------------------------------------------------------------


@router.get("/protocol/{name}")
def events_by_protocol(name: str, request: Request, limit: int = 500):
    if not valid_protocol(name):
        raise HTTPException(status_code=400, detail="Invalid protocol name")
    limit = min(max(limit, 1), 2000)
    conn = db()
    cur = conn.cursor()

    cols = _get_shared()._build_events_query()
    cur.execute(
        psycopg2_sql.SQL("""
        SELECT {}
        FROM sensor_events
        WHERE protocol = %s
          AND NOT (src_ip <<= ANY(%s::inet[]))
        ORDER BY timestamp DESC
        LIMIT %s
    """).format(psycopg2_sql.SQL(cols)),
        (name, EXCLUDED_SUBNETS, limit),
    )

    rows = cur.fetchall()
    conn.close()
    result = []
    for r in rows:
        src_ip = strip_cidr(r[2])
        d = {
            "event_id": r[0],
            "source": r[1],
            "src_ip": src_ip,
            "src_port": r[3],
            "protocol": r[4],
            "dst_port": r[5],
            "timestamp": r[6],
            "scan_score": r[7],
            "port_entropy": r[8],
            "attack_types": r[9] if _HAS_ATTACK_COL else None,
            "country_code": _get_country(src_ip),
        }
        result.append(d)
    return html_response(f"Events by Protocol: {name}", result, request, "events")


# ---------------------------------------------------------------------------
# Routes — Temporal
# ---------------------------------------------------------------------------


@router.get("/temporal")
def temporal():
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            DATE_TRUNC('minute', timestamp)::text,
            COUNT(*)
        FROM sensor_events
        WHERE NOT (src_ip <<= ANY(%s::inet[]))
        GROUP BY 1
        ORDER BY 1
    """,
        (EXCLUDED_SUBNETS,),
    )
    rows = cur.fetchall()
    conn.close()
    return [{"minute": r[0], "count": r[1]} for r in rows]


# ---------------------------------------------------------------------------
# Routes — Top Scanners
# ---------------------------------------------------------------------------


@router.get("/top_scanners")
def top_scanners(request: Request):
    conn = db()
    cur = conn.cursor()
    query = """
        SELECT
            src_ip::text,
            COUNT(*),
            MAX(scan_score)
        FROM sensor_events
        WHERE NOT (src_ip <<= ANY(%s::inet[]))
          AND timestamp >= NOW() - INTERVAL '24 hours'
          AND source != 'suricata'
        GROUP BY src_ip
        ORDER BY COUNT(*) DESC
        LIMIT 15
    """
    cur.execute(query, [EXCLUDED_SUBNETS])
    rows = cur.fetchall()
    conn.close()

    # Build result with country info
    result_rows = []
    result_dicts = []
    for r in rows:
        src_ip = strip_cidr(r[0])
        country_code = _get_country(src_ip)
        if src_ip and is_whitelisted(src_ip):
            country_code = "PIRATE"
        # Array format for dashboard JS compatibility
        result_rows.append([src_ip, r[1], r[2], country_code])
        # Dict format for HTML view
        result_dicts.append(
            {
                "src_ip": src_ip,
                "event_count": r[1],
                "max_scan_score": r[2],
                "country_code": country_code,
            }
        )

    # Return array for JSON (dashboard), dict for HTML view
    if wants_html(request):
        return html_response("Top Scanners", result_dicts, request, "stats")
    return result_rows


# ---------------------------------------------------------------------------
# Routes — GeoIP Lookup
# ---------------------------------------------------------------------------


@router.get("/geoip/{ip}")
def geoip_lookup(ip: str):
    """Look up geolocation information for an IP address."""
    if not valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")

    geo_info = lookup_ip(ip)
    return geo_info


# ---------------------------------------------------------------------------
# Routes — Top Ports
# ---------------------------------------------------------------------------


@router.get("/top_ports")
def top_ports(request: Request):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            dst_port,
            COUNT(*)
        FROM sensor_events
        WHERE NOT (src_ip <<= ANY(%s::inet[]))
          AND dst_port IS NOT NULL
          AND timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY dst_port
        ORDER BY COUNT(*) DESC
        LIMIT 15
    """,
        (EXCLUDED_SUBNETS,),
    )
    rows = cur.fetchall()
    conn.close()

    # Return array for JSON (dashboard), dict for HTML view
    if wants_html(request):
        result = [{"port": r[0], "count": r[1]} for r in rows]
        return html_response("Top Targeted Ports", result, request, "stats")
    return rows  # Original array format [[port, count], ...]


# ---------------------------------------------------------------------------
# Routes — Protocol Stats
# ---------------------------------------------------------------------------


@router.get("/protocols")
def protocols(request: Request):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            protocol,
            COUNT(*)
        FROM sensor_events
        WHERE NOT (src_ip <<= ANY(%s::inet[]))
          AND timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY protocol
        ORDER BY COUNT(*) DESC
    """,
        (EXCLUDED_SUBNETS,),
    )
    rows = cur.fetchall()
    conn.close()

    # Return array for JSON (dashboard), dict for HTML view
    if wants_html(request):
        result = [{"protocol": r[0], "count": r[1]} for r in rows]
        return html_response("Protocol Distribution", result, request, "stats")
    return rows  # Original array format [[protocol, count], ...]


# ---------------------------------------------------------------------------
# Routes — Sources
# ---------------------------------------------------------------------------


@router.get("/sources")
def sources(request: Request):
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT source, COUNT(*)
        FROM sensor_events
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY source
        ORDER BY COUNT(*) DESC
    """)
    rows = cur.fetchall()
    conn.close()

    # Return array for JSON (dashboard), dict for HTML view
    if wants_html(request):
        result = [{"source": r[0], "count": r[1]} for r in rows]
        return html_response("Event Sources", result, request, "stats")
    return rows  # Original array format [[source, count], ...]


# ---------------------------------------------------------------------------

# Routes — Full Event Detail
# ---------------------------------------------------------------------------


@router.get("/event_full/{event_id}")
def event_full(event_id: str, request: Request):
    if not valid_event_id(event_id):
        raise HTTPException(status_code=400, detail="Invalid event_id format")
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            event_id, timestamp::text, source, protocol,
            src_ip::text, src_port, dst_ip::text, dst_port,
            payload, payload_hash,
            scan_score, port_entropy,
            ja3, metadata, attack_types
        FROM sensor_events
        WHERE event_id = %s
    """,
        (event_id,),
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Event not found")

    meta = row[13]
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except (json.JSONDecodeError, TypeError):  # silent: raw payload display fallback
            pass  # silent: meta may not be valid JSON

    src_ip = strip_cidr(row[4])
    dst_ip = strip_cidr(row[6])

    # Parse payload - for FortiGate/honeypot events, payload is JSON
    payload_raw = row[8]
    payload_parsed = None
    payload_display = payload_raw

    if payload_raw and row[2] in ("fortigate-honeypot", "k8s-honeypot", "honeypotng"):
        try:
            payload_parsed = json.loads(payload_raw)
            # Create a formatted display version
            payload_display = json.dumps(payload_parsed, indent=2)
        except (json.JSONDecodeError, TypeError):  # silent: raw payload display fallback
            pass

    result = {
        "event_id": row[0],
        "timestamp": row[1],
        "source": row[2],
        "protocol": row[3],
        "src_ip": src_ip,
        "src_port": row[5],
        "dst_ip": dst_ip,
        "dst_port": row[7],
        "payload": payload_display,
        "payload_hash": row[9],
        "scan_score": row[10],
        "entropy": row[11],
        "ja3": row[12],
        "metadata": meta,
        "attack_types": row[14],
        "country_code": _get_country(src_ip),
    }

    # For FortiGate events, add parsed details to result
    if payload_parsed and row[2] == "fortigate-honeypot":
        result["fortigate_details"] = {
            "event_type": payload_parsed.get("event_type", ""),
            "path": payload_parsed.get("path", ""),
            "method": payload_parsed.get("method", ""),
            "user_agent": payload_parsed.get("user_agent", ""),
            "data": payload_parsed.get("data", {}),
        }

    # Fetch AI triage + Claude structured data from ai_analysis
    conn2 = db()
    cur2 = conn2.cursor()
    try:
        cur2.execute(
            """
            SELECT triage_class, triage_confidence, triage_reasoning,
                   novelty_score, known_cve, zero_day_score,
                   claude_verdict, claude_confidence, claude_attack_type,
                   claude_technique, claude_tactic, claude_cve,
                   claude_threat_actor, claude_summary, claude_kill_chain,
                   cve_details
            FROM ai_analysis WHERE event_id = %s
        """,
            (event_id,),
        )
        ai_row = cur2.fetchone()
        if ai_row:
            result["ai_triage"] = {
                "class": ai_row[0],
                "confidence": ai_row[1],
                "reasoning": ai_row[2],
                "novelty": ai_row[3],
                "cve": ai_row[4],
                "zero_day": ai_row[5],
            }
            # CVE intelligence (Idea 32)
            if ai_row[15]:
                result["cve_details"] = ai_row[15]
            if ai_row[6]:  # claude_verdict exists
                result["claude_current"] = {
                    "verdict": ai_row[6],
                    "confidence": ai_row[7],
                    "attack_type": ai_row[8],
                    "technique": ai_row[9],
                    "tactic": ai_row[10],
                    "cve": ai_row[11],
                    "threat_actor": ai_row[12],
                    "summary": ai_row[13],
                    "kill_chain": ai_row[14],
                }
    except Exception as e:
        logger.debug("AI analysis lookup failed for event: %s", e)

    # Fetch last 3 Claude analyses for this event from the audit log
    try:
        cur2.execute(
            """
            SELECT verdict, confidence, attack_type, technique, tactic,
                   cve, threat_actor, kill_chain, summary,
                   model, input_tokens, output_tokens, estimated_cost_usd,
                   elapsed_ms, created_at
            FROM claude_analysis_log
            WHERE event_id = %s
            ORDER BY created_at DESC LIMIT 3
        """,
            (event_id,),
        )
        result["claude_history"] = [
            {
                "verdict": r[0],
                "confidence": r[1],
                "attack_type": r[2],
                "technique": r[3],
                "tactic": r[4],
                "cve": r[5],
                "threat_actor": r[6],
                "kill_chain": r[7],
                "summary": r[8],
                "model": r[9],
                "input_tokens": r[10],
                "output_tokens": r[11],
                "cost": r[12],
                "elapsed_ms": r[13],
                "analyzed_at": r[14].isoformat() if r[14] else None,
            }
            for r in cur2.fetchall()
        ]
    except Exception as e:
        logger.debug("Claude history lookup failed: %s", e)
        result["claude_history"] = []

    conn2.close()

    if wants_html(request):
        return HTMLResponse(content=_event_detail_html(result))
    return result


# ---------------------------------------------------------------------------
# Routes — Payload
# ---------------------------------------------------------------------------


@router.get("/payload/{event_id}")
def payload(event_id: str, request: Request):
    if not valid_event_id(event_id):
        raise HTTPException(status_code=400, detail="Invalid event_id format")
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT payload, payload_hash FROM sensor_events WHERE event_id = %s", (event_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Payload not found")
    result = {"event_id": event_id, "payload": row[0], "payload_hash": row[1]}
    if wants_html(request):
        payload_text = row[0] or "(empty)"
        # Try to pretty-print if JSON
        display = payload_text
        try:
            parsed = json.loads(payload_text)
            display = json.dumps(parsed, indent=2)
        except (json.JSONDecodeError, TypeError):  # silent: raw payload display fallback
            pass
        payload_escaped = html.escape(display)
        content = f"""<h3>Payload</h3>
<p style="font-size:12px;color:var(--text2)"><b>Event:</b> <code>{html.escape(event_id)}</code></p>
<p style="font-size:12px;color:var(--text2)"><b>Hash:</b> <code>{html.escape(str(row[1] or ""))}</code></p>
<p style="font-size:12px;color:var(--text2)"><b>Size:</b> {len(payload_text)} bytes</p>
<div style="margin-top:12px">
<h4>Raw Payload</h4>
<pre style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:16px;font-size:12px;font-family:var(--mono);color:var(--text);overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:600px;overflow-y:auto">{payload_escaped}</pre>
</div>"""
        # Hex dump (first 512 bytes)
        raw_bytes = payload_text.encode("utf-8", errors="replace")[:512]
        hex_lines = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i : i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hex_lines.append(f"{i:04x}  {hex_part:<48s}  {ascii_part}")
        if hex_lines:
            content += f"""<div style="margin-top:16px">
<h4>Hex Dump (first 512 bytes)</h4>
<pre style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:16px;font-size:11px;font-family:var(--mono);color:var(--accent);overflow-x:auto">{html.escape(chr(10).join(hex_lines))}</pre>
</div>"""
        from honeylens.webui.dashboard_classifier import _classifier_html_page

        return HTMLResponse(content=_classifier_html_page("Payload — " + event_id[:16], content))
    return result


# ---------------------------------------------------------------------------
# Routes — PCAP download
# ---------------------------------------------------------------------------


@router.get("/pcap/{event_id}")
def download_pcap(event_id: str):
    if not valid_event_id(event_id):
        raise HTTPException(status_code=400, detail="Invalid event_id format")
    pcap_dir = Path(API_PCAP_DIR).resolve()
    pcap_path = (pcap_dir / f"{event_id}.pcap").resolve()
    if not pcap_path.is_relative_to(pcap_dir):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail="PCAP not found")
    return FileResponse(
        pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"{event_id}.pcap",
    )


# ---------------------------------------------------------------------------
# Routes — Attack Pattern Stats
