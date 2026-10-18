"""
routes/ics.py — ICS/OT Detection Routes
=========================================
Extracted from api.py (Phase 1 refactor).
"""

from __future__ import annotations

import html
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# get_country_code is the GeoIP fallback used by /ics/event/{id}. Soft-import
# matches the pattern in api.py / routes/core.py / routes/classifier.py /
# routes/intelligence.py — without it, the bare reference at line 410 raises
# NameError on every ICS event detail page.
from honeylens.geoip import get_country_code
from honeylens.routes._helpers import db, html_response, strip_cidr, valid_event_id, wants_html

logger = logging.getLogger("api")

# Summary counters; {fp_pred} is a constant fragment from code (false_positive gate).
_SUMMARY_SQL = """
    SELECT
        COUNT(*) FILTER (WHERE TRUE{fp_pred})                          AS total,
        COUNT(*) FILTER (WHERE timestamp >= NOW()-INTERVAL '24 hours'{fp_pred}) AS last_24h,
        COUNT(*) FILTER (WHERE timestamp >= NOW()-INTERVAL '1 hour'{fp_pred})   AS last_1h,
        COUNT(*) FILTER (WHERE (is_write OR is_control){fp_pred})       AS writes_controls,
        COUNT(*) FILTER (WHERE severity = 'CRITICAL'{fp_pred})          AS critical,
        COUNT(*) FILTER (WHERE severity = 'HIGH'{fp_pred})              AS high,
        COUNT(*) FILTER (WHERE severity = 'MEDIUM'{fp_pred})            AS medium,
        COUNT(*) FILTER (WHERE severity = 'LOW'{fp_pred})               AS low,
        COUNT(*) FILTER (WHERE acknowledged = FALSE{fp_pred})           AS unacked,
        COUNT(DISTINCT src_ip) FILTER (WHERE TRUE{fp_pred})             AS unique_src,
        COUNT(DISTINCT dst_ip) FILTER (WHERE TRUE{fp_pred})             AS unique_dst,
        COUNT(*) FILTER (WHERE false_positive)                          AS false_positives
    FROM ics_events
"""

router = APIRouter(tags=["ICS/OT Detection"])


# WebUI imports (lazy)
def _ics_not_configured_html():
    from honeylens.webui.dashboard_ics import _ics_not_configured_html as fn

    return fn()


def _ics_dashboard_html(data):
    from honeylens.webui.dashboard_ics import _ics_dashboard_html as fn

    return fn(data)


# Routes — ICS/OT Detection (MITRE ATT&CK for ICS / Caldera)
# ---------------------------------------------------------------------------


def _ics_table_exists() -> bool:
    """Check if ics_events table exists."""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'ics_events'
            )
        """)
        exists = cur.fetchone()[0]
        conn.close()
        return exists
    except Exception:
        return False  # silent: table existence check


def _derive_intent(attack_type, is_control, is_write, is_discovery, severity) -> str:
    """Operator intent funnel bucket. Precedence: command > write > recon >
    enumeration. Mirrors the SQL intent funnel in ics_stats."""
    at = (attack_type or "").lower()
    if "command" in at or is_control:
        return "command"
    if "write" in at or is_write:
        return "write"
    if "recon" in at or is_discovery or severity in ("MEDIUM",):
        return "recon"
    return "enumeration"


# ── Triage request body models ──────────────────────────────────────────────
class _EventIdsBody(BaseModel):
    event_ids: list[str]


class _FalsePositiveBody(BaseModel):
    event_ids: list[str] = []
    src_ip: str | None = None
    protocol: str | None = None
    dst_port: int | None = None
    note: str | None = None


class _TrustSourceBody(BaseModel):
    src_ip: str
    protocol: str | None = None


# SQL CASE that mirrors _derive_intent() exactly, for server-side intent
# filtering (the dashboard's KPI / funnel / chip drill-downs need to query the
# whole table, not just the last 500 rows the page embeds).
_INTENT_CASE = (
    "CASE"
    " WHEN LOWER(COALESCE(attack_type,'')) LIKE '%%command%%' OR is_control THEN 'command'"
    " WHEN LOWER(COALESCE(attack_type,'')) LIKE '%%write%%' OR is_write THEN 'write'"
    " WHEN LOWER(COALESCE(attack_type,'')) LIKE '%%recon%%' OR is_discovery OR severity='MEDIUM' THEN 'recon'"
    " ELSE 'enumeration' END"
)


@router.get("/ics/events")
def ics_events(
    request: Request,
    limit: int = 50,
    page: int = 1,
    ip: str | None = None,
    protocol: str | None = None,
    severity: str | None = None,
    mitre_technique: str | None = None,
    is_write: bool | None = None,
    rule: str | None = None,
    q: str | None = None,
    intent: str | None = None,
    impact: bool | None = None,
    include_fp: bool = False,
):
    """Get recent ICS/OT security events with search and pagination.

    `intent` filters on the funnel bucket (command/write/recon/enumeration);
    `impact` = True restricts to physical-impact ops (is_write OR is_control).
    """
    if not _ics_table_exists():
        return {"error": "ICS detection not configured", "events": []}

    limit = min(max(limit, 1), 500)
    page = max(page, 1)
    offset = (page - 1) * limit

    conn = db()
    cur = conn.cursor()

    query = """
        SELECT event_id, timestamp, protocol, function_code, function_name,
               src_ip::text, src_port, dst_ip::text, dst_port,
               unit_id, register_start, register_count,
               is_read, is_write, is_control, is_discovery,
               mitre_tactic, mitre_technique, attack_type, rule_name,
               severity, confidence, metadata, acknowledged
        FROM ics_events
        WHERE 1=1
    """
    params: list[Any] = []

    if not include_fp:
        query += " AND NOT false_positive"
    if ip:
        query += " AND src_ip::text LIKE %s"
        params.append(f"%{ip}%")
    if protocol:
        query += " AND protocol = %s"
        params.append(protocol)
    if severity:
        query += " AND severity = %s"
        params.append(severity.upper())
    if mitre_technique:
        query += " AND mitre_technique = %s"
        params.append(mitre_technique.upper())
    if is_write is not None:
        query += " AND is_write = %s"
        params.append(is_write)
    if impact:
        query += " AND (is_write OR is_control)"
    if intent:
        query += " AND " + _INTENT_CASE + " = %s"
        params.append(intent.lower())
    if rule:
        query += " AND (rule_name ILIKE %s OR attack_type ILIKE %s)"
        params.extend([f"%{rule}%", f"%{rule}%"])
    if q:
        query += " AND (rule_name ILIKE %s OR attack_type ILIKE %s OR src_ip::text LIKE %s OR protocol ILIKE %s)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])

    # Count total matching
    count_query = query.replace(
        "SELECT event_id, timestamp, protocol, function_code, function_name,\n"
        "               src_ip::text, src_port, dst_ip::text, dst_port,\n"
        "               unit_id, register_start, register_count,\n"
        "               is_read, is_write, is_control, is_discovery,\n"
        "               mitre_tactic, mitre_technique, attack_type, rule_name,\n"
        "               severity, confidence, metadata, acknowledged",
        "SELECT COUNT(*)",
    )
    cur.execute(count_query, params[:])
    cur.fetchone()[0]

    query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    events = [
        {
            "event_id": r[0],
            "timestamp": r[1].isoformat() if r[1] else None,
            "protocol": r[2],
            "function_code": r[3],
            "function_name": r[4],
            "src_ip": r[5],
            "src_port": r[6],
            "dst_ip": r[7],
            "dst_port": r[8],
            "unit_id": r[9],
            "register_start": r[10],
            "register_count": r[11],
            "is_read": r[12],
            "is_write": r[13],
            "is_control": r[14],
            "is_discovery": r[15],
            "mitre_tactic": r[16],
            "mitre_technique": r[17],
            "attack_type": r[18],
            "rule_name": r[19],
            "severity": r[20],
            "confidence": r[21],
            "metadata": r[22],
            "acknowledged": r[23],
            "intent": _derive_intent(r[18], r[14], r[13], r[15], r[20]),
        }
        for r in rows
    ]

    if wants_html(request):
        return html_response("ICS/OT Events", events, request, "events")
    return {"events": events, "count": len(events)}


@router.get("/ics/ip/{ip}")
def ics_ip_profile(ip: str, request: Request, include_fp: bool = False):
    """Everything we know about one source IP — answers 'who was it?' and
    'are there related events with this IP?'. Aggregates + the IP's own events."""
    if not _ics_table_exists():
        return {"error": "ICS detection not configured"}
    ipc = strip_cidr(ip)
    conn = db()
    cur = conn.cursor()
    fp = "" if include_fp else " AND NOT false_positive"
    W = "WHERE src_ip = %s::inet" + fp

    def q(sql, one=False):
        cur.execute(sql, (ipc,))
        return cur.fetchone() if one else cur.fetchall()

    # headline counters
    s = q(
        f"""SELECT COUNT(*), MIN(timestamp), MAX(timestamp),
                 COUNT(*) FILTER (WHERE timestamp >= NOW()-INTERVAL '24 hours'),
                 COUNT(*) FILTER (WHERE timestamp >= NOW()-INTERVAL '1 hour'),
                 COUNT(*) FILTER (WHERE is_write OR is_control),
                 COUNT(*) FILTER (WHERE severity='CRITICAL'),
                 COUNT(DISTINCT dst_ip), COUNT(DISTINCT protocol)
              FROM ics_events {W}""",  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        one=True,
    )
    profile = dict(
        ip=ipc,
        total=s[0],
        first_seen=s[1].isoformat() if s[1] else None,
        last_seen=s[2].isoformat() if s[2] else None,
        last_24h=s[3],
        last_1h=s[4],
        writes_controls=s[5],
        critical=s[6],
        unique_targets=s[7],
        unique_protocols=s[8],
    )

    profile["intent"] = {
        r[0]: r[1]
        for r in q(f"SELECT {_INTENT_CASE} AS i, COUNT(*) FROM ics_events {W} GROUP BY i")  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    }
    profile["severity"] = {
        r[0]: r[1]
        for r in q(f"SELECT severity, COUNT(*) FROM ics_events {W} GROUP BY severity")  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    }
    profile["protocols"] = [
        dict(protocol=r[0], count=r[1])
        for r in q(
            f"SELECT protocol, COUNT(*) FROM ics_events {W} GROUP BY protocol ORDER BY 2 DESC"  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        )
    ]
    profile["targets"] = [
        dict(dst_ip=r[0], dst_port=r[1], count=r[2])
        for r in q(
            f"SELECT dst_ip::text, dst_port, COUNT(*) FROM ics_events {W} GROUP BY 1,2 ORDER BY 3 DESC LIMIT 25"  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        )
    ]
    profile["functions"] = [
        dict(protocol=r[0], function_name=r[1], count=r[2], max_severity=r[3])
        for r in q(
            f"SELECT protocol, function_name, COUNT(*), MAX(severity) FROM ics_events {W} GROUP BY 1,2 ORDER BY 3 DESC LIMIT 25"  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        )
    ]
    profile["timeline"] = [
        dict(day=str(r[0]), count=r[1])
        for r in q(
            f"SELECT timestamp::date, COUNT(*) FROM ics_events {W} AND timestamp >= NOW()-INTERVAL '30 days' GROUP BY 1 ORDER BY 1"  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        )
    ]

    # trusted? (best effort)
    try:
        t = q("SELECT bool_or(is_trusted) FROM ics_baselines WHERE src_ip = %s", one=True)
        profile["is_trusted"] = bool(t and t[0])
    except Exception:
        profile["is_trusted"] = False

    # the IP's own events (most recent)
    cur.execute(
        f"""SELECT event_id, timestamp, protocol, function_code, function_name,
                  src_ip::text, src_port, dst_ip::text, dst_port,
                  is_write, is_control, is_discovery,
                  mitre_technique, attack_type, rule_name, severity, acknowledged
               FROM ics_events {W} ORDER BY timestamp DESC LIMIT 200""",  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        (ipc,),
    )
    profile["events"] = [
        dict(
            event_id=r[0],
            timestamp=r[1].isoformat() if r[1] else None,
            protocol=r[2],
            function_code=r[3],
            function_name=r[4],
            src_ip=r[5],
            src_port=r[6],
            dst_ip=r[7],
            dst_port=r[8],
            is_write=r[9],
            is_control=r[10],
            is_discovery=r[11],
            mitre_technique=r[12],
            attack_type=r[13],
            rule_name=r[14],
            severity=r[15],
            acknowledged=r[16],
            intent=_derive_intent(r[13], r[10], r[9], r[11], r[15]),
        )
        for r in cur.fetchall()
    ]
    conn.close()
    return profile


@router.get("/ics/stats")
def ics_stats(request: Request, include_fp: bool = False):
    """ICS/OT CERT Dashboard — full event table + statistics.

    When include_fp is False (default) every aggregate/list query hides rows
    flagged false_positive (operator-cleared noise, e.g. the Ollama FP pattern).
    """
    if not _ics_table_exists():
        if wants_html(request):
            return HTMLResponse(content=_ics_not_configured_html())
        return {"error": "ICS detection not configured"}

    # FP gate fragments — appended to WHERE clauses unless include_fp=True.
    fp_where = "" if include_fp else " WHERE NOT false_positive"
    fp_and = "" if include_fp else " AND NOT false_positive"

    conn = db()
    cur = conn.cursor()

    # ── Summary counters ────────────────────────────────────────────────────
    # false_positives is the TRUE count over the whole table (ignores fp gate);
    # everything else respects the gate.
    cur.execute(_SUMMARY_SQL.format(fp_pred="" if include_fp else " AND NOT false_positive"))
    s = cur.fetchone()
    summary = dict(
        total=s[0],
        last_24h=s[1],
        last_1h=s[2],
        writes_controls=s[3],
        critical=s[4],
        high=s[5],
        medium=s[6],
        low=s[7],
        unacked=s[8],
        unique_src=s[9],
        unique_dst=s[10],
        false_positives=s[11],
    )

    # ── New sources in last 24h (first-ever event within 24h) ───────────────
    cur.execute("""
        SELECT COUNT(*) FROM (
            SELECT src_ip FROM ics_events
            GROUP BY src_ip HAVING MIN(timestamp) >= NOW()-INTERVAL '24 hours'
        ) t
    """)
    summary["new_src_24h"] = cur.fetchone()[0]

    # ── Intent funnel (full table, respects fp gate) ────────────────────────
    cur.execute(f"""
        SELECT attack_type, is_control, is_write, is_discovery, severity,
               COUNT(*)
        FROM ics_events{fp_where}
        GROUP BY 1,2,3,4,5
    """)  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    funnel = {"command": 0, "write": 0, "recon": 0, "enumeration": 0}
    for r in cur.fetchall():
        bucket = _derive_intent(r[0], r[1], r[2], r[3], r[4])
        funnel[bucket] += r[5]
    summary["intent_command"] = funnel["command"]
    summary["intent_write"] = funnel["write"]
    summary["intent_recon"] = funnel["recon"]
    summary["intent_enumeration"] = funnel["enumeration"]

    # ── By protocol ─────────────────────────────────────────────────────────
    cur.execute(f"""
        SELECT protocol,
               COUNT(*)                                                     AS total,
               COUNT(*) FILTER (WHERE is_write)                            AS writes,
               COUNT(*) FILTER (WHERE is_control)                          AS controls,
               COUNT(*) FILTER (WHERE is_discovery)                        AS discovery,
               COUNT(*) FILTER (WHERE severity IN ('CRITICAL','HIGH'))     AS high_sev,
               MAX(timestamp)                                               AS last_seen
        FROM ics_events{fp_where}
        GROUP BY protocol ORDER BY total DESC
    """)  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    by_protocol = [
        dict(
            protocol=r[0],
            total=r[1],
            writes=r[2],
            controls=r[3],
            discovery=r[4],
            high_sev=r[5],
            last_seen=r[6].isoformat() if r[6] else None,
        )
        for r in cur.fetchall()
    ]

    # ── By MITRE technique ──────────────────────────────────────────────────
    cur.execute(f"""
        SELECT mitre_technique, mitre_tactic, COUNT(*),
               COUNT(*) FILTER (WHERE severity IN ('CRITICAL','HIGH')),
               MAX(timestamp)
        FROM ics_events
        WHERE mitre_technique IS NOT NULL{fp_and}
        GROUP BY mitre_technique, mitre_tactic
        ORDER BY COUNT(*) DESC LIMIT 20
    """)  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    by_technique = [
        dict(
            technique=r[0],
            tactic=r[1],
            count=r[2],
            high_sev=r[3],
            last_seen=r[4].isoformat() if r[4] else None,
        )
        for r in cur.fetchall()
    ]

    # ── Top source IPs ───────────────────────────────────────────────────────
    cur.execute(f"""
        SELECT src_ip::text, COUNT(*),
               COUNT(*) FILTER (WHERE is_write OR is_control),
               COUNT(*) FILTER (WHERE severity = 'CRITICAL'),
               array_agg(DISTINCT protocol) FILTER (WHERE protocol IS NOT NULL)
        FROM ics_events WHERE src_ip IS NOT NULL{fp_and}
        GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 10
    """)  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    top_src = [
        dict(ip=r[0], total=r[1], writes_controls=r[2], critical=r[3], protocols=r[4] or [])
        for r in cur.fetchall()
    ]

    # ── Top targeted devices ────────────────────────────────────────────────
    cur.execute(f"""
        SELECT dst_ip::text, dst_port, COUNT(*),
               array_agg(DISTINCT protocol) FILTER (WHERE protocol IS NOT NULL),
               COUNT(*) FILTER (WHERE is_write OR is_control)
        FROM ics_events WHERE dst_ip IS NOT NULL{fp_and}
        GROUP BY dst_ip, dst_port ORDER BY COUNT(*) DESC LIMIT 10
    """)  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    top_dst = [
        dict(ip=r[0], port=r[1], total=r[2], protocols=r[3] or [], writes=r[4])
        for r in cur.fetchall()
    ]

    # ── Recent events (full detail, last 500) ───────────────────────────────
    cur.execute(f"""
        SELECT event_id, timestamp, protocol, function_code, function_name,
               src_ip::text, src_port, dst_ip::text, dst_port,
               unit_id, device_address, register_start, register_count, data_value,
               is_read, is_write, is_control, is_discovery, is_anomaly,
               mitre_tactic, mitre_technique, attack_type, rule_name,
               caldera_ability, caldera_tactic,
               severity, confidence, source, acknowledged, false_positive, notes,
               metadata
        FROM ics_events{fp_where}
        ORDER BY timestamp DESC LIMIT 500
    """)  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    cols = [
        "event_id",
        "timestamp",
        "protocol",
        "function_code",
        "function_name",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "unit_id",
        "device_address",
        "register_start",
        "register_count",
        "data_value",
        "is_read",
        "is_write",
        "is_control",
        "is_discovery",
        "is_anomaly",
        "mitre_tactic",
        "mitre_technique",
        "attack_type",
        "rule_name",
        "caldera_ability",
        "caldera_tactic",
        "severity",
        "confidence",
        "source",
        "acknowledged",
        "false_positive",
        "notes",
        "metadata",
    ]
    events = []
    for r in cur.fetchall():
        row = dict(zip(cols, r, strict=False))
        row["timestamp"] = row["timestamp"].isoformat() if row["timestamp"] else None
        row["intent"] = _derive_intent(
            row["attack_type"],
            row["is_control"],
            row["is_write"],
            row["is_discovery"],
            row["severity"],
        )
        events.append(row)

    # ── Function code breakdown (Modbus + S7comm) ────────────────────────────
    cur.execute(f"""
        SELECT protocol, function_code, function_name,
               COUNT(*) as total,
               COUNT(*) FILTER (WHERE is_write) as writes,
               COUNT(*) FILTER (WHERE is_control) as controls,
               COUNT(*) FILTER (WHERE is_read) as reads,
               COUNT(*) FILTER (WHERE is_discovery) as discovery,
               COUNT(DISTINCT src_ip) as unique_src,
               MAX(severity) as max_severity
        FROM ics_events
        WHERE function_code IS NOT NULL{fp_and}
        GROUP BY protocol, function_code, function_name
        ORDER BY protocol, total DESC
    """)  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    by_function = [
        dict(
            protocol=r[0],
            function_code=r[1],
            function_name=r[2],
            total=r[3],
            writes=r[4],
            controls=r[5],
            reads=r[6],
            discovery=r[7],
            unique_src=r[8],
            max_severity=r[9],
        )
        for r in cur.fetchall()
    ]

    # ── Write/Control operations (CRITICAL — safety-relevant) ──────────────
    cur.execute(f"""
        SELECT event_id, timestamp, protocol, function_code, function_name,
               src_ip::text, dst_ip::text, dst_port,
               unit_id, register_start, register_count, data_value,
               severity, mitre_technique, attack_type
        FROM ics_events
        WHERE (is_write OR is_control){fp_and}
        ORDER BY timestamp DESC LIMIT 50
    """)  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    write_ops = [
        dict(
            event_id=r[0],
            timestamp=r[1].isoformat() if r[1] else None,
            protocol=r[2],
            function_code=r[3],
            function_name=r[4],
            src_ip=r[5],
            dst_ip=r[6],
            dst_port=r[7],
            unit_id=r[8],
            register_start=r[9],
            register_count=r[10],
            data_value=r[11],
            severity=r[12],
            mitre_technique=r[13],
            attack_type=r[14],
        )
        for r in cur.fetchall()
    ]

    # ── Daily ICS event trend ──────────────────────────────────────────────
    cur.execute(f"""
        SELECT timestamp::date as day,
               COUNT(*) as total,
               COUNT(*) FILTER (WHERE is_write OR is_control) as write_ctrl,
               COUNT(*) FILTER (WHERE is_discovery) as discovery,
               COUNT(*) FILTER (WHERE severity IN ('CRITICAL','HIGH')) as high_sev
        FROM ics_events
        WHERE timestamp >= NOW() - INTERVAL '30 days'{fp_and}
        GROUP BY day ORDER BY day DESC
    """)  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    daily_trend = [
        dict(day=str(r[0]), total=r[1], write_ctrl=r[2], discovery=r[3], high_sev=r[4])
        for r in cur.fetchall()
    ]

    # ── Needs-attention queue (server-built triage list) ────────────────────
    # Newest unacked, non-FP, write/control or CRITICAL/HIGH events.
    cur.execute("""
        SELECT event_id, timestamp, protocol, function_name,
               attack_type, is_control, is_write, is_discovery, severity,
               src_ip::text, dst_ip::text, dst_port, mitre_technique
        FROM ics_events
        WHERE (is_write OR is_control OR severity IN ('CRITICAL','HIGH'))
          AND acknowledged = FALSE
          AND NOT false_positive
        ORDER BY timestamp DESC LIMIT 100
    """)
    needs_attention = []
    for r in cur.fetchall():
        needs_attention.append(
            dict(
                event_id=r[0],
                timestamp=r[1].isoformat() if r[1] else None,
                protocol=r[2],
                function_name=r[3],
                intent=_derive_intent(r[4], r[5], r[6], r[7], r[8]),
                severity=r[8],
                src_ip=r[9],
                dst_ip=r[10],
                dst_port=r[11],
                attack_type=r[4],
                mitre_technique=r[12],
            )
        )

    conn.close()

    result = dict(
        summary=summary,
        by_protocol=by_protocol,
        by_technique=by_technique,
        top_src=top_src,
        top_dst=top_dst,
        events=events,
        by_function=by_function,
        write_ops=write_ops,
        daily_trend=daily_trend,
        needs_attention=needs_attention,
    )

    # ICS vendor advisories (Idea 32 Phase D) — non-blocking with timeout
    try:
        from honeylens.intelligence.circl_enricher import _cache

        # Only use cached data — never block page render with live API calls
        cached = _cache.get("ics:advisories", 86400)  # 24h fallback TTL
        result["advisories"] = cached.get("advisories", []) if cached else []
    except Exception as e:
        logger.debug("ICS advisories fetch failed: %s", e)
        result["advisories"] = []

    if wants_html(request):
        return HTMLResponse(content=_ics_dashboard_html(result))
    return result


@router.get("/ics/event/{event_id}")
def ics_event_detail(event_id: str, request: Request):
    """Get full detail for a single ICS/OT event."""
    if not valid_event_id(event_id):
        raise HTTPException(status_code=400, detail="Invalid event_id format")
    if not _ics_table_exists():
        raise HTTPException(status_code=503, detail="ICS detection not configured")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            event_id, timestamp, protocol, function_code, function_name,
            src_ip::text, src_port, dst_ip::text, dst_port,
            unit_id, device_address, register_start, register_count, data_value,
            is_read, is_write, is_control, is_discovery, is_anomaly,
            mitre_tactic, mitre_technique, mitre_subtechnique,
            attack_type, rule_name,
            caldera_ability, caldera_tactic,
            severity, confidence, source,
            acknowledged, false_positive, notes,
            metadata, created_at
        FROM ics_events
        WHERE event_id = %s
    """,
        (event_id,),
    )
    row = cur.fetchone()

    # Also fetch the corresponding sensor_event for payload/JA3/scan_score
    cur.execute(
        """
        SELECT s.payload, s.payload_hash, s.scan_score, s.port_entropy, s.ja3, s.attack_types,
               j.fingerprint AS ja4
        FROM sensor_events s
        LEFT JOIN ja4_fingerprints j ON j.event_id = s.event_id
        WHERE s.event_id = %s
    """,
        (event_id,),
    )
    sensor_row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="ICS event not found")

    cols = [
        "event_id",
        "timestamp",
        "protocol",
        "function_code",
        "function_name",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "unit_id",
        "device_address",
        "register_start",
        "register_count",
        "data_value",
        "is_read",
        "is_write",
        "is_control",
        "is_discovery",
        "is_anomaly",
        "mitre_tactic",
        "mitre_technique",
        "mitre_subtechnique",
        "attack_type",
        "rule_name",
        "caldera_ability",
        "caldera_tactic",
        "severity",
        "confidence",
        "source",
        "acknowledged",
        "false_positive",
        "notes",
        "metadata",
        "created_at",
    ]
    result = dict(zip(cols, row, strict=False))
    result["timestamp"] = result["timestamp"].isoformat() if result["timestamp"] else None
    result["created_at"] = result["created_at"].isoformat() if result["created_at"] else None

    # Country for src_ip
    result["country_code"] = get_country_code(result["src_ip"]) if result["src_ip"] else "??"

    if sensor_row:
        result["payload"] = sensor_row[0]
        result["payload_hash"] = sensor_row[1]
        result["scan_score"] = sensor_row[2]
        result["entropy"] = sensor_row[3]
        result["ja3"] = sensor_row[4]
        result["attack_types"] = sensor_row[5]
        result["ja4"] = sensor_row[6]

    return result


@router.get("/ics/mitre-matrix")
def ics_mitre_matrix(request: Request):
    """Get MITRE ATT&CK for ICS coverage matrix."""
    if not _ics_table_exists():
        return {"error": "ICS detection not configured"}

    conn = db()
    cur = conn.cursor()

    # Get all detected techniques grouped by tactic
    cur.execute("""
        SELECT mitre_tactic, mitre_technique, COUNT(*),
               MAX(timestamp) as last_seen,
               COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') as last_24h
        FROM ics_events
        WHERE mitre_technique IS NOT NULL
        GROUP BY mitre_tactic, mitre_technique
        ORDER BY mitre_tactic, COUNT(*) DESC
    """)

    # Build matrix structure
    matrix: dict[str, Any] = {}
    for row in cur.fetchall():
        tactic = row[0] or "unknown"
        if tactic not in matrix:
            matrix[tactic] = []
        matrix[tactic].append(
            {
                "technique": row[1],
                "count": row[2],
                "last_seen": row[3].isoformat() if row[3] else None,
                "last_24h": row[4],
            }
        )

    conn.close()

    # Define ICS tactic order
    tactic_order = [
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "evasion",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "inhibit-response-function",
        "impair-process-control",
        "impact",
    ]

    # Sort by tactic order
    ordered_matrix = {}
    for tactic in tactic_order:
        if tactic in matrix:
            ordered_matrix[tactic] = matrix[tactic]
    # Add any remaining tactics
    for tactic in matrix:
        if tactic not in ordered_matrix:
            ordered_matrix[tactic] = matrix[tactic]

    result = {
        "matrix": ordered_matrix,
        "total_tactics": len(ordered_matrix),
        "total_techniques": sum(len(techs) for techs in ordered_matrix.values()),
    }

    if wants_html(request):
        return html_response("MITRE ATT&CK for ICS Matrix", result, request, "stats")
    return result


@router.get("/ics/baselines")
def ics_baselines(request: Request, limit: int = 100, trusted_only: bool = False):
    """Get ICS communication baselines."""
    if not _ics_table_exists():
        return {"error": "ICS detection not configured"}

    conn = db()
    cur = conn.cursor()

    query = """
        SELECT protocol, src_ip::text, dst_ip::text, dst_port,
               allowed_functions, typical_rate,
               is_hmi, is_engineering, is_trusted,
               first_seen, last_seen, request_count, anomaly_count
        FROM ics_baselines
    """
    if trusted_only:
        query += " WHERE is_trusted = TRUE"
    query += " ORDER BY request_count DESC LIMIT %s"

    cur.execute(query, (limit,))

    result = [
        {
            "protocol": r[0],
            "src_ip": r[1],
            "dst_ip": r[2],
            "dst_port": r[3],
            "allowed_functions": r[4],
            "typical_rate": r[5],
            "is_hmi": r[6],
            "is_engineering": r[7],
            "is_trusted": r[8],
            "first_seen": r[9].isoformat() if r[9] else None,
            "last_seen": r[10].isoformat() if r[10] else None,
            "request_count": r[11],
            "anomaly_count": r[12],
        }
        for r in cur.fetchall()
    ]

    conn.close()

    if wants_html(request):
        return html_response("ICS Baselines", result, request, "events")
    return {"baselines": result, "count": len(result)}


@router.post("/ics/baselines/trust")
def ics_trust_baseline(
    request: Request,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    is_hmi: bool = False,
    is_engineering: bool = False,
):
    """Mark an ICS communication pair as trusted. Admin only."""
    if request and not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    if not _ics_table_exists():
        raise HTTPException(status_code=400, detail="ICS detection not configured")

    conn = db()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE ics_baselines
        SET is_trusted = TRUE, is_hmi = %s, is_engineering = %s
        WHERE src_ip = %s AND dst_ip = %s AND protocol = %s
        RETURNING id
    """,
        (is_hmi, is_engineering, src_ip, dst_ip, protocol),
    )

    result = cur.fetchone()
    conn.commit()
    conn.close()

    if not result:
        raise HTTPException(status_code=404, detail="Baseline not found")

    return {"status": "trusted", "id": result[0]}


@router.get("/ics/summary")
def ics_summary(request: Request):
    """Get ICS/OT detection summary for dashboard."""
    if not _ics_table_exists():
        return {"enabled": False, "message": "ICS detection not configured"}

    conn = db()
    cur = conn.cursor()

    # Total events
    cur.execute("SELECT COUNT(*) FROM ics_events")
    total = cur.fetchone()[0]

    # Last 24 hours
    cur.execute("""
        SELECT COUNT(*) FROM ics_events
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
    """)
    last_24h = cur.fetchone()[0]

    # Critical events (writes/controls) last 24h
    cur.execute("""
        SELECT COUNT(*) FROM ics_events
        WHERE (is_write OR is_control)
          AND timestamp >= NOW() - INTERVAL '24 hours'
    """)
    critical_24h = cur.fetchone()[0]

    # Protocols seen
    cur.execute("""
        SELECT protocol, COUNT(*) FROM ics_events
        GROUP BY protocol ORDER BY COUNT(*) DESC LIMIT 5
    """)
    protocols = {r[0]: r[1] for r in cur.fetchall()}

    # Most recent event
    cur.execute("""
        SELECT timestamp, protocol, mitre_technique, severity, src_ip::text
        FROM ics_events
        ORDER BY timestamp DESC
        LIMIT 1
    """)
    recent = cur.fetchone()

    conn.close()

    result = {
        "enabled": True,
        "total_events": total,
        "last_24h": last_24h,
        "critical_24h": critical_24h,
        "protocols": protocols,
        "most_recent": {
            "timestamp": recent[0].isoformat() if recent else None,
            "protocol": recent[1] if recent else None,
            "mitre_technique": recent[2] if recent else None,
            "severity": recent[3] if recent else None,
            "src_ip": recent[4] if recent else None,
        }
        if recent
        else None,
    }

    if wants_html(request):
        return html_response("ICS/OT Summary", result, request, "stats")
    return result


@router.get("/llm/dashboard")
def llm_dashboard(request: Request):
    """LLM Honeypot Dashboard (Idea 37 Phase G)."""
    conn = db()
    cur = conn.cursor()

    result: dict[str, Any] = {
        "stats": {},
        "events": [],
        "sessions": [],
        "by_category": [],
        "by_actor": [],
        "honeytokens": [],
    }

    try:
        # Stats
        cur.execute("""
            SELECT COUNT(*) as total,
                   COUNT(DISTINCT src_ip) as unique_ips,
                   COUNT(DISTINCT session_id) as unique_sessions,
                   COUNT(*) FILTER (WHERE actor_type = 'LLM_AGENT') as agents,
                   COUNT(*) FILTER (WHERE response_strategy = 'deliberate_leak') as leaked,
                   COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical,
                   COUNT(*) FILTER (WHERE severity = 'HIGH') as high
            FROM llm_honeypot_events
        """)
        r = cur.fetchone()
        result["stats"] = {
            "total": r[0],
            "unique_ips": r[1],
            "unique_sessions": r[2],
            "agents_detected": r[3],
            "creds_leaked": r[4],
            "critical": r[5],
            "high": r[6],
        }

        # By category
        cur.execute("""
            SELECT attack_category, COUNT(*) as cnt
            FROM llm_honeypot_events
            GROUP BY attack_category ORDER BY cnt DESC
        """)
        result["by_category"] = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]

        # By actor type
        cur.execute("""
            SELECT COALESCE(actor_type, 'UNKNOWN') as actor_type, COUNT(*) as cnt
            FROM llm_honeypot_events
            GROUP BY actor_type ORDER BY cnt DESC
        """)
        result["by_actor"] = [{"actor_type": r[0], "count": r[1]} for r in cur.fetchall()]

        # Recent events
        cur.execute("""
            SELECT timestamp::text, attack_category, severity, actor_type,
                   host(src_ip), LEFT(user_message, 200), attack_rules,
                   confidence, response_strategy, session_id
            FROM llm_honeypot_events
            ORDER BY timestamp DESC LIMIT 50
        """)
        result["events"] = [
            {
                "timestamp": r[0],
                "attack_category": r[1],
                "severity": r[2],
                "actor_type": r[3],
                "src_ip": r[4],
                "user_message": r[5],
                "attack_rules": r[6] or [],
                "confidence": r[7],
                "response_strategy": r[8],
                "session_id": r[9],
            }
            for r in cur.fetchall()
        ]

        # Sessions summary
        cur.execute("""
            SELECT host(src_ip) as ip,
                   COUNT(*) as turns,
                   MAX(severity) as max_severity,
                   MAX(actor_type) as actor_type,
                   STRING_AGG(DISTINCT attack_category, ', ') as categories,
                   BOOL_OR(response_strategy = 'deliberate_leak') as has_leak,
                   MIN(timestamp)::text as first_seen,
                   MAX(timestamp)::text as last_seen
            FROM llm_honeypot_events
            GROUP BY src_ip
            ORDER BY turns DESC
        """)
        result["sessions"] = [
            {
                "src_ip": r[0],
                "turns": r[1],
                "max_severity": r[2],
                "actor_type": r[3] or "UNKNOWN",
                "top_categories": r[4],
                "has_leak": r[5],
                "first_seen": r[6],
                "last_seen": r[7],
            }
            for r in cur.fetchall()
        ]

        # Honeytokens leaked
        cur.execute("""
            SELECT host(src_ip) AS ip, session_id, timestamp::text,
                   LEFT(response_text, 200) AS response_preview,
                   attack_category, user_message
            FROM llm_honeypot_events
            WHERE response_strategy = 'deliberate_leak'
            ORDER BY timestamp DESC LIMIT 50
        """)
        result["honeytokens"] = [
            {
                "src_ip": r[0],
                "session_id": r[1],
                "timestamp": r[2],
                "response_preview": r[3],
                "attack_category": r[4],
                "user_message": r[5],
            }
            for r in cur.fetchall()
        ]

    except Exception as exc:
        logger.warning("LLM dashboard error: %s", exc)

    conn.close()

    if wants_html(request):
        from honeylens.webui.dashboard_llm import llm_dashboard_html

        return HTMLResponse(content=llm_dashboard_html(result))
    return result


@router.get("/llm/session/{session_key}")
def llm_session_replay(session_key: str, request: Request):
    """Replay a full LLM honeypot conversation by session_id or src_ip."""
    conn = db()
    cur = conn.cursor()
    try:
        # Try as session_id first, then as IP
        cur.execute(
            """
            SELECT event_id, timestamp::text, session_id, host(src_ip),
                   turn_number, user_message, response_text,
                   attack_category, attack_rules, severity, confidence,
                   actor_type, response_strategy, response_ms
            FROM llm_honeypot_events
            WHERE session_id = %s OR host(src_ip) = %s
            ORDER BY timestamp ASC
        """,
            (session_key, session_key),
        )
        cols = [
            "event_id",
            "timestamp",
            "session_id",
            "src_ip",
            "turn",
            "user_message",
            "response_text",
            "attack_category",
            "attack_rules",
            "severity",
            "confidence",
            "actor_type",
            "response_strategy",
            "response_ms",
        ]
        messages = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
        conn.close()
        result = {"session_key": session_key, "messages": messages, "total_turns": len(messages)}
        if wants_html(request):
            from honeylens.webui.dashboard_llm import llm_session_replay_html

            return HTMLResponse(content=llm_session_replay_html(result))
        return result
    except Exception as e:
        conn.close()
        return {"error": str(e), "messages": []}


@router.get("/llm/live")
def llm_live_feed(request: Request, since_id: int = 0):
    """Live feed of recent LLM honeypot events (for polling).
    Returns events newer than since_id."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT id, timestamp::text, attack_category, severity, actor_type,
                   host(src_ip), LEFT(user_message, 150), LEFT(response_text, 150),
                   response_strategy, session_id, confidence
            FROM llm_honeypot_events
            WHERE id > %s
            ORDER BY id DESC LIMIT 20
        """,
            (since_id,),
        )
        events = [
            {
                "id": r[0],
                "timestamp": r[1],
                "category": r[2],
                "severity": r[3],
                "actor_type": r[4],
                "src_ip": r[5],
                "user_message": r[6],
                "response_text": r[7],
                "response_strategy": r[8],
                "session_id": r[9],
                "confidence": r[10],
            }
            for r in cur.fetchall()
        ]
        max_id = max((e["id"] for e in events), default=since_id)
        conn.close()
        return {"events": events, "max_id": max_id, "count": len(events)}
    except Exception as e:
        conn.close()
        return {"events": [], "max_id": since_id, "error": str(e)}


@router.get("/cve/dashboard")
def cve_dashboard(request: Request):
    """CVE Intelligence Dashboard (Idea 32)."""
    conn = db()
    cur = conn.cursor()

    # Fetch all CVE intelligence
    cve_rows = []
    try:
        cur.execute("""
            SELECT cve_id, title, cvss_score, cvss_severity, is_kev,
                   times_seen, vendor, product,
                   first_seen_on_sensor, last_seen_on_sensor
            FROM cve_intelligence
            ORDER BY times_seen DESC, cvss_score DESC NULLS LAST
        """)
        cols = [d[0] for d in cur.description]
        for r in cur.fetchall():
            row = dict(zip(cols, r, strict=False))
            for k in ("first_seen_on_sensor", "last_seen_on_sensor"):
                if row.get(k):
                    row[k] = row[k].isoformat()
            cve_rows.append(row)
    except Exception as e:
        logger.debug("CVE intelligence query failed: %s", e)

    # AI enrichment stats
    ai_summary = {"total_enriched": 0, "pending": 0}
    try:
        cur.execute("SELECT COUNT(*) FROM ai_analysis WHERE cve_details IS NOT NULL")
        ai_summary["total_enriched"] = cur.fetchone()[0]
        cur.execute("""
            SELECT COUNT(*) FROM ai_analysis
            WHERE claude_cve IS NOT NULL AND claude_cve != '' AND claude_cve != 'None'
              AND cve_details IS NULL
        """)
        ai_summary["pending"] = cur.fetchone()[0]
    except Exception as e:
        logger.debug("AI enrichment stats query failed: %s", e)

    # KEV stats — cache_only on the request path so a cold cache cannot stall
    # the /cve/dashboard render (CIRCL pagination is ~3 minutes uncached).
    kev_stats = {}
    try:
        from honeylens.intelligence.circl_enricher import get_kev_list

        kev = get_kev_list(cache_only=True)
        kev_stats["total_kev"] = len(kev)
    except Exception as e:
        logger.debug("KEV list fetch failed: %s", e)
        kev_stats["total_kev"] = 0

    # CVE timeline: first_seen grouped by day (last 90 days)
    cve_timeline = []
    try:
        cur.execute("""
            SELECT first_seen_on_sensor::date AS day, COUNT(*) AS new_cves,
                   SUM(times_seen) AS total_hits
            FROM cve_intelligence
            WHERE first_seen_on_sensor >= NOW() - INTERVAL '90 days'
            GROUP BY day ORDER BY day
        """)
        cve_timeline = [
            {"day": str(r[0]), "new_cves": r[1], "total_hits": r[2]} for r in cur.fetchall()
        ]
    except Exception as e:
        logger.debug("CVE timeline query failed: %s", e)

    # CVE-to-attacker mapping: which IPs triggered which CVEs
    cve_attackers = []
    try:
        cur.execute("""
            SELECT ci.cve_id, ci.cvss_score, ci.cvss_severity, ci.is_kev,
                   host(se.src_ip) AS src_ip, COUNT(*) AS hits,
                   MAX(se.timestamp) AS last_seen
            FROM cve_intelligence ci
            JOIN attack_patterns ap ON ap.attack_type LIKE '%%' || REPLACE(ci.cve_id, '-', '_') || '%%'
                OR ap.matched_text LIKE '%%' || ci.cve_id || '%%'
            JOIN sensor_events se ON se.event_id = ap.event_id
            GROUP BY ci.cve_id, ci.cvss_score, ci.cvss_severity, ci.is_kev, host(se.src_ip)
            ORDER BY hits DESC
            LIMIT 100
        """)
        cve_attackers = [
            {
                "cve_id": r[0],
                "cvss_score": r[1],
                "cvss_severity": r[2],
                "is_kev": r[3],
                "src_ip": r[4],
                "hits": r[5],
                "last_seen": r[6].isoformat() if r[6] else None,
            }
            for r in cur.fetchall()
        ]
    except Exception as e:
        logger.debug("CVE-to-attacker mapping query failed: %s", e)

    conn.close()

    if wants_html(request):
        from honeylens.webui.dashboard_cve import cve_dashboard_html

        return HTMLResponse(
            content=cve_dashboard_html(
                cve_rows,
                ai_summary,
                kev_stats,
                cve_timeline=cve_timeline,
                cve_attackers=cve_attackers,
            )
        )
    return {
        "cves": cve_rows,
        "ai_summary": ai_summary,
        "kev_stats": kev_stats,
        "cve_timeline": cve_timeline,
        "cve_attackers": cve_attackers,
    }


@router.get("/cve/trending")
def cve_trending(request: Request, days: int = 30, limit: int = 20):
    """Trending CVEs detected on this sensor (Idea 32 Phase E)."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT cve_id, title, cvss_score, cvss_severity, is_kev,
                   times_seen, first_seen_on_sensor, last_seen_on_sensor
            FROM cve_intelligence
            WHERE last_seen_on_sensor >= NOW() - INTERVAL '%s days'
            ORDER BY times_seen DESC, cvss_score DESC NULLS LAST
            LIMIT %s
        """,
            (days, limit),
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
        for r in rows:
            for k in ("first_seen_on_sensor", "last_seen_on_sensor"):
                if r.get(k):
                    r[k] = r[k].isoformat()
    except Exception as e:
        logger.debug("CVE trending query failed: %s", e)
        rows = []
    finally:
        conn.close()

    result = {"trending": rows, "days": days}
    if wants_html(request):
        from honeylens.webui.shared import SHARED_CSS, nav_bar_html, sortable_table_js

        esc = html.escape
        trows = ""
        for r in rows:
            sev = str(r.get("cvss_severity") or "")
            sc = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#22c55e",
            }.get(sev, "#64748b")
            kev = (
                ' <span style="background:#ef4444;color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700">KEV</span>'
                if r.get("is_kev")
                else ""
            )
            cve_id = esc(str(r.get("cve_id", "")))
            trows += (
                f"<tr>"
                f'<td><a href="https://vulnerability.circl.lu/cve/{cve_id}" target="_blank" '
                f'style="color:#f87171;text-decoration:none">{cve_id}</a>{kev}</td>'
                f'<td style="color:{sc};font-weight:700">{r.get("cvss_score") or "—"}</td>'
                f'<td style="color:{sc}">{sev}</td>'
                f'<td style="text-align:center;font-weight:700">{r.get("times_seen", 0)}</td>'
                f'<td class="trunc" title="{esc(str(r.get("title") or ""))}">{esc(str(r.get("title") or "")[:80])}</td>'
                f'<td style="color:#64748b">{str(r.get("first_seen_on_sensor") or "")[:10]}</td>'
                f'<td style="color:#64748b">{str(r.get("last_seen_on_sensor") or "")[:10]}</td>'
                f"</tr>"
            )
        if not trows:
            trows = '<tr><td colspan="7" style="text-align:center;color:#64748b;padding:30px">No CVEs tracked yet. Run AI analysis to detect CVEs.</td></tr>'
        h = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Trending CVEs</title>
<style>{SHARED_CSS}</style></head><body>
{nav_bar_html("cve")}
<div class="page">
<h2 style="color:#f8fafc;margin-bottom:16px">Trending CVEs on Sensor <span style="color:#64748b;font-size:14px">(last {days} days)</span></h2>
<div style="overflow-x:auto">
<table style="width:100%;border-collapse:collapse;font-size:12px">
<thead><tr style="border-bottom:1px solid #334155;color:#64748b;font-size:10px;text-transform:uppercase">
<th style="padding:8px;text-align:left">CVE</th>
<th style="padding:8px">CVSS</th><th style="padding:8px">Severity</th>
<th style="padding:8px">Hits</th><th style="padding:8px;text-align:left">Title</th>
<th style="padding:8px">First Seen</th><th style="padding:8px">Last Seen</th>
</tr></thead><tbody>{trows}</tbody></table></div>
</div>
{sortable_table_js()}
</body></html>"""
        return HTMLResponse(content=h)
    return result


@router.get("/ics/advisories")
def ics_advisories():
    """Get ICS vendor advisories from CIRCL (Idea 32 Phase D)."""
    try:
        from honeylens.intelligence.circl_enricher import get_ics_advisories_cached

        return {"advisories": get_ics_advisories_cached()}
    except ImportError:
        return {"advisories": [], "error": "CIRCL enricher not available"}
    except Exception as e:
        return {"advisories": [], "error": str(e)}


# ---------------------------------------------------------------------------
# Operator triage API — ack / unack / false-positive / trust-source
# All admin-gated, all mutate ics_events. Match the file's error style.
# ---------------------------------------------------------------------------


def _require_admin(request: Request):
    if request and not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")


@router.post("/ics/triage/ack")
def ics_triage_ack(body: _EventIdsBody, request: Request):
    """Acknowledge a batch of ICS events. Admin only."""
    _require_admin(request)
    if not _ics_table_exists():
        raise HTTPException(status_code=400, detail="ICS detection not configured")
    if not body.event_ids:
        raise HTTPException(status_code=400, detail="event_ids must be non-empty")

    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE ics_events SET acknowledged = TRUE WHERE event_id = ANY(%s)", (body.event_ids,)
        )
        affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return {"status": "ok", "acknowledged": affected}


@router.post("/ics/triage/unack")
def ics_triage_unack(body: _EventIdsBody, request: Request):
    """Un-acknowledge (undo) a batch of ICS events. Admin only."""
    _require_admin(request)
    if not _ics_table_exists():
        raise HTTPException(status_code=400, detail="ICS detection not configured")
    if not body.event_ids:
        raise HTTPException(status_code=400, detail="event_ids must be non-empty")

    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE ics_events SET acknowledged = FALSE WHERE event_id = ANY(%s)", (body.event_ids,)
        )
        affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return {"status": "ok", "unacknowledged": affected}


@router.post("/ics/triage/false-positive")
def ics_triage_false_positive(body: _FalsePositiveBody, request: Request):
    """Mark events as false-positive (also acknowledges them). Admin only.

    Two modes: explicit event_ids, or a pattern (src_ip / protocol / dst_port).
    This is how the operator clears recurring noise like the Ollama FP pattern.
    """
    _require_admin(request)
    if not _ics_table_exists():
        raise HTTPException(status_code=400, detail="ICS detection not configured")

    has_pattern = any(v is not None for v in (body.src_ip, body.protocol, body.dst_port))
    if not body.event_ids and not has_pattern:
        raise HTTPException(
            status_code=400, detail="Provide event_ids or at least one of src_ip/protocol/dst_port"
        )

    set_clause = "false_positive = TRUE, acknowledged = TRUE"
    params: list[Any] = []
    if body.note is not None:
        set_clause += ", notes = %s"
        params.append(body.note)

    if body.event_ids:
        where = "event_id = ANY(%s)"
        params.append(body.event_ids)
    else:
        conds = []
        if body.src_ip is not None:
            conds.append("src_ip = %s::inet")
            params.append(body.src_ip)
        if body.protocol is not None:
            conds.append("protocol = %s")
            params.append(body.protocol)
        if body.dst_port is not None:
            conds.append("dst_port = %s")
            params.append(body.dst_port)
        where = " AND ".join(conds)

    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(f"UPDATE ics_events SET {set_clause} WHERE {where}", params)  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return {"status": "ok", "marked": affected}


@router.post("/ics/triage/false-positive/undo")
def ics_triage_false_positive_undo(body: _EventIdsBody, request: Request):
    """Restore events previously flagged false-positive. Admin only.

    Clears false_positive but leaves acknowledged untouched.
    """
    _require_admin(request)
    if not _ics_table_exists():
        raise HTTPException(status_code=400, detail="ICS detection not configured")
    if not body.event_ids:
        raise HTTPException(status_code=400, detail="event_ids must be non-empty")

    conn = db()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE ics_events SET false_positive = FALSE WHERE event_id = ANY(%s)",
            (body.event_ids,),
        )
        affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return {"status": "ok", "restored": affected}


@router.post("/ics/triage/trust-source")
def ics_triage_trust_source(body: _TrustSourceBody, request: Request):
    """Trust a source IP: acknowledge all its events and (best-effort) mark its
    communication pairs trusted in ics_baselines. Admin only."""
    _require_admin(request)
    if not _ics_table_exists():
        raise HTTPException(status_code=400, detail="ICS detection not configured")

    conn = db()
    try:
        cur = conn.cursor()
        # (1) Primary effect: acknowledge all events from this source.
        if body.protocol is not None:
            cur.execute(
                "UPDATE ics_events SET acknowledged = TRUE "
                "WHERE src_ip = %s::inet AND protocol = %s",
                (body.src_ip, body.protocol),
            )
        else:
            cur.execute(
                "UPDATE ics_events SET acknowledged = TRUE WHERE src_ip = %s::inet", (body.src_ip,)
            )
        affected = cur.rowcount

        # (2) Best-effort baseline trust upsert — never fail the endpoint on a
        # missing/empty ics_baselines.
        try:
            if body.protocol is not None:
                cur.execute(
                    "SELECT DISTINCT src_ip::text, dst_ip::text, protocol "
                    "FROM ics_events WHERE src_ip = %s::inet AND protocol = %s "
                    "AND dst_ip IS NOT NULL AND protocol IS NOT NULL",
                    (body.src_ip, body.protocol),
                )
            else:
                cur.execute(
                    "SELECT DISTINCT src_ip::text, dst_ip::text, protocol "
                    "FROM ics_events WHERE src_ip = %s::inet "
                    "AND dst_ip IS NOT NULL AND protocol IS NOT NULL",
                    (body.src_ip,),
                )
            pairs = cur.fetchall()
            for s_ip, d_ip, proto in pairs:
                cur.execute(
                    "UPDATE ics_baselines SET is_trusted = TRUE "
                    "WHERE src_ip = %s AND dst_ip = %s AND protocol = %s",
                    (s_ip, d_ip, proto),
                )
        except Exception as exc:
            logger.debug("trust-source baseline upsert skipped: %s", exc)
            conn.rollback()
            # Re-apply the primary ack effect after rollback.
            if body.protocol is not None:
                cur.execute(
                    "UPDATE ics_events SET acknowledged = TRUE "
                    "WHERE src_ip = %s::inet AND protocol = %s",
                    (body.src_ip, body.protocol),
                )
            else:
                cur.execute(
                    "UPDATE ics_events SET acknowledged = TRUE WHERE src_ip = %s::inet",
                    (body.src_ip,),
                )
            affected = cur.rowcount

        conn.commit()
    finally:
        conn.close()
    return {"status": "ok", "acknowledged": affected, "src_ip": body.src_ip}


# ---------------------------------------------------------------------------
