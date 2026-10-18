"""
routes/intelligence.py — Intelligence & Detection Routes
=========================================================
Extracted from api.py (Phase 1 refactor).
MiTM detection, Suricata IDS, MITRE ATT&CK, CVE, LLM honeypot.
"""

from __future__ import annotations

import html as html_module
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from honeylens.classification.mitre_mapping import (
    ATTACK_TO_MITRE,
    TACTICS,
    get_all_techniques,
    get_attack_types_for_technique,
    get_tactics_ordered,
    get_techniques_by_tactic,
)
from honeylens.geoip import get_country_code
from honeylens.intelligence.whitelist import get_whitelist_filter, is_whitelisted
from honeylens.routes._helpers import EXCLUDED_SUBNETS, db, html_response, wants_html


def _get_country(ip):
    if not ip:
        return "??"
    if is_whitelisted(ip):
        return "PIRATE"
    return get_country_code(ip)


# WebUI imports (lazy to avoid circular)
def _mitm_dashboard():
    from honeylens.webui.dashboard_mitm import MITM_DASHBOARD_HTML

    return MITM_DASHBOARD_HTML


def _suricata_dashboard(data):
    from honeylens.webui.dashboard_suricata import suricata_dashboard_html

    return suricata_dashboard_html(data)


logger = logging.getLogger("api")

router = APIRouter(tags=["Intelligence & Detection"])


@router.get("/mitm", response_class=HTMLResponse)
def mitm_dashboard():
    """MiTM Detection Dashboard."""
    return HTMLResponse(content=_mitm_dashboard())


def _mitm_table_exists() -> bool:
    """Check if mitm_events table exists."""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'mitm_events'
            )
        """)
        exists = cur.fetchone()[0]
        conn.close()
        return exists
    except Exception:
        return False  # silent: table existence check


@router.get("/mitm/events")
def mitm_events(
    request: Request,
    limit: int = 100,
    attack_type: str | None = None,
    severity: str | None = None,
    view: str | None = None,
):
    """Get recent MiTM detection events.

    By default excludes baseline (known-good) events; pass view=baseline to
    list only the baselined events.
    """
    if not _mitm_table_exists():
        return {"error": "MiTM detection not configured", "events": []}

    limit = min(max(limit, 1), 1000)

    conn = db()
    cur = conn.cursor()

    query = """
        SELECT event_id, timestamp, attack_type, severity, confidence,
               src_mac, dst_mac, src_ip::text, dst_ip::text, src_port, dst_port,
               original_mac, spoofed_mac,
               dns_query, dns_answer::text, expected_answer::text,
               interface, vlan_id, metadata, notes, acknowledged, false_positive,
               COALESCE(baseline, FALSE)
        FROM mitm_events
        WHERE 1=1
    """
    params: list[Any] = []

    if view == "baseline":
        query += " AND COALESCE(baseline, FALSE) = TRUE"
    else:
        query += " AND COALESCE(baseline, FALSE) = FALSE"
    if attack_type:
        query += " AND attack_type = %s"
        params.append(attack_type)
    if severity:
        query += " AND severity = %s"
        params.append(severity)

    query += " ORDER BY timestamp DESC LIMIT %s"
    params.append(limit)

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    result = [
        {
            "event_id": r[0],
            "timestamp": r[1].isoformat() if r[1] else None,
            "attack_type": r[2],
            "severity": r[3],
            "confidence": r[4],
            "src_mac": r[5],
            "dst_mac": r[6],
            "src_ip": r[7],
            "dst_ip": r[8],
            "src_port": r[9],
            "dst_port": r[10],
            "original_mac": r[11],
            "spoofed_mac": r[12],
            "dns_query": r[13],
            "dns_answer": r[14],
            "expected_answer": r[15],
            "interface": r[16],
            "vlan_id": r[17],
            "metadata": r[18],
            "notes": r[19],
            "acknowledged": r[20],
            "false_positive": r[21],
            "baseline": r[22],
        }
        for r in rows
    ]

    if wants_html(request):
        return html_response("MiTM Detection Events", result, request, "events")
    return result


@router.post("/mitm/acknowledge/{event_id}")
def mitm_acknowledge(event_id: str, request: Request):
    """Acknowledge a MiTM event. Admin only."""
    if request and not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    if not _mitm_table_exists():
        raise HTTPException(status_code=404, detail="MiTM detection not configured")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE mitm_events SET acknowledged = TRUE
        WHERE event_id = %s
        RETURNING event_id
    """,
        (event_id,),
    )
    result = cur.fetchone()
    conn.commit()
    conn.close()

    if not result:
        raise HTTPException(status_code=404, detail="Event not found")

    return {"status": "acknowledged", "event_id": event_id}


@router.post("/mitm/false_positive/{event_id}")
def mitm_false_positive(event_id: str, request: Request, notes: str | None = None):
    """Mark a MiTM event as false positive."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    if not _mitm_table_exists():
        raise HTTPException(status_code=404, detail="MiTM detection not configured")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE mitm_events
        SET false_positive = TRUE, acknowledged = TRUE, notes = %s
        WHERE event_id = %s
        RETURNING event_id
    """,
        (notes, event_id),
    )
    result = cur.fetchone()
    conn.commit()
    conn.close()

    if not result:
        raise HTTPException(status_code=404, detail="Event not found")

    return {"status": "marked_false_positive", "event_id": event_id}


@router.post("/mitm/baseline/{event_id}")
def mitm_add_baseline(event_id: str, request: Request):
    """Add an event's pattern (attack_type + src_ip) to the MiTM baseline.

    Baseline = operator-confirmed known-good. Matching current and future events
    are flagged baseline=TRUE: hidden from the main dashboard and excluded from
    alert counts, filed under the "baseline events" view. Admin only.
    """
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    if not _mitm_table_exists():
        raise HTTPException(status_code=404, detail="MiTM detection not configured")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT attack_type, src_ip::text FROM mitm_events WHERE event_id = %s", (event_id,)
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Event not found")
    attack_type, src_ip = row
    created_by = getattr(request.state, "username", None) if request else None
    cur.execute(
        """
        INSERT INTO mitm_baseline (attack_type, src_ip, note, created_by)
        VALUES (%s, %s, %s, %s) RETURNING id
    """,
        (attack_type, src_ip, f"baselined from event {event_id}", created_by),
    )
    rule_id = cur.fetchone()[0]
    cur.execute(
        """
        UPDATE mitm_events SET baseline = TRUE
        WHERE attack_type = %s AND src_ip = %s::inet
    """,
        (attack_type, src_ip),
    )
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return {
        "status": "baselined",
        "rule_id": rule_id,
        "attack_type": attack_type,
        "src_ip": src_ip,
        "events_suppressed": affected,
    }


@router.get("/mitm/baseline")
def mitm_list_baseline(request: Request):
    """List MiTM baseline (suppression) rules."""
    if not _mitm_table_exists():
        return {"rules": []}
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, attack_type, src_ip::text, src_mac::text, note, created_by, created_at
            FROM mitm_baseline ORDER BY created_at DESC
        """)
        rules = [
            {
                "id": r[0],
                "attack_type": r[1],
                "src_ip": r[2],
                "src_mac": r[3],
                "note": r[4],
                "created_by": r[5],
                "created_at": r[6].isoformat() if r[6] else None,
            }
            for r in cur.fetchall()
        ]
    except Exception:
        rules = []  # table not present yet
    conn.close()
    return {"rules": rules}


@router.delete("/mitm/baseline/{rule_id}")
def mitm_delete_baseline(rule_id: int, request: Request):
    """Remove a baseline rule and re-evaluate the events it covered. Admin only."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    if not _mitm_table_exists():
        raise HTTPException(status_code=404, detail="MiTM detection not configured")
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT attack_type, src_ip::text FROM mitm_baseline WHERE id = %s", (rule_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Rule not found")
    at, ip = row
    cur.execute("DELETE FROM mitm_baseline WHERE id = %s", (rule_id,))
    # Events covered by the deleted rule keep baseline=TRUE only if another rule
    # still matches them.
    cur.execute(
        """
        UPDATE mitm_events e SET baseline = EXISTS (
            SELECT 1 FROM mitm_baseline b
            WHERE (b.attack_type IS NULL OR b.attack_type = e.attack_type)
              AND (b.src_ip     IS NULL OR b.src_ip     = e.src_ip)
              AND (b.src_mac    IS NULL OR b.src_mac    = e.src_mac)
        )
        WHERE (%s IS NULL OR e.attack_type = %s)
          AND (%s IS NULL OR e.src_ip = %s::inet)
    """,
        (at, at, ip, ip),
    )
    reevaluated = cur.rowcount
    conn.commit()
    conn.close()
    return {"status": "deleted", "rule_id": rule_id, "events_reevaluated": reevaluated}


@router.get("/mitm/arp-cache")
def mitm_arp_cache(request: Request, limit: int = 500):
    """Get current ARP cache — DB table with /proc/net/arp fallback."""

    def _read_proc_arp() -> list:
        """Parse /proc/net/arp directly — always available on Linux."""
        entries = []
        try:
            with Path("/proc/net/arp").open() as fh:
                for line in fh.readlines()[1:]:  # skip header
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    ip, hw_type, flags, mac, _, iface = parts[:6]
                    if mac == "00:00:00:00:00:00":
                        continue
                    try:
                        flags_int = int(flags, 16)
                    except ValueError:
                        flags_int = 0
                    # flag 0x2 = complete/reachable, 0x0 = incomplete
                    entries.append(
                        {
                            "ip": ip,
                            "mac": mac,
                            "interface": iface,
                            "first_seen": None,
                            "last_seen": None,
                            "seen_count": 1,
                            "is_gateway": False,
                            "is_static": bool(flags_int & 0x4),  # ATF_PERM
                            "trust_score": 50,
                            "source": "proc",
                            "flags": flags,
                            "hw_type": hw_type,
                        }
                    )
        except Exception as ex:
            logger.warning("Could not read /proc/net/arp: %s", ex)
        return entries

    result = []
    source = "db"

    try:
        conn = db()
        cur = conn.cursor()

        # Check table exists
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'mitm_arp_cache'
            )
        """)
        table_exists = cur.fetchone()[0]

        if table_exists:
            cur.execute(
                """
                SELECT ip_address::text, mac_address::text, interface,
                       first_seen, last_seen, seen_count,
                       is_gateway, is_static, trust_score
                FROM mitm_arp_cache
                ORDER BY last_seen DESC NULLS LAST
                LIMIT %s
            """,
                (limit,),
            )
            rows = cur.fetchall()
        else:
            rows = []

        conn.close()

        if rows:
            result = [
                {
                    "ip": r[0],
                    "mac": r[1],
                    "interface": r[2],
                    "first_seen": r[3].isoformat() if r[3] else None,
                    "last_seen": r[4].isoformat() if r[4] else None,
                    "seen_count": r[5],
                    "is_gateway": r[6],
                    "is_static": r[7],
                    "trust_score": r[8],
                    "source": "db",
                }
                for r in rows
            ]
        else:
            # DB table empty or missing — fall back to /proc/net/arp
            result = _read_proc_arp()
            source = "proc"
            logger.info(
                "/mitm/arp-cache: DB empty, serving %d entries from /proc/net/arp", len(result)
            )

    except Exception as e:
        logger.error("Error fetching ARP cache from DB: %s — falling back to /proc", e)
        result = _read_proc_arp()
        source = "proc"

    if wants_html(request):
        return html_response(
            "MiTM ARP Cache",
            {"entries": result, "source": source, "count": len(result)},
            request,
            "events",
        )
    return result


@router.get("/mitm/summary")
def mitm_summary(request: Request):
    """Get MiTM detection summary for dashboard."""
    if not _mitm_table_exists():
        return {"enabled": False, "message": "MiTM detection not configured"}

    conn = db()
    cur = conn.cursor()

    # Total events
    cur.execute("SELECT COUNT(*) FROM mitm_events")
    total = cur.fetchone()[0]

    # Last 24 hours
    cur.execute("""
        SELECT COUNT(*) FROM mitm_events
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
    """)
    last_24h = cur.fetchone()[0]

    # Unacknowledged critical/high — excludes baselined (known-good) events.
    cur.execute("""
        SELECT COUNT(*) FROM mitm_events
        WHERE acknowledged = FALSE
          AND severity IN ('CRITICAL', 'HIGH')
          AND COALESCE(baseline, FALSE) = FALSE
    """)
    unacked_critical = cur.fetchone()[0]

    # Baselined (suppressed known-good) count
    try:
        cur.execute("SELECT COUNT(*) FROM mitm_events WHERE COALESCE(baseline, FALSE) = TRUE")
        baseline_count = cur.fetchone()[0]
    except Exception:
        baseline_count = 0

    # Most recent event
    cur.execute("""
        SELECT timestamp, attack_type, severity, src_ip::text
        FROM mitm_events
        ORDER BY timestamp DESC
        LIMIT 1
    """)
    recent = cur.fetchone()

    # By attack type
    cur.execute("""
        SELECT UPPER(attack_type) AS attack_type, COUNT(*),
               COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours')
        FROM mitm_events
        GROUP BY UPPER(attack_type)
        ORDER BY COUNT(*) DESC
    """)
    by_type = [{"type": r[0], "total": r[1], "last_24h": r[2]} for r in cur.fetchall()]

    # By severity
    cur.execute("""
        SELECT severity, COUNT(*)
        FROM mitm_events
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
            END
    """)
    by_severity = [{"severity": r[0], "count": r[1]} for r in cur.fetchall()]

    # Top offending MACs
    cur.execute("""
        SELECT src_mac, COUNT(*) as cnt
        FROM mitm_events
        WHERE src_mac IS NOT NULL
        GROUP BY src_mac
        ORDER BY cnt DESC
        LIMIT 10
    """)
    top_macs = [{"mac": r[0], "count": r[1]} for r in cur.fetchall()]

    conn.close()

    result = {
        "enabled": True,
        "total_events": total,
        "last_24h": last_24h,
        "unacked_critical_high": unacked_critical,
        "baseline_count": baseline_count,
        "most_recent": {
            "timestamp": recent[0].isoformat() if recent else None,
            "attack_type": recent[1] if recent else None,
            "severity": recent[2] if recent else None,
            "src_ip": recent[3] if recent else None,
        }
        if recent
        else None,
        "by_attack_type": by_type,
        "by_severity": by_severity,
        "top_offending_macs": top_macs,
    }

    if wants_html(request):
        return html_response("MiTM Summary", result, request, "stats")
    return result


# ---------------------------------------------------------------------------

# Routes — Suricata IDS Dashboard
# ---------------------------------------------------------------------------


@router.get("/suricata/stats")
def suricata_stats(request: Request):
    """Suricata IDS dashboard — alerts, top rules, hunting cross-reference."""
    conn = db()
    cur = conn.cursor()
    # These are read-only aggregate scans over sensor_events; on a large/un-pruned
    # table the COUNT(DISTINCT ...) can exceed the default 30s statement_timeout and
    # 500 the page. Lift the per-statement limit for this dashboard transaction.
    # (The partial covering index idx_se_suricata_stats keeps it fast in practice.)
    cur.execute("SET LOCAL statement_timeout = '120000'")

    # ── Summary KPIs ────────────────────────────────────────────────────────
    cur.execute("""
        SELECT
            COUNT(*)                                                        AS total,
            COUNT(*) FILTER (WHERE timestamp >= NOW()-INTERVAL '24 hours') AS last_24h,
            COUNT(*) FILTER (WHERE timestamp >= NOW()-INTERVAL '1 hour')   AS last_1h,
            COUNT(*) FILTER (WHERE timestamp >= NOW()-INTERVAL '5 minutes') AS last_5m,
            COUNT(DISTINCT suricata_sid)                                    AS unique_sids,
            COUNT(DISTINCT src_ip)                                         AS unique_src
        FROM sensor_events WHERE source = 'suricata'
    """)
    r = cur.fetchone()
    summary = dict(
        total=r[0],
        last_24h=r[1],
        last_1h=r[2],
        last_5m=r[3],
        unique_sids=r[4],
        unique_src=r[5],
        critical=0,
        high=0,
        medium=0,
        low=0,
        hunting_overlap=0,
    )

    # Severity counts from attack_patterns
    cur.execute("""
        SELECT severity, COUNT(*) FROM attack_patterns
        WHERE rule_name LIKE 'suricata_sid_%%'
        GROUP BY severity
    """)
    for sev, cnt in cur.fetchall():
        key = (sev or "").lower()
        if key in summary:
            summary[key] = cnt

    # ── Hunting overlap — IPs in attacker_profiles that also have Suricata events ──
    hunting_overlap_ips = []
    try:
        cur.execute("""
            SELECT host(ap.ip),
                   ap.ai_threat_level,
                   COUNT(se.event_id) AS suricata_events,
                   COUNT(DISTINCT se.suricata_sid) AS unique_sids,
                   (SELECT COUNT(*) FROM sensor_events se2
                    WHERE se2.src_ip = ap.ip AND se2.source != 'suricata') AS sensor_events,
                   MAX(se.timestamp) AS last_seen
            FROM attacker_profiles ap
            JOIN sensor_events se ON se.src_ip = ap.ip AND se.source = 'suricata'
            GROUP BY ap.ip, ap.ai_threat_level
            ORDER BY suricata_events DESC
            LIMIT 50
        """)
        for row in cur.fetchall():
            # Check if AI has analysed this IP
            ai_status = "PENDING"
            try:
                cur2 = conn.cursor()
                cur2.execute(
                    """
                    SELECT COUNT(*) FROM ai_analysis
                    WHERE event_id IN (
                        SELECT event_id FROM sensor_events
                        WHERE src_ip = %s::inet AND source != 'suricata'
                    )
                """,
                    (row[0],),
                )
                ai_cnt = cur2.fetchone()[0]
                ai_status = "ANALYSED" if ai_cnt > 0 else "NEEDS AI"
            except Exception as e:
                logger.debug("AI status check for hunting overlap: %s", e)
                conn.rollback()

            hunting_overlap_ips.append(
                dict(
                    ip=row[0],
                    threat_level=row[1] or "",
                    suricata_events=row[2],
                    unique_sids=row[3],
                    sensor_events=row[4],
                    last_seen=row[5].isoformat() if row[5] else "",
                    ai_status=ai_status,
                )
            )
        summary["hunting_overlap"] = len(hunting_overlap_ips)
    except Exception as e:
        logger.debug("Suricata hunting overlap: %s", e)
        try:
            conn.rollback()
        except Exception as e:
            logger.debug("rollback after hunting overlap error: %s", e)

    # ── Top rules ───────────────────────────────────────────────────────────
    cur.execute("""
        SELECT se.suricata_sid, se.suricata_signature,
               ap.severity, ap.attack_type,
               COUNT(*) AS hits,
               COUNT(DISTINCT se.src_ip) AS unique_ips,
               MAX(se.timestamp) AS last_seen
        FROM sensor_events se
        LEFT JOIN attack_patterns ap ON ap.event_id = se.event_id
            AND ap.rule_name = 'suricata_sid_' || se.suricata_sid::text
        WHERE se.source = 'suricata' AND se.suricata_sid IS NOT NULL
        GROUP BY se.suricata_sid, se.suricata_signature, ap.severity, ap.attack_type
        ORDER BY hits DESC LIMIT 30
    """)
    top_rules = [
        dict(
            sid=r[0],
            signature=r[1],
            severity=r[2] or "MEDIUM",
            attack_type=r[3] or "",
            hits=r[4],
            unique_ips=r[5],
            last_seen=r[6].isoformat() if r[6] else "",
        )
        for r in cur.fetchall()
    ]

    # ── By attack type ──────────────────────────────────────────────────────
    cur.execute("""
        SELECT ap.attack_type, COUNT(*),
               COUNT(DISTINCT se.src_ip), COUNT(DISTINCT se.suricata_sid),
               MAX(se.timestamp)
        FROM attack_patterns ap
        JOIN sensor_events se ON se.event_id = ap.event_id
        WHERE ap.rule_name LIKE 'suricata_sid_%%'
        GROUP BY ap.attack_type ORDER BY COUNT(*) DESC
    """)
    by_attack_type = [
        dict(
            attack_type=r[0],
            count=r[1],
            unique_ips=r[2],
            unique_sids=r[3],
            last_seen=r[4].isoformat() if r[4] else "",
        )
        for r in cur.fetchall()
    ]

    # ── Top source IPs ──────────────────────────────────────────────────────
    hunted_ips = set()
    try:
        cur.execute("SELECT host(ip) FROM attacker_profiles")
        hunted_ips = {r[0] for r in cur.fetchall()}
    except Exception as e:
        logger.debug("attacker_profiles lookup failed: %s", e)
        try:
            conn.rollback()
        except Exception as e2:
            logger.debug("rollback after attacker_profiles error: %s", e2)

    cur.execute("""
        SELECT host(src_ip), COUNT(*),
               COUNT(DISTINCT suricata_sid),
               MODE() WITHIN GROUP (ORDER BY attack_types),
               MAX(timestamp)
        FROM sensor_events WHERE source = 'suricata'
        GROUP BY host(src_ip) ORDER BY COUNT(*) DESC LIMIT 20
    """)
    top_sources = [
        dict(
            ip=r[0],
            hits=r[1],
            unique_sids=r[2],
            top_category=r[3] or "",
            last_seen=r[4].isoformat() if r[4] else "",
            is_hunted=r[0] in hunted_ips,
        )
        for r in cur.fetchall()
    ]

    # ── Timeline (14 days) ──────────────────────────────────────────────────
    cur.execute("""
        SELECT timestamp::date AS day, COUNT(*)
        FROM sensor_events WHERE source = 'suricata'
            AND timestamp >= NOW() - INTERVAL '14 days'
        GROUP BY day ORDER BY day
    """)
    timeline = [dict(date=r[0].isoformat(), count=r[1]) for r in cur.fetchall()]

    # ── By Suricata category ────────────────────────────────────────────────
    cur.execute("""
        SELECT attack_types, COUNT(*) FROM sensor_events
        WHERE source = 'suricata' AND attack_types IS NOT NULL
        GROUP BY attack_types ORDER BY COUNT(*) DESC LIMIT 15
    """)
    by_category = [dict(category=r[0], count=r[1]) for r in cur.fetchall()]

    # ── Recent 50 events (excluding whitelisted IPs) ────────────────────────
    wl_filter, wl_params = "", []
    try:
        wl_filter, wl_params = get_whitelist_filter("se.src_ip")
    except Exception as e:
        logger.debug("whitelist filter failed: %s", e)
    cur.execute(
        f"""
        SELECT se.event_id, se.timestamp, host(se.src_ip), se.src_port,
               se.dst_port, se.protocol, se.suricata_sid, se.suricata_signature,
               se.attack_types, se.payload
        FROM sensor_events se
        WHERE se.source = 'suricata'
          {wl_filter}
        ORDER BY se.timestamp DESC LIMIT 50
    """,  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        wl_params,
    )
    recent_events = []
    for r in cur.fetchall():
        src_ip = r[2] or ""
        # Parse CVE from payload JSON
        cve = ""
        try:
            pj = json.loads(r[9]) if r[9] else {}
            cve = pj.get("cve", "")
        except Exception as exc:  # optional JSON payload parsing
            logging.getLogger(__name__).debug("ignored: %s", exc)
        recent_events.append(
            dict(
                event_id=r[0],
                timestamp=r[1].isoformat() if r[1] else "",
                src_ip=src_ip,
                src_port=r[3],
                dst_port=r[4],
                protocol=r[5] or "",
                sid=r[6],
                signature=r[7] or "",
                attack_types=r[8] or "",
                cve=cve,
                country=_get_country(src_ip),
            )
        )

    data = dict(
        summary=summary,
        top_rules=top_rules,
        by_attack_type=by_attack_type,
        hunting_overlap_ips=hunting_overlap_ips,
        top_sources=top_sources,
        timeline=timeline,
        by_category=by_category,
        recent_events=recent_events,
    )

    if wants_html(request):
        return HTMLResponse(content=_suricata_dashboard(data))
    return data


# ---------------------------------------------------------------------------
# Routes — MITRE ATT&CK Mapping
# ---------------------------------------------------------------------------


@router.get("/mitre/matrix")
def mitre_matrix(request: Request, hours: int = 24):
    """
    Get MITRE ATT&CK matrix coverage based on detected events.

    Returns techniques detected in the time period, organized by tactic.
    """

    conn = db()
    cur = conn.cursor()

    # Get attack types from sensor_events
    cur.execute(
        """
        SELECT UPPER(attack_types) AS attack_types, COUNT(*) as count
        FROM sensor_events
        WHERE attack_types IS NOT NULL
          AND attack_types != ''
          AND timestamp >= NOW() - INTERVAL '%s hours'
        GROUP BY UPPER(attack_types)
    """,
        (hours,),
    )

    attack_counts: dict[str, Any] = {}
    for row in cur.fetchall():
        if row[0]:
            for attack_type in row[0].split(","):
                attack_type = attack_type.strip().upper()
                if attack_type:
                    attack_counts[attack_type] = attack_counts.get(attack_type, 0) + row[1]

    # Also get MiTM events
    try:
        cur.execute(
            """
            SELECT UPPER(attack_type) AS attack_type, COUNT(*)
            FROM mitm_events
            WHERE timestamp >= NOW() - INTERVAL '%s hours'
            GROUP BY UPPER(attack_type)
        """,
            (hours,),
        )

        for row in cur.fetchall():
            if row[0]:
                attack_counts[row[0].upper()] = attack_counts.get(row[0].upper(), 0) + row[1]
    except Exception as e:
        logger.debug("MiTM attack counts query failed: %s", e)  # silent: optional table

    conn.close()

    # Build matrix
    matrix: dict[str, Any] = {tactic: [] for tactic in TACTICS.keys()}
    technique_counts = {}

    for attack_type, count in attack_counts.items():
        mappings = ATTACK_TO_MITRE.get(attack_type, [])

        for m in mappings:
            tech_id = m["technique"]
            tactic = m["tactic"]

            # Skip ICS-specific tactics for enterprise matrix
            if tactic.endswith("-ics") or tactic in [
                "inhibit-response-function",
                "impair-process-control",
            ]:
                continue

            if tech_id not in technique_counts:
                technique_counts[tech_id] = {
                    "id": tech_id,
                    "name": m["name"],
                    "tactic": tactic,
                    "count": 0,
                    "attack_types": [],
                }

            technique_counts[tech_id]["count"] += count
            if attack_type not in technique_counts[tech_id]["attack_types"]:
                technique_counts[tech_id]["attack_types"].append(attack_type)

    # Organize by tactic
    for tech in technique_counts.values():
        tactic = tech["tactic"]
        if tactic in matrix:
            matrix[tactic].append(tech)

    # Sort techniques within each tactic by count
    for tactic in matrix:
        matrix[tactic].sort(key=lambda x: x["count"], reverse=True)

    result = {
        "period_hours": hours,
        "total_techniques": len(technique_counts),
        "total_events": sum(attack_counts.values()),
        "attack_types_seen": len(attack_counts),
        "matrix": matrix,
        "tactics_order": get_tactics_ordered(),
    }

    if wants_html(request):
        # Render full MITRE dashboard (Idea 10 — dedicated visualisation)
        try:
            # Create a fake request that returns JSON
            from starlette.requests import Request as _Req

            from honeylens.webui.dashboard_mitre import mitre_dashboard_html

            _fake_scope = {
                "type": "http",
                "method": "GET",
                "path": "/",
                "query_string": b"",
                "headers": [],
            }
            _fake_req = _Req(_fake_scope)
            coverage = mitre_coverage(request=_fake_req)
            tactics = mitre_tactics(request=_fake_req)
            atk_types = mitre_attack_types(request=_fake_req)
            return HTMLResponse(content=mitre_dashboard_html(result, coverage, tactics, atk_types))
        except Exception as exc:
            # Dashboard render failed (slow query, missing dependency, etc.).
            # Don't try to pass the nested `result` dict to the generic stats
            # renderer — its "matrix" key is a dict-of-list-of-dict which the
            # flat-stats template can't handle and produces a second 500.
            # Instead, return a minimal error page that links the operator to
            # the JSON view and the API endpoints they can inspect manually.
            logger.warning("MITRE dashboard render failed: %s", exc)
            err_html = f"""<!DOCTYPE html><html><head>
<title>MITRE ATT&amp;CK Matrix — degraded</title>
<style>
body {{ background:#0b1219; color:#cbd5e1; font-family:-apple-system,sans-serif;
       padding:30px; max-width:900px; margin:auto }}
h1 {{ color:#ef4444 }}
code {{ background:#111820; padding:2px 6px; border-radius:3px; color:#22d3ee }}
.box {{ background:#111820; border:1px solid #1e2a3a; border-radius:6px;
        padding:14px; margin:18px 0 }}
a {{ color:#22d3ee }}
</style></head><body>
<h1>MITRE ATT&amp;CK Matrix — temporarily degraded</h1>
<p>The full dashboard render failed. The underlying <code>attack_patterns</code>
table query exceeded the database statement timeout, or another dependency
failed to load.</p>
<div class="box">
<strong>Error:</strong><br><code>{html_module.escape(str(exc))[:500]}</code>
</div>
<p>Working endpoints you can use in the meantime:</p>
<ul>
  <li><a href="/mitre/matrix?format=json">/mitre/matrix?format=json</a> &mdash;
      raw matrix (no joined coverage)</li>
  <li><a href="/mitre/tactics">/mitre/tactics</a> &mdash; tactic-level rollup</li>
  <li><a href="/mitre/attack_types">/mitre/attack_types</a> &mdash; attack-type counts</li>
  <li><a href="/mitre/coverage">/mitre/coverage</a> &mdash; raw coverage JSON
      (will return degraded result if the DB scan times out)</li>
</ul>
<p>If this persists, check <code>journalctl -u sensor-api</code> for the
underlying SQL exception. Slow query on <code>attack_patterns</code> usually
means the table needs <code>VACUUM ANALYZE</code> or a row purge of old
forensic events.</p>
</body></html>"""
            return HTMLResponse(content=err_html, status_code=200)
    return result


@router.get("/mitre/technique/{technique_id}")
def mitre_technique_events(technique_id: str, request: Request, limit: int = 100):
    """
    Get events that map to a specific MITRE technique.
    """

    # Validate technique_id format
    if not technique_id.startswith("T") or len(technique_id) < 4:
        raise HTTPException(status_code=400, detail="Invalid technique ID format")

    # Find attack types that map to this technique
    matching_attack_types = get_attack_types_for_technique(technique_id)

    if not matching_attack_types:
        return {
            "technique_id": technique_id,
            "events": [],
            "message": f"No mapping found for {technique_id}",
        }

    limit = min(max(limit, 1), 1000)

    conn = db()
    cur = conn.cursor()

    # Build query with OR conditions for each attack type
    conditions = " OR ".join(["attack_types LIKE %s" for _ in matching_attack_types])
    params: list[Any] = [f"%{at}%" for at in matching_attack_types]
    # Technique drill-downs used to carry no subnet exclusion at all, unlike every other
    # event view — so this page showed the operator's own internal traffic. It shows up
    # worst on the behavioural techniques: T1110.001 (password guessing) is exactly what
    # internal monitoring and backup jobs look like to a honeypot.
    params.append(EXCLUDED_SUBNETS)
    params.append(limit)

    query = (
        """
        SELECT event_id, timestamp, source, protocol,
               src_ip::text, dst_port, attack_types
        FROM sensor_events
        WHERE ("""  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        + conditions
        + """)
          AND NOT (src_ip <<= ANY(%s::inet[]))
        ORDER BY timestamp DESC
        LIMIT %s
    """
    )
    cur.execute(query, params)

    # Column order leads with the two things the technique drill-down is for: the attacker
    # (src_ip) and the honeypot that caught it (source). The rest follow.
    events = [
        {
            "src_ip": r[4],
            "source": r[2],
            "protocol": r[3],
            "dst_port": r[5],
            "attack_types": r[6],
            "timestamp": r[1].isoformat() if r[1] else None,
            "event_id": r[0],
        }
        for r in cur.fetchall()
    ]

    conn.close()

    # Get technique name
    technique_name = None
    for attack_type in matching_attack_types:
        mappings = ATTACK_TO_MITRE.get(attack_type, [])
        for m in mappings:
            if m["technique"] == technique_id:
                technique_name = m["name"]
                break
        if technique_name:
            break

    result = {
        "technique_id": technique_id,
        "technique_name": technique_name,
        "matching_attack_types": matching_attack_types,
        "events": events,
        "count": len(events),
    }

    if wants_html(request):
        # Render the events themselves as the main table (attacker IP + honeypot + how), not a
        # generic stats dump of the result dict. The technique and totals go in a header banner.
        name = html_module.escape(technique_name or technique_id)
        types = html_module.escape(", ".join(matching_attack_types)) or "—"
        banner = (
            f'<div class="ep-hdr"><h2>{html_module.escape(technique_id)} &middot; {name}</h2>'
            f'<span class="ep-count">{len(events):,} events</span></div>'
            f'<div style="margin-bottom:14px;color:var(--text3);font-size:12px">'
            f"attacker IPs and the honeypots that caught them &middot; "
            f"matched attack types: {types}</div>"
        )
        return html_response(
            f"MITRE {technique_id}",
            events,
            request,
            "events",
            back_url="/mitre/matrix",
            extra_html_top=banner,
        )
    return result


@router.get("/mitre/coverage")
def mitre_coverage(request: Request):
    """
    Get overall MITRE ATT&CK detection coverage.

    Shows which techniques we CAN detect vs which we HAVE detected.
    """

    # All techniques we can detect
    all_techniques = get_all_techniques()

    # Get attack types we have actually detected.
    # attack_patterns has grown to 30 M+ rows on long-running sensors, so the
    # 14-day DISTINCT scan can outrun the default statement_timeout (30 s) even
    # with idx_ap_created_at + idx_ap_type_created in place. We do two things:
    #   1. SET LOCAL statement_timeout = 120 s for this transaction, so the
    #      query gets enough headroom to complete on cold caches.
    #   2. On failure, fall back to an empty detected set so the dashboard
    #      degrades gracefully instead of returning a 500 from upstream.
    conn = db()
    cur = conn.cursor()

    detected_attack_types = set()
    try:
        cur.execute("SET LOCAL statement_timeout = '120s'")
        cur.execute("""
            SELECT DISTINCT UPPER(attack_type) FROM attack_patterns
            WHERE created_at >= NOW() - INTERVAL '14 days'
        """)
        for row in cur.fetchall():
            if row[0]:
                detected_attack_types.add(row[0].strip())
    except Exception as exc:
        # statement_timeout / query cancelation / other DB error.
        # Log and return a degraded coverage view rather than a 500.
        logger.warning("mitre_coverage: attack_patterns scan failed: %s", exc)
        try:
            conn.rollback()
        except Exception as exc:
            logging.getLogger(__name__).debug("ignored: %s", exc)

    # Also check MiTM events
    try:
        cur.execute("""
            SELECT DISTINCT attack_type FROM mitm_events
            WHERE attack_type IS NOT NULL
        """)
        for row in cur.fetchall():
            if row[0]:
                detected_attack_types.add(row[0])
    except Exception as e:
        logger.debug("mitm_events attack types query failed: %s", e)  # silent: optional table

    conn.close()

    # Map detected attack types to techniques
    detected_techniques = set()
    for attack_type in detected_attack_types:
        mappings = ATTACK_TO_MITRE.get(attack_type, [])
        for m in mappings:
            detected_techniques.add(m["technique"])

    # Coverage by tactic
    tactic_coverage = {}
    for tactic, tactic_info in TACTICS.items():
        tactic_techniques = set()
        detected_in_tactic = set()

        for attack_type, mappings in ATTACK_TO_MITRE.items():
            for m in mappings:
                if m["tactic"] == tactic:
                    tactic_techniques.add(m["technique"])
                    if attack_type in detected_attack_types:
                        detected_in_tactic.add(m["technique"])

        if tactic_techniques:
            tactic_coverage[tactic] = {
                "name": tactic_info["name"],
                "total": len(tactic_techniques),
                "detected": len(detected_in_tactic),
                "coverage_pct": round(100 * len(detected_in_tactic) / len(tactic_techniques), 1),
                "techniques": list(tactic_techniques),
                "detected_techniques": list(detected_in_tactic),
                "color": tactic_info["color"],
            }

    result = {
        "total_techniques_monitored": len(all_techniques),
        "total_techniques_detected": len(detected_techniques),
        "overall_coverage_pct": round(100 * len(detected_techniques) / len(all_techniques), 1)
        if all_techniques
        else 0,
        "attack_types_detected": len(detected_attack_types),
        "by_tactic": tactic_coverage,
        "detected_techniques": list(detected_techniques),
        "undetected_techniques": list(all_techniques - detected_techniques),
    }

    if wants_html(request):
        # Flatten for HTML display
        flat_tactics = []
        for tactic, info in tactic_coverage.items():
            flat_tactics.append(
                {
                    "tactic": tactic,
                    "name": info["name"],
                    "total": info["total"],
                    "detected": info["detected"],
                    "coverage_pct": info["coverage_pct"],
                }
            )
        html_result = {
            "total_techniques_monitored": len(all_techniques),
            "total_techniques_detected": len(detected_techniques),
            "overall_coverage_pct": result["overall_coverage_pct"],
            "attack_types_detected": len(detected_attack_types),
            "coverage_by_tactic": flat_tactics,
        }
        return html_response("MITRE ATT&CK Coverage", html_result, request, "stats")
    return result


@router.get("/mitre/tactics")
def mitre_tactics(request: Request):
    """List all MITRE ATT&CK tactics with their techniques."""

    tactics = []
    for tactic in get_tactics_ordered():
        info = TACTICS[tactic]
        techniques = get_techniques_by_tactic(tactic)

        tactics.append(
            {
                "id": info["id"],
                "name": info["name"],
                "key": tactic,
                "color": info["color"],
                "technique_count": len(techniques),
                "techniques": techniques,
            }
        )

    if wants_html(request):
        # Flatten for HTML display
        flat_tactics = []
        for t in tactics:
            flat_tactics.append(
                {
                    "id": t["id"],
                    "name": t["name"],
                    "key": t["key"],
                    "technique_count": t["technique_count"],
                }
            )
        return html_response("MITRE ATT&CK Tactics", {"tactics": flat_tactics}, request, "stats")
    return {"tactics": tactics}


@router.get("/mitre/attack-types")
def mitre_attack_types(request: Request):
    """List all attack types and their MITRE mappings."""

    attack_types: list[dict[str, Any]] = []
    for attack_type, mappings in sorted(ATTACK_TO_MITRE.items()):
        attack_types.append(
            {
                "attack_type": attack_type,
                "techniques": [
                    {
                        "id": m["technique"],
                        "name": m["name"],
                        "tactic": m["tactic"],
                    }
                    for m in mappings
                ],
                "technique_count": len(mappings),
            }
        )

    if wants_html(request):
        # Flatten for HTML display
        flat_types = []
        for at in attack_types:
            techs = ", ".join([t["id"] for t in at["techniques"]])
            flat_types.append(
                {
                    "attack_type": at["attack_type"],
                    "techniques": techs,
                    "technique_count": at["technique_count"],
                }
            )
        return html_response(
            "Attack Types to MITRE", {"attack_types": flat_types}, request, "stats"
        )
    return {"attack_types": attack_types, "count": len(attack_types)}


@router.get("/mitre/navigator")
def mitre_navigator_export(hours: int = 24):
    """
    Export ATT&CK Navigator layer JSON.

    This can be imported into MITRE ATT&CK Navigator for visualization.
    """

    conn = db()
    cur = conn.cursor()

    # Get attack counts
    cur.execute(
        """
        SELECT UPPER(attack_types) AS attack_types, COUNT(*) as count
        FROM sensor_events
        WHERE attack_types IS NOT NULL
          AND attack_types != ''
          AND timestamp >= NOW() - INTERVAL '%s hours'
        GROUP BY UPPER(attack_types)
    """,
        (hours,),
    )

    attack_counts: dict[str, Any] = {}
    for row in cur.fetchall():
        if row[0]:
            for attack_type in row[0].split(","):
                attack_type = attack_type.strip().upper()
                if attack_type:
                    attack_counts[attack_type] = attack_counts.get(attack_type, 0) + row[1]

    conn.close()

    # Build technique scores
    technique_scores = {}
    for attack_type, count in attack_counts.items():
        mappings = ATTACK_TO_MITRE.get(attack_type, [])
        for m in mappings:
            tech_id = m["technique"]
            if tech_id not in technique_scores:
                technique_scores[tech_id] = 0
            technique_scores[tech_id] += count

    # Normalize scores (0-100)
    max_score = max(technique_scores.values()) if technique_scores else 1

    # Build Navigator layer
    techniques = []
    for tech_id, score in technique_scores.items():
        normalized = int(100 * score / max_score)
        techniques.append(
            {
                "techniqueID": tech_id,
                "score": normalized,
                "color": "",  # Let Navigator color by score
                "comment": f"Detected {score} times in last {hours}h",
                "enabled": True,
            }
        )

    layer = {
        "name": f"Sensor Detections ({hours}h)",
        "version": "4.5",
        "domain": "enterprise-attack",
        "description": f"Attack techniques detected by Hybrid Intelligence Sensor in the last {hours} hours",
        "filters": {"platforms": ["Linux", "Windows", "Network", "Containers"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
    }

    return layer


# ---------------------------------------------------------------------------
