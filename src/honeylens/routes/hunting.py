"""
routes/hunting.py — Attacker Hunting & Export Routes
=====================================================
Extracted from api.py (Phase 1 refactor).
Attacker profiling, hunting workflow, IP status, correlation, export.
"""

from __future__ import annotations

import html as html_module
import logging
from datetime import UTC, datetime
from typing import Any

import psycopg2.sql as psycopg2_sql
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

# is_known_scanner skips deep AI analysis on Censys / Shodan / etc. so the
# bulk-hunt and attacker_hunting_trigger paths don't burn Claude credits on
# research traffic. Soft-import like the other route modules — without this
# the bare reference at line 751 raises NameError on every "Hunt this IP"
# click and the endpoint 500s.
from honeylens.intelligence.scanner_exclusions import is_known_scanner
from honeylens.intelligence.whitelist import is_whitelisted
from honeylens.routes._helpers import (
    db,
    html_response,
    valid_ip,
    wants_html,
)

logger = logging.getLogger("api")

router = APIRouter(tags=["Attacker Hunting"])


# Lazy imports for webui modules
def _hunting_not_configured_html():
    from honeylens.webui.dashboard_hunting import _hunting_not_configured_html

    return _hunting_not_configured_html()


def _hunting_dashboard_html(*args, **kwargs):
    from honeylens.webui.dashboard_hunting import _hunting_dashboard_html as _fn

    return _fn(*args, **kwargs)


def _hunting_detail_html(profile):
    from honeylens.webui.dashboard_hunting import _hunting_detail_html

    return _hunting_detail_html(profile)


def _hunting_history_html(data):
    from honeylens.webui.dashboard_hunting import _hunting_history_html

    return _hunting_history_html(data)


def _hunting_map_html(status="ACTIVE", rng="24h"):
    from honeylens.webui.dashboard_hunting import _hunting_map_html

    return _hunting_map_html(status, rng)


def _clusters_html(data):
    from honeylens.webui.dashboard_hunting import _clusters_html

    return _clusters_html(data)


# ---------------------------------------------------------------------------
# Attacker Hunting — Idea 22 (Dashboard + REST + Start Hunt)
# ---------------------------------------------------------------------------


def _attacker_hunting_tables_exist() -> bool:
    """True only when ``attacker_profiles`` is genuinely absent-vs-present.

    This must distinguish "the table does not exist" (→ False → callers answer 503/"run
    setup_db") from "the existence check itself errored" (a dead/poisoned pooled connection, a
    pool-exhaustion blip, a statement timeout). The old version swallowed EVERY exception into
    ``False``, so a transient DB hiccup surfaced to the user as a permanent-looking
    "attacker_profiles table not found" on a table that has 800+ rows — and it never closed the
    connection on the error path, leaking it. Now: always release the connection, and let a real
    error propagate (honest 500) instead of masquerading as a missing table. ``to_regclass`` is
    schema-qualified and cheaper than scanning ``information_schema``."""
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT to_regclass('public.attacker_profiles') IS NOT NULL")
        return bool(cur.fetchone()[0])
    except Exception:
        logger.exception(
            "attacker_profiles existence check failed (transient — NOT a missing table)"
        )
        raise
    finally:
        conn.close()


@router.get("/attacker_hunting")
async def attacker_hunting_dashboard(
    request: Request,
    limit: int = 200,
    tag: str | None = None,
    threat: str | None = None,
    country: str | None = None,
    search: str | None = None,
):
    """Attacker Hunting dashboard — all profiled attacker IPs with Start Hunt button."""
    try:
        return await _attacker_hunting_dashboard_impl(request, limit, tag, threat, country, search)
    except Exception as e:
        logger.exception("Attacker Hunting dashboard error: %s", e)
        if wants_html(request):
            return HTMLResponse(
                f'<html><body style="background:#0f172a;color:#e2e8f0;font-family:monospace;padding:40px">'
                f'<h2 style="color:#ef4444">Attacker Hunting Error</h2>'
                f'<pre style="color:#f87171">{html_module.escape(str(e))}</pre>'
                f'<a href="/" style="color:#38bdf8">Back to Dashboard</a></body></html>',
                status_code=500,
            )
        raise HTTPException(status_code=500, detail=str(e)) from e


async def _attacker_hunting_dashboard_impl(
    request: Request,
    limit: int = 200,
    tag: str | None = None,
    threat: str | None = None,
    country: str | None = None,
    search: str | None = None,
):
    """Internal implementation of the hunting dashboard."""
    if not _attacker_hunting_tables_exist():
        if wants_html(request):
            return HTMLResponse(_hunting_not_configured_html())
        return {"error": "attacker_profiles table not found. Run: python setup_db.py"}

    conn = db()
    cur = conn.cursor()

    # Build WHERE clause
    conditions = []
    params = []

    if tag:
        conditions.append("%s = ANY(ap.internal_tags)")
        params.append(tag)
    if threat:
        conditions.append("ap.ai_threat_level = %s")
        params.append(threat.upper())
    if country:
        conditions.append("ap.country = %s")
        params.append(country.upper()[:2])
    if search:
        conditions.append(
            "(ap.ip::text LIKE %s OR ap.as_org ILIKE %s OR ap.hostname ILIKE %s OR "
            "EXISTS(SELECT 1 FROM unnest(ap.internal_tags) t WHERE t ILIKE %s) OR "
            "ap.apt_candidates::text ILIKE %s)"
        )
        s = f"%{search}%"
        params.extend([s, s, s, s, s])

    limit = min(limit, 2000)
    # Default: show only ACTIVE hunts (not FINISHED)
    conditions.append("(ap.hunt_status IS NULL OR ap.hunt_status = 'ACTIVE')")
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    try:
        cur.execute(
            psycopg2_sql.SQL("""
            SELECT host(ap.ip) AS ip, ap.first_seen,
                   COALESCE(
                       (SELECT MAX(se.timestamp) FROM sensor_events se
                        WHERE se.src_ip = ap.ip
                        AND se.timestamp >= NOW() - INTERVAL '14 days'),
                       ap.last_seen
                   ) AS last_seen,
                   ap.total_events, ap.total_attacks,
                   ap.attack_types, ap.abuse_score, ap.is_noise, ap.is_vpn,
                   ap.asn, ap.as_org, ap.country, ap.city, ap.hostname,
                   ap.open_ports, ap.os_guess,
                   ap.ai_summary, ap.ai_intent, ap.ai_threat_level, ap.ai_updated_at,
                   ap.mitre_techniques, ap.internal_tags, ap.apt_candidates,
                   ap.profile_version, ap.updated_at
            FROM attacker_profiles ap
            {}
            ORDER BY
                CASE ap.ai_threat_level
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3 ELSE 4
                END,
                ap.abuse_score DESC NULLS LAST,
                ap.total_events DESC
            LIMIT %s
        """).format(psycopg2_sql.SQL(where)),
            [*params, limit],
        )

        cols = [d[0] for d in cur.description]
        profiles = []
        for row in cur.fetchall():
            p = dict(zip(cols, row, strict=False))
            for k in ("first_seen", "last_seen", "ai_updated_at", "updated_at"):
                if p.get(k):
                    p[k] = p[k].isoformat()
            profiles.append(p)

        # Stats summary
        cur.execute("""
            SELECT
                COUNT(*) AS total_profiles,
                COUNT(*) FILTER (WHERE ai_threat_level = 'CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE ai_threat_level = 'HIGH') AS high,
                COUNT(*) FILTER (WHERE ai_threat_level = 'MEDIUM') AS medium,
                COUNT(*) FILTER (WHERE ai_threat_level = 'LOW') AS low,
                COUNT(*) FILTER (WHERE apt_candidates::text != '[]') AS with_apt,
                COUNT(*) FILTER (WHERE is_vpn = TRUE) AS vpn_count,
                COUNT(*) FILTER (WHERE is_noise = TRUE) AS noise_count
            FROM attacker_profiles
        """)
        sr = cur.fetchone()
        stats = dict(
            total=sr[0],
            critical=sr[1],
            high=sr[2],
            medium=sr[3],
            low=sr[4],
            with_apt=sr[5],
            vpn=sr[6],
            noise=sr[7],
        )

        # Top tags
        cur.execute("""
            SELECT t, COUNT(*) AS cnt
            FROM attacker_profiles, unnest(internal_tags) AS t
            GROUP BY t ORDER BY cnt DESC LIMIT 20
        """)
        top_tags = [{"tag": r[0], "count": r[1]} for r in cur.fetchall()]

        # Top countries
        cur.execute("""
            SELECT country, COUNT(*) AS cnt
            FROM attacker_profiles WHERE country IS NOT NULL AND country != ''
            GROUP BY country ORDER BY cnt DESC LIMIT 15
        """)
        top_countries = [{"country": r[0], "count": r[1]} for r in cur.fetchall()]

    except Exception as e:
        conn.close()
        logger.error("attacker_hunting_dashboard error: %s", e)
        if wants_html(request):
            return HTMLResponse("<h2>Error: An internal error occurred</h2>")
        return {"error": "An internal error occurred"}

    conn.close()
    result = dict(
        stats=stats,
        top_tags=top_tags,
        top_countries=top_countries,
        profiles=profiles,
        filters=dict(tag=tag, threat=threat, country=country, search=search),
    )

    if wants_html(request):
        return HTMLResponse(content=_hunting_dashboard_html(result))
    return result


@router.get("/attacker_hunting/stats")
async def attacker_hunting_stats():
    """Aggregate profiling statistics."""
    if not _attacker_hunting_tables_exist():
        return {"error": "attacker_profiles table not found"}

    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE ai_threat_level = 'CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE ai_threat_level = 'HIGH') AS high,
                COUNT(*) FILTER (WHERE ai_threat_level = 'MEDIUM') AS medium,
                COUNT(*) FILTER (WHERE ai_threat_level = 'LOW') AS low,
                AVG(abuse_score) FILTER (WHERE abuse_score IS NOT NULL) AS avg_abuse,
                COUNT(*) FILTER (WHERE apt_candidates::text != '[]') AS with_apt,
                SUM(total_events) AS total_events_tracked
            FROM attacker_profiles
        """)
        r = cur.fetchone()
        conn.close()
        return dict(
            total=r[0],
            critical=r[1],
            high=r[2],
            medium=r[3],
            low=r[4],
            avg_abuse_score=round(r[5], 1) if r[5] else 0,
            with_apt_attribution=r[6],
            total_events_tracked=r[7],
        )
    except Exception as e:
        logger.error("attacker_hunting_summary error: %s", e)
        conn.close()
        return {"error": "An internal error occurred"}


@router.get("/attacker_hunting/osint-status")
async def attacker_hunting_osint_status(request: Request):
    """OSINT provider health — success/rate-limited/error counts for last 7 days."""
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT provider,
                   COUNT(*) as total,
                   COUNT(*) FILTER (WHERE response_code = 200) as ok,
                   COUNT(*) FILTER (WHERE response_code = 429) as rate_limited,
                   COUNT(*) FILTER (WHERE response_code NOT IN (200, 429)) as errors,
                   MAX(queried_at) as last_query,
                   ROUND(100.0 * COUNT(*) FILTER (WHERE response_code = 200) / NULLIF(COUNT(*), 0), 1) as success_pct
            FROM attacker_osint_log
            WHERE queried_at >= NOW() - INTERVAL '7 days'
            GROUP BY provider ORDER BY total DESC
        """)
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
        for r in rows:
            if r.get("last_query"):
                r["last_query"] = r["last_query"].isoformat()
            # Status indicator
            pct = r.get("success_pct") or 0
            if pct >= 90:
                r["status"] = "healthy"
            elif pct >= 50:
                r["status"] = "degraded"
            elif r.get("total", 0) == 0:
                r["status"] = "inactive"
            else:
                r["status"] = "failing"
        conn.close()
        if wants_html(request):
            from honeylens.webui.shared import SHARED_CSS, nav_bar_html, sortable_table_js

            status_colors = {
                "healthy": "#22c55e",
                "degraded": "#eab308",
                "failing": "#ef4444",
                "inactive": "#64748b",
            }
            html = "<!DOCTYPE html><html><head><title>OSINT Status</title>"
            html += f"<style>{SHARED_CSS}</style></head><body>{nav_bar_html('hunting')}"
            html += '<div style="display:flex;gap:8px;padding:6px 22px;background:var(--bg2);border-bottom:1px solid var(--border);flex-wrap:wrap;">'
            html += '<a class="nav-btn" href="/attacker_hunting">Profiles</a>'
            html += '<a class="nav-btn" href="/attacker_hunting/osint-status" style="background:var(--accent);color:#000;border-color:var(--accent);">OSINT Status</a>'
            html += "</div>"
            # Known rate limits per provider (requests per day/minute)
            _rate_limits = {
                "abuseipdb": "1,000/day (free)",
                "virustotal": "500/day (free)",
                "shodan": "100/month (free)",
                "greynoise": "50/day (community)",
                "otx": "10,000/day",
                "urlhaus": "unlimited",
                "threatfox": "unlimited",
                "pulsedive": "30/day (free)",
                "ipqs": "200/day (free)",
                "censys": "250/month (free)",
                "circl": "120/min",
            }
            html += '<div style="padding:20px"><h2 style="color:#e2e8f0;margin-bottom:16px">OSINT Provider Health (7 days)</h2>'
            html += "<table><thead><tr><th>Provider</th><th>Status</th><th>Total</th><th>OK</th><th>Rate Limited</th><th>Errors</th><th>Success %</th><th>Rate Limit</th><th>Last Query</th></tr></thead><tbody>"
            for r in rows:
                sc = status_colors.get(r["status"], "#64748b")
                prov = r.get("provider", "")
                html += f'<tr><td style="font-weight:600">{html_module.escape(prov)}</td>'
                html += f'<td><span style="color:{sc};font-weight:700">{r["status"].upper()}</span></td>'
                html += f'<td>{r["total"]}</td><td style="color:#22c55e">{r["ok"]}</td>'
                rl = r["rate_limited"]
                html += f'<td style="color:{"#eab308" if rl else "#64748b"}">{rl}</td>'
                er = r["errors"]
                html += f'<td style="color:{"#ef4444" if er else "#64748b"}">{er}</td>'
                html += f'<td style="color:{sc}">{r.get("success_pct", 0)}%</td>'
                rl_info = _rate_limits.get(prov.lower(), "—")
                rl_color = "#eab308" if rl > 0 else "#64748b"
                html += f'<td style="color:{rl_color};font-size:10px">{html_module.escape(rl_info)}</td>'
                lq = (r.get("last_query") or "—")[:19].replace("T", " ")
                html += f'<td style="color:#64748b;font-size:11px">{lq}</td></tr>'
            html += "</tbody></table></div>"
            html += sortable_table_js()
            html += "</body></html>"
            return HTMLResponse(html)
        return {"providers": rows}
    except Exception as e:
        conn.close()
        return {"error": str(e)}


@router.post("/attacker_hunting/bulk-hunt")
async def attacker_hunting_bulk_hunt(request: Request):
    """Queue up to 50 IPs for OSINT + AI, durably, for the profiler worker."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON object")
    level = body.get("level")
    supplied = body.get("ips", [])
    if not isinstance(supplied, list) or len(supplied) > 50:
        raise HTTPException(status_code=400, detail="Provide at most 50 IP addresses")
    if level is not None and level not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        raise HTTPException(status_code=400, detail="Invalid threat level")
    if any(not isinstance(ip, str) or not valid_ip(ip) for ip in supplied):
        raise HTTPException(status_code=400, detail="Invalid IP address")

    from honeylens.analysis.hunt_queue import enqueue

    conn = db()
    try:
        ips = list(dict.fromkeys(supplied))
        if level:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT host(ip) FROM attacker_profiles
                       WHERE ai_threat_level = %s ORDER BY updated_at NULLS FIRST LIMIT 50""",
                    (level,),
                )
                ips = [r[0] for r in cur.fetchall()]
        eligible = [ip for ip in ips if not is_known_scanner(ip=ip) and not is_whitelisted(ip)]
        queued = enqueue(conn, eligible)
        return {
            "status": "queued",
            "hunted": queued,
            "queued": queued,
            "total_requested": len(ips),
            "skipped": len(ips) - queued,
        }
    except Exception:
        conn.rollback()
        logger.exception("Could not queue hunting requests")
        raise HTTPException(status_code=503, detail="Hunting queue unavailable") from None
    finally:
        conn.close()


@router.get("/attacker_hunting/ips")
async def attacker_hunting_ip_set():
    """Return set of all profiled IP addresses (lightweight, for dashboard badges)."""
    if not _attacker_hunting_tables_exist():
        return {"ips": []}
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT host(ip) FROM attacker_profiles")
        ips = [r[0] for r in cur.fetchall()]
        conn.close()
        return {"ips": ips}
    except Exception:
        conn.close()
        return {"ips": []}


@router.get("/ai/analyzed_ips")
async def ai_analyzed_ip_set(request: Request):
    """Return set of IPs that have AI-analyzed events + their best triage class."""
    conn = db()
    try:
        cur = conn.cursor()
        # For each src_ip, get the highest-severity AI triage class
        cur.execute("""
            SELECT host(se.src_ip) AS ip,
                   (array_agg(a.triage_class ORDER BY
                        CASE a.triage_class
                          WHEN 'CRITICAL'   THEN 1
                          WHEN 'SUSPICIOUS' THEN 2
                          WHEN 'KNOWN'      THEN 3
                          ELSE 4
                        END))[1] AS best_class
            FROM ai_analysis a
            JOIN sensor_events se ON se.event_id = a.event_id
            WHERE se.src_ip IS NOT NULL
              AND a.timestamp >= NOW() - INTERVAL '14 days'
            GROUP BY se.src_ip
        """)
        result = {r[0]: r[1] for r in cur.fetchall()}
        conn.close()
        if wants_html(request):
            ip_list = [{"ip": ip, "best_class": cls} for ip, cls in result.items()]
            return html_response("AI Analyzed IPs", ip_list, request, "auto")
        return {"ips": result}
    except Exception:
        conn.close()
        return {"ips": {}}


@router.get("/attacker_hunting/history")
async def attacker_hunting_history(request: Request, limit: int = 200):
    """Hunt History — shows all FINISHED hunting investigations."""
    if not _attacker_hunting_tables_exist():
        if wants_html(request):
            return HTMLResponse(_hunting_not_configured_html())
        return {"error": "attacker_profiles table not found"}

    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT host(ip) AS ip, first_seen, last_seen, total_events, total_attacks,
                   abuse_score, country, as_org, ai_threat_level, ai_intent,
                   internal_tags, mitre_techniques, claude_verdict,
                   finished_at, finish_notes, profile_version, updated_at
            FROM attacker_profiles
            WHERE hunt_status = 'FINISHED'
            ORDER BY finished_at DESC NULLS LAST
            LIMIT %s
        """,
            (min(limit, 2000),),
        )
        cols = [d[0] for d in cur.description]
        profiles = []
        for row in cur.fetchall():
            p = dict(zip(cols, row, strict=False))
            for k in ("first_seen", "last_seen", "finished_at", "updated_at"):
                if p.get(k):
                    p[k] = p[k].isoformat()
            profiles.append(p)
        conn.close()

        if wants_html(request):
            return HTMLResponse(_hunting_history_html(profiles))
        return {"count": len(profiles), "profiles": profiles}
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e)[:200]) from e


@router.get("/attacker_hunting/map")
async def attacker_hunting_map(request: Request, status: str = "ACTIVE", range: str = "24h"):
    """SOC console attacker map — HTML shell; JSON returns the console dataset."""
    if not _attacker_hunting_tables_exist():
        if wants_html(request):
            return HTMLResponse(_hunting_not_configured_html())
        return {"error": "attacker_profiles table not found"}

    if wants_html(request):
        return HTMLResponse(_hunting_map_html(status, range))

    conn = db()
    cur = conn.cursor()
    try:
        # Check which optional columns exist
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'attacker_profiles'
              AND column_name IN ('hunt_status', 'claude_verdict')
        """)
        existing_cols = {r[0] for r in cur.fetchall()}
        has_hunt = "hunt_status" in existing_cols
        has_claude = "claude_verdict" in existing_cols

        # Build status filter
        if has_hunt:
            if status == "FINISHED":
                status_filter = "AND hunt_status = 'FINISHED'"
            elif status == "ALL":
                status_filter = ""
            else:
                status_filter = "AND (hunt_status IS NULL OR hunt_status = 'ACTIVE')"
        else:
            status_filter = ""  # No hunt_status column — show all

        claude_col = "claude_verdict," if has_claude else "NULL AS claude_verdict,"
        hunt_col = "hunt_status" if has_hunt else "NULL AS hunt_status"

        cur.execute(
            f"""
            SELECT host(ip) AS ip, country, city, as_org, abuse_score,
                   ai_threat_level, ai_intent, total_events, total_attacks,
                   internal_tags, {claude_col} {hunt_col}
            FROM attacker_profiles
            WHERE country IS NOT NULL AND country != '' {status_filter}
            ORDER BY
                CASE ai_threat_level
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3 ELSE 4
                END,
                abuse_score DESC NULLS LAST
            LIMIT 500
        """  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        )
        cols = [d[0] for d in cur.description]
        attackers = [dict(zip(cols, row, strict=False)) for row in cur.fetchall()]

        # Enrich with real geolocation (lat/lon) for precise map placement
        try:
            from honeylens.geoip import lookup_ip

            for a in attackers:
                geo = lookup_ip(a.get("ip", ""))
                if geo:
                    a["lat"] = geo.get("latitude")
                    a["lon"] = geo.get("longitude")
        except Exception as e:
            logger.debug("geo lookup enrichment failed: %s", e)

        cur.execute(
            f"""
            SELECT COUNT(*), COUNT(DISTINCT country)
            FROM attacker_profiles
            WHERE country IS NOT NULL AND country != '' {status_filter}
        """  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        )
        total, countries = cur.fetchone()
        conn.close()

        return {"total": total, "countries": countries, "attackers": attackers}
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e)[:200]) from e


# ---------------------------------------------------------------------------
# SOC console data + live feed endpoints
# ---------------------------------------------------------------------------

_RANGE_SQL = {"1h": "1 hour", "24h": "24 hours", "7d": "7 days", "30d": "30 days"}
_RANGE_LBL = {
    "1h": "last 1h",
    "24h": "last 24h",
    "7d": "last 7d",
    "30d": "last 30d",
    "all": "all time",
}


def _soc_profile_cols(cur):
    cur.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'attacker_profiles'
          AND column_name IN ('hunt_status','ai_intent','internal_tags','ai_threat_level',
                              'abuse_score','as_org','asn','country','city')
    """)
    return {r[0] for r in cur.fetchall()}


def _soc_filters(cols, rng, severity, status, country, asn, q):
    """Build shared WHERE clause + params for the window/filters."""
    where: list[Any] = []
    params: list[Any] = []
    iv = _RANGE_SQL.get(rng)
    if iv:
        where.append("se.timestamp >= NOW() - %s::interval")
        params.append(iv)
    if severity and "ai_threat_level" in cols:
        where.append("ap.ai_threat_level = %s")
        params.append(severity.upper()[:12])
    if country and "country" in cols:
        where.append("ap.country = %s")
        params.append(country.upper()[:2])
    if asn and "asn" in cols:
        try:
            where.append("ap.asn = %s")
            params.append(int(str(asn).upper().replace("AS", "").strip()))
        except (ValueError, TypeError):
            where.pop()  # asn not numeric — skip
    if q:
        where.append("(host(se.src_ip) ILIKE %s OR ap.as_org ILIKE %s OR ap.country ILIKE %s)")
        like = "%" + q[:60] + "%"
        params += [like, like, like]
    if "hunt_status" in cols and status and status.upper() != "ALL":
        if status.upper() == "FINISHED":
            where.append("ap.hunt_status = 'FINISHED'")
        else:
            where.append("(ap.hunt_status IS NULL OR ap.hunt_status = 'ACTIVE')")
    return (" AND " + " AND ".join(where)) if where else "", params


def _soc_map_data(conn, rng, severity, status, country, asn, q):
    from collections import Counter

    cur = conn.cursor()
    cur.execute("SET statement_timeout = '20000'")
    cols = _soc_profile_cols(cur)
    wsql, params = _soc_filters(cols, rng, severity, status, country, asn, q)

    intent_sel = "ap.ai_intent" if "ai_intent" in cols else "NULL AS ai_intent"
    tags_sel = "ap.internal_tags" if "internal_tags" in cols else "NULL AS internal_tags"
    grp = [
        "host(se.src_ip)",
        "ap.country",
        "ap.city",
        "ap.asn",
        "ap.as_org",
        "ap.abuse_score",
        "ap.ai_threat_level",
    ]
    if "ai_intent" in cols:
        grp.append("ap.ai_intent")
    if "internal_tags" in cols:
        grp.append("ap.internal_tags")

    sql = """
        SELECT host(se.src_ip) AS ip, COUNT(*) AS events, MAX(se.timestamp) AS last_seen,
               ap.country, ap.city, ap.asn, ap.as_org, ap.abuse_score, ap.ai_threat_level,
               {}, {}
        FROM sensor_events se
        LEFT JOIN attacker_profiles ap ON ap.ip = se.src_ip
        WHERE TRUE {}
        GROUP BY {}
        ORDER BY CASE ap.ai_threat_level WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
                 ap.abuse_score DESC NULLS LAST, events DESC
        LIMIT 500
    """.format(intent_sel, tags_sel, wsql, ", ".join(grp))  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    cur.execute(sql, params)
    rows = [dict(zip([d[0] for d in cur.description], r, strict=False)) for r in cur.fetchall()]

    # KPI totals over the full window (not capped)
    cur.execute(
        f"""
        SELECT COUNT(DISTINCT se.src_ip), COUNT(*)
        FROM sensor_events se
        LEFT JOIN attacker_profiles ap ON ap.ip = se.src_ip
        WHERE TRUE {wsql}
    """,  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        params,
    )
    kpi_attackers, kpi_events = cur.fetchone()

    from honeylens.geoip import lookup_ip

    countries: Counter[str] = Counter()
    asns: dict[str, Any] = {}
    sevs: Counter[str] = Counter()
    intents: Counter[str] = Counter()
    crit_high = 0
    attackers = []
    for r in rows:
        ip = r["ip"]
        geo = {}
        try:
            geo = lookup_ip(ip) or {}
        except Exception as exc:
            logging.getLogger(__name__).debug("ignored: %s", exc)
        cc = (r.get("country") or geo.get("country_code") or "").upper()
        if cc in ("??", "LAN", "PIRATE"):
            cc = r.get("country") or ""
        thr = r.get("ai_threat_level") or "UNKNOWN"
        if thr in ("CRITICAL", "HIGH"):
            crit_high += 1
        tags = r.get("internal_tags") or []
        attackers.append(
            {
                "ip": ip,
                "events": r.get("events") or 0,
                "last_seen": r["last_seen"].isoformat() if r.get("last_seen") else "",
                "country": cc,
                "city": r.get("city") or geo.get("city") or "",
                "asn": r.get("asn"),
                "as_org": r.get("as_org") or "",
                "abuse_score": r.get("abuse_score") or 0,
                "ai_threat_level": thr,
                "ai_intent": r.get("ai_intent") or "",
                "tags": list(tags)[:5],
                "lat": geo.get("latitude"),
                "lon": geo.get("longitude"),
            }
        )
        if cc:
            countries[cc] += 1
        if r.get("asn"):
            k = r["asn"]
            asns.setdefault(k, {"asn": k, "org": r.get("as_org") or "", "count": 0})
            asns[k]["count"] += 1
        sevs[thr] += 1
        if r.get("ai_intent"):
            intents[r["ai_intent"]] += 1

    return {
        "window": _RANGE_LBL.get(rng, rng),
        "kpis": {
            "attackers": kpi_attackers or 0,
            "events": kpi_events or 0,
            "countries": len(countries),
            "crit_high": crit_high,
        },
        "attackers": attackers,
        "top_countries": [{"country": c, "count": n} for c, n in countries.most_common(10)],
        "top_asns": sorted(asns.values(), key=lambda x: x["count"], reverse=True)[:10],
        "severity": [
            {"level": lv, "count": sevs[lv]}
            for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
            if sevs.get(lv)
        ],
        "intents": [{"intent": i, "count": n} for i, n in intents.most_common(6)],
    }


@router.get("/attacker_hunting/map/data")
async def attacker_hunting_map_data(
    request: Request,
    range: str = "24h",
    severity: str = "",
    status: str = "ACTIVE",
    country: str = "",
    asn: str = "",
    q: str = "",
):
    """JSON dataset powering the SOC console (map + panels + table)."""
    if not _attacker_hunting_tables_exist():
        return {"error": "attacker_profiles table not found"}
    conn = db()
    try:
        return _soc_map_data(conn, range, severity, status, country, asn, q)
    except Exception as e:
        return {"error": str(e)[:200], "attackers": [], "kpis": {}}
    finally:
        conn.close()


@router.get("/attacker_hunting/map/feed")
async def attacker_hunting_map_feed(
    request: Request,
    range: str = "24h",
    severity: str = "",
    status: str = "ACTIVE",
    country: str = "",
    asn: str = "",
    q: str = "",
    since: str = "",
):
    """Newest attacker hits for the live feed ticker."""
    if not _attacker_hunting_tables_exist():
        return {"feed": []}
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("SET statement_timeout = '10000'")
        cols = _soc_profile_cols(cur)
        # feed always looks at a short recent window regardless of range
        wsql, params = _soc_filters(cols, "1h", severity, status, country, asn, q)
        if since:
            wsql += " AND se.timestamp > %s"
            params.append(since)
        thr_sel = "ap.ai_threat_level" if "ai_threat_level" in cols else "NULL AS ai_threat_level"
        sql = f"""
            SELECT se.timestamp, host(se.src_ip) AS ip, se.dst_port, ap.country, {thr_sel}
            FROM sensor_events se
            LEFT JOIN attacker_profiles ap ON ap.ip = se.src_ip
            WHERE TRUE {wsql}
            ORDER BY se.timestamp DESC
            LIMIT 40
        """  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        cur.execute(sql, params)
        rows = cur.fetchall()
        from honeylens.geoip import get_country_code

        feed = []
        for ts, ip, dport, country_v, thr in rows:
            cc = country_v
            if not cc:
                try:
                    cc = get_country_code(ip)
                except Exception:
                    cc = ""
            feed.append(
                {
                    "ts": ts.isoformat() if ts else "",
                    "ip": ip,
                    "dst_port": dport,
                    "country": cc if cc not in ("??", "LAN") else "",
                    "threat": thr or "UNKNOWN",
                }
            )
        return {"feed": feed}
    except Exception as e:
        return {"feed": [], "error": str(e)[:200]}
    finally:
        conn.close()


@router.get("/attacker_hunting/clusters")
async def attacker_clusters_api(request: Request, limit: int = 100):
    """List all fingerprint clusters."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT EXISTS (SELECT 1 FROM information_schema.tables
                           WHERE table_name = 'fingerprint_clusters')
        """)
        if not cur.fetchone()[0]:
            conn.close()
            if wants_html(request):
                return HTMLResponse(_clusters_html({"clusters": [], "total": 0}))
            return {"error": "fingerprint_clusters table not found"}

        cur.execute(
            """
            SELECT cluster_tag, fingerprint_type, fingerprint_value,
                   ip_count, confidence, ips, first_seen, last_seen
            FROM fingerprint_clusters
            ORDER BY confidence DESC, ip_count DESC
            LIMIT %s
        """,
            (min(limit, 500),),
        )
        clusters = []
        for r in cur.fetchall():
            clusters.append(
                {
                    "tag": r[0],
                    "type": r[1],
                    "value": r[2][:80],
                    "ip_count": r[3],
                    "confidence": r[4],
                    "ips": [str(i) for i in (r[5] or [])],
                    "first_seen": r[6].isoformat() if r[6] else None,
                    "last_seen": r[7].isoformat() if r[7] else None,
                }
            )

        cur.execute("SELECT COUNT(*) FROM fingerprint_clusters")
        total = cur.fetchone()[0]
        conn.close()

        result = {"total": total, "clusters": clusters}
        if wants_html(request):
            return HTMLResponse(_clusters_html(result))
        return result
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e)[:200]) from e


@router.get("/attacker_hunting/{ip}")
async def attacker_hunting_detail(ip: str, request: Request):
    """Full attacker profile detail."""
    import ipaddress as _ipa

    try:
        _ipa.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None

    if not _attacker_hunting_tables_exist():
        raise HTTPException(status_code=503, detail="attacker_profiles table not found")

    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT host(ip) AS ip, first_seen, last_seen, total_events, total_attacks,
               attack_types, osint_data, abuse_score, is_noise, is_vpn,
               asn, as_org, country, city, hostname, open_ports, os_guess,
               ai_summary, ai_intent, ai_threat_level, ai_updated_at,
               mitre_techniques, internal_tags, apt_candidates,
               profile_version, created_at, updated_at,
               hunt_status, finished_at, finish_notes
        FROM attacker_profiles WHERE ip = %s::inet
    """,
        (ip,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail=f"No profile found for {ip}")

    cols = [d[0] for d in cur.description]
    profile = dict(zip(cols, row, strict=False))
    for k in ("first_seen", "last_seen", "ai_updated_at", "created_at", "updated_at"):
        if profile.get(k):
            profile[k] = profile[k].isoformat()

    # Get recent OSINT log entries
    cur.execute(
        """
        SELECT provider, response_code, queried_at
        FROM attacker_osint_log WHERE ip = %s::inet
        ORDER BY queried_at DESC LIMIT 20
    """,
        (ip,),
    )
    profile["osint_log"] = [
        {"provider": r[0], "code": r[1], "at": r[2].isoformat() if r[2] else None}
        for r in cur.fetchall()
    ]

    # Get event count timeline (last 30 days, daily)
    cur.execute(
        """
        SELECT DATE(timestamp) AS day, COUNT(*) AS cnt
        FROM sensor_events
        WHERE src_ip = %s::inet AND timestamp > NOW() - INTERVAL '30 days'
        GROUP BY day ORDER BY day
    """,
        (ip,),
    )
    profile["event_timeline"] = [{"day": r[0].isoformat(), "count": r[1]} for r in cur.fetchall()]

    # Get last 15 events for this IP with key fields + AI/Claude status
    cur.execute(
        """
        SELECT se.event_id, se.timestamp::text, se.protocol, se.dst_port,
               se.attack_types, se.scan_score,
               a.triage_class, a.claude_verdict, a.claude_attack_type, a.claude_cve
        FROM sensor_events se
        LEFT JOIN ai_analysis a ON a.event_id = se.event_id
        WHERE se.src_ip = %s::inet
        ORDER BY se.timestamp DESC LIMIT 15
    """,
        (ip,),
    )
    profile["recent_events"] = [
        {
            "event_id": r[0],
            "timestamp": r[1],
            "protocol": r[2],
            "dst_port": r[3],
            "attack_types": r[4],
            "scan_score": r[5],
            "ai_class": r[6],
            "claude_verdict": r[7],
            "claude_attack": r[8],
            "claude_cve": r[9],
        }
        for r in cur.fetchall()
    ]

    # Get Claude analysis data if columns exist
    try:
        cur.execute(
            """
            SELECT claude_verdict, claude_summary, claude_technique,
                   claude_cve, claude_threat_actor, claude_analyzed_at
            FROM attacker_profiles WHERE ip = %s::inet
        """,
            (ip,),
        )
        cr = cur.fetchone()
        if cr and cr[0]:
            profile["claude"] = {
                "verdict": cr[0],
                "summary": cr[1],
                "technique": cr[2],
                "cve": cr[3],
                "threat_actor": cr[4],
                "analyzed_at": cr[5].isoformat() if cr[5] else None,
            }
    except Exception as e:
        logger.debug("Claude columns not available: %s", e)  # silent: optional columns

    # Get ALL Claude analyses for this IP from the log
    try:
        cur.execute(
            """
            SELECT event_id, verdict, confidence, attack_type, technique,
                   cve, threat_actor, summary, estimated_cost_usd, created_at
            FROM claude_analysis_log
            WHERE src_ip = %s::inet
            ORDER BY created_at DESC
            LIMIT 20
        """,
            (ip,),
        )
        profile["claude_history"] = [
            {
                "event_id": r[0],
                "verdict": r[1],
                "confidence": r[2],
                "attack_type": r[3],
                "technique": r[4],
                "cve": r[5],
                "threat_actor": r[6],
                "summary": r[7],
                "cost": r[8],
                "analyzed_at": r[9].isoformat() if r[9] else None,
            }
            for r in cur.fetchall()
        ]
    except Exception as e:
        logger.debug("claude_analysis_log query failed: %s", e)
        profile["claude_history"] = []

    # CVE intelligence for this attacker (Idea 32 Phase E)
    try:
        attacker_cves = set()
        for ev in profile.get("recent_events", []):
            if ev.get("claude_cve") and ev["claude_cve"] not in ("None", "null", ""):
                attacker_cves.add(ev["claude_cve"])
        for ch in profile.get("claude_history", []):
            if ch.get("cve") and ch["cve"] not in ("None", "null", ""):
                attacker_cves.add(ch["cve"])

        if attacker_cves:
            # cache_only=True so a cold cache cannot block the HTTP request.
            # circl.lu has been observed at ~3 minutes for a full KEV-pagination
            # + 2-CVE enrichment cycle on cold cache; that latency is
            # unacceptable on the user-facing /attacker_hunting/<ip> page.
            # Cache warming is the responsibility of a separate periodic job
            # (run intelligence.circl_enricher's enrich_existing_db, or the
            # bulk-hunt pipeline, on a daily cron).
            from honeylens.intelligence.circl_enricher import enrich_cve

            cve_intel = []
            for cve_id in sorted(attacker_cves):
                detail = enrich_cve(cve_id, cache_only=True)
                if detail:
                    cve_intel.append(detail)
            cve_intel.sort(key=lambda d: d.get("cvss_score") or 0, reverse=True)
            profile["cve_intelligence"] = cve_intel
            # Note any CVEs missing from the local cache so the UI can
            # optionally surface a "warming" hint (and so a hunter knows
            # the page may render with thin enrichment).
            cached_ids = {d.get("cve_id") for d in cve_intel if d}
            uncached = [c for c in sorted(attacker_cves) if c not in cached_ids]
            if uncached:
                profile["cve_intelligence_uncached"] = uncached
    except Exception as e:
        logger.debug("CVE intelligence enrichment failed: %s", e)

    conn.close()

    if wants_html(request):
        return HTMLResponse(content=_hunting_detail_html(profile))
    return profile


@router.post("/attacker_hunting/{ip}/hunt")
async def attacker_hunting_trigger(ip: str, request: Request):
    """
    Start Hunt — trigger immediate OSINT + AI profiling for a single IP.
    Same pattern as POST /ai/analyze/{event_id}.
    """
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    import ipaddress as _ipa

    try:
        _ipa.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None

    if not _attacker_hunting_tables_exist():
        raise HTTPException(status_code=503, detail="attacker_profiles table not found")

    # Skip known research scanners (unless force=true)
    force = request.query_params.get("force", "") if hasattr(request, "query_params") else ""
    if is_known_scanner(ip=ip) and force != "true":
        raise HTTPException(
            status_code=422,
            detail=f"Skipped: {ip} is a known research scanner (Shadowserver/Censys/Shodan/etc.). Add ?force=true to override.",
        )

    try:
        from honeylens.analysis.attacker_profiler import get_db_connection, profile_ip
        from honeylens.config import ATTACKER_PROFILING
        from honeylens.intelligence.apt_attribution import get_mitre_data
        from honeylens.intelligence.osint_providers import build_providers

        # Build providers and get IP stats from DB
        providers = build_providers(ATTACKER_PROFILING)
        if not providers:
            raise HTTPException(
                status_code=503,
                detail="No OSINT providers configured. Set API keys in config.py or env vars.",
            )

        from honeylens.analysis.attacker_profiler import fetch_ip_info

        prof_conn = get_db_connection()
        try:
            ip_info = fetch_ip_info(prof_conn, ip)
            get_mitre_data(ATTACKER_PROFILING)
            result = await profile_ip(
                ip, ip_info, prof_conn, providers, ATTACKER_PROFILING, dry_run=False
            )
        finally:
            prof_conn.close()

        if result:
            return {
                "status": "profiled",
                "ip": ip,
                "threat_level": result.get("ai_threat_level", "UNKNOWN"),
                "intent": result.get("ai_intent", "UNKNOWN"),
                "tags": result.get("internal_tags", []),
                "mitre_techniques": result.get("mitre_techniques", []),
                "apt_candidates": len(result.get("apt_candidates", [])),
                "abuse_score": result.get("abuse_score"),
                "ai_summary": (result.get("ai_summary") or "")[:300],
            }
        else:
            raise HTTPException(status_code=500, detail="Profiling returned no result")

    except ImportError as e:
        raise HTTPException(
            status_code=503,
            detail=f"attacker_profiler.py not found: {e}. "
            "Deploy Idea 22 files (attacker_profiler.py, "
            "osint_providers.py, apt_attribution.py).",
        ) from e
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hunt error: {e!s}") from e


@router.post("/attacker_hunting/{ip}/finish")
async def attacker_hunting_finish(ip: str, request: Request):
    """Finish hunting an IP — marks as FINISHED with notes and timestamp."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    import ipaddress as _ipa

    try:
        _ipa.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None

    notes = ""
    try:
        body = await request.json()
        notes = body.get("notes", "")
    except Exception as exc:  # optional JSON body
        logging.getLogger(__name__).debug("ignored: %s", exc)

    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE attacker_profiles SET
                hunt_status = 'FINISHED',
                finished_at = NOW(),
                finish_notes = %s,
                updated_at = NOW()
            WHERE host(ip) = %s
            RETURNING host(ip), ai_threat_level, hunt_status
        """,
            (notes[:2000] if notes else None, ip),
        )
        row = cur.fetchone()
        conn.commit()
        conn.close()
        if row:
            return {"status": "finished", "ip": row[0], "threat_level": row[1]}
        raise HTTPException(status_code=404, detail=f"No profile for {ip}")
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e)[:200]) from e


@router.post("/attacker_hunting/{ip}/reopen")
async def attacker_hunting_reopen(ip: str, request: Request):
    """Re-open a finished hunt — sets back to ACTIVE for continued investigation."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    import ipaddress as _ipa

    try:
        _ipa.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None

    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE attacker_profiles SET
                hunt_status = 'ACTIVE',
                finished_at = NULL,
                finish_notes = NULL,
                updated_at = NOW()
            WHERE host(ip) = %s
            RETURNING host(ip), ai_threat_level
        """,
            (ip,),
        )
        row = cur.fetchone()
        conn.commit()
        conn.close()
        if row:
            return {"status": "reopened", "ip": row[0], "threat_level": row[1]}
        raise HTTPException(status_code=404, detail=f"No profile for {ip}")
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e)[:200]) from e


# --- Fingerprint Correlation (Idea 28) ---


@router.get("/attacker_hunting/{ip}/fingerprints")
async def attacker_fingerprints_api(ip: str, request: Request):
    """Get all fingerprints for a specific IP."""
    import ipaddress as _ipa

    try:
        _ipa.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address") from None

    try:
        from honeylens.classification.fingerprint_extractor import get_ip_fingerprints

        conn = db()
        fps = get_ip_fingerprints(conn, ip)
        conn.close()
        return {"ip": ip, "count": len(fps), "fingerprints": fps}
    except ImportError:
        return {"error": "fingerprint_extractor.py not deployed"}
    except Exception as e:
        logger.error("fingerprint_extract error: %s", e)
        return {"error": "An internal error occurred"}


@router.post("/correlation/run")
async def run_correlation_api(request: Request):
    """Trigger a correlation engine run manually."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    try:
        from honeylens.intelligence.correlation_engine import run_correlation

        result = run_correlation()
        return result
    except ImportError:
        return {"error": "correlation_engine.py not deployed"}
    except Exception as e:
        logger.error("correlation_run error: %s", e)
        return {"error": "An internal error occurred"}


# --- Attacker Hunting HTML templates ---


# ---------------------------------------------------------------------------
# IP Status — Smart IP routing (hunted → profile; not hunted → events)
# ---------------------------------------------------------------------------


@router.get("/ip/status/{ip}")
def ip_status(ip: str, request: Request):
    """Check if an IP has been hunted (has attacker_profile)."""
    import ipaddress as _ipa

    try:
        _ipa.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address") from None

    hunted = False
    threat_level = None
    if _attacker_hunting_tables_exist():
        conn = db()
        cur = conn.cursor()
        try:
            cur.execute("SELECT ai_threat_level FROM attacker_profiles WHERE host(ip) = %s", (ip,))
            row = cur.fetchone()
            if row:
                hunted = True
                threat_level = row[0]
        except Exception as e:
            logger.debug("threat level lookup failed for %s: %s", ip, e)
        conn.close()

    return {"ip": ip, "hunted": hunted, "threat_level": threat_level}


# ---------------------------------------------------------------------------
# Attacker Export — CRITICAL/HIGH from Hunting Verdicts
# ---------------------------------------------------------------------------
# Excludes whitelisted IPs. Multiple firewall/SIEM output formats.


@router.get("/export/attackers")
def export_attackers(
    request: Request,
    format: str = "text",
    threat: str = "CRITICAL,HIGH",
    min_abuse: int = 0,
    min_events: int = 0,
    days: int = 0,
    tag: str = "",
    country: str = "",
):
    """Export attacker IPs from Hunting verdicts. Excludes whitelisted IPs."""
    # Parse threat levels
    levels = [t.strip().upper() for t in threat.split(",") if t.strip()]
    valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    levels = [lvl for lvl in levels if lvl in valid_levels]
    if not levels:
        levels = ["CRITICAL", "HIGH"]

    conn = db()
    cur = conn.cursor()

    # Check table exists
    try:
        cur.execute(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='attacker_profiles')"
        )
        if not cur.fetchone()[0]:
            conn.close()
            raise HTTPException(503, "attacker_profiles table not found")
    except HTTPException:
        raise
    except Exception as e:
        conn.close()
        raise HTTPException(500, str(e)) from e

    # Build query
    conditions = ["ai_threat_level = ANY(%s)"]
    params: list = [levels]

    if min_abuse > 0:
        conditions.append("abuse_score >= %s")
        params.append(min_abuse)
    if min_events > 0:
        conditions.append("total_events >= %s")
        params.append(min_events)
    if days > 0:
        conditions.append("last_seen >= NOW() - INTERVAL '%s days'")
        params.append(days)
    if tag:
        conditions.append("%s = ANY(internal_tags)")
        params.append(tag.strip())
    if country:
        conditions.append("UPPER(country) = UPPER(%s)")
        params.append(country.strip())

    where = " AND ".join(conditions)

    try:
        cur.execute(
            psycopg2_sql.SQL("""
            SELECT host(ip) AS ip, ai_threat_level, abuse_score, country,
                   as_org, total_events, total_attacks, ai_intent,
                   internal_tags, mitre_techniques, first_seen, last_seen
            FROM attacker_profiles
            WHERE {}
            ORDER BY
                CASE ai_threat_level
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3 ELSE 4
                END,
                abuse_score DESC NULLS LAST,
                total_events DESC
        """).format(psycopg2_sql.SQL(where)),
            params,
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row, strict=False)) for row in cur.fetchall()]
    except Exception as e:
        conn.close()
        logger.error("attacker_hunting_ips query error: %s", e)
        raise HTTPException(500, "An internal error occurred") from e

    conn.close()

    # Filter out whitelisted IPs
    filtered = []
    whitelisted_count = 0
    for row in rows:
        ip_val = row.get("ip", "")
        if ip_val and is_whitelisted(ip_val):
            whitelisted_count += 1
            continue
        for k in ("first_seen", "last_seen"):
            if row.get(k) and hasattr(row[k], "isoformat"):
                row[k] = row[k].isoformat()
        for k in ("internal_tags", "mitre_techniques"):
            if row.get(k) and not isinstance(row[k], list):
                row[k] = []
        filtered.append(row)

    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {
        "generated": generated_at,
        "threat_levels": levels,
        "total_ips": len(filtered),
        "whitelisted_excluded": whitelisted_count,
        "filters": {
            "min_abuse": min_abuse,
            "min_events": min_events,
            "days": days,
            "tag": tag or None,
            "country": country or None,
        },
    }

    fmt = format.lower().strip()

    # --- Plain text ---
    if fmt == "text":
        header = (
            f"# Hybrid Intelligence Sensor — Attacker Export\n"
            f"# Generated: {generated_at}\n"
            f"# Threat levels: {', '.join(levels)}\n"
            f"# Total IPs: {len(filtered)} (excluded {whitelisted_count} whitelisted)\n#\n"
        )
        body = "\n".join(r["ip"] for r in filtered)
        return Response(
            content=header + body + "\n",
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="attackers_{generated_at[:10]}.txt"'
            },
        )

    # --- CSV ---
    if fmt == "csv":
        import csv
        import io

        output = io.StringIO()
        output.write(
            f"# Generated: {generated_at} | Levels: {','.join(levels)} | "
            f"Total: {len(filtered)} | Whitelisted excluded: {whitelisted_count}\n"
        )
        writer = csv.writer(output)
        writer.writerow(
            [
                "ip",
                "threat_level",
                "abuse_score",
                "country",
                "asn",
                "events",
                "attacks",
                "intent",
                "tags",
                "mitre",
                "first_seen",
                "last_seen",
            ]
        )
        for r in filtered:
            writer.writerow(
                [
                    r["ip"],
                    r.get("ai_threat_level", ""),
                    r.get("abuse_score", ""),
                    r.get("country", ""),
                    r.get("as_org", ""),
                    r.get("total_events", 0),
                    r.get("total_attacks", 0),
                    r.get("ai_intent", ""),
                    "|".join(r.get("internal_tags", [])),
                    "|".join(r.get("mitre_techniques", [])),
                    r.get("first_seen", ""),
                    r.get("last_seen", ""),
                ]
            )
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="attackers_{generated_at[:10]}.csv"'
            },
        )

    # --- JSON ---
    if fmt == "json":
        return JSONResponse(
            content={"meta": meta, "attackers": filtered},
            headers={
                "Content-Disposition": f'attachment; filename="attackers_{generated_at[:10]}.json"'
            },
        )

    # --- iptables ---
    if fmt == "iptables":
        header = (
            f"#!/bin/bash\n"
            f"# Hybrid Intelligence Sensor — Attacker Block Rules (iptables)\n"
            f"# Generated: {generated_at}\n"
            f"# Threat levels: {', '.join(levels)} | Total IPs: {len(filtered)}\n"
            f"# Usage: bash attackers_iptables.sh\n"
            f"# Flush: iptables -F SENSOR_BLOCK\n\n"
            f"iptables -N SENSOR_BLOCK 2>/dev/null || true\n"
            f"iptables -F SENSOR_BLOCK\n\n"
        )
        rules = "\n".join(
            f"iptables -A SENSOR_BLOCK -s {r['ip']}/32 -j DROP"
            f"  # {r.get('ai_threat_level', '?')} abuse={r.get('abuse_score', '?')} "
            f"{r.get('country', '??')} events={r.get('total_events', 0)}"
            for r in filtered
        )
        footer = (
            f"\n\niptables -C INPUT -j SENSOR_BLOCK 2>/dev/null || iptables -I INPUT 1 -j SENSOR_BLOCK\n"
            f"iptables -C FORWARD -j SENSOR_BLOCK 2>/dev/null || iptables -I FORWARD 1 -j SENSOR_BLOCK\n"
            f'echo "Blocked {len(filtered)} attacker IPs"\n'
        )
        return Response(
            content=header + rules + footer,
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="attackers_iptables_{generated_at[:10]}.sh"'
            },
        )

    # --- nftables ---
    if fmt == "nftables":
        elements = ", ".join(r["ip"] for r in filtered)
        content = (
            f"#!/usr/sbin/nft -f\n"
            f"# Hybrid Intelligence Sensor — Attacker Block (nftables)\n"
            f"# Generated: {generated_at} | Total: {len(filtered)}\n\n"
            f"define sensor_blocklist = {{\n    {elements}\n}}\n\n"
            f"table inet sensor_filter {{\n"
            f"    set blocklist {{\n        type ipv4_addr\n        flags interval\n"
            f"        elements = $sensor_blocklist\n    }}\n\n"
            f"    chain input {{\n        type filter hook input priority 0; policy accept;\n"
            f"        ip saddr @blocklist drop\n    }}\n}}\n"
        )
        return Response(
            content=content,
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="attackers_nftables_{generated_at[:10]}.nft"'
            },
        )

    # --- PF (BSD) ---
    if fmt == "pf":
        header = (
            f"# Hybrid Intelligence Sensor — Attacker Table (PF)\n"
            f"# Generated: {generated_at} | Total: {len(filtered)}\n"
            f"# Usage: pfctl -t sensor_block -T replace -f attackers.pf\n"
            f"# Rule:  block in quick on egress from <sensor_block>\n\n"
        )
        body = "\n".join(r["ip"] for r in filtered)
        return Response(
            content=header + body + "\n",
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="attackers_pf_{generated_at[:10]}.txt"'
            },
        )

    # --- MikroTik ---
    if fmt == "mikrotik":
        header = (
            f"# Hybrid Intelligence Sensor — Attacker Address List (MikroTik)\n"
            f"# Generated: {generated_at} | Total: {len(filtered)}\n\n"
        )
        cmds = "\n".join(
            f"/ip firewall address-list add list=sensor_block address={r['ip']} "
            f'comment="{r.get("ai_threat_level", "?")} abuse={r.get("abuse_score", "?")} '
            f'{r.get("country", "??")}" timeout=30d'
            for r in filtered
        )
        return Response(
            content=header + cmds + "\n",
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="attackers_mikrotik_{generated_at[:10]}.rsc"'
            },
        )

    # --- Cisco ACL ---
    if fmt == "cisco":
        header = (
            f"! Hybrid Intelligence Sensor — Attacker ACL (Cisco IOS)\n"
            f"! Generated: {generated_at} | Total: {len(filtered)}\n!\n"
            f"ip access-list extended SENSOR_BLOCK\n"
        )
        rules = "\n".join(
            f" deny ip host {r['ip']} any"
            f"  ! {r.get('ai_threat_level', '?')} {r.get('country', '??')} abuse={r.get('abuse_score', '?')}"
            for r in filtered
        )
        footer = "\n permit ip any any\n!\n"
        return Response(
            content=header + rules + footer,
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="attackers_cisco_{generated_at[:10]}.txt"'
            },
        )

    # --- STIX 2.1 ---
    if fmt == "stix":
        import uuid as _uuid

        indicators = []
        for r in filtered:
            indicators.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{_uuid.uuid5(_uuid.NAMESPACE_URL, r['ip'])}",
                    "created": generated_at,
                    "modified": generated_at,
                    "name": f"Malicious IP: {r['ip']}",
                    "description": (
                        f"Threat: {r.get('ai_threat_level', '?')}, "
                        f"Abuse: {r.get('abuse_score', '?')}/100, "
                        f"Country: {r.get('country', '?')}, "
                        f"ASN: {r.get('as_org', '?')}, "
                        f"Intent: {r.get('ai_intent', '?')}, "
                        f"Events: {r.get('total_events', 0)}"
                    ),
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[ipv4-addr:value = '{r['ip']}']",
                    "pattern_type": "stix",
                    "valid_from": r.get("first_seen", generated_at),
                    "confidence": min(r.get("abuse_score", 50) or 50, 100),
                    "labels": [
                        r.get("ai_threat_level", "unknown").lower(),
                        r.get("ai_intent", "unknown").lower(),
                    ]
                    + [t.lower() for t in r.get("internal_tags", [])[:5]],
                }
            )
        bundle = {"type": "bundle", "id": f"bundle--{_uuid.uuid4()}", "objects": indicators}
        return JSONResponse(
            content=bundle,
            headers={
                "Content-Disposition": f'attachment; filename="attackers_stix_{generated_at[:10]}.json"'
            },
        )

    raise HTTPException(
        400,
        f"Unknown format: {format}. "
        "Supported: text, csv, json, iptables, nftables, pf, mikrotik, cisco, stix",
    )


@router.get("/export/attackers/summary")
def export_attackers_summary(request: Request):
    """Quick stats for export-eligible attackers."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT
                COUNT(*) FILTER (WHERE ai_threat_level = 'CRITICAL') AS critical,
                COUNT(*) FILTER (WHERE ai_threat_level = 'HIGH') AS high,
                COUNT(*) FILTER (WHERE ai_threat_level IN ('CRITICAL','HIGH')) AS exportable,
                COUNT(*) AS total_profiles
            FROM attacker_profiles
        """)
        row = cur.fetchone()
        conn.close()
        return {"critical": row[0], "high": row[1], "exportable": row[2], "total_profiles": row[3]}
    except Exception as e:
        logger.error("stix_export_summary error: %s", e)
        conn.close()
        return {"error": "An internal error occurred"}
