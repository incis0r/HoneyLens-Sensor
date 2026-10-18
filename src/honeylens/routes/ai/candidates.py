"""AI routes — candidates feature (Phase 2 / T10, split from routes/ai.py)."""

from __future__ import annotations

from fastapi import APIRouter

from honeylens.routes.ai._common import (
    HTMLResponse,
    Request,
    _ai_subnav,
    _render_candidate_table,
    ai_subnav,
    db,
    wants_html,
)

router = APIRouter(tags=["AI Analysis"])


@router.get("/ai/zero-days")
def ai_zero_days(request: Request, min_score: int = 70, limit: int = 100):
    """0-Day candidates — ranked by the deep-analysis zero_day_score (0-100).

    Triage novelty is a coarse "worth-a-look" signal; the actual 0-day judgement
    comes from deep analysis (Claude/OpenAI). This page surfaces what deep
    analysis scored, not the raw high-novelty triage bucket. For that bucket see
    /ai/high-novelty.
    """
    min_score = max(0, min(min_score, 100))
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT a.event_id, a.triage_class, a.novelty_score, a.triage_confidence,
                   a.triage_reasoning, a.known_cve, a.zero_day_score,
                   a.suggested_rule_name, a.suggested_mitre,
                   a.claude_verdict, a.claude_attack_type, a.claude_summary,
                   a.timestamp,
                   se.src_ip::text, se.protocol, se.dst_port, se.attack_types,
                   LEFT(se.payload, 300) as payload_preview
            FROM ai_analysis a
            LEFT JOIN sensor_events se ON se.event_id = a.event_id
            WHERE a.zero_day_score >= %s
            ORDER BY a.zero_day_score DESC, a.novelty_score DESC, a.timestamp DESC
            LIMIT %s
        """,
            (min_score, min(limit, 500)),
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
        for r in rows:
            if r.get("timestamp"):
                r["timestamp"] = r["timestamp"].isoformat()
        conn.close()

        if wants_html(request):
            return _render_candidate_table(
                request,
                rows,
                active="candidates",
                subnav_key="zero-days",
                title="0-Day Candidates",
                subtitle=(
                    f"Events the deep model scored zero-day probability &ge; {min_score}/100. "
                    "Ranked by deep-analysis score, not raw triage novelty — "
                    "high-novelty-but-unscored traffic lives under "
                    "<a href='/ai/high-novelty' style='color:#38bdf8'>High-Novelty Triage</a>."
                ),
                headline="zd",
            )
        return {
            "events": rows,
            "count": len(rows),
            "min_score": min_score,
            "ranked_by": "zero_day_score",
        }
    except Exception as e:
        conn.close()
        return {"error": str(e)}


@router.get("/ai/high-novelty")
def ai_high_novelty(request: Request, min_score: int = 6, limit: int = 100):
    """Triage high-novelty bucket — events the triage model flagged as unusual
    (novelty >= min_score) but that deep analysis has not (yet) scored as 0-day.
    A review queue for unknowns, distinct from confirmed 0-day candidates."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT a.event_id, a.triage_class, a.novelty_score, a.triage_confidence,
                   a.triage_reasoning, a.known_cve, a.zero_day_score,
                   a.suggested_rule_name, a.suggested_mitre,
                   a.claude_verdict, a.claude_attack_type, a.claude_summary,
                   a.timestamp,
                   se.src_ip::text, se.protocol, se.dst_port, se.attack_types,
                   LEFT(se.payload, 300) as payload_preview
            FROM ai_analysis a
            LEFT JOIN sensor_events se ON se.event_id = a.event_id
            WHERE a.novelty_score >= %s
            ORDER BY a.novelty_score DESC, a.timestamp DESC
            LIMIT %s
        """,
            (min_score, min(limit, 500)),
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
        for r in rows:
            if r.get("timestamp"):
                r["timestamp"] = r["timestamp"].isoformat()
        conn.close()

        if wants_html(request):
            return _render_candidate_table(
                request,
                rows,
                active="highnov",
                subnav_key="high-novelty",
                title="High-Novelty Triage",
                subtitle=(
                    f"Events triage flagged as unusual (novelty &ge; {min_score}/10). "
                    "A coarse worth-a-look queue — routine honeypot protocol "
                    "traffic is guarded out. Confirmed 0-day candidates (by "
                    "deep-analysis score) are under "
                    "<a href='/ai/zero-days' style='color:#38bdf8'>0-Day Candidates</a>."
                ),
                headline="novelty",
            )
        return {
            "events": rows,
            "count": len(rows),
            "min_score": min_score,
            "ranked_by": "novelty_score",
        }
    except Exception as e:
        conn.close()
        return {"error": str(e)}


@router.get("/ai/cves")
def ai_cves(request: Request, limit: int = 200):
    """All AI-identified CVEs with event context."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT a.known_cve, COUNT(*) as event_count,
                   MAX(a.novelty_score) as max_novelty,
                   array_agg(DISTINCT a.triage_class) as classes,
                   array_agg(DISTINCT se.protocol) as protocols,
                   array_agg(DISTINCT se.dst_port) as ports,
                   MIN(a.timestamp)::date as first_seen,
                   MAX(a.timestamp)::date as last_seen,
                   COUNT(DISTINCT se.src_ip) as unique_ips
            FROM ai_analysis a
            LEFT JOIN sensor_events se ON se.event_id = a.event_id
            WHERE a.known_cve IS NOT NULL
              AND a.known_cve ~ '^CVE-[0-9]{4}-[0-9]{4,7}$'
            GROUP BY a.known_cve
            ORDER BY event_count DESC
            LIMIT %s
        """,
            (min(limit, 500),),
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
        for r in rows:
            if r.get("first_seen"):
                r["first_seen"] = str(r["first_seen"])
            if r.get("last_seen"):
                r["last_seen"] = str(r["last_seen"])
        conn.close()

        if wants_html(request):
            from honeylens.webui.shared import SHARED_CSS, nav_bar_html, sortable_table_js

            page = f"""<!DOCTYPE html><html><head><title>AI-Detected CVEs</title>
<style>{SHARED_CSS}</style></head><body>{nav_bar_html("ai")}{ai_subnav("cves")}
{_ai_subnav("cves")}
<div style="padding:20px">
<h2 style="color:#e2e8f0;margin-bottom:4px">AI-Detected CVEs</h2>
<p style="color:#64748b;font-size:12px;margin-bottom:16px">Vulnerabilities identified by AI analysis across all events.</p>
<table><thead><tr><th>CVE</th><th>Events</th><th>Unique IPs</th><th>Max Novelty</th><th>Protocols</th><th>Ports</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody>"""
            for r in rows:
                cve = r.get("known_cve", "")
                page += f'<tr><td style="color:#f87171;font-weight:700"><a href="https://nvd.nist.gov/vuln/detail/{cve}" style="color:#f87171" target="_blank">{cve}</a></td>'
                page += f'<td style="font-weight:700">{r.get("event_count", 0)}</td>'
                page += f"<td>{r.get('unique_ips', 0)}</td>"
                page += f'<td style="color:#eab308">{r.get("max_novelty", "")}</td>'
                protos = ", ".join(str(p) for p in (r.get("protocols") or []) if p)
                ports = ", ".join(str(p) for p in (r.get("ports") or []) if p)
                page += f'<td style="font-size:11px">{protos}</td><td style="font-size:11px">{ports}</td>'
                page += f'<td style="color:#64748b;font-size:11px">{r.get("first_seen", "")}</td>'
                page += (
                    f'<td style="color:#64748b;font-size:11px">{r.get("last_seen", "")}</td></tr>'
                )
            page += f"</tbody></table><p style='color:#64748b;font-size:11px;margin-top:8px'>{len(rows)} CVEs detected</p>"
            page += f"<script>{sortable_table_js()}</script></div></body></html>"
            return HTMLResponse(page)
        return {"cves": rows, "count": len(rows)}
    except Exception as e:
        conn.close()
        return {"error": str(e)}
