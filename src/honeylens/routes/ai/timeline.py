"""AI routes — timeline feature (Phase 2 / T10, split from routes/ai.py)."""

from __future__ import annotations

from fastapi import APIRouter

from honeylens.routes.ai._common import (
    HTMLResponse,
    Request,
    _ai_subnav,
    ai_subnav,
    db,
    wants_html,
)

router = APIRouter(tags=["AI Analysis"])


@router.get("/ai/timeline")
def ai_timeline(request: Request, days: int = 30):
    """Daily classification trend — NOISE/KNOWN/SUSPICIOUS/CRITICAL over time."""
    conn = db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT timestamp::date as day,
                   COUNT(*) FILTER (WHERE triage_class = 'NOISE') as noise,
                   COUNT(*) FILTER (WHERE triage_class = 'KNOWN') as known,
                   COUNT(*) FILTER (WHERE triage_class = 'SUSPICIOUS') as suspicious,
                   COUNT(*) FILTER (WHERE triage_class = 'CRITICAL') as critical,
                   COUNT(*) as total,
                   MAX(novelty_score) as max_novelty,
                   COUNT(*) FILTER (WHERE known_cve IS NOT NULL AND known_cve != '') as cves
            FROM ai_analysis
            WHERE timestamp >= NOW() - INTERVAL '%s days'
            GROUP BY day ORDER BY day DESC
        """,
            (min(days, 365),),
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
        for r in rows:
            r["day"] = str(r["day"])
        conn.close()

        if wants_html(request):
            from honeylens.webui.shared import SHARED_CSS, nav_bar_html, sortable_table_js

            page = f"""<!DOCTYPE html><html><head><title>AI Timeline</title>
<style>{SHARED_CSS}</style></head><body>{nav_bar_html("ai")}{ai_subnav("timeline")}
{_ai_subnav("timeline")}
<div style="padding:20px">
<h2 style="color:#e2e8f0;margin-bottom:4px">AI Classification Timeline</h2>
<p style="color:#64748b;font-size:12px;margin-bottom:16px">Daily distribution of AI triage classifications over {days} days.</p>
<table><thead><tr><th>Day</th><th>Total</th><th style="color:#64748b">NOISE</th><th style="color:#38bdf8">KNOWN</th><th style="color:#f97316">SUSPICIOUS</th><th style="color:#ef4444">CRITICAL</th><th>Max Novelty</th><th>CVEs</th></tr></thead><tbody>"""
            for r in rows:
                page += f'<tr><td style="font-weight:600">{r["day"]}</td>'
                page += f'<td style="font-weight:700">{r["total"]}</td>'
                page += f'<td style="color:#64748b">{r["noise"]}</td>'
                page += f'<td style="color:#38bdf8">{r["known"]}</td>'
                s = r["suspicious"]
                page += f'<td style="color:#f97316;font-weight:{"700" if s else "400"}">{s}</td>'
                c = r["critical"]
                page += f'<td style="color:#ef4444;font-weight:{"700" if c else "400"}">{c}</td>'
                page += f'<td style="color:#eab308">{r["max_novelty"] or ""}</td>'
                page += f'<td style="color:#f87171">{r["cves"] or ""}</td></tr>'
            page += "</tbody></table>"
            page += f"<script>{sortable_table_js()}</script></div></body></html>"
            return HTMLResponse(page)
        return {"timeline": rows, "days": days}
    except Exception as e:
        conn.close()
        return {"error": str(e)}
