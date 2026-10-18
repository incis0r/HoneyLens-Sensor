"""AI routes — search feature (Phase 2 / T10, split from routes/ai.py)."""

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


@router.get("/ai/search")
def ai_search(
    request: Request,
    q: str = "",
    ip: str = "",
    cve: str = "",
    triage_class: str = "",
    protocol: str = "",
    days: int = 30,
    limit: int = 200,
):
    """Full-text search across AI analysis results."""
    import re as _re

    # Input validation
    errors = []
    q = q.strip()[:200]
    ip = ip.strip()
    cve = cve.strip()[:30]
    triage_class = triage_class.strip().strip("'\"").upper()
    protocol = protocol.strip().strip("'\"")[:20]
    days = max(1, min(days, 365))
    limit = max(1, min(limit, 500))

    if ip and not _re.match(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", ip):
        errors.append(f"Invalid IP address: {ip}")
        ip = ""
    if triage_class and triage_class not in ("CRITICAL", "SUSPICIOUS", "KNOWN", "NOISE"):
        errors.append(
            f"Invalid triage class: {triage_class}. Must be CRITICAL, SUSPICIOUS, KNOWN, or NOISE."
        )
        triage_class = ""

    conn = db()
    cur = conn.cursor()
    conditions = [f"a.timestamp >= NOW() - INTERVAL '{days} days'"]
    params = []

    if q:
        conditions.append(
            "(a.triage_reasoning ILIKE %s OR a.claude_summary ILIKE %s OR a.suggested_rule_name ILIKE %s OR se.attack_types ILIKE %s)"
        )
        s = f"%{q}%"
        params.extend([s, s, s, s])
    if ip:
        conditions.append("se.src_ip = %s::inet")
        params.append(ip)
    if cve:
        conditions.append("a.known_cve ILIKE %s")
        params.append(f"%{cve}%")
    if triage_class:
        conditions.append("a.triage_class = %s")
        params.append(triage_class)
    if protocol:
        conditions.append("se.protocol ILIKE %s")
        params.append(protocol)

    where = " AND ".join(conditions)

    try:
        cur.execute("SET statement_timeout = '60s'")
        cur.execute(
            f"""
            SELECT a.event_id, a.triage_class, a.novelty_score, a.triage_confidence,
                   a.triage_reasoning, a.known_cve, a.zero_day_score,
                   a.suggested_rule_name, a.claude_verdict, a.claude_summary,
                   a.timestamp,
                   se.src_ip::text, se.protocol, se.dst_port, se.attack_types,
                   LEFT(se.payload, 200) as payload_preview
            FROM ai_analysis a
            LEFT JOIN sensor_events se ON se.event_id = a.event_id
            WHERE {where}
            ORDER BY a.timestamp DESC
            LIMIT %s
        """,  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
            [*params, min(limit, 500)],
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r, strict=False)) for r in cur.fetchall()]
        for r in rows:
            if r.get("timestamp"):
                r["timestamp"] = r["timestamp"].isoformat()
        conn.close()

        if wants_html(request):
            import html as _h

            from honeylens.webui.shared import SHARED_CSS, nav_bar_html, sortable_table_js

            err_html = ""
            if errors:
                err_html = '<div style="background:#ef444420;border:1px solid #ef4444;border-radius:6px;padding:10px 14px;margin-bottom:12px;color:#fca5a5;font-size:12px">'
                err_html += " ".join(_h.escape(e) for e in errors)
                err_html += "</div>"
            page = f"""<!DOCTYPE html><html><head><title>AI Search</title>
<style>{SHARED_CSS}</style></head><body>{nav_bar_html("ai")}{ai_subnav("search")}
{_ai_subnav("search")}
<div style="padding:20px">
<h2 style="color:#e2e8f0;margin-bottom:12px">AI Analysis Search</h2>
{err_html}
<form method="GET" action="/ai/search" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:end">
  <div><label style="font-size:10px;color:#64748b;display:block">Keyword</label>
  <input name="q" value="{_h.escape(q)}" placeholder="reasoning, summary, rule..." style="background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:6px 10px;border-radius:4px;width:180px;font-size:12px"></div>
  <div><label style="font-size:10px;color:#64748b;display:block">Source IP</label>
  <input name="ip" value="{_h.escape(ip)}" placeholder="1.2.3.4" style="background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:6px 10px;border-radius:4px;width:120px;font-size:12px"></div>
  <div><label style="font-size:10px;color:#64748b;display:block">CVE</label>
  <input name="cve" value="{_h.escape(cve)}" placeholder="CVE-2024-..." style="background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:6px 10px;border-radius:4px;width:130px;font-size:12px"></div>
  <div><label style="font-size:10px;color:#64748b;display:block">Class</label>
  <select name="triage_class" style="background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:6px;border-radius:4px;font-size:12px">
    <option value="">All</option><option value="CRITICAL" {"selected" if triage_class == "CRITICAL" else ""}>CRITICAL</option>
    <option value="SUSPICIOUS" {"selected" if triage_class == "SUSPICIOUS" else ""}>SUSPICIOUS</option>
    <option value="KNOWN" {"selected" if triage_class == "KNOWN" else ""}>KNOWN</option>
    <option value="NOISE" {"selected" if triage_class == "NOISE" else ""}>NOISE</option>
  </select></div>
  <div><label style="font-size:10px;color:#64748b;display:block">Protocol</label>
  <input name="protocol" value="{_h.escape(protocol)}" placeholder="HTTP, SSH..." style="background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:6px 10px;border-radius:4px;width:80px;font-size:12px"></div>
  <div><label style="font-size:10px;color:#64748b;display:block">Days</label>
  <input name="days" value="{days}" type="number" min="1" max="365" style="background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:6px 10px;border-radius:4px;width:60px;font-size:12px"></div>
  <button type="submit" style="background:#3b82f6;color:#fff;border:none;padding:6px 16px;border-radius:4px;cursor:pointer;font-size:12px;height:32px">Search</button>
</form>
<table><thead><tr><th>Class</th><th>Novelty</th><th>IP</th><th>Protocol</th><th>Port</th><th>CVE</th><th>Verdict</th><th>Reasoning</th><th>Date</th></tr></thead><tbody>"""
            _cc = {
                "CRITICAL": "#ef4444",
                "SUSPICIOUS": "#f97316",
                "KNOWN": "#38bdf8",
                "NOISE": "#64748b",
            }
            for r in rows:
                tc = r.get("triage_class", "")
                c = _cc.get(tc, "#94a3b8")
                ts = (r.get("timestamp") or "")[:16]
                sip = (r.get("src_ip") or "").split("/")[0]
                reason = _h.escape(
                    str(r.get("triage_reasoning", "") or r.get("claude_summary", "") or "")[:100]
                )
                page += f'<tr><td style="color:{c};font-weight:700">{tc}</td>'
                page += f'<td style="text-align:center">{r.get("novelty_score", "")}</td>'
                page += (
                    f'<td><a href="/attacker_hunting/{sip}" style="color:#22d3ee">{sip}</a></td>'
                )
                page += f"<td>{r.get('protocol', '')}</td><td>{r.get('dst_port', '')}</td>"
                page += (
                    f'<td style="color:#f87171;font-size:10px">{r.get("known_cve", "") or ""}</td>'
                )
                page += f'<td style="font-size:10px">{r.get("claude_verdict", "") or ""}</td>'
                page += f'<td style="font-size:10px;color:#94a3b8;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{reason}</td>'
                page += f'<td style="color:#64748b;font-size:10px">{ts}</td></tr>'
            page += f"</tbody></table><p style='color:#64748b;font-size:11px;margin-top:8px'>{len(rows)} results (last {days} days)</p>"
            page += f"<script>{sortable_table_js()}</script></div></body></html>"
            return HTMLResponse(page)
        return {
            "results": rows,
            "count": len(rows),
            "query": {"q": q, "ip": ip, "cve": cve, "class": triage_class, "days": days},
        }
    except Exception as e:
        conn.close()
        err_msg = str(e).split("\n")[0]  # First line only, no SQL details
        if wants_html(request):
            import html as _h

            from honeylens.webui.shared import SHARED_CSS, nav_bar_html

            return HTMLResponse(f"""<!DOCTYPE html><html><head><title>AI Search</title>
<style>{SHARED_CSS}</style></head><body>{nav_bar_html("ai")}{ai_subnav("search")}
{_ai_subnav("search")}
<div style="padding:20px">
<h2 style="color:#e2e8f0;margin-bottom:12px">AI Analysis Search</h2>
<div style="background:#ef444420;border:1px solid #ef4444;border-radius:6px;padding:10px 14px;margin-bottom:12px;color:#fca5a5;font-size:12px">
Search error: {_h.escape(err_msg)}</div>
<a href="/ai/search" style="color:#38bdf8">Clear search and try again</a>
</div></body></html>""")
        return {"error": err_msg}
