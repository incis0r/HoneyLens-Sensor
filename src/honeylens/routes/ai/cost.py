"""AI routes — cost feature (Phase 2 / T10, split from routes/ai.py)."""

from __future__ import annotations

from fastapi import APIRouter

from honeylens.routes.ai._common import (
    HTMLResponse,
    Request,
    ai_subnav,
    wants_html,
)

router = APIRouter(tags=["AI Analysis"])


@router.get("/ai/cost")
async def ai_cost(request: Request):
    """AI cost monitoring — daily/monthly spend, budget status, model breakdown."""
    try:
        from honeylens.analysis.claude_analyzer import get_cost_summary

        summary = get_cost_summary()
    except ImportError:
        summary = {"error": "claude_analyzer not available"}
    except Exception as e:
        summary = {"error": str(e)}

    if wants_html(request):
        from honeylens.webui.shared import SHARED_CSS, nav_bar_html, sortable_table_js

        s = summary
        if "error" in s:
            return HTMLResponse(f"<html><body><p>Error: {s['error']}</p></body></html>")
        budget_ok = s.get("budget_ok", True)
        status_color = "#22c55e" if budget_ok else "#ef4444"
        status_text = "ACTIVE" if budget_ok else "PAUSED"

        html = f"""<!DOCTYPE html><html><head><title>AI Cost Monitor</title>
<style>{SHARED_CSS}</style></head><body>{nav_bar_html("ai")}{ai_subnav("cost")}
<div style="padding:20px">
<h2 style="color:#e2e8f0;margin-bottom:16px">AI Cost Monitor</h2>

<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:20px">
  <div style="background:#111820;border:1px solid #1e2a3a;border-radius:7px;padding:12px 14px">
    <div style="font-size:10px;color:#64748b;text-transform:uppercase">Status</div>
    <div style="font-size:20px;font-weight:800;color:{status_color}">{status_text}</div>
  </div>
  <div style="background:#111820;border:1px solid #1e2a3a;border-radius:7px;padding:12px 14px">
    <div style="font-size:10px;color:#64748b;text-transform:uppercase">Today</div>
    <div style="font-size:20px;font-weight:800;color:#22d3ee">${s.get("today_usd", 0):.2f}</div>
    <div style="font-size:9px;color:#64748b">of ${s.get("today_limit_usd", 0):.2f} limit ({s.get("today_events", 0)} events)</div>
  </div>
  <div style="background:#111820;border:1px solid #1e2a3a;border-radius:7px;padding:12px 14px">
    <div style="font-size:10px;color:#64748b;text-transform:uppercase">This Month</div>
    <div style="font-size:20px;font-weight:800;color:#f97316">${s.get("month_usd", 0):.2f}</div>
    <div style="font-size:9px;color:#64748b">of ${s.get("month_limit_usd", 0):.2f} ({s.get("month_pct", 0):.0f}%, {s.get("month_events", 0)} events)</div>
  </div>
  <div style="background:#111820;border:1px solid #1e2a3a;border-radius:7px;padding:12px 14px">
    <div style="font-size:10px;color:#64748b;text-transform:uppercase">Triage Model</div>
    <div style="font-size:14px;font-weight:600;color:#a78bfa">{s.get("triage_model", "?").split("-")[1] if "-" in s.get("triage_model", "") else "?"}</div>
  </div>
  <div style="background:#111820;border:1px solid #1e2a3a;border-radius:7px;padding:12px 14px">
    <div style="font-size:10px;color:#64748b;text-transform:uppercase">Deep Model</div>
    <div style="font-size:14px;font-weight:600;color:#a78bfa">{s.get("deep_model", "?").split("-")[1] if "-" in s.get("deep_model", "") else "?"}</div>
  </div>
</div>

<h3 style="color:#94a3b8;margin:16px 0 8px">Model Breakdown (This Month)</h3>
<table><thead><tr><th>Model</th><th>Calls</th><th>Input Tokens</th><th>Output Tokens</th><th>Cost (USD)</th></tr></thead><tbody>"""
        for model, data in s.get("model_breakdown", {}).items():
            html += f"""<tr><td style="font-weight:600">{model}</td>
            <td>{data["calls"]}</td><td>{data["input_tokens"]:,}</td>
            <td>{data["output_tokens"]:,}</td>
            <td style="color:#22d3ee;font-weight:700">${data["cost_usd"]:.4f}</td></tr>"""
        html += "</tbody></table>"

        html += '<h3 style="color:#94a3b8;margin:16px 0 8px">Daily Trend (7 days)</h3>'
        html += (
            "<table><thead><tr><th>Day</th><th>Calls</th><th>Cost (USD)</th></tr></thead><tbody>"
        )
        for d in s.get("daily_trend", []):
            html += (
                f"<tr><td>{d['day']}</td><td>{d['calls']}</td><td>${d['cost_usd']:.4f}</td></tr>"
            )
        html += "</tbody></table>"
        html += f'<p style="color:#64748b;font-size:11px;margin-top:16px">{s.get("budget_status", "")}</p>'
        html += f"<script>{sortable_table_js()}</script></div></body></html>"
        return HTMLResponse(html)

    return summary
