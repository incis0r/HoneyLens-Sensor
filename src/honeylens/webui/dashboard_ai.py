"""
webui/dashboard_ai.py — AI Analysis Dashboard
===============================================
Dashboard at /ai/stats showing AI triage distribution, flagged events.
Extracted from api.py.
Compatible with Python 3.9+.
"""

from __future__ import annotations

import html
import json as _json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI


def register_routes(app: FastAPI) -> None:
    """AI dashboard HTML routes are served by api.py — this module
    provides the HTML rendering functions only."""
    pass


def _cve_badge(cve_id, cve_details=None) -> str:
    """Render CVE ID with optional KEV badge and CVSS tooltip."""
    if not cve_id or cve_id in ("None", "null", ""):
        return '<span style="color:#475569">—</span>'
    e = html.escape(str(cve_id))
    link = f'<a href="https://vulnerability.circl.lu/cve/{e}" target="_blank" style="color:#f87171;text-decoration:none">{e}</a>'
    kev = ""
    cvss = ""
    if isinstance(cve_details, dict):
        if cve_details.get("is_kev"):
            kev = ' <span style="background:#ef4444;color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700">KEV</span>'
        score = cve_details.get("cvss_score")
        if score is not None:
            sev = cve_details.get("cvss_severity", "")
            colors = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#22c55e",
            }
            c = colors.get(sev, "#64748b")
            cvss = f' <span style="color:{c};font-size:10px" title="{html.escape(str(cve_details.get("cvss_vector", "")))}">{score}</span>'
    elif isinstance(cve_details, str):
        try:
            d = _json.loads(cve_details)
            return _cve_badge(cve_id, d)
        except Exception as exc:  # best effort JSON parse for CVE badge display
            logging.getLogger(__name__).debug("ignored: %s", exc)
    return f"{link}{cvss}{kev}"


def _ai_not_configured_html() -> str:
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><title>AI Analysis</title>'
        "<style>body{background:#0f172a;color:#e2e8f0;font-family:monospace;"
        "display:flex;align-items:center;justify-content:center;min-height:100vh}</style>"
        '</head><body><div style="text-align:center">'
        '<div style="font-size:3rem">&#x1F9E0;</div>'
        '<h2 style="color:#f87171;margin:16px 0">AI Analysis Not Configured</h2>'
        '<p style="color:#94a3b8">Run <code>python ai_analyzer.py --test-ollama</code> to verify Ollama,</p>'
        '<p style="color:#94a3b8">then <code>python ai_analyzer.py --once</code> to process a batch.</p>'
        '<a href="/" style="color:#38bdf8">&#8592; Back to Dashboard</a>'
        "</div></body></html>"
    )


# Shared AI-section secondary navigation — used by every /ai/* page so the
# section tabs and active state stay consistent across the feature.
AI_SUBNAV = [
    ("overview", "/ai/stats", "Overview"),
    ("candidates", "/ai/zero-days", "0-Day Candidates"),
    ("highnov", "/ai/high-novelty", "High-Novelty Triage"),
    ("cves", "/ai/cves", "CVEs"),
    ("timeline", "/ai/timeline", "Timeline"),
    ("search", "/ai/search", "Search"),
    ("rules", "/ai/rules/suggested", "Suggested Rules"),
    ("rulemgr", "/ai/rules", "Rule Manager"),
    ("queue", "/ai/queue", "Queue"),
    ("cost", "/ai/cost", "Cost"),
]


def ai_subnav(active: str = "") -> str:
    """The AI-section secondary nav (subnav_html) with `active` tab highlighted."""
    from honeylens.webui.shared import subnav_html

    return subnav_html(AI_SUBNAV, active=active)


def _ai_dashboard_html(data: dict) -> str:
    """AI Analysis dashboard — full HTML with dark theme matching ICS/OT."""
    import json as _json

    s = data["summary"]
    _json.dumps(data, default=str)

    _cls_color = {
        "CRITICAL": "#ef4444",
        "SUSPICIOUS": "#f97316",
        "KNOWN": "#38bdf8",
        "NOISE": "#64748b",
    }
    _cls_bg = {
        "CRITICAL": "#ef444420",
        "SUSPICIOUS": "#f9731620",
        "KNOWN": "#38bdf820",
        "NOISE": "#64748b20",
    }

    def cls_c(c):
        return _cls_color.get(str(c).upper(), "#94a3b8")

    def cls_b(c):
        return _cls_bg.get(str(c).upper(), "#ffffff10")

    def e(v):
        return html.escape(str(v)) if v is not None else ""

    # ── KPI strip ────────────────────────────────────────────────────────
    kpi_html = ""
    kpis = [
        ("Total Analysed", s["total"], "#38bdf8"),
        ("Last 24h", s["last_24h"], "#22c55e"),
        ("Last 1h", s["last_1h"], "#eab308"),
        ("Suspicious", s["suspicious"], "#f97316"),
        ("Critical", s["critical"], "#ef4444"),
        ("0-Day Candidates", s["zero_day_candidates"], "#f43f5e"),
        ("Pending Review", s["pending_review"], "#fb923c"),
        ("Deep Analysed", s["deep_analysed"], "#a78bfa"),
        ("Suggested Rules", s["suggested_rules"], "#34d399"),
        ("Avg Novelty", s["avg_novelty"], "#f472b6"),
        ("Avg Triage", f"{s['avg_triage_ms']}ms", "#94a3b8"),
    ]
    for label, val, color in kpis:
        display = f"{val:,}" if isinstance(val, int) else str(val)
        kpi_html += (
            f'<div class="kpi">'
            f'<div class="kpi-lbl">{label}</div>'
            f'<div class="kpi-val" style="color:{color}">{display}</div>'
            f"</div>"
        )

    # ── LLM Cost & Usage Panel (Anthropic + OpenAI shared schema) ───────
    claude_stats_html = ""
    cs = data.get("claude_stats")
    if cs and cs.get("total_calls", 0) > 0:
        # Detect provider mix in the by_model breakdown to pick a panel header.
        _bm = cs.get("by_model", []) or []
        _has_openai = any(
            (m.get("model") or "").lower().startswith(("gpt-", "o1", "o3", "o4")) for m in _bm
        )
        _has_claude = any(("claude" in (m.get("model") or "").lower()) for m in _bm)
        if _has_openai and _has_claude:
            _panel_label = "LLM Cost &amp; Usage — Anthropic + OpenAI"
        elif _has_openai:
            _panel_label = "OpenAI — Cost &amp; Usage"
        else:
            _panel_label = "Claude — Cost &amp; Usage"
        claude_stats_html = f"""
<div class="panel" style="margin-bottom:16px;border-color:#d9770644">
  <div class="panel-hdr" style="color:#d97706">&#x1F52C; {_panel_label}</div>
  <div style="display:flex;flex-wrap:wrap;gap:10px;padding:10px">
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">Total Calls</div>
      <div class="kpi-val" style="color:#d97706">{cs["total_calls"]:,}</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">Total Cost</div>
      <div class="kpi-val" style="color:#ef4444">${cs["total_cost"]:.4f}</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">Last 24h</div>
      <div class="kpi-val" style="color:#f97316">{cs["calls_24h"]} / ${cs["cost_24h"]:.4f}</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">Last 1h</div>
      <div class="kpi-val" style="color:#eab308">{cs["calls_1h"]} / ${cs["cost_1h"]:.4f}</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">Input Tokens</div>
      <div class="kpi-val" style="color:#94a3b8">{cs["total_input_tokens"]:,}</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">Output Tokens</div>
      <div class="kpi-val" style="color:#94a3b8">{cs["total_output_tokens"]:,}</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">Avg Latency</div>
      <div class="kpi-val" style="color:#64748b">{cs["avg_elapsed_ms"]:,}ms</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">Unique IPs</div>
      <div class="kpi-val" style="color:#38bdf8">{cs["unique_ips"]}</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">CRITICAL</div>
      <div class="kpi-val" style="color:#ef4444">{cs["critical"]}</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">HIGH</div>
      <div class="kpi-val" style="color:#f97316">{cs["high"]}</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">CVEs Found</div>
      <div class="kpi-val" style="color:#f87171">{cs["with_cve"]}</div>
    </div>
    <div class="kpi" style="min-width:100px">
      <div class="kpi-lbl">Threat Actors</div>
      <div class="kpi-val" style="color:#a78bfa">{cs["with_actor"]}</div>
    </div>
  </div>
  <div style="padding:0 10px 8px;color:#64748b;font-size:10px">
    Last call: {e(str(cs.get("last_call") or "never")[:19].replace("T", " "))}
    &mdash; Cost per call: ${(cs["total_cost"] / max(cs["total_calls"], 1)):.4f}
  </div>"""

        # Per-model breakdown
        by_model = cs.get("by_model", [])
        if by_model:
            claude_stats_html += '<div style="padding:0 10px 10px"><table style="width:100%;border-collapse:collapse;font-size:11px">'
            claude_stats_html += '<thead><tr style="border-bottom:1px solid #334155;color:#64748b;font-size:10px;text-transform:uppercase">'
            claude_stats_html += '<th style="padding:3px 6px;text-align:left">Model</th>'
            claude_stats_html += '<th style="padding:3px 6px;text-align:right">Calls</th>'
            claude_stats_html += '<th style="padding:3px 6px;text-align:right">Cost</th>'
            claude_stats_html += '<th style="padding:3px 6px;text-align:right">In Tokens</th>'
            claude_stats_html += '<th style="padding:3px 6px;text-align:right">Out Tokens</th>'
            claude_stats_html += '<th style="padding:3px 6px;text-align:right">Avg Latency</th>'
            claude_stats_html += (
                '<th style="padding:3px 6px;text-align:right">Cost/Call</th></tr></thead><tbody>'
            )
            for mm in by_model:
                model_name = e(mm.get("model", ""))
                ml = model_name.lower()
                is_haiku = "haiku" in ml
                is_sonnet = "sonnet" in ml
                is_gpt_mini_triage = (
                    ml.startswith("gpt-4.1-mini")
                    or ml.startswith("gpt-4o-mini")
                    or ml.startswith("gpt-4.1-nano")
                )
                is_gpt_deep = (
                    ml.startswith("gpt-5")
                    or ml.startswith("o1")
                    or ml.startswith("o3")
                    or ml.startswith("o4")
                )
                if is_haiku:
                    model_color, model_label = "#22c55e", "Haiku (triage)"
                elif is_sonnet:
                    model_color, model_label = "#d97706", "Sonnet (deep)"
                elif is_gpt_mini_triage:
                    model_color, model_label = "#10a37f", f"{model_name} (triage)"
                elif is_gpt_deep:
                    model_color, model_label = "#0ea5e9", f"{model_name} (deep)"
                else:
                    model_color, model_label = "#94a3b8", model_name[:30]
                m_calls = mm.get("calls", 0)
                m_cost = mm.get("cost", 0)
                m_in = mm.get("input_tokens", 0)
                m_out = mm.get("output_tokens", 0)
                m_ms = mm.get("avg_ms", 0)
                m_per = m_cost / max(m_calls, 1)
                claude_stats_html += '<tr style="border-bottom:1px solid #ffffff08">'
                claude_stats_html += f'<td style="padding:3px 6px;color:{model_color};font-weight:700">{model_label}</td>'
                claude_stats_html += (
                    f'<td style="padding:3px 6px;text-align:right">{m_calls:,}</td>'
                )
                claude_stats_html += (
                    f'<td style="padding:3px 6px;text-align:right;color:#ef4444">${m_cost:.4f}</td>'
                )
                claude_stats_html += (
                    f'<td style="padding:3px 6px;text-align:right;color:#94a3b8">{m_in:,}</td>'
                )
                claude_stats_html += (
                    f'<td style="padding:3px 6px;text-align:right;color:#94a3b8">{m_out:,}</td>'
                )
                claude_stats_html += (
                    f'<td style="padding:3px 6px;text-align:right;color:#64748b">{m_ms:,}ms</td>'
                )
                claude_stats_html += (
                    f'<td style="padding:3px 6px;text-align:right;color:#f97316">${m_per:.4f}</td>'
                )
                claude_stats_html += "</tr>"
            claude_stats_html += "</tbody></table></div>"

        claude_stats_html += "</div>"

    # ── Model Comparison Panel ─────────────────────────────────────────
    model_compare_html = ""
    if cs and cs.get("model_verdicts"):
        mv = cs["model_verdicts"]
        model_compare_html = """
<div class="panel" style="margin-bottom:16px;border-color:#a78bfa44">
  <div class="panel-hdr" style="color:#a78bfa">&#x1F4CA; Model Comparison — Verdict Accuracy</div>
  <p style="color:#94a3b8;font-size:11px;padding:0 10px 8px;margin:0">
    Verdict distribution per model. Use TP/FP buttons in the Flagged Events table to build accuracy data over time.</p>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:12px;padding:0 10px 10px">"""
        _verdict_colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
            "INFO": "#38bdf8",
            "KNOWN": "#64748b",
            "NOISE": "#475569",
            "SUSPICIOUS": "#f97316",
        }
        for model_name, verdicts in mv.items():
            mn = model_name.lower()
            if "haiku" in mn:
                mc, ml = "#22c55e", "Haiku (triage)"
            elif "sonnet" in mn:
                mc, ml = "#d97706", "Sonnet (deep)"
            elif mn.startswith(("gpt-4.1-mini", "gpt-4o-mini", "gpt-4.1-nano")):
                mc, ml = "#10a37f", f"{e(model_name)} (triage)"
            elif mn.startswith(("gpt-5", "o1", "o3", "o4")):
                mc, ml = "#0ea5e9", f"{e(model_name)} (deep)"
            else:
                mc, ml = "#94a3b8", e(model_name[:30])
            total_v = sum(verdicts.values()) or 1
            model_compare_html += f"""
    <div style="background:var(--bg2);padding:10px;border-radius:6px;border:1px solid {mc}30">
      <div style="color:{mc};font-weight:700;font-size:12px;margin-bottom:8px">{ml}
        <span style="color:#64748b;font-weight:400"> — {total_v:,} analyses</span></div>"""
            for verdict in sorted(verdicts.keys(), key=lambda v: -verdicts[v]):
                cnt = verdicts[verdict]
                pct = cnt / total_v * 100
                vc = _verdict_colors.get(verdict, "#94a3b8")
                model_compare_html += (
                    f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px">'
                    f'<div style="width:70px;font-size:10px;color:{vc};font-weight:700">{e(verdict)}</div>'
                    f'<div style="flex:1;height:14px;background:#1e293b;border-radius:2px;overflow:hidden">'
                    f'<div style="width:{pct}%;height:100%;background:{vc}40;border-radius:2px"></div></div>'
                    f'<div style="width:50px;text-align:right;font-size:10px;color:#94a3b8">{cnt:,} ({pct:.0f}%)</div>'
                    f"</div>"
                )
            model_compare_html += "</div>"
        model_compare_html += "</div></div>"

    # ── Per-IP Cost Breakdown ──────────────────────────────────────────
    ip_cost_html = ""
    if cs and cs.get("ip_costs"):
        ip_costs = cs["ip_costs"]
        ip_cost_html = """
<div class="panel" style="margin-bottom:16px;border-color:#ef444430">
  <div class="panel-hdr" style="color:#ef4444">&#x1F4B0; Per-IP Cost Breakdown
    <span class="panel-cnt">top 20 most expensive IPs</span></div>
  <table>
    <thead><tr>
      <th>IP</th><th>Calls</th><th>Cost (USD)</th><th>Tokens</th>
      <th>Cost/Call</th><th>Top Verdict</th><th>Last Call</th>
    </tr></thead><tbody>"""
        for ipc in ip_costs:
            ip_raw = (ipc.get("ip") or "").split("/")[0]
            ip_disp = e(ip_raw)
            calls = ipc.get("calls", 0)
            cost = ipc.get("cost", 0)
            tokens = ipc.get("tokens", 0)
            per_call = cost / max(calls, 1)
            verdict = ipc.get("top_verdict") or ""
            vc = _verdict_colors.get(verdict, "#94a3b8") if verdict else "#64748b"
            last = str(ipc.get("last_call") or "")[:16].replace("T", " ")
            # Cost color: red > $0.10, orange > $0.01, green
            cc = "#ef4444" if cost > 0.10 else "#f97316" if cost > 0.01 else "#22c55e"
            ip_cost_html += (
                f"<tr>"
                f'<td class="ip" style="cursor:pointer" onclick="window.location.href=\'/events_ip/{ip_disp}?format=html\'">{ip_disp}</td>'
                f'<td style="text-align:right">{calls:,}</td>'
                f'<td style="text-align:right;color:{cc};font-weight:700">${cost:.4f}</td>'
                f'<td style="text-align:right;color:#94a3b8">{tokens:,}</td>'
                f'<td style="text-align:right;color:#f97316">${per_call:.4f}</td>'
                f'<td><span style="color:{vc};font-weight:700">{e(verdict)}</span></td>'
                f'<td style="font-size:10px;color:#64748b">{last}</td>'
                f"</tr>"
            )
        ip_cost_html += "</tbody></table></div>"

    # ── Classification bar ───────────────────────────────────────────────
    total = max(s["total"], 1)
    cls_bar = ""
    for key, color in [
        ("critical", "#ef4444"),
        ("suspicious", "#f97316"),
        ("known", "#38bdf8"),
        ("noise", "#64748b"),
    ]:
        pct = s[key] / total * 100
        if s[key]:
            cls_bar += (
                f'<div style="background:{color};width:{pct:.1f}%;'
                f'height:100%;display:inline-block" '
                f'title="{key.upper()}: {s[key]:,}"></div>'
            )

    # ── Hunted IPs set for indicator ────────────────────────────────
    hunted_set = set(data.get("hunted_ips", []))

    # ── Flagged events rows ──────────────────────────────────────────────
    flagged_rows = ""
    for f in data["flagged"]:
        cc = cls_c(f["triage_class"])
        cb = cls_b(f["triage_class"])
        ts = (f.get("timestamp") or "")[:19].replace("T", " ")
        full_eid = e(f["event_id"])
        eid = e(f["event_id"][:16])
        zday = f.get("zero_day_score") or ""
        zday_html = (
            f'<span style="color:#f43f5e;font-weight:700">{zday}%</span>'
            if isinstance(zday, int | float) and zday >= 50
            else f'<span class="dim">{zday}%</span>'
            if zday
            else '<span class="dim">—</span>'
        )
        reviewed = "✔" if f.get("reviewed") else "⚠"
        rev_color = "#22c55e" if f.get("reviewed") else "#f97316"
        src_ip_raw = (f.get("src_ip") or "").split("/")[0] if f.get("src_ip") else ""
        src_ip_display = e(src_ip_raw)
        hunted_badge = (
            ' <span style="color:#f59e0b;font-size:9px" title="Profiled in Attacker Hunting">&#x1F3AF;</span>'
            if src_ip_raw in hunted_set
            else ""
        )

        flagged_rows += (
            f"<tr>"
            f'<td class="ts">{e(ts)}</td>'
            f'<td><span class="cls-pill" style="background:{cb};color:{cc};'
            f'border-color:{cc}44">{e(f["triage_class"])}</span></td>'
            f'<td class="num">{f.get("novelty_score", 0)}</td>'
            f'<td class="num">{f.get("confidence", 0)}%</td>'
            f"<td>{zday_html}</td>"
            f'<td class="trunc" title="{e(f.get("reasoning", ""))}">{e((f.get("reasoning") or "")[:80])}</td>'
            f'<td class="mono dim">{_cve_badge(f.get("known_cve"), f.get("cve_details"))}</td>'
            f'<td style="color:{rev_color}">{reviewed}</td>'
            f'<td class="ip" style="cursor:pointer" onclick="window.location.href=\'/events_ip/{src_ip_display}?format=html\'">{src_ip_display}{hunted_badge}</td>'
            f'<td class="mono" style="cursor:pointer;color:var(--accent)" '
            f"onclick=\"window.open('/event_full/{full_eid}?format=html','_blank')\" "
            f'title="{full_eid}">{eid}…</td>'
            f"<td>"
            f'<button class="btn-sm btn-approve" onclick="aiFeedback(\'{full_eid}\',\'tp\',this)" title="True Positive">&#x2714; TP</button> '
            f'<button class="btn-sm btn-danger" onclick="aiFeedback(\'{full_eid}\',\'fp\',this)" title="False Positive">&#x2718; FP</button> '
            f'<button class="btn-sm" style="color:#a78bfa;border-color:#a78bfa44" '
            f"onclick=\"aiReAnalyze('{full_eid}',this)\">&#x1F9E0;</button> "
            f'<button class="btn-sm btn-claude" style="color:#d97706;border-color:#d9770644;display:none" '
            f"onclick=\"claudeAnalyze('{full_eid}',this)\">&#x1F52C;</button>"
            f'<button class="btn-sm btn-blog" style="color:#06b6d4;border-color:#06b6d444;display:none" '
            f'onclick="publishBlog(\'{src_ip_raw}\',this)" title="Publish to blog">&#x1F4DD;</button>'
            f"</td>"
            f"</tr>"
        )
    if not flagged_rows:
        flagged_rows = '<tr><td colspan="11" class="empty">No flagged events yet</td></tr>'

    # ── Full event log rows ──────────────────────────────────────────────
    event_rows = ""
    for ev in data["events"]:
        cls = str(ev.get("triage_class") or "NOISE").upper()
        cc = cls_c(cls)
        cb = cls_b(cls)
        ts = (ev.get("timestamp") or "")[:19].replace("T", " ")
        full_eid = e(ev.get("event_id") or "")
        eid = e((ev.get("event_id") or "")[:12])
        proto = e((ev.get("protocol") or "").upper())
        port = ev.get("dst_port") or ""
        novelty = ev.get("novelty", 0) or 0
        conf = ev.get("confidence", 0) or 0
        dur = ev.get("duration_ms") or 0
        reasoning = e((ev.get("reasoning") or "")[:60])
        cve_raw = ev.get("cve") or ""
        cve_details_ev = ev.get("cve_details")
        zday = ev.get("zero_day") or ""
        rule = e(ev.get("suggested_rule") or "")
        mitre = e(ev.get("suggested_mitre") or "")
        atk = e((ev.get("attack_types") or "")[:30])
        src_ip_raw = (ev.get("src_ip") or "").split("/")[0] if ev.get("src_ip") else ""
        src_display = e(src_ip_raw)
        hunted_badge = (
            ' <span style="color:#f59e0b;font-size:9px" title="Profiled in Attacker Hunting">&#x1F3AF;</span>'
            if src_ip_raw in hunted_set
            else ""
        )
        reviewed = "✔" if ev.get("reviewed") else ""

        # Novelty colour
        if novelty >= 7:
            n_color = "#ef4444"
        elif novelty >= 5:
            n_color = "#f97316"
        elif novelty >= 3:
            n_color = "#eab308"
        else:
            n_color = "#64748b"

        event_rows += (
            f'<tr data-cls="{cls}">'
            f'<td class="ts">{e(ts)}</td>'
            f'<td><span class="cls-pill" style="background:{cb};color:{cc};'
            f'border-color:{cc}44">{cls}</span></td>'
            f'<td style="color:{n_color};font-weight:700;text-align:center">{novelty}</td>'
            f'<td class="num">{conf}%</td>'
            f'<td class="trunc" title="{e(ev.get("reasoning") or "")}">{reasoning}</td>'
            f'<td class="mono">{_cve_badge(cve_raw, cve_details_ev)}</td>'
            f'<td class="dim">{proto}</td>'
            f'<td class="dim">{port}</td>'
            f'<td class="ip" style="cursor:pointer" onclick="window.location.href=\'/events_ip/{src_display}?format=html\'">{src_display}{hunted_badge}</td>'
            f'<td class="trunc dim">{atk}</td>'
            f'<td class="purple trunc">{rule}</td>'
            f'<td class="dim">{mitre}</td>'
            f'<td class="dim">{dur}ms</td>'
            f'<td class="dim">{reviewed}</td>'
            f'<td class="mono" style="cursor:pointer;color:var(--accent)" '
            f"onclick=\"window.open('/event_full/{full_eid}?format=html','_blank')\" "
            f'title="{full_eid}">{eid}…</td>'
            f"<td>"
            f'<button class="btn-sm btn-claude" style="color:#d97706;border-color:#d9770644;display:none" '
            f"onclick=\"claudeAnalyze('{full_eid}',this)\">&#x1F52C;</button>"
            f"</td>"
            f"</tr>"
        )
    if not event_rows:
        event_rows = '<tr><td colspan="16" class="empty">No events analysed yet</td></tr>'

    # ── Critical alerts ──────────────────────────────────────────────────
    crit_badge = ""
    if s["critical"]:
        crit_badge = f'<div class="badge-crit">&#9888; {s["critical"]:,} CRITICAL</div>'
    zday_badge = ""
    if s["zero_day_candidates"]:
        zday_badge = f'<div class="badge-crit" style="background:#f43f5e20;border-color:#f43f5e;color:#f43f5e">&#x1F9E0; {s["zero_day_candidates"]:,} 0-DAY CANDIDATES</div>'

    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, page_header_html

    _header = page_header_html(
        "AI Analysis",
        eyebrow="Detection",
        description="Model triage, deep analysis, suggested rules, and cost.",
        actions=(
            '<button class="btn" onclick="window.location.reload()">&#x1F504; Refresh</button>',
        ),
    )
    _subnav = ai_subnav("overview")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Analysis — HoneyLens</title>
<style>
{SHARED_CSS}
/* AI-specific styles */
.cls-bar{{height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;margin-bottom:18px;display:flex}}
.cls-pill{{padding:2px 8px;border-radius:4px;font-weight:700;font-size:11px;border:1px solid;white-space:nowrap}}
.sec-title{{font-size:16px;font-weight:800;color:var(--text);margin:20px 0 12px;display:flex;align-items:center;gap:8px}}
.badge-crit{{display:inline-block;background:#ef444420;border:1px solid #ef4444;color:#ef4444;padding:4px 12px;border-radius:6px;font-weight:700;font-size:12px;margin:0 6px 12px 0;animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.6}}}}
.filter-btn{{padding:4px 10px;border-radius:4px;border:1px solid var(--border);background:var(--bg3);color:var(--text2);cursor:pointer;font-size:11px;font-family:inherit}}
.filter-btn:hover,.filter-btn.active{{background:var(--bg4);color:var(--text);border-color:var(--accent)}}
.scroll-table{{max-height:600px;overflow-y:auto}}
.btn-sm{{padding:2px 6px;border-radius:4px;border:1px solid;background:transparent;cursor:pointer;font-size:11px;font-family:inherit;transition:all .15s}}
.btn-sm:hover{{filter:brightness(1.3)}}
.btn-approve{{background:#22c55e20;color:#22c55e;border-color:#22c55e44}}
.btn-danger{{background:#ef444420;color:#ef4444;border-color:#ef444444}}
.toast{{position:fixed;bottom:20px;right:20px;padding:10px 16px;border-radius:6px;font-size:12px;z-index:999;opacity:0;transition:opacity .3s}}
.toast.ok{{background:#22c55e20;border:1px solid #22c55e;color:#22c55e;opacity:1}}
.toast.err{{background:#ef444420;border:1px solid #ef4444;color:#ef4444;opacity:1}}
.regex-cell{{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono);font-size:11px}}
.num{{text-align:right;font-variant-numeric:tabular-nums}}
.purple{{color:#a78bfa}}
</style>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to content</a>
{nav_bar_html("ai")}
<div class="page" id="main-content" role="main">
{_header}
{_subnav}
  {crit_badge}{zday_badge}
  <div class="kpi-grid">{kpi_html}</div>
  <div class="cls-bar">{cls_bar}</div>

  {claude_stats_html}
  {model_compare_html}
  {ip_cost_html}

  <div class="sec-title">&#x1F6A8; Flagged Events (Suspicious + Critical)
    <span style="font-size:10px;color:#64748b;font-weight:400;margin-left:8px">Use TP/FP buttons to build accuracy data</span></div>
  <div class="panel">
    <div class="panel-hdr">Analyst Review Queue
      <span class="panel-cnt">{len(data["flagged"])} events</span></div>
    <div class="scroll-table">
    <table>
      <thead><tr>
        <th>Time</th><th>Class</th><th>Nov</th><th>Conf</th>
        <th>0-Day</th><th>Reasoning</th><th>CVE</th>
        <th>Rev</th><th>Source IP</th><th>Event</th><th>Actions</th>
      </tr></thead>
      <tbody>{flagged_rows}</tbody>
    </table>
    </div>
  </div>

  <div class="sec-title" style="margin-top:24px">&#x1F50D; Full Analysis Log</div>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterCls('')">All</button>
    <button class="filter-btn" onclick="filterCls('CRITICAL')" style="color:#ef4444">Critical</button>
    <button class="filter-btn" onclick="filterCls('SUSPICIOUS')" style="color:#f97316">Suspicious</button>
    <button class="filter-btn" onclick="filterCls('KNOWN')" style="color:#38bdf8">Known</button>
    <button class="filter-btn" onclick="filterCls('NOISE')" style="color:#64748b">Noise</button>
    <button class="filter-btn" onclick="filterKev()" style="color:#ef4444;font-weight:700">KEV Only</button>
  </div>
  <div class="panel">
    <div class="panel-hdr">AI Triage Results
      <span class="panel-cnt">{len(data["events"])} events</span></div>
    <div class="scroll-table" style="max-height:700px">
    <table>
      <thead><tr>
        <th>Time</th><th>Class</th><th>Nov</th><th>Conf</th>
        <th>Reasoning</th><th>CVE</th><th>Proto</th><th>Port</th>
        <th>Source</th><th>Attacks</th><th>Rule Suggestion</th>
        <th>MITRE</th><th>Time</th><th>Rev</th><th>Event</th><th>Actions</th>
      </tr></thead>
      <tbody id="logBody">{event_rows}</tbody>
    </table>
    </div>
  </div>
</div>

<script>
var activeFilter = '';
function filterCls(cls) {{
  activeFilter = cls;
  var rows = document.querySelectorAll('#logBody tr');
  rows.forEach(function(r) {{
    if (!cls || r.dataset.cls === cls) {{
      r.style.display = '';
    }} else {{
      r.style.display = 'none';
    }}
  }});
  document.querySelectorAll('.filter-btn').forEach(function(b) {{
    b.classList.toggle('active', b.textContent.trim().toUpperCase().startsWith(cls) || (!cls && b.textContent.trim() === 'All'));
  }});
}}
function filterKev() {{
  var rows = document.querySelectorAll('#logBody tr');
  rows.forEach(function(r) {{
    r.style.display = r.innerHTML.indexOf('KEV') > -1 ? '' : 'none';
  }});
  document.querySelectorAll('.filter-btn').forEach(function(b) {{
    b.classList.toggle('active', b.textContent.trim() === 'KEV Only');
  }});
}}
// JSON link
document.getElementById('jsonLink').href = '/ai/stats';

/* AI Deep availability — show btn-claude buttons (any configured backend) */
fetch('/ai/deep-status', {{credentials:'same-origin'}})
  .then(function(r){{ return r.json(); }})
  .then(function(d){{
    if (d.available) {{
      var btns = document.querySelectorAll('.btn-claude');
      for (var i = 0; i < btns.length; i++) btns[i].style.display = 'inline-block';
    }}
  }}).catch(function(){{}});

/* Blog availability — show btn-blog buttons */
fetch('/blog/status', {{credentials:'same-origin'}})
  .then(function(r){{ return r.json(); }})
  .then(function(d){{
    if (d.available) {{
      var btns = document.querySelectorAll('.btn-blog');
      for (var i = 0; i < btns.length; i++) btns[i].style.display = 'inline-block';
    }}
  }}).catch(function(){{}});

function publishBlog(ip, btn) {{
  if (!confirm('Publish threat advisory for ' + ip + ' to the blog?')) return;
  btn.disabled = true; btn.innerHTML = '&#x23F3;'; btn.style.color = '#eab308';
  fetch('/blog/publish/' + encodeURIComponent(ip), {{method:'POST',credentials:'same-origin'}})
    .then(function(r) {{ return r.json().then(function(d) {{ return {{ok:r.ok, data:d}}; }}); }})
    .then(function(res) {{
      if (res.ok) {{
        btn.innerHTML = '&#x2705;'; btn.style.color = '#22c55e';
        setTimeout(function() {{ btn.innerHTML = '&#x1F4DD;'; btn.style.color='#06b6d4'; btn.disabled=false; }}, 3000);
      }} else {{
        btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
        setTimeout(function() {{ btn.innerHTML = '&#x1F4DD;'; btn.style.color='#06b6d4'; btn.disabled=false; }}, 4000);
      }}
    }})
    .catch(function() {{
      btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
      setTimeout(function() {{ btn.innerHTML = '&#x1F4DD;'; btn.style.color='#06b6d4'; btn.disabled=false; }}, 4000);
    }});
}}

function claudeAnalyze(eventId, btn) {{
  btn.disabled = true; btn.innerHTML = '&#x23F3;'; btn.style.color = '#eab308';
  fetch('/ai/deep-analyze/' + encodeURIComponent(eventId), {{method:'POST',credentials:'same-origin'}})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      if (data.detail || data.error) {{
        btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
        setTimeout(function() {{ btn.innerHTML = '&#x1F52C;'; btn.style.color='#d97706'; btn.disabled=false; }}, 5000);
        return;
      }}
      var v = data.verdict || '?';
      var vc = {{'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e','INFO':'#38bdf8'}}[v] || '#94a3b8';
      btn.innerHTML = '&#x1F52C; ' + v; btn.style.color = vc; btn.disabled = false;
    }})
    .catch(function() {{
      btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
      setTimeout(function() {{ btn.innerHTML = '&#x1F52C;'; btn.style.color='#d97706'; btn.disabled=false; }}, 5000);
    }});
}}

function aiFeedback(eventId, fb, btn) {{
  btn.disabled = true;
  var label = fb === 'tp' ? 'True Positive' : 'False Positive';
  fetch('/ai/feedback/' + encodeURIComponent(eventId), {{
    method: 'POST', credentials: 'same-origin',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{feedback: fb}})
  }})
  .then(function(r) {{ return r.json(); }})
  .then(function(d) {{
    if (d.error) {{
      btn.style.color = '#ef4444'; btn.innerHTML = '&#x274C;';
      setTimeout(function() {{ btn.disabled = false; btn.innerHTML = fb==='tp'?'&#x2714; TP':'&#x2718; FP'; }}, 3000);
      return;
    }}
    // Update both buttons in the row
    var row = btn.closest('tr');
    var tpBtn = row.querySelector('.btn-approve');
    var fpBtn = row.querySelector('.btn-danger');
    if (fb === 'tp') {{
      btn.innerHTML = '&#x2714; TP'; btn.style.color = '#22c55e'; btn.style.fontWeight = '700';
      if (fpBtn) {{ fpBtn.style.opacity = '0.3'; fpBtn.disabled = true; }}
    }} else {{
      btn.innerHTML = '&#x2718; FP'; btn.style.color = '#ef4444'; btn.style.fontWeight = '700';
      if (tpBtn) {{ tpBtn.style.opacity = '0.3'; tpBtn.disabled = true; }}
    }}
    // Update reviewed column
    var cells = row.querySelectorAll('td');
    for (var i = 0; i < cells.length; i++) {{
      if (cells[i].textContent.trim() === '⚠') {{
        cells[i].textContent = '✔';
        cells[i].style.color = '#22c55e';
        break;
      }}
    }}
  }})
  .catch(function() {{
    btn.style.color = '#ef4444'; btn.innerHTML = '&#x274C;';
    setTimeout(function() {{ btn.disabled = false; btn.innerHTML = fb==='tp'?'&#x2714; TP':'&#x2718; FP'; }}, 3000);
  }});
}}

function aiReAnalyze(eventId, btn) {{
  btn.disabled = true; btn.innerHTML = '&#x23F3;'; btn.style.color = '#eab308';
  fetch('/ai/analyze/' + encodeURIComponent(eventId), {{method:'POST',credentials:'same-origin'}})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      if (data.detail) {{
        btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
        setTimeout(function() {{ btn.innerHTML = '&#x1F9E0;'; btn.style.color='#a78bfa'; btn.disabled=false; }}, 4000);
        return;
      }}
      var cls = data.triage_class || '?';
      var cc = {{'CRITICAL':'#ef4444','SUSPICIOUS':'#f97316','KNOWN':'#38bdf8','NOISE':'#64748b'}}[cls] || '#94a3b8';
      btn.innerHTML = '&#x1F9E0; ' + cls; btn.style.color = cc; btn.disabled = false;
    }})
    .catch(function() {{
      btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
      setTimeout(function() {{ btn.innerHTML = '&#x1F9E0;'; btn.style.color='#a78bfa'; btn.disabled=false; }}, 4000);
    }});
}}
</script>
</body>
</html>"""


def _ai_rules_html() -> str:
    """AI Rule Management dashboard — suggested + custom rules with approve/toggle/delete."""

    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, page_header_html, sortable_table_js

    _nav = nav_bar_html("ai")
    _sort = sortable_table_js()
    _header = page_header_html(
        "Rule Manager",
        eyebrow="Detection · AI Analysis",
        description="Approve AI-suggested detections and manage custom rules.",
        actions=(
            '<a href="/ai/rules/export" class="nav-btn" style="background:#22c55e22;'
            'border-color:#22c55e;color:#22c55e;">&#x1F4E5; Export</a>',
            '<button class="nav-btn" onclick="loadAll()">&#x1F504; Refresh</button>',
            '<button class="nav-btn btn-approve" onclick="reloadClassifier(this)">'
            "&#x26A1; Reload Classifier</button>",
        ),
    )
    _subnav = ai_subnav("rulemgr")

    return (
        """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Rule Management — HoneyLens</title>
<style>
"""
        + SHARED_CSS
        + """
/* Rules page specific */
.btn-approve{background:#22c55e22;border-color:#22c55e;color:#22c55e}
.btn-approve:hover{background:#22c55e44}
.btn-danger{background:#ef444422;border-color:#ef4444;color:#ef4444}
.btn-danger:hover{background:#ef444444}
.btn-toggle{background:#eab30822;border-color:#eab308;color:#eab308}
.sec-title{font-size:16px;font-weight:800;color:var(--text);margin:20px 0 12px;display:flex;align-items:center;gap:8px}
.purple{color:#a78bfa}
.sev-pill{padding:2px 8px;border-radius:4px;font-weight:700;font-size:10px;border:1px solid}
.regex-cell{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  color:var(--orange);font-family:monospace;font-size:10px}
.scroll-table{max-height:500px;overflow-y:auto}
.status-on{color:var(--green);font-weight:700}
.status-off{color:var(--red);font-weight:700}
.badge-approved{background:#22c55e22;color:#22c55e;padding:2px 8px;border-radius:4px;
  font-size:10px;font-weight:700}
.empty{text-align:center;color:var(--text3);padding:24px}
.toast{position:fixed;bottom:20px;right:20px;padding:10px 20px;border-radius:6px;
  font-size:12px;font-weight:700;z-index:1000;display:none;animation:fadeIn .3s}
.toast.ok{background:#22c55e22;border:1px solid #22c55e;color:#22c55e;display:block}
.toast.err{background:#ef444422;border:1px solid #ef4444;color:#ef4444;display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
</style>
</head>
<body>
"""
        + '<a class="skip-link" href="#main-content">Skip to content</a>'
        + _nav
        + """
<div class="page" id="main-content" role="main">
"""
        + _header
        + _subnav
        + """
  <div class="sec-title">&#x1F9E0; AI-Suggested Rules (pending approval)</div>
  <div class="panel">
    <div class="panel-hdr" style="color:var(--purple)">Suggestions from AI Deep Analysis
      <span class="panel-cnt" id="sugCount">loading...</span></div>
    <div class="scroll-table">
      <table>
        <thead><tr>
          <th>Rule Name</th><th>Regex Pattern</th><th>Class</th><th>Nov</th>
          <th>MITRE</th><th>Protocol</th><th>Source IP</th><th>Reasoning</th>
          <th>Status</th><th>Action</th>
        </tr></thead>
        <tbody id="sugBody"><tr><td colspan="10" class="empty">Loading...</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="sec-title" style="margin-top:24px">&#x2705; Approved Custom Rules (active in classifier)</div>
  <div class="panel">
    <div class="panel-hdr" style="color:var(--green)">Custom Rules
      <span class="panel-cnt" id="custCount">loading...</span></div>
    <div class="scroll-table">
      <table>
        <thead><tr>
          <th>ID</th><th>Rule Name</th><th>Attack Type</th><th>Regex Pattern</th>
          <th>Severity</th><th>MITRE</th><th>Enabled</th><th>Approved</th>
          <th>Actions</th>
        </tr></thead>
        <tbody id="custBody"><tr><td colspan="9" class="empty">Loading...</td></tr></tbody>
      </table>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
function esc(v) {
  if (v == null) return '';
  return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function toast(msg, ok) {
  var t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast ' + (ok ? 'ok' : 'err');
  setTimeout(function() { t.className = 'toast'; }, 3000);
}

var sevColors = {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#22c55e'};
var clsColors = {CRITICAL:'#ef4444',SUSPICIOUS:'#f97316',KNOWN:'#38bdf8',NOISE:'#64748b'};

function sevPill(s) {
  var c = sevColors[s] || '#94a3b8';
  return '<span class="sev-pill" style="background:'+c+'20;color:'+c+';border-color:'+c+'44">'+esc(s)+'</span>';
}
function clsPill(s) {
  var c = clsColors[(s||'').toUpperCase()] || '#94a3b8';
  return '<span class="sev-pill" style="background:'+c+'20;color:'+c+';border-color:'+c+'44">'+esc(s)+'</span>';
}

async function loadSuggested(preloaded) {
  try {
    var data = preloaded || (await (await fetch('/ai/rules/suggested', {credentials:'same-origin'})).json());
    var rules = data.rules || [];
    document.getElementById('sugCount').textContent = rules.length + ' suggestions';
    if (!rules.length) {
      document.getElementById('sugBody').innerHTML = '<tr><td colspan="10" class="empty">No AI rule suggestions yet. Run deep analysis on suspicious events.</td></tr>';
      return;
    }
    var html = '';
    for (var r of rules) {
      html += '<tr>';
      html += '<td class="mono" style="color:var(--purple)">' + esc(r.suggested_rule_name) + '</td>';
      html += '<td class="regex-cell" title="' + esc(r.suggested_rule_regex) + '">' + esc(r.suggested_rule_regex) + '</td>';
      html += '<td>' + clsPill(r.triage_class) + '</td>';
      html += '<td style="text-align:center;color:' + (r.novelty_score >= 7 ? '#ef4444' : r.novelty_score >= 5 ? '#f97316' : '#64748b') + ';font-weight:700">' + (r.novelty_score || 0) + '</td>';
      html += '<td class="mono dim">' + esc(r.suggested_mitre || '—') + '</td>';
      html += '<td class="dim">' + esc((r.protocol || '').toUpperCase()) + '</td>';
      html += '<td class="mono" style="color:var(--accent)">' + esc(r.src_ip || '') + '</td>';
      html += '<td class="dim" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(r.triage_reasoning) + '">' + esc((r.triage_reasoning || '').substring(0, 80)) + '</td>';
      if (r.already_approved) {
        html += '<td><span class="badge-approved">&#x2705; Approved</span></td>';
        html += '<td class="dim">—</td>';
      } else {
        html += '<td class="dim">Pending</td>';
        html += '<td style="white-space:nowrap">'
            + '<button class="btn btn-approve" data-eid="' + esc(r.event_id) + '" onclick="approveRule(this.dataset.eid,this)">&#x2705; Approve</button> '
            + '<button class="btn btn-danger" style="font-size:10px;padding:3px 8px" data-eid="' + esc(r.event_id) + '" onclick="rejectRule(this.dataset.eid,this)">&#x274C; Reject</button>'
            + '</td>';
      }
      html += '</tr>';
    }
    document.getElementById('sugBody').innerHTML = html;
  } catch(e) {
    document.getElementById('sugBody').innerHTML = '<tr><td colspan="10" class="empty">Error loading suggestions</td></tr>';
  }
}

async function loadCustom(preloaded) {
  try {
    var data = preloaded || (await (await fetch('/ai/rules/custom', {credentials:'same-origin'})).json());
    var rules = data.rules || [];
    document.getElementById('custCount').textContent = rules.length + ' rules';
    if (!rules.length) {
      document.getElementById('custBody').innerHTML = '<tr><td colspan="9" class="empty">No custom rules yet. Approve AI suggestions above.</td></tr>';
      return;
    }
    var html = '';
    for (var r of rules) {
      var ts = r.approved_at ? r.approved_at.replace('T', ' ').substring(0, 16) : '—';
      html += '<tr>';
      html += '<td class="dim">' + r.id + '</td>';
      html += '<td class="mono" style="color:var(--green)">' + esc(r.rule_name) + '</td>';
      html += '<td class="dim">' + esc(r.attack_type) + '</td>';
      html += '<td class="regex-cell" title="' + esc(r.regex_pattern) + '">' + esc(r.regex_pattern) + '</td>';
      html += '<td>' + sevPill(r.severity) + '</td>';
      html += '<td class="mono dim">' + esc(r.mitre_technique || '—') + '</td>';
      html += '<td class="' + (r.enabled ? 'status-on' : 'status-off') + '">' + (r.enabled ? 'ON' : 'OFF') + '</td>';
      html += '<td class="dim" style="font-size:10px">' + esc(ts) + '</td>';
      html += '<td>';
      html += '<button class="btn btn-toggle" style="font-size:10px;padding:3px 8px" onclick="toggleRule(' + r.id + ',this)">' + (r.enabled ? 'Disable' : 'Enable') + '</button> ';
      html += '<button class="btn btn-danger" style="font-size:10px;padding:3px 8px" data-rid="' + r.id + '" data-rname="' + esc(r.rule_name) + '" onclick="deleteRule(this.dataset.rid,this.dataset.rname)">Delete</button>';
      html += '</td>';
      html += '</tr>';
    }
    document.getElementById('custBody').innerHTML = html;
  } catch(e) {
    document.getElementById('custBody').innerHTML = '<tr><td colspan="9" class="empty">Error loading custom rules</td></tr>';
  }
}

async function approveRule(eventId, btn) {
  btn.disabled = true;
  btn.textContent = 'Approving...';
  try {
    var res = await fetch('/ai/rules/approve', {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({event_id: eventId})
    });
    var data = await res.json();
    if (data.detail) {
      toast(data.detail, false);
      btn.textContent = 'Error';
      btn.disabled = false;
      return;
    }
    toast('Rule approved: ' + data.rule_name, true);
    btn.innerHTML = '&#x2705; Done';
    btn.className = 'btn';
    btn.style.color = '#22c55e';
    loadCustom();  // refresh custom rules table
  } catch(e) {
    toast('Error: ' + e.message, false);
    btn.textContent = 'Retry';
    btn.disabled = false;
  }
}

async function rejectRule(eventId, btn) {
  if (!confirm('Reject this suggested rule? It will be removed from the suggestions list.')) return;
  btn.disabled = true;
  btn.textContent = 'Rejecting...';
  try {
    var res = await fetch('/ai/rules/reject', {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({event_id: eventId})
    });
    var data = await res.json();
    if (data.detail) {
      toast(data.detail, false);
      btn.textContent = 'Error';
      btn.disabled = false;
      return;
    }
    toast('Rule rejected and dismissed', true);
    // Remove the row from the table
    var row = btn.closest('tr');
    if (row) row.remove();
    // Update count
    var countEl = document.getElementById('sugCount');
    if (countEl) {
      var rows = document.querySelectorAll('#sugBody tr');
      countEl.textContent = rows.length + ' suggestions';
    }
  } catch(e) {
    toast('Error: ' + e.message, false);
    btn.textContent = 'Retry';
    btn.disabled = false;
  }
}

async function toggleRule(ruleId, btn) {
  btn.disabled = true;
  try {
    var res = await fetch('/ai/rules/custom/' + ruleId + '/toggle', {
      method: 'POST', credentials: 'same-origin'
    });
    var data = await res.json();
    toast(data.rule_name + ': ' + (data.enabled ? 'ENABLED' : 'DISABLED'), true);
    loadCustom();
  } catch(e) {
    toast('Error toggling rule', false);
    btn.disabled = false;
  }
}

async function deleteRule(ruleId, name) {
  if (!confirm('Delete rule "' + name + '"? This cannot be undone.')) return;
  try {
    var res = await fetch('/ai/rules/custom/' + ruleId, {
      method: 'DELETE', credentials: 'same-origin'
    });
    var data = await res.json();
    toast('Deleted: ' + data.deleted, true);
    loadAll();
  } catch(e) {
    toast('Error deleting rule', false);
  }
}

async function loadAll() {
  try {
    var res = await fetch('/ai/rules/all', {credentials:'same-origin'});
    var data = await res.json();
    loadSuggested(data.suggested || {rules:[], count:0});
    loadCustom(data.custom || {rules:[], count:0});
  } catch(e) {
    loadSuggested();
    loadCustom();
  }
}

async function reloadClassifier(btn) {
  btn.disabled = true;
  btn.textContent = 'Reloading...';
  try {
    var res = await fetch('/ai/rules/reload', {method:'POST', credentials:'same-origin'});
    var data = await res.json();
    if (data.status === 'reloaded') {
      toast('Classifier reloaded: ' + data.custom_rules_loaded + ' custom rules active', true);
      btn.textContent = '⚡ Reloaded (' + data.custom_rules_loaded + ')';
    } else {
      toast('Reload error: ' + (data.detail || 'unknown'), false);
      btn.textContent = '⚡ Reload Classifier';
    }
  } catch(e) {
    toast('Reload failed: ' + e.message, false);
    btn.textContent = '⚡ Reload Classifier';
  }
  btn.disabled = false;
}

loadAll();

/* AI Deep Analysis availability check (any configured backend) */
(function() {
  fetch('/ai/deep-status', {credentials:'same-origin'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (d.available) {
        var btns = document.querySelectorAll('.btn-claude');
        for (var i = 0; i < btns.length; i++) btns[i].style.display = 'inline-block';
      }
    })
    .catch(function(){});
})();

function claudeAnalyze(eventId, btn) {
  btn.disabled = true; btn.innerHTML = '&#x23F3;'; btn.style.color = '#eab308';
  fetch('/ai/deep-analyze/' + encodeURIComponent(eventId), {method:'POST',credentials:'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.detail || data.error) {
        btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
        btn.title = data.detail || data.error || '';
        setTimeout(function() { btn.innerHTML = '&#x1F52C;'; btn.style.color='#d97706'; btn.disabled=false; btn.title='AI DEEP'; }, 5000);
        return;
      }
      var v = data.verdict || '?';
      var vc = {'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e','INFO':'#38bdf8'}[v] || '#94a3b8';
      btn.innerHTML = '&#x1F52C; ' + v; btn.style.color = vc; btn.disabled = false;
      var _b = (data._backend || 'AI').toUpperCase();
      btn.title = _b + ': ' + v + ' (' + (data.confidence||'?') + '%) \u2014 ' + (data.attack_type||'') + (data.cve ? ' \u2014 ' + data.cve : '');
    })
    .catch(function(err) {
      btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
      setTimeout(function() { btn.innerHTML = '&#x1F52C;'; btn.style.color='#d97706'; btn.disabled=false; }, 5000);
    });
}

function aiReAnalyze(eventId, btn) {
  btn.disabled = true; btn.innerHTML = '&#x23F3;'; btn.style.color = '#eab308';
  fetch('/ai/analyze/' + encodeURIComponent(eventId), {method:'POST',credentials:'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.detail) {
        btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
        setTimeout(function() { btn.innerHTML = '&#x1F9E0;'; btn.style.color='#a78bfa'; btn.disabled=false; }, 4000);
        return;
      }
      var cls = data.triage_class || '?';
      var cc = {'CRITICAL':'#ef4444','SUSPICIOUS':'#f97316','KNOWN':'#38bdf8','NOISE':'#64748b'}[cls] || '#94a3b8';
      btn.innerHTML = '&#x1F9E0; ' + cls; btn.style.color = cc; btn.disabled = false;
      btn.title = 'AI: ' + cls + ' (' + (data.confidence||0) + '%)';
    })
    .catch(function(err) {
      btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
      setTimeout(function() { btn.innerHTML = '&#x1F9E0;'; btn.style.color='#a78bfa'; btn.disabled=false; }, 4000);
    });
}

</script>
"""
        + _sort
        + """
</body>
</html>"""
    )
