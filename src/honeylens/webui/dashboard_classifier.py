"""
webui/dashboard_classifier.py — Attack Classifier Dashboard
=============================================================
Full classifier dashboard with rule stats, threat heatmap, severity
breakdown, attack type distribution, and rule browser.
Compatible with Python 3.9+.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

from honeylens.webui.shared import (
    SHARED_CSS,
    drawer_html,
    esc,
    nav_bar_html,
    page_header_html,
    sortable_table_js,
    subnav_html,
)

# Shared Classifier-section secondary navigation — related detection views.
CLASSIFIER_SUBNAV = [
    ("stats", "/classifier/stats", "Stats"),
    ("threats", "/classifier/top-threats", "Top Threats"),
    ("rules", "/classifier/rules", "Rules"),
    ("analyze", "/classifier/analyze", "Analyze"),
]


def classifier_subnav(active: str = "") -> str:
    return subnav_html(CLASSIFIER_SUBNAV, active=active)


def register_routes(app: FastAPI) -> None:
    """Classifier routes are served by api.py — this module
    provides the HTML rendering functions only."""
    pass


def classifier_dashboard_html(
    stats: dict,
    threats: list,
    rules_by_type: dict,
    rule_perf: list | None = None,
    rule_trend: list | None = None,
) -> str:
    """Render the full classifier dashboard with tabs."""

    total_rules = stats.get("total_rules", 0)
    builtin = stats.get("builtin_rules", 0)
    custom = stats.get("custom_rules", 0)
    atk_types = stats.get("attack_types", 0)
    by_sev = stats.get("by_severity", {})
    by_type = stats.get("by_type", {})
    custom_names = stats.get("custom_rule_names", [])

    _sev_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#22c55e",
        "info": "#38bdf8",
    }

    # Severity donut data
    sev_total = sum(by_sev.values()) or 1
    sev_bars = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = by_sev.get(sev, 0)
        pct = count / sev_total * 100
        c = _sev_colors.get(sev, "#64748b")
        if count:
            sev_bars += (
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">'
                f'<div style="width:80px;font-size:11px;font-weight:700;color:{c};text-transform:uppercase">{sev}</div>'
                f'<div style="flex:1;height:20px;background:#1e293b;border-radius:3px;overflow:hidden;position:relative">'
                f'<div style="width:{pct}%;height:100%;background:{c}40;border-left:3px solid {c};border-radius:3px"></div>'
                f'<span style="position:absolute;right:8px;top:2px;font-size:10px;color:#e2e8f0;font-weight:600">{count}</span>'
                f"</div>"
                f'<div style="width:40px;text-align:right;font-size:11px;color:{c}">{pct:.0f}%</div>'
                f"</div>"
            )

    # Attack type distribution — top 20 as horizontal bars
    sorted_types = sorted(by_type.items(), key=lambda x: -x[1])
    max_count = sorted_types[0][1] if sorted_types else 1
    type_bars = ""
    _type_colors = [
        "#ef4444",
        "#f97316",
        "#eab308",
        "#22c55e",
        "#06b6d4",
        "#3b82f6",
        "#8b5cf6",
        "#ec4899",
        "#f472b6",
        "#a78bfa",
        "#34d399",
        "#fbbf24",
        "#fb923c",
        "#38bdf8",
        "#818cf8",
        "#f87171",
        "#4ade80",
        "#facc15",
        "#2dd4bf",
        "#c084fc",
    ]
    for i, (atype, count) in enumerate(sorted_types[:20]):
        pct = count / max_count * 100
        c = _type_colors[i % len(_type_colors)]
        type_bars += (
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
            f'<div style="width:160px;font-size:10px;font-weight:600;color:{c};'
            f'font-family:var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis"'
            f' title="{esc(atype)}">{esc(atype)}</div>'
            f'<div style="flex:1;height:16px;background:#1e293b;border-radius:2px;overflow:hidden">'
            f'<div style="width:{pct}%;height:100%;background:{c}50;border-radius:2px"></div>'
            f"</div>"
            f'<div style="width:35px;text-align:right;font-size:10px;color:#94a3b8;font-weight:700">{count}</div>'
            f"</div>"
        )

    # Remaining types count
    remaining = len(sorted_types) - 20
    if remaining > 0:
        type_bars += f'<div style="color:#64748b;font-size:10px;margin-top:6px">+{remaining} more attack types</div>'

    # Top threats table
    threat_rows = ""
    for t in (threats or [])[:20]:
        atype = esc(t.get("attack_type", ""))
        count = t.get("count", 0)
        sev = t.get("severity", "medium")
        score = t.get("threat_score", 0)
        sc = _sev_colors.get(sev, "#64748b")
        threat_rows += (
            f"<tr>"
            f'<td><span class="attack-badge">{atype}</span></td>'
            f'<td style="text-align:center;font-weight:700">{count:,}</td>'
            f'<td><span style="color:{sc};font-weight:700;text-transform:uppercase">{esc(sev)}</span></td>'
            f'<td style="text-align:right;font-weight:700;color:var(--accent)">{score:,}</td>'
            f"</tr>"
        )
    if not threat_rows:
        threat_rows = '<tr><td colspan="4" class="empty">No threats detected in last 24h</td></tr>'

    # Rules browser — by attack type
    rules_html = ""
    for atype in sorted(rules_by_type.keys()):
        rules = rules_by_type[atype]
        rules_html += (
            f'<div style="margin-bottom:10px">'
            f'<div style="font-size:11px;font-weight:700;color:var(--accent);margin-bottom:4px;'
            f'cursor:pointer" onclick="this.nextElementSibling.style.display='
            f"this.nextElementSibling.style.display==='none'?'block':'none'"
            f'">{esc(atype)} <span style="color:#64748b;font-weight:400">({len(rules)} rules)</span>'
            f' <span style="font-size:9px;color:#475569">click to expand</span></div>'
            f'<div style="display:none">'
        )
        for r in rules[:20]:
            rname = esc(r.get("rule_name", ""))
            rsev = r.get("severity", "medium")
            rpat = esc(r.get("pattern", "")[:80])
            rc = _sev_colors.get(rsev, "#64748b")
            rules_html += (
                f'<div style="display:flex;gap:8px;align-items:center;padding:3px 0;border-bottom:1px solid #ffffff06">'
                f'<span style="width:10px;height:10px;border-radius:50%;background:{rc};flex-shrink:0"></span>'
                f'<span style="font-family:var(--mono);font-size:10px;color:#e2e8f0;min-width:250px">{rname}</span>'
                f'<span style="font-size:9px;color:#475569;font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{rpat}">{rpat}</span>'
                f"</div>"
            )
        if len(rules) > 20:
            rules_html += f'<div style="color:#64748b;font-size:10px;padding-top:4px">+{len(rules) - 20} more rules</div>'
        rules_html += "</div></div>"

    # ── Performance metrics rows ─────────────────────────────────────────
    perf_rows = ""
    for rp in rule_perf or []:
        rn = esc(rp.get("rule_name", ""))
        at = esc(rp.get("attack_type", ""))
        sev = (rp.get("severity") or "medium").lower()
        sc = _sev_colors.get(sev, "#64748b")
        hits = rp.get("total_hits", 0)
        tp = rp.get("confirmed_true", 0)
        fp = rp.get("confirmed_false", 0)
        tp_rate = rp.get("tp_rate")
        fp_rate = rp.get("fp_rate")
        avg_s = rp.get("avg_score")
        last = str(rp.get("last_hit") or "")[:16].replace("T", " ")
        enabled = rp.get("enabled", True)
        # FP rate coloring: green < 5%, yellow < 20%, red >= 20%
        if fp_rate is not None:
            fp_color = "#22c55e" if fp_rate < 5 else ("#eab308" if fp_rate < 20 else "#ef4444")
            fp_disp = f'<span style="color:{fp_color};font-weight:700">{fp_rate:.1f}%</span>'
            tp_disp = f'<span style="color:#22c55e;font-weight:700">{tp_rate:.1f}%</span>'
        else:
            fp_disp = '<span style="color:#475569">&mdash;</span>'
            tp_disp = '<span style="color:#475569">&mdash;</span>'
        status = (
            '<span style="color:#22c55e">Active</span>'
            if enabled
            else '<span style="color:#ef4444">Disabled</span>'
        )
        avg_disp = f"{avg_s:.1f}" if avg_s else "&mdash;"
        perf_rows += (
            f"<tr>"
            f'<td style="font-family:var(--mono);font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{rn}">{rn}</td>'
            f'<td style="font-size:10px;color:var(--accent)">{at}</td>'
            f'<td><span style="color:{sc};font-weight:700;text-transform:uppercase;font-size:10px">{sev}</span></td>'
            f'<td style="text-align:right;font-weight:700">{hits:,}</td>'
            f'<td style="text-align:right;color:#22c55e">{tp:,}</td>'
            f'<td style="text-align:right;color:#ef4444">{fp:,}</td>'
            f'<td style="text-align:center">{tp_disp}</td>'
            f'<td style="text-align:center">{fp_disp}</td>'
            f'<td style="text-align:center;font-family:var(--mono);color:#94a3b8">{avg_disp}</td>'
            f'<td style="font-size:10px;color:#64748b">{last}</td>'
            f"<td>{status}</td>"
            f"</tr>"
        )
    if not perf_rows:
        perf_rows = '<tr><td colspan="11" class="empty">No rule statistics data yet — rules populate as events are classified</td></tr>'

    # ── Trend chart + rows ──────────────────────────────────────────────
    trend_data = list(reversed(rule_trend or []))  # oldest first for chart
    trend_rows = ""
    for d in rule_trend or []:
        trend_rows += (
            f"<tr>"
            f'<td style="font-weight:600">{d["day"]}</td>'
            f'<td class="num" style="font-weight:700">{d["total"]:,}</td>'
            f'<td class="num" style="color:var(--accent)">{d["unique_rules"]:,}</td>'
            f'<td class="num" style="color:#f97316">{d["unique_types"]:,}</td>'
            f'<td class="num" style="color:#a78bfa">{d["unique_events"]:,}</td>'
            f"</tr>"
        )
    if not trend_rows:
        trend_rows = '<tr><td colspan="5" class="empty">No detection data in last 30 days</td></tr>'

    # SVG trend chart
    trend_chart = ""
    if trend_data:
        chart_w, chart_h = 900, 200
        ml, mb, mt = 55, 28, 10
        n = len(trend_data)
        max_v = max((d.get("total", 0) for d in trend_data), default=1) or 1
        bw = max(4, min(22, (chart_w - ml) // n - 2))
        bars_svg = ""
        xlabels = ""
        for i, d in enumerate(trend_data):
            x = ml + i * (bw + 2)
            total = d.get("total", 0)
            rules = d.get("unique_rules", 0)
            h_total = int((total / max_v) * (chart_h - mb - mt))
            h_rules = int((rules / max_v) * (chart_h - mb - mt)) if rules < total else h_total
            y = chart_h - mb - h_total
            bars_svg += f'<rect x="{x}" y="{y}" width="{bw}" height="{h_total}" fill="#3b82f640" rx="1"><title>{d["day"]}: {total:,} detections, {rules} rules, {d.get("unique_events", 0):,} events</title></rect>'
            if h_rules and h_rules < h_total:
                bars_svg += f'<rect x="{x}" y="{chart_h - mb - h_rules}" width="{bw}" height="{h_rules}" fill="#22d3ee60" rx="1"/>'
            lbl_int = max(1, n // 10)
            if i % lbl_int == 0:
                xlabels += f'<text x="{x + bw // 2}" y="{chart_h - 6}" fill="#64748b" font-size="9" text-anchor="middle">{d["day"][-5:]}</text>'

        yscale = ""
        for frac in [0, 0.25, 0.5, 0.75, 1.0]:
            y = chart_h - mb - int(frac * (chart_h - mb - mt))
            val = int(frac * max_v)
            yscale += f'<line x1="{ml - 4}" y1="{y}" x2="{chart_w}" y2="{y}" stroke="#1e2a3a" stroke-width="0.5"/>'
            yscale += f'<text x="{ml - 6}" y="{y + 3}" fill="#64748b" font-size="9" text-anchor="end">{val:,}</text>'

        legend = (
            f'<rect x="{ml}" y="2" width="10" height="10" fill="#3b82f640" rx="1"/>'
            f'<text x="{ml + 14}" y="10" fill="#94a3b8" font-size="10">Detections</text>'
            f'<rect x="{ml + 100}" y="2" width="10" height="10" fill="#22d3ee60" rx="1"/>'
            f'<text x="{ml + 114}" y="10" fill="#94a3b8" font-size="10">Unique Rules</text>'
        )
        trend_chart = (
            f'<div style="overflow-x:auto;padding:10px 14px">'
            f'<svg width="{chart_w}" height="{chart_h}" style="font-family:monospace;min-width:{chart_w}px">'
            f"{yscale}{bars_svg}{xlabels}{legend}</svg></div>"
        )
    else:
        trend_chart = '<p style="color:#64748b;padding:14px;text-align:center">No trend data</p>'

    # Custom (AI-discovered) rules section
    custom_html = ""
    if custom_names:
        custom_html = '<div class="panel" style="margin-bottom:16px;border-color:#a78bfa44">'
        custom_html += f'<div class="panel-hdr" style="color:#a78bfa">AI-Discovered Rules <span class="panel-cnt">{custom} rules</span></div>'
        custom_html += '<div style="padding:10px">'
        for cn in custom_names:
            custom_html += f'<div style="padding:3px 0"><span style="font-family:var(--mono);font-size:11px;color:#a78bfa">{esc(cn)}</span></div>'
        custom_html += "</div></div>"

    _header = page_header_html(
        "Attack Classifier",
        eyebrow="Detection",
        description=f"{total_rules} detection rules across {atk_types} attack categories.",
        actions=(
            '<a href="/classifier/stats" class="nav-btn">JSON</a>',
            '<a href="/attack/kb" class="nav-btn">Knowledge Base</a>',
        ),
    )

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack Classifier — HoneyLens</title>
<style>{SHARED_CSS}
.cls-tab{{padding:10px 18px;background:none;border:none;color:var(--text3);font-size:12px;
  font-weight:600;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;
  transition:all .15s;font-family:inherit}}
.cls-tab:hover{{color:var(--text);background:var(--bg2)}}
.cls-tab.active{{color:var(--accent);border-bottom-color:var(--accent)}}
.cls-sec{{display:none}}.cls-sec.active{{display:block}}
.attack-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;
  margin:1px;background:#ef444422;color:#f87171;border:1px solid #ef444444;font-family:var(--mono)}}
</style>
</head><body>
<a class="skip-link" href="#main-content">Skip to content</a>
{nav_bar_html("classifier")}
<div id="main-content" role="main" style="padding:14px 22px 0">{_header}</div>

<!-- Sub-navigation -->
<div style="display:flex;gap:0;padding:0 22px;background:var(--bg1);border-bottom:2px solid var(--border)">
  <button class="cls-tab active" onclick="clsTab('overview')" id="ct-overview">Overview</button>
  <button class="cls-tab" onclick="clsTab('performance')" id="ct-performance">&#x1F4CA; Performance</button>
  <button class="cls-tab" onclick="clsTab('trend')" id="ct-trend">&#x1F4C8; Trend</button>
  <button class="cls-tab" onclick="clsTab('test')" id="ct-test">&#x1F9EA; Test Rule</button>
  <button class="cls-tab" onclick="clsTab('threats')" id="ct-threats">Top Threats <span style="background:#ef4444;color:#fff;padding:0 5px;border-radius:8px;font-size:9px;margin-left:4px">{len(threats or [])}</span></button>
  <button class="cls-tab" onclick="clsTab('rules')" id="ct-rules">Rule Browser <span style="background:var(--accent);color:#000;padding:0 5px;border-radius:8px;font-size:9px;margin-left:4px">{total_rules}</span></button>
</div>

<div class="page">

<!-- ═══ OVERVIEW TAB ═══ -->
<div class="cls-sec active" id="sec-overview">

  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-lbl">Total Rules</div>
      <div class="kpi-val" style="color:var(--accent)">{total_rules}</div></div>
    <div class="kpi"><div class="kpi-lbl">Built-in Rules</div>
      <div class="kpi-val" style="color:#38bdf8">{builtin}</div></div>
    <div class="kpi"><div class="kpi-lbl">AI-Discovered</div>
      <div class="kpi-val" style="color:#a78bfa">{custom}</div></div>
    <div class="kpi"><div class="kpi-lbl">Attack Categories</div>
      <div class="kpi-val" style="color:#f97316">{atk_types}</div></div>
    <div class="kpi"><div class="kpi-lbl">Critical Rules</div>
      <div class="kpi-val" style="color:#ef4444">{by_sev.get("critical", 0)}</div></div>
    <div class="kpi"><div class="kpi-lbl">High Rules</div>
      <div class="kpi-val" style="color:#f97316">{by_sev.get("high", 0)}</div></div>
  </div>

  <div class="two-col">
    <div class="panel">
      <div class="panel-hdr">Severity Distribution</div>
      <div style="padding:14px">{sev_bars}</div>
    </div>
    <div class="panel">
      <div class="panel-hdr">Attack Type Distribution <span class="panel-cnt">top 20 of {len(sorted_types)}</span></div>
      <div style="padding:14px;max-height:400px;overflow-y:auto">{type_bars}</div>
    </div>
  </div>

  {custom_html}

</div>

<!-- ═══ TOP THREATS TAB ═══ -->
<div class="cls-sec" id="sec-threats">

  <div class="panel">
    <div class="panel-hdr">Top Threats (Last 24h)
      <span class="panel-cnt">ranked by threat score (count x severity weight)</span></div>
    <div style="overflow-x:auto;max-height:70vh">
    <table>
      <thead><tr>
        <th>Attack Type</th><th>Events</th><th>Severity</th><th>Threat Score</th>
      </tr></thead>
      <tbody>{threat_rows}</tbody>
    </table>
    </div>
  </div>

</div>

<!-- ═══ PERFORMANCE TAB ═══ -->
<div class="cls-sec" id="sec-performance">

  <div class="panel">
    <div class="panel-hdr">Rule Performance Metrics
      <span class="panel-cnt">hit count, true/false positive rates from rule_statistics</span></div>
    <p style="color:#94a3b8;font-size:12px;padding:0 14px 10px;margin:0">
      Rules are tracked in <code>rule_statistics</code>. TP/FP rates require operator confirmation
      via the event detail panel (mark as true/false positive). Rules with no reviewed events show &mdash; for rates.
    </p>
    <div style="overflow-x:auto;max-height:70vh">
    <table>
      <thead><tr>
        <th>Rule Name</th><th>Attack Type</th><th>Severity</th>
        <th>Total Hits</th><th>TP</th><th>FP</th>
        <th>TP Rate</th><th>FP Rate</th><th>Avg Score</th>
        <th>Last Hit</th><th>Status</th>
      </tr></thead>
      <tbody>{perf_rows}</tbody>
    </table>
    </div>
  </div>

</div>

<!-- ═══ TREND TAB ═══ -->
<div class="cls-sec" id="sec-trend">

  <div class="panel">
    <div class="panel-hdr">Detection Trend
      <span class="panel-cnt">30-day detection activity</span></div>
    {trend_chart}
  </div>

  <div class="panel" style="margin-top:12px">
    <div class="panel-hdr">Daily Detection Breakdown</div>
    <div style="overflow-x:auto;max-height:50vh">
    <table>
      <thead><tr>
        <th>Day</th><th>Total Detections</th><th>Unique Rules</th>
        <th>Unique Attack Types</th><th>Unique Events</th>
      </tr></thead>
      <tbody>{trend_rows}</tbody>
    </table>
    </div>
  </div>

</div>

<!-- ═══ TEST RULE TAB ═══ -->
<div class="cls-sec" id="sec-test">

  <div class="panel">
    <div class="panel-hdr">Rule Testing Interface
      <span class="panel-cnt">validate rules against sample payloads</span></div>
    <p style="color:#94a3b8;font-size:12px;padding:0 14px 10px;margin:0">
      Paste a payload sample and select a protocol to test which classifier rules match.
      This runs <code>classify_event_row()</code> in the browser without creating any events.
    </p>
    <div style="padding:0 14px 14px;display:grid;grid-template-columns:1fr 200px;gap:12px">
      <div>
        <label style="color:var(--text2);font-size:11px;display:block;margin-bottom:4px">Payload (text or hex)</label>
        <textarea id="test-payload" rows="6"
          style="width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);
          padding:8px 10px;border-radius:4px;font-family:var(--mono);font-size:12px;resize:vertical"
          placeholder="GET /wp-admin/install.php HTTP/1.1&#10;Host: target.local&#10;User-Agent: Mozilla/5.0"></textarea>
      </div>
      <div>
        <label style="color:var(--text2);font-size:11px;display:block;margin-bottom:4px">Protocol</label>
        <select id="test-proto"
          style="width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);
          padding:6px 10px;border-radius:4px;font-size:12px;margin-bottom:8px">
          <option value="HTTP">HTTP</option>
          <option value="TCP">TCP (generic)</option>
          <option value="SSH">SSH</option>
          <option value="FTP">FTP</option>
          <option value="SMTP">SMTP</option>
          <option value="Telnet">Telnet</option>
          <option value="MySQL">MySQL</option>
          <option value="Redis">Redis</option>
          <option value="MQTT">MQTT</option>
          <option value="Modbus">Modbus</option>
          <option value="S7comm">S7comm</option>
          <option value="DNP3">DNP3</option>
        </select>
        <label style="color:var(--text2);font-size:11px;display:block;margin-bottom:4px">Dest Port (optional)</label>
        <input type="number" id="test-port" placeholder="e.g. 80"
          style="width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);
          padding:6px 10px;border-radius:4px;font-family:var(--mono);font-size:12px;margin-bottom:12px">
        <button onclick="testRule()"
          style="width:100%;padding:10px;background:var(--accent);color:#000;border:none;border-radius:4px;
          font-weight:700;font-size:12px;cursor:pointer">&#x25B6; Run Classifier</button>
      </div>
    </div>
    <div id="test-results" style="padding:0 14px 14px"></div>
  </div>

</div>

<!-- ═══ RULE BROWSER TAB ═══ -->
<div class="cls-sec" id="sec-rules">

  <div style="margin-bottom:10px;color:var(--text3);font-size:11px">
    Click an attack type to expand and see individual detection rules with regex patterns.
    Severity indicated by coloured dot (red=critical, orange=high, yellow=medium, green=low).
  </div>

  <div class="panel">
    <div class="panel-hdr">Detection Rules by Attack Type
      <span class="panel-cnt">{total_rules} rules in {len(rules_by_type)} categories</span></div>
    <div style="padding:14px;max-height:70vh;overflow-y:auto">
      {rules_html}
    </div>
  </div>

</div>

</div><!-- /page -->

<script>
function clsTab(name) {{
  document.querySelectorAll('.cls-sec').forEach(function(s){{ s.classList.remove('active'); }});
  document.querySelectorAll('.cls-tab').forEach(function(t){{ t.classList.remove('active'); }});
  var sec = document.getElementById('sec-' + name);
  var tab = document.getElementById('ct-' + name);
  if (sec) sec.classList.add('active');
  if (tab) tab.classList.add('active');
  history.replaceState(null, '', '#' + name);
}}
(function(){{
  var h = location.hash.replace('#','');
  if (h && document.getElementById('sec-' + h)) clsTab(h);
}})();

function testRule() {{
  var payload = document.getElementById('test-payload').value;
  var proto = document.getElementById('test-proto').value;
  var port = document.getElementById('test-port').value || '';
  var results = document.getElementById('test-results');
  if (!payload.trim()) {{
    results.innerHTML = '<div style="color:#f97316;padding:10px">Enter a payload to test.</div>';
    return;
  }}
  results.innerHTML = '<div style="color:var(--accent);padding:10px">Running classifier...</div>';
  fetch('/classifier/test', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{payload: payload, protocol: proto, dst_port: parseInt(port) || 0}})
  }})
  .then(function(r) {{ return r.json(); }})
  .then(function(d) {{
    if (d.error) {{
      results.innerHTML = '<div style="color:#ef4444;padding:10px">Error: ' + d.error + '</div>';
      return;
    }}
    var hits = d.hits || [];
    if (hits.length === 0) {{
      results.innerHTML = '<div style="color:#22c55e;padding:10px;border:1px solid #22c55e40;border-radius:4px;margin-top:8px">' +
        '&#x2714; No rules matched — payload appears benign for protocol <strong>' + proto + '</strong></div>';
      return;
    }}
    var h = '<div style="border:1px solid #ef444440;border-radius:4px;margin-top:8px;padding:10px">' +
      '<div style="color:#ef4444;font-weight:700;margin-bottom:8px">&#x26A0; ' + hits.length + ' rule(s) matched:</div>' +
      '<table><thead><tr><th>Attack Type</th><th>Rule Name</th><th>Matched Text</th></tr></thead><tbody>';
    hits.forEach(function(hit) {{
      h += '<tr><td><span class="attack-badge">' + (hit[0]||'') + '</span></td>' +
        '<td style="font-family:var(--mono);font-size:10px">' + (hit[1]||'') + '</td>' +
        '<td style="font-size:10px;color:#94a3b8;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + (hit[2]||'').substring(0,100) + '</td></tr>';
    }});
    h += '</tbody></table></div>';
    results.innerHTML = h;
  }})
  .catch(function(e) {{
    results.innerHTML = '<div style="color:#ef4444;padding:10px">Request failed: ' + e + '</div>';
  }});
}}
</script>
{sortable_table_js()}
</body></html>"""


def threats_dashboard_html(threats: list, hours: int = 24) -> str:
    """Render the Threat Landscape dashboard."""
    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, sortable_table_js

    total_events = sum(t.get("count", 0) for t in threats)
    total_score = sum(t.get("threat_score", 0) for t in threats)
    unique_types = len(threats)
    crit = sum(1 for t in threats if t.get("severity") == "critical")
    high = sum(1 for t in threats if t.get("severity") == "high")
    med = sum(1 for t in threats if t.get("severity") == "medium")
    top_threat = threats[0] if threats else {}

    _sc = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#22c55e",
        "info": "#38bdf8",
    }

    # Threat score treemap — proportional blocks
    max_score = threats[0].get("threat_score", 1) if threats else 1
    treemap = ""
    for _i, t in enumerate(threats[:12]):
        atype = esc(t.get("attack_type", ""))
        score = t.get("threat_score", 0)
        count = t.get("count", 0)
        sev = t.get("severity", "medium")
        sc = _sc.get(sev, "#64748b")
        # Size proportional to score (min 80px)
        w = max(80, int(score / max_score * 250))
        treemap += (
            f'<div style="width:{w}px;background:{sc}15;border:1px solid {sc}40;'
            f'border-left:3px solid {sc};border-radius:6px;padding:10px;flex-shrink:0">'
            f'<div style="font-size:10px;font-weight:700;color:{sc};font-family:var(--mono);'
            f'margin-bottom:4px">{atype}</div>'
            f'<div style="font-size:20px;font-weight:800;color:#e2e8f0">{count:,}</div>'
            f'<div style="font-size:9px;color:#64748b">events</div>'
            f'<div style="font-size:11px;font-weight:700;color:{sc};margin-top:4px">Score: {score:,}</div>'
            f"</div>"
        )

    # Severity breakdown donut
    from honeylens.webui.dashboard_cve import _donut_chart

    sev_data = []
    if crit:
        sev_data.append(("CRITICAL", crit, "#ef4444"))
    if high:
        sev_data.append(("HIGH", high, "#f97316"))
    if med:
        sev_data.append(("MEDIUM", med, "#eab308"))
    low_count = sum(1 for t in threats if t.get("severity") == "low")
    if low_count:
        sev_data.append(("LOW", low_count, "#22c55e"))
    donut = _donut_chart(sev_data, unique_types, "Types") if sev_data else ""

    # Event volume bars (proportional)
    vol_bars = ""
    max_count = threats[0].get("count", 1) if threats else 1
    _colors = [
        "#ef4444",
        "#f97316",
        "#eab308",
        "#22c55e",
        "#06b6d4",
        "#3b82f6",
        "#8b5cf6",
        "#ec4899",
        "#f472b6",
        "#a78bfa",
        "#34d399",
        "#fbbf24",
    ]
    for _i, t in enumerate(threats[:15]):
        atype = esc(t.get("attack_type", ""))
        count = t.get("count", 0)
        sev = t.get("severity", "medium")
        sc = _sc.get(sev, "#64748b")
        pct = count / max_count * 100
        vol_bars += (
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
            f'<div style="width:10px;height:10px;border-radius:50%;background:{sc};flex-shrink:0"></div>'
            f'<div style="width:160px;font-size:10px;font-weight:600;color:#e2e8f0;'
            f'font-family:var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis" '
            f'title="{atype}">{atype}</div>'
            f'<div style="flex:1;height:18px;background:#1e293b;border-radius:3px;overflow:hidden;position:relative">'
            f'<div style="width:{max(pct, 1)}%;height:100%;background:{sc}40;border-radius:3px"></div>'
            f'<span style="position:absolute;right:6px;top:1px;font-size:10px;color:#e2e8f0;font-weight:600">{count:,}</span>'
            f"</div>"
            f"</div>"
        )

    # Full table
    table_rows = ""
    for i, t in enumerate(threats):
        atype = esc(t.get("attack_type", ""))
        count = t.get("count", 0)
        sev = t.get("severity", "medium")
        score = t.get("threat_score", 0)
        sc = _sc.get(sev, "#64748b")
        pct_of_total = (count / total_events * 100) if total_events else 0
        # Inline sparkbar
        bar_w = max(1, int(count / max_count * 100))
        table_rows += (
            f"<tr>"
            f'<td style="text-align:center;color:#475569;font-size:10px">{i + 1}</td>'
            f'<td><span style="background:{sc}20;color:{sc};padding:2px 8px;border-radius:4px;'
            f'font-size:10px;font-family:var(--mono);border:1px solid {sc}40">{atype}</span></td>'
            f'<td style="text-align:right;font-weight:700">{count:,}</td>'
            f'<td style="text-align:right;color:#64748b;font-size:11px">{pct_of_total:.1f}%</td>'
            f'<td><span style="color:{sc};font-weight:700;text-transform:uppercase">{esc(sev)}</span></td>'
            f'<td style="text-align:right;font-weight:700;color:var(--accent)">{score:,}</td>'
            f'<td style="width:120px"><div style="height:12px;background:#1e293b;border-radius:2px;overflow:hidden">'
            f'<div style="width:{bar_w}%;height:100%;background:{sc}60;border-radius:2px"></div></div></td>'
            f"</tr>"
        )
    if not table_rows:
        table_rows = '<tr><td colspan="7" class="empty">No threats detected in last 24h</td></tr>'

    _header = page_header_html(
        "Threat Landscape",
        eyebrow="Overview",
        description=f"Attack activity across the last {hours} hours.",
        actions=('<a href="/classifier/stats" class="nav-btn">Classifier</a>',),
    )

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Threat Landscape — HoneyLens</title>
<style>{SHARED_CSS}
.thr-tab{{padding:10px 18px;background:none;border:none;color:var(--text3);font-size:12px;
  font-weight:600;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;
  transition:all .15s;font-family:inherit}}
.thr-tab:hover{{color:var(--text);background:var(--bg2)}}
.thr-tab.active{{color:var(--accent);border-bottom-color:var(--accent)}}
.thr-sec{{display:none}}.thr-sec.active{{display:block}}
</style>
</head><body>
<a class="skip-link" href="#main-content">Skip to content</a>
{nav_bar_html("threats")}
<div id="main-content" role="main" style="padding:14px 22px 0">{_header}</div>

<div style="display:flex;gap:0;padding:0 22px;background:var(--bg1);border-bottom:2px solid var(--border)">
  <button class="thr-tab active" onclick="thrTab('landscape')" id="tt-landscape">Threat Landscape</button>
  <button class="thr-tab" onclick="thrTab('table')" id="tt-table">Full Table <span style="background:var(--accent);color:#000;padding:0 5px;border-radius:8px;font-size:9px;margin-left:4px">{unique_types}</span></button>
</div>

<div class="page">

<!-- ═══ LANDSCAPE TAB ═══ -->
<div class="thr-sec active" id="sec-landscape">

  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-lbl">Total Events</div>
      <div class="kpi-val" style="color:var(--accent)">{total_events:,}</div></div>
    <div class="kpi"><div class="kpi-lbl">Attack Types</div>
      <div class="kpi-val" style="color:#f97316">{unique_types}</div></div>
    <div class="kpi"><div class="kpi-lbl">Total Threat Score</div>
      <div class="kpi-val" style="color:#ef4444">{total_score:,}</div></div>
    <div class="kpi"><div class="kpi-lbl">Top Threat</div>
      <div class="kpi-val" style="color:#f87171;font-size:16px">{esc(top_threat.get("attack_type", "—"))}</div></div>
    <div class="kpi"><div class="kpi-lbl">Critical Types</div>
      <div class="kpi-val" style="color:#ef4444">{crit}</div></div>
    <div class="kpi"><div class="kpi-lbl">High Types</div>
      <div class="kpi-val" style="color:#f97316">{high}</div></div>
  </div>

  <!-- Threat blocks -->
  <div class="panel" style="margin-bottom:14px">
    <div class="panel-hdr">Threat Heatmap <span class="panel-cnt">sized by threat score</span></div>
    <div style="display:flex;flex-wrap:wrap;gap:8px;padding:14px;overflow-x:auto">
      {treemap}
    </div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
    <div class="panel">
      <div class="panel-hdr">Severity Breakdown</div>
      <div style="display:flex;justify-content:center;padding:20px">{donut}</div>
    </div>
    <div class="panel">
      <div class="panel-hdr">Event Volume by Type <span class="panel-cnt">top 15</span></div>
      <div style="padding:14px;max-height:400px;overflow-y:auto">{vol_bars}</div>
    </div>
  </div>

</div>

<!-- ═══ TABLE TAB ═══ -->
<div class="thr-sec" id="sec-table">

  <div class="panel">
    <div class="panel-hdr">All Detected Threats
      <span class="panel-cnt">{unique_types} types, {total_events:,} events</span></div>
    <div style="overflow-x:auto;max-height:70vh">
    <table>
      <thead><tr>
        <th>#</th><th>Attack Type</th><th>Events</th><th>% of Total</th>
        <th>Severity</th><th>Threat Score</th><th>Volume</th>
      </tr></thead>
      <tbody>{table_rows}</tbody>
    </table>
    </div>
  </div>

</div>

</div>

<script>
function thrTab(name) {{
  document.querySelectorAll('.thr-sec').forEach(function(s){{ s.classList.remove('active'); }});
  document.querySelectorAll('.thr-tab').forEach(function(t){{ t.classList.remove('active'); }});
  var sec = document.getElementById('sec-' + name);
  var tab = document.getElementById('tt-' + name);
  if (sec) sec.classList.add('active');
  if (tab) tab.classList.add('active');
  history.replaceState(null, '', '#' + name);
}}
(function(){{
  var h = location.hash.replace('#','');
  if (h && document.getElementById('sec-' + h)) thrTab(h);
}})();
</script>
{sortable_table_js()}
</body></html>"""


# Keep backward compat for simple pages
def _classifier_html_page(title: str, content: str) -> str:
    """Legacy wrapper for simple classifier pages (rules list, etc)."""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} — HoneyLens</title>
<style>{SHARED_CSS}</style></head><body>
<a class="skip-link" href="#main-content">Skip to content</a>
{nav_bar_html("classifier")}
<main id="main-content" class="page">
{page_header_html(title, eyebrow="Detection · Classifier")}
{classifier_subnav()}
{content}
</main>
{drawer_html()}
{sortable_table_js()}
</body></html>"""
