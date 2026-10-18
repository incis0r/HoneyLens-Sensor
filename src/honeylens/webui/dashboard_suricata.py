"""
webui/dashboard_suricata.py — Suricata IDS Dashboard
=====================================================
Dashboard at /suricata/stats showing Suricata alert statistics,
top rules, attack type breakdown, hunting cross-reference, and timeline.

IPs in attacker_profiles (hunting) that also trigger Suricata alerts
are highlighted — these need AI analysis even though Suricata already
classified them (hunting context trumps cost-saving skip).

Compatible with Python 3.9+.
"""

from __future__ import annotations

import html as _html
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


def _esc(v) -> str:
    if v is None:
        return ""
    return _html.escape(str(v).replace("\r", "").replace("\n", " "))


def suricata_dashboard_html(data: dict) -> str:
    """Render the Suricata IDS dashboard HTML."""
    import json as _json

    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, sortable_table_js

    s = data["summary"]
    _sev_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}

    # ── KPI strip ────────────────────────────────────────────────────────────
    kpi_html = ""
    kpis = [
        ("Total Alerts", s["total"], "#38bdf8"),
        ("Last 24 h", s["last_24h"], "#22c55e"),
        ("Last 1 h", s["last_1h"], "#eab308"),
        ("Last 5 min", s["last_5m"], "#f97316"),
        ("Critical", s["critical"], "#ef4444"),
        ("High", s["high"], "#f97316"),
        ("Medium", s["medium"], "#eab308"),
        ("Low", s["low"], "#22c55e"),
        ("Unique SIDs", s["unique_sids"], "#a78bfa"),
        ("Unique Sources", s["unique_src"], "#f472b6"),
        ("Hunting Overlap", s["hunting_overlap"], "#ef4444"),
    ]
    for label, val, color in kpis:
        kpi_html += (
            f'<div class="kpi">'
            f'<div class="kpi-lbl">{label}</div>'
            f'<div class="kpi-val" style="color:{color}">{val:,}</div>'
            f"</div>"
        )

    # ── Severity bar ─────────────────────────────────────────────────────────
    total = max(s["total"], 1)
    sev_bar = ""
    for key, color in [
        ("critical", "#ef4444"),
        ("high", "#f97316"),
        ("medium", "#eab308"),
        ("low", "#22c55e"),
    ]:
        pct = s[key] / total * 100
        if s[key]:
            sev_bar += (
                f'<div style="background:{color};width:{pct:.1f}%;'
                f'height:100%;display:inline-block" '
                f'title="{key.upper()}: {s[key]:,}"></div>'
            )

    # ── Top rules table ──────────────────────────────────────────────────────
    rule_rows = ""
    for r in data["top_rules"]:
        sev_c = _sev_color.get(r["severity"], "#94a3b8")
        rule_rows += (
            f"<tr>"
            f'<td style="color:#a78bfa;font-weight:600">{r["sid"]}</td>'
            f'<td class="trunc" title="{_esc(r["signature"])}">{_esc((r["signature"] or "")[:80])}</td>'
            f'<td style="color:{sev_c};font-weight:700">{_esc(r["severity"])}</td>'
            f'<td style="color:#38bdf8">{_esc(r["attack_type"])}</td>'
            f'<td class="num">{r["hits"]:,}</td>'
            f'<td class="num">{r["unique_ips"]:,}</td>'
            f'<td class="ts">{_esc((r["last_seen"] or "")[:19].replace("T", " "))}</td>'
            f"</tr>"
        )
    if not rule_rows:
        rule_rows = '<tr><td colspan="7" class="empty">No alerts yet</td></tr>'

    # ── Attack type breakdown ────────────────────────────────────────────────
    attack_rows = ""
    for a in data["by_attack_type"]:
        attack_rows += (
            f"<tr>"
            f'<td style="color:#22d3ee;font-weight:600">{_esc(a["attack_type"])}</td>'
            f'<td class="num">{a["count"]:,}</td>'
            f'<td class="num">{a["unique_ips"]:,}</td>'
            f'<td class="num" style="color:#a78bfa">{a["unique_sids"]:,}</td>'
            f'<td class="ts">{_esc((a["last_seen"] or "")[:19].replace("T", " "))}</td>'
            f"</tr>"
        )
    if not attack_rows:
        attack_rows = '<tr><td colspan="5" class="empty">No data</td></tr>'

    # ── Hunting overlap table (IPs in hunting + Suricata) ────────────────────
    hunt_rows = ""
    for h in data.get("hunting_overlap_ips", []):
        threat_c = _sev_color.get(h.get("threat_level", ""), "#94a3b8")
        hunt_rows += (
            f"<tr>"
            f'<td><a href="/attacker_hunting/{_esc(h["ip"])}" '
            f'style="color:#22d3ee">{_esc(h["ip"])}</a></td>'
            f'<td style="color:{threat_c};font-weight:700">{_esc(h.get("threat_level", ""))}</td>'
            f'<td class="num">{h["suricata_events"]:,}</td>'
            f'<td class="num" style="color:#a78bfa">{h["unique_sids"]:,}</td>'
            f'<td class="num" style="color:#f97316">{h["sensor_events"]:,}</td>'
            f'<td style="color:#ef4444">{_esc(h.get("ai_status", ""))}</td>'
            f'<td class="ts">{_esc((h.get("last_seen", "") or "")[:19].replace("T", " "))}</td>'
            f"</tr>"
        )
    if not hunt_rows:
        hunt_rows = (
            '<tr><td colspan="7" class="empty">No hunting IPs with Suricata alerts</td></tr>'
        )

    hunting_panel = (
        '<div class="panel" style="border:1px solid #ef444440">'
        '<div class="panel-hdr" style="color:#ef4444">'
        "&#x1F3AF; Hunting IPs with Suricata Alerts "
        f'<span class="panel-cnt">{len(data.get("hunting_overlap_ips", []))} IPs — need AI analysis</span></div>'
        '<div class="scroll-table" style="max-height:400px">'
        "<table><thead><tr>"
        "<th>IP</th><th>Threat</th><th>Suricata Events</th>"
        "<th>Unique SIDs</th><th>Total Events</th><th>AI Status</th><th>Last Seen</th>"
        "</tr></thead><tbody>"
        f"{hunt_rows}"
        "</tbody></table></div></div>"
    )

    # ── Top source IPs ───────────────────────────────────────────────────────
    src_rows = ""
    for ip_info in data["top_sources"]:
        is_hunted = ip_info.get("is_hunted", False)
        hunt_badge = (
            ' <span style="background:#ef4444;color:#fff;padding:1px 5px;'
            'border-radius:3px;font-size:8px;font-weight:700">HUNTING</span>'
            if is_hunted
            else ""
        )
        src_rows += (
            f"<tr>"
            f'<td><a href="/events_ip/{_esc(ip_info["ip"])}" '
            f'style="color:#22d3ee">{_esc(ip_info["ip"])}</a>{hunt_badge}</td>'
            f'<td class="num">{ip_info["hits"]:,}</td>'
            f'<td class="num" style="color:#a78bfa">{ip_info["unique_sids"]:,}</td>'
            f'<td style="color:#f97316">{_esc(ip_info.get("top_category", ""))}</td>'
            f'<td class="ts">{_esc((ip_info.get("last_seen", "") or "")[:19].replace("T", " "))}</td>'
            f"</tr>"
        )
    if not src_rows:
        src_rows = '<tr><td colspan="5" class="empty">No data</td></tr>'

    # ── Recent events table ────────────────────────────────────────────────
    event_rows = ""
    for ev in data.get("recent_events", []):
        sev_c = "#94a3b8"
        ts = (ev.get("timestamp", "") or "")[:19].replace("T", " ")
        sig_short = (ev.get("signature", "") or "")[:70]
        cve_badge = ""
        if ev.get("cve"):
            cve_norm = ev["cve"].replace("_", "-")
            if not cve_norm.startswith("CVE-"):
                cve_norm = "CVE-" + cve_norm.lstrip("CVE")
            cve_badge = (
                f' <a href="https://vulnerability.circl.lu/cve/{_esc(cve_norm)}" '
                f'target="_blank" style="background:#ef4444;color:#fff;padding:1px 5px;'
                f'border-radius:3px;font-size:9px;font-weight:700;text-decoration:none">'
                f"{_esc(cve_norm)}</a>"
            )
        country = ev.get("country", "??")
        flag = "\U0001f3f4\u200d\u2620\ufe0f" if country == "PIRATE" else ""
        if not flag and country and len(country) == 2:
            flag = chr(0x1F1E6 + ord(country[0]) - ord("A")) + chr(
                0x1F1E6 + ord(country[1]) - ord("A")
            )
        event_rows += (
            f"<tr>"
            f'<td class="ts">{_esc(ts)}</td>'
            f'<td title="{_esc(country)}" style="font-size:14px">{flag}</td>'
            f'<td><a href="/events_ip/{_esc(ev["src_ip"])}" '
            f'style="color:#22d3ee">{_esc(ev["src_ip"])}</a></td>'
            f'<td class="num">{ev.get("dst_port", "")}</td>'
            f'<td style="color:#a78bfa">{ev.get("sid", "")}</td>'
            f'<td class="trunc" title="{_esc(ev.get("signature", ""))}">{_esc(sig_short)}{cve_badge}</td>'
            f"<td>{_esc(ev.get('attack_types', ''))}</td>"
            f'<td><a href="/event_full/{_esc(ev["event_id"])}" '
            f'style="color:#38bdf8;font-size:11px">detail &#x2197;</a></td>'
            f"</tr>"
        )
    if not event_rows:
        event_rows = '<tr><td colspan="8" class="empty">No recent events</td></tr>'

    # ── Timeline data (JSON for JS chart) ────────────────────────────────────
    timeline_json = _json.dumps(data.get("timeline", []))

    # ── Category distribution for SVG chart ──────────────────────────────────
    cat_data = data.get("by_category", [])
    cat_json = _json.dumps(cat_data)

    # ── Assemble page ────────────────────────────────────────────────────────
    extra_css = """
.sur-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:1100px){.sur-grid{grid-template-columns:1fr}}
.chart-box{background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:14px}
.chart-title{font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.7px;margin-bottom:10px}
"""

    from honeylens.webui.shared import page_header_html

    header = page_header_html(
        "Suricata IDS",
        eyebrow="Detection",
        description="Real-time Suricata alert monitoring · IPs in hunting are flagged for AI deep analysis",
        metadata=[
            f"{s['unique_sids']:,} SIDs",
            f"{s['unique_src']:,} sources",
            f"{s['hunting_overlap']:,} in hunting",
        ],
    )
    body = f"""
{header}

<div class="kpi-grid" style="margin-bottom:14px">{kpi_html}</div>

<div style="background:var(--bg2);border-radius:5px;height:18px;overflow:hidden;margin-bottom:16px;border:1px solid var(--border)">
{sev_bar}
</div>

{hunting_panel}

<div class="sur-grid">
  <div class="chart-box">
    <div class="chart-title">Daily Alert Volume (14 days)</div>
    <svg id="timeline-chart" width="100%" height="200" viewBox="0 0 600 200"></svg>
  </div>
  <div class="chart-box">
    <div class="chart-title">Suricata Categories</div>
    <svg id="cat-chart" width="100%" height="200" viewBox="0 0 600 200"></svg>
  </div>
</div>

<div class="panel" style="margin-top:14px;border:1px solid #38bdf840">
<div class="panel-hdr" style="color:#38bdf8">&#x1F4E1; Recent Suricata Alerts
<span class="panel-cnt">last 50, excluding whitelisted</span></div>
<div class="scroll-table" style="max-height:600px">
<table><thead><tr>
<th>Time</th><th></th><th>Source IP</th><th>Port</th><th>SID</th>
<th>Signature</th><th>Type</th><th></th>
</tr></thead><tbody>
{event_rows}
</tbody></table></div></div>

<div class="panel" style="margin-top:14px">
<div class="panel-hdr">&#x1F4CB; Top Suricata Rules
<span class="panel-cnt">{s["unique_sids"]:,} unique SIDs</span></div>
<div class="scroll-table" style="max-height:500px">
<table><thead><tr>
<th>SID</th><th>Signature</th><th>Severity</th><th>Attack Type</th>
<th>Hits</th><th>IPs</th><th>Last Seen</th>
</tr></thead><tbody>
{rule_rows}
</tbody></table></div></div>

<div class="sur-grid" style="margin-top:14px">
  <div class="panel">
    <div class="panel-hdr">&#x1F525; Attack Type Breakdown</div>
    <div class="scroll-table" style="max-height:400px">
    <table><thead><tr>
    <th>Type</th><th>Count</th><th>IPs</th><th>SIDs</th><th>Last Seen</th>
    </tr></thead><tbody>
    {attack_rows}
    </tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-hdr">&#x1F310; Top Source IPs</div>
    <div class="scroll-table" style="max-height:400px">
    <table><thead><tr>
    <th>IP</th><th>Hits</th><th>SIDs</th><th>Top Category</th><th>Last Seen</th>
    </tr></thead><tbody>
    {src_rows}
    </tbody></table></div>
  </div>
</div>

{sortable_table_js()}

<script>
// Timeline bar chart
(function(){{
  var data = {timeline_json};
  var svg = document.getElementById('timeline-chart');
  if(!data.length) return;
  var max = Math.max.apply(null, data.map(function(d){{return d.count}})) || 1;
  var w = 600, h = 180, pad = 30, barW = Math.max(2, (w - pad*2) / data.length - 2);
  var html = '';
  data.forEach(function(d, i){{
    var bh = (d.count / max) * (h - pad - 10);
    var x = pad + i * ((w - pad*2) / data.length);
    var y = h - pad - bh;
    html += '<rect x="'+x+'" y="'+y+'" width="'+barW+'" height="'+bh+'" fill="#38bdf8" opacity="0.8" rx="1">';
    html += '<title>'+d.date+': '+d.count+' alerts</title></rect>';
    if(i % Math.ceil(data.length/7) === 0){{
      html += '<text x="'+(x+barW/2)+'" y="'+(h-5)+'" text-anchor="middle" fill="#64748b" font-size="9">'+d.date.slice(5)+'</text>';
    }}
  }});
  // Y axis labels
  html += '<text x="2" y="'+pad+'" fill="#64748b" font-size="9">'+max+'</text>';
  html += '<text x="2" y="'+(h-pad)+'" fill="#64748b" font-size="9">0</text>';
  svg.innerHTML = html;
}})();

// Category horizontal bar chart
(function(){{
  var data = {cat_json};
  var svg = document.getElementById('cat-chart');
  if(!data.length) return;
  var max = data[0].count || 1;
  var h = Math.max(200, data.length * 22 + 20);
  svg.setAttribute('viewBox', '0 0 600 ' + h);
  svg.setAttribute('height', h);
  var colors = ['#38bdf8','#f97316','#a78bfa','#22c55e','#ef4444','#eab308','#06b6d4','#ec4899','#84cc16','#f59e0b'];
  var html = '';
  data.slice(0,15).forEach(function(d, i){{
    var y = 5 + i * 22;
    var bw = Math.max(2, (d.count / max) * 350);
    var c = colors[i % colors.length];
    html += '<rect x="200" y="'+y+'" width="'+bw+'" height="16" fill="'+c+'" opacity="0.8" rx="2">';
    html += '<title>'+d.category+': '+d.count+'</title></rect>';
    html += '<text x="195" y="'+(y+12)+'" text-anchor="end" fill="#94a3b8" font-size="10">'+d.category.slice(0,28)+'</text>';
    html += '<text x="'+(205+bw)+'" y="'+(y+12)+'" fill="#e2e8f0" font-size="10" font-weight="600">'+d.count.toLocaleString()+'</text>';
  }});
  svg.innerHTML = html;
}})();
</script>
"""

    return (
        '<!DOCTYPE html><html lang="en"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<link rel="icon" href="/favicon.ico" type="image/x-icon">'
        "<title>Suricata IDS \u2014 HoneyLens</title>"
        f"<style>{SHARED_CSS}{extra_css}</style>"
        "</head><body>"
        '<a href="#main-content" class="skip-link">Skip to main content</a>'
        f"{nav_bar_html('suricata')}"
        f'<main id="main-content" class="page">{body}</main>'
        "</body></html>"
    )
