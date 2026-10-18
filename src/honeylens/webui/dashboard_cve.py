"""
webui/dashboard_cve.py — CVE Intelligence Dashboard
=====================================================
Visualises CVE intelligence from CIRCL enrichment (Idea 32).
Shows trending CVEs, severity distribution, KEV correlation,
vendor breakdown, and timeline.
Compatible with Python 3.9+.
"""

from __future__ import annotations

import html
import math
from typing import Any


def cve_dashboard_html(
    cve_rows: list,
    ai_cve_summary: dict,
    kev_stats: dict,
    cve_timeline: list | None = None,
    cve_attackers: list | None = None,
) -> str:
    """Render the full CVE Intelligence dashboard."""
    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, page_header_html, sortable_table_js

    e = html.escape

    total = len(cve_rows)
    kev_count = sum(1 for r in cve_rows if r.get("is_kev"))
    non_kev = total - kev_count
    crit_count = sum(1 for r in cve_rows if str(r.get("cvss_severity", "")).upper() == "CRITICAL")
    high_count = sum(1 for r in cve_rows if str(r.get("cvss_severity", "")).upper() == "HIGH")
    med_count = sum(1 for r in cve_rows if str(r.get("cvss_severity", "")).upper() == "MEDIUM")
    low_count = sum(1 for r in cve_rows if str(r.get("cvss_severity", "")).upper() == "LOW")
    no_score = sum(1 for r in cve_rows if r.get("cvss_score") is None)
    total_hits = sum(r.get("times_seen", 0) for r in cve_rows)
    avg_cvss = 0
    scored = [r["cvss_score"] for r in cve_rows if r.get("cvss_score") is not None]
    if scored:
        avg_cvss = sum(scored) / len(scored)
    max_cvss = max(scored) if scored else 0

    # Unique vendors
    vendors: dict[str, int] = {}
    for r in cve_rows:
        v = r.get("vendor") or "Unknown"
        if v in ("n/a", ""):
            v = "Unknown"
        vendors[v] = vendors.get(v, 0) + 1

    _sc = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}

    # ── SVG Donut Chart: Severity Distribution ──
    sev_data = [
        ("CRITICAL", crit_count, "#ef4444"),
        ("HIGH", high_count, "#f97316"),
        ("MEDIUM", med_count, "#eab308"),
        ("LOW", low_count, "#22c55e"),
        ("N/A", no_score, "#334155"),
    ]
    sev_data = [(lvl, c, clr) for lvl, c, clr in sev_data if c > 0]
    donut_svg = _donut_chart(sev_data, total, "Severity")

    # ── SVG Donut Chart: KEV Status ──
    kev_data = [
        ("In KEV", kev_count, "#ef4444"),
        ("Not in KEV", non_kev, "#334155"),
    ]
    kev_donut = _donut_chart(kev_data, total, "KEV")

    # ── SVG Bar Chart: CVSS Score Distribution ──
    cvss_bars = _cvss_histogram(cve_rows)

    # ── SVG Bar Chart: Top Vendors ──
    vendor_bars = ""
    sorted_vendors = sorted(vendors.items(), key=lambda x: -x[1])[:10]
    if sorted_vendors:
        max_v = sorted_vendors[0][1]
        _vc = [
            "#38bdf8",
            "#f97316",
            "#22c55e",
            "#a78bfa",
            "#f472b6",
            "#eab308",
            "#06b6d4",
            "#ef4444",
            "#34d399",
            "#818cf8",
        ]
        for i, (vname, vcount) in enumerate(sorted_vendors):
            pct = vcount / max_v * 100
            c = _vc[i % len(_vc)]
            vendor_bars += (
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">'
                f'<div style="width:150px;font-size:10px;color:{c};font-weight:600;'
                f'white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="{e(vname)}">{e(vname)}</div>'
                f'<div style="flex:1;height:18px;background:#1e293b;border-radius:3px;overflow:hidden">'
                f'<div style="width:{pct}%;height:100%;background:{c}40;border-left:3px solid {c};border-radius:3px"></div>'
                f"</div>"
                f'<div style="width:30px;text-align:right;font-size:11px;color:#94a3b8;font-weight:700">{vcount}</div>'
                f"</div>"
            )

    # ── Trending CVEs Table ──
    trend_rows = ""
    for r in sorted(cve_rows, key=lambda x: x.get("times_seen", 0), reverse=True):
        cve_id = e(str(r.get("cve_id", "")))
        score = r.get("cvss_score")
        sev = str(r.get("cvss_severity", "") or "").upper()
        sc = _sc.get(sev, "#64748b")
        kev_tag = (
            ' <span style="background:#ef4444;color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700">KEV</span>'
            if r.get("is_kev")
            else ""
        )
        vendor = e(str(r.get("vendor") or "—"))
        product = e(str(r.get("product") or "—"))
        title = e(str(r.get("title") or "")[:70])
        times = r.get("times_seen", 0)
        first = str(r.get("first_seen_on_sensor") or "")[:10]
        last = str(r.get("last_seen_on_sensor") or "")[:10]

        trend_rows += (
            f"<tr>"
            f'<td><a href="https://vulnerability.circl.lu/cve/{cve_id}" target="_blank" '
            f'style="color:#f87171;font-family:var(--mono);font-weight:700;text-decoration:none">{cve_id}</a>{kev_tag}</td>'
            f'<td style="color:{sc};font-weight:700;text-align:center">{score if score else "—"}</td>'
            f'<td style="color:{sc}">{sev or "—"}</td>'
            f'<td style="text-align:center;font-weight:700">{times}</td>'
            f'<td style="color:#94a3b8;font-size:11px">{vendor}</td>'
            f'<td style="color:#94a3b8;font-size:11px">{product}</td>'
            f'<td class="trunc" style="color:#cbd5e1;font-size:11px" title="{title}">{title}</td>'
            f'<td style="color:#64748b;font-size:10px">{first}</td>'
            f'<td style="color:#64748b;font-size:10px">{last}</td>'
            f"</tr>"
        )
    if not trend_rows:
        trend_rows = '<tr><td colspan="9" style="text-align:center;color:#64748b;padding:30px">No CVEs tracked yet. AI analysis will populate this automatically.</td></tr>'

    # ── KEV Watchlist ──
    kev_rows = ""
    for r in sorted(
        [r for r in cve_rows if r.get("is_kev")],
        key=lambda x: x.get("cvss_score") or 0,
        reverse=True,
    ):
        cve_id = e(str(r.get("cve_id", "")))
        score = r.get("cvss_score")
        sev = str(r.get("cvss_severity", "") or "").upper()
        sc = _sc.get(sev, "#64748b")
        title = e(str(r.get("title") or "")[:80])
        kev_rows += (
            f"<tr>"
            f'<td><a href="https://vulnerability.circl.lu/cve/{cve_id}" target="_blank" '
            f'style="color:#f87171;font-family:var(--mono);font-weight:700;text-decoration:none">{cve_id}</a></td>'
            f'<td style="color:{sc};font-weight:700;text-align:center">{score if score else "—"}</td>'
            f'<td style="color:{sc}">{sev or "—"}</td>'
            f'<td style="color:#cbd5e1;font-size:11px">{title}</td>'
            f'<td><a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank" '
            f'style="color:#38bdf8;font-size:10px">NVD</a></td>'
            f"</tr>"
        )
    if not kev_rows:
        kev_rows = '<tr><td colspan="5" style="text-align:center;color:#64748b;padding:20px">No KEV CVEs detected on sensor</td></tr>'

    # ── CVE Timeline Chart ─────────────────────────────────────────────
    tl = cve_timeline or []
    timeline_chart = ""
    if tl:
        chart_w, chart_h = 900, 200
        ml, mb, mt = 55, 28, 10
        n = len(tl)
        max_v = max((d.get("new_cves", 0) for d in tl), default=1) or 1
        bw = max(4, min(20, (chart_w - ml) // n - 2))
        bars_svg = ""
        xlabels = ""
        for i, d in enumerate(tl):
            x = ml + i * (bw + 2)
            nc = d.get("new_cves", 0)
            h_bar = int((nc / max_v) * (chart_h - mb - mt))
            y = chart_h - mb - h_bar
            bars_svg += f'<rect x="{x}" y="{y}" width="{bw}" height="{h_bar}" fill="#f8717140" rx="1"><title>{d["day"]}: {nc} new CVEs, {d.get("total_hits", 0)} hits</title></rect>'
            lbl_int = max(1, n // 12)
            if i % lbl_int == 0:
                xlabels += f'<text x="{x + bw // 2}" y="{chart_h - 6}" fill="#64748b" font-size="9" text-anchor="middle">{d["day"][-5:]}</text>'
        yscale = ""
        for frac in [0, 0.25, 0.5, 0.75, 1.0]:
            y = chart_h - mb - int(frac * (chart_h - mb - mt))
            val = int(frac * max_v)
            yscale += f'<line x1="{ml - 4}" y1="{y}" x2="{chart_w}" y2="{y}" stroke="#1e2a3a" stroke-width="0.5"/>'
            yscale += f'<text x="{ml - 6}" y="{y + 3}" fill="#64748b" font-size="9" text-anchor="end">{val}</text>'
        legend_svg = (
            f'<rect x="{ml}" y="2" width="10" height="10" fill="#f8717140" rx="1"/>'
            f'<text x="{ml + 14}" y="10" fill="#94a3b8" font-size="10">New CVEs per day</text>'
        )
        timeline_chart = (
            f'<div style="overflow-x:auto;padding:10px 14px">'
            f'<svg width="{chart_w}" height="{chart_h}" style="font-family:monospace;min-width:{chart_w}px">'
            f"{yscale}{bars_svg}{xlabels}{legend_svg}</svg></div>"
        )
    else:
        timeline_chart = (
            '<p style="color:#64748b;padding:14px;text-align:center">No timeline data yet</p>'
        )

    # ── CVE-to-Attacker mapping rows ───────────────────────────────────
    attacker_rows = ""
    for a in cve_attackers or []:
        cid = e(str(a.get("cve_id", "")))
        sc_val = a.get("cvss_score")
        sev = str(a.get("cvss_severity", "") or "").upper()
        sc = _sc.get(sev, "#64748b")
        kev_tag = (
            ' <span style="background:#ef4444;color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700">KEV</span>'
            if a.get("is_kev")
            else ""
        )
        ip_raw = e(str(a.get("src_ip", "")))
        hits = a.get("hits", 0)
        last = str(a.get("last_seen") or "")[:19].replace("T", " ")
        attacker_rows += (
            f"<tr>"
            f'<td><a href="https://vulnerability.circl.lu/cve/{cid}" target="_blank" '
            f'style="color:#f87171;font-family:var(--mono);font-weight:700;text-decoration:none">{cid}</a>{kev_tag}</td>'
            f'<td style="color:{sc};font-weight:700;text-align:center">{sc_val if sc_val else "—"}</td>'
            f'<td style="color:{sc}">{sev or "—"}</td>'
            f'<td class="ip" style="cursor:pointer" onclick="window.location.href=\'/events_ip/{ip_raw}?format=html\'">{ip_raw}</td>'
            f'<td style="text-align:right;font-weight:700">{hits:,}</td>'
            f'<td style="color:#64748b;font-size:10px">{last}</td>'
            f"</tr>"
        )
    if not attacker_rows:
        attacker_rows = '<tr><td colspan="6" style="text-align:center;color:#64748b;padding:20px">No CVE-to-attacker mappings found. AI analysis links CVEs to source IPs.</td></tr>'

    # ── EPSS lookup data (CVE IDs for client-side fetch) ────────────────
    import json as _json2

    cve_ids_json = _json2.dumps([r.get("cve_id", "") for r in cve_rows if r.get("cve_id")])
    cve_data_json = _json2.dumps(
        {
            r.get("cve_id", ""): {
                "cvss": float(r["cvss_score"]) if r.get("cvss_score") is not None else None,
                "sev": str(r.get("cvss_severity", "") or "").upper(),
                "kev": bool(r.get("is_kev")),
                "hits": r.get("times_seen", 0),
            }
            for r in cve_rows
            if r.get("cve_id")
        },
        default=str,
    )

    # AI enrichment stats
    ai_total = ai_cve_summary.get("total_enriched", 0)
    ai_cve_summary.get("pending", 0)

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CVE Intelligence — HoneyLens</title>
<style>{SHARED_CSS}
.cve-tab{{padding:10px 18px;background:none;border:none;color:var(--text3);font-size:12px;
  font-weight:600;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;
  transition:all .15s;font-family:inherit}}
.cve-tab:hover{{color:var(--text);background:var(--bg2)}}
.cve-tab.active{{color:var(--accent);border-bottom-color:var(--accent)}}
.cve-sec{{display:none}}.cve-sec.active{{display:block}}
.chart-container{{display:flex;justify-content:center;align-items:center;padding:20px}}
</style>
</head><body>
<a href="#main-content" class="skip-link">Skip to main content</a>
{nav_bar_html("cve")}
{
        page_header_html(
            "CVE Intelligence",
            eyebrow="Investigate",
            description="Observed CVEs enriched via CIRCL Vulnerability-Lookup (NVD · CISA KEV · EPSS)",
            actions=['<a href="/cve/trending" class="btn">JSON</a>'],
        )
    }

<!-- Sub-navigation -->
<div id="main-content" style="display:flex;gap:0;padding:0 22px;background:var(--bg1);border-bottom:2px solid var(--border)">
  <button class="cve-tab active" onclick="cveTab('overview')" id="cvt-overview">Overview</button>
  <button class="cve-tab" onclick="cveTab('timeline')" id="cvt-timeline">&#x1F4C8; Timeline</button>
  <button class="cve-tab" onclick="cveTab('attackers')" id="cvt-attackers">&#x1F3AF; Attackers</button>
  <button class="cve-tab" onclick="cveTab('epss')" id="cvt-epss">&#x1F4CA; EPSS</button>
  <button class="cve-tab" onclick="cveTab('trending')" id="cvt-trending">Trending CVEs <span style="background:var(--accent);color:#000;padding:0 5px;border-radius:8px;font-size:9px;margin-left:4px">{
        total
    }</span></button>
  <button class="cve-tab" onclick="cveTab('kev')" id="cvt-kev">CISA KEV <span style="background:#ef4444;color:#fff;padding:0 5px;border-radius:8px;font-size:9px;margin-left:4px">{
        kev_count
    }</span></button>
</div>

<div class="page">

<!-- ═══ OVERVIEW TAB ═══ -->
<div class="cve-sec active" id="sec-overview">

  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-lbl">CVEs Tracked</div>
      <div class="kpi-val" style="color:var(--accent)">{total}</div></div>
    <div class="kpi"><div class="kpi-lbl">In CISA KEV</div>
      <div class="kpi-val" style="color:#ef4444">{kev_count}</div></div>
    <div class="kpi"><div class="kpi-lbl">Critical</div>
      <div class="kpi-val" style="color:#ef4444">{crit_count}</div></div>
    <div class="kpi"><div class="kpi-lbl">High</div>
      <div class="kpi-val" style="color:#f97316">{high_count}</div></div>
    <div class="kpi"><div class="kpi-lbl">Total Hits</div>
      <div class="kpi-val" style="color:#22c55e">{total_hits}</div></div>
    <div class="kpi"><div class="kpi-lbl">Avg CVSS</div>
      <div class="kpi-val" style="color:{
        "#ef4444" if avg_cvss >= 9 else "#f97316" if avg_cvss >= 7 else "#eab308"
    }">{avg_cvss:.1f}</div></div>
    <div class="kpi"><div class="kpi-lbl">Max CVSS</div>
      <div class="kpi-val" style="color:#ef4444">{max_cvss}</div></div>
    <div class="kpi"><div class="kpi-lbl">AI Enriched</div>
      <div class="kpi-val" style="color:#a78bfa">{ai_total}</div></div>
  </div>

  <!-- Charts row -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
    <div class="panel">
      <div class="panel-hdr">Severity Distribution</div>
      <div class="chart-container">{donut_svg}</div>
    </div>
    <div class="panel">
      <div class="panel-hdr">CISA KEV Status</div>
      <div class="chart-container">{kev_donut}</div>
    </div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
    <div class="panel">
      <div class="panel-hdr">CVSS Score Distribution</div>
      <div style="padding:14px">{cvss_bars}</div>
    </div>
    <div class="panel">
      <div class="panel-hdr">Top Vendors</div>
      <div style="padding:14px">{
        vendor_bars
        if vendor_bars
        else '<div style="color:#64748b;text-align:center;padding:20px">No vendor data</div>'
    }</div>
    </div>
  </div>

</div>

<!-- ═══ TIMELINE TAB ═══ -->
<div class="cve-sec" id="sec-timeline">

  <div class="panel">
    <div class="panel-hdr">CVE Discovery Timeline
      <span class="panel-cnt">90-day view — when CVEs were first seen on sensor</span></div>
    {timeline_chart}
  </div>

</div>

<!-- ═══ ATTACKERS TAB ═══ -->
<div class="cve-sec" id="sec-attackers">

  <div class="panel">
    <div class="panel-hdr" style="color:#f59e0b">&#x1F3AF; CVE-to-Attacker Mapping
      <span class="panel-cnt">which IPs exploit which CVEs</span></div>
    <p style="color:#94a3b8;font-size:11px;padding:0 14px 8px;margin:0">
      Maps CVEs detected in attack patterns to source IPs. Click an IP to see all events from that attacker.</p>
    <div style="overflow-x:auto;max-height:60vh">
    <table>
      <thead><tr>
        <th>CVE</th><th>CVSS</th><th>Severity</th><th>Attacker IP</th><th>Hits</th><th>Last Seen</th>
      </tr></thead>
      <tbody>{attacker_rows}</tbody>
    </table>
    </div>
  </div>

</div>

<!-- ═══ EPSS TAB ═══ -->
<div class="cve-sec" id="sec-epss">

  <div class="panel">
    <div class="panel-hdr" style="color:#a78bfa">&#x1F4CA; EPSS — Exploit Prediction Scoring
      <span class="panel-cnt">probability of exploitation in next 30 days</span></div>
    <p style="color:#94a3b8;font-size:11px;padding:0 14px 8px;margin:0">
      <a href="https://www.first.org/epss/" target="_blank" style="color:#38bdf8">EPSS</a> (Exploit Prediction Scoring System)
      by FIRST.org predicts the probability that a CVE will be exploited in the wild within 30 days.
      Scores range from 0 (unlikely) to 1 (very likely). Fetched live from the EPSS API.</p>
    <div id="epss-loading" style="text-align:center;padding:30px;color:var(--accent)">Loading EPSS data from FIRST.org API...</div>
    <div id="epss-table" style="display:none;overflow-x:auto;max-height:60vh">
    <table>
      <thead><tr>
        <th>CVE</th><th>CVSS</th><th>Severity</th><th>KEV</th>
        <th>EPSS Score</th><th>EPSS Percentile</th><th>Exploitation Risk</th><th>Hits</th>
      </tr></thead>
      <tbody id="epss-body"></tbody>
    </table>
    </div>
  </div>

</div>

<!-- ═══ TRENDING TAB ═══ -->
<div class="cve-sec" id="sec-trending">

  <div class="panel">
    <div class="panel-hdr">All CVEs Detected on Sensor
      <span class="panel-cnt">{total} CVEs, {total_hits} total hits</span></div>
    <div style="overflow-x:auto;max-height:70vh">
    <table>
      <thead><tr>
        <th>CVE</th><th>CVSS</th><th>Severity</th><th>Hits</th>
        <th>Vendor</th><th>Product</th><th>Title</th>
        <th>First Seen</th><th>Last Seen</th>
      </tr></thead>
      <tbody>{trend_rows}</tbody>
    </table>
    </div>
  </div>

</div>

<!-- ═══ KEV WATCHLIST TAB ═══ -->
<div class="cve-sec" id="sec-kev">

  <div style="background:#7f1d1d;border:1px solid #ef4444;border-radius:6px;padding:12px 16px;margin-bottom:14px;color:#fca5a5;font-size:12px">
    <strong>CISA Known Exploited Vulnerabilities</strong> — These CVEs are confirmed actively exploited in the wild.
    Attackers targeting your sensor used exploits for these vulnerabilities. Prioritise patching and monitoring.
  </div>

  <div class="panel">
    <div class="panel-hdr" style="color:#ef4444">KEV CVEs Detected on Sensor
      <span class="panel-cnt">{kev_count} of {total} CVEs are in KEV</span></div>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>CVE</th><th>CVSS</th><th>Severity</th><th>Title</th><th>Links</th>
      </tr></thead>
      <tbody>{kev_rows}</tbody>
    </table>
    </div>
  </div>

</div>

</div><!-- /page -->

<script>
function cveTab(name) {{
  document.querySelectorAll('.cve-sec').forEach(function(s){{ s.classList.remove('active'); }});
  document.querySelectorAll('.cve-tab').forEach(function(t){{ t.classList.remove('active'); }});
  var sec = document.getElementById('sec-' + name);
  var tab = document.getElementById('cvt-' + name);
  if (sec) sec.classList.add('active');
  if (tab) tab.classList.add('active');
  history.replaceState(null, '', '#' + name);
}}
(function(){{
  var h = location.hash.replace('#','');
  if (h && document.getElementById('sec-' + h)) cveTab(h);
}})();

// ── EPSS Fetcher ──────────────────────────────────────────────────
var CVE_IDS = {cve_ids_json};
var CVE_DATA = {cve_data_json};

function fetchEPSS() {{
  if (!CVE_IDS.length) {{
    document.getElementById('epss-loading').innerHTML = '<span style="color:#64748b">No CVEs to look up</span>';
    return;
  }}
  // EPSS API supports up to 100 CVEs per request
  var batch = CVE_IDS.slice(0, 100).join(',');
  fetch('https://api.first.org/data/v1/epss?cve=' + encodeURIComponent(batch))
    .then(function(r) {{ return r.json(); }})
    .then(function(d) {{
      var data = d.data || [];
      var rows = '';
      // Merge with our CVE data and sort by EPSS score desc
      data.sort(function(a, b) {{ return parseFloat(b.epss) - parseFloat(a.epss); }});
      data.forEach(function(ep) {{
        var cve = ep.cve || '';
        var epss = parseFloat(ep.epss) || 0;
        var pct = parseFloat(ep.percentile) || 0;
        var info = CVE_DATA[cve] || {{}};
        var cvss = info.cvss != null ? info.cvss : '—';
        var sev = info.sev || '—';
        var kev = info.kev ? '<span style="background:#ef4444;color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700">KEV</span>' : '—';
        var hits = info.hits || 0;
        var sevColors = {{CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#22c55e'}};
        var sc = sevColors[sev] || '#64748b';
        // Risk label based on EPSS
        var risk, rc;
        if (epss >= 0.5) {{ risk = 'VERY HIGH'; rc = '#ef4444'; }}
        else if (epss >= 0.1) {{ risk = 'HIGH'; rc = '#f97316'; }}
        else if (epss >= 0.01) {{ risk = 'MODERATE'; rc = '#eab308'; }}
        else {{ risk = 'LOW'; rc = '#22c55e'; }}
        rows += '<tr>'
          + '<td><a href="https://vulnerability.circl.lu/cve/' + cve + '" target="_blank" style="color:#f87171;font-family:monospace;font-weight:700;text-decoration:none">' + cve + '</a></td>'
          + '<td style="color:' + sc + ';font-weight:700;text-align:center">' + cvss + '</td>'
          + '<td style="color:' + sc + '">' + sev + '</td>'
          + '<td>' + kev + '</td>'
          + '<td style="text-align:center;font-weight:700;color:' + rc + '">' + (epss * 100).toFixed(2) + '%</td>'
          + '<td style="text-align:center;color:#94a3b8">' + (pct * 100).toFixed(0) + 'th</td>'
          + '<td><span style="color:' + rc + ';font-weight:700;font-size:11px">' + risk + '</span></td>'
          + '<td style="text-align:right">' + hits.toLocaleString() + '</td>'
          + '</tr>';
      }});
      // Add CVEs without EPSS data
      CVE_IDS.forEach(function(cve) {{
        if (!data.find(function(d) {{ return d.cve === cve; }})) {{
          var info = CVE_DATA[cve] || {{}};
          var cvss = info.cvss != null ? info.cvss : '—';
          var sev = info.sev || '—';
          var sevColors = {{CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#22c55e'}};
          var sc = sevColors[sev] || '#64748b';
          var kev = info.kev ? '<span style="background:#ef4444;color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700">KEV</span>' : '—';
          rows += '<tr><td><a href="https://vulnerability.circl.lu/cve/' + cve + '" target="_blank" style="color:#f87171;font-family:monospace;text-decoration:none">' + cve + '</a></td>'
            + '<td style="color:' + sc + ';text-align:center">' + cvss + '</td>'
            + '<td style="color:' + sc + '">' + sev + '</td>'
            + '<td>' + kev + '</td>'
            + '<td style="text-align:center;color:#64748b">—</td>'
            + '<td style="text-align:center;color:#64748b">—</td>'
            + '<td style="color:#64748b;font-size:11px">No EPSS data</td>'
            + '<td style="text-align:right">' + (info.hits||0).toLocaleString() + '</td></tr>';
        }}
      }});
      document.getElementById('epss-body').innerHTML = rows;
      document.getElementById('epss-loading').style.display = 'none';
      document.getElementById('epss-table').style.display = 'block';
    }})
    .catch(function(e) {{
      document.getElementById('epss-loading').innerHTML = '<span style="color:#ef4444">Failed to fetch EPSS data: ' + e + '</span>';
    }});
}}
// Fetch EPSS when tab is opened (lazy load)
var epssFetched = false;
var origCveTab = cveTab;
cveTab = function(name) {{
  origCveTab(name);
  if (name === 'epss' && !epssFetched) {{ epssFetched = true; fetchEPSS(); }}
}};
// Also fetch if URL hash is epss
if (location.hash === '#epss') {{ epssFetched = true; fetchEPSS(); }}
</script>
{sortable_table_js()}
</body></html>"""


def _donut_chart(data: list, total: int, center_label: str) -> str:
    """Render an SVG donut chart. data = [(label, count, color), ...]"""
    if not data or total == 0:
        return '<div style="color:#64748b;text-align:center;padding:20px">No data</div>'

    size = 180
    cx, cy = size // 2, size // 2
    r_outer = 70
    r_inner = 45
    svg = f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'

    angle = -90  # start at top
    for label, count, color in data:
        if count == 0:
            continue
        pct = count / total
        sweep = pct * 360
        end_angle = angle + sweep

        # Arc path
        large = 1 if sweep > 180 else 0
        a1 = math.radians(angle)
        a2 = math.radians(end_angle)

        x1o = cx + r_outer * math.cos(a1)
        y1o = cy + r_outer * math.sin(a1)
        x2o = cx + r_outer * math.cos(a2)
        y2o = cy + r_outer * math.sin(a2)
        x1i = cx + r_inner * math.cos(a2)
        y1i = cy + r_inner * math.sin(a2)
        x2i = cx + r_inner * math.cos(a1)
        y2i = cy + r_inner * math.sin(a1)

        path = (
            f"M {x1o:.1f} {y1o:.1f} "
            f"A {r_outer} {r_outer} 0 {large} 1 {x2o:.1f} {y2o:.1f} "
            f"L {x1i:.1f} {y1i:.1f} "
            f"A {r_inner} {r_inner} 0 {large} 0 {x2i:.1f} {y2i:.1f} Z"
        )
        svg += f'<path d="{path}" fill="{color}" opacity="0.85">'
        svg += f"<title>{html.escape(label)}: {count} ({pct * 100:.0f}%)</title></path>"
        angle = end_angle

    # Center text
    svg += (
        f'<text x="{cx}" y="{cy - 6}" text-anchor="middle" '
        f'fill="#e2e8f0" font-size="22" font-weight="800" font-family="IBM Plex Sans">{total}</text>'
    )
    svg += (
        f'<text x="{cx}" y="{cy + 12}" text-anchor="middle" '
        f'fill="#64748b" font-size="10" font-family="IBM Plex Sans">{html.escape(center_label)}</text>'
    )

    svg += "</svg>"

    # Legend
    legend = (
        '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:8px;justify-content:center">'
    )
    for label, count, color in data:
        if count == 0:
            continue
        legend += (
            f'<span style="font-size:10px;color:#94a3b8">'
            f'<span style="display:inline-block;width:8px;height:8px;border-radius:50%;'
            f'background:{color};margin-right:3px"></span>{html.escape(label)} ({count})</span>'
        )
    legend += "</div>"

    return f'<div style="text-align:center">{svg}{legend}</div>'


def _cvss_histogram(cve_rows: list) -> str:
    """Render CVSS score distribution as horizontal bars."""
    buckets: dict[str, dict[str, Any]] = {
        "9.0-10.0 (Critical)": {"count": 0, "color": "#ef4444"},
        "7.0-8.9 (High)": {"count": 0, "color": "#f97316"},
        "4.0-6.9 (Medium)": {"count": 0, "color": "#eab308"},
        "0.1-3.9 (Low)": {"count": 0, "color": "#22c55e"},
        "No Score": {"count": 0, "color": "#334155"},
    }
    for r in cve_rows:
        score = r.get("cvss_score")
        if score is None:
            buckets["No Score"]["count"] += 1
        elif score >= 9.0:
            buckets["9.0-10.0 (Critical)"]["count"] += 1
        elif score >= 7.0:
            buckets["7.0-8.9 (High)"]["count"] += 1
        elif score >= 4.0:
            buckets["4.0-6.9 (Medium)"]["count"] += 1
        else:
            buckets["0.1-3.9 (Low)"]["count"] += 1

    max_count = max((b["count"] for b in buckets.values()), default=1) or 1
    bars = ""
    for label, b in buckets.items():
        pct = b["count"] / max_count * 100
        c = b["color"]
        if b["count"]:
            bars += (
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
                f'<div style="width:140px;font-size:10px;color:{c};font-weight:600">{html.escape(label)}</div>'
                f'<div style="flex:1;height:20px;background:#1e293b;border-radius:3px;overflow:hidden;position:relative">'
                f'<div style="width:{pct}%;height:100%;background:{c}40;border-left:3px solid {c};border-radius:3px"></div>'
                f'<span style="position:absolute;right:8px;top:2px;font-size:10px;color:#e2e8f0;font-weight:600">{b["count"]}</span>'
                f"</div>"
                f"</div>"
            )
    return (
        bars
        if bars
        else '<div style="color:#64748b;text-align:center;padding:20px">No CVSS data</div>'
    )
