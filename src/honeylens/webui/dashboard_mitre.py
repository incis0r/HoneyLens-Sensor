"""
webui/dashboard_mitre.py — MITRE ATT&CK Dashboard
===================================================
Full MITRE ATT&CK matrix visualisation with coverage heatmap,
tactic breakdown, technique detection status, and attack type mapping.
Compatible with Python 3.9+.
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI


def register_routes(app: FastAPI) -> None:
    """MITRE routes are served by api.py — this module provides HTML rendering."""
    pass


def mitre_dashboard_html(
    matrix_data: dict, coverage_data: dict, tactics_data: dict, attack_types_data: dict
) -> str:
    """Render the full MITRE ATT&CK dashboard."""
    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, page_header_html, sortable_table_js

    e = html.escape

    cov = coverage_data
    total_mon = cov.get("total_techniques_monitored", 0)
    total_det = cov.get("total_techniques_detected", 0)
    cov_pct = cov.get("overall_coverage_pct", 0)
    atk_det = cov.get("attack_types_detected", 0)

    # Tactic colours
    _tactic_colors = {
        "reconnaissance": "#ff6b6b",
        "resource-development": "#ee5a24",
        "initial-access": "#f97316",
        "execution": "#e17055",
        "persistence": "#fdcb6e",
        "privilege-escalation": "#ffeaa7",
        "defense-evasion": "#55efc4",
        "credential-access": "#00cec9",
        "discovery": "#74b9ff",
        "lateral-movement": "#a29bfe",
        "collection": "#6c5ce7",
        "command-and-control": "#fd79a8",
        "exfiltration": "#e84393",
        "impact": "#d63031",
    }

    # KPI strip
    cov_color = "#22c55e" if cov_pct >= 80 else "#eab308" if cov_pct >= 50 else "#ef4444"

    # Tactic coverage bars
    by_tactic = cov.get("by_tactic", {})
    tactic_bars = ""
    for tkey in [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ]:
        t = by_tactic.get(tkey, {})
        tname = t.get("name", tkey.replace("-", " ").title())
        total = t.get("total", 0)
        detected = t.get("detected", 0)
        pct = t.get("coverage_pct", 0)
        tc = _tactic_colors.get(tkey, "#64748b")
        bar_w = max(pct, 2)
        tactic_bars += (
            f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">'
            f'<div style="width:180px;font-size:11px;color:{tc};font-weight:600;white-space:nowrap">{e(tname)}</div>'
            f'<div style="flex:1;height:18px;background:#1e293b;border-radius:3px;overflow:hidden;position:relative">'
            f'<div style="width:{bar_w}%;height:100%;background:{tc};border-radius:3px;transition:width .5s"></div>'
            f'<span style="position:absolute;right:6px;top:1px;font-size:10px;color:#e2e8f0;font-weight:700">{detected}/{total}</span>'
            f"</div>"
            f'<div style="width:45px;text-align:right;font-size:11px;color:{tc};font-weight:700">{pct:.0f}%</div>'
            f"</div>"
        )

    # ATT&CK Matrix heatmap — tactics as columns, techniques as cells
    matrix = matrix_data.get("matrix", {})
    tactics_list = tactics_data.get("tactics", [])

    # Build heatmap columns
    heatmap_cols = ""
    max_techniques = 0
    for tac in tactics_list:
        max_techniques = max(max_techniques, len(tac.get("techniques", [])))

    for tac in tactics_list:
        tkey = tac.get("key", "")
        tname = tac.get("name", "")
        tc = _tactic_colors.get(tkey, "#64748b")
        techs = tac.get("techniques", [])

        cells = ""
        for tech in techs:
            tid = e(tech.get("technique", ""))
            tname_tech = e(tech.get("name", ""))
            atk_types = tech.get("attack_types", [])
            atk_str = ", ".join(atk_types[:3])

            # Check if detected in current matrix data (has events)
            matrix_techs = matrix.get(tkey, [])
            detected_count = 0
            for mt in matrix_techs:
                if mt.get("id") == tech.get("technique"):
                    detected_count = mt.get("count", 0)
                    break

            if detected_count > 0:
                bg = tc + "40"
                border = tc
                # The count links to the events mapped to this technique (operator drill-down).
                count_html = (
                    f'<a href="/mitre/technique/{tid}" '
                    f'style="font-size:9px;color:{tc};font-weight:700;text-decoration:underline" '
                    f'title="Show the events mapped to {tid}">{detected_count} events</a>'
                )
            else:
                bg = "#1e293b"
                border = "#334155"
                count_html = '<div style="font-size:9px;color:#475569">monitored</div>'

            cells += (
                f'<div style="background:{bg};border:1px solid {border};border-radius:4px;'
                f'padding:5px 7px;margin-bottom:3px;cursor:default" '
                f'title="{tid}: {tname_tech}\nAttacks: {atk_str}">'
                f'<div style="font-size:9px;font-weight:700;color:#e2e8f0;font-family:monospace">'
                f'<a href="https://attack.mitre.org/techniques/{tid.replace(".", "/")}/" '
                f'target="_blank" style="color:inherit;text-decoration:none">{tid}</a></div>'
                f'<div style="font-size:8px;color:#94a3b8;line-height:1.3;margin-top:1px">'
                f"{e(tname_tech[:40])}</div>"
                f"{count_html}"
                f"</div>"
            )

        # Fill empty slots for alignment
        for _ in range(max_techniques - len(techs)):
            cells += '<div style="height:1px"></div>'

        heatmap_cols += (
            f'<div style="min-width:140px;max-width:180px">'
            f'<div style="background:{tc};color:#fff;padding:5px 7px;border-radius:4px 4px 0 0;'
            f"font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;"
            f'text-align:center;margin-bottom:3px;position:sticky;top:0;z-index:1">'
            f"{e(tname)}</div>"
            f"{cells}"
            f"</div>"
        )

    # Attack type → technique table
    atk_types = attack_types_data.get("attack_types", [])
    atk_rows = ""
    for at in sorted(atk_types, key=lambda x: x.get("technique_count", 0), reverse=True)[:30]:
        atype = e(at.get("attack_type", ""))
        techs = at.get("techniques", [])
        tc_count = at.get("technique_count", 0)
        tech_badges = ""
        for t in techs[:5]:
            tid = e(t.get("id", ""))
            tactic = e(t.get("tactic", ""))
            tcolor = _tactic_colors.get(tactic, "#64748b")
            tech_badges += (
                f'<a href="https://attack.mitre.org/techniques/{tid.replace(".", "/")}/" '
                f'target="_blank" style="display:inline-block;padding:1px 6px;border-radius:3px;'
                f"font-size:10px;font-family:monospace;margin:1px;background:{tcolor}20;"
                f'color:{tcolor};border:1px solid {tcolor}40;text-decoration:none">{tid}</a>'
            )
        if len(techs) > 5:
            tech_badges += f'<span style="color:#64748b;font-size:10px">+{len(techs) - 5}</span>'

        atk_rows += (
            f"<tr>"
            f'<td><span class="attack-badge">{atype}</span></td>'
            f'<td style="text-align:center;font-weight:700">{tc_count}</td>'
            f"<td>{tech_badges}</td>"
            f"</tr>"
        )

    # Detected techniques detail table
    det_rows = ""
    all_detected = []
    for tkey, techs in matrix.items():
        for t in techs:
            t["_tactic"] = tkey
            all_detected.append(t)
    all_detected.sort(key=lambda x: x.get("count", 0), reverse=True)

    for t in all_detected:
        tid = e(t.get("id", ""))
        tname_t = e(t.get("name", ""))
        tactic = t.get("_tactic", "")
        tc = _tactic_colors.get(tactic, "#64748b")
        count = t.get("count", 0)
        atypes = ", ".join(e(a) for a in t.get("attack_types", [])[:3])
        det_rows += (
            f"<tr>"
            f'<td><a href="https://attack.mitre.org/techniques/{tid.replace(".", "/")}/" '
            f'target="_blank" style="color:#f87171;font-family:monospace;font-weight:700;'
            f'text-decoration:none">{tid}</a></td>'
            f"<td>{tname_t}</td>"
            f'<td style="color:{tc}">{e(tactic.replace("-", " ").title())}</td>'
            f'<td style="text-align:center;font-weight:700">{count}</td>'
            f'<td><span class="attack-badge">{atypes}</span></td>'
            f"</tr>"
        )
    if not det_rows:
        det_rows = '<tr><td colspan="5" style="text-align:center;color:#64748b;padding:20px">No techniques detected in last 24h — check longer time range</td></tr>'

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MITRE ATT&CK — HoneyLens</title>
<style>{SHARED_CSS}</style>
</head><body>
<a href="#main-content" class="skip-link">Skip to main content</a>
{nav_bar_html("mitre")}
{
        page_header_html(
            "MITRE ATT&CK",
            eyebrow="Investigate",
            description="ATT&CK for Enterprise — sensor detection coverage",
            actions=[
                '<a href="/mitre/navigator" class="btn" target="_blank">Export Navigator</a>',
                '<a href="/mitre/matrix" class="btn">JSON</a>',
                '<button class="btn btn-accent" onclick="location.reload()">Refresh</button>',
            ],
        )
    }

<style>
.mitre-tab{{padding:10px 18px;background:none;border:none;color:var(--text3);font-size:12px;
  font-weight:600;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;
  transition:all .15s;font-family:inherit}}
.mitre-tab:hover{{color:var(--text);background:var(--bg2)}}
.mitre-tab.active{{color:var(--accent);border-bottom-color:var(--accent)}}
.mitre-sec{{display:none}}.mitre-sec.active{{display:block}}
</style>

<!-- Sub-navigation -->
<div id="main-content" style="display:flex;gap:0;padding:0 22px;background:var(--bg1);border-bottom:2px solid var(--border)">
  <button class="mitre-tab active" onclick="mitreTab('overview')" id="mt-overview">Overview</button>
  <button class="mitre-tab" onclick="mitreTab('matrix')" id="mt-matrix">ATT&CK Matrix</button>
  <button class="mitre-tab" onclick="mitreTab('detected')" id="mt-detected">Detected Techniques <span style="background:#22c55e;color:#000;padding:0 5px;border-radius:8px;font-size:9px;margin-left:4px">{
        len(all_detected)
    }</span></button>
  <button class="mitre-tab" onclick="mitreTab('mapping')" id="mt-mapping">Attack Type Mapping <span style="background:var(--accent);color:#000;padding:0 5px;border-radius:8px;font-size:9px;margin-left:4px">{
        len(atk_types)
    }</span></button>
</div>

<div class="page">

<!-- ═══ OVERVIEW TAB ═══ -->
<div class="mitre-sec active" id="sec-overview">

  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-lbl">Techniques Monitored</div>
      <div class="kpi-val" style="color:var(--accent)">{total_mon}</div></div>
    <div class="kpi"><div class="kpi-lbl">Techniques Detected</div>
      <div class="kpi-val" style="color:#22c55e">{total_det}</div></div>
    <div class="kpi"><div class="kpi-lbl">Coverage</div>
      <div class="kpi-val" style="color:{cov_color}">{cov_pct:.1f}%</div></div>
    <div class="kpi"><div class="kpi-lbl">Attack Types Mapped</div>
      <div class="kpi-val" style="color:#f97316">{atk_det}</div></div>
    <div class="kpi"><div class="kpi-lbl">Tactics Covered</div>
      <div class="kpi-val" style="color:#a78bfa">{
        len([t for t in by_tactic.values() if t.get("detected", 0) > 0])
    }/14</div></div>
    <div class="kpi"><div class="kpi-lbl">Events (24h)</div>
      <div class="kpi-val">{matrix_data.get("total_events", 0):,}</div></div>
  </div>

  <div class="panel" style="margin-bottom:16px">
    <div class="panel-hdr">Tactic Coverage Breakdown</div>
    <div style="padding:14px">{tactic_bars}</div>
  </div>

</div>

<!-- ═══ ATT&CK MATRIX TAB ═══ -->
<div class="mitre-sec" id="sec-matrix">

  <div style="margin-bottom:10px;color:var(--text3);font-size:11px">
    Coloured cells = detected on sensor (event count shown). Grey cells = monitored but no events in last 24h.
    Click technique ID to view on MITRE ATT&CK.
  </div>

  <div style="overflow-x:auto;overflow-y:auto;max-height:75vh;padding-bottom:20px">
    <div style="display:flex;gap:4px;min-width:2000px">
      {heatmap_cols}
    </div>
  </div>

</div>

<!-- ═══ DETECTED TECHNIQUES TAB ═══ -->
<div class="mitre-sec" id="sec-detected">

  <div class="panel">
    <div class="panel-hdr">Detected Techniques (Last 24h)
      <span class="panel-cnt">{len(all_detected)} techniques</span></div>
    <div style="overflow-x:auto;max-height:70vh">
    <table>
      <thead><tr>
        <th>Technique</th><th>Name</th><th>Tactic</th><th>Events</th><th>Attack Types</th>
      </tr></thead>
      <tbody>{det_rows}</tbody>
    </table>
    </div>
  </div>

</div>

<!-- ═══ ATTACK TYPE MAPPING TAB ═══ -->
<div class="mitre-sec" id="sec-mapping">

  <div class="panel">
    <div class="panel-hdr">Attack Type to MITRE ATT&CK Mapping
      <span class="panel-cnt">{len(atk_types)} attack types</span></div>
    <div style="overflow-x:auto;max-height:70vh">
    <table>
      <thead><tr>
        <th>Attack Type</th><th>Techniques</th><th>MITRE Techniques</th>
      </tr></thead>
      <tbody>{atk_rows}</tbody>
    </table>
    </div>
  </div>

</div>

</div><!-- /page -->

<script>
function mitreTab(name) {{
  document.querySelectorAll('.mitre-sec').forEach(function(s){{ s.classList.remove('active'); }});
  document.querySelectorAll('.mitre-tab').forEach(function(t){{ t.classList.remove('active'); }});
  var sec = document.getElementById('sec-' + name);
  var tab = document.getElementById('mt-' + name);
  if (sec) sec.classList.add('active');
  if (tab) tab.classList.add('active');
  history.replaceState(null, '', '#' + name);
}}
(function(){{
  var h = location.hash.replace('#','');
  if (h && document.getElementById('sec-' + h)) mitreTab(h);
}})();
</script>
{sortable_table_js()}
</body></html>"""
