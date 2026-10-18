"""
webui/dashboard_main.py — Main Sensor Dashboard
=================================================
Primary dashboard at / with top scanners, ports, protocols, recent events.
Extracted from api.py DASHBOARD_HTML constant.
Compatible with Python 3.9+.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI


def render_dashboard() -> str:
    """Render the main sensor dashboard: the DASHBOARD_HTML template with the
    shared design system, grouped nav, page header, and <main> landmark injected.

    Used by BOTH this module's `/` route and routes/core.py's `/` handler (two
    handlers are registered for `/`; whichever wins must render identically), so
    the transform lives here as the single source of truth.
    """
    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, page_header_html

    html = DASHBOARD_HTML
    # Inject the shared design system — this template carries its own <style>
    # and would otherwise bypass SHARED_CSS (leaving the grouped nav unstyled).
    html = html.replace("<style>", "<style>\n" + SHARED_CSS + "\n", 1)
    nav = nav_bar_html("dashboard")
    header = page_header_html(
        "Sensor Overview",
        eyebrow="Overview",
        description="Live capture, detections, and recent activity for this sensor.",
        metadata=("Auto-refresh 30s",),
    )
    html = html.replace(
        '<div class="header">\n  <h1>SENSOR<span>//</span>INTEL</h1>\n'
        '  <div class="header-right">\n    <div class="live-dot"></div>\n'
        '    <span class="refresh-label">auto-refresh 30s</span>\n'
        "  </div>\n</div>",
        '<a class="skip-link" href="#main-content">Skip to content</a>\n'
        + nav
        + '\n<main id="main-content">\n<div style="padding:14px 22px 0">'
        + header
        + "</div>",
        1,
    )
    html = html.replace("</body>", "</main>\n</body>", 1)
    return html


def register_routes(app: FastAPI) -> None:
    from fastapi.responses import HTMLResponse

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def main_dashboard():
        return HTMLResponse(content=render_dashboard())


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="/favicon.ico" type="image/x-icon">
<title>HoneyLens — Dashboard</title>
<style>
  :root {
    --bg:       #0a0e14;
    --bg2:      #111820;
    --bg3:      #1a2230;
    --border:   #1e2a3a;
    --text:     #c5cdd8;
    --text2:    #8899aa;
    --accent:   #22d3ee;
    --accent2:  #10b981;
    --danger:   #f43f5e;
    --warning:  #f59e0b;
    --purple:   #a78bfa;
    --blue:     #3b82f6;
    --orange:   #f97316;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'IBM Plex Sans', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    min-height: 100vh;
  }

  /* Header */
  .header {
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 16px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
    backdrop-filter: blur(12px);
  }
  .header h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 18px;
    font-weight: 600;
    color: var(--accent);
    letter-spacing: -0.5px;
  }
  .header h1 span { color: var(--text2); font-weight: 300; }
  .header-right {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .live-dot {
    width: 8px; height: 8px;
    background: var(--accent2);
    border-radius: 50%;
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }
  .refresh-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--text2);
  }

  /* Search bar */
  .search-bar {
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 12px 24px;
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .search-bar input {
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    padding: 8px 14px;
    border-radius: 6px;
    width: 260px;
    outline: none;
    transition: border-color 0.2s;
  }
  .search-bar input:focus { border-color: var(--accent); }
  .search-bar input::placeholder { color: var(--text2); }
  .search-bar button {
    background: var(--accent);
    color: var(--bg);
    border: none;
    font-family: 'IBM Plex Sans', sans-serif;
    font-size: 13px;
    font-weight: 600;
    padding: 8px 18px;
    border-radius: 6px;
    cursor: pointer;
    transition: opacity 0.2s;
  }
  .search-bar button:hover { opacity: 0.85; }
  .search-bar .sep { color: var(--text2); font-size: 13px; }

  /* API link bar */
  .api-links {
    background: var(--bg);
    border-bottom: 1px solid var(--border);
    padding: 8px 24px;
    display: flex;
    gap: 6px;
    align-items: center;
    flex-wrap: wrap;
  }
  .api-links span.label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    color: var(--text2);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-right: 6px;
  }
  .api-chip {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--accent);
    background: var(--bg3);
    border: 1px solid var(--border);
    padding: 3px 10px;
    border-radius: 4px;
    text-decoration: none;
    transition: all 0.15s;
  }
  .api-chip:hover {
    background: var(--accent);
    color: var(--bg);
    border-color: var(--accent);
  }

  /* Main layout */
  .main {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 16px;
    padding: 20px 24px;
    max-width: 1600px;
    margin: 0 auto;
  }

  /* Cards */
  .card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }
  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
  }
  .card-header h2 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--text2);
  }
  .card-header .badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--accent);
    background: rgba(34,211,238,0.08);
    padding: 2px 8px;
    border-radius: 4px;
  }
  .card-body {
    padding: 14px 18px;
    max-height: 340px;
    overflow-y: auto;
  }
  .card-body::-webkit-scrollbar { width: 4px; }
  .card-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  /* Stats rows */
  .stat-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid rgba(30,42,58,0.5);
    font-size: 13px;
  }
  .stat-row:last-child { border-bottom: none; }
  .stat-row .label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
  }
  .stat-row .value {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    font-size: 13px;
  }
  .clickable {
    cursor: pointer;
    transition: color 0.15s;
  }
  .clickable:hover { color: var(--accent) !important; text-decoration: underline; }

  /* Protocol colors */
  .proto-tls    { color: var(--accent2); }
  .proto-ssh    { color: var(--purple); }
  .proto-http   { color: var(--orange); }
  .proto-tcp    { color: var(--blue); }
  .proto-modbus { color: var(--danger); }
  .proto-mqtt   { color: var(--warning); }
  .proto-dns    { color: #67e8f9; }
  .proto-other  { color: var(--text); }

  /* Full-width card */
  .full-width { grid-column: 1 / -1; }

  /* Events table */
  .events-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .events-table th {
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 1px;
    color: var(--text2);
    text-align: left;
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--bg2);
  }
  .events-table td {
    font-family: 'JetBrains Mono', monospace;
    padding: 7px 10px;
    border-bottom: 1px solid rgba(30,42,58,0.4);
    font-size: 12px;
    white-space: nowrap;
  }
  .events-table tr:hover td { background: rgba(34,211,238,0.04); }

  .score-high   { color: var(--danger);  font-weight: 700; }
  .score-med    { color: var(--warning); font-weight: 600; }
  .score-low    { color: var(--text2); }

  /* Attack type badges */
  .atk-badge {
    display: inline-block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 600;
    padding: 1px 6px;
    border-radius: 3px;
    margin: 1px 2px;
    cursor: pointer;
    transition: opacity 0.15s;
  }
  .atk-badge:hover { opacity: 0.75; }
  .atk-SQLI      { background: #7c3aed22; color: #a78bfa; border: 1px solid #7c3aed44; }
  .atk-XSS       { background: #f59e0b22; color: #fbbf24; border: 1px solid #f59e0b44; }
  .atk-LFI       { background: #f4735e22; color: #fb7185; border: 1px solid #f4735e44; }
  .atk-RFI       { background: #e1115522; color: #f43f5e; border: 1px solid #e1115544; }
  .atk-RCE       { background: #dc262622; color: #ef4444; border: 1px solid #dc262644; }
  .atk-PHP       { background: #818cf822; color: #818cf8; border: 1px solid #818cf844; }
  .atk-SSTI      { background: #c084fc22; color: #c084fc; border: 1px solid #c084fc44; }
  .atk-LOG4SHELL { background: #ff000022; color: #ff4444; border: 1px solid #ff000044; }
  .atk-SSRF      { background: #06b6d422; color: #22d3ee; border: 1px solid #06b6d444; }
  .atk-XXE       { background: #14b8a622; color: #2dd4bf; border: 1px solid #14b8a644; }
  .atk-CRLF      { background: #64748b22; color: #94a3b8; border: 1px solid #64748b44; }
  .atk-LDAPI     { background: #78716c22; color: #a8a29e; border: 1px solid #78716c44; }
  .atk-SHELLSHOCK { background: #b9121222; color: #ff6b6b; border: 1px solid #b9121244; }
  .atk-CREDENTIAL { background: #f59e0b22; color: #fcd34d; border: 1px solid #f59e0b44; }
  .atk-SCANNER   { background: #3b82f622; color: #60a5fa; border: 1px solid #3b82f644; }
  .atk-PROTO_ABUSE { background: #10b98122; color: #34d399; border: 1px solid #10b98144; }
  .atk-MODBUS    { background: #f9731622; color: #fb923c; border: 1px solid #f9731644; }
  .atk-SESSION   { background: #a855f722; color: #c084fc; border: 1px solid #a855f744; }
  .atk-SMB       { background: #0ea5e922; color: #38bdf8; border: 1px solid #0ea5e944; }
  .atk-K8S_ATTACK { background: #6366f122; color: #818cf8; border: 1px solid #6366f144; }
  .atk-SMTP_PROBE { background: #f59e0b22; color: #fbbf24; border: 1px solid #f59e0b44; }
  .atk-ORACLE_TNS { background: #dc262622; color: #f87171; border: 1px solid #dc262644; }
  .atk-MQTT_ATTACK { background: #0891b222; color: #22d3ee; border: 1px solid #0891b244; }
  .atk-FORTI_ATTACK { background: #ea580c22; color: #fb923c; border: 1px solid #ea580c44; }
  .atk-ARP_SPOOF { background: #dc262622; color: #ef4444; border: 1px solid #dc262644; }
  .atk-ARP_MAC_CHANGE { background: #f59e0b22; color: #fbbf24; border: 1px solid #f59e0b44; }
  .atk-ARP_GRATUITOUS { background: #64748b22; color: #94a3b8; border: 1px solid #64748b44; }
  .atk-DNS_SPOOF { background: #7c3aed22; color: #a78bfa; border: 1px solid #7c3aed44; }
  .atk-DNS_UNTRUSTED { background: #0ea5e922; color: #38bdf8; border: 1px solid #0ea5e944; }
  .atk-default   { background: #33333322; color: #999; border: 1px solid #33333344; }

  /* Detail panel (overlay) */
  .overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.7);
    z-index: 500;
    justify-content: center;
    align-items: flex-start;
    padding-top: 60px;
  }
  .overlay.active { display: flex; }
  .detail-panel {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    width: 800px;
    max-width: 90vw;
    max-height: 80vh;
    overflow-y: auto;
    padding: 24px;
  }
  .detail-panel h3 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
    color: var(--accent);
    margin-bottom: 16px;
  }
  .detail-panel .close-btn {
    float: right;
    background: none;
    border: 1px solid var(--border);
    color: var(--text2);
    padding: 4px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
  }
  .detail-panel .close-btn:hover { color: var(--danger); border-color: var(--danger); }
  .detail-grid {
    display: grid;
    grid-template-columns: 140px 1fr;
    gap: 6px 12px;
    font-size: 13px;
  }
  .detail-grid .dk {
    font-family: 'JetBrains Mono', monospace;
    color: var(--text2);
    font-size: 11px;
    text-transform: uppercase;
    padding: 4px 0;
  }
  .detail-grid .dv {
    font-family: 'JetBrains Mono', monospace;
    color: var(--text);
    padding: 4px 0;
    word-break: break-all;
  }
  .detail-grid .dv a {
    color: var(--accent);
    text-decoration: none;
  }
  .detail-grid .dv a:hover { text-decoration: underline; }

  /* Payload block */
  .payload-block {
    margin-top: 16px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--text2);
    white-space: pre-wrap;
    max-height: 200px;
    overflow-y: auto;
  }

  /* IP results view */
  .ip-results {
    grid-column: 1 / -1;
  }

  /* Loading */
  .loading {
    color: var(--text2);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    padding: 20px;
    text-align: center;
  }

  /* Mini stats for status cards */
  .stats-mini {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
  }
  .stats-mini .stat-row {
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
  }
  .stats-mini .stat-row:last-child { border-bottom: none; }
  .stats-mini .stat-label { color: var(--text2); }
  .stats-mini .stat-value { color: var(--accent); font-weight: 500; }

  /* Responsive */
  @media (max-width: 1100px) {
    .main { grid-template-columns: 1fr 1fr; }
  }
  @media (max-width: 700px) {
    .main { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div class="header">
  <h1>SENSOR<span>//</span>INTEL</h1>
  <div class="header-right">
    <div class="live-dot"></div>
    <span class="refresh-label">auto-refresh 30s</span>
  </div>
</div>

<div class="search-bar">
  <input id="ipSearch" type="text" placeholder="Search IP (e.g. 8.3.2.1)">
  <button onclick="searchIP()">Search IP</button>
  <input id="ruleSearch" type="text" placeholder="Rule (e.g. lfi_etc_passwd)" style="margin-left:20px">
  <button onclick="searchRule()">Search Rule</button>
  <span class="sep">|</span>
  <input id="protoSearch" type="text" placeholder="Protocol (e.g. TLS/1.2+)">
  <button onclick="searchProtocol()">Search Protocol</button>
  <span class="sep">|</span>
  <select id="attackSelect" style="background:var(--bg3);border:1px solid var(--border);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px;padding:8px 14px;border-radius:6px;outline:none;cursor:pointer;">
    <option value="">Attack Type...</option>
  </select>
  <button onclick="searchAttack()">Search Attacks</button>
  <label style="display:flex;align-items:center;gap:6px;margin-left:8px;font-size:12px;color:var(--text2);cursor:pointer;">
    <input type="checkbox" id="httpOnlyCheck" style="accent-color:var(--accent);cursor:pointer;">
    HTTP only
  </label>
</div>

<!-- KPI strip (from mv_event_stats — no COUNT on 25M rows) -->
<div id="kpiStrip" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px;padding:10px 22px;background:var(--bg);">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;">
    <div style="font-size:9px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px">Total Events</div>
    <div id="kpiTotal" style="font-size:20px;font-weight:800;color:var(--accent);font-family:'JetBrains Mono',monospace">—</div>
  </div>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;">
    <div style="font-size:9px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px">Last 24h</div>
    <div id="kpi24h" style="font-size:20px;font-weight:800;color:#22c55e;font-family:'JetBrains Mono',monospace">—</div>
  </div>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;">
    <div style="font-size:9px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px">Last 1h</div>
    <div id="kpi1h" style="font-size:20px;font-weight:800;color:var(--warning);font-family:'JetBrains Mono',monospace">—</div>
  </div>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;">
    <div style="font-size:9px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px">Last 5m</div>
    <div id="kpi5m" style="font-size:20px;font-weight:800;color:var(--danger);font-family:'JetBrains Mono',monospace">—</div>
  </div>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;">
    <div style="font-size:9px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px">Unique IPs (24h)</div>
    <div id="kpiIPs" style="font-size:20px;font-weight:800;color:var(--purple);font-family:'JetBrains Mono',monospace">—</div>
  </div>
</div>


<div class="main" id="mainGrid">
  <!-- Top Scanners -->
  <div class="card" id="scannersCard">
    <div class="card-header">
      <h2>Top Scanners</h2>
      <span class="badge" id="scannerCount">—</span>
    </div>
    <div class="card-body" id="scanners"><div class="loading">Loading...</div></div>
  </div>

  <!-- MiTM Detection Status -->
  <div class="card" id="mitmCard">
    <div class="card-header">
      <h2>🛡️ MiTM Detection</h2>
      <a href="/mitm" class="badge" style="text-decoration:none;cursor:pointer;">View All →</a>
    </div>
    <div class="card-body" id="mitmStatus"><div class="loading">Loading...</div></div>
  </div>

  <!-- Honeypots Status -->
  <div class="card" id="honeypotCard">
    <div class="card-header">
      <h2>🍯 Honeypots</h2>
      <a href="/honeypots/summary" class="badge" style="text-decoration:none;cursor:pointer;">View All →</a>
    </div>
    <div class="card-body" id="honeypotStatus"><div class="loading">Loading...</div></div>
  </div>

  <!-- Attack Patterns -->
  <div class="card full-width" id="attacksCard">
    <div class="card-header">
      <h2>Attack Patterns Detected</h2>
      <div style="display:flex;align-items:center;gap:12px;">
        <label style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text2);cursor:pointer;">
          <input type="checkbox" id="httpAttacksOnly" style="accent-color:var(--accent);cursor:pointer;" onchange="loadAttacks()">
          HTTP events only
        </label>
        <span class="badge" id="attackCount">—</span>
      </div>
    </div>
    <div class="card-body" id="attacks" style="max-height:360px"><div class="loading">Loading...</div></div>
  </div>

  <!-- Recent Events -->
  <div class="card full-width" id="eventsCard">
    <div class="card-header">
      <h2>Recent External Events</h2>
      <span class="badge" id="eventCount">—</span>
    </div>
    <div class="card-body" id="events" style="max-height:500px">
      <div class="loading">Loading...</div>
    </div>
  </div>
</div>

<!-- Detail overlay -->
<div class="overlay" id="overlay" onclick="if(event.target===this)closeDetail()">
  <div class="detail-panel" id="detailPanel"></div>
</div>

<script>
const API = '';  // same origin

// --- Helpers ---
function protoClass(p) {
  if (!p) return 'proto-other';
  const l = p.toLowerCase();
  if (l.includes('tls') || l.includes('ssl')) return 'proto-tls';
  if (l.includes('ssh')) return 'proto-ssh';
  if (l.includes('http')) return 'proto-http';
  if (l.includes('modbus') || l.includes('s7') || l.includes('iec')) return 'proto-modbus';
  if (l.includes('mqtt')) return 'proto-mqtt';
  if (l.includes('dns')) return 'proto-dns';
  if (l.includes('tcp') || l.includes('syn')) return 'proto-tcp';
  return 'proto-other';
}

function scoreClass(s) {
  if (s >= 8) return 'score-high';
  if (s >= 4) return 'score-med';
  return 'score-low';
}

function fmtTime(epoch) {
  if (!epoch) return '—';
  const d = new Date(epoch * 1000);
  return d.toISOString().replace('T', ' ').substring(0, 19);
}

function esc(s) {
  if (s === null || s === undefined) return '—';
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

async function fetchJSON(url) {
  const r = await fetch(API + url);
  if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
  return r.json();
}

// --- IP click → /events_ip/{ip} ---
function clickIP(ip) {
  document.getElementById('ipSearch').value = ip;
  searchIP();
}

// --- Protocol click → /protocol/{name} ---
function clickProtocol(name) {
  document.getElementById('protoSearch').value = name;
  searchProtocol();
}

// --- Event click → /event_full/{id} overlay ---
async function clickEvent(eventId) {
  const panel = document.getElementById('detailPanel');
  panel.innerHTML = '<div class="loading">Loading event...</div>';
  document.getElementById('overlay').classList.add('active');

  try {
    const ev = await fetchJSON('/event_full/' + eventId);
    let html = '<button class="close-btn" onclick="closeDetail()">✕ Close</button>';
    html += '<h3>Event Detail</h3>';
    html += '<div style="margin-bottom:8px;font-size:11px">';
    html += '<a class="api-chip" href="/event_full/' + esc(eventId) + '" target="_blank">&#x1F4CB; Event Details</a> ';
    html += '<a class="api-chip" href="/payload/' + esc(eventId) + '" target="_blank">&#x1F4C4; Payload</a> ';
    html += '<a class="api-chip" href="/pcap/' + esc(eventId) + '" target="_blank">&#x1F4E6; PCAP</a> ';
    html += '<a class="api-chip" href="/attack_event/' + esc(eventId) + '" target="_blank">&#x26A0; Attacks</a>';
    html += '<button class="api-chip" style="cursor:pointer" onclick="aiAnalyzeMain(\'' + esc(eventId) + '\',this)">&#x1F9E0; AI Analyze</button>';
    if (window._claudeAvailable) {
      html += '<button class="api-chip" style="cursor:pointer" onclick="claudeAnalyzeMain(\'' + esc(eventId) + '\',this)">&#x1F52C; AI DEEP</button>';
    }
    if (ev.src_ip) {
      html += '<button class="api-chip" style="cursor:pointer" onclick="huntIPMain(\'' + esc(ev.src_ip) + '\',this)">&#x1F3AF; Hunt IP</button>';
    }
    html += '</div>';
    html += '<div class="detail-grid">';

    const fields = [
      ['Event ID',    ev.event_id],
      ['Timestamp',   ev.timestamp],
      ['Source',      ev.source],
      ['Protocol',    ev.protocol ? '<span class="' + protoClass(ev.protocol) + ' clickable" onclick="closeDetail();clickProtocol(\'' + esc(ev.protocol) + '\')">' + esc(ev.protocol) + '</span>' : '—'],
      ['Src IP',      ev.src_ip ? '<span class="clickable" style="color:var(--accent)" onclick="closeDetail();clickIP(\'' + esc(ev.src_ip) + '\')">' + esc(ev.src_ip) + '</span>' : '—'],
      ['Src Port',    ev.src_port],
      ['Dst IP',      ev.dst_ip],
      ['Dst Port',    ev.dst_port],
      ['Scan Score',  ev.scan_score !== null ? '<span class="' + scoreClass(ev.scan_score) + '">' + ev.scan_score + '</span>' : '—'],
      ['Entropy',     ev.entropy],
      ['JA3',         ev.ja3],
      ['Payload Hash', ev.payload_hash],
    ];

    for (const [k, v] of fields) {
      html += '<div class="dk">' + k + '</div>';
      // already contains HTML for protocol/IP clickables
      if (typeof v === 'string' && v.includes('<')) {
        html += '<div class="dv">' + v + '</div>';
      } else {
        html += '<div class="dv">' + esc(v) + '</div>';
      }
    }

    if (ev.metadata) {
      html += '<div class="dk">Metadata</div>';
      html += '<div class="dv" style="font-size:11px">' + esc(JSON.stringify(ev.metadata, null, 2)).substring(0, 2000) + '</div>';
    }

    // FortiGate honeypot details
    if (ev.fortigate_details) {
      const fg = ev.fortigate_details;
      html += '<div class="dk">FortiGate Event</div>';
      html += '<div class="dv"><span class="atk-badge atk-FORTI_ATTACK">' + esc(fg.event_type) + '</span></div>';
      if (fg.method && fg.path) {
        html += '<div class="dk">Request</div>';
        html += '<div class="dv" style="font-family:JetBrains Mono;font-size:12px">' + esc(fg.method) + ' ' + esc(fg.path) + '</div>';
      }
      if (fg.user_agent) {
        html += '<div class="dk">User-Agent</div>';
        html += '<div class="dv" style="font-size:11px;word-break:break-all">' + esc(fg.user_agent) + '</div>';
      }
      if (fg.data && Object.keys(fg.data).length > 0) {
        html += '<div class="dk">Captured Data</div>';
        html += '<div class="dv" style="font-size:11px;background:var(--bg);padding:8px;border-radius:4px;font-family:JetBrains Mono">';
        for (const [k, v] of Object.entries(fg.data)) {
          if (k === 'password' || k === 'credential' || k === 'secretkey') {
            html += '<div><span style="color:var(--danger)">' + esc(k) + ':</span> <span style="color:#f472b6">' + esc(String(v)) + '</span></div>';
          } else if (k === 'username') {
            html += '<div><span style="color:var(--accent)">' + esc(k) + ':</span> <span style="color:#38bdf8">' + esc(String(v)) + '</span></div>';
          } else {
            html += '<div><span style="color:var(--text2)">' + esc(k) + ':</span> ' + esc(String(v).substring(0, 200)) + '</div>';
          }
        }
        html += '</div>';
      }
    }

    html += '</div>';

    // Load attack patterns for this event
    try {
      const atkData = await fetchJSON('/attack_event/' + eventId);
      if (atkData && atkData.length > 0) {
        html += '<div style="margin-top:16px;padding:12px;background:var(--bg);border:1px solid var(--border);border-radius:6px">';
        html += '<div style="font-family:JetBrains Mono;font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Attack Patterns Detected</div>';
        for (const a of atkData) {
          html += '<div style="margin:4px 0;font-size:12px">';
          html += '<span class="atk-badge atk-' + esc(a.attack_type) + '">' + esc(a.attack_type) + '</span> ';
          html += '<span style="font-family:JetBrains Mono;color:var(--text2);font-size:11px">' + esc(a.rule_name) + '</span> ';
          if (a.matched_text) {
            html += '<span style="font-family:JetBrains Mono;color:var(--danger);font-size:11px;opacity:0.8">→ ' + esc(a.matched_text.substring(0, 80)) + '</span>';
          }
          html += '</div>';
        }
        html += '</div>';
      }
    } catch(e) { /* no attack data */ }

    if (ev.payload) {
      html += '<div class="payload-block"><pre style="margin:0;white-space:pre-wrap;word-break:break-all">' + esc(ev.payload).substring(0, 4000) + '</pre></div>';
    }

    panel.innerHTML = html;
  } catch (e) {
    panel.innerHTML = '<button class="close-btn" onclick="closeDetail()">✕</button><h3>Error</h3><p>' + esc(e.message) + '</p>';
  }
}

function aiAnalyzeMain(eventId, btn) {
  btn.disabled = true;
  btn.textContent = '⏳ Analysing...';
  btn.style.color = '#eab308';
  fetch('/ai/analyze/' + encodeURIComponent(eventId), {method: 'POST'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.detail) {
        btn.textContent = '❌ ' + data.detail.substring(0, 40);
        btn.style.color = '#ef4444';
        return;
      }
      var cls = data.triage_class || '?';
      var clsColor = {'CRITICAL':'#ef4444','SUSPICIOUS':'#f97316','KNOWN':'#38bdf8','NOISE':'#64748b'}[cls] || '#94a3b8';
      btn.innerHTML = '&#x1F9E0; ' + cls;
      btn.style.color = clsColor;
      btn.disabled = false;

      // Append result block to detail panel
      var panel = document.getElementById('detailPanel');
      if (panel) {
        var existing = document.getElementById('ai-main-result');
        if (existing) existing.remove();
        var div = document.createElement('div');
        div.id = 'ai-main-result';
        div.style.cssText = 'margin-top:16px;padding:12px;background:var(--bg);border:1px solid #a78bfa33;border-radius:6px';
        var h = '<div style="font-family:JetBrains Mono;font-size:11px;color:#a78bfa;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">&#x1F9E0; AI Analysis Result</div>';
        h += '<div class="detail-grid">';
        h += '<div class="dk">Classification</div><div class="dv" style="color:' + clsColor + ';font-weight:700">' + cls + '</div>';
        h += '<div class="dk">Confidence</div><div class="dv">' + (data.confidence || 0) + '%</div>';
        h += '<div class="dk">Novelty</div><div class="dv">' + (data.novelty_score || 0) + '/10</div>';
        h += '<div class="dk">Reasoning</div><div class="dv" style="font-size:11px">' + esc(data.reasoning || '') + '</div>';
        if (data.known_cve) h += '<div class="dk">CVE</div><div class="dv" style="color:#f87171">' + esc(data.known_cve) + '</div>';
        if (data.zero_day_score != null) {
          var zc = data.zero_day_score >= 70 ? '#ef4444' : data.zero_day_score >= 40 ? '#f97316' : '#22c55e';
          h += '<div class="dk">0-Day Score</div><div class="dv" style="color:' + zc + ';font-weight:700">' + data.zero_day_score + '%</div>';
        }
        if (data.deep_analysis) {
          var da = data.deep_analysis;
          if (da.exploit_type) h += '<div class="dk">Exploit Type</div><div class="dv">' + esc(da.exploit_type) + '</div>';
          if (da.attack_objective) h += '<div class="dk">Objective</div><div class="dv" style="font-size:11px">' + esc(da.attack_objective) + '</div>';
          if (da.suggested_rule_name) h += '<div class="dk">Suggested Rule</div><div class="dv" style="color:#a78bfa;font-family:monospace">' + esc(da.suggested_rule_name) + '</div>';
          if (da.summary) h += '<div class="dk">Summary</div><div class="dv" style="font-size:11px">' + esc(da.summary) + '</div>';
        }
        if (data.iocs && data.iocs.length) h += '<div class="dk">IOCs</div><div class="dv" style="font-size:10px;color:#f97316">' + data.iocs.map(esc).join(', ') + '</div>';
        h += '</div>';
        div.innerHTML = h;
        panel.appendChild(div);
      }
    })
    .catch(function(err) {
      btn.textContent = '❌ Error';
      btn.style.color = '#ef4444';
      setTimeout(function() { btn.innerHTML = '&#x1F9E0; AI Analyze'; btn.style.color = '#a78bfa'; btn.disabled = false; }, 3000);
    });
}

function huntIPMain(ip, btn) {
  btn.disabled = true;
  btn.innerHTML = '&#x23F3; Hunting...';
  btn.style.color = '#eab308';
  fetch('/attacker_hunting/' + encodeURIComponent(ip) + '/hunt', {method: 'POST'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.detail) {
        btn.textContent = '❌ ' + data.detail.substring(0, 50);
        btn.style.color = '#ef4444';
        setTimeout(function() { btn.innerHTML = '&#x1F3AF; Hunt IP'; btn.style.color = '#f59e0b'; btn.disabled = false; }, 4000);
        return;
      }
      var thr = data.threat_level || '?';
      var thrColor = {'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e'}[thr] || '#94a3b8';
      btn.innerHTML = '&#x1F3AF; ' + thr;
      btn.style.color = thrColor;
      btn.disabled = false;

      // Append hunt result to detail panel
      var panel = document.getElementById('detailPanel');
      if (panel) {
        var existing = document.getElementById('hunt-main-result');
        if (existing) existing.remove();
        var div = document.createElement('div');
        div.id = 'hunt-main-result';
        div.style.cssText = 'margin-top:16px;padding:12px;background:var(--bg);border:1px solid #f59e0b33;border-radius:6px';
        var h = '<div style="font-family:JetBrains Mono;font-size:11px;color:#f59e0b;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">&#x1F3AF; Attacker Hunt Result</div>';
        h += '<div class="detail-grid">';
        h += '<div class="dk">IP</div><div class="dv"><a href="/attacker_hunting/' + esc(ip) + '" target="_blank" style="color:#38bdf8">' + esc(ip) + '</a></div>';
        h += '<div class="dk">Threat Level</div><div class="dv" style="color:' + thrColor + ';font-weight:700">' + esc(thr) + '</div>';
        h += '<div class="dk">Intent</div><div class="dv">' + esc(data.intent || 'UNKNOWN') + '</div>';
        h += '<div class="dk">Abuse Score</div><div class="dv">' + (data.abuse_score != null ? data.abuse_score + '/100' : '—') + '</div>';
        if (data.tags && data.tags.length) {
          h += '<div class="dk">Tags</div><div class="dv">';
          data.tags.forEach(function(t) { h += '<span style="display:inline-block;padding:1px 7px;border-radius:8px;font-size:10px;background:#33415544;color:#94a3b8;margin:1px">' + esc(t) + '</span> '; });
          h += '</div>';
        }
        if (data.mitre_techniques && data.mitre_techniques.length) {
          h += '<div class="dk">MITRE</div><div class="dv" style="font-size:10px">' + data.mitre_techniques.map(esc).join(', ') + '</div>';
        }
        h += '<div class="dk">APT Candidates</div><div class="dv">' + (data.apt_candidates || 0) + '</div>';
        if (data.ai_summary) {
          h += '<div class="dk">AI Summary</div><div class="dv" style="font-size:11px">' + esc(data.ai_summary) + '</div>';
        }
        h += '</div>';
        h += '<div style="margin-top:8px;font-size:10px"><a href="/attacker_hunting/' + esc(ip) + '" target="_blank" style="color:#f59e0b">View Full Profile →</a></div>';
        div.innerHTML = h;
        panel.appendChild(div);
      }
    })
    .catch(function(err) {
      btn.textContent = '❌ Error';
      btn.style.color = '#ef4444';
      setTimeout(function() { btn.innerHTML = '&#x1F3AF; Hunt IP'; btn.style.color = '#f59e0b'; btn.disabled = false; }, 4000);
    });
}

function closeDetail() {
  document.getElementById('overlay').classList.remove('active');
}

// AI Deep Analysis availability check (any configured backend: OpenAI / Claude)
window._claudeAvailable = false;
window._aiDeepBackend   = null;
window._aiDeepModel     = null;
fetch('/ai/deep-status', {credentials:'same-origin'})
  .then(function(r){ return r.json(); })
  .then(function(d){
    window._claudeAvailable = d.available === true;
    window._aiDeepBackend   = d.backend || null;
    window._aiDeepModel     = d.deep_model || d.model || null;
  })
  .catch(function(){ window._claudeAvailable = false; });

function claudeAnalyzeMain(eventId, btn) {
  /* Function name retained for backward compat; backend dispatched server-side. */
  btn.disabled = true;
  btn.innerHTML = '&#x23F3; AI Deep...';
  btn.style.color = '#eab308';
  fetch('/ai/deep-analyze/' + encodeURIComponent(eventId), {method:'POST',credentials:'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.detail || data.error) {
        btn.innerHTML = '&#x274C; ' + (data.detail || data.error || '').substring(0, 40);
        btn.style.color = '#ef4444';
        setTimeout(function() { btn.innerHTML = '&#x1F52C; AI DEEP'; btn.style.color='#d97706'; btn.disabled=false; }, 5000);
        return;
      }
      var v = data.verdict || '?';
      var vc = {'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e','INFO':'#38bdf8'}[v] || '#94a3b8';
      btn.innerHTML = '&#x1F52C; ' + v;
      btn.style.color = vc;
      btn.disabled = false;
      // Append AI Deep result to detail panel
      var panel = document.getElementById('detailPanel');
      if (panel) {
        var existing = document.getElementById('claude-main-result');
        if (existing) existing.remove();
        var div = document.createElement('div');
        div.id = 'claude-main-result';
        div.style.cssText = 'margin-top:16px;padding:12px;background:var(--bg);border:1px solid #d9770633;border-radius:6px';
        var _backend = esc(String(data._backend || window._aiDeepBackend || 'AI').toUpperCase());
        var _model   = esc(data._deep_model || window._aiDeepModel || '');
        var h = '<div style="font-family:JetBrains Mono;font-size:11px;color:#d97706;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">&#x1F52C; AI DEEP Analysis ('+_backend+(_model?' &mdash; '+_model:'')+')</div>';
        h += '<div class="detail-grid">';
        h += '<div class="dk">Verdict</div><div class="dv" style="color:' + vc + ';font-weight:700">' + esc(v) + ' (' + esc(data.confidence||'?') + '% confidence)</div>';
        h += '<div class="dk">Attack Type</div><div class="dv">' + esc(data.attack_type||'—') + '</div>';
        if (data.technique) h += '<div class="dk">MITRE</div><div class="dv" style="color:#f87171;font-weight:700">' + esc(data.technique) + ' — ' + esc(data.tactic||'') + '</div>';
        if (data.cve) h += '<div class="dk">CVE</div><div class="dv" style="color:#f87171;font-weight:700">' + esc(data.cve) + '</div>';
        if (data.zero_day_probability != null) {
          var zc = data.zero_day_probability >= 70 ? '#ef4444' : data.zero_day_probability >= 40 ? '#f97316' : '#22c55e';
          h += '<div class="dk">0-Day Prob</div><div class="dv" style="color:' + zc + ';font-weight:700">' + data.zero_day_probability + '%</div>';
        }
        if (data.kill_chain_phase) h += '<div class="dk">Kill Chain</div><div class="dv">' + esc(data.kill_chain_phase) + '</div>';
        if (data.threat_actor) h += '<div class="dk">Threat Actor</div><div class="dv" style="color:#ef4444;font-weight:700">' + esc(data.threat_actor) + '</div>';
        h += '<div class="dk">Analysis</div><div class="dv" style="font-size:11px;white-space:pre-wrap">' + esc(data.exploit_analysis||'') + '</div>';
        if (data.recommendations && data.recommendations.length) {
          h += '<div class="dk">Actions</div><div class="dv" style="font-size:11px">';
          data.recommendations.forEach(function(r,i){ h += '<div style="margin:2px 0">' + esc((i+1)+'. '+r) + '</div>'; });
          h += '</div>';
        }
        h += '<div class="dk">Summary</div><div class="dv" style="font-size:11px">' + esc(data.summary||'') + '</div>';
        if (data._meta) {
          h += '<div class="dk">Cost</div><div class="dv" style="font-size:10px;color:#64748b">' + esc(data._meta.model) + ' — '
            + (data._meta.input_tokens||0) + ' in / ' + (data._meta.output_tokens||0) + ' out — '
            + (data._meta.elapsed_ms||0) + 'ms</div>';
        }
        h += '</div>';
        div.innerHTML = h;
        panel.appendChild(div);
      }
    })
    .catch(function(err) {
      btn.innerHTML = '&#x274C; Error';
      btn.style.color = '#ef4444';
      setTimeout(function() { btn.innerHTML = '&#x1F52C; AI DEEP'; btn.style.color='#d97706'; btn.disabled=false; }, 5000);
    });
}

// --- Search Rule ---
async function searchRule() {
  const rule = document.getElementById('ruleSearch').value.trim();
  if (!rule) return;
  const container = document.getElementById('events');
  container.innerHTML = '<div class="loading">Searching for rule: ' + esc(rule) + '...</div>';
  try {
    const data = await fetchJSON('/attack/rule/' + encodeURIComponent(rule) + '?limit=200');
    if (!data || data.length === 0) {
      container.innerHTML = '<div class="loading">No events found for rule: ' + esc(rule) + '</div>';
      return;
    }
    let html = '<table class="events-table"><thead><tr>';
    html += '<th>Time</th><th>Source IP</th><th>Port</th><th>Protocol</th><th>Attack Types</th>';
    html += '</tr></thead><tbody>';
    for (const e of data) {
      const ts = e.timestamp ? new Date(e.timestamp).toLocaleString() : '';
      html += '<tr class="clickable" onclick="loadEvent(\'' + esc(e.event_id) + '\')">';
      html += '<td>' + ts + '</td>';
      html += '<td>' + esc(e.src_ip || '') + '</td>';
      html += '<td>' + (e.dst_port || '') + '</td>';
      html += '<td>' + esc(e.protocol || '') + '</td>';
      html += '<td style="font-size:11px">' + esc(e.attack_types || '') + '</td>';
      html += '</tr>';
    }
    html += '</tbody></table>';
    html += '<div style="margin-top:10px;font-size:11px;color:var(--text2)">Found ' + data.length + ' events for rule: ' + esc(rule) + '</div>';
    container.innerHTML = html;
  } catch(e) {
    container.innerHTML = '<div class="loading">Error searching rule</div>';
  }
}

// --- Search IP ---
async function searchIP() {
  const ip = document.getElementById('ipSearch').value.trim();
  if (!ip) return;

  // Remove previous results card
  const prev = document.getElementById('searchResults');
  if (prev) prev.remove();

  const card = document.createElement('div');
  card.className = 'card full-width';
  card.id = 'searchResults';
  card.innerHTML = '<div class="card-header"><h2>Events from ' + esc(ip) + '</h2>'
    + '<span><a class="api-chip" href="/events_ip/' + encodeURIComponent(ip) + '" target="_blank">JSON ↗</a> '
    + '<button class="close-btn" onclick="this.closest(\'.card\').remove()" style="margin-left:8px">✕</button></span></div>'
    + '<div class="card-body" style="max-height:400px"><div class="loading">Searching...</div></div>';

  const grid = document.getElementById('mainGrid');
  grid.insertBefore(card, grid.firstChild);

  try {
    const data = await fetchJSON('/events_ip/' + encodeURIComponent(ip));
    renderEventsTable(card.querySelector('.card-body'), data, 'ip');
  } catch (e) {
    card.querySelector('.card-body').innerHTML = '<div class="loading">Error: ' + esc(e.message) + '</div>';
  }
}

// --- Search Protocol ---
async function searchProtocol() {
  const proto = document.getElementById('protoSearch').value.trim();
  if (!proto) return;

  const prev = document.getElementById('protoResults');
  if (prev) prev.remove();

  const card = document.createElement('div');
  card.className = 'card full-width';
  card.id = 'protoResults';
  card.innerHTML = '<div class="card-header"><h2>Events — ' + esc(proto) + '</h2>'
    + '<span><a class="api-chip" href="/protocol/' + encodeURIComponent(proto) + '" target="_blank">JSON ↗</a> '
    + '<button class="close-btn" onclick="this.closest(\'.card\').remove()" style="margin-left:8px">✕</button></span></div>'
    + '<div class="card-body" style="max-height:400px"><div class="loading">Searching...</div></div>';

  const grid = document.getElementById('mainGrid');
  grid.insertBefore(card, grid.firstChild);

  try {
    const data = await fetchJSON('/protocol/' + encodeURIComponent(proto));
    renderEventsTable(card.querySelector('.card-body'), data, 'proto');
  } catch (e) {
    card.querySelector('.card-body').innerHTML = '<div class="loading">Error: ' + esc(e.message) + '</div>';
  }
}

// --- Country code to flag emoji ---
function countryFlag(code) {
  if (!code || code === '??' || code === 'unknown') return '🏴';
  if (code === 'LAN') return '🏠';
  if (code === 'PIRATE') return '🏴‍☠️';
  try {
    // Only convert 2-letter codes to regional indicator symbols
    if (code.length !== 2) return '🏴';
    const codePoints = [...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65);
    return String.fromCodePoint(...codePoints);
  } catch(e) {
    return '🏴';
  }
}

// --- Render events table (reusable for main, IP search, protocol search) ---
function renderEventsTable(container, rows, mode) {
  if (!rows || rows.length === 0) {
    container.innerHTML = '<div class="loading">No events found</div>';
    return;
  }

  let html = '<table class="events-table"><thead><tr>'
    + '<th>Time</th><th>Source</th><th>🌍</th><th>Src IP</th><th>Protocol</th>'
    + '<th>Dst Port</th><th>Score</th><th>Attacks</th><th>Event</th>'
    + '</tr></thead><tbody>';

  for (const r of rows) {
    const eid = r.event_id || r[0];
    const src = r.source || r[1] || '';
    const sip = (r.src_ip || r[2] || '').split('/')[0];
    const proto = r.protocol || r[4] || '';
    const dport = r.dst_port || r[5] || '';
    const ts = r.timestamp || r[6];
    const score = r.scan_score !== undefined ? r.scan_score : (r[7] || 0);
    const atypes = r.attack_types || '';
    const country = r.country_code || '??';

    const epoch = typeof ts === 'number' ? ts : (Date.parse(ts) / 1000);

    // Badges for hunted / AI analyzed
    let ipBadges = '';
    if (window._huntedIPs && window._huntedIPs.has(sip)) {
      ipBadges += ' <span title="Profiled in Hunting" style="font-size:10px;cursor:pointer" onclick="event.stopPropagation();window.location.href=\'/attacker_hunting/' + esc(sip) + '\'">🎯</span>';
    }
    if (window._aiIPs && window._aiIPs[sip]) {
      var aiCls = window._aiIPs[sip];
      var aiColor = {'CRITICAL':'#ef4444','SUSPICIOUS':'#f97316','KNOWN':'#38bdf8','NOISE':'#64748b'}[aiCls] || '#94a3b8';
      ipBadges += ' <span title="AI: ' + esc(aiCls) + '" style="font-size:10px;color:' + aiColor + '">🧠</span>';
    }

    html += '<tr>';
    html += '<td>' + fmtTime(epoch) + '</td>';
    html += '<td>' + esc(src) + '</td>';
    html += '<td title="' + esc(country) + '" style="font-size:16px;cursor:help">' + countryFlag(country) + '</td>';
    html += '<td class="clickable" style="color:var(--accent)" onclick="clickIP(\'' + esc(sip) + '\')">' + esc(sip) + ipBadges + '</td>';
    html += '<td class="' + protoClass(proto) + ' clickable" onclick="clickProtocol(\'' + esc(proto) + '\')">' + esc(proto) + '</td>';
    html += '<td>' + esc(dport) + '</td>';
    html += '<td class="' + scoreClass(score) + '">' + (score !== null ? score : '—') + '</td>';
    html += '<td>' + atkBadges(atypes) + '</td>';
    html += '<td><span class="clickable" style="color:var(--accent)" onclick="clickEvent(\'' + esc(eid) + '\')">detail ↗</span></td>';
    html += '</tr>';
  }

  html += '</tbody></table>';
  container.innerHTML = html;
}

// --- Attack type badge ---
function atkBadge(type) {
  const cls = 'atk-' + (type || 'default');
  return '<span class="atk-badge ' + cls + '" onclick="clickAttack(\'' + esc(type) + '\')">' + esc(type) + '</span>';
}

function atkBadges(types) {
  if (!types) return '';
  return types.split(',').map(t => atkBadge(t.trim())).join('');
}

// --- Attack type click → /attack/type/{type} ---
function clickAttack(type) {
  document.getElementById('attackSelect').value = type;
  searchAttack();
}

// --- View attack events directly (called from Attack Patterns table) ---
async function viewAttackEvents(type, httpOnly) {
  const prev = document.getElementById('attackResults');
  if (prev) prev.remove();

  const endpoint = httpOnly ? '/attack/type/' + encodeURIComponent(type) + '/http?limit=50' : '/attack/type/' + encodeURIComponent(type) + '?limit=50';
  const title = httpOnly ? type + ' (HTTP only)' : type;

  const card = document.createElement('div');
  card.className = 'card full-width';
  card.id = 'attackResults';
  card.innerHTML = '<div class="card-header"><h2>🔍 Attack Events: ' + esc(title) + '</h2>'
    + '<span><a class="api-chip" href="' + endpoint + '" target="_blank">JSON ↗</a> '
    + '<button class="close-btn" onclick="this.closest(\'.card\').remove()" style="margin-left:8px">✕ Close</button></span></div>'
    + '<div class="card-body" style="max-height:600px;overflow:auto"><div class="loading">Loading last 50 events...</div></div>';

  const grid = document.getElementById('mainGrid');
  grid.insertBefore(card, grid.firstChild);

  // Scroll to the card
  card.scrollIntoView({ behavior: 'smooth', block: 'start' });

  try {
    const data = await fetchJSON(endpoint);
    renderAttackEventsTable(card.querySelector('.card-body'), data);
  } catch (e) {
    card.querySelector('.card-body').innerHTML = '<div class="loading">Error: ' + esc(e.message) + '</div>';
  }
}

// --- Search Attack Type (via new endpoint) ---
async function searchAttack() {
  const type = document.getElementById('attackSelect').value;
  if (!type) return;
  const httpOnly = document.getElementById('httpOnlyCheck').checked;
  viewAttackEvents(type, httpOnly);
}

// --- Render attack events table with payload preview ---
function renderAttackEventsTable(container, rows) {
  if (!rows || rows.length === 0) {
    container.innerHTML = '<div class="loading">No events found</div>';
    return;
  }

  let html = '<table class="events-table"><thead><tr>'
    + '<th>Time</th><th>🌍</th><th>Src IP</th><th>Protocol</th>'
    + '<th>Dst Port</th><th>Attacks</th><th>Payload Preview</th><th>Detail</th>'
    + '</tr></thead><tbody>';

  for (const r of rows) {
    const eid = r.event_id;
    const sip = r.src_ip || '';
    const proto = r.protocol || '';
    const dport = r.dst_port || '';
    const ts = r.timestamp;
    const atypes = r.attack_types || '';
    const payload = r.payload_preview || '';
    const country = r.country_code || '??';

    html += '<tr>';
    html += '<td>' + fmtTime(ts) + '</td>';
    html += '<td title="' + esc(country) + '" style="font-size:16px;cursor:help">' + countryFlag(country) + '</td>';
    html += '<td class="clickable" style="color:var(--accent)" onclick="clickIP(\'' + esc(sip) + '\')">' + esc(sip) + '</td>';
    html += '<td class="' + protoClass(proto) + ' clickable" onclick="clickProtocol(\'' + esc(proto) + '\')">' + esc(proto) + '</td>';
    html += '<td>' + esc(dport) + '</td>';
    html += '<td>' + atkBadges(atypes) + '</td>';
    html += '<td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;font-size:11px;color:var(--text2)" title="' + esc(payload) + '">' + esc(payload.substring(0, 80)) + '</td>';
    html += '<td><span class="clickable" style="color:var(--accent)" onclick="clickEvent(\'' + esc(eid) + '\')">detail ↗</span></td>';
    html += '</tr>';
  }

  html += '</tbody></table>';
  html += '<div style="margin-top:10px;font-size:11px;color:var(--text2)">Showing ' + rows.length + ' events</div>';
  container.innerHTML = html;
}

// --- KPI strip (fast — from materialised view) ---
async function loadKPIs() {
  try {
    const s = await fetchJSON('/stats/summary');
    const fmt = n => n >= 1000000 ? (n/1000000).toFixed(1)+'M' : n >= 1000 ? (n/1000).toFixed(1)+'K' : String(n);
    document.getElementById('kpiTotal').textContent = fmt(s.total_events || 0);
    document.getElementById('kpi24h').textContent = fmt(s.recent_24h || 0);
    document.getElementById('kpi1h').textContent = fmt(s.recent_1h || 0);
    document.getElementById('kpi5m').textContent = String(s.recent_5m || 0);
    document.getElementById('kpiIPs').textContent = fmt(s.unique_ips_24h || 0);
  } catch(e) {}
}

// --- Cache attack types (loaded once, used by both dropdown and table) ---
let _attackTypesCache = null;
async function _getAttackTypes() {
  if (!_attackTypesCache) _attackTypesCache = await fetchJSON('/attack/types');
  return _attackTypesCache;
}

// --- Load attack type options ---
async function loadAttackTypes() {
  try {
    const data = await _getAttackTypes();
    const sel = document.getElementById('attackSelect');
    sel.innerHTML = '<option value="">Attack Type...</option>';
    for (const r of data) {
      const opt = document.createElement('option');
      opt.value = r.attack_type;
      opt.textContent = r.attack_type + ' (' + r.event_count + ')';
      sel.appendChild(opt);
    }
  } catch(e) { /* ignore */ }
}

// --- Load dashboard data ---
async function loadAttacks() {
  try {
    const data = await _getAttackTypes();
    document.getElementById('attackCount').textContent = data.length;

    let html = '<table class="events-table"><thead><tr>'
      + '<th>Attack Type</th><th>Events</th><th>Rules</th><th>Top Rule</th><th>View</th>'
      + '</tr></thead><tbody>';

    for (const r of data) {
      html += '<tr>';
      html += '<td>' + atkBadge(r.attack_type) + '</td>';
      html += '<td class="value">' + r.event_count + '</td>';
      html += '<td>' + r.rule_count + '</td>';
      html += '<td style="font-size:11px;color:var(--text2)">' + esc(r.top_rule) + '</td>';
      html += '<td>';
      html += '<span class="clickable" style="color:var(--accent);font-size:11px;margin-right:8px" onclick="viewAttackEvents(\'' + esc(r.attack_type) + '\', false)">all ↗</span>';
      html += '<span class="clickable" style="color:var(--orange);font-size:11px" onclick="viewAttackEvents(\'' + esc(r.attack_type) + '\', true)">HTTP ↗</span>';
      html += '</td>';
      html += '</tr>';
    }
    html += '</tbody></table>';
    document.getElementById('attacks').innerHTML = html || '<div class="loading">No attacks detected</div>';
  } catch (e) {
    document.getElementById('attacks').innerHTML = '<div class="loading">No attack data (classifier not yet active)</div>';
  }
}

async function loadScanners() {
  try {
    const data = await fetchJSON('/top_scanners');
    document.getElementById('scannerCount').textContent = data.length;
    let html = '';
    for (const r of data) {
      const ip = (r[0] || '').split('/')[0], count = r[1], maxScore = r[2], country = r[3] || '??';
      const flag = countryFlag(country);
      let badges = '';
      if (window._huntedIPs && window._huntedIPs.has(ip)) badges += ' <span title="Hunted" style="font-size:10px;cursor:pointer" onclick="event.stopPropagation();window.location.href=\'/attacker_hunting/' + esc(ip) + '\'">🎯</span>';
      if (window._aiIPs && window._aiIPs[ip]) {
        var aic = window._aiIPs[ip];
        var ac = {'CRITICAL':'#ef4444','SUSPICIOUS':'#f97316','KNOWN':'#38bdf8','NOISE':'#64748b'}[aic]||'#94a3b8';
        badges += ' <span title="AI: ' + esc(aic) + '" style="font-size:10px;color:'+ac+'">🧠</span>';
      }
      html += '<div class="stat-row">';
      html += '<span class="label"><span title="' + esc(country) + '" style="cursor:help">' + flag + '</span> <span class="clickable" style="color:var(--accent)" onclick="clickIP(\'' + esc(ip) + '\')">' + esc(ip) + '</span>' + badges + '</span>';
      html += '<span class="value"><span class="' + scoreClass(maxScore) + '" title="max score">' + maxScore + '</span> · ' + count + '</span>';
      html += '</div>';
    }
    document.getElementById('scanners').innerHTML = html || '<div class="loading">No data</div>';
  } catch (e) {
    document.getElementById('scanners').innerHTML = '<div class="loading">Error</div>';
  }
}

async function loadEvents() {
  try {
    const data = await fetchJSON('/events?limit=200');
    document.getElementById('eventCount').textContent = data.length;
    renderEventsTable(document.getElementById('events'), data, 'main');
  } catch (e) {
    document.getElementById('events').innerHTML = '<div class="loading">Error loading events</div>';
  }
}

async function loadMitmStatus() {
  try {
    const data = await fetchJSON('/mitm/summary');
    const el = document.getElementById('mitmStatus');
    if (!data.enabled) {
      el.innerHTML = '<div style="color:var(--text2);font-size:12px;padding:8px;">MiTM detection not configured</div>';
      return;
    }
    const sevColor = (sev) => {
      if (sev === 'CRITICAL') return 'var(--danger)';
      if (sev === 'HIGH') return 'var(--warning)';
      return 'var(--text2)';
    };
    let html = '<div class="stats-mini">';
    html += `<div class="stat-row"><span class="stat-label">Events (24h)</span><span class="stat-value">${data.last_24h || 0}</span></div>`;
    html += `<div class="stat-row"><span class="stat-label">Unacked Critical/High</span><span class="stat-value" style="color:${data.unacked_critical_high > 0 ? 'var(--danger)' : 'var(--accent2)'}">${data.unacked_critical_high || 0}</span></div>`;
    if (data.most_recent) {
      html += `<div class="stat-row"><span class="stat-label">Latest</span><span class="stat-value" style="color:${sevColor(data.most_recent.severity)}">${data.most_recent.attack_type}</span></div>`;
      html += `<div class="stat-row"><span class="stat-label">From IP</span><span class="stat-value">${data.most_recent.src_ip || '—'}</span></div>`;
    }
    html += '</div>';
    el.innerHTML = html;
  } catch (e) {
    document.getElementById('mitmStatus').innerHTML = '<div class="loading" style="font-size:11px;">Not available</div>';
  }
}

async function loadHoneypotStatus() {
  try {
    const data = await fetchJSON('/honeypots/summary');
    const el = document.getElementById('honeypotStatus');
    let html = '<div class="stats-mini">';
    html += `<div class="stat-row"><span class="stat-label">Total Events</span><span class="stat-value">${(data.total_events || 0).toLocaleString()}</span></div>`;
    html += `<div class="stat-row"><span class="stat-label">Unique IPs</span><span class="stat-value">${(data.total_unique_ips || 0).toLocaleString()}</span></div>`;
    if (data.honeypots && data.honeypots.length > 0) {
      html += '<div style="margin-top:8px;font-size:11px;color:var(--text2);">';
      for (const hp of data.honeypots.slice(0, 3)) {
        html += `<div style="display:flex;justify-content:space-between;padding:2px 0;"><span>${hp.source}</span><span style="color:var(--accent)">${(hp.total_events || 0).toLocaleString()}</span></div>`;
      }
      html += '</div>';
    }
    html += '</div>';
    el.innerHTML = html;
  } catch (e) {
    document.getElementById('honeypotStatus').innerHTML = '<div class="loading" style="font-size:11px;">Not available</div>';
  }
}

// --- Init + auto-refresh ---
window._huntedIPs = new Set();
window._aiIPs = {};

async function loadBadgeData() {
  try {
    const [huntRes, aiRes] = await Promise.all([
      fetchJSON('/attacker_hunting/ips').catch(() => ({ips:[]})),
      fetchJSON('/ai/analyzed_ips').catch(() => ({ips:{}}))
    ]);
    window._huntedIPs = new Set(huntRes.ips || []);
    window._aiIPs = aiRes.ips || {};
  } catch(e) {}
}

async function refresh() {
  _attackTypesCache = null;  // Invalidate cache on refresh
  // Each panel loads independently. Previously the main panels waited (await Promise.all)
  // until KPIs + badge data finished — so ONE slow or hung fetch (e.g. over a slow link
  // to the sensor) left ALL panels on "Loading...", because their fetch never started.
  // Badges (hunt/AI) load in the background and refresh the scanners when they arrive —
  // their absence blocks nothing else.
  loadBadgeData().then(() => { loadScanners(); }).catch(() => {});
  await Promise.all([
    loadKPIs(), loadScanners(), loadAttacks(), loadEvents(), loadMitmStatus(), loadHoneypotStatus(),
  ]);
}

loadAttackTypes();  // Load attack type dropdown options (shares cache with loadAttacks)
loadKPIs();         // Fast KPI strip
refresh();
setInterval(refresh, 30000);

// Enter key support
document.getElementById('ipSearch').addEventListener('keydown', e => { if (e.key === 'Enter') searchIP(); });
document.getElementById('ruleSearch').addEventListener('keydown', e => { if (e.key === 'Enter') searchRule(); });
document.getElementById('protoSearch').addEventListener('keydown', e => { if (e.key === 'Enter') searchProtocol(); });
document.getElementById('attackSelect').addEventListener('change', e => { if (e.target.value) searchAttack(); });
// Esc to close overlay
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDetail(); });

// ── Sortable tables (event delegation — works for AJAX tables) ──
(function(){
  function doSort(th){
    var table=th.closest("table");if(!table)return;
    var tbody=table.tBodies[0]||table;var rows=Array.from(tbody.rows);if(rows.length<1)return;
    var idx=Array.from(th.parentNode.cells).indexOf(th);if(idx<0)return;
    var asc=th.dataset.sortDir!=="asc";th.dataset.sortDir=asc?"asc":"desc";
    Array.from(th.parentNode.cells).forEach(function(h){h.classList.remove("sorted-asc","sorted-desc");});
    th.classList.add(asc?"sorted-asc":"sorted-desc");
    rows.sort(function(a,b){
      var ac=a.cells[idx],bc=b.cells[idx];if(!ac||!bc)return 0;
      var av=ac.textContent.trim(),bv=bc.textContent.trim();
      var an=parseFloat(av.replace(/,/g,"")),bn=parseFloat(bv.replace(/,/g,""));
      if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;
      if(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(av)){var ap=av.split(".").map(Number),bp=bv.split(".").map(Number);for(var i=0;i<4;i++){var d=(ap[i]||0)-(bp[i]||0);if(d)return asc?d:-d;}return 0;}
      var sv={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,INFO:0};if(sv[av]!==undefined&&sv[bv]!==undefined)return asc?sv[av]-sv[bv]:sv[bv]-sv[av];
      return asc?av.localeCompare(bv):bv.localeCompare(av);
    });
    rows.forEach(function(r){tbody.appendChild(r);});
  }
  document.addEventListener("click",function(e){var th=e.target.closest("th");if(th&&th.closest("table"))doSort(th);});
})();
</script>
<style>th{cursor:pointer;user-select:none;position:relative;white-space:nowrap;transition:background .15s;}th:hover{background:rgba(34,211,238,0.08)!important;}th.sorted-asc::after{content:" \25B2";font-size:10px;color:#22d3ee;}th.sorted-desc::after{content:" \25BC";font-size:10px;color:#22d3ee;}tbody tr:hover,table tr:hover{background:rgba(34,211,238,0.04)!important;}</style>
</body>
</html>"""
