"""
webui/dashboard_mitm.py — MiTM Detection Dashboard
====================================================
Dashboard at /mitm showing ARP spoofing and DNS poisoning events.
Uses SHARED_CSS + nav_bar + drawer for consistency with all dashboards.
Compatible with Python 3.9+.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

from honeylens.webui.shared import SHARED_CSS, drawer_html, nav_bar_html, page_header_html


def register_routes(app: FastAPI) -> None:
    from fastapi.responses import HTMLResponse

    @app.get("/mitm", response_class=HTMLResponse, include_in_schema=False)
    async def mitm_dashboard():
        return HTMLResponse(content=MITM_DASHBOARD_HTML)


# Extra CSS for MiTM-specific elements
_MITM_CSS = """
/* MiTM severity badges */
.sev-CRITICAL{background:#dc262633;color:#ef4444;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600}
.sev-HIGH{background:#f59e0b33;color:#fbbf24;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600}
.sev-MEDIUM{background:#3b82f633;color:#60a5fa;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600}
.sev-LOW{background:#64748b33;color:#94a3b8;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600}
.type-badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:500;background:var(--bg3);color:var(--text)}
.btn-ack{border-color:var(--green);color:var(--green)}
.btn-ack:hover{background:#22c55e22}
.mitm-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:16px}
.mitm-grid .kpi-val.danger{color:var(--red)}
.mitm-grid .kpi-val.warning{color:var(--orange)}
.mitm-grid .kpi-val.ok{color:var(--green)}
@media(max-width:1000px){.mitm-grid{grid-template-columns:1fr 1fr}}
@media(max-width:600px){.mitm-grid{grid-template-columns:1fr}}
/* Expandable event detail */
.mitm-row{cursor:pointer}
.mitm-row:hover{background:var(--bg3)}
.mitm-caret{width:14px;color:var(--dim,#94a3b8)}
.mitm-detail{padding:12px 16px;background:var(--bg2);display:grid;grid-template-columns:1fr 1fr;gap:8px 24px}
.mitm-det-sec{font-size:11px;line-height:1.7}
.mitm-det-sec.wide{grid-column:1/-1}
.mitm-det-h{font-weight:600;color:var(--accent,#38bdf8);text-transform:uppercase;font-size:10px;letter-spacing:.04em;margin-bottom:3px}
.mitm-det-sec .dim{display:inline-block;min-width:92px}
.mitm-pre{background:var(--bg1);border:1px solid var(--border);border-radius:4px;padding:8px;overflow:auto;max-height:280px;white-space:pre-wrap;word-break:break-all;font-size:11px;margin:2px 0;font-family:ui-monospace,Menlo,Consolas,monospace}
@media(max-width:700px){.mitm-detail{grid-template-columns:1fr}}
"""


MITM_DASHBOARD_HTML = (
    '<!DOCTYPE html>\n<html lang="en">\n<head>\n'  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
    '<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
    '<meta name="referrer" content="strict-origin-when-cross-origin">\n'
    "<title>MiTM Detection — Hybrid Intelligence Sensor</title>\n"
    "<style>" + SHARED_CSS + _MITM_CSS + "</style>\n"
    "</head>\n<body>\n"
    '<a href="#main-content" class="skip-link">Skip to main content</a>\n'
    + nav_bar_html("mitm")
    + '<div class="page" id="main-content">\n'
    + page_header_html(
        "MiTM Detection",
        eyebrow="Detection",
        description="ARP-spoofing / man-in-the-middle anomaly detection from the on-sensor detector",
    )
    # KPI cards
    + r"""
<div class="mitm-grid">
  <div class="kpi">
    <div class="kpi-lbl">Total Events</div>
    <div class="kpi-val" id="totalEvents">—</div>
  </div>
  <div class="kpi">
    <div class="kpi-lbl">Last 24 Hours</div>
    <div class="kpi-val" id="last24h">—</div>
  </div>
  <div class="kpi">
    <div class="kpi-lbl">Unacked Critical/High</div>
    <div class="kpi-val" id="unacked">—</div>
  </div>
  <div class="kpi">
    <div class="kpi-lbl">Detector Status</div>
    <div class="kpi-val ok" id="status">—</div>
  </div>
</div>

<div class="two-col">
  <div class="panel">
    <div class="panel-hdr">By Attack Type</div>
    <div id="byType" style="padding:8px"><span class="dim">Loading...</span></div>
  </div>
  <div class="panel">
    <div class="panel-hdr">By Severity</div>
    <div id="bySeverity" style="padding:8px"><span class="dim">Loading...</span></div>
  </div>
</div>

<div class="panel">
  <div class="panel-hdr">
    <span>Recent MiTM Events</span>
    <select id="filterSeverity" onchange="loadEvents()"
      style="background:var(--bg3);border:1px solid var(--border);color:var(--text);
        padding:3px 8px;border-radius:4px;font-size:11px;font-family:inherit">
      <option value="">All Severities</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="HIGH">HIGH</option>
      <option value="MEDIUM">MEDIUM</option>
      <option value="LOW">LOW</option>
    </select>
    <label style="font-size:11px;color:var(--dim);margin-left:8px;cursor:pointer">
      <input type="checkbox" id="showBaseline" onchange="loadEvents()" style="vertical-align:middle"> show baselined
    </label>
    <span id="baselineCount" class="dim" style="font-size:11px;margin-left:8px"></span>
  </div>
  <div id="events"><span class="dim" style="padding:12px;display:block">Loading...</span></div>
</div>

<div class="panel" style="margin-top:14px">
  <div class="panel-hdr">Baseline rules <span class="dim" style="font-size:11px">(known-good — matching events are suppressed from alerts)</span></div>
  <div id="baselineRules"><span class="dim" style="padding:12px;display:block">Loading...</span></div>
</div>

<div class="panel" style="margin-top:14px">
  <div class="panel-hdr">ARP Cache</div>
  <div id="arpCache"><span class="dim" style="padding:12px;display:block">Loading...</span></div>
</div>
</div>
"""
    + drawer_html()
    + r"""
<script>
async function fetchJSON(url) {
  const r = await fetch(url);
  return r.json();
}

async function loadSummary() {
  try {
    const d = await fetchJSON('/mitm/summary');
    if (!d.enabled) {
      document.getElementById('status').textContent = 'DISABLED';
      document.getElementById('status').className = 'kpi-val warning';
      return;
    }
    document.getElementById('totalEvents').textContent = (d.total_events || 0).toLocaleString();
    document.getElementById('last24h').textContent = (d.last_24h || 0).toLocaleString();
    const unacked = d.unacked_critical_high || 0;
    document.getElementById('unacked').textContent = unacked;
    document.getElementById('unacked').className = 'kpi-val ' + (unacked > 0 ? 'danger' : 'ok');
    const bc = document.getElementById('baselineCount');
    if (bc) bc.textContent = (d.baseline_count ? (d.baseline_count.toLocaleString() + ' baselined') : '');
    document.getElementById('status').textContent = 'ACTIVE';
    renderStats(d);
  } catch (e) {
    document.getElementById('status').textContent = 'ERROR';
    document.getElementById('status').className = 'kpi-val danger';
  }
}

function renderStats(d) {
  try {
    let html = '<table><thead><tr><th>Type</th><th>Total</th><th>24h</th></tr></thead><tbody>';
    for (const t of (d.by_attack_type || [])) {
      html += '<tr><td><span class="type-badge">' + t.type + '</span></td><td>' + t.total + '</td><td>' + t.last_24h + '</td></tr>';
    }
    html += '</table>';
    document.getElementById('byType').innerHTML = html || '<span class="dim">No data</span>';

    html = '<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>';
    for (const s of (d.by_severity || [])) {
      html += '<tr><td><span class="sev-' + s.severity + '">' + s.severity + '</span></td><td>' + s.count + '</td></tr>';
    }
    html += '</table>';
    document.getElementById('bySeverity').innerHTML = html || '<span class="dim">No data</span>';
  } catch (e) {
    document.getElementById('byType').innerHTML = '<span class="dim">Error</span>';
    document.getElementById('bySeverity').innerHTML = '<span class="dim">Error</span>';
  }
}

// HTML-escape \u2014 metadata/payload are attacker-controlled, never inject raw.
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

function kv(label,val){return (val==null||val==='')?'':'<div><span class="dim">'+label+'</span> '+esc(val)+'</div>';}

// Build the expandable per-event detail: network 5-tuple, ARP/DNS specifics,
// the captured payload, and the full metadata JSON.
function detailHtml(e){
  const md = e.metadata || {};
  const parts = [];
  const net = kv('src', (e.src_ip||'?')+(e.src_port?':'+e.src_port:''))
            + kv('dst', (e.dst_ip||'?')+(e.dst_port?':'+e.dst_port:''))
            + kv('src MAC', e.src_mac) + kv('dst MAC', e.dst_mac)
            + kv('interface', e.interface) + kv('vlan', e.vlan_id);
  if (net) parts.push('<div class="mitm-det-sec"><div class="mitm-det-h">Network</div>'+net+'</div>');
  if (e.original_mac || e.spoofed_mac)
    parts.push('<div class="mitm-det-sec"><div class="mitm-det-h">ARP spoof</div>'+kv('legit MAC',e.original_mac)+kv('spoofed MAC',e.spoofed_mac)+'</div>');
  if (e.dns_query)
    parts.push('<div class="mitm-det-sec"><div class="mitm-det-h">DNS poison</div>'+kv('query',e.dns_query)+kv('answer',e.dns_answer)+kv('expected',e.expected_answer)+'</div>');
  const fp = e.false_positive ? '<span style="color:var(--orange)">false positive</span>'
           : (e.baseline ? '<span style="color:var(--cyan)">baseline (suppressed)</span>'
           : (e.acknowledged ? 'acknowledged' : '<span style="color:var(--red)">unacknowledged</span>'));
  let st = kv('event id', e.event_id) + kv('confidence', e.confidence+'%') + '<div><span class="dim">state</span> '+fp+'</div>';
  if (!e.false_positive && !e.baseline) {
    st += '<div style="margin-top:6px;display:flex;gap:14px">'
        + '<button class="act-link" style="color:var(--cyan)" onclick="baselineEvent(event,\''+esc(e.event_id)+'\')">Add to baseline</button>'
        + '<button class="act-link" style="color:var(--orange)" onclick="fpEvent(event,\''+esc(e.event_id)+'\')">Mark false positive</button>'
        + '</div>';
  }
  parts.push('<div class="mitm-det-sec"><div class="mitm-det-h">Status</div>'+st+'</div>');
  const payload = md.raw || md.payload || md.line;
  if (payload) parts.push('<div class="mitm-det-sec wide"><div class="mitm-det-h">Payload</div><pre class="mitm-pre">'+esc(payload)+'</pre></div>');
  let mdStr=''; try{mdStr=JSON.stringify(md,null,2);}catch(x){mdStr=String(md);}
  if (mdStr && mdStr!=='{}') parts.push('<div class="mitm-det-sec wide"><div class="mitm-det-h">Attack details (metadata)</div><pre class="mitm-pre">'+esc(mdStr)+'</pre></div>');
  if (e.notes) parts.push('<div class="mitm-det-sec wide"><div class="mitm-det-h">Notes</div>'+esc(e.notes)+'</div>');
  return '<div class="mitm-detail">'+parts.join('')+'</div>';
}

function toggleDetail(i){
  const row=document.getElementById('mitm-det-'+i), caret=document.getElementById('mitm-caret-'+i);
  if(!row) return;
  const open = row.style.display==='none';
  row.style.display = open?'':'none';
  if(caret) caret.textContent = open?'\u25be':'\u25b8';
}

async function loadEvents() {
  try {
    const sev = document.getElementById('filterSeverity').value;
    const sb = document.getElementById('showBaseline');
    let url = '/mitm/events?limit=100';
    if (sev) url += '&severity=' + sev;
    if (sb && sb.checked) url += '&view=baseline';
    const data = await fetchJSON(url);

    let html = '<table><thead><tr><th></th><th>Time</th><th>Type</th><th>Severity</th><th>Source IP</th><th>MAC</th><th>Conf.</th><th>Actions</th></tr></thead><tbody>';
    data.forEach(function(e, i) {
      const time = e.timestamp ? new Date(e.timestamp).toLocaleString() : '\u2014';
      html += '<tr class="mitm-row" onclick="toggleDetail(' + i + ')" title="Click to inspect payload &amp; details">';
      html += '<td class="mitm-caret" id="mitm-caret-' + i + '">\u25b8</td>';
      html += '<td class="ts">' + time + '</td>';
      html += '<td><span class="type-badge">' + esc(e.attack_type) + '</span></td>';
      html += '<td><span class="sev-' + esc(e.severity) + '">' + esc(e.severity) + '</span></td>';
      html += '<td class="ip">' + esc(e.src_ip || '\u2014') + '</td>';
      html += '<td class="mono dim">' + esc(e.src_mac || '\u2014') + '</td>';
      html += '<td>' + esc(e.confidence) + '%</td>';
      html += '<td>' + (!e.acknowledged ? '<button class="act-link" style="color:var(--green)" onclick="ackEvent(event,\'' + esc(e.event_id) + '\')">Ack</button>' : '\u2713') + '</td>';
      html += '</tr>';
      html += '<tr id="mitm-det-' + i + '" style="display:none"><td colspan="8" style="padding:0">' + detailHtml(e) + '</td></tr>';
    });
    html += '</table>';
    document.getElementById('events').innerHTML = data.length ? html : '<span class="dim" style="padding:12px;display:block">No events</span>';
  } catch (e) {
    document.getElementById('events').innerHTML = '<span class="dim" style="padding:12px;display:block">Error loading events</span>';
  }
}

async function loadArpCache() {
  try {
    const data = await fetchJSON('/mitm/arp-cache?limit=500');
    const entries = Array.isArray(data) ? data : (data.entries || []);
    if (!entries.length) {
      document.getElementById('arpCache').innerHTML = '<span class="dim" style="padding:12px;display:block">No ARP entries found</span>';
      return;
    }
    const fromProc = entries.length > 0 && entries[0].source === 'proc';
    let html = '';
    if (fromProc) {
      html += '<div style="font-size:11px;color:var(--orange);padding:6px 10px;background:#f9731610;border-bottom:1px solid #f9731630">';
      html += '&#9432; Live from <code style="background:var(--bg3);padding:1px 5px;border-radius:3px">/proc/net/arp</code> \u2014 MiTM detector not yet running or no events ingested</div>';
    }
    html += '<table><thead><tr>';
    html += '<th>IP Address</th><th>MAC Address</th><th>Interface</th>';
    if (fromProc) {
      html += '<th>HW Type</th><th>Flags</th><th>Static</th>';
    } else {
      html += '<th>First Seen</th><th>Last Seen</th><th>Seen</th><th>Gateway</th><th>Trust</th>';
    }
    html += '</tr></thead><tbody>';
    for (const e of entries) {
      const isGw = e.is_gateway;
      const trust = e.trust_score || 50;
      const trustColor = trust >= 80 ? 'var(--green)' : trust >= 50 ? 'var(--yellow)' : 'var(--red)';
      html += '<tr' + (isGw ? ' style="background:#22c55e08"' : '') + '>';
      html += '<td class="ip">' + (e.ip || '\u2014') + '</td>';
      html += '<td class="mono dim">' + (e.mac || '\u2014') + '</td>';
      html += '<td class="dim">' + (e.interface || '\u2014') + '</td>';
      if (fromProc) {
        html += '<td class="dim" style="font-size:11px">' + (e.hw_type || '\u2014') + '</td>';
        html += '<td class="mono" style="font-size:11px">' + (e.flags || '\u2014') + '</td>';
        html += '<td>' + (e.is_static ? '<span style="color:var(--green)">\u2713</span>' : '') + '</td>';
      } else {
        const firstSeen = e.first_seen ? new Date(e.first_seen).toLocaleString() : '\u2014';
        const lastSeen  = e.last_seen  ? new Date(e.last_seen).toLocaleString()  : '\u2014';
        html += '<td class="ts">' + firstSeen + '</td>';
        html += '<td class="ts">' + lastSeen + '</td>';
        html += '<td style="text-align:right">' + (e.seen_count || 1) + '</td>';
        html += '<td style="text-align:center">' + (isGw ? '<span style="color:var(--green);font-weight:700">GW</span>' : '') + '</td>';
        html += '<td><span style="color:' + trustColor + ';font-weight:700">' + trust + '</span><span class="dim">/100</span></td>';
      }
      html += '</tr>';
    }
    html += '</tbody></table>';
    document.getElementById('arpCache').innerHTML = html;
  } catch (e) {
    document.getElementById('arpCache').innerHTML = '<span class="dim" style="padding:12px;display:block">Error loading ARP cache: ' + e.message + '</span>';
  }
}

async function ackEvent(ev, eventId) {
  if (ev) ev.stopPropagation();
  try {
    const r = await fetch('/mitm/acknowledge/' + eventId, { method: 'POST' });
    if (!r.ok) { alert('Not permitted (admin only) or failed'); return; }
    loadEvents();
    loadSummary();
  } catch (e) {
    alert('Error acknowledging event');
  }
}

async function fpEvent(ev, eventId) {
  if (ev) ev.stopPropagation();
  if (!confirm('Mark this event as a false positive?')) return;
  try {
    const r = await fetch('/mitm/false_positive/' + eventId, { method: 'POST' });
    if (!r.ok) { alert('Not permitted (admin only) or failed'); return; }
    loadEvents();
    loadSummary();
  } catch (e) {
    alert('Error marking false positive');
  }
}

async function baselineEvent(ev, eventId) {
  if (ev) ev.stopPropagation();
  if (!confirm('Add this pattern (attack type + source IP) to the baseline?\n\nMatching current and future events will be treated as known-good: hidden from the main dashboard and excluded from alerts.')) return;
  try {
    const r = await fetch('/mitm/baseline/' + eventId, { method: 'POST' });
    if (!r.ok) { alert('Not permitted (admin only) or failed'); return; }
    loadEvents(); loadSummary(); loadBaselineRules();
  } catch (e) {
    alert('Error adding to baseline');
  }
}

async function loadBaselineRules() {
  try {
    const d = await fetchJSON('/mitm/baseline');
    const rules = (d && d.rules) || [];
    if (!rules.length) {
      document.getElementById('baselineRules').innerHTML = '<span class="dim" style="padding:12px;display:block">No baseline rules — use "Add to baseline" on an event to suppress a known-good pattern.</span>';
      return;
    }
    let html = '<table><thead><tr><th>Attack Type</th><th>Source IP</th><th>MAC</th><th>Added by</th><th>When</th><th></th></tr></thead><tbody>';
    for (const r of rules) {
      const when = r.created_at ? new Date(r.created_at).toLocaleString() : '—';
      html += '<tr>'
        + '<td><span class="type-badge">' + esc(r.attack_type || 'any') + '</span></td>'
        + '<td class="ip">' + esc(r.src_ip || 'any') + '</td>'
        + '<td class="mono dim">' + esc(r.src_mac || 'any') + '</td>'
        + '<td class="dim">' + esc(r.created_by || '—') + '</td>'
        + '<td class="ts">' + when + '</td>'
        + '<td><button class="act-link" style="color:var(--red)" onclick="removeBaselineRule(' + Number(r.id) + ')">Remove</button></td>'
        + '</tr>';
    }
    html += '</table>';
    document.getElementById('baselineRules').innerHTML = html;
  } catch (e) {
    document.getElementById('baselineRules').innerHTML = '<span class="dim" style="padding:12px;display:block">Error loading baseline rules</span>';
  }
}

async function removeBaselineRule(id) {
  if (!confirm('Remove this baseline rule? Its events return to normal detection.')) return;
  try {
    const r = await fetch('/mitm/baseline/' + id, { method: 'DELETE' });
    if (!r.ok) { alert('Not permitted (admin only) or failed'); return; }
    loadBaselineRules(); loadEvents(); loadSummary();
  } catch (e) {
    alert('Error removing baseline rule');
  }
}

loadSummary();
loadEvents();
loadArpCache();
loadBaselineRules();
setInterval(function() { loadSummary(); loadEvents(); }, 30000);
</script>
</body>
</html>"""
)
