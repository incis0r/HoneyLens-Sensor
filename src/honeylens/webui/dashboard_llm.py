"""
webui/dashboard_llm.py — LLM Honeypot Dashboard (Idea 37 Phase G)
==================================================================
Visualises OWASP LLM Top 10 attacks captured by honeypot_llm.py.
Shows attack distribution, session replay, agent detection, honeytoken tracking.
Compatible with Python 3.9+.
"""

from __future__ import annotations

import html
import json as _json


def llm_dashboard_html(data: dict) -> str:
    """Render the full LLM Honeypot dashboard."""
    from honeylens.webui.dashboard_cve import _donut_chart
    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, page_header_html, sortable_table_js

    e = html.escape

    stats = data.get("stats", {})
    events = data.get("events", [])
    sessions = data.get("sessions", [])
    by_category = data.get("by_category", [])
    by_actor = data.get("by_actor", [])
    honeytokens = data.get("honeytokens", [])

    total = stats.get("total", 0)
    unique_ips = stats.get("unique_ips", 0)
    unique_sessions = stats.get("unique_sessions", 0)
    agents_detected = stats.get("agents_detected", 0)
    creds_leaked = stats.get("creds_leaked", 0)
    critical = stats.get("critical", 0)
    high = stats.get("high", 0)

    _cat_colors = {
        "LLM01": "#ef4444",
        "LLM02": "#f97316",
        "LLM03": "#eab308",
        "LLM04": "#84cc16",
        "LLM05": "#22c55e",
        "LLM06": "#06b6d4",
        "LLM07": "#3b82f6",
        "LLM08": "#8b5cf6",
        "LLM09": "#a78bfa",
        "LLM10": "#ec4899",
        "BENIGN": "#334155",
    }
    _cat_names = {
        "LLM01": "Prompt Injection",
        "LLM02": "Sensitive Info Disclosure",
        "LLM03": "Supply Chain Probing",
        "LLM04": "Data Poisoning",
        "LLM05": "Output Handling (XSS/SQLi)",
        "LLM06": "Excessive Agency",
        "LLM07": "System Prompt Leakage",
        "LLM08": "Vector/Embedding",
        "LLM09": "Misinformation",
        "LLM10": "Unbounded Consumption",
        "BENIGN": "Benign",
    }
    _sev = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
        "INFO": "#64748b",
    }
    _actor = {
        "HUMAN": "#22c55e",
        "LLM_AGENT": "#ef4444",
        "BOT_OR_FAST_HUMAN": "#f97316",
        "UNKNOWN": "#64748b",
    }

    # Donut: Attack Categories
    cat_data = [
        (
            f"{c['category']} ({_cat_names.get(c['category'], '')})",
            c["count"],
            _cat_colors.get(c["category"], "#64748b"),
        )
        for c in by_category
        if c["count"] > 0
    ]
    cat_donut = _donut_chart(cat_data, total, "Attacks") if cat_data else ""

    # Donut: Actor Types
    actor_data = [
        (a["actor_type"] or "UNKNOWN", a["count"], _actor.get(a["actor_type"], "#64748b"))
        for a in by_actor
        if a.get("count", 0) > 0
    ]
    actor_donut = _donut_chart(actor_data, total, "Actors") if actor_data else ""

    # OWASP category breakdown bars
    cat_bars = ""
    max_cat = max((c["count"] for c in by_category), default=1) or 1
    for c in sorted(by_category, key=lambda x: x["count"], reverse=True):
        cat = c["category"]
        cnt = c["count"]
        if cnt == 0:
            continue
        cc = _cat_colors.get(cat, "#64748b")
        name = _cat_names.get(cat, cat)
        pct = cnt / max_cat * 100
        cat_bars += (
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">'
            f'<div style="width:60px;font-size:10px;font-weight:700;color:{cc};font-family:monospace">{e(cat)}</div>'
            f'<div style="width:160px;font-size:10px;color:#94a3b8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{e(name)}</div>'
            f'<div style="flex:1;height:18px;background:#1e293b;border-radius:3px;overflow:hidden;position:relative">'
            f'<div style="width:{pct}%;height:100%;background:{cc}40;border-left:3px solid {cc};border-radius:3px"></div>'
            f'<span style="position:absolute;right:6px;top:1px;font-size:10px;color:#e2e8f0;font-weight:600">{cnt}</span>'
            f"</div>"
            f"</div>"
        )

    # Events table
    event_rows = ""
    for ev in events[:50]:
        cat = ev.get("attack_category", "BENIGN")
        cc = _cat_colors.get(cat, "#64748b")
        sc = _sev.get(ev.get("severity", "INFO"), "#64748b")
        ac = _actor.get(ev.get("actor_type"), "#64748b")
        ts = str(ev.get("timestamp", ""))[:19].replace("T", " ")
        msg = e(str(ev.get("user_message", ""))[:100])
        rules = ", ".join(ev.get("attack_rules", [])[:3]) if ev.get("attack_rules") else ""
        resp_strat = ev.get("response_strategy", "")
        leak_badge = (
            ' <span style="background:#7f1d1d;color:#fca5a5;padding:1px 5px;border-radius:3px;font-size:8px;font-weight:700">LEAKED</span>'
            if resp_strat == "deliberate_leak"
            else ""
        )

        event_rows += (
            f"<tr>"
            f'<td style="color:#64748b;font-size:10px;white-space:nowrap">{e(ts)}</td>'
            f'<td><span style="background:{cc}20;color:{cc};padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;border:1px solid {cc}40">{e(cat)}</span></td>'
            f'<td><span style="color:{sc};font-weight:700;font-size:10px">{e(ev.get("severity", ""))}</span></td>'
            f'<td style="color:{ac};font-size:10px;font-weight:600">{e(ev.get("actor_type", "") or "?")}</td>'
            f'<td style="color:#f472b6;font-family:monospace;font-size:10px">{e(str(ev.get("src_ip", ""))[:20])}</td>'
            f'<td style="font-size:11px;color:#cbd5e1;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{msg}">{msg}{leak_badge}</td>'
            f'<td style="color:#64748b;font-size:9px;font-family:monospace">{e(rules)}</td>'
            f'<td style="color:#64748b;font-size:10px;text-align:center">{ev.get("confidence", "")}%</td>'
            f"</tr>"
        )
    if not event_rows:
        event_rows = '<tr><td colspan="8" style="text-align:center;color:#64748b;padding:30px">No LLM honeypot events yet. Deploy honeypot on port 3080.</td></tr>'

    # Sessions table
    session_rows = ""
    for s in sessions[:20]:
        cat_counts = s.get("top_categories", "")
        leaked = (
            '<span style="color:#ef4444;font-weight:700">&#x1F36F; Yes</span>'
            if s.get("has_leak")
            else ""
        )
        agent = s.get("actor_type", "")
        ac = _actor.get(agent, "#64748b")
        ip_raw = e(str(s.get("src_ip", "")))
        session_rows += (
            f"<tr>"
            f'<td style="color:#f472b6;font-family:monospace;font-size:11px">{ip_raw}</td>'
            f'<td style="text-align:center;font-weight:700">{s.get("turns", 0)}</td>'
            f'<td style="text-align:center;font-weight:700;color:{_sev.get(s.get("max_severity", ""), "#64748b")}">{e(s.get("max_severity", ""))}</td>'
            f'<td style="color:{ac};font-size:10px;font-weight:600">{e(agent)}</td>'
            f'<td style="font-size:10px;color:#94a3b8">{e(cat_counts)}</td>'
            f'<td style="text-align:center">{leaked}</td>'
            f'<td style="color:#64748b;font-size:10px">{e(str(s.get("first_seen", ""))[:16])}</td>'
            f'<td style="color:#64748b;font-size:10px">{e(str(s.get("last_seen", ""))[:16])}</td>'
            f'<td><a href="/llm/session/{ip_raw}?format=html" style="color:var(--accent);font-size:10px;text-decoration:none;font-weight:700">&#x25B6; Replay</a></td>'
            f"</tr>"
        )
    if not session_rows:
        session_rows = '<tr><td colspan="9" style="text-align:center;color:#64748b;padding:20px">No sessions</td></tr>'

    # ── Honeytoken tracking rows ────────────────────────────────────────
    ht_rows = ""
    for ht in honeytokens:
        ts = str(ht.get("timestamp", ""))[:19].replace("T", " ")
        ip_raw = e(str(ht.get("src_ip", "")))
        cat = ht.get("attack_category", "")
        cc = _cat_colors.get(cat, "#64748b")
        msg = e(str(ht.get("user_message", ""))[:80])
        resp = e(str(ht.get("response_preview", ""))[:120])
        e(str(ht.get("session_id", ""))[:16])
        # Detect which honeytoken was leaked
        leaked_type = ""
        rp = str(ht.get("response_preview", "")).lower()
        if "postgres://" in rp or "hr_readonly" in rp:
            leaked_type = '<span style="color:#ef4444;font-weight:700">DB Credential</span>'
        elif "sk-nexova" in rp:
            leaked_type = '<span style="color:#f97316;font-weight:700">API Key</span>'
        elif "admin" in rp and "internal" in rp:
            leaked_type = '<span style="color:#eab308;font-weight:700">Admin URL</span>'
        elif "jwt_secret" in rp.lower() or "secret" in rp.lower():
            leaked_type = '<span style="color:#a78bfa;font-weight:700">JWT Secret</span>'
        else:
            leaked_type = '<span style="color:#64748b">Unknown</span>'
        ht_rows += (
            f"<tr>"
            f'<td style="color:#64748b;font-size:10px;white-space:nowrap">{ts}</td>'
            f'<td class="ip" style="color:#f472b6;font-family:monospace;font-size:11px;cursor:pointer" '
            f"onclick=\"window.location.href='/llm/session/{ip_raw}?format=html'\">{ip_raw}</td>"
            f"<td>{leaked_type}</td>"
            f'<td><span style="background:{cc}20;color:{cc};padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;border:1px solid {cc}40">{e(cat)}</span></td>'
            f'<td style="font-size:10px;color:#94a3b8;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{msg}">{msg}</td>'
            f'<td style="font-size:10px;color:#fca5a5;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace" title="{resp}">{resp}</td>'
            f'<td><a href="/llm/session/{ip_raw}?format=html" style="color:var(--accent);font-size:10px;text-decoration:none">&#x25B6;</a></td>'
            f"</tr>"
        )
    if not ht_rows:
        ht_rows = '<tr><td colspan="7" style="text-align:center;color:#64748b;padding:20px">No honeytokens leaked yet — attackers haven\'t triggered credential disclosure</td></tr>'

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LLM Honeypot — HoneyLens</title>
<style>{SHARED_CSS}
.llm-tab{{padding:10px 18px;background:none;border:none;color:var(--text3);font-size:12px;
  font-weight:600;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;
  transition:all .15s;font-family:inherit}}
.llm-tab:hover{{color:var(--text);background:var(--bg2)}}
.llm-tab.active{{color:var(--accent);border-bottom-color:var(--accent)}}
.llm-sec{{display:none}}.llm-sec.active{{display:block}}
</style>
</head><body>
<a href="#main-content" class="skip-link">Skip to main content</a>
{nav_bar_html("llm")}
{
        page_header_html(
            "LLM Honeypot",
            eyebrow="Deception",
            description="OWASP LLM Top 10 attack collector (port 3080)",
            actions=['<a href="/llm/dashboard" class="btn">JSON</a>'],
        )
    }

<div id="main-content" style="display:flex;gap:0;padding:0 22px;background:var(--bg1);border-bottom:2px solid var(--border)">
  <button class="llm-tab active" onclick="llmTab('overview')" id="lt-overview">Overview</button>
  <button class="llm-tab" onclick="llmTab('events')" id="lt-events">Event Log <span style="background:var(--accent);color:#000;padding:0 5px;border-radius:8px;font-size:9px;margin-left:4px">{
        total
    }</span></button>
  <button class="llm-tab" onclick="llmTab('sessions')" id="lt-sessions">Sessions <span style="background:#f97316;color:#fff;padding:0 5px;border-radius:8px;font-size:9px;margin-left:4px">{
        unique_sessions
    }</span></button>
  <button class="llm-tab" onclick="llmTab('honeytokens')" id="lt-honeytokens">&#x1F36F; Honeytokens <span style="background:#a78bfa;color:#fff;padding:0 5px;border-radius:8px;font-size:9px;margin-left:4px">{
        creds_leaked
    }</span></button>
  <button class="llm-tab" onclick="llmTab('live')" id="lt-live">&#x1F534; Live Feed</button>
</div>

<div class="page">

<!-- ═══ OVERVIEW ═══ -->
<div class="llm-sec active" id="sec-overview">

  <div class="kpi-grid">
    <div class="kpi"><div class="kpi-lbl">Total Events</div>
      <div class="kpi-val" style="color:var(--accent)">{total}</div></div>
    <div class="kpi"><div class="kpi-lbl">Unique Attackers</div>
      <div class="kpi-val" style="color:#f472b6">{unique_ips}</div></div>
    <div class="kpi"><div class="kpi-lbl">Sessions</div>
      <div class="kpi-val" style="color:#f97316">{unique_sessions}</div></div>
    <div class="kpi"><div class="kpi-lbl">Critical</div>
      <div class="kpi-val" style="color:#ef4444">{critical}</div></div>
    <div class="kpi"><div class="kpi-lbl">High</div>
      <div class="kpi-val" style="color:#f97316">{high}</div></div>
    <div class="kpi"><div class="kpi-lbl">LLM Agents</div>
      <div class="kpi-val" style="color:#ef4444">{agents_detected}</div></div>
    <div class="kpi"><div class="kpi-lbl">Creds Leaked</div>
      <div class="kpi-val" style="color:#a78bfa">{creds_leaked}</div></div>
    <div class="kpi"><div class="kpi-lbl">Detection Rules</div>
      <div class="kpi-val">50</div></div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
    <div class="panel">
      <div class="panel-hdr">OWASP LLM Top 10 Distribution</div>
      <div style="display:flex;justify-content:center;padding:20px">{cat_donut}</div>
    </div>
    <div class="panel">
      <div class="panel-hdr">Actor Type Detection</div>
      <div style="display:flex;justify-content:center;padding:20px">{actor_donut}</div>
    </div>
  </div>

  <div class="panel" style="margin-bottom:16px">
    <div class="panel-hdr">Attack Category Breakdown <span class="panel-cnt">OWASP LLM01&ndash;LLM10</span></div>
    <div style="padding:14px">{
        cat_bars
        if cat_bars
        else '<div style="color:#64748b;text-align:center;padding:20px">No attacks detected</div>'
    }</div>
  </div>

</div>

<!-- ═══ EVENTS ═══ -->
<div class="llm-sec" id="sec-events">
  <div class="panel">
    <div class="panel-hdr">LLM Honeypot Event Log <span class="panel-cnt">{
        total
    } events</span></div>
    <div style="overflow-x:auto;max-height:70vh">
    <table>
      <thead><tr>
        <th>Time</th><th>Category</th><th>Severity</th><th>Actor</th>
        <th>Source IP</th><th>Message</th><th>Rules</th><th>Conf</th>
      </tr></thead>
      <tbody>{event_rows}</tbody>
    </table>
    </div>
  </div>
</div>

<!-- ═══ SESSIONS ═══ -->
<div class="llm-sec" id="sec-sessions">
  <div class="panel">
    <div class="panel-hdr">Attacker Sessions <span class="panel-cnt">{
        unique_sessions
    } sessions from {unique_ips} IPs</span></div>
    <div style="overflow-x:auto;max-height:70vh">
    <table>
      <thead><tr>
        <th>Source IP</th><th>Turns</th><th>Max Severity</th><th>Actor</th>
        <th>Categories</th><th>Cred Leak</th><th>First Seen</th><th>Last Seen</th><th>Replay</th>
      </tr></thead>
      <tbody>{session_rows}</tbody>
    </table>
    </div>
  </div>
</div>

<!-- ═══ HONEYTOKENS ═══ -->
<div class="llm-sec" id="sec-honeytokens">
  <div class="panel" style="border-color:#a78bfa44">
    <div class="panel-hdr" style="color:#a78bfa">&#x1F36F; Honeytoken Leak Tracking
      <span class="panel-cnt">{creds_leaked} deliberate leaks to attackers</span></div>
    <p style="color:#94a3b8;font-size:11px;padding:0 14px 8px;margin:0">
      The LLM honeypot deliberately leaks fake credentials (DB URL, API key, admin URL, JWT secret)
      to attackers who use prompt injection or social engineering. These honeytokens can be monitored
      for reuse across other services.</p>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:0 14px 14px">
      <div style="background:#ef444410;border:1px solid #ef444430;border-radius:6px;padding:10px;font-size:10px">
        <div style="color:#ef4444;font-weight:700;margin-bottom:4px">DB Credential</div>
        <code style="color:#fca5a5;word-break:break-all;font-size:9px">postgres://hr_readonly:N3x0va2024!@hr-db.internal.nexova.tech</code>
      </div>
      <div style="background:#f9731610;border:1px solid #f9731630;border-radius:6px;padding:10px;font-size:10px">
        <div style="color:#f97316;font-weight:700;margin-bottom:4px">API Key</div>
        <code style="color:#fdba74;word-break:break-all;font-size:9px">sk-nexova-doc-2024-a8f3e2b1c9d0e7f6</code>
      </div>
      <div style="background:#eab30810;border:1px solid #eab30830;border-radius:6px;padding:10px;font-size:10px">
        <div style="color:#eab308;font-weight:700;margin-bottom:4px">Admin URL</div>
        <code style="color:#fde68a;word-break:break-all;font-size:9px">https://internal.nexova.tech/admin</code>
      </div>
      <div style="background:#a78bfa10;border:1px solid #a78bfa30;border-radius:6px;padding:10px;font-size:10px">
        <div style="color:#a78bfa;font-weight:700;margin-bottom:4px">JWT Secret</div>
        <code style="color:#c4b5fd;word-break:break-all;font-size:9px">NEXOVA_INTERNAL_JWT_SECRET=xK9mW2pL7qR4vT8n</code>
      </div>
    </div>
    <div style="overflow-x:auto;max-height:50vh">
    <table>
      <thead><tr>
        <th>Time</th><th>Attacker IP</th><th>Token Type</th><th>Category</th>
        <th>Attacker Prompt</th><th>Leaked Response</th><th>Replay</th>
      </tr></thead>
      <tbody>{ht_rows}</tbody>
    </table>
    </div>
  </div>
</div>

<!-- ═══ LIVE FEED ═══ -->
<div class="llm-sec" id="sec-live">
  <div class="panel">
    <div class="panel-hdr">
      <span id="live-dot" style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#ef4444;margin-right:6px;animation:pulse 1.5s infinite"></span>
      Live Feed — LLM Honeypot
      <span class="panel-cnt" id="live-count">waiting for events...</span>
      <div style="margin-left:auto;display:flex;gap:8px">
        <button onclick="toggleLive()" id="live-btn" style="padding:4px 12px;border-radius:4px;border:1px solid #22c55e;background:#22c55e20;color:#22c55e;cursor:pointer;font-size:11px;font-weight:700">&#x25B6; Start</button>
        <button onclick="clearLive()" style="padding:4px 12px;border-radius:4px;border:1px solid var(--border);background:var(--bg3);color:var(--text2);cursor:pointer;font-size:11px">Clear</button>
      </div>
    </div>
    <div id="live-feed" style="max-height:70vh;overflow-y:auto;padding:10px 14px;font-family:monospace;font-size:11px">
      <div style="color:#64748b;text-align:center;padding:40px">Click <strong>Start</strong> to begin polling for live events (every 3 seconds)</div>
    </div>
  </div>
</div>

</div>

<script>
function llmTab(name) {{
  document.querySelectorAll('.llm-sec').forEach(function(s){{ s.classList.remove('active'); }});
  document.querySelectorAll('.llm-tab').forEach(function(t){{ t.classList.remove('active'); }});
  var sec = document.getElementById('sec-' + name);
  var tab = document.getElementById('lt-' + name);
  if (sec) sec.classList.add('active');
  if (tab) tab.classList.add('active');
  history.replaceState(null, '', '#' + name);
}}
(function(){{
  var h = location.hash.replace('#','');
  if (h && document.getElementById('sec-' + h)) llmTab(h);
}})();

// ── Live Feed ──────────────────────────────────────────────────────
var liveInterval = null;
var lastId = 0;
var liveTotal = 0;
var catColors = {_json.dumps(_cat_colors)};
var sevColors = {_json.dumps(_sev)};

function toggleLive() {{
  var btn = document.getElementById('live-btn');
  if (liveInterval) {{
    clearInterval(liveInterval);
    liveInterval = null;
    btn.innerHTML = '&#x25B6; Start';
    btn.style.borderColor = '#22c55e';
    btn.style.color = '#22c55e';
    document.getElementById('live-dot').style.background = '#64748b';
  }} else {{
    liveInterval = setInterval(pollLive, 3000);
    btn.innerHTML = '&#x23F8; Pause';
    btn.style.borderColor = '#f97316';
    btn.style.color = '#f97316';
    document.getElementById('live-dot').style.background = '#ef4444';
    pollLive();
  }}
}}
function clearLive() {{
  document.getElementById('live-feed').innerHTML = '<div style="color:#64748b;text-align:center;padding:20px">Cleared</div>';
  liveTotal = 0;
  document.getElementById('live-count').textContent = '0 events';
}}
function pollLive() {{
  fetch('/llm/live?since_id=' + lastId, {{credentials:'same-origin'}})
    .then(function(r) {{ return r.json(); }})
    .then(function(d) {{
      if (!d.events || !d.events.length) return;
      lastId = d.max_id;
      liveTotal += d.events.length;
      document.getElementById('live-count').textContent = liveTotal + ' events';
      var feed = document.getElementById('live-feed');
      // Remove placeholder
      if (feed.querySelector('div[style*="text-align:center"]')) feed.innerHTML = '';
      d.events.reverse().forEach(function(ev) {{
        var cc = catColors[ev.category] || '#64748b';
        var sc = sevColors[ev.severity] || '#64748b';
        var leaked = ev.response_strategy === 'deliberate_leak' ? ' <span style="background:#7f1d1d;color:#fca5a5;padding:0 4px;border-radius:2px;font-size:8px">LEAKED</span>' : '';
        var row = document.createElement('div');
        row.style.cssText = 'padding:6px 0;border-bottom:1px solid #ffffff06;animation:fadeIn .3s';
        var ipLink = '/llm/session/' + encodeURIComponent(ev.src_ip||'') + '?format=html';
        row.innerHTML =
          '<span style="color:#64748b">' + (ev.timestamp||'').substring(11,19) + '</span> '
          + '<span style="background:'+cc+'20;color:'+cc+';padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;border:1px solid '+cc+'40">' + (ev.category||'?') + '</span> '
          + '<span style="color:'+sc+';font-weight:700;font-size:10px">' + (ev.severity||'') + '</span> '
          + '<a href="' + ipLink + '" style="color:#f472b6;text-decoration:none">' + (ev.src_ip||'?') + '</a> '
          + '<span style="color:#cbd5e1">' + ((ev.user_message||'').substring(0,80)) + '</span>'
          + leaked;
        feed.insertBefore(row, feed.firstChild);
      }});
      // Trim to 200 entries
      while (feed.children.length > 200) feed.removeChild(feed.lastChild);
    }})
    .catch(function() {{}});
}}
</script>
{sortable_table_js()}
</body></html>"""


def llm_session_replay_html(data: dict) -> str:
    """Render a full conversation replay as chat bubbles."""
    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, page_header_html

    e = html.escape

    messages = data.get("messages", [])
    session_key = data.get("session_key", "")
    total = data.get("total_turns", 0)

    _cat_colors = {
        "LLM01": "#ef4444",
        "LLM02": "#f97316",
        "LLM03": "#eab308",
        "LLM04": "#84cc16",
        "LLM05": "#22c55e",
        "LLM06": "#06b6d4",
        "LLM07": "#3b82f6",
        "LLM08": "#8b5cf6",
        "LLM09": "#a78bfa",
        "LLM10": "#ec4899",
        "BENIGN": "#334155",
    }
    _sev = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
        "INFO": "#64748b",
    }

    src_ip = messages[0].get("src_ip", "") if messages else session_key
    actor = messages[0].get("actor_type", "UNKNOWN") if messages else "UNKNOWN"

    chat_html = ""
    for m in messages:
        ts = str(m.get("timestamp", ""))[:19].replace("T", " ")
        cat = m.get("attack_category", "BENIGN")
        cc = _cat_colors.get(cat, "#64748b")
        sc = _sev.get(m.get("severity", "INFO"), "#64748b")
        turn = m.get("turn", "")
        user_msg = e(str(m.get("user_message", "")))
        resp_msg = e(str(m.get("response_text", "")))
        strat = m.get("response_strategy", "")
        leaked = strat == "deliberate_leak"
        rules = ", ".join(m.get("attack_rules") or [])

        # User message (right aligned)
        chat_html += (
            f'<div style="display:flex;justify-content:flex-end;margin-bottom:12px">'
            f'<div style="max-width:70%;background:#5436da20;border:1px solid #5436da40;border-radius:12px;border-bottom-right-radius:4px;padding:10px 14px">'
            f'<div style="display:flex;justify-content:space-between;margin-bottom:4px">'
            f'<span style="color:#64748b;font-size:9px">Turn {turn} &mdash; {ts}</span>'
            f'<span style="background:{cc}20;color:{cc};padding:0 5px;border-radius:3px;font-size:9px;font-weight:700;border:1px solid {cc}40;margin-left:8px">{e(cat)}</span>'
            f"</div>"
            f'<div style="color:#e2e8f0;font-size:12px;white-space:pre-wrap;word-break:break-word">{user_msg}</div>'
        )
        if rules:
            chat_html += (
                f'<div style="margin-top:4px;font-size:9px;color:{sc}">Rules: {e(rules)}</div>'
            )
        chat_html += "</div></div>"

        # Assistant response (left aligned)
        if resp_msg:
            leak_border = "border-color:#ef4444" if leaked else "border-color:#10a37f40"
            leak_badge = (
                ' <span style="background:#7f1d1d;color:#fca5a5;padding:1px 5px;border-radius:3px;font-size:8px;font-weight:700">HONEYTOKEN LEAKED</span>'
                if leaked
                else ""
            )
            chat_html += (
                f'<div style="display:flex;justify-content:flex-start;margin-bottom:12px">'
                f'<div style="max-width:70%;background:#10a37f10;border:1px solid;{leak_border};border-radius:12px;border-bottom-left-radius:4px;padding:10px 14px">'
                f'<div style="color:#10a37f;font-size:9px;margin-bottom:4px">CorpAssist AI &mdash; {e(strat)}{leak_badge}</div>'
                f'<div style="color:#cbd5e1;font-size:12px;white-space:pre-wrap;word-break:break-word">{resp_msg}</div>'
                f"</div></div>"
            )

    if not chat_html:
        chat_html = '<div style="text-align:center;color:#64748b;padding:40px">No messages found for this session</div>'

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Session Replay — {e(src_ip)} — HoneyLens</title>
<style>{SHARED_CSS}
@keyframes fadeIn{{from{{opacity:0;transform:translateY(10px)}}to{{opacity:1;transform:translateY(0)}}}}
</style>
</head><body>
<a href="#main-content" class="skip-link">Skip to main content</a>
{nav_bar_html("llm")}
{
        page_header_html(
            "Session Replay",
            eyebrow="Deception · LLM",
            description=f"{src_ip} — {total} turns",
            status=(actor, "red" if actor == "LLM_AGENT" else "green"),
            actions=['<a href="/llm/dashboard?format=html#sessions" class="btn">← Dashboard</a>'],
        )
    }
<main id="main-content" style="max-width:800px;margin:0 auto;padding:20px">
  {chat_html}
</main>
</body></html>"""
