"""
webui/dashboard_hunting.py — Attacker Hunting Dashboard
========================================================
Dashboard at /attacker_hunting with attacker profiles, OSINT data,
APT attribution, and Start Hunt buttons.
Extracted from api.py.
Compatible with Python 3.9+.
"""

from __future__ import annotations

import html
import json as _json
from typing import TYPE_CHECKING

from honeylens.webui.shared import (
    SHARED_CSS,
    nav_bar_html,
    page_header_html,
    sortable_table_js,
    subnav_html,
)

# Shared Attacker-Hunting secondary navigation — used by every hunting page so
# the section tabs + active state stay consistent (IA phase 2).
HUNT_SUBNAV = [
    ("profiles", "/attacker_hunting", "Profiles"),
    ("map", "/attacker_hunting/map?format=html", "Map"),
    ("clusters", "/attacker_hunting/clusters?format=html", "Clusters"),
    ("history", "/attacker_hunting/history?format=html", "History"),
    ("osint", "/attacker_hunting/osint-status", "OSINT Status"),
]


def hunt_subnav(active: str = "") -> str:
    """The Attacker-Hunting section nav (subnav_html) with `active` tab marked."""
    return subnav_html(HUNT_SUBNAV, active=active)


if TYPE_CHECKING:
    from fastapi import FastAPI


def register_routes(app: FastAPI) -> None:
    """Hunting routes are served by api.py — this module
    provides the HTML rendering functions only."""
    pass


def _hunting_not_configured_html() -> str:
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Attacker Hunting</title>'
        "<style>body{background:#0f172a;color:#e2e8f0;font-family:monospace;"
        "display:flex;align-items:center;justify-content:center;min-height:100vh}</style>"
        '</head><body><div style="text-align:center">'
        '<div style="font-size:3rem">&#x1F3AF;</div>'
        '<h2 style="color:#f59e0b;margin:16px 0">Attacker Hunting Not Configured</h2>'
        '<p style="color:#94a3b8">Run <code>python setup_db.py</code> to create tables,</p>'
        '<p style="color:#94a3b8">then <code>python attacker_profiler.py --once</code> to profile attackers.</p>'
        '<a href="/" style="color:#38bdf8">&#8592; Back to Dashboard</a>'
        "</div></body></html>"
    )


def _hunting_dashboard_html(data: dict) -> str:
    """Attacker Hunting dashboard — full HTML with dark theme."""
    st = data["stats"]
    profiles = data["profiles"]
    tags = data["top_tags"]
    countries = data["top_countries"]
    filters = data.get("filters", {})

    _thr_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
        "UNKNOWN": "#64748b",
    }
    _thr_bg = {
        "CRITICAL": "#ef444422",
        "HIGH": "#f9731622",
        "MEDIUM": "#eab30822",
        "LOW": "#22c55e22",
        "UNKNOWN": "#64748b22",
    }
    _intent_icon = {"RECON": "🔍", "EXPLOIT": "💥", "BOTNET": "🤖", "APT": "🎯", "UNKNOWN": "❓"}

    h = '<!DOCTYPE html><html><head><meta charset="utf-8">\n'
    h += "<title>Attacker Hunting \u2014 Hybrid Intelligence Sensor</title>\n"
    h += "<style>\n"
    h += SHARED_CSS
    h += "\n"
    h += ".stats-row{display:flex;gap:12px;padding:14px 20px;flex-wrap:wrap}\n"
    h += ".stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px 18px;\n"
    h += "  min-width:120px;text-align:center}\n"
    h += ".stat-val{font-size:22px;font-weight:700}\n"
    h += ".stat-lbl{font-size:10px;color:var(--text3);margin-top:2px}\n"
    h += ".filters{padding:8px 20px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}\n"
    h += ".threat-badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:10px;font-weight:700}\n"
    h += ".ip-link{color:var(--accent);cursor:pointer}\n"
    h += ".ip-link:hover{text-decoration:underline}\n"
    h += ".apt-tag{display:inline-block;padding:1px 6px;border-radius:6px;font-size:10px;\n"
    h += "  background:#7c3aed22;color:#a78bfa;border:1px solid #7c3aed44}\n"
    h += ".scroll-wrap{overflow-x:auto;padding:0 20px}\n"
    h += ".back-link{display:inline-block;margin:14px 20px;color:var(--accent);font-size:12px}\n"
    h += "</style>\n"
    h += "</head><body>\n"
    h += '<a class="skip-link" href="#main-content">Skip to content</a>\n'
    h += nav_bar_html("hunting")
    h += '<div id="main-content" role="main" style="padding:14px 22px 0">'
    h += page_header_html(
        "Attacker Hunting",
        eyebrow="Investigate",
        description="Profile, correlate, and review hostile sources.",
    )
    h += hunt_subnav("profiles")
    h += "</div>\n"

    # Bulk hunt + auto-hunt threshold bar
    h += '<div style="display:flex;gap:8px;padding:6px 22px;background:var(--bg);border-bottom:1px solid var(--border);align-items:center;flex-wrap:wrap">'
    h += '<span style="color:var(--text3);font-size:11px">Bulk Hunt:</span>'
    h += '<button onclick="bulkHunt(\'CRITICAL\')" style="padding:4px 12px;border-radius:4px;border:1px solid #ef4444;background:#ef444420;color:#ef4444;cursor:pointer;font-size:11px;font-weight:700">Hunt All CRITICAL</button>'
    h += '<button onclick="bulkHunt(\'HIGH\')" style="padding:4px 12px;border-radius:4px;border:1px solid #f97316;background:#f9731620;color:#f97316;cursor:pointer;font-size:11px;font-weight:700">Hunt All HIGH</button>'
    h += '<span id="bulk-result" style="font-size:11px;color:#64748b"></span>'
    h += '<div style="margin-left:auto;display:flex;gap:8px;align-items:center">'
    h += '<span style="color:var(--text3);font-size:11px">Auto-hunt if:</span>'
    h += '<label style="color:#94a3b8;font-size:10px">Events&ge;</label>'
    h += '<input type="number" id="auto-hunt-events" min="0" step="10" placeholder="100" style="width:60px;background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:3px 6px;border-radius:3px;font-size:11px;font-family:monospace" onchange="saveAutoHunt()">'
    h += '<label style="color:#94a3b8;font-size:10px">Abuse&ge;</label>'
    h += '<input type="number" id="auto-hunt-abuse" min="0" max="100" step="10" placeholder="80" style="width:55px;background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:3px 6px;border-radius:3px;font-size:11px;font-family:monospace" onchange="saveAutoHunt()">'
    h += "</div></div>\n"

    # Stats row
    h += '<div class="stats-row">'
    for val, lbl, clr in [
        (st["total"], "Profiled IPs", "#38bdf8"),
        (st["critical"], "CRITICAL", "#ef4444"),
        (st["high"], "HIGH", "#f97316"),
        (st["medium"], "MEDIUM", "#eab308"),
        (st["low"], "LOW", "#22c55e"),
        (st["with_apt"], "APT Matches", "#a78bfa"),
        (st["vpn"], "VPN/Proxy", "#64748b"),
        (st["noise"], "Noise", "#475569"),
    ]:
        h += f'<div class="stat-card"><div class="stat-val" style="color:{clr}">{val}</div>'
        h += f'<div class="stat-lbl">{lbl}</div></div>'
    h += "</div>"

    # Search / filters
    cur_search = html.escape(filters.get("search") or "")
    h += '<div class="filters">'
    h += f'<input type="text" id="huntSearch" placeholder="Search IP / org / tag / APT…" value="{cur_search}" '
    h += 'onkeydown="if(event.key===\'Enter\')doSearch()" style="width:260px">'
    h += '<select id="threatFilter" onchange="doFilter()">'
    h += '<option value="">All Threats</option>'
    for t in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        sel = " selected" if (filters.get("threat") or "").upper() == t else ""
        h += f'<option value="{t}"{sel}>{t}</option>'
    h += "</select>"
    h += '<select id="countryFilter" onchange="doFilter()">'
    h += '<option value="">All Countries</option>'
    for c in countries:
        sel = " selected" if (filters.get("country") or "").upper() == c["country"] else ""
        h += f'<option value="{c["country"]}"{sel}>{c["country"]} ({c["count"]})</option>'
    h += "</select>"
    h += ' <span style="color:#64748b;font-size:11px">Tags:</span> '
    for tag_row in tags[:12]:
        h += f'<span class="tag-pill" onclick="filterTag(\'{html.escape(tag_row["tag"])}\')">{html.escape(tag_row["tag"])} ({tag_row["count"]})</span> '
    h += "</div>"

    # Profiles table
    h += '<div class="scroll-wrap"><table><thead><tr>'
    h += "<th>IP</th><th>Country</th><th>ASN / Org</th><th>Abuse</th>"
    h += "<th>Threat</th><th>Intent</th><th>Tags</th><th>APT Match</th>"
    h += "<th>Events</th><th>Last Seen</th><th>Ver</th><th>Hunt</th>"
    h += "</tr></thead><tbody>"

    for p in profiles:
        ip_val = html.escape(str(p.get("ip", "")))
        thr = p.get("ai_threat_level") or "UNKNOWN"
        tc = _thr_color.get(thr, "#64748b")
        tb = _thr_bg.get(thr, "#64748b22")
        intent = p.get("ai_intent") or "UNKNOWN"
        iicon = _intent_icon.get(intent, "❓")
        abuse = p.get("abuse_score")
        abuse_str = str(abuse) if abuse is not None else "—"
        abuse_clr = (
            "#ef4444"
            if abuse and abuse >= 80
            else "#f97316"
            if abuse and abuse >= 50
            else "#eab308"
            if abuse and abuse >= 20
            else "#22c55e"
        )
        tags_html = " ".join(
            f'<span class="tag-pill" onclick="filterTag(\'{html.escape(t)}\')">{html.escape(t)}</span>'
            for t in (p.get("internal_tags") or [])
        )
        # APT candidates
        apts = p.get("apt_candidates") or []
        if isinstance(apts, str):
            try:
                apts = _json.loads(apts)
            except Exception:
                apts = []
        apt_html = ""
        if apts and len(apts) > 0:
            top = apts[0]
            gname = html.escape(str(top.get("group_name", "")))
            prob = top.get("probability", 0)
            apt_html = f'<span class="apt-tag">{gname} ({prob:.0%})</span>'
            if len(apts) > 1:
                apt_html += f' <span style="color:#64748b;font-size:10px">+{len(apts) - 1}</span>'

        last_seen = (p.get("last_seen") or "")[:10]
        ver = p.get("profile_version", 1)

        h += "<tr>"
        h += f'<td><span class="ip-link" onclick="location.href=\'/attacker_hunting/{ip_val}\'">{ip_val}</span></td>'
        h += f"<td>{html.escape(str(p.get('country') or '—'))}</td>"
        org = html.escape(str(p.get("as_org") or "—"))[:30]
        h += f'<td title="{html.escape(str(p.get("as_org") or ""))}">{org}</td>'
        h += f'<td style="color:{abuse_clr};font-weight:700">{abuse_str}</td>'
        h += f'<td><span class="threat-badge" style="background:{tb};color:{tc}">{thr}</span></td>'
        h += f"<td>{iicon} {intent}</td>"
        h += f"<td>{tags_html}</td>"
        h += f"<td>{apt_html}</td>"
        h += f"<td>{p.get('total_events', 0)}</td>"
        h += f"<td>{last_seen}</td>"
        h += f'<td style="color:#64748b">{ver}</td>'
        h += f'<td><button class="hunt-btn" onclick="startHunt(\'{ip_val}\',this)">&#x1F3AF; Start Hunt</button></td>'
        h += "</tr>"

    if not profiles:
        h += '<tr><td colspan="12" style="text-align:center;color:#64748b;padding:30px">'
        h += "No attacker profiles yet. Run <code>python attacker_profiler.py --once</code> to start profiling."
        h += "</td></tr>"

    h += "</tbody></table></div>"

    # JavaScript
    h += r"""
<script>
function esc(s) { var d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

function doSearch() {
  var q = document.getElementById('huntSearch').value.trim();
  var url = '/attacker_hunting?search=' + encodeURIComponent(q);
  var t = document.getElementById('threatFilter').value;
  var c = document.getElementById('countryFilter').value;
  if (t) url += '&threat=' + t;
  if (c) url += '&country=' + c;
  location.href = url;
}

function doFilter() {
  var q = document.getElementById('huntSearch').value.trim();
  var t = document.getElementById('threatFilter').value;
  var c = document.getElementById('countryFilter').value;
  var url = '/attacker_hunting?';
  if (q) url += 'search=' + encodeURIComponent(q) + '&';
  if (t) url += 'threat=' + t + '&';
  if (c) url += 'country=' + c + '&';
  location.href = url;
}

function filterTag(tag) {
  location.href = '/attacker_hunting?tag=' + encodeURIComponent(tag);
}

function startHunt(ip, btn, force) {
  btn.disabled = true;
  btn.innerHTML = '&#x23F3; Hunting...';
  btn.style.color = '#f59e0b';
  var url = '/attacker_hunting/' + encodeURIComponent(ip) + '/hunt' + (force ? '?force=true' : '');
  fetch(url, {method:'POST', credentials:'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.status === 'profiled') {
        btn.innerHTML = '&#x2705; ' + (data.threat_level || 'OK');
        btn.style.color = '#22c55e';
        var row = btn.closest('tr');
        if (row) {
          setTimeout(function() { location.reload(); }, 1500);
        }
      } else if (data.detail && data.detail.indexOf('known research scanner') > -1) {
        btn.innerHTML = '&#x1F50D; Scanner — Force?';
        btn.style.color = '#eab308';
        btn.disabled = false;
        btn.onclick = function() { startHunt(ip, btn, true); };
      } else {
        btn.innerHTML = '&#x274C; ' + (data.detail || 'Error');
        btn.style.color = '#ef4444';
        setTimeout(function() { btn.innerHTML = '&#x1F3AF; Start Hunt'; btn.style.color='#f59e0b'; btn.disabled=false; }, 3000);
      }
    })
    .catch(function(err) {
      btn.innerHTML = '&#x274C; Error';
      btn.style.color = '#ef4444';
      setTimeout(function() { btn.innerHTML = '&#x1F3AF; Start Hunt'; btn.style.color='#f59e0b'; btn.disabled=false; }, 3000);
    });
}

function bulkHunt(level) {
  var res = document.getElementById('bulk-result');
  res.innerHTML = '<span style="color:#f59e0b">Hunting ' + level + ' IPs...</span>';
  fetch('/attacker_hunting/bulk-hunt', {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({level: level})
  })
  .then(function(r) { return r.json(); })
  .then(function(d) {
    if (d.error) {
      res.innerHTML = '<span style="color:#ef4444">Error: ' + d.error + '</span>';
    } else if (d.hunted === 0) {
      res.innerHTML = '<span style="color:#64748b">No matching IPs to hunt</span>';
    } else {
      res.innerHTML = '<span style="color:#22c55e">&#x2705; ' + d.hunted + ' IPs queued for hunting</span>';
      setTimeout(function() { location.reload(); }, 2000);
    }
  })
  .catch(function(e) {
    res.innerHTML = '<span style="color:#ef4444">Request failed</span>';
  });
}

function saveAutoHunt() {
  var t = {
    events: parseInt(document.getElementById('auto-hunt-events').value) || 0,
    abuse: parseInt(document.getElementById('auto-hunt-abuse').value) || 0,
  };
  localStorage.setItem('hunting_auto_thresholds', JSON.stringify(t));
  applyAutoHunt(t);
}
function loadAutoHunt() {
  try {
    var t = JSON.parse(localStorage.getItem('hunting_auto_thresholds'));
    if (t) {
      if (t.events) document.getElementById('auto-hunt-events').value = t.events;
      if (t.abuse) document.getElementById('auto-hunt-abuse').value = t.abuse;
      applyAutoHunt(t);
    }
  } catch(e) {}
}
function applyAutoHunt(t) {
  // Highlight rows that exceed auto-hunt thresholds
  document.querySelectorAll('table tbody tr').forEach(function(row) {
    var cells = row.querySelectorAll('td');
    if (cells.length < 10) return;
    // Find events column (typically index 8) and abuse column (index 3)
    var eventsCell = null, abuseCell = null;
    cells.forEach(function(c) {
      var txt = c.textContent.trim();
      if (c.style && c.style.cursor === 'pointer' && /^\d+$/.test(txt.replace(/,/g,''))) eventsCell = c;
    });
    // Check abuse score cell (has /100 or is number 0-100)
    for (var i = 0; i < cells.length; i++) {
      var v = parseInt(cells[i].textContent.trim().replace(/,/g,''));
      if (v >= 0 && v <= 100 && cells[i].textContent.indexOf('/') === -1) {
        var title = cells[i].getAttribute('title') || '';
        if (title.indexOf('abuse') > -1 || cells[i].className.indexOf('abuse') > -1) {
          abuseCell = cells[i]; break;
        }
      }
    }
    var alert = false;
    if (t.events && eventsCell) {
      var ev = parseInt(eventsCell.textContent.replace(/,/g,'')) || 0;
      if (ev >= t.events) alert = true;
    }
    if (t.abuse && abuseCell) {
      var ab = parseInt(abuseCell.textContent.replace(/,/g,'')) || 0;
      if (ab >= t.abuse) alert = true;
    }
    if (alert) {
      row.style.borderLeft = '3px solid #f59e0b';
      row.style.background = '#f59e0b08';
    }
  });
}
loadAutoHunt();
</script>
"""
    h += sortable_table_js()
    h += "\n</body></html>"
    return h


def _hunting_detail_html(p: dict) -> str:
    """Attacker profile detail page."""
    ip = html.escape(str(p.get("ip", "")))
    thr = p.get("ai_threat_level") or "UNKNOWN"
    _thr_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
        "UNKNOWN": "#64748b",
    }
    tc = _thr_color.get(thr, "#64748b")

    _thr_kind = {
        "CRITICAL": "red",
        "HIGH": "orange",
        "MEDIUM": "yellow",
        "LOW": "green",
        "UNKNOWN": "text3",
    }
    _hunt_status = p.get("hunt_status") or "ACTIVE"
    _meta = ["Finished hunt" if _hunt_status == "FINISHED" else "Active hunt"]
    if p.get("asn"):
        _meta.append("AS" + str(p.get("asn")) + " " + str(p.get("as_org") or ""))
    if p.get("country"):
        _meta.append(str(p.get("country")))
    _nav = nav_bar_html("hunting")
    _header = page_header_html(
        "Attacker " + ip,
        eyebrow="Investigate · Hunting",
        description="Profile, infrastructure, and intelligence for this source.",
        status=(thr, _thr_kind.get(thr, "text3")),
        metadata=_meta,
        actions=('<a class="nav-btn" href="/attacker_hunting">&#8592; Hunting</a>',),
    )
    _subnav = hunt_subnav("")

    h = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attacker {ip} — Hunting</title>
<style>{SHARED_CSS}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}}
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px}}
.card h3{{font-size:13px;color:var(--text2);margin-bottom:8px}}
.kv{{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;font-size:12px}}
.kk{{color:var(--text3)}}.kv-val{{word-break:break-all}}
.threat-badge{{display:inline-block;padding:3px 12px;border-radius:6px;font-weight:700}}
.apt-card{{background:#7c3aed11;border:1px solid #7c3aed44;border-radius:8px;padding:10px;margin:6px 0}}
.apt-card h4{{color:var(--purple);font-size:12px;margin-bottom:4px}}
.bar{{height:6px;border-radius:3px;background:var(--bg4)}}
.bar-fill{{height:6px;border-radius:3px;background:var(--purple)}}
pre{{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;font-size:11px;overflow-x:auto;max-height:300px}}
.act-btn{{background:transparent;border:1px solid #33415544;padding:2px 5px;border-radius:4px;
  cursor:pointer;font-size:12px;font-family:inherit;transition:all .15s}}
.act-btn:hover{{filter:brightness(1.4)}}
.hunt-btn{{background:#f59e0b22;border:1px solid var(--hunt);color:var(--hunt);padding:6px 14px;
  border-radius:6px;cursor:pointer;font-family:inherit;font-weight:700;font-size:12px;transition:all .15s}}
.hunt-btn:hover{{filter:brightness(1.2)}}
</style></head><body>
<a class="skip-link" href="#main-content">Skip to content</a>{_nav}
<div class="page" id="main-content" role="main">
{_header}{_subnav}
"""
    # Top info cards
    h += '<div class="grid">'

    # Identity card
    h += '<div class="card"><h3>Identity</h3><div class="kv">'
    for k, v in [
        ("IP", ip),
        ("Country", p.get("country") or "—"),
        ("City", p.get("city") or "—"),
        ("ASN", str(p.get("asn") or "—")),
        ("Org", p.get("as_org") or "—"),
        ("Hostname", p.get("hostname") or "—"),
        ("OS Guess", p.get("os_guess") or "—"),
        ("VPN/Proxy", "Yes" if p.get("is_vpn") else "No"),
        ("Noise", "Yes" if p.get("is_noise") else "No"),
        ("Open Ports", ", ".join(str(x) for x in (p.get("open_ports") or [])[:20]) or "—"),
    ]:
        h += f'<div class="kk">{k}</div><div class="kv-val">{html.escape(str(v))}</div>'
    h += "</div></div>"

    # OSINT — source-of-truth card (keyless module: whois/RDAP/Cymru/InternetDB/Tor)
    canon = (p.get("osint_data") or {}).get("_canonical") or {}
    _tor = canon.get("tor_exit")
    h += '<div class="card"><h3>&#x1F50E; OSINT — Source of Truth</h3><div class="kv">'
    for k, v in [
        ("ASN", canon.get("asn") or p.get("asn") or "—"),
        ("AS Name", canon.get("as_name") or "—"),
        ("Org", canon.get("org") or p.get("as_org") or "—"),
        ("Netname", canon.get("netname") or "—"),
        ("CIDR / Prefix", canon.get("cidr") or "—"),
        ("Country", canon.get("country") or p.get("country") or "—"),
        ("Registry", canon.get("registry") or "—"),
        ("Registered", canon.get("registered") or "—"),
        ("PTR", canon.get("ptr") or "—"),
        ("Abuse Contact", canon.get("abuse_contact") or "—"),
        ("Tor Exit", "&#x26A0; YES" if _tor else ("No" if _tor is not None else "—")),
        (
            "Open Ports",
            ", ".join(str(x) for x in (canon.get("ports") or p.get("open_ports") or [])[:25])
            or "—",
        ),
        ("Known CVEs", (", ".join(canon.get("cves") or [])[:400]) or "—"),
        ("Tags", ", ".join(canon.get("tags") or []) or "—"),
        ("Sources", ", ".join(canon.get("sources") or []) or "—"),
    ]:
        cell = v if k == "Tor Exit" else html.escape(str(v))
        h += f'<div class="kk">{k}</div><div class="kv-val">{cell}</div>'
    h += "</div></div>"

    # Threat card
    abuse = p.get("abuse_score")
    h += '<div class="card"><h3>Threat Assessment</h3><div class="kv">'
    h += f'<div class="kk">Threat Level</div><div class="kv-val"><span class="threat-badge" style="background:{tc}22;color:{tc}">{thr}</span></div>'
    h += f'<div class="kk">Intent</div><div class="kv-val">{html.escape(str(p.get("ai_intent") or "UNKNOWN"))}</div>'
    h += f'<div class="kk">Abuse Score</div><div class="kv-val" style="font-weight:700;color:{"#ef4444" if abuse and abuse >= 80 else "#f97316" if abuse and abuse >= 50 else "#22c55e"}">{abuse if abuse is not None else "—"}/100</div>'
    h += f'<div class="kk">Total Events</div><div class="kv-val">{p.get("total_events", 0)}</div>'
    h += f'<div class="kk">Attack Types</div><div class="kv-val">{p.get("total_attacks", 0)}</div>'
    h += f'<div class="kk">First Seen</div><div class="kv-val">{html.escape(str(p.get("first_seen") or "—")[:19])}</div>'
    h += f'<div class="kk">Last Seen</div><div class="kv-val">{html.escape(str(p.get("last_seen") or "—")[:19])}</div>'
    h += f'<div class="kk">Profile Ver</div><div class="kv-val">{p.get("profile_version", 1)}</div>'
    h += "</div></div>"
    h += "</div>"  # end grid

    # Tags + MITRE
    h += '<div class="grid">'
    h += '<div class="card"><h3>Internal Tags</h3>'
    for t in p.get("internal_tags") or []:
        h += f'<span class="tag-pill">{html.escape(t)}</span> '
    if not p.get("internal_tags"):
        h += '<span style="color:#64748b">No tags assigned</span>'
    h += "</div>"

    h += '<div class="card"><h3>MITRE ATT&CK Techniques</h3>'
    for t in p.get("mitre_techniques") or []:
        h += f'<a class="tag-pill" href="https://attack.mitre.org/techniques/{html.escape(t.replace(".", "/"))}/" target="_blank" style="color:#38bdf8">{html.escape(t)}</a> '
    if not p.get("mitre_techniques"):
        h += '<span style="color:#64748b">No techniques mapped</span>'
    h += "</div>"
    h += "</div>"

    # AI Summary
    h += '<div class="card" style="margin-bottom:14px"><h3>&#x1F9E0; AI Analysis</h3>'
    h += f'<p style="margin:8px 0;line-height:1.6">{html.escape(str(p.get("ai_summary") or "No AI analysis yet."))}</p>'
    if p.get("ai_updated_at"):
        h += f'<div style="color:#64748b;font-size:10px;margin-top:6px">Updated: {html.escape(str(p["ai_updated_at"])[:19])}</div>'
    h += "</div>"

    # APT Attribution
    apts = p.get("apt_candidates") or []
    if isinstance(apts, str):
        try:
            apts = _json.loads(apts)
        except Exception:
            apts = []

    h += (
        '<div class="card" style="margin-bottom:14px"><h3>&#x1F3AF; APT Attribution Candidates</h3>'
    )
    if apts:
        for a in apts[:5]:
            gname = html.escape(str(a.get("group_name", "")))
            gid = html.escape(str(a.get("group_id", "")))
            prob = a.get("probability", 0)
            aliases = ", ".join(html.escape(str(x)) for x in (a.get("aliases") or [])[:5])
            techs = ", ".join(html.escape(str(t)) for t in (a.get("matching_techniques") or []))
            reasoning = html.escape(str(a.get("reasoning", "")))
            pct = int(prob * 100)
            h += '<div class="apt-card">'
            h += f'<h4><a href="https://attack.mitre.org/groups/{gid}/" target="_blank">{gname}</a> ({gid}) — {pct}%</h4>'
            h += f'<div class="bar" style="margin:6px 0"><div class="bar-fill" style="width:{pct}%"></div></div>'
            if aliases:
                h += f'<div style="font-size:10px;color:#94a3b8">Aliases: {aliases}</div>'
            h += f'<div style="font-size:10px;color:#94a3b8;margin-top:2px">Techniques: {techs}</div>'
            h += f'<div style="font-size:10px;color:#64748b;margin-top:2px">{reasoning}</div>'
            h += "</div>"
    else:
        h += '<span style="color:#64748b">No APT candidates above threshold</span>'
    h += "</div>"

    # Attack types
    h += '<div class="card" style="margin-bottom:14px"><h3>Attack Types Observed</h3>'
    for at in p.get("attack_types") or []:
        if at:
            h += f'<span class="tag-pill" style="background:#ef444422;color:#f87171">{html.escape(str(at))}</span> '
    h += "</div>"

    # Claude Analysis card — profile-level summary
    claude = p.get("claude")
    if claude and claude.get("verdict"):
        cv = claude["verdict"]
        cvc = _thr_color.get(cv, "#d97706")
        h += '<div class="card" style="margin-bottom:14px;border-color:#d9770644"><h3 style="color:#d97706">&#x1F52C; Claude Sonnet — Best Verdict</h3>'
        h += '<div class="kv">'
        h += f'<div class="kk">Verdict</div><div class="kv-val" style="color:{cvc};font-weight:700">{html.escape(cv)}</div>'
        if claude.get("technique"):
            h += f'<div class="kk">MITRE</div><div class="kv-val" style="color:#f87171">{html.escape(claude["technique"])}</div>'
        if claude.get("cve"):
            h += f'<div class="kk">CVE</div><div class="kv-val" style="color:#f87171;font-weight:700">{html.escape(claude["cve"])}</div>'
        if claude.get("threat_actor"):
            h += f'<div class="kk">Threat Actor</div><div class="kv-val" style="color:#ef4444;font-weight:700">{html.escape(claude["threat_actor"])}</div>'
        if claude.get("summary"):
            h += f'<div class="kk">Summary</div><div class="kv-val" style="font-size:11px;line-height:1.5">{html.escape(claude["summary"])}</div>'
        if claude.get("analyzed_at"):
            h += f'<div class="kk">Analyzed</div><div class="kv-val" style="color:#64748b;font-size:10px">{html.escape(claude["analyzed_at"][:19])}</div>'
        h += "</div></div>"

    # Claude Analysis History — all analyses for this IP
    claude_hist = p.get("claude_history", [])
    if claude_hist:
        h += '<div class="card" style="margin-bottom:14px;border-color:#d9770644"><h3 style="color:#d97706">&#x1F52C; Claude Analysis History'
        h += f' <span style="color:#64748b;font-weight:400;font-size:11px">({len(claude_hist)} analyses)</span></h3>'
        h += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:8px">'
        h += '<thead><tr style="border-bottom:1px solid #334155;color:#64748b;font-size:10px;text-transform:uppercase">'
        h += '<th style="padding:4px 8px">Verdict</th><th style="padding:4px 8px;text-align:left">Attack</th>'
        h += '<th style="padding:4px 8px">MITRE</th><th style="padding:4px 8px">CVE</th>'
        h += '<th style="padding:4px 8px;text-align:left">Summary</th>'
        h += '<th style="padding:4px 8px">Cost</th><th style="padding:4px 8px">Time</th>'
        h += '<th style="padding:4px 8px">Event</th></tr></thead><tbody>'
        for ch in claude_hist:
            chv = ch.get("verdict", "")
            chc = _thr_color.get(chv, "#64748b")
            eid_short = html.escape(str(ch.get("event_id", ""))[:12])
            eid_full = html.escape(str(ch.get("event_id", "")))
            ch_atk = html.escape(str(ch.get("attack_type", "") or "")[:30])
            ch_tech = html.escape(str(ch.get("technique", "") or ""))
            ch_cve = html.escape(str(ch.get("cve", "") or ""))
            ch_summary = html.escape(str(ch.get("summary", "") or "")[:80])
            ch_cost = ch.get("cost") or 0
            ch_time = html.escape(str(ch.get("analyzed_at", "") or "")[:16].replace("T", " "))
            h += '<tr style="border-bottom:1px solid #ffffff08">'
            h += f'<td style="padding:4px 8px;text-align:center"><span style="color:{chc};font-weight:700;font-size:11px">{html.escape(chv)}</span></td>'
            h += f'<td style="padding:4px 8px;font-size:11px">{ch_atk}</td>'
            h += f'<td style="padding:4px 8px;color:#f87171;font-size:10px;text-align:center">{ch_tech}</td>'
            h += f'<td style="padding:4px 8px;color:#f87171;font-size:10px;font-weight:700;text-align:center">{ch_cve}</td>'
            h += f'<td style="padding:4px 8px;color:#94a3b8;font-size:10px" title="{html.escape(str(ch.get("summary", "") or ""))}">{ch_summary}</td>'
            h += f'<td style="padding:4px 8px;color:#64748b;font-size:10px;text-align:center">${ch_cost:.3f}</td>'
            h += f'<td style="padding:4px 8px;color:#64748b;font-size:10px;white-space:nowrap">{ch_time}</td>'
            h += f'<td style="padding:4px 8px"><a href="/event_full/{eid_full}?format=html" target="_blank" style="color:#38bdf8;font-size:10px">{eid_short}…</a></td>'
            h += "</tr>"
        h += "</tbody></table></div></div>"

    # CVE Intelligence (Idea 32 Phase E)
    cve_intel = p.get("cve_intelligence", [])
    if cve_intel:
        h += '<div class="card" style="margin-bottom:14px;border-color:#f8717144"><h3 style="color:#f87171">&#x1F6E1; CVE Intelligence (CIRCL)</h3>'
        h += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:8px">'
        h += '<thead><tr style="border-bottom:1px solid #334155;color:#64748b;font-size:10px;text-transform:uppercase">'
        h += '<th style="padding:4px 8px;text-align:left">CVE</th>'
        h += '<th style="padding:4px 8px">CVSS</th><th style="padding:4px 8px">Severity</th>'
        h += '<th style="padding:4px 8px">KEV</th>'
        h += '<th style="padding:4px 8px;text-align:left">Title</th>'
        h += '<th style="padding:4px 8px;text-align:left">Vendor / Product</th>'
        h += '<th style="padding:4px 8px;text-align:left">CWE</th>'
        h += "</tr></thead><tbody>"
        _sev_c = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
        for cd in cve_intel:
            cid = html.escape(str(cd.get("cve_id", "")))
            sc = _sev_c.get(str(cd.get("cvss_severity", "")), "#64748b")
            kev_tag = (
                '<span style="background:#ef4444;color:#fff;padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700">KEV</span>'
                if cd.get("is_kev")
                else '<span style="color:#64748b">—</span>'
            )
            title = html.escape(str(cd.get("title", "") or "")[:80])
            vendor = html.escape(str(cd.get("vendor", "") or ""))
            product = html.escape(str(cd.get("product", "") or ""))
            cwes = ", ".join(cd.get("cwe", []))
            h += "<tr>"
            h += f'<td style="padding:4px 8px"><a href="https://vulnerability.circl.lu/cve/{cid}" target="_blank" style="color:#f87171;text-decoration:none;font-weight:600">{cid}</a></td>'
            h += f'<td style="padding:4px 8px;color:{sc};font-weight:700;text-align:center">{cd.get("cvss_score") or "—"}</td>'
            h += f'<td style="padding:4px 8px;color:{sc}">{html.escape(str(cd.get("cvss_severity", "") or ""))}</td>'
            h += f'<td style="padding:4px 8px;text-align:center">{kev_tag}</td>'
            h += f'<td style="padding:4px 8px;color:#cbd5e1;font-size:11px" title="{title}">{title}</td>'
            h += f'<td style="padding:4px 8px;color:#94a3b8;font-size:11px">{vendor} {product}</td>'
            h += (
                f'<td style="padding:4px 8px;color:#94a3b8;font-size:10px">{html.escape(cwes)}</td>'
            )
            h += "</tr>"
        h += "</tbody></table></div></div>"

    # Recent Events table
    recent = p.get("recent_events", [])
    h += '<div class="card" style="margin-bottom:14px"><h3>&#x1F4CB; Recent Events</h3>'
    if recent:
        h += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:8px">'
        h += '<thead><tr style="border-bottom:1px solid #334155;color:#64748b;font-size:10px;text-transform:uppercase">'
        h += '<th style="padding:4px 8px;text-align:left">Time</th>'
        h += '<th style="padding:4px 8px">Proto</th><th style="padding:4px 8px">Port</th>'
        h += '<th style="padding:4px 8px;text-align:left">Attacks</th>'
        h += '<th style="padding:4px 8px">Score</th>'
        h += '<th style="padding:4px 8px">AI</th><th style="padding:4px 8px">Claude</th>'
        h += '<th style="padding:4px 8px">Actions</th></tr></thead><tbody>'
        _vc = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
            "INFO": "#38bdf8",
            "SUSPICIOUS": "#f97316",
            "KNOWN": "#38bdf8",
            "NOISE": "#64748b",
        }
        for ev in recent:
            eid = html.escape(str(ev.get("event_id", "")))
            ets = html.escape(str(ev.get("timestamp", ""))[:19].replace("T", " "))
            eproto = html.escape(str(ev.get("protocol", "")).upper())
            eport = ev.get("dst_port", "")
            eatk = html.escape(str(ev.get("attack_types", "") or "")[:40])
            escore = ev.get("scan_score", "")
            # AI triage status
            ai_cls = ev.get("ai_class") or ""
            ai_color = _vc.get(ai_cls, "#64748b")
            ai_html = (
                f'<span style="color:{ai_color};font-weight:700;font-size:10px">{html.escape(ai_cls)}</span>'
                if ai_cls
                else '<span style="color:#334155">—</span>'
            )
            # Claude status
            cl_v = ev.get("claude_verdict") or ""
            cl_color = _vc.get(cl_v, "#64748b")
            cl_atk = html.escape(str(ev.get("claude_attack") or "")[:25])
            cl_cve = html.escape(str(ev.get("claude_cve") or ""))
            if cl_v:
                cl_html = f'<span style="color:{cl_color};font-weight:700;font-size:10px">{html.escape(cl_v)}</span>'
                if cl_cve:
                    cl_html += f' <span style="color:#f87171;font-size:9px">{cl_cve}</span>'
                elif cl_atk:
                    cl_html += f' <span style="color:#94a3b8;font-size:9px">{cl_atk}</span>'
            else:
                cl_html = '<span style="color:#334155">—</span>'
            h += '<tr style="border-bottom:1px solid #ffffff08">'
            h += f'<td style="padding:4px 8px;color:#94a3b8;font-size:11px;white-space:nowrap">{ets}</td>'
            h += f'<td style="padding:4px 8px;color:#38bdf8;font-weight:700;text-align:center">{eproto}</td>'
            h += f'<td style="padding:4px 8px;text-align:center">{eport}</td>'
            h += f'<td style="padding:4px 8px;color:#f87171;font-size:11px">{eatk}</td>'
            h += f'<td style="padding:4px 8px;text-align:center">{escore}</td>'
            h += f'<td style="padding:4px 8px;text-align:center">{ai_html}</td>'
            h += f'<td style="padding:4px 8px;text-align:center">{cl_html}</td>'
            h += '<td style="padding:4px 8px;white-space:nowrap">'
            h += f'<a href="/event_full/{eid}?format=html" target="_blank" style="color:#38bdf8;font-size:10px;margin-right:4px" title="View">&#x1F50D;</a>'
            h += f'<button class="act-btn" style="color:#a78bfa" data-eid="{eid}" onclick="aiEvent(this.dataset.eid,this)" title="AI Analyze">&#x1F9E0;</button>'
            h += f'<button class="act-btn btn-claude" style="color:#d97706;display:none" data-eid="{eid}" onclick="claudeEvent(this.dataset.eid,this)" title="AI Deep">&#x1F52C;</button>'
            h += "</td></tr>"
        h += "</tbody></table></div>"
    else:
        h += '<span style="color:#64748b">No recent events found</span>'
    h += "</div>"

    # Hunt status
    hunt_status = p.get("hunt_status") or "ACTIVE"
    is_finished = hunt_status == "FINISHED"
    finish_notes = html.escape(str(p.get("finish_notes") or "")) if p.get("finish_notes") else ""
    finished_at = html.escape(str(p.get("finished_at") or "")[:19]) if p.get("finished_at") else ""

    # Status badge
    if is_finished:
        h += '<div style="margin-bottom:14px;padding:10px;background:#22c55e11;border:1px solid #22c55e44;border-radius:8px">'
        h += '<span style="color:#22c55e;font-weight:700;font-size:13px">&#x2705; Hunt Finished</span>'
        h += f' <span style="color:#64748b;font-size:11px;margin-left:8px">{finished_at}</span>'
        if finish_notes:
            h += f'<div style="color:#94a3b8;font-size:12px;margin-top:6px;line-height:1.5">{finish_notes}</div>'
        h += "</div>"

    # Action buttons bar
    h += f"""
<div style="margin:16px 0;display:flex;gap:8px;flex-wrap:wrap">
  <button class="hunt-btn" style="font-size:13px;padding:8px 16px" onclick="startHunt('{ip}',this)">
    &#x1F3AF; Re-Hunt (Re-profile)
  </button>
  <button class="hunt-btn" style="font-size:13px;padding:8px 16px;background:#d9770622;border-color:#d97706;color:#d97706;display:none" id="claudeAllBtn"
    onclick="claudeLatest('{ip}',this)">
    &#x1F52C; AI DEEP &mdash; Latest Event
  </button>"""

    if is_finished:
        h += f"""
  <button class="hunt-btn" style="font-size:13px;padding:8px 16px;background:#f9731622;border-color:#f97316;color:#f97316"
    onclick="reopenHunt('{ip}',this)">
    &#x1F504; Re-open Hunt
  </button>"""
    else:
        h += f"""
  <button class="hunt-btn" style="font-size:13px;padding:8px 16px;background:#22c55e22;border-color:#22c55e;color:#22c55e"
    onclick="finishHunt('{ip}',this)">
    &#x2705; Finish Hunt
  </button>"""

    h += f"""
  <a href="/events_ip/{ip}?format=html" class="hunt-btn" style="font-size:13px;padding:8px 16px;background:#38bdf822;border-color:#38bdf8;color:#38bdf8;text-decoration:none;display:inline-block">
    &#x1F50D; All Events for IP
  </a>
  <a href="/attacker_hunting/history?format=html" class="hunt-btn" style="font-size:13px;padding:8px 16px;background:#64748b22;border-color:#64748b;color:#94a3b8;text-decoration:none;display:inline-block">
    &#x1F4DA; Hunt History
  </a>
  <button class="hunt-btn btn-blog" style="font-size:13px;padding:8px 16px;background:#06b6d422;border-color:#06b6d4;color:#06b6d4;display:none"
    onclick="publishBlog('{ip}',this)">
    &#x1F4DD; Publish Post
  </button>
</div>"""

    h += """
<div id="ai-result"></div>
<div id="claude-result"></div>

<script>
function esc(v) { return v==null?'':String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

/* AI Deep availability check (any configured backend) */
fetch('/ai/deep-status', {credentials:'same-origin'})
  .then(function(r){ return r.json(); })
  .then(function(d){
    if (d.available) {
      document.querySelectorAll('.btn-claude').forEach(function(b){ b.style.display='inline-block'; });
      var cab = document.getElementById('claudeAllBtn');
      if (cab) cab.style.display = 'inline-block';
    }
  }).catch(function(){});

/* Blog availability check */
fetch('/blog/status', {credentials:'same-origin'})
  .then(function(r){ return r.json(); })
  .then(function(d){
    if (d.available) {
      document.querySelectorAll('.btn-blog').forEach(function(b){ b.style.display='inline-block'; });
    }
  }).catch(function(){});

function publishBlog(ip, btn) {
  if (!confirm('Publish threat advisory for ' + ip + ' to the external blog?')) return;
  btn.disabled = true;
  btn.innerHTML = '&#x23F3; Publishing...';
  btn.style.color = '#eab308';
  fetch('/blog/publish/' + encodeURIComponent(ip), {method:'POST',credentials:'same-origin'})
    .then(function(r) { return r.json().then(function(d) { return {ok:r.ok, data:d}; }); })
    .then(function(res) {
      if (res.ok) {
        var s = res.data.status === 'updated' ? 'Updated' : 'Published';
        btn.innerHTML = '&#x2705; ' + s;
        btn.style.color = '#22c55e';
        if (res.data.post_url) {
          setTimeout(function() {
            btn.innerHTML = '<a href=\"' + res.data.post_url + '\" target=\"_blank\" style=\"color:#06b6d4;text-decoration:none\">&#x1F4DD; View Post &#x2197;</a>';
            btn.disabled = false;
          }, 2000);
        }
      } else {
        btn.innerHTML = '&#x274C; ' + (res.data.detail || 'Error').substring(0, 40);
        btn.style.color = '#ef4444';
        setTimeout(function() { btn.innerHTML = '&#x1F4DD; Publish Post'; btn.style.color='#06b6d4'; btn.disabled=false; }, 4000);
      }
    })
    .catch(function(err) {
      btn.innerHTML = '&#x274C; Error';
      btn.style.color = '#ef4444';
      setTimeout(function() { btn.innerHTML = '&#x1F4DD; Publish Post'; btn.style.color='#06b6d4'; btn.disabled=false; }, 4000);
    });
}

function startHunt(ip, btn, force) {
  btn.disabled = true;
  btn.innerHTML = '&#x23F3; Hunting...';
  var url = '/attacker_hunting/' + encodeURIComponent(ip) + '/hunt' + (force ? '?force=true' : '');
  fetch(url, {method:'POST',credentials:'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.status === 'profiled') {
        btn.innerHTML = '&#x2705; Done — reloading...';
        btn.style.color = '#22c55e';
        setTimeout(function() { location.reload(); }, 1500);
      } else if (data.detail && data.detail.indexOf('known research scanner') > -1) {
        btn.innerHTML = '&#x1F50D; Scanner — Force?';
        btn.style.color = '#eab308';
        btn.disabled = false;
        btn.onclick = function() { startHunt(ip, btn, true); };
      } else {
        btn.innerHTML = '&#x274C; ' + (data.detail || 'Error');
        setTimeout(function() { btn.innerHTML = '&#x1F3AF; Re-Hunt'; btn.disabled=false; }, 3000);
      }
    })
    .catch(function(err) {
      btn.innerHTML = '&#x274C; Error';
      setTimeout(function() { btn.innerHTML = '&#x1F3AF; Re-Hunt'; btn.disabled=false; }, 3000);
    });
}

function aiEvent(eventId, btn) {
  btn.disabled = true; btn.innerHTML = '&#x23F3;'; btn.style.color = '#eab308';
  fetch('/ai/analyze/' + encodeURIComponent(eventId), {method:'POST',credentials:'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.detail) { btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444'; return; }
      var cls = data.triage_class || '?';
      var cc = {'CRITICAL':'#ef4444','SUSPICIOUS':'#f97316','KNOWN':'#38bdf8','NOISE':'#64748b'}[cls] || '#94a3b8';
      btn.innerHTML = '&#x1F9E0; ' + cls; btn.style.color = cc; btn.disabled = false;
    })
    .catch(function() { btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444'; });
}

function claudeEvent(eventId, btn) {
  btn.disabled = true; btn.innerHTML = '&#x23F3;'; btn.style.color = '#eab308';
  fetch('/ai/deep-analyze/' + encodeURIComponent(eventId), {method:'POST',credentials:'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.detail || data.error) {
        btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
        setTimeout(function() { btn.innerHTML = '&#x1F52C;'; btn.style.color='#d97706'; btn.disabled=false; }, 5000);
        return;
      }
      var v = data.verdict || '?';
      var vc = {'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e'}[v] || '#94a3b8';
      btn.innerHTML = '&#x1F52C; ' + v; btn.style.color = vc; btn.disabled = false;
      /* Show result below */
      var c = document.getElementById('claude-result');
      if (c) {
        var _backend = esc(String(data._backend || 'AI').toUpperCase());
        var h = '<div class="card" style="margin-top:12px;border-color:#d9770644"><h3 style="color:#d97706">&#x1F52C; AI DEEP Result &mdash; '+_backend+' ('+esc(eventId.substring(0,12))+'...)</h3><div class="kv">';
        h += '<div class="kk">Verdict</div><div class="kv-val" style="color:'+vc+';font-weight:700">'+esc(v)+' ('+esc(data.confidence||'?')+'%)</div>';
        if(data.attack_type) h += '<div class="kk">Attack</div><div class="kv-val">'+esc(data.attack_type)+'</div>';
        if(data.technique) h += '<div class="kk">MITRE</div><div class="kv-val" style="color:#f87171">'+esc(data.technique)+'</div>';
        if(data.cve) h += '<div class="kk">CVE</div><div class="kv-val" style="color:#f87171;font-weight:700">'+esc(data.cve)+'</div>';
        if(data.threat_actor) h += '<div class="kk">Threat Actor</div><div class="kv-val" style="color:#ef4444;font-weight:700">'+esc(data.threat_actor)+'</div>';
        if(data.summary) h += '<div class="kk">Summary</div><div class="kv-val" style="font-size:11px">'+esc(data.summary)+'</div>';
        if(data._meta) h += '<div class="kk">Cost</div><div class="kv-val" style="font-size:10px;color:#64748b">'+esc(data._meta.model)+' — '+(data._meta.input_tokens||0)+' in / '+(data._meta.output_tokens||0)+' out — $'+((data._meta.input_tokens*3+data._meta.output_tokens*15)/1000000).toFixed(4)+'</div>';
        h += '</div></div>';
        c.innerHTML = h;
      }
    })
    .catch(function() {
      btn.innerHTML = '&#x274C;'; btn.style.color = '#ef4444';
      setTimeout(function() { btn.innerHTML = '&#x1F52C;'; btn.style.color='#d97706'; btn.disabled=false; }, 5000);
    });
}

function claudeLatest(ip, btn) {
  /* Find first event_id from the recent events table and analyze it */
  var firstBtn = document.querySelector('.act-btn[data-eid]');
  if (firstBtn) {
    claudeEvent(firstBtn.dataset.eid, btn);
  } else {
    btn.innerHTML = '&#x274C; No events';
    btn.style.color = '#ef4444';
    setTimeout(function() { btn.innerHTML = '&#x1F52C; AI DEEP &mdash; Latest'; btn.style.color='#d97706'; btn.disabled=false; }, 3000);
  }
}

function finishHunt(ip, btn) {
  var notes = prompt('Finish Hunt — enter closing notes (optional):');
  if (notes === null) return;  // cancelled
  btn.disabled = true; btn.innerHTML = '&#x23F3; Finishing...';
  fetch('/attacker_hunting/' + encodeURIComponent(ip) + '/finish', {
    method:'POST', credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({notes: notes})
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.status === 'finished') {
      btn.innerHTML = '&#x2705; Finished — reloading...';
      btn.style.color = '#22c55e';
      setTimeout(function() { location.reload(); }, 1500);
    } else {
      btn.innerHTML = '&#x274C; ' + (data.detail || 'Error');
      setTimeout(function() { btn.innerHTML = '&#x2705; Finish Hunt'; btn.style.color='#22c55e'; btn.disabled=false; }, 3000);
    }
  })
  .catch(function() {
    btn.innerHTML = '&#x274C; Error';
    setTimeout(function() { btn.innerHTML = '&#x2705; Finish Hunt'; btn.style.color='#22c55e'; btn.disabled=false; }, 3000);
  });
}

function reopenHunt(ip, btn) {
  if (!confirm('Re-open hunt for ' + ip + '?')) return;
  btn.disabled = true; btn.innerHTML = '&#x23F3; Re-opening...';
  fetch('/attacker_hunting/' + encodeURIComponent(ip) + '/reopen', {
    method:'POST', credentials:'same-origin'
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.status === 'reopened') {
      btn.innerHTML = '&#x1F504; Reopened — reloading...';
      btn.style.color = '#f97316';
      setTimeout(function() { location.reload(); }, 1500);
    } else {
      btn.innerHTML = '&#x274C; ' + (data.detail || 'Error');
      setTimeout(function() { btn.innerHTML = '&#x1F504; Re-open Hunt'; btn.disabled=false; }, 3000);
    }
  })
  .catch(function() {
    btn.innerHTML = '&#x274C; Error';
    setTimeout(function() { btn.innerHTML = '&#x1F504; Re-open Hunt'; btn.disabled=false; }, 3000);
  });
}
</script>
</div></body></html>"""
    return h


def _hunting_history_html(profiles: list) -> str:
    """Hunt History page — shows all FINISHED investigations."""
    _thr_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
        "UNKNOWN": "#64748b",
    }

    h = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Hunt History — HoneyLens</title>"
        "<style>"
        + SHARED_CSS
        + ".threat-badge{display:inline-block;padding:2px 8px;border-radius:6px;font-weight:700;font-size:11px}"
        ".btn{padding:4px 10px;border-radius:4px;border:1px solid var(--border);background:transparent;"
        "color:var(--orange);cursor:pointer;font-family:inherit;font-size:11px}"
        ".btn:hover{filter:brightness(1.3)}"
        "</style></head><body>"
        '<a class="skip-link" href="#main-content">Skip to content</a>'
        + nav_bar_html("hunting")
        + '<div class="page" id="main-content" role="main">'
        + page_header_html(
            "Hunt History",
            eyebrow="Investigate",
            description=str(len(profiles)) + " finished investigations.",
            actions=('<a class="nav-btn" href="/attacker_hunting">&#8592; Active Hunts</a>',),
        )
        + hunt_subnav("history")
    )
    h += (
        '<p style="color:#64748b;margin-bottom:16px;font-size:12px">'
        + str(len(profiles))
        + " finished hunts</p>"
    )

    if not profiles:
        h += '<div class="empty">No finished hunts yet.</div>'
    else:
        h += '<div style="overflow-x:auto"><table>'
        h += "<thead><tr><th>IP</th><th>Threat</th><th>Claude</th><th>Abuse</th>"
        h += "<th>Country</th><th>Org</th><th>Events</th><th>Tags</th>"
        h += "<th>Finished</th><th>Notes</th><th>Actions</th></tr></thead><tbody>"
        for p in profiles:
            ip = html.escape(str(p.get("ip", "")))
            thr = p.get("ai_threat_level") or "UNKNOWN"
            tc = _thr_color.get(thr, "#64748b")
            cv = html.escape(str(p.get("claude_verdict") or ""))
            cvc = _thr_color.get(p.get("claude_verdict"), "#64748b") if cv else "#64748b"
            abuse = p.get("abuse_score")
            country = html.escape(str(p.get("country") or ""))
            org = html.escape(str(p.get("as_org") or "")[:30])
            events = p.get("total_events", 0)
            tags = p.get("internal_tags") or []
            tags_html = " ".join(
                '<span class="tag-pill">' + html.escape(t) + "</span>"
                for t in (tags[:5] if tags else [])
            )
            fin_at = html.escape(str(p.get("finished_at") or "")[:16].replace("T", " "))
            notes = html.escape(str(p.get("finish_notes") or "")[:60])
            abuse_c = (
                "#ef4444"
                if abuse and abuse >= 80
                else "#f97316"
                if abuse and abuse >= 50
                else "#22c55e"
            )

            h += "<tr>"
            h += '<td><a href="/attacker_hunting/' + ip + '">' + ip + "</a></td>"
            h += (
                '<td><span class="threat-badge" style="background:'
                + tc
                + "22;color:"
                + tc
                + '">'
                + thr
                + "</span></td>"
            )
            h += '<td style="color:' + cvc + ';font-weight:700">' + (cv or "\u2014") + "</td>"
            h += (
                '<td style="color:'
                + abuse_c
                + ';font-weight:700">'
                + (str(abuse) if abuse is not None else "\u2014")
                + "</td>"
            )
            h += "<td>" + country + "</td>"
            h += '<td class="dim">' + org + "</td>"
            h += '<td style="text-align:right">' + format(events, ",") + "</td>"
            h += "<td>" + (tags_html or "\u2014") + "</td>"
            h += '<td style="color:#22c55e;white-space:nowrap">' + fin_at + "</td>"
            h += '<td style="color:#94a3b8;font-size:11px">' + notes + "</td>"
            h += '<td style="white-space:nowrap">'
            h += (
                '<button class="btn" onclick="reopenHunt(\''
                + ip
                + "',this)\">&#x1F504; Re-open</button> "
            )
            h += (
                '<button class="btn" style="color:#f59e0b" onclick="rehunt(\''
                + ip
                + "',this)\">&#x1F3AF; Re-hunt</button>"
            )
            h += "</td></tr>"
        h += "</tbody></table></div>"

    js = (
        "\n<script>\n"
        "function reopenHunt(ip, btn) {\n"
        '  if (!confirm("Re-open hunt for " + ip + "?")) return;\n'
        '  btn.disabled = true; btn.textContent = "Re-opening...";\n'
        '  fetch("/attacker_hunting/" + encodeURIComponent(ip) + "/reopen", {method:"POST", credentials:"same-origin"})\n'
        "    .then(function(r) { return r.json(); })\n"
        "    .then(function(d) {\n"
        '      if (d.status === "reopened") { btn.textContent = "Reopened!"; btn.style.color = "#22c55e"; btn.closest("tr").style.opacity = "0.4"; }\n'
        '      else { btn.textContent = "Error"; btn.disabled = false; }\n'
        '    }).catch(function() { btn.textContent = "Error"; btn.disabled = false; });\n'
        "}\n"
        "function rehunt(ip, btn) {\n"
        '  btn.disabled = true; btn.textContent = "Hunting...";\n'
        '  fetch("/attacker_hunting/" + encodeURIComponent(ip) + "/reopen", {method:"POST", credentials:"same-origin"})\n'
        '    .then(function() { return fetch("/attacker_hunting/" + encodeURIComponent(ip) + "/hunt", {method:"POST", credentials:"same-origin"}); })\n'
        "    .then(function(r) { return r.json(); })\n"
        "    .then(function(d) {\n"
        '      if (d.status === "profiled") { btn.textContent = "Done!"; btn.style.color = "#22c55e"; btn.closest("tr").style.opacity = "0.4"; }\n'
        '      else { btn.textContent = "Error"; btn.disabled = false; }\n'
        '    }).catch(function() { btn.textContent = "Error"; btn.disabled = false; });\n'
        "}\n"
        "</script>\n"
        "</div></body></html>"
    )
    h += js
    return h


def _hunting_map_html(status: str = "ACTIVE", rng: str = "24h") -> str:
    """SOC console attacker map — time-aware, panels + synced table (client-fetched)."""

    h = (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<link rel="icon" href="/favicon.ico" type="image/x-icon">'
        "<title>Attacker Map — HoneyLens</title>"
        '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css"/>'
        '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet.markercluster/1.5.3/MarkerCluster.css"/>'
        '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet.markercluster/1.5.3/MarkerCluster.Default.css"/>'
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>'
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet.markercluster/1.5.3/leaflet.markercluster.min.js"></script>'
        "<style>"
        + SHARED_CSS
        + ".top-bar{padding:12px 20px;display:flex;align-items:center;gap:16px;background:var(--bg3);"
        "border-bottom:1px solid var(--border)}"
        ".top-bar h2{color:#f59e0b;font-size:15px;margin:0}"
        ".top-bar a{color:#38bdf8;text-decoration:none;font-size:12px}"
        ".stat{color:#64748b;font-size:12px}"
        ".stat b{color:#e2e8f0}"
        ".filter-bar{display:flex;gap:6px;margin-left:auto}"
        ".fbtn{padding:4px 12px;border-radius:4px;border:1px solid #334155;background:transparent;"
        "color:#94a3b8;cursor:pointer;font-family:inherit;font-size:11px}"
        ".fbtn:hover{border-color:#f59e0b;color:#f59e0b}"
        ".fbtn.active{background:#f59e0b22;border-color:#f59e0b;color:#f59e0b;font-weight:700}"
        ".fbar{display:flex;align-items:center;gap:10px;padding:8px 20px;background:var(--bg3);border-bottom:1px solid var(--border);flex-wrap:wrap;font-size:12px}"
        ".fbar label{color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.5px}"
        ".rbtn{padding:4px 9px;border-radius:4px;border:1px solid #334155;background:transparent;color:#94a3b8;cursor:pointer;font:inherit;font-size:11px}"
        ".rbtn:hover{border-color:#f59e0b;color:#f59e0b}"
        ".rbtn.active{background:#f59e0b22;border-color:#f59e0b;color:#f59e0b;font-weight:700}"
        ".fbar select,.fbar input{background:var(--bg2);border:1px solid #334155;color:#e2e8f0;border-radius:4px;padding:4px 8px;font:inherit;font-size:12px}"
        ".fbar input{width:160px}"
        ".chips{display:flex;gap:6px;flex-wrap:wrap}"
        ".chip{background:#38bdf822;border:1px solid #38bdf8;color:#38bdf8;border-radius:12px;padding:2px 10px;font-size:11px;cursor:pointer}"
        ".chip:hover{background:#38bdf844}"
        ".livetog{display:flex;align-items:center;gap:6px;cursor:pointer;color:#94a3b8;font-size:11px;user-select:none}"
        ".live-dot{width:8px;height:8px;border-radius:50%;background:#22c55e;display:inline-block;animation:pulse 1.4s infinite}"
        ".live-off .live-dot{background:#64748b;animation:none}"
        "@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}"
        ".soc-grid{display:grid;grid-template-columns:1fr 350px;grid-template-rows:minmax(0,1fr) 232px;height:calc(100vh - 150px)}"
        "#map{grid-column:1;grid-row:1;min-height:0}"
        ".soc-rail{grid-column:2;grid-row:1 / span 2;overflow-y:auto;background:var(--bg2);border-left:1px solid var(--border);padding:10px;display:flex;flex-direction:column;gap:10px}"
        ".soc-tablewrap{grid-column:1;grid-row:2;overflow:auto;border-top:1px solid var(--border);background:var(--bg1)}"
        ".panel{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:10px}"
        ".panel h3{margin:0 0 8px;font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:#f59e0b;display:flex;align-items:center;gap:6px}"
        ".kpis{display:grid;grid-template-columns:1fr 1fr;gap:8px}"
        ".kpi{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 10px}"
        ".kpi .n{font-size:19px;font-weight:800;line-height:1.1}"
        ".kpi .l{font-size:9px;text-transform:uppercase;color:#64748b;letter-spacing:.4px;margin-top:2px}"
        ".rowlist .r{padding:3px 0;font-size:12px;cursor:pointer;border-bottom:1px solid rgba(255,255,255,.03)}"
        ".rowlist .r:hover .rk{color:#38bdf8}"
        ".rowlist .rt{display:flex;justify-content:space-between;gap:8px}"
        ".rowlist .rk{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
        ".rowlist .rn{color:#64748b;font-family:monospace;flex-shrink:0}"
        ".rowlist .bar{height:4px;background:#38bdf8;border-radius:3px;margin-top:3px;min-width:2px}"
        ".brk{display:flex;flex-direction:column;gap:4px;font-size:11px}"
        ".brk .b{display:flex;align-items:center;gap:6px}"
        ".brk .bl{width:70px;color:#94a3b8;flex-shrink:0}"
        ".brk .bb{height:9px;border-radius:3px;min-width:2px}"
        ".feed{max-height:230px;overflow-y:auto}"
        ".feed .f{font-size:11px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04);font-family:monospace;cursor:pointer}"
        ".feed .f:hover{color:#e2e8f0}"
        ".feed .ft{color:#64748b}"
        ".soctable{width:100%;border-collapse:collapse;font-size:12px}"
        ".soctable thead th{position:sticky;top:0;background:var(--bg3);color:#94a3b8;text-align:left;padding:6px 8px;font-size:10px;text-transform:uppercase;z-index:2}"
        ".soctable td{padding:5px 8px;border-bottom:1px solid rgba(255,255,255,.04);white-space:nowrap}"
        ".soctable tbody tr{cursor:pointer}"
        ".soctable tbody tr.hl{background:rgba(56,189,248,.14)}"
        ".sev{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;font-weight:700}"
        ".mono{font-family:monospace}"
        ".leaflet-popup-content-wrapper{background:#1e293b!important;color:#e2e8f0!important;"
        "border:1px solid #334155!important;border-radius:8px!important;font-family:monospace!important}"
        ".leaflet-popup-tip{background:#1e293b!important}"
        ".leaflet-popup-content{font-size:12px!important;line-height:1.6!important}"
        ".popup-ip{color:#f472b6;font-weight:700;font-size:13px}"
        ".popup-lbl{color:#64748b;font-size:10px;text-transform:uppercase}"
        ".popup-val{font-weight:700}"
        ".popup-thr{display:inline-block;padding:1px 8px;border-radius:4px;font-size:10px;font-weight:700}"
        ".leaflet-control-attribution{background:rgba(2,6,23,.55)!important;color:#475569!important;font-size:9px!important;padding:0 4px!important}"
        ".leaflet-control-attribution a{color:#64748b!important}"
        "</style></head><body>"
        '<a class="skip-link" href="#main-content">Skip to content</a>'
        + nav_bar_html("hunting")
        + '<div id="main-content" role="main" style="padding:12px 22px 0">'
        + page_header_html("Attacker Map", eyebrow="Investigate")
        + hunt_subnav("map")
        + "</div>"
        '<div class="fbar">'
        '<label>Range</label><div id="rangeBtns" style="display:flex;gap:4px">'
        '<button class="rbtn" data-r="1h">1h</button>'
        '<button class="rbtn" data-r="24h">24h</button>'
        '<button class="rbtn" data-r="7d">7d</button>'
        '<button class="rbtn" data-r="30d">30d</button>'
        '<button class="rbtn" data-r="all">All</button>'
        "</div>"
        '<label>Severity</label><select id="sevSel"><option value="">All</option>'
        '<option value="CRITICAL">Critical</option><option value="HIGH">High</option>'
        '<option value="MEDIUM">Medium</option><option value="LOW">Low</option></select>'
        '<label>Status</label><select id="statSel"><option value="ACTIVE">Active</option>'
        '<option value="ALL">All</option><option value="FINISHED">Finished</option></select>'
        '<input id="searchInp" placeholder="IP / ASN / country / org">'
        '<div class="chips" id="chips"></div>'
        '<div class="livetog" id="liveTog"><span class="live-dot"></span><span id="liveLbl">Live</span></div>'
        '<span class="stat" style="margin-left:auto"><span id="winlbl"></span></span>'
        "</div>"
        '<div class="soc-grid">'
        '<div id="map"></div>'
        '<div class="soc-rail">'
        '<div class="kpis" id="kpis"></div>'
        '<div class="panel"><h3>Top Source Countries</h3><div class="rowlist" id="topCountries"></div></div>'
        '<div class="panel"><h3>Top ASNs / Orgs</h3><div class="rowlist" id="topAsns"></div></div>'
        '<div class="panel"><h3>Severity &amp; Intent</h3><div id="breakdown"></div></div>'
        '<div class="panel"><h3><span class="live-dot"></span> Live Feed</h3><div class="feed" id="feed"></div></div>'
        "</div>"
        '<div class="soc-tablewrap">'
        '<table class="soctable"><thead><tr>'
        "<th>IP</th><th>Threat</th><th>Country</th><th>ASN / Org</th>"
        "<th>Abuse</th><th>Events</th><th>Last seen</th><th>Tags</th>"
        '</tr></thead><tbody id="socbody"></tbody></table>'
        "</div>"
        "</div>"
    )

    # SOC console — client-fetched data, panels, synced table
    h += "<script>"
    h += "var INIT={status:" + _json.dumps(status) + ",range:" + _json.dumps(rng) + "};"
    h += r"""
// Country code -> approximate [lat, lon]
var CC = {
AF:[33,65],AL:[41,20],DZ:[28,3],AO:[-12.5,18.5],AR:[-34,-64],AM:[40,45],AU:[-25,135],
AT:[47.5,13.5],AZ:[40.5,47.5],BS:[24,-76],BH:[26,50.5],BD:[24,90],BY:[53,28],BE:[50.8,4.3],
BZ:[17,-88.8],BJ:[9.5,2.3],BT:[27.5,90.5],BO:[-17,-65],BA:[44,18],BW:[-22,24],BR:[-10,-55],
BN:[4.5,114.7],BG:[43,25],BF:[13,-1.5],BI:[-3.5,30],KH:[13,105],CM:[6,12],CA:[60,-96],
CF:[7,21],TD:[15,19],CL:[-30,-71],CN:[35,105],CO:[4,-72],KM:[-12.2,44.2],CD:[-2.5,23.5],
CG:[-1,15],CR:[10,-84],CI:[8,-5.5],HR:[45.2,15.5],CU:[22,-80],CY:[35,33],CZ:[49.8,15.5],
DK:[56,10],DJ:[11.5,43],DO:[19,-70.7],EC:[-2,-77.5],EG:[27,30],SV:[13.8,-88.9],GQ:[2,10],
ER:[15,39],EE:[59,26],ET:[8,38],FI:[64,26],FR:[46,2],GA:[-1,11.8],GE:[42,43.5],DE:[51,9],
GH:[8,-1.2],GR:[39,22],GT:[15.5,-90.3],GN:[11,-10],HT:[19,-72.3],HN:[15,-86.5],HK:[22.3,114.2],
HU:[47,20],IS:[65,-18],IN:[22,78],ID:[-5,120],IR:[32,53],IQ:[33,44],IE:[53.4,-8],IL:[31.5,34.8],
IT:[42.8,12.8],JM:[18.1,-77.3],JP:[36,138],JO:[31,36],KZ:[48,68],KE:[-1,38],KW:[29.5,45.8],
KG:[41,75],LA:[18,105],LV:[57,25],LB:[33.8,35.8],LY:[26,17],LT:[56,24],LU:[49.8,6.1],
MG:[-20,47],MW:[-13.5,34],MY:[2.5,112.5],ML:[17,-4],MX:[23,-102],MD:[47,28.8],MN:[46,105],
ME:[42.5,19.3],MA:[32,-5],MZ:[-18.3,35],MM:[22,98],NA:[-22,17],NP:[28,84],NL:[52.5,5.8],
NZ:[-42,174],NI:[13,-85],NE:[16,8],NG:[10,8],NO:[62,10],OM:[21,57],PK:[30,70],PA:[9,-80],
PG:[-6,147],PY:[-23,-58],PE:[-10,-76],PH:[13,122],PL:[52,20],PT:[39.5,-8],QA:[25.5,51.3],
RO:[46,25],RU:[60,100],RW:[-2,29.9],SA:[24,45],SN:[14,-14.5],RS:[44,21],SG:[1.35,103.8],
SK:[48.7,19.7],SI:[46.1,14.8],SO:[6,48],ZA:[-29,24],KR:[37,127.5],ES:[40,-4],LK:[7.5,80.8],
SD:[15,30],SE:[62,15],CH:[47,8.2],SY:[35,38],TW:[23.5,121],TJ:[39,71],TZ:[-6,35],TH:[15,100],
TG:[8,1.2],TT:[10.5,-61.3],TN:[34,9],TR:[39,35],TM:[40,60],UG:[1,32],UA:[49,32],
AE:[24,54],GB:[54,-2],US:[39,-98],UY:[-33,-56],UZ:[41.5,64.6],VE:[8,-66],VN:[16,108],
YE:[15.5,48],ZM:[-15,28],ZW:[-20,30],SC:[-4.7,55.5],CW:[12.2,-69]
};

var thrColor={CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#22c55e',UNKNOWN:'#64748b',INFO:'#64748b'};
function sc(s){return thrColor[s]||'#64748b';}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function num(n){return (n||0).toLocaleString();}
var state={range:INIT.range||'24h',severity:'',status:INIT.status||'ACTIVE',country:'',asn:'',q:''};
var liveOn=true,lastTs=null,rowByIp={},markerByIp={};

var map=L.map('map',{zoomControl:true,attributionControl:true}).setView([25,15],2);
// Esri "World Dark Gray Canvas" base — keyless (no account/token), dark SOC look.
// Esri tiles use {z}/{y}/{x} order and cap at native zoom 16 (overzoomed to 18).
L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',{maxNativeZoom:16,maxZoom:18,attribution:'&copy; Esri, HERE, Garmin, &copy; OpenStreetMap contributors'}).addTo(map);
var cluster=L.markerClusterGroup({showCoverageOnHover:false,maxClusterRadius:44,spiderfyOnMaxZoom:true});
map.addLayer(cluster);

function qs(){var p=new URLSearchParams();p.set('range',state.range);if(state.severity)p.set('severity',state.severity);if(state.status)p.set('status',state.status);if(state.country)p.set('country',state.country);if(state.asn)p.set('asn',state.asn);if(state.q)p.set('q',state.q);return p.toString();}

function load(){
  fetch('/attacker_hunting/map/data?'+qs()).then(function(r){return r.json();}).then(function(d){
    if(d.error){document.getElementById('winlbl').textContent=d.error;return;}
    renderKpis(d.kpis||{});renderMap(d.attackers||[]);renderTable(d.attackers||[]);
    renderList('topCountries',d.top_countries||[],'country');
    renderList('topAsns',d.top_asns||[],'asn');
    renderBreak(d.severity||[],d.intents||[]);renderChips();
    document.getElementById('winlbl').textContent=d.window||'';
  }).catch(function(){document.getElementById('winlbl').textContent='load error';});
}
function renderKpis(k){
  function t(n,l,c){return '<div class="kpi"><div class="n" style="color:'+(c||'#e2e8f0')+'">'+n+'</div><div class="l">'+l+'</div></div>';}
  document.getElementById('kpis').innerHTML=t(num(k.attackers),'Attackers','#38bdf8')+t(num(k.countries),'Countries','#a78bfa')+t(num(k.crit_high),'Crit + High','#ef4444')+t(num(k.events),'Events','#f59e0b');
}
function pos(a){var lat=a.lat,lon=a.lon;if(lat==null||lon==null){var c=CC[(a.country||'').toUpperCase().substring(0,2)];if(!c)return null;lat=c[0]+(Math.random()-0.5)*3;lon=c[1]+(Math.random()-0.5)*3;}return [lat,lon];}
function renderMap(list){
  cluster.clearLayers();markerByIp={};
  list.forEach(function(a){var p=pos(a);if(!p)return;var thr=a.ai_threat_level||'UNKNOWN',color=sc(thr),ab=a.abuse_score||0;
    var m=L.circleMarker(p,{radius:Math.max(5,Math.min(16,(ab||30)/8)),fillColor:color,color:color,weight:1,opacity:0.9,fillOpacity:0.6});
    m.bindPopup(popup(a,color,thr));m.on('click',function(){hl(a.ip);});markerByIp[a.ip]=m;cluster.addLayer(m);});
}
function popup(a,color,thr){var tags=(a.tags||[]).slice(0,3).join(', ')||'-';
  return '<div style="min-width:200px"><div class="popup-ip"><a href="/attacker_hunting/'+a.ip+'" style="color:#f472b6">'+a.ip+'</a></div>'+
  '<div style="margin:4px 0"><span class="popup-thr" style="background:'+color+'22;color:'+color+'">'+thr+'</span></div>'+
  '<div><span class="popup-lbl">Country</span> '+esc(a.country||'?')+(a.city?' / '+esc(a.city):'')+'</div>'+
  '<div><span class="popup-lbl">Org</span> '+esc((a.as_org||'-').substring(0,40))+'</div>'+
  '<div><span class="popup-lbl">Abuse</span> <span class="popup-val" style="color:'+(a.abuse_score>=80?'#ef4444':a.abuse_score>=50?'#f97316':'#22c55e')+'">'+(a.abuse_score||0)+'/100</span></div>'+
  '<div><span class="popup-lbl">Events (win)</span> '+num(a.events)+'</div>'+
  '<div><span class="popup-lbl">Tags</span> '+esc(tags)+'</div></div>';
}
function badge(thr){var c=sc(thr);return '<span class="sev" style="background:'+c+'22;color:'+c+'">'+thr+'</span>';}
function renderTable(list){
  var b=document.getElementById('socbody');rowByIp={};
  b.innerHTML=list.map(function(a){var thr=a.ai_threat_level||'UNKNOWN';var org=((a.asn?('AS'+a.asn+' '):'')+(a.as_org||'')).substring(0,34);
    return '<tr data-ip="'+a.ip+'"><td class="mono"><a href="/attacker_hunting/'+a.ip+'" style="color:#f472b6">'+a.ip+'</a></td>'+
    '<td>'+badge(thr)+'</td><td>'+esc(a.country||'-')+(a.city?' / '+esc(a.city):'')+'</td>'+
    '<td>'+esc(org||'-')+'</td>'+
    '<td style="color:'+(a.abuse_score>=80?'#ef4444':a.abuse_score>=50?'#f97316':'#22c55e')+'">'+(a.abuse_score||0)+'</td>'+
    '<td>'+num(a.events)+'</td><td class="mono" style="color:#94a3b8">'+esc((a.last_seen||'').replace('T',' ').substring(0,16))+'</td>'+
    '<td style="color:#64748b">'+esc((a.tags||[]).slice(0,3).join(', ')||'-')+'</td></tr>';
  }).join('');
  Array.prototype.forEach.call(b.querySelectorAll('tr'),function(tr){rowByIp[tr.dataset.ip]=tr;tr.addEventListener('click',function(e){if(e.target.tagName==='A')return;focusIp(tr.dataset.ip);});});
}
function renderList(id,items,key){
  var el=document.getElementById(id);var max=Math.max.apply(null,items.map(function(i){return i.count;}).concat([1]));
  el.innerHTML=items.map(function(i){var label=key==='asn'?(((i.asn?('AS'+i.asn+' '):'')+(i.org||'')).substring(0,26)):(i.country||'??');var val=key==='asn'?(i.asn||''):(i.country||'');
    return '<div class="r" data-k="'+key+'" data-v="'+esc(val)+'"><div class="rt"><span class="rk">'+esc(label||'??')+'</span><span class="rn">'+num(i.count)+'</span></div><div class="bar" style="width:'+Math.round(i.count/max*100)+'%"></div></div>';
  }).join('')||'<div style="color:#64748b;font-size:11px">no data</div>';
  Array.prototype.forEach.call(el.querySelectorAll('.r'),function(r){r.addEventListener('click',function(){var v=r.dataset.v;if(!v)return;state[r.dataset.k]=v;load();});});
}
function renderBreak(sev,intents){
  var tot=sev.reduce(function(s,x){return s+x.count;},0)||1;var order=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'];var m={};sev.forEach(function(x){m[x.level]=x.count;});
  var html='<div class="brk">'+order.map(function(l){var c=m[l]||0;if(!c&&l==='UNKNOWN')return '';return '<div class="b"><span class="bl">'+l+'</span><span class="bb" style="width:'+Math.round(c/tot*150)+'px;background:'+sc(l)+'"></span><span style="color:#64748b">'+c+'</span></div>';}).join('')+'</div>';
  if(intents&&intents.length){html+='<div style="margin-top:8px;color:#64748b;font-size:9px;text-transform:uppercase">Top intents</div><div class="brk" style="margin-top:3px">'+intents.slice(0,4).map(function(x){return '<div class="b"><span class="bl" style="width:auto;color:#c4b5fd">'+esc(x.intent||'?')+'</span><span style="color:#64748b">'+x.count+'</span></div>';}).join('')+'</div>';}
  document.getElementById('breakdown').innerHTML=html;
}
function renderChips(){
  var c=document.getElementById('chips');var out='';
  if(state.country)out+='<span class="chip" data-k="country">country: '+esc(state.country)+' x</span>';
  if(state.asn)out+='<span class="chip" data-k="asn">AS'+esc(state.asn)+' x</span>';
  if(state.q)out+='<span class="chip" data-k="q">"'+esc(state.q)+'" x</span>';
  c.innerHTML=out;
  Array.prototype.forEach.call(c.querySelectorAll('.chip'),function(ch){ch.addEventListener('click',function(){state[ch.dataset.k]='';if(ch.dataset.k==='q')document.getElementById('searchInp').value='';load();});});
}
function hl(ip){Object.keys(rowByIp).forEach(function(k){rowByIp[k].classList.remove('hl');});var tr=rowByIp[ip];if(tr){tr.classList.add('hl');tr.scrollIntoView({block:'nearest'});}}
function focusIp(ip){var m=markerByIp[ip];if(m){map.setView(m.getLatLng(),5);if(cluster.zoomToShowLayer){cluster.zoomToShowLayer(m,function(){m.openPopup();});}else{m.openPopup();}}hl(ip);}

function pollFeed(){
  if(!liveOn)return;
  fetch('/attacker_hunting/map/feed?'+qs()+(lastTs?('&since='+encodeURIComponent(lastTs)):'')).then(function(r){return r.json();}).then(function(d){
    var items=d.feed||[];if(!items.length)return;lastTs=items[0].ts;var box=document.getElementById('feed');
    var html=items.map(function(i){var c=sc(i.threat||'UNKNOWN');return '<div class="f" data-ip="'+i.ip+'"><span class="ft">'+esc((i.ts||'').substring(11,19))+'</span> <span style="color:'+c+'">&#x25cf;</span> <a href="/attacker_hunting/'+i.ip+'" style="color:#f472b6">'+i.ip+'</a> <span style="color:#94a3b8">'+esc(i.country||'??')+'</span> :'+(i.dst_port||'')+'</div>';}).join('');
    box.innerHTML=html+box.innerHTML;var kids=box.querySelectorAll('.f');for(var j=60;j<kids.length;j++)kids[j].remove();
    Array.prototype.forEach.call(box.querySelectorAll('.f'),function(f){f.onclick=function(e){if(e.target.tagName==='A')return;focusIp(f.dataset.ip);};});
  }).catch(function(){});
}

document.getElementById('rangeBtns').addEventListener('click',function(e){var b=e.target.closest('.rbtn');if(!b)return;state.range=b.dataset.r;setRange();lastTs=null;document.getElementById('feed').innerHTML='';load();pollFeed();});
function setRange(){Array.prototype.forEach.call(document.querySelectorAll('#rangeBtns .rbtn'),function(b){b.classList.toggle('active',b.dataset.r===state.range);});}
document.getElementById('sevSel').addEventListener('change',function(){state.severity=this.value;load();});
document.getElementById('statSel').addEventListener('change',function(){state.status=this.value;load();});
var stmr;document.getElementById('searchInp').addEventListener('input',function(){var v=this.value.trim();clearTimeout(stmr);stmr=setTimeout(function(){state.q=v;load();},400);});
document.getElementById('liveTog').addEventListener('click',function(){liveOn=!liveOn;this.classList.toggle('live-off',!liveOn);document.getElementById('liveLbl').textContent=liveOn?'Live':'Paused';});

document.getElementById('statSel').value=state.status;setRange();load();pollFeed();setInterval(pollFeed,15000);
"""
    h += """</script>
<script>
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
      if(/^\\d{4}-\\d{2}-\\d{2}/.test(av)&&/^\\d{4}-\\d{2}-\\d{2}/.test(bv)){var da=new Date(av),db=new Date(bv);if(!isNaN(da)&&!isNaN(db))return asc?da-db:db-da;}
      var an=parseFloat(av.replace(/,/g,"")),bn=parseFloat(bv.replace(/,/g,""));
      if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;
      if(/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/.test(av)){var ap=av.split(".").map(Number),bp=bv.split(".").map(Number);for(var i=0;i<4;i++){var d=(ap[i]||0)-(bp[i]||0);if(d)return asc?d:-d;}return 0;}
      var sv={CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,INFO:0};if(sv[av]!==undefined&&sv[bv]!==undefined)return asc?sv[av]-sv[bv]:sv[bv]-sv[av];
      return asc?av.localeCompare(bv):bv.localeCompare(av);
    });
    rows.forEach(function(r){tbody.appendChild(r);});
  }
  document.addEventListener("click",function(e){var th=e.target.closest("th");if(th&&th.closest("table"))doSort(th);});
})();
</script>
<style>th{cursor:pointer;user-select:none;position:relative;white-space:nowrap;transition:background .15s;}th:hover{background:rgba(34,211,238,0.08)!important;}th.sorted-asc::after{content:" \\25B2";font-size:10px;color:#22d3ee;}th.sorted-desc::after{content:" \\25BC";font-size:10px;color:#22d3ee;}tbody tr:hover,table tr:hover{background:rgba(34,211,238,0.04)!important;}</style>
</body></html>"""
    return h


def _clusters_html(data: dict) -> str:
    """Fingerprint Clusters page."""
    clusters = data.get("clusters", [])
    total = data.get("total", 0)
    _thr = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}

    h = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Fingerprint Clusters — HoneyLens</title>"
        "<style>"
        + SHARED_CSS
        + ".tag{display:inline-block;padding:2px 8px;border-radius:6px;font-size:10px;margin:1px}"
        ".conf-bar{height:6px;border-radius:3px;background:var(--bg4);width:80px;display:inline-block}"
        ".conf-fill{height:6px;border-radius:3px;display:inline-block}"
        ".ip-pill{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;"
        "background:var(--bg3);border:1px solid var(--border);margin:1px;color:var(--pink)}"
        ".run-btn{padding:6px 14px;border-radius:6px;border:1px solid var(--hunt);background:#f59e0b22;"
        "color:var(--hunt);cursor:pointer;font-family:inherit;font-weight:700;font-size:12px}"
        ".run-btn:hover{filter:brightness(1.2)}"
        "</style></head><body>"
        '<a class="skip-link" href="#main-content">Skip to content</a>'
        + nav_bar_html("hunting")
        + '<div class="page" id="main-content" role="main">'
        + page_header_html(
            "Fingerprint Clusters",
            eyebrow="Investigate",
            description=str(total) + " clusters detected.",
            actions=(
                '<button class="run-btn" onclick="runCorr(this)">&#x26A1; Run Correlation</button>',
                '<a class="nav-btn" href="/attacker_hunting">&#8592; Hunting</a>',
            ),
        )
        + hunt_subnav("clusters")
    )
    h += (
        '<p style="color:#64748b;margin-bottom:16px;font-size:12px">'
        + str(total)
        + " clusters detected</p>"
    )

    if not clusters:
        h += (
            '<div class="empty">No clusters detected yet. Run backfill_fingerprints.py '
            "then correlation_engine.py to detect clusters.</div>"
        )
    else:
        h += '<div style="overflow-x:auto"><table>'
        h += "<thead><tr><th>Cluster Tag</th><th>Type</th><th>Fingerprint</th>"
        h += "<th>IPs</th><th>Confidence</th><th>Members</th><th>Seen</th></tr></thead><tbody>"
        for c in clusters:
            tag = html.escape(str(c.get("tag", "")))
            fp_type = html.escape(str(c.get("type", "")))
            fp_val = html.escape(str(c.get("value", ""))[:60])
            ip_count = c.get("ip_count", 0)
            conf = c.get("confidence", 0)
            conf_pct = int(conf * 100)
            conf_color = (
                "#ef4444"
                if conf >= 0.9
                else "#f97316"
                if conf >= 0.7
                else "#eab308"
                if conf >= 0.5
                else "#64748b"
            )
            is_botnet = tag.startswith("BOTNET_")
            tag_bg = "#ef444422" if is_botnet else "#f59e0b22"
            tag_color = "#ef4444" if is_botnet else "#f59e0b"

            ips_html = ""
            for ip in (c.get("ips") or [])[:8]:
                eip = html.escape(str(ip))
                ips_html += (
                    '<a class="ip-pill smart-ip" data-ip="'
                    + eip
                    + '" href="#" onclick="smartNav(\''
                    + eip
                    + "');return false\">"
                    + eip
                    + "</a> "
                )
            if ip_count > 8:
                ips_html += (
                    '<span style="color:#64748b;font-size:10px">+'
                    + str(ip_count - 8)
                    + " more</span>"
                )

            last_seen = html.escape(str(c.get("last_seen") or "")[:16].replace("T", " "))

            h += "<tr>"
            h += (
                '<td><span class="tag" style="background:'
                + tag_bg
                + ";color:"
                + tag_color
                + ';font-weight:700">'
                + tag
                + "</span></td>"
            )
            h += '<td style="color:#94a3b8">' + fp_type + "</td>"
            h += (
                '<td style="font-size:11px;color:#a78bfa;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'
                + html.escape(str(c.get("value", "")))
                + '">'
                + fp_val
                + "</td>"
            )
            h += '<td style="text-align:center;font-weight:700">' + str(ip_count) + "</td>"
            h += (
                '<td><span class="conf-bar"><span class="conf-fill" style="width:'
                + str(conf_pct)
                + "%;background:"
                + conf_color
                + '"></span></span> <span style="color:'
                + conf_color
                + ';font-size:10px">'
                + str(conf_pct)
                + "%</span></td>"
            )
            h += "<td>" + ips_html + "</td>"
            h += '<td style="color:#64748b;white-space:nowrap">' + last_seen + "</td>"
            h += "</tr>"
        h += "</tbody></table></div>"

    h += """
<script>
function runCorr(btn) {
  btn.disabled = true; btn.textContent = 'Running...';
  fetch('/correlation/run', {method:'POST', credentials:'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (d.status === 'completed') {
        btn.textContent = 'Done! ' + (d.clusters_detected||0) + ' clusters — reloading...';
        btn.style.color = '#22c55e';
        setTimeout(function() { location.reload(); }, 2000);
      } else {
        btn.textContent = d.error || d.status || 'Error';
        setTimeout(function() { btn.textContent = '\\u26A1 Run Correlation'; btn.disabled = false; }, 3000);
      }
    }).catch(function() {
      btn.textContent = 'Error';
      setTimeout(function() { btn.textContent = '\\u26A1 Run Correlation'; btn.disabled = false; }, 3000);
    });
}
function smartNav(ip) {
  fetch('/ip/status/' + encodeURIComponent(ip), {credentials:'same-origin'})
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (d.hunted) {
        window.location.href = '/attacker_hunting/' + encodeURIComponent(ip);
      } else {
        window.location.href = '/events_ip/' + encodeURIComponent(ip) + '?format=html&limit=10';
      }
    }).catch(function() {
      window.location.href = '/events_ip/' + encodeURIComponent(ip) + '?format=html&limit=10';
    });
}
</script>
</div></body></html>"""
    return h
