"""
webui/dashboard_ja4.py — JA3/JA4+ Fingerprint Dashboards
==========================================================
Rich dashboard pages for /ja3_stats, /ja4_stats, /ja4/detected.
ICS/OT dark theme with KPIs, panels, clickable fingerprints/apps.
Compatible with Python 3.9+.
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

from honeylens.webui.shared import SHARED_CSS, nav_bar_html, page_header_html, sortable_table_js

if TYPE_CHECKING:
    from fastapi import FastAPI


def register_routes(app: FastAPI) -> None:
    pass


def e(v):
    return html.escape(str(v).replace("\r", "").replace("\n", " ")) if v is not None else ""


_CSS = (
    SHARED_CSS
    + r"""
/* JA4-specific styles */
tr.clickable{cursor:pointer}
.scroll-table{max-height:600px;overflow-y:auto}
.fp{color:var(--purple);font-family:var(--mono);font-size:10px;word-break:break-all}
.threat{color:var(--red);font-weight:700}
.app-name{color:var(--orange);font-weight:600}
.sec-title{font-size:16px;font-weight:800;color:var(--text);margin:20px 0 12px;display:flex;align-items:center;gap:8px}
.tls-badge{display:inline-block;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:700}
.tls13{background:#22c55e20;color:#22c55e;border:1px solid #22c55e44}
.tls12{background:#eab30820;color:#eab308;border:1px solid #eab30844}
.tls-old{background:#ef444420;color:#ef4444;border:1px solid #ef444444}
.alert-card{background:#ef444410;border:1px solid #ef444444;border-radius:6px;padding:10px 14px;margin-bottom:8px}
.verified-badge{color:var(--green);font-weight:700;font-size:10px}
"""
)

_THREAT_KW = [
    "cobalt",
    "strike",
    "metasploit",
    "empire",
    "sliver",
    "havoc",
    "brute",
    "scan",
    "nmap",
    "masscan",
    "zmap",
    "sqlmap",
    "nikto",
]

_EXTRA_CSS = """
.act-btn{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9px;
  font-weight:700;cursor:pointer;border:1px solid;background:transparent;
  font-family:inherit;transition:all .15s;margin:0 2px;vertical-align:middle}
.act-btn:hover{filter:brightness(1.3)}
.act-ai{color:#a78bfa;border-color:#a78bfa44}
.act-hunt{color:#f59e0b;border-color:#f59e0b44}
.drw-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:200;display:none}
.drw-overlay.on{display:block}
.drw{position:fixed;top:0;right:-500px;width:480px;max-width:90vw;height:100vh;
  background:var(--bg2);border-left:2px solid var(--border);z-index:201;
  transition:right .25s ease;overflow-y:auto}
.drw.on{right:0}
.drw-hdr{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;
  align-items:center;justify-content:space-between;position:sticky;top:0;
  background:var(--bg2);z-index:1}
.drw-hdr h3{font-size:14px;color:var(--accent);font-weight:700}
.drw-close{background:none;border:none;color:var(--text3);font-size:20px;cursor:pointer}
.drw-body{padding:14px 18px}
.dsec{margin-bottom:14px}
.dhdr{font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;
  letter-spacing:.5px;padding-bottom:6px;border-bottom:1px solid var(--border);margin-bottom:8px}
.drow{display:flex;gap:10px;padding:4px 0;font-size:12px;border-bottom:1px solid #ffffff06}
.dlbl{width:110px;flex-shrink:0;color:var(--text3);font-size:10px;text-transform:uppercase}
.dval{flex:1;word-break:break-word}
.drw-actions{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.drw-act{padding:4px 10px;border-radius:4px;font-size:10px;font-weight:600;
  border:1px solid var(--border);color:var(--text2);text-decoration:none;cursor:pointer;
  background:var(--bg3);font-family:inherit;transition:all .15s}
.drw-act:hover{background:var(--bg4);color:var(--text)}
"""


def _is_threat(name):
    n = (name or "").lower()
    return any(kw in n for kw in _THREAT_KW)


def _tls_badge(tls_str):
    t = str(tls_str or "")
    if "1.3" in t:
        return '<span class="tls-badge tls13">TLS 1.3</span>'
    elif "1.2" in t:
        return '<span class="tls-badge tls12">TLS 1.2</span>'
    elif t and t != "Unknown":
        return '<span class="tls-badge tls-old">' + e(t) + "</span>"
    return '<span class="dim">&mdash;</span>'


def _drawer_html():
    return (
        '<div class="drw-overlay" id="ov" onclick="closeDrawer()"></div>'
        '<div class="drw" id="drw">'
        '<div class="drw-hdr"><h3 id="drwTitle">Event Detail</h3>'
        '<button class="drw-close" onclick="closeDrawer()">&times;</button></div>'
        '<div class="drw-body" id="drwBody"></div></div>'
    )


def _actions_js():
    """JS for AI Analyze, Hunt IP, and drawer management."""
    return r"""<script>
function esc2(v){return v==null?'':String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function openDrawer(){document.getElementById('drw').classList.add('on');document.getElementById('ov').classList.add('on');}
function closeDrawer(){document.getElementById('drw').classList.remove('on');document.getElementById('ov').classList.remove('on');}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeDrawer();});

function loadEventDrawer(eventId){
  document.getElementById('drwTitle').textContent='Loading '+eventId.substring(0,12)+'...';
  document.getElementById('drwBody').innerHTML='<div style="color:var(--text3);text-align:center;padding:40px">Loading...</div>';
  openDrawer();
  fetch('/event_full/'+encodeURIComponent(eventId),{credentials:'same-origin'})
    .then(function(r){return r.json();})
    .then(function(ev){
      var h='';
      h+='<div class="drw-actions">';
      h+='<a href="/event_full/'+esc2(ev.event_id)+'" target="_blank" class="drw-act">&#x1F4CB; Event Details</a>';
      if(ev.payload)h+='<a href="/payload/'+esc2(ev.event_id)+'" target="_blank" class="drw-act">&#x1F4C4; Payload</a>';
      h+='<a href="/pcap/'+esc2(ev.event_id)+'" target="_blank" class="drw-act">&#x1F4E6; PCAP</a>';
      h+='<button class="drw-act" onclick="aiAnalyze(\''+esc2(ev.event_id)+'\',this)">&#x1F9E0; AI Analyze</button>';
      if(window._claudeAvailable)h+='<button class="drw-act" onclick="claudeAnalyze(\''+esc2(ev.event_id)+'\',this)">&#x1F52C; AI DEEP</button>';
      var srcIp=(ev.src_ip||'').split('/')[0];
      if(srcIp)h+='<button class="drw-act" onclick="huntIP(\''+esc2(srcIp)+'\',this)">&#x1F3AF; Hunt IP</button>';
      h+='</div>';

      h+='<div class="dsec"><div class="dhdr">Overview</div>';
      h+='<div class="drow"><div class="dlbl">Event ID</div><div class="dval" style="font-size:9px;word-break:break-all">'+esc2(ev.event_id)+'</div></div>';
      h+='<div class="drow"><div class="dlbl">Time</div><div class="dval">'+esc2((ev.timestamp||'').replace('T',' ').substring(0,19))+'</div></div>';
      h+='<div class="drow"><div class="dlbl">Protocol</div><div class="dval" style="color:var(--accent);font-weight:700">'+esc2((ev.protocol||'').toUpperCase())+'</div></div>';
      h+='<div class="drow"><div class="dlbl">Source</div><div class="dval"><a href="/events_ip/'+esc2(srcIp)+'?format=html" style="color:#f472b6;text-decoration:none">'+esc2(srcIp)+'</a>'+(ev.src_port?' <span style="color:#fbbf24">:'+ev.src_port+'</span>':'')+'</div></div>';
      h+='<div class="drow"><div class="dlbl">Destination</div><div class="dval">'+esc2((ev.dst_ip||'').split('/')[0])+(ev.dst_port?' <span style="color:#fbbf24">:'+ev.dst_port+'</span>':'')+'</div></div>';
      if(ev.attack_types)h+='<div class="drow"><div class="dlbl">Attacks</div><div class="dval" style="color:var(--red)">'+esc2(ev.attack_types)+'</div></div>';
      if(ev.ja3)h+='<div class="drow"><div class="dlbl">JA3</div><div class="dval" style="font-size:9px;color:var(--purple)">'+esc2(ev.ja3)+'</div></div>';
      if(ev.scan_score!=null)h+='<div class="drow"><div class="dlbl">Scan Score</div><div class="dval">'+ev.scan_score+'</div></div>';
      h+='</div>';

      if(ev.payload){
        var pl=ev.payload;
        if(pl.length>500)pl=pl.substring(0,500)+'...';
        h+='<div class="dsec"><div class="dhdr">Payload</div><pre style="font-size:10px;color:var(--text2);max-height:200px;overflow:auto;word-break:break-all;white-space:pre-wrap">'+esc2(pl)+'</pre></div>';
      }
      document.getElementById('drwTitle').textContent=(ev.protocol||'').toUpperCase()+' — '+ev.event_id.substring(0,16)+'...';
      document.getElementById('drwBody').innerHTML=h;
    })
    .catch(function(err){
      document.getElementById('drwBody').innerHTML='<div style="color:var(--red);padding:20px">Error: '+esc2(err.message)+'</div>';
    });
}

function aiAnalyze(eventId,btn){
  btn.disabled=true;btn.innerHTML='&#x23F3; Analysing...';btn.style.color='#eab308';
  fetch('/ai/analyze/'+encodeURIComponent(eventId),{method:'POST',credentials:'same-origin'})
    .then(function(r){return r.json();})
    .then(function(data){
      if(data.detail){btn.innerHTML='&#x274C; '+data.detail.substring(0,40);btn.style.color='#ef4444';
        setTimeout(function(){btn.innerHTML='&#x1F9E0; AI';btn.style.color='#a78bfa';btn.disabled=false;},4000);return;}
      var cls=data.triage_class||'?';
      var cc={'CRITICAL':'#ef4444','SUSPICIOUS':'#f97316','KNOWN':'#38bdf8','NOISE':'#64748b'}[cls]||'#94a3b8';
      btn.innerHTML='&#x1F9E0; '+cls;btn.style.color=cc;btn.disabled=false;
      var drw=document.getElementById('drwBody');
      if(drw){
        var existing=document.getElementById('ai-result');if(existing)existing.remove();
        var sec=document.createElement('div');sec.id='ai-result';sec.className='dsec';
        var h='<div class="dhdr" style="color:#a78bfa">&#x1F9E0; AI Analysis</div>';
        h+='<div class="drow"><div class="dlbl">Class</div><div class="dval" style="color:'+cc+';font-weight:700">'+cls+'</div></div>';
        h+='<div class="drow"><div class="dlbl">Confidence</div><div class="dval">'+(data.confidence||0)+'%</div></div>';
        h+='<div class="drow"><div class="dlbl">Novelty</div><div class="dval">'+(data.novelty_score||0)+'/10</div></div>';
        if(data.reasoning)h+='<div class="drow"><div class="dlbl">Reasoning</div><div class="dval" style="font-size:10px">'+esc2(data.reasoning)+'</div></div>';
        if(data.known_cve)h+='<div class="drow"><div class="dlbl">CVE</div><div class="dval" style="color:#f87171">'+esc2(data.known_cve)+'</div></div>';
        sec.innerHTML=h;drw.insertBefore(sec,drw.children[1]||null);
      }
    })
    .catch(function(){btn.innerHTML='&#x274C; Error';btn.style.color='#ef4444';
      setTimeout(function(){btn.innerHTML='&#x1F9E0; AI';btn.style.color='#a78bfa';btn.disabled=false;},4000);});
}

function huntIP(ip,btn){
  btn.disabled=true;btn.innerHTML='&#x23F3; Hunting...';btn.style.color='#eab308';
  fetch('/attacker_hunting/'+encodeURIComponent(ip)+'/hunt',{method:'POST',credentials:'same-origin'})
    .then(function(r){return r.json();})
    .then(function(data){
      if(data.detail){btn.innerHTML='&#x274C; '+(data.detail||'').substring(0,40);btn.style.color='#ef4444';
        setTimeout(function(){btn.innerHTML='&#x1F3AF; Hunt';btn.style.color='#f59e0b';btn.disabled=false;},4000);return;}
      var thr=(data.ai_summary&&data.ai_summary.threat_level)?data.ai_summary.threat_level:(data.threat_level||'DONE');
      var tc={'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e'}[thr]||'#22c55e';
      btn.innerHTML='&#x1F3AF; '+thr;btn.style.color=tc;btn.disabled=false;
      var drw=document.getElementById('drwBody');
      if(drw){
        var existing=document.getElementById('hunt-result');if(existing)existing.remove();
        var sec=document.createElement('div');sec.id='hunt-result';sec.className='dsec';
        var h='<div class="dhdr" style="color:#f59e0b">&#x1F3AF; Hunt Result</div>';
        h+='<div class="drow"><div class="dlbl">Threat</div><div class="dval" style="color:'+tc+';font-weight:700">'+esc2(thr)+'</div></div>';
        if(data.abuse_score!=null)h+='<div class="drow"><div class="dlbl">Abuse Score</div><div class="dval">'+data.abuse_score+'</div></div>';
        if(data.country)h+='<div class="drow"><div class="dlbl">Country</div><div class="dval">'+esc2(data.country)+'</div></div>';
        if(data.asn_org)h+='<div class="drow"><div class="dlbl">ASN</div><div class="dval" style="font-size:10px">'+esc2(data.asn_org)+'</div></div>';
        if(data.internal_tags&&data.internal_tags.length)h+='<div class="drow"><div class="dlbl">Tags</div><div class="dval" style="color:#f59e0b">'+data.internal_tags.map(esc2).join(', ')+'</div></div>';
        h+='<div class="drow"><div class="dlbl">Profile</div><div class="dval"><a href="/attacker_hunting/'+encodeURIComponent(ip)+'" style="color:#f59e0b" target="_blank">Full Profile &rarr;</a></div></div>';
        sec.innerHTML=h;drw.insertBefore(sec,drw.children[2]||null);
      }
    })
    .catch(function(){btn.innerHTML='&#x274C; Error';btn.style.color='#ef4444';
      setTimeout(function(){btn.innerHTML='&#x1F3AF; Hunt';btn.style.color='#f59e0b';btn.disabled=false;},4000);});
}

/* AI Deep Analysis (any configured backend) */
window._claudeAvailable=false;
fetch('/ai/deep-status',{credentials:'same-origin'})
  .then(function(r){return r.json();})
  .then(function(d){window._claudeAvailable=d.available===true;})
  .catch(function(){window._claudeAvailable=false;});

function claudeAnalyze(eventId,btn){
  btn.disabled=true;btn.innerHTML='&#x23F3; Claude...';btn.style.color='#eab308';
  fetch('/ai/deep-analyze/'+encodeURIComponent(eventId),{method:'POST',credentials:'same-origin'})
    .then(function(r){return r.json();})
    .then(function(data){
      if(data.detail||data.error){
        btn.innerHTML='&#x274C; '+(data.detail||data.error||'').substring(0,35);btn.style.color='#ef4444';
        setTimeout(function(){btn.innerHTML='&#x1F52C; AI DEEP';btn.style.color='#d97706';btn.disabled=false;},5000);return;
      }
      var v=data.verdict||'?';
      var vc={'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e','INFO':'#38bdf8'}[v]||'#94a3b8';
      btn.innerHTML='&#x1F52C; '+v;btn.style.color=vc;btn.disabled=false;
      var body=document.getElementById('drwBody');
      if(body){
        var ex=document.getElementById('claude-ja4-result');if(ex)ex.remove();
        var sec=document.createElement('div');sec.id='claude-ja4-result';sec.className='dsec';
        var h='<div class="dhdr" style="color:#d97706">&#x1F52C; Claude Analysis</div>';
        h+='<div class="drow"><div class="dlbl">Verdict</div><div class="dval" style="color:'+vc+';font-weight:700">'+esc2(v)+' ('+esc2(data.confidence||'?')+'%)</div></div>';
        if(data.attack_type)h+='<div class="drow"><div class="dlbl">Attack</div><div class="dval">'+esc2(data.attack_type)+'</div></div>';
        if(data.technique)h+='<div class="drow"><div class="dlbl">MITRE</div><div class="dval" style="color:#f87171">'+esc2(data.technique)+'</div></div>';
        if(data.cve)h+='<div class="drow"><div class="dlbl">CVE</div><div class="dval" style="color:#f87171;font-weight:700">'+esc2(data.cve)+'</div></div>';
        h+='<div class="drow"><div class="dlbl">Summary</div><div class="dval" style="font-size:11px">'+esc2(data.summary||data.exploit_analysis||'')+'</div></div>';
        sec.innerHTML=h;body.appendChild(sec);
      }
    })
    .catch(function(){btn.innerHTML='&#x274C; Error';btn.style.color='#ef4444';
      setTimeout(function(){btn.innerHTML='&#x1F52C; AI DEEP';btn.style.color='#d97706';btn.disabled=false;},5000);});
}
</script>"""


def _page(title, logo_text, body, json_url=""):
    return (
        '<!DOCTYPE html><html lang="en"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>" + e(title) + " — HoneyLens</title>"
        "<style>" + _CSS + _EXTRA_CSS + "</style></head><body>"
        '<a href="#main-content" class="skip-link">Skip to main content</a>'
        + nav_bar_html("ja4")
        + page_header_html(
            title,
            eyebrow="Investigate",
            actions=(['<a href="' + e(json_url) + '" class="btn">JSON</a>'] if json_url else ()),
        )
        + '<div style="display:flex;gap:8px;padding:6px 22px;background:var(--bg2);border-bottom:1px solid var(--border);">'
        '<a href="/ja3_stats?format=html" class="nav-btn">JA3</a>'
        '<a href="/ja4_stats?format=html" class="nav-btn">JA4+</a>'
        '<a href="/ja4/stats/ja4s?format=html" class="nav-btn">JA4S (server)</a>'
        '<a href="/ja4/stats/ja4h?format=html" class="nav-btn">JA4H (HTTP)</a>'
        '<a href="/ja4/detected?format=html" class="nav-btn">Apps</a>'
        "</div>"
        '<main id="main-content" class="page">'
        + body
        + "</main>"
        + _drawer_html()
        + _actions_js()
        + sortable_table_js()
        + "</body></html>"
    )


# ═══════════════════════════════════════════════════════════════════════════
# JA3 Stats
# ═══════════════════════════════════════════════════════════════════════════


def ja3_stats_html(data):
    """Render JA3 stats. data = list of {ja3_hash, count}."""
    total = len(data) if data else 0
    total_events = sum(r.get("count", 0) for r in data) if data else 0

    kpi = (
        '<div class="kpi-grid">'
        '<div class="kpi"><div class="kpi-lbl">Unique JA3 Hashes</div>'
        '<div class="kpi-val" style="color:var(--purple)">' + str(total) + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Total TLS Events</div>'
        '<div class="kpi-val" style="color:var(--accent)">' + f"{total_events:,}" + "</div></div>"
        "</div>"
    )

    rows = ""
    for r in data or []:
        ja3 = e(r.get("ja3_hash", ""))
        count = r.get("count", 0)
        short = ja3[:32] + ("&hellip;" if len(ja3) > 32 else "")
        rows += '<tr><td class="fp" title="' + ja3 + '">' + short + "</td>"
        rows += '<td style="text-align:right;font-weight:700">' + f"{count:,}" + "</td></tr>"
    if not rows:
        rows = '<tr><td colspan="2" class="empty">No JA3 fingerprints captured yet</td></tr>'

    panel = (
        '<div class="panel">'
        '<div class="panel-hdr" style="color:var(--purple)">JA3 Fingerprint Frequency'
        '<span class="panel-cnt">' + str(total) + " hashes</span></div>"
        '<div class="scroll-table"><table>'
        '<thead><tr><th>JA3 Hash</th><th style="text-align:right">Events</th></tr></thead>'
        "<tbody>" + rows + "</tbody></table></div></div>"
    )

    return _page("JA3 Stats", "&#x1F510; JA3 <span>Fingerprints</span>", kpi + panel, "/ja3_stats")


# ═══════════════════════════════════════════════════════════════════════════
# JA4 Stats — matches actual API data: fingerprints[], summary[],
#             identified_threats[], top_snis[]
# ═══════════════════════════════════════════════════════════════════════════


def ja4_stats_html(data):
    """Render JA4+ stats dashboard. data = dict from /ja4_stats API."""
    fingerprints = data.get("fingerprints", [])
    summary_list = data.get("summary", [])
    identified = data.get("identified_threats", [])
    snis = data.get("top_snis", [])
    db_loaded = data.get("ja4_db_loaded", False)
    db_count = data.get("ja4_db_count", 0)

    # Compute KPI values from summary list
    total_fp = sum(s.get("total", 0) for s in summary_list)
    unique_fp = sum(s.get("unique_fingerprints", 0) for s in summary_list)
    identified_count = sum(s.get("identified_count", 0) for s in summary_list)
    unique_snis = sum(s.get("unique_snis", 0) for s in summary_list)

    kpi = (
        '<div class="kpi-grid">'
        '<div class="kpi"><div class="kpi-lbl">Total Captured</div>'
        '<div class="kpi-val" style="color:var(--accent)">' + f"{total_fp:,}" + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Unique Fingerprints</div>'
        '<div class="kpi-val" style="color:var(--purple)">' + f"{unique_fp:,}" + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Identified Apps</div>'
        '<div class="kpi-val" style="color:var(--green)">'
        + f"{identified_count:,}"
        + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Unique SNIs</div>'
        '<div class="kpi-val" style="color:var(--orange)">' + f"{unique_snis:,}" + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">JA4 DB</div>'
        '<div class="kpi-val" style="color:'
        + ("var(--green)" if db_loaded else "var(--red)")
        + '">'
        + (f"{db_count:,}" if db_loaded else "Not loaded")
        + "</div></div>"
        "</div>"
    )

    # Identified threats panel
    threat_panel = ""
    if identified:
        threat_rows = ""
        for r in identified:
            fp = e(r.get("fingerprint", ""))
            ident = e(r.get("identified", ""))
            count = r.get("count", 0)
            decoded = r.get("decoded", {})
            tls = decoded.get("tls_version", "")
            name_cls = "threat" if _is_threat(ident) else "app-name"
            db_app = e(r.get("db_application", "") or "")

            threat_rows += (
                "<tr>"
                '<td class="' + name_cls + '">' + (ident or db_app or "&mdash;") + "</td>"
                '<td class="fp" title="'
                + fp
                + '"><a href="/ja4/lookup/'
                + fp
                + '?format=html" style="color:var(--purple);text-decoration:none">'
                + fp[:24]
                + "&hellip;</a></td>"
                "<td>" + _tls_badge(tls) + "</td>"
                '<td style="text-align:right;font-weight:700">' + f"{count:,}" + "</td>"
                "</tr>"
            )

        threat_panel = (
            '<div class="panel">'
            '<div class="panel-hdr" style="color:var(--red)">&#x26A0; Identified Applications'
            '<span class="panel-cnt">' + str(len(identified)) + " matches</span></div>"
            '<div class="scroll-table"><table>'
            "<thead><tr><th>Application</th><th>Fingerprint</th><th>TLS</th>"
            '<th style="text-align:right">Events</th></tr></thead>'
            "<tbody>" + threat_rows + "</tbody></table></div></div>"
        )

    # Top fingerprints panel
    top_rows = ""
    for r in fingerprints:
        fp = e(r.get("fingerprint", ""))
        fp_type = e(r.get("type", ""))
        ident = e(r.get("identified", "") or r.get("db_application", "") or "")
        count = r.get("count", 0)
        decoded = r.get("decoded", {})
        tls = decoded.get("tls_version", "")
        ciphers = decoded.get("ciphers", "")
        exts = decoded.get("extensions", "")
        alpn = decoded.get("alpn", "")

        top_rows += (
            "<tr>"
            '<td class="fp" title="'
            + fp
            + '"><a href="/ja4/lookup/'
            + fp
            + '?format=html" style="color:var(--purple);text-decoration:none">'
            + fp[:24]
            + ("&hellip;" if len(fp) > 24 else "")
            + "</a></td>"
            '<td class="dim">' + fp_type + "</td>"
            "<td>" + _tls_badge(tls) + "</td>"
            '<td class="dim">' + (str(ciphers) + "c" if ciphers else "&mdash;") + "</td>"
            '<td class="dim">' + (str(exts) + "e" if exts else "&mdash;") + "</td>"
            '<td class="dim">' + (e(alpn) if alpn and str(alpn) != "None" else "&mdash;") + "</td>"
            '<td class="app-name">' + (ident if ident else "") + "</td>"
            '<td style="text-align:right;font-weight:700">' + f"{count:,}" + "</td>"
            "</tr>"
        )
    if not top_rows:
        top_rows = '<tr><td colspan="8" class="empty">No fingerprints captured</td></tr>'

    top_panel = (
        '<div class="panel">'
        '<div class="panel-hdr">Top Fingerprints'
        '<span class="panel-cnt">' + str(len(fingerprints)) + " shown</span></div>"
        '<div class="scroll-table"><table>'
        "<thead><tr><th>Fingerprint</th><th>Type</th><th>TLS</th><th>Ciphers</th>"
        '<th>Exts</th><th>ALPN</th><th>Identified</th><th style="text-align:right">Events</th></tr></thead>'
        "<tbody>" + top_rows + "</tbody></table></div></div>"
    )

    # SNI panel
    sni_panel = ""
    if snis:
        sni_rows = ""
        for r in snis:
            sni_rows += (
                '<tr><td class="mono">'
                + e(r.get("sni", ""))
                + '</td><td style="text-align:right">'
                + f"{r.get('count', 0):,}"
                + "</td></tr>"
            )
        sni_panel = (
            '<div class="panel">'
            '<div class="panel-hdr">Top SNI (Server Name)</div>'
            '<div class="scroll-table"><table>'
            '<thead><tr><th>SNI</th><th style="text-align:right">Events</th></tr></thead>'
            "<tbody>" + sni_rows + "</tbody></table></div></div>"
        )

    # Summary by type panel
    type_panel = ""
    if summary_list:
        type_rows = ""
        for s in summary_list:
            type_rows += (
                "<tr>"
                '<td style="color:var(--accent);font-weight:700">' + e(s.get("type", "")) + "</td>"
                '<td style="text-align:right">' + f"{s.get('total', 0):,}" + "</td>"
                '<td style="text-align:right">' + f"{s.get('unique_fingerprints', 0):,}" + "</td>"
                '<td style="text-align:right">' + f"{s.get('identified_count', 0):,}" + "</td>"
                "</tr>"
            )
        type_panel = (
            '<div class="panel">'
            '<div class="panel-hdr">By Fingerprint Type</div>'
            '<div class="scroll-table"><table>'
            '<thead><tr><th>Type</th><th style="text-align:right">Total</th>'
            '<th style="text-align:right">Unique</th><th style="text-align:right">Identified</th></tr></thead>'
            "<tbody>" + type_rows + "</tbody></table></div></div>"
        )

    # Malicious fingerprint alert banner
    malicious_alert = ""
    malicious_fps = [
        r for r in identified if _is_threat(r.get("identified", "") or r.get("db_application", ""))
    ]
    if malicious_fps:
        alert_items = ""
        for mf in malicious_fps[:5]:
            name = e(mf.get("identified", "") or mf.get("db_application", ""))
            fp = e(mf.get("fingerprint", ""))[:24]
            cnt = mf.get("count", 0)
            alert_items += f'<div style="margin-bottom:4px"><span style="color:#ef4444;font-weight:700">{name}</span> — <span class="fp">{fp}&hellip;</span> ({cnt:,} events)</div>'
        malicious_alert = (
            '<div class="alert-card" style="animation:pulse 2s infinite">'
            '<div style="font-weight:700;color:#ef4444;margin-bottom:6px">&#x26A0; Malicious Fingerprints Detected</div>'
            + alert_items
            + '<div style="font-size:10px;color:#94a3b8;margin-top:6px">These fingerprints match known attack tools. '
            "Click to investigate IPs and events.</div>"
            "</div>"
        )

    # Fingerprint comparison tool
    compare_panel = (
        '<div class="panel" style="margin-bottom:14px;border-color:#a78bfa44">'
        '<div class="panel-hdr" style="color:#a78bfa">&#x1F50E; Fingerprint Lookup Tool</div>'
        '<div style="padding:10px 14px;display:flex;gap:10px;align-items:flex-end">'
        '<div style="flex:1">'
        '<label style="color:var(--text2);font-size:11px;display:block;margin-bottom:4px">JA4/JA4S/JA4H Fingerprint</label>'
        '<input type="text" id="fp-compare" placeholder="t13d1517h2_8daaf6152771_b0da82dd1658" '
        'style="width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);'
        'padding:6px 10px;border-radius:4px;font-family:var(--mono);font-size:12px">'
        "</div>"
        '<button onclick="compareFp()" style="padding:8px 16px;background:var(--accent);color:#000;'
        'border:none;border-radius:4px;font-weight:700;font-size:12px;cursor:pointer;white-space:nowrap">'
        "&#x1F50E; Lookup</button>"
        "</div>"
        '<div id="compare-results" style="padding:0 14px 10px"></div>'
        "</div>"
    )

    body = (
        malicious_alert
        + kpi
        + compare_panel
        + threat_panel
        + top_panel
        + '<div class="two-col">'
        + type_panel
        + sni_panel
        + "</div>"
    )

    # Add comparison JS
    compare_js = r"""<script>
function compareFp() {
  var fp = document.getElementById('fp-compare').value.trim();
  var res = document.getElementById('compare-results');
  if (!fp || fp.length < 4) { res.innerHTML = '<div style="color:#f97316;font-size:12px">Enter at least 4 characters</div>'; return; }
  res.innerHTML = '<div style="color:var(--accent);font-size:12px">Searching...</div>';
  fetch('/ja4/compare', {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({fingerprint: fp})
  })
  .then(function(r) { return r.json(); })
  .then(function(d) {
    if (d.error) { res.innerHTML = '<div style="color:#ef4444">'+d.error+'</div>'; return; }
    var h = '';
    if (d.is_malicious) {
      h += '<div class="alert-card" style="margin-bottom:8px"><span style="color:#ef4444;font-weight:700">&#x26A0; MALICIOUS FINGERPRINT</span> — matches known attack tool</div>';
    }
    if (d.db_matches && d.db_matches.length) {
      h += '<div style="margin-bottom:8px"><div style="color:var(--green);font-weight:700;font-size:11px;margin-bottom:4px">&#x2714; ' + d.db_matches.length + ' database match(es)</div>';
      h += '<table style="font-size:11px"><thead><tr><th>Application</th><th>Type</th><th>Library</th><th>OS</th></tr></thead><tbody>';
      d.db_matches.forEach(function(m) {
        h += '<tr><td style="color:var(--orange);font-weight:600">'+(m.application||'—')+'</td>';
        h += '<td>'+( m.fingerprint_type||'')+'</td>';
        h += '<td style="color:#94a3b8">'+(m.library||'—')+'</td>';
        h += '<td style="color:#94a3b8">'+(m.os||'—')+'</td></tr>';
      });
      h += '</tbody></table></div>';
    } else {
      h += '<div style="color:#64748b;font-size:11px;margin-bottom:4px">No database matches — unknown fingerprint</div>';
    }
    if (d.events && d.events.length) {
      h += '<div style="margin-top:8px"><div style="color:var(--accent);font-weight:700;font-size:11px;margin-bottom:4px">&#x1F4CB; ' + d.events.length + ' captured event(s)</div>';
      h += '<table style="font-size:11px"><thead><tr><th>Source IP</th><th>Port</th><th>SNI</th><th>TLS</th><th>Time</th></tr></thead><tbody>';
      d.events.forEach(function(ev) {
        var ip = (ev.src_ip||'').split('/')[0];
        h += '<tr><td class="ip" style="cursor:pointer" onclick="window.location.href=\'/events_ip/'+ip+'?format=html\'">'+(ip||'—')+'</td>';
        h += '<td>'+(ev.dst_port||'')+'</td>';
        h += '<td class="mono dim" style="max-width:150px;overflow:hidden;text-overflow:ellipsis">'+(ev.sni||'—')+'</td>';
        h += '<td>'+(ev.tls_version||'—')+'</td>';
        h += '<td class="ts">'+(ev.timestamp||'').substring(0,19).replace('T',' ')+'</td></tr>';
      });
      h += '</tbody></table></div>';
    } else {
      h += '<div style="color:#64748b;font-size:11px">No matching events in sensor data</div>';
    }
    res.innerHTML = h;
  })
  .catch(function(e) { res.innerHTML = '<div style="color:#ef4444">Request failed</div>'; });
}
// Allow Enter key
document.getElementById('fp-compare').addEventListener('keydown', function(e) { if (e.key === 'Enter') compareFp(); });
</script>"""

    return (
        _page("JA4+ Stats", "&#x1F510; JA4+ <span>Fingerprints</span>", body, "/ja4_stats")
        + compare_js
    )


# ═══════════════════════════════════════════════════════════════════════════
# JA4 Detected Applications — matches actual API data:
#   total_detected, summary_by_app[], threats_detected[], all_detected[]
# ═══════════════════════════════════════════════════════════════════════════


def ja4_detected_html(data):
    """Render JA4+ detected applications dashboard."""
    total = data.get("total_detected", 0)
    summary = data.get("summary_by_app", [])
    threats = data.get("threats_detected", [])
    detected = data.get("all_detected", [])

    kpi = (
        '<div class="kpi-grid">'
        '<div class="kpi"><div class="kpi-lbl">Total Detections</div>'
        '<div class="kpi-val" style="color:var(--accent)">' + f"{total:,}" + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Unique Applications</div>'
        '<div class="kpi-val" style="color:var(--green)">' + f"{len(summary):,}" + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Threats Identified</div>'
        '<div class="kpi-val" style="color:var(--red)">' + f"{len(threats):,}" + "</div></div>"
        "</div>"
    )

    # Threat alert cards
    threat_html = ""
    if threats:
        threat_html = '<div class="sec-title" style="color:var(--red)">&#x26A0; Threat Applications Detected</div>'
        for t in threats:
            app = e(t.get("application", ""))
            events = t.get("event_count", 0)
            ips = t.get("unique_ips", 0)
            fp = e(t.get("fingerprint", ""))
            threat_html += (
                '<div class="alert-card">'
                '<span class="threat">' + app + "</span> "
                '<span class="dim">&mdash; '
                + f"{events:,}"
                + " events from "
                + f"{ips:,}"
                + " IPs</span> "
                '<span class="fp" style="font-size:9px">' + fp[:30] + "</span>"
                "</div>"
            )

    # Summary by application — clickable rows
    summary_rows = ""
    for s in summary:
        app = s.get("application", "")
        app_e = e(app)
        events = s.get("total_events", 0)
        ips = s.get("unique_ips", 0)
        variants = s.get("fingerprint_variants", 0)
        verified = s.get("verified", False)
        name_cls = "threat" if _is_threat(app) else "app-name"
        app_url = "/ja4/detected/" + html.escape(app, quote=True) + "?format=html"

        summary_rows += (
            '<tr class="clickable" onclick="window.location.href=\'' + app_url + "'\">"
            '<td class="' + name_cls + '">' + app_e + "</td>"
            '<td style="text-align:right;font-weight:700">' + f"{events:,}" + "</td>"
            '<td style="text-align:right">' + f"{ips:,}" + "</td>"
            '<td style="text-align:right" class="dim">' + str(variants) + "</td>"
            "<td>"
            + ('<span class="verified-badge">&#x2713; Verified</span>' if verified else "")
            + "</td>"
            "</tr>"
        )
    if not summary_rows:
        summary_rows = '<tr><td colspan="5" class="empty">No applications detected. Ensure ja4_database is loaded.</td></tr>'

    summary_panel = (
        '<div class="panel">'
        '<div class="panel-hdr" style="color:var(--green)">&#x1F50D; Detected Applications (click for detail)'
        '<span class="panel-cnt">' + str(len(summary)) + " applications</span></div>"
        '<div class="scroll-table"><table>'
        '<thead><tr><th>Application</th><th style="text-align:right">Events</th>'
        '<th style="text-align:right">Unique IPs</th><th style="text-align:right">Variants</th>'
        "<th>Verified</th></tr></thead>"
        "<tbody>" + summary_rows + "</tbody></table></div></div>"
    )

    # Full detections table
    full_rows = ""
    for d in detected[:100]:
        app = e(d.get("application", ""))
        lib = e(d.get("library", "") or "")
        device = e(d.get("device", "") or "")
        os_name = e(d.get("os", "") or "")
        fp = e(d.get("fingerprint", ""))
        events = d.get("event_count", 0)
        ips = d.get("unique_ips", 0)
        verified = d.get("verified", False)
        first = (d.get("first_seen") or "")[:16].replace("T", " ")
        last = (d.get("last_seen") or "")[:16].replace("T", " ")
        name_cls = "threat" if _is_threat(d.get("application", "")) else "app-name"

        full_rows += (
            "<tr>"
            '<td class="' + name_cls + '">' + app + "</td>"
            '<td class="dim">' + lib + "</td>"
            '<td class="dim">' + device + "</td>"
            '<td class="dim">' + os_name + "</td>"
            '<td class="fp" title="'
            + fp
            + '"><a href="/ja4/lookup/'
            + fp
            + '?format=html" style="color:var(--purple);text-decoration:none">'
            + fp[:20]
            + ("&hellip;" if len(fp) > 20 else "")
            + "</a></td>"
            '<td style="text-align:right;font-weight:700">' + f"{events:,}" + "</td>"
            '<td style="text-align:right">' + f"{ips:,}" + "</td>"
            "<td>" + ('<span class="verified-badge">&#x2713;</span>' if verified else "") + "</td>"
            '<td class="dim" style="font-size:10px">' + first + "</td>"
            '<td class="dim" style="font-size:10px">' + last + "</td>"
            "</tr>"
        )
    if not full_rows:
        full_rows = '<tr><td colspan="10" class="empty">No detections</td></tr>'

    full_panel = (
        '<div class="panel">'
        '<div class="panel-hdr">All Detections'
        '<span class="panel-cnt">' + str(total) + " total</span></div>"
        '<div class="scroll-table" style="max-height:500px"><table>'
        "<thead><tr><th>Application</th><th>Library</th><th>Device</th><th>OS</th>"
        '<th>Fingerprint</th><th style="text-align:right">Events</th>'
        '<th style="text-align:right">IPs</th><th>Ver</th>'
        "<th>First Seen</th><th>Last Seen</th></tr></thead>"
        "<tbody>" + full_rows + "</tbody></table></div></div>"
    )

    body = kpi + threat_html + summary_panel + full_panel

    return _page(
        "JA4+ Detected Apps", "&#x1F50D; JA4+ <span>Applications</span>", body, "/ja4/detected"
    )


# ═══════════════════════════════════════════════════════════════════════════
# JA4 Lookup (single fingerprint detail)
# ═══════════════════════════════════════════════════════════════════════════


def ja4_lookup_html(data):
    """Render JA4+ lookup result for a single fingerprint."""
    fp = e(data.get("fingerprint", ""))
    found = data.get("found", False)

    if not found:
        body = (
            '<div class="panel"><div class="panel-hdr" style="color:var(--orange)">'
            "Fingerprint Not Found</div>"
            '<div style="padding:24px;text-align:center;color:var(--text3)">'
            '<div style="font-size:14px;margin-bottom:8px">No match in JA4+ database for:</div>'
            '<div class="fp" style="font-size:12px;color:var(--purple)">' + fp + "</div>"
            '<div style="margin-top:16px;font-size:11px">'
            '<a href="/ja4/'
            + fp
            + '?format=html" style="color:var(--accent)">View events with this fingerprint &rarr;</a>'
            "</div></div></div>"
        )
        return _page("JA4 Lookup: Not Found", "&#x1F510; JA4+ <span>Lookup</span>", body)

    app_name = e(data.get("application", "") or "")
    lib = e(data.get("library", "") or "")
    device = e(data.get("device", "") or "")
    os_name = e(data.get("os", "") or "")
    ua = e(data.get("user_agent", "") or "")
    ca = e(data.get("certificate_authority", "") or "")
    verified = data.get("verified", False)
    notes = e(data.get("notes", "") or "")
    fp_type = e(data.get("fp_type", "") or "")
    is_threat = _is_threat(data.get("application", ""))

    name_cls = "threat" if is_threat else "app-name"
    ver_html = (
        '<span class="verified-badge">&#x2713; Verified</span>'
        if verified
        else '<span class="dim">Not verified</span>'
    )

    rows = ""
    fields = [
        ("Fingerprint", '<span class="fp" style="font-size:12px">' + fp + "</span>"),
        ("Type", fp_type or "&mdash;"),
        (
            "Application",
            '<span class="'
            + name_cls
            + '" style="font-size:14px">'
            + (app_name or "&mdash;")
            + "</span>",
        ),
        ("Library", lib or "&mdash;"),
        ("Device", device or "&mdash;"),
        ("OS", os_name or "&mdash;"),
        (
            "User Agent",
            '<span style="font-size:10px;word-break:break-all">' + (ua or "&mdash;") + "</span>",
        ),
        ("Certificate Authority", ca or "&mdash;"),
        ("Verified", ver_html),
        ("Notes", '<span style="font-size:11px">' + (notes or "&mdash;") + "</span>"),
    ]
    for label, val in fields:
        rows += (
            '<tr><th style="text-align:right;width:180px;padding:8px 12px;color:var(--text3);font-size:10px;text-transform:uppercase;white-space:nowrap;border-bottom:1px solid #1a2a40">'
            + label
            + "</th>"
        )
        rows += '<td style="padding:8px 12px;border-bottom:1px solid #1a2a40">' + val + "</td></tr>"

    body = (
        '<div class="panel">'
        '<div class="panel-hdr" style="color:var(--purple)">&#x1F510; Fingerprint Detail'
        + (
            ' <span style="color:var(--red);margin-left:8px">&#x26A0; THREAT</span>'
            if is_threat
            else ""
        )
        + "</div>"
        '<table style="font-size:12px">' + rows + "</table>"
        '<div style="padding:12px 16px;border-top:1px solid var(--border)">'
        '<a href="/ja4/'
        + fp
        + '?format=html" class="btn" style="background:var(--purple);color:#000;border-color:var(--purple)">'
        "&#x1F50D; View Events With This Fingerprint</a>"
        "</div></div>"
    )

    title = app_name if app_name else fp[:30]
    return _page("JA4 Lookup: " + title, "&#x1F510; JA4+ <span>Lookup</span>", body)


# ═══════════════════════════════════════════════════════════════════════════
# JA4 Events (events matching a fingerprint)
# ═══════════════════════════════════════════════════════════════════════════


def ja4_events_html(data):
    """Render events matching a JA4+ fingerprint."""
    fp = e(data.get("fingerprint", ""))
    events = data.get("events", [])
    db_match = data.get("db_match")
    count = data.get("event_count", 0)

    # DB match info
    match_html = ""
    if db_match:
        app = e(db_match.get("application", "") or "")
        is_threat = _is_threat(db_match.get("application", ""))
        match_html = (
            '<div class="panel" style="margin-bottom:14px">'
            '<div class="panel-hdr" style="color:var(--green)">&#x2705; Database Match</div>'
            '<div style="padding:10px 16px;font-size:12px">'
            '<span class="'
            + ("threat" if is_threat else "app-name")
            + '" style="font-size:14px">'
            + app
            + "</span>"
            + (
                ' &mdash; <span class="dim">' + e(db_match.get("library", "") or "") + "</span>"
                if db_match.get("library")
                else ""
            )
            + (
                ' &mdash; <span class="dim">' + e(db_match.get("os", "") or "") + "</span>"
                if db_match.get("os")
                else ""
            )
            + (
                ' <span class="verified-badge" style="margin-left:8px">&#x2713; Verified</span>'
                if db_match.get("verified")
                else ""
            )
            + ' <a href="/ja4/lookup/'
            + fp
            + '?format=html" style="color:var(--purple);margin-left:12px">Full lookup &rarr;</a>'
            "</div></div>"
        )

    kpi = (
        '<div class="kpi-grid">'
        '<div class="kpi"><div class="kpi-lbl">Matching Events</div>'
        '<div class="kpi-val" style="color:var(--accent)">' + f"{count:,}" + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Fingerprint</div>'
        '<div class="kpi-val" style="color:var(--purple);font-size:12px;word-break:break-all">'
        + fp
        + "</div></div>"
        "</div>"
    )

    # Events table
    rows = ""
    for ev in events:
        eid = e(ev.get("event_id", ""))
        eid_short = eid[:12] + ("&hellip;" if len(eid) > 12 else "")
        ts = e((ev.get("timestamp") or "")[:19].replace("T", " "))
        src = (ev.get("src_ip") or "").split("/")[0]
        dst = (ev.get("dst_ip") or "").split("/")[0]
        port = ev.get("dst_port", "")
        sni = e(ev.get("sni", "") or "")
        tls = e(ev.get("tls_version", "") or "")
        ident = e(ev.get("identified", "") or "")

        rows += (
            "<tr>"
            '<td class="dim" style="font-size:10px">' + ts + "</td>"
            '<td class="ip" onclick="window.location.href=\'/events_ip/'
            + e(src)
            + "?format=html'\">"
            + e(src)
            + "</td>"
            '<td class="dim">' + e(dst) + "</td>"
            '<td class="dim">' + str(port) + "</td>"
            '<td class="mono">' + sni + "</td>"
            "<td>" + _tls_badge(tls) + "</td>"
            '<td class="app-name">' + ident + "</td>"
            "<td>"
            '<button class="act-btn act-ai" data-eid="'
            + eid
            + '" onclick="aiAnalyze(this.dataset.eid,this)">&#x1F9E0; AI</button>'
            + (
                '<button class="act-btn act-hunt" data-ip="'
                + e(src)
                + '" onclick="huntIP(this.dataset.ip,this)">&#x1F3AF; Hunt</button>'
                if src
                else ""
            )
            + "</td>"
            '<td class="mono" style="cursor:pointer;color:var(--accent)" '
            "onclick=\"loadEventDrawer('" + eid + "')\" "
            'title="' + eid + '">' + eid_short + "</td>"
            "</tr>"
        )
    if not rows:
        rows = '<tr><td colspan="9" class="empty">No events found for this fingerprint</td></tr>'

    table = (
        '<div class="panel">'
        '<div class="panel-hdr">Events'
        '<span class="panel-cnt">' + str(count) + " events</span></div>"
        '<div class="scroll-table"><table>'
        "<thead><tr><th>Time</th><th>Source IP</th><th>Dest IP</th><th>Port</th>"
        "<th>SNI</th><th>TLS</th><th>Identified</th><th>Actions</th><th>Event</th></tr></thead>"
        "<tbody>" + rows + "</tbody></table></div></div>"
    )

    body = kpi + match_html + table
    return _page("JA4 Events: " + fp[:30], "&#x1F510; JA4+ <span>Events</span>", body)


# ═══════════════════════════════════════════════════════════════════════════
# JA4 Detected Application Detail (events for a specific app)
# ═══════════════════════════════════════════════════════════════════════════


def ja4_app_detail_html(data):
    """Render events for a specific detected JA4+ application."""
    app_name = e(data.get("application", ""))
    events = data.get("events", [])
    unique_ips = data.get("unique_ips", [])
    count = data.get("event_count", 0)
    is_threat = _is_threat(data.get("application", ""))

    kpi = (
        '<div class="kpi-grid">'
        '<div class="kpi"><div class="kpi-lbl">Application</div>'
        '<div class="kpi-val" style="color:'
        + ("var(--red)" if is_threat else "var(--orange)")
        + ';font-size:16px">'
        + app_name
        + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Total Events</div>'
        '<div class="kpi-val" style="color:var(--accent)">' + f"{count:,}" + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Unique Source IPs</div>'
        '<div class="kpi-val" style="color:var(--pink)">' + f"{len(unique_ips):,}" + "</div></div>"
        "</div>"
    )

    # Unique IPs panel
    ip_pills = ""
    for ip_raw in unique_ips[:50]:
        ip_clean = (ip_raw or "").split("/")[0]
        ip_pills += (
            '<a href="/events_ip/'
            + e(ip_clean)
            + '?format=html" style="display:inline-block;padding:3px 10px;margin:2px;border-radius:4px;background:var(--bg3);border:1px solid var(--border);color:var(--accent);text-decoration:none;font-size:11px;font-family:monospace">'
            + e(ip_clean)
            + "</a>"
        )
    if not ip_pills:
        ip_pills = '<span class="dim">No IPs</span>'

    ip_panel = (
        '<div class="panel" style="margin-bottom:14px">'
        '<div class="panel-hdr" style="color:var(--pink)">Source IPs'
        '<span class="panel-cnt">' + str(len(unique_ips)) + " unique</span></div>"
        '<div style="padding:10px 14px">' + ip_pills + "</div></div>"
    )

    # Events table
    rows = ""
    for ev in events:
        eid = e(ev.get("event_id", ""))
        eid_short = eid[:12] + ("&hellip;" if len(eid) > 12 else "")
        ts = e((ev.get("timestamp") or "")[:19].replace("T", " "))
        src = (ev.get("src_ip") or "").split("/")[0]
        dst = (ev.get("dst_ip") or "").split("/")[0]
        port = ev.get("dst_port", "")
        proto = e((ev.get("protocol") or "").upper())
        fp = e(ev.get("fingerprint", ""))
        sni = e(ev.get("sni", "") or "")
        lib = e(ev.get("library", "") or "")
        e(ev.get("os", "") or "")
        verified = ev.get("verified", False)

        rows += (
            "<tr>"
            '<td class="dim" style="font-size:10px">' + ts + "</td>"
            '<td class="ip" onclick="window.location.href=\'/events_ip/'
            + e(src)
            + "?format=html'\">"
            + e(src)
            + "</td>"
            '<td class="dim">' + e(dst) + "</td>"
            '<td class="dim">' + str(port) + "</td>"
            '<td class="dim">' + proto + "</td>"
            '<td class="fp" title="'
            + fp
            + '"><a href="/ja4/lookup/'
            + fp
            + '?format=html" style="color:var(--purple);text-decoration:none">'
            + fp[:20]
            + ("&hellip;" if len(fp) > 20 else "")
            + "</a></td>"
            '<td class="mono">' + sni + "</td>"
            '<td class="dim">' + lib + "</td>"
            "<td>" + ('<span class="verified-badge">&#x2713;</span>' if verified else "") + "</td>"
            "<td>"
            '<button class="act-btn act-ai" data-eid="'
            + eid
            + '" onclick="aiAnalyze(this.dataset.eid,this)">&#x1F9E0; AI</button>'
            + (
                '<button class="act-btn act-hunt" data-ip="'
                + e(src)
                + '" onclick="huntIP(this.dataset.ip,this)">&#x1F3AF; Hunt</button>'
                if src
                else ""
            )
            + "</td>"
            '<td class="mono" style="cursor:pointer;color:var(--accent)" '
            "onclick=\"loadEventDrawer('" + eid + "')\" "
            'title="' + eid + '">' + eid_short + "</td>"
            "</tr>"
        )
    if not rows:
        rows = '<tr><td colspan="12" class="empty">No events found</td></tr>'

    table = (
        '<div class="panel">'
        '<div class="panel-hdr">Events'
        '<span class="panel-cnt">' + str(count) + " events</span></div>"
        '<div class="scroll-table" style="max-height:600px"><table>'
        "<thead><tr><th>Time</th><th>Source IP</th><th>Dest IP</th><th>Port</th>"
        "<th>Proto</th><th>Fingerprint</th><th>SNI</th><th>Library</th>"
        "<th>Ver</th><th>Actions</th><th>Event</th></tr></thead>"
        "<tbody>" + rows + "</tbody></table></div></div>"
    )

    body = kpi + ip_panel + table
    return _page(
        "JA4 App: " + app_name,
        "&#x1F50D; JA4+ <span>Application Detail</span>",
        body,
        "/ja4/detected?format=html",
    )


# ═══════════════════════════════════════════════════════════════════════════
# JA4S (Server) Stats
# ═══════════════════════════════════════════════════════════════════════════


def ja4s_stats_html(data):
    """Render JA4S server fingerprint dashboard."""
    total = data.get("total", 0)
    unique = data.get("unique", 0)
    fps = data.get("fingerprints", [])

    kpi = (
        '<div class="kpi-grid">'
        '<div class="kpi"><div class="kpi-lbl">Total JA4S Captured</div>'
        '<div class="kpi-val" style="color:var(--accent)">' + f"{total:,}" + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Unique Server FPs</div>'
        '<div class="kpi-val" style="color:var(--purple)">' + f"{unique:,}" + "</div></div>"
        "</div>"
    )

    rows = ""
    for r in fps:
        fp = e(r.get("fingerprint", ""))
        ident = e(r.get("identified", "") or "")
        tls = r.get("tls_version", "")
        sni = e(r.get("sni", "") or "")
        count = r.get("count", 0)
        ips = r.get("unique_ips", 0)
        last = (r.get("last_seen") or "")[:19].replace("T", " ")
        rows += (
            "<tr>"
            '<td class="fp" title="'
            + fp
            + '"><a href="/ja4/lookup/'
            + fp
            + '?format=html" style="color:var(--purple);text-decoration:none">'
            + fp[:28]
            + ("&hellip;" if len(fp) > 28 else "")
            + "</a></td>"
            "<td>" + _tls_badge(tls) + "</td>"
            '<td class="mono dim" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'
            + sni
            + '">'
            + sni
            + "</td>"
            '<td class="app-name">' + ident + "</td>"
            '<td style="text-align:right;font-weight:700">' + f"{count:,}" + "</td>"
            '<td style="text-align:right;color:var(--accent)">' + f"{ips:,}" + "</td>"
            '<td class="ts">' + last + "</td>"
            "</tr>"
        )
    if not rows:
        rows = '<tr><td colspan="7" class="empty">No JA4S fingerprints captured — server hello parsing required</td></tr>'

    panel = (
        '<div class="panel">'
        '<div class="panel-hdr">&#x1F5A5; Server Fingerprints (JA4S)'
        '<span class="panel-cnt">' + str(len(fps)) + " shown</span></div>"
        '<p style="color:#94a3b8;font-size:11px;padding:0 14px 8px;margin:0">'
        "JA4S captures TLS ServerHello parameters: TLS version, cipher suite chosen, extensions. "
        "Identifies the server software responding to connections.</p>"
        '<div class="scroll-table"><table>'
        "<thead><tr><th>Fingerprint</th><th>TLS</th><th>SNI</th><th>Identified</th>"
        '<th style="text-align:right">Events</th><th style="text-align:right">IPs</th><th>Last Seen</th></tr></thead>'
        "<tbody>" + rows + "</tbody></table></div></div>"
    )

    return _page(
        "JA4S Stats",
        "&#x1F5A5; JA4S <span>Server Fingerprints</span>",
        kpi + panel,
        "/ja4/stats/ja4s",
    )


# ═══════════════════════════════════════════════════════════════════════════
# JA4H (HTTP) Stats
# ═══════════════════════════════════════════════════════════════════════════


def ja4h_stats_html(data):
    """Render JA4H HTTP fingerprint dashboard."""
    total = data.get("total", 0)
    unique = data.get("unique", 0)
    fps = data.get("fingerprints", [])

    kpi = (
        '<div class="kpi-grid">'
        '<div class="kpi"><div class="kpi-lbl">Total JA4H Captured</div>'
        '<div class="kpi-val" style="color:var(--accent)">' + f"{total:,}" + "</div></div>"
        '<div class="kpi"><div class="kpi-lbl">Unique HTTP FPs</div>'
        '<div class="kpi-val" style="color:var(--orange)">' + f"{unique:,}" + "</div></div>"
        "</div>"
    )

    rows = ""
    for r in fps:
        fp = e(r.get("fingerprint", ""))
        ident = e(r.get("identified", "") or "")
        sni = e(r.get("sni", "") or "")
        count = r.get("count", 0)
        ips = r.get("unique_ips", 0)
        last = (r.get("last_seen") or "")[:19].replace("T", " ")
        name_cls = "threat" if _is_threat(ident) else "app-name"
        rows += (
            "<tr>"
            '<td class="fp" title="'
            + fp
            + '"><a href="/ja4/lookup/'
            + fp
            + '?format=html" style="color:var(--purple);text-decoration:none">'
            + fp[:28]
            + ("&hellip;" if len(fp) > 28 else "")
            + "</a></td>"
            '<td class="mono dim" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'
            + sni
            + '">'
            + sni
            + "</td>"
            '<td class="' + name_cls + '">' + (ident or "&mdash;") + "</td>"
            '<td style="text-align:right;font-weight:700">' + f"{count:,}" + "</td>"
            '<td style="text-align:right;color:var(--accent)">' + f"{ips:,}" + "</td>"
            '<td class="ts">' + last + "</td>"
            "</tr>"
        )
    if not rows:
        rows = '<tr><td colspan="6" class="empty">No JA4H fingerprints captured — HTTP header parsing required</td></tr>'

    panel = (
        '<div class="panel">'
        '<div class="panel-hdr">&#x1F310; HTTP Fingerprints (JA4H)'
        '<span class="panel-cnt">' + str(len(fps)) + " shown</span></div>"
        '<p style="color:#94a3b8;font-size:11px;padding:0 14px 8px;margin:0">'
        "JA4H captures HTTP client fingerprints: method, headers, accept-language, cookie presence. "
        "Identifies HTTP clients, bots, and scanners without TLS inspection.</p>"
        '<div class="scroll-table"><table>'
        "<thead><tr><th>Fingerprint</th><th>SNI/Host</th><th>Identified</th>"
        '<th style="text-align:right">Events</th><th style="text-align:right">IPs</th><th>Last Seen</th></tr></thead>'
        "<tbody>" + rows + "</tbody></table></div></div>"
    )

    return _page(
        "JA4H Stats",
        "&#x1F310; JA4H <span>HTTP Fingerprints</span>",
        kpi + panel,
        "/ja4/stats/ja4h",
    )
