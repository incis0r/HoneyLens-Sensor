"""
webui/endpoint_generic.py — Generic Endpoint HTML Renderer
============================================================
Renders table/record/stats views for /events, /top_scanners, etc.
Uses the ICS/OT shared style with nav bar, drawer, and full action buttons.

Rebuilt with shared components (Idea 4).
Compatible with Python 3.9+.
"""

from __future__ import annotations

import html
import json
import re
from typing import TYPE_CHECKING

from honeylens.webui.shared import (
    SHARED_CSS,
    drawer_html,
    event_actions_js,
    nav_bar_html,
)

if TYPE_CHECKING:
    from fastapi import FastAPI


def register_routes(app: FastAPI) -> None:
    """Generic endpoint routes are served by api.py — this module
    provides the HTML rendering functions only."""
    pass


# ---------------------------------------------------------------------------
# Main page generator
# ---------------------------------------------------------------------------


def _generate_endpoint_html(title: str, data, table_type: str, back_url: str, endpoint: str) -> str:
    """Generate HTML page for endpoint data using ICS/OT style."""

    safe_title = html.escape(str(title)) if title else "Results"
    safe_endpoint = html.escape(str(endpoint)) if endpoint else ""
    safe_back_url = html.escape(str(back_url)) if back_url else "/"

    if isinstance(data, list):
        table_html = _generate_table_html(data, table_type)
        count_info = f"{len(data):,} records"
    elif isinstance(data, dict):
        if any(isinstance(v, list) for v in data.values()):
            table_html = _generate_stats_html(data)
            count_info = f"{len(data)} sections"
        else:
            table_html = _generate_record_html(data)
            count_info = "1 record"
    else:
        table_html = (
            f'<pre class="payload-blk">{html.escape(json.dumps(data, indent=2, default=str))}</pre>'
        )
        count_info = ""

    extra_css = """
th[data-col]{position:relative;white-space:nowrap;}
th[data-col]:hover{background:rgba(34,211,238,0.08);}
th[data-col][data-sort-dir]{color:var(--accent);}
tbody tr:hover{background:rgba(34,211,238,0.04);}
.ep-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;
  padding-bottom:12px;border-bottom:1px solid var(--border)}
.ep-hdr h2{color:var(--accent);font-size:16px;font-weight:700;display:flex;align-items:center;gap:10px}
.ep-endpoint{font-family:monospace;background:var(--bg3);padding:3px 10px;border-radius:4px;
  color:var(--text3);font-size:11px}
.ep-count{background:#22c55e22;color:#4ade80;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700}
.ep-actions{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.ep-btn{padding:5px 13px;border-radius:5px;border:1px solid var(--border);
  background:var(--bg3);color:var(--text2);cursor:pointer;font-family:inherit;
  font-size:12px;font-weight:600;text-decoration:none;display:inline-block;transition:all .15s}
.ep-btn:hover{background:var(--bg4);color:var(--text);text-decoration:none}
.ep-btn.primary{background:var(--accent);color:#000;border-color:var(--accent)}
.ep-btn.primary:hover{background:#7dd3fc}
.evt-scroll{overflow-x:auto;overflow-y:auto;max-height:70vh}
.json-link{color:var(--text3);font-size:11px;margin-top:10px;display:block}
.json-link a{color:var(--accent)}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:7px;overflow:hidden}
.stat-card h3{padding:8px 13px;background:var(--bg3);border-bottom:1px solid var(--border);
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:var(--text2)}
.stat-value{font-size:28px;font-weight:800;color:var(--accent);padding:14px;text-align:center}
.stat-card pre{padding:10px;font-size:11px;overflow-x:auto;color:var(--text2)}
.stat-card table{margin:0}
.record-table th{text-align:right;width:180px;padding:7px 12px;color:var(--text3);
  font-size:10px;text-transform:uppercase;letter-spacing:.5px;vertical-align:top;
  white-space:nowrap;border-bottom:1px solid #1a2a40}
.record-table td{padding:7px 12px;border-bottom:1px solid #1a2a40;font-size:12px;word-break:break-all}
.record-table pre{font-size:11px;color:var(--text2);max-height:200px;overflow:auto}
.ip{color:var(--pink);font-family:monospace;font-size:12px;cursor:pointer}
.ip:hover{text-decoration:underline}
.port{color:#fbbf24;font-family:monospace;font-size:11px}
.protocol{color:var(--accent);font-weight:700}
.timestamp{color:var(--text3);font-size:11px}
.event-link{color:var(--accent);text-decoration:none;font-family:monospace;cursor:pointer}
.event-link:hover{text-decoration:underline}
.fp-link{color:var(--purple);text-decoration:none;font-family:monospace}
.fp-link:hover{text-decoration:underline}
.attack-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;
  margin:1px;background:#ef444422;color:#f87171;border:1px solid #ef444444}
.identified-threat{color:var(--red);font-weight:700}
.db-app{color:var(--green);font-weight:600}
.db-info{color:var(--text2);font-size:11px}
.db-notes{color:var(--text3);font-size:10px}
.verified-badge{color:var(--green);font-weight:700;font-size:10px}
.decoded-tls{color:var(--accent);font-weight:600;font-size:11px}
.decoded-info{color:var(--text2);font-size:10px}
.decoded-alpn{color:var(--purple);font-size:10px}
.decoded-warn{color:var(--orange);font-size:10px;font-weight:700}
"""

    body = f'''
<div class="ep-hdr">
  <h2>{safe_title} <span class="ep-endpoint">{safe_endpoint}</span>
  {f'<span class="ep-count">{count_info}</span>' if count_info else ""}</h2>
</div>
<div class="ep-actions">
  <a href="{safe_back_url}" class="ep-btn">\u2190 Dashboard</a>
  <a href="{safe_endpoint}" class="ep-btn" target="_blank">\U0001f4e5 Raw JSON</a>
  <button class="ep-btn" onclick="window.location.reload()">\U0001f504 Refresh</button>
</div>
<div class="evt-scroll">
  {table_html}
</div>
<div class="json-link">API: <a href="{safe_endpoint}">{safe_endpoint}</a> (returns JSON)</div>
'''

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="strict-origin-when-cross-origin">
<link rel="icon" href="/favicon.ico" type="image/x-icon">
<title>{safe_title} \u2014 HoneyLens</title>
<style>{SHARED_CSS}{extra_css}</style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
{nav_bar_html("dashboard")}
<main id="main-content" class="page">
{body}
</main>
{drawer_html()}
{_endpoint_js()}
{event_actions_js()}
<script>
// --- Sortable tables (event delegation) ---
(function(){{
  function doSort(th){{
    var table=th.closest("table");if(!table)return;
    var tbody=table.tBodies[0]||table;var rows=Array.from(tbody.rows);if(rows.length<1)return;
    var idx=Array.from(th.parentNode.cells).indexOf(th);if(idx<0)return;
    var asc=th.dataset.sortDir!=="asc";th.dataset.sortDir=asc?"asc":"desc";
    Array.from(th.parentNode.cells).forEach(function(h){{h.classList.remove("sorted-asc","sorted-desc");}});
    th.classList.add(asc?"sorted-asc":"sorted-desc");
    rows.sort(function(a,b){{
      var ac=a.cells[idx],bc=b.cells[idx];if(!ac||!bc)return 0;
      var av=ac.textContent.trim(),bv=bc.textContent.trim();
      var an=parseFloat(av.replace(/,/g,"")),bn=parseFloat(bv.replace(/,/g,""));
      if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;
      if(/^\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}/.test(av)){{var ap=av.split(".").map(Number),bp=bv.split(".").map(Number);for(var i=0;i<4;i++){{var d=(ap[i]||0)-(bp[i]||0);if(d)return asc?d:-d;}}return 0;}}
      var sv={{CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,INFO:0}};if(sv[av]!==undefined&&sv[bv]!==undefined)return asc?sv[av]-sv[bv]:sv[bv]-sv[av];
      return asc?av.localeCompare(bv):bv.localeCompare(av);
    }});
    rows.forEach(function(r){{tbody.appendChild(r);}});
  }}
  document.addEventListener("click",function(e){{var th=e.target.closest("th");if(th&&th.closest("table"))doSort(th);}});
}})();

// --- Timestamps ---
document.querySelectorAll('.timestamp').forEach(function(el) {{
    var ts = parseFloat(el.dataset.ts);
    if (ts) el.textContent = new Date(ts * 1000).toLocaleString();
}});
document.querySelectorAll('.ip').forEach(function(el) {{
    el.style.cursor = 'pointer';
    el.addEventListener('click', function() {{
        var ip = this.textContent.trim();
        if (!ip || ip === '-' || ip === '\u2014') return;
        fetch('/ip/status/' + encodeURIComponent(ip), {{credentials:'same-origin'}})
            .then(function(r) {{ return r.json(); }})
            .then(function(d) {{
                if (d.hunted) window.location.href = '/attacker_hunting/' + encodeURIComponent(ip);
                else window.location.href = '/events_ip/' + encodeURIComponent(ip) + '?format=html&limit=10';
            }})
            .catch(function() {{
                window.location.href = '/events_ip/' + encodeURIComponent(ip) + '?format=html&limit=10';
            }});
    }});
}});
</script>
</body>
</html>"""


def _endpoint_js() -> str:
    return """<script>
function loadEventDrawer(eventId) {
    document.getElementById('drwTitle').textContent = 'Loading ' + eventId.substring(0,12) + '...';
    document.getElementById('drwBody').innerHTML = '<div style="color:var(--text3);text-align:center;padding:40px">Loading...</div>';
    openDrawer();
    fetch('/event_full/' + encodeURIComponent(eventId), {credentials:'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(ev) { renderDrawerEvent(ev); })
        .catch(function(err) {
            document.getElementById('drwBody').innerHTML =
                '<div style="color:var(--red);padding:20px">Error: ' + esc(err.message) + '</div>';
        });
}
</script>"""


# ---------------------------------------------------------------------------
# Table rendering
# ---------------------------------------------------------------------------


def _generate_table_html(data: list, table_type: str) -> str:
    if not data:
        return '<div class="empty" style="padding:40px">No data found</div>'

    # A list of scalars (e.g. mitre_technique_events' matching_attack_types) is not a table
    # of records — render it as a single-column table instead of crashing on .keys().
    if not isinstance(data[0], dict):
        scalar_rows = []
        for v in data:
            safe_val = html.escape(str(v)) if v is not None else "—"
            scalar_rows.append(f"<tr><td>{safe_val}</td></tr>")
        return f"<table><tbody>{''.join(scalar_rows)}</tbody></table>"

    columns = list(data[0].keys())
    header = "".join(
        f'<th data-col="{html.escape(col)}" onclick="sortTable(this)" '
        f'style="cursor:pointer;user-select:none;">'
        f"{html.escape(col.replace('_', ' ').title())} "
        f'<span class="sort-arrow" style="opacity:0.3;font-size:10px;">&#x25B2;&#x25BC;</span></th>'
        for col in columns
    )

    rows = []
    for record in data:
        cells = []
        for col in columns:
            val = record.get(col)
            cell_class = ""
            safe_val = html.escape(str(val)) if val is not None else "\u2014"

            if col in ("src_ip", "dst_ip", "ip"):
                cell_class = "ip"
                cell_content = safe_val
            elif col in ("src_port", "dst_port", "port"):
                cell_class = "port"
                cell_content = safe_val
            elif col == "protocol":
                cell_class = "protocol"
                cell_content = safe_val
            elif col == "timestamp":
                cell_content = f'<span class="timestamp" data-ts="{safe_val}">{safe_val}</span>'
            elif col == "event_id":
                if val and re.match(r"^[a-zA-Z0-9_-]+$", str(val)):
                    safe_id = html.escape(str(val))
                    cell_content = (
                        f'<a href="#" class="event-link" data-eid="{safe_id}" '
                        f"onclick=\"event.preventDefault();loadEventDrawer('{safe_id}')\">"
                        f"{safe_id[:12]}\u2026</a>"
                    )
                else:
                    cell_content = safe_val
            elif col == "fingerprint" and val:
                if re.match(r"^[a-z0-9_]+$", str(val)):
                    safe_fp = html.escape(str(val))
                    display_fp = (
                        safe_fp if len(safe_fp) <= 30 else f"{safe_fp[:15]}\u2026{safe_fp[-10:]}"
                    )
                    cell_content = f'<a href="/ja4/{safe_fp}" class="fp-link" title="{safe_fp}">{display_fp}</a>'
                else:
                    cell_content = safe_val
            elif col == "decoded" and isinstance(val, dict):
                parts = []
                if val.get("tls_version"):
                    parts.append(
                        f'<span class="decoded-tls">{html.escape(val["tls_version"])}</span>'
                    )
                if val.get("ciphers"):
                    parts.append(f'<span class="decoded-info">{val["ciphers"]}c</span>')
                if val.get("extensions"):
                    parts.append(f'<span class="decoded-info">{val["extensions"]}e</span>')
                if val.get("alpn") and val["alpn"] != "None":
                    parts.append(f'<span class="decoded-alpn">{html.escape(val["alpn"])}</span>')
                if val.get("has_sni") is False:
                    parts.append('<span class="decoded-warn">no-SNI</span>')
                cell_content = " ".join(parts) if parts else "\u2014"
            elif col == "attack_types" and val:
                badges = "".join(
                    f'<span class="attack-badge">{html.escape(t.strip())}</span>'
                    for t in str(val).split(",")
                    if t.strip()
                )
                cell_content = badges or "\u2014"
            elif col == "identified" and val:
                cell_content = f'<span class="identified-threat">{safe_val}</span>'
            elif col == "db_application" and val:
                cell_content = f'<span class="db-app">{safe_val}</span>'
            elif col == "db_verified" and val:
                cell_content = '<span class="verified-badge">\u2713 Verified</span>'
            elif col in ("db_library", "db_device", "db_os") and val:
                cell_content = f'<span class="db-info">{safe_val}</span>'
            elif col == "db_notes" and val:
                short = safe_val[:50] + "\u2026" if len(safe_val) > 50 else safe_val
                cell_content = f'<span class="db-notes" title="{safe_val}">{short}</span>'
            else:
                cell_content = safe_val

            if cell_class:
                cells.append(f'<td class="{cell_class}">{cell_content}</td>')
            else:
                cells.append(f"<td>{cell_content}</td>")

        rows.append(f"<tr>{''.join(cells)}</tr>")

    return f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


# ---------------------------------------------------------------------------
# Stats rendering
# ---------------------------------------------------------------------------


def _generate_stats_html(data: dict) -> str:
    parts = []
    for key, value in data.items():
        safe_key = html.escape(str(key).replace("_", " ").title())
        if isinstance(value, list):
            table = _generate_table_html(value, "stats")
            parts.append(f'<div class="stat-card"><h3>{safe_key}</h3>{table}</div>')
        elif isinstance(value, (int, float)):
            parts.append(
                f'<div class="stat-card"><h3>{safe_key}</h3>'
                f'<div class="stat-value">{value:,}</div></div>'
            )
        else:
            parts.append(
                f'<div class="stat-card"><h3>{safe_key}</h3>'
                f"<pre>{html.escape(json.dumps(value, indent=2, default=str))}</pre></div>"
            )
    return f'<div class="stats-grid">{"".join(parts)}</div>'


# ---------------------------------------------------------------------------
# Single record rendering
# ---------------------------------------------------------------------------


def _generate_record_html(data: dict) -> str:
    rows = []
    for key, value in data.items():
        safe_key = html.escape(str(key))
        if isinstance(value, (dict, list)):
            val_html = f"<pre>{html.escape(json.dumps(value, indent=2, default=str))}</pre>"
        elif key == "attack_types" and value:
            badges = "".join(
                f'<span class="attack-badge">{html.escape(t.strip())}</span>'
                for t in str(value).split(",")
                if t.strip()
            )
            val_html = badges
        else:
            val_html = html.escape(str(value)) if value is not None else "\u2014"
        rows.append(f"<tr><th>{safe_key}</th><td>{val_html}</td></tr>")
    return f'<table class="record-table">{"".join(rows)}</table>'


_SECTION_HEAD = (
    '<div style="font-size:11px;font-weight:700;color:var(--accent);'
    "text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;"
    'border-bottom:1px solid var(--border);padding-bottom:4px">%s</div>'
)
_PRE = (
    "font-size:11px;color:var(--text);max-height:%dpx;overflow:auto;"
    "white-space:pre-wrap;word-break:break-all;background:var(--bg3);"
    "padding:10px;border-radius:6px;font-family:var(--mono)"
)

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}


def http_request_html(meta) -> str:
    """Render the captured request — line, headers, full body — or "" if it is not one.

    The event page used to show `payload`, which for an HTTP honeypot is a one-line
    summary like `POST / body_len=700`, while the 700 bytes themselves were only
    reachable by scrolling a raw-JSON box. Capturing bodies is pointless if reading
    them is this awkward.

    Everything below is attacker-supplied and every piece of it is escaped. A honeypot
    that renders a captured payload unescaped hands the attack to whoever opens the
    page — the one place where that content must never be live.
    """
    if not isinstance(meta, dict) or not meta:
        return ""

    method = str(meta.get("method") or "")
    if method.upper() not in _HTTP_METHODS:
        return ""

    path = str(meta.get("path") or "")
    parts = [_SECTION_HEAD % "HTTP Request"]
    parts.append(f'<pre style="{_PRE % 80}">{html.escape(method)} {html.escape(path)}</pre>')

    headers = meta.get("headers")
    if isinstance(headers, dict) and headers:
        lines = "\n".join(
            f"{html.escape(str(k))}: {html.escape(str(v))}" for k, v in headers.items()
        )
        parts.append(_SECTION_HEAD % "Headers")
        parts.append(f'<pre style="{_PRE % 240}">{lines}</pre>')

    body_len = meta.get("body_len")
    sample = meta.get("body_sample")
    sample_b64 = meta.get("body_sample_b64")

    if sample is not None or sample_b64 is not None:
        label = "Body"
        note = ""
        if body_len is not None:
            note = f"{body_len} bytes"
        if meta.get("body_truncated"):
            # Say it plainly: a silently clipped body reads as a complete record.
            note += " — TRUNCATED, stored up to the capture limit"
        if meta.get("body_encoding") == "binary":
            note += " — binary, shown base64-encoded"
        if note:
            label += (
                ' <span style="color:var(--text2);font-weight:400;'
                f'text-transform:none;letter-spacing:0">({html.escape(note)})</span>'
            )
        parts.append(_SECTION_HEAD % label)
        shown = sample if sample is not None else sample_b64
        parts.append(f'<pre style="{_PRE % 520}">{html.escape(str(shown))}</pre>')

    return '<div style="margin-top:16px">' + "".join(parts) + "</div>"


def event_detail_html(data: dict) -> str:
    """Render full event detail page with AI/Hunt action buttons and drawer."""
    eid = html.escape(str(data.get("event_id", "")))
    eid_short = eid[:16] + "..." if len(eid) > 16 else eid
    src_ip = (data.get("src_ip") or "").split("/")[0]
    dst_ip = (data.get("dst_ip") or "").split("/")[0]
    proto = html.escape(str(data.get("protocol") or "").upper())
    ts = html.escape(str(data.get("timestamp") or "")[:19].replace("T", " "))
    attacks = html.escape(str(data.get("attack_types") or ""))
    payload = data.get("payload") or ""
    scan_score = data.get("scan_score")
    ja3 = data.get("ja3") or ""
    country = html.escape(str(data.get("country_code") or "??"))
    source = html.escape(str(data.get("source") or ""))
    meta = data.get("metadata")

    # Action buttons
    actions = (
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">'
        f'<a href="/event_full/{eid}" class="ep-btn" target="_blank">\U0001f4cb Event Details</a>'
        f'<a href="/payload/{eid}" class="ep-btn" target="_blank">\U0001f4c4 Payload</a>'
        f'<a href="/pcap/{eid}" class="ep-btn" target="_blank">\U0001f4e6 PCAP</a>'
        f'<a href="/events_ip/{html.escape(src_ip)}?format=html" class="ep-btn">\U0001f50d IP Events</a>'
        f'<button class="ep-btn" style="cursor:pointer" '
        f'data-eid="{eid}" onclick="aiAnalyze(this.dataset.eid,this)">\U0001f9e0 AI Analyze</button>'
        f'<button class="ep-btn btn-claude" style="cursor:pointer;display:none" '
        f'data-eid="{eid}" onclick="claudeAnalyze(this.dataset.eid,this)">\U0001f52c AI DEEP</button>'
    )
    if src_ip:
        actions += (
            f'<button class="ep-btn" style="cursor:pointer" '
            f'data-ip="{html.escape(src_ip)}" onclick="huntIP(this.dataset.ip,this)">\U0001f3af Hunt IP</button>'
        )
    actions += "</div>"

    # Attack badges
    atk_html = ""
    if attacks:
        badges = "".join(
            f'<span class="attack-badge">{html.escape(t.strip())}</span>'
            for t in attacks.split(",")
            if t.strip()
        )
        atk_html = f"<tr><th>Attack Types</th><td>{badges}</td></tr>"

    # Build detail table
    rows = f'''
    <tr><th>Event ID</th><td style="font-size:10px;word-break:break-all;color:var(--accent)">{eid}</td></tr>
    <tr><th>Timestamp</th><td>{ts}</td></tr>
    <tr><th>Source</th><td>{source}</td></tr>
    <tr><th>Protocol</th><td style="color:var(--accent);font-weight:700">{proto}</td></tr>
    <tr><th>Source IP</th><td><span class="smart-ip" data-ip="{html.escape(src_ip)}" style="color:#f472b6;cursor:pointer;text-decoration:underline">{html.escape(src_ip)}</span>{f" :{data.get('src_port', '')}" if data.get("src_port") else ""}</td></tr>
    <tr><th>Destination</th><td>{html.escape(dst_ip)}{f" :{data.get('dst_port', '')}" if data.get("dst_port") else ""}</td></tr>
    <tr><th>Country</th><td>{country}</td></tr>
    {atk_html}
    '''

    if scan_score is not None:
        rows += f"<tr><th>Scan Score</th><td>{scan_score}</td></tr>"
    if ja3:
        rows += f'<tr><th>JA3</th><td class="fp" style="font-size:10px;color:var(--purple)">{html.escape(ja3)}</td></tr>'
    if data.get("entropy") is not None:
        rows += f"<tr><th>Port Entropy</th><td>{data['entropy']}</td></tr>"
    if data.get("payload_hash"):
        rows += f'<tr><th>Payload Hash</th><td style="font-size:9px;word-break:break-all">{html.escape(str(data["payload_hash"]))}</td></tr>'

    # Metadata
    meta_html = ""
    if meta and isinstance(meta, dict):
        import json as _j

        meta_html = f'<tr><th>Metadata</th><td><pre style="font-size:10px;color:var(--text2);max-height:200px;overflow:auto">{html.escape(_j.dumps(meta, indent=2, default=str))}</pre></td></tr>'

    # The captured request itself: line, headers, full body. Empty for anything that
    # is not HTTP, so ICS and other protocols are unaffected.
    http_html = http_request_html(meta)

    # Payload — the one-line summary. Demoted to a label under the request above,
    # because on an HTTP honeypot it says "POST / body_len=700" and the 700 bytes
    # are what the reader came for.
    payload_html = ""
    if payload:
        pl = html.escape(str(payload)[:2000])
        heading = "Payload Summary" if http_html else "Payload"
        payload_html = (
            '<div style="margin-top:16px"><div style="font-size:11px;font-weight:700;color:var(--accent);'
            "text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;border-bottom:1px solid var(--border);"
            f'padding-bottom:4px">{heading}</div>'
            f'<pre style="font-size:10px;color:var(--text2);max-height:400px;overflow:auto;'
            f'word-break:break-all;white-space:pre-wrap;background:var(--bg3);padding:10px;border-radius:6px">{pl}</pre></div>'
        )

    # FortiGate details
    fg_html = ""
    if data.get("fortigate_details"):
        import json as _j

        fg = data["fortigate_details"]
        fg_html = (
            '<div style="margin-top:16px"><div style="font-size:11px;font-weight:700;color:var(--orange);'
            "text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;border-bottom:1px solid var(--border);"
            'padding-bottom:4px">FortiGate Details</div>'
            f'<pre style="font-size:10px;color:var(--text2);max-height:200px;overflow:auto">{html.escape(_j.dumps(fg, indent=2, default=str))}</pre></div>'
        )

    # CVE Intelligence panel (Idea 32 — CIRCL enrichment)
    cve_html = ""
    cve_data = data.get("cve_details")
    if isinstance(cve_data, str):
        try:
            import json as _jj

            cve_data = _jj.loads(cve_data)
        except Exception:
            cve_data = None
    if isinstance(cve_data, dict) and cve_data.get("cve_id"):
        cd = cve_data
        cve_id = html.escape(str(cd.get("cve_id", "")))
        score = cd.get("cvss_score")
        sev = cd.get("cvss_severity", "")
        sev_colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
        }
        sc = sev_colors.get(sev, "#64748b")
        kev_banner = ""
        if cd.get("is_kev"):
            kev_banner = (
                '<div style="background:#7f1d1d;border:1px solid #ef4444;border-radius:6px;padding:8px 12px;'
                'margin-bottom:10px;color:#fca5a5;font-size:12px;font-weight:600">'
                "&#x26A0; CISA Known Exploited Vulnerability &mdash; actively exploited in the wild</div>"
            )
        score_html = (
            f'<span style="color:{sc};font-size:18px;font-weight:700">{score}</span> <span style="color:{sc};font-size:11px">{sev}</span>'
            if score
            else "N/A"
        )
        cvss_vec = html.escape(str(cd.get("cvss_vector", "") or ""))
        title = html.escape(str(cd.get("title", "") or "")[:150])
        vendor = html.escape(str(cd.get("vendor", "") or ""))
        product = html.escape(str(cd.get("product", "") or ""))
        cwes = cd.get("cwe", [])
        cwe_tags = " ".join(
            f'<span style="background:#1e293b;border:1px solid #334155;padding:2px 6px;border-radius:3px;font-size:10px;color:#94a3b8">{html.escape(c)}</span>'
            for c in cwes
        )
        refs = cd.get("references", [])[:3]
        refs_html = "".join(
            f'<a href="{html.escape(r)}" target="_blank" style="color:#38bdf8;font-size:10px;display:block;margin-top:2px">{html.escape(r[:80])}</a>'
            for r in refs
            if r
        )
        published = html.escape(str(cd.get("published", "") or ""))

        cve_html = (
            '<div style="margin-top:16px"><div style="font-size:11px;font-weight:700;color:#f87171;'
            "text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;border-bottom:1px solid var(--border);"
            'padding-bottom:4px">CVE Intelligence (CIRCL)</div>'
            f"{kev_banner}"
            '<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px">'
            f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">'
            f'<a href="https://vulnerability.circl.lu/cve/{cve_id}" target="_blank" style="color:#f87171;font-size:16px;font-weight:700;text-decoration:none">{cve_id}</a>'
            f"{score_html}"
            f"</div>"
            f'<div style="color:#e2e8f0;font-size:12px;margin-bottom:6px">{title}</div>'
            f'<div style="font-size:11px;color:#64748b;margin-bottom:4px">'
            f"{'<b>Vendor:</b> ' + vendor + ' &nbsp; <b>Product:</b> ' + product if vendor else ''}"
            f"{'&nbsp; <b>Published:</b> ' + published if published else ''}"
            f"</div>"
            f'<div style="font-size:10px;color:#64748b;margin-bottom:4px">{cvss_vec}</div>'
            f'<div style="margin-bottom:4px">{cwe_tags}</div>'
            f"{refs_html}"
            f'<div style="margin-top:6px"><a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank" '
            f'style="color:#94a3b8;font-size:10px">View on NVD &rarr;</a></div>'
            "</div></div>"
        )

    body = f"""
    <div class="ep-hdr">
      <h2>Event: {eid_short} <span class="ep-endpoint" style="color:var(--accent)">{proto}</span></h2>
    </div>
    {actions}
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden">
      <table class="record-table">{rows}{meta_html}</table>
    </div>
    {cve_html}
    {http_html}
    {payload_html}
    {fg_html}
    """

    # AI Triage section (server-rendered from DB if exists)
    ai_triage = data.get("ai_triage")
    if ai_triage and ai_triage.get("class"):
        _cls_c = {
            "CRITICAL": "#ef4444",
            "SUSPICIOUS": "#f97316",
            "KNOWN": "#38bdf8",
            "NOISE": "#64748b",
        }
        ac = _cls_c.get(ai_triage["class"], "#94a3b8")
        body += '<div class="ai-section"><h4>&#x1F9E0; AI Triage (Ollama)</h4>'
        body += f'<div class="result-row"><div class="result-lbl">Class</div><div class="result-val" style="color:{ac};font-weight:700">{html.escape(ai_triage["class"])}</div></div>'
        if ai_triage.get("confidence"):
            body += f'<div class="result-row"><div class="result-lbl">Confidence</div><div class="result-val">{ai_triage["confidence"]}%</div></div>'
        if ai_triage.get("novelty") is not None:
            body += f'<div class="result-row"><div class="result-lbl">Novelty</div><div class="result-val">{ai_triage["novelty"]}/10</div></div>'
        if ai_triage.get("reasoning"):
            body += f'<div class="result-row"><div class="result-lbl">Reasoning</div><div class="result-val" style="font-size:11px">{html.escape(str(ai_triage["reasoning"])[:500])}</div></div>'
        if ai_triage.get("cve"):
            body += f'<div class="result-row"><div class="result-lbl">CVE</div><div class="result-val" style="color:#f87171">{html.escape(ai_triage["cve"])}</div></div>'
        if ai_triage.get("zero_day") is not None:
            body += f'<div class="result-row"><div class="result-lbl">0-Day Score</div><div class="result-val">{ai_triage["zero_day"]}%</div></div>'
        body += "</div>"

    # Claude current result (from ai_analysis structured columns)
    claude_cur = data.get("claude_current")
    if claude_cur and claude_cur.get("verdict"):
        _vc = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
            "INFO": "#38bdf8",
        }
        vc = _vc.get(claude_cur["verdict"], "#94a3b8")
        body += '<div class="claude-section"><h4>&#x1F52C; Claude Sonnet — Latest Analysis</h4>'
        body += f'<div class="result-row"><div class="result-lbl">Verdict</div><div class="result-val" style="color:{vc};font-weight:700">{html.escape(claude_cur["verdict"])} ({claude_cur.get("confidence", "?")}%)</div></div>'
        if claude_cur.get("attack_type"):
            body += f'<div class="result-row"><div class="result-lbl">Attack Type</div><div class="result-val">{html.escape(str(claude_cur["attack_type"]))}</div></div>'
        if claude_cur.get("technique"):
            body += f'<div class="result-row"><div class="result-lbl">MITRE</div><div class="result-val" style="color:#f87171;font-weight:700">{html.escape(claude_cur["technique"])} — {html.escape(str(claude_cur.get("tactic") or ""))}</div></div>'
        if claude_cur.get("cve"):
            body += f'<div class="result-row"><div class="result-lbl">CVE</div><div class="result-val" style="color:#f87171;font-weight:700">{html.escape(claude_cur["cve"])}</div></div>'
        if claude_cur.get("threat_actor"):
            body += f'<div class="result-row"><div class="result-lbl">Threat Actor</div><div class="result-val" style="color:#ef4444;font-weight:700">{html.escape(claude_cur["threat_actor"])}</div></div>'
        if claude_cur.get("kill_chain"):
            body += f'<div class="result-row"><div class="result-lbl">Kill Chain</div><div class="result-val">{html.escape(claude_cur["kill_chain"])}</div></div>'
        if claude_cur.get("summary"):
            body += f'<div class="result-row"><div class="result-lbl">Summary</div><div class="result-val" style="font-size:11px">{html.escape(str(claude_cur["summary"])[:800])}</div></div>'
        body += "</div>"

    # Claude Analysis History (last 3 from audit log)
    claude_hist = data.get("claude_history", [])
    if claude_hist and len(claude_hist) > 1:
        body += '<div class="claude-section" style="border-color:#d9770633"><h4>&#x1F52C; Claude Analysis History'
        body += f' <span style="color:#64748b;font-weight:400;font-size:11px">({len(claude_hist)} runs)</span></h4>'
        body += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:11px">'
        body += '<thead><tr style="border-bottom:1px solid #334155;color:#64748b;font-size:10px;text-transform:uppercase">'
        body += '<th style="padding:4px 6px">Run</th><th style="padding:4px 6px">Verdict</th>'
        body += '<th style="padding:4px 6px">Attack</th><th style="padding:4px 6px">MITRE</th>'
        body += '<th style="padding:4px 6px">CVE</th><th style="padding:4px 6px">Threat Actor</th>'
        body += '<th style="padding:4px 6px;text-align:left">Summary</th>'
        body += '<th style="padding:4px 6px">Cost</th><th style="padding:4px 6px">Time</th></tr></thead><tbody>'
        _vc_map = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
            "INFO": "#38bdf8",
        }
        for i, ch in enumerate(claude_hist):
            chv = html.escape(str(ch.get("verdict", "")))
            chc = _vc_map.get(ch.get("verdict", ""), "#94a3b8")
            body += '<tr style="border-bottom:1px solid #ffffff08">'
            body += f'<td style="padding:4px 6px;color:#64748b;text-align:center">#{i + 1}</td>'
            body += f'<td style="padding:4px 6px;text-align:center"><span style="color:{chc};font-weight:700">{chv}</span></td>'
            body += f'<td style="padding:4px 6px">{html.escape(str(ch.get("attack_type", "") or "")[:30])}</td>'
            body += f'<td style="padding:4px 6px;color:#f87171">{html.escape(str(ch.get("technique", "") or ""))}</td>'
            body += f'<td style="padding:4px 6px;color:#f87171;font-weight:700">{html.escape(str(ch.get("cve", "") or ""))}</td>'
            body += f'<td style="padding:4px 6px;color:#ef4444">{html.escape(str(ch.get("threat_actor", "") or ""))}</td>'
            body += f'<td style="padding:4px 6px;color:#94a3b8" title="{html.escape(str(ch.get("summary", "") or ""))}">{html.escape(str(ch.get("summary", "") or "")[:60])}</td>'
            cost = ch.get("cost") or 0
            body += f'<td style="padding:4px 6px;color:#64748b;text-align:center">${cost:.3f}</td>'
            body += f'<td style="padding:4px 6px;color:#64748b;white-space:nowrap">{html.escape(str(ch.get("analyzed_at", "") or "")[:16].replace("T", " "))}</td>'
            body += "</tr>"
        body += "</tbody></table></div></div>"

    body += """
    <div id="ai-result-container"></div>
    <div id="claude-result-container"></div>
    <div id="hunt-result-container"></div>
    """

    extra_css = """
.record-table th{text-align:right;width:140px;padding:8px 12px;color:var(--text3);
  font-size:10px;text-transform:uppercase;letter-spacing:.5px;vertical-align:top;
  white-space:nowrap;border-bottom:1px solid #1a2a40}
.record-table td{padding:8px 12px;border-bottom:1px solid #1a2a40;font-size:12px;word-break:break-word}
.attack-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;
  margin:1px;background:#ef444422;color:#f87171;border:1px solid #ef444444}
.fp{color:var(--purple);font-family:monospace}
.ai-section,.hunt-section,.claude-section{margin-top:16px;background:var(--bg2);border:1px solid var(--border);
  border-radius:8px;padding:14px}
.ai-section h4{color:#a78bfa;font-size:12px;margin-bottom:8px}
.hunt-section h4{color:#f59e0b;font-size:12px;margin-bottom:8px}
.claude-section h4{color:#d97706;font-size:12px;margin-bottom:8px}
.result-row{display:flex;gap:8px;padding:3px 0;font-size:12px}
.result-lbl{width:100px;color:var(--text3);font-size:10px;text-transform:uppercase}
.result-val{flex:1}
"""

    js = r"""<script>
function esc(v){return v==null?'':String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

/* Claude availability check */
(function(){
  fetch('/ai/deep-status',{credentials:'same-origin'})
    .then(function(r){return r.json();})
    .then(function(d){
      if(d.available){
        var btns=document.querySelectorAll('.btn-claude');
        for(var i=0;i<btns.length;i++) btns[i].style.display='inline-block';
      }
    }).catch(function(){});
})();

/* Smart IP click — hunted → profile; not hunted → last 10 events */
document.querySelectorAll('.smart-ip').forEach(function(el){
  el.addEventListener('click',function(){
    var ip=this.dataset.ip;
    if(!ip)return;
    fetch('/ip/status/'+encodeURIComponent(ip),{credentials:'same-origin'})
      .then(function(r){return r.json();})
      .then(function(d){
        if(d.hunted) window.location.href='/attacker_hunting/'+encodeURIComponent(ip);
        else window.location.href='/events_ip/'+encodeURIComponent(ip)+'?format=html&limit=10';
      })
      .catch(function(){ window.location.href='/events_ip/'+encodeURIComponent(ip)+'?format=html&limit=10'; });
  });
});

/* Auto-hunt: queue IP for profiling after AI/Claude analysis */
function autoHunt(ip){
  if(!ip)return;
  fetch('/attacker_hunting/'+encodeURIComponent(ip)+'/hunt',{method:'POST',credentials:'same-origin'})
    .then(function(r){return r.json();})
    .then(function(d){
      console.log('Auto-hunt '+ip+': '+(d.status||d.detail||'done'));
    }).catch(function(e){console.log('Auto-hunt failed for '+ip+': '+e);});
}

function aiAnalyze(eventId,btn){
  btn.disabled=true;btn.innerHTML='&#x23F3; Analysing...';btn.style.color='#eab308';
  fetch('/ai/analyze/'+encodeURIComponent(eventId),{method:'POST',credentials:'same-origin'})
    .then(function(r){return r.json();})
    .then(function(data){
      if(data.detail){btn.innerHTML='&#x274C; '+data.detail.substring(0,40);btn.style.color='#ef4444';
        setTimeout(function(){btn.innerHTML='&#x1F9E0; AI Analyze';btn.style.color='#a78bfa';btn.disabled=false;},4000);return;}
      var cls=data.triage_class||'?';
      var cc={'CRITICAL':'#ef4444','SUSPICIOUS':'#f97316','KNOWN':'#38bdf8','NOISE':'#64748b'}[cls]||'#94a3b8';
      btn.innerHTML='&#x1F9E0; '+cls;btn.style.color=cc;btn.disabled=false;
      var c=document.getElementById('ai-result-container');
      if(c){
        var h='<div class="ai-section"><h4>&#x1F9E0; AI Analysis Result</h4>';
        h+='<div class="result-row"><div class="result-lbl">Class</div><div class="result-val" style="color:'+cc+';font-weight:700">'+cls+'</div></div>';
        h+='<div class="result-row"><div class="result-lbl">Confidence</div><div class="result-val">'+(data.confidence||0)+'%</div></div>';
        h+='<div class="result-row"><div class="result-lbl">Novelty</div><div class="result-val">'+(data.novelty_score||0)+'/10</div></div>';
        if(data.reasoning)h+='<div class="result-row"><div class="result-lbl">Reasoning</div><div class="result-val" style="font-size:11px">'+esc(data.reasoning)+'</div></div>';
        if(data.known_cve)h+='<div class="result-row"><div class="result-lbl">CVE</div><div class="result-val" style="color:#f87171">'+esc(data.known_cve)+'</div></div>';
        if(data.zero_day_score!=null)h+='<div class="result-row"><div class="result-lbl">0-Day Score</div><div class="result-val">'+data.zero_day_score+'%</div></div>';
        h+='</div>';
        c.innerHTML=h;
      }
      /* Auto-hunt the source IP after AI analysis */
      var ipEl=document.querySelector('.smart-ip');
      if(ipEl) autoHunt(ipEl.dataset.ip);
    })
    .catch(function(){btn.innerHTML='&#x274C; Error';btn.style.color='#ef4444';
      setTimeout(function(){btn.innerHTML='&#x1F9E0; AI Analyze';btn.style.color='#a78bfa';btn.disabled=false;},4000);});
}

function claudeAnalyze(eventId,btn){
  btn.disabled=true;btn.innerHTML='&#x23F3; Claude...';btn.style.color='#eab308';
  fetch('/ai/deep-analyze/'+encodeURIComponent(eventId),{method:'POST',credentials:'same-origin'})
    .then(function(r){return r.json();})
    .then(function(data){
      if(data.detail||data.error){
        btn.innerHTML='&#x274C; '+(data.detail||data.error||'').substring(0,40);btn.style.color='#ef4444';
        setTimeout(function(){btn.innerHTML='&#x1F52C; AI DEEP';btn.style.color='#d97706';btn.disabled=false;},5000);return;}
      var v=data.verdict||'?';
      var vc={'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e','INFO':'#38bdf8'}[v]||'#94a3b8';
      btn.innerHTML='&#x1F52C; '+v;btn.style.color=vc;btn.disabled=false;
      var c=document.getElementById('claude-result-container');
      if(c){
        var h='<div class="claude-section"><h4>&#x1F52C; Claude Sonnet Deep Analysis</h4>';
        h+='<div class="result-row"><div class="result-lbl">Verdict</div><div class="result-val" style="color:'+vc+';font-weight:700">'+esc(v)+' ('+esc(data.confidence||'?')+'%)</div></div>';
        if(data.attack_type)h+='<div class="result-row"><div class="result-lbl">Attack Type</div><div class="result-val">'+esc(data.attack_type)+'</div></div>';
        if(data.technique)h+='<div class="result-row"><div class="result-lbl">MITRE</div><div class="result-val" style="color:#f87171;font-weight:700">'+esc(data.technique)+' — '+esc(data.tactic||'')+'</div></div>';
        if(data.cve)h+='<div class="result-row"><div class="result-lbl">CVE</div><div class="result-val" style="color:#f87171;font-weight:700">'+esc(data.cve)+'</div></div>';
        if(data.zero_day_probability!=null){
          var zc=data.zero_day_probability>=70?'#ef4444':data.zero_day_probability>=40?'#f97316':'#22c55e';
          h+='<div class="result-row"><div class="result-lbl">0-Day Prob</div><div class="result-val" style="color:'+zc+';font-weight:700">'+data.zero_day_probability+'%</div></div>';
        }
        if(data.kill_chain_phase)h+='<div class="result-row"><div class="result-lbl">Kill Chain</div><div class="result-val">'+esc(data.kill_chain_phase)+'</div></div>';
        if(data.threat_actor)h+='<div class="result-row"><div class="result-lbl">Threat Actor</div><div class="result-val" style="color:#ef4444;font-weight:700">'+esc(data.threat_actor)+'</div></div>';
        h+='<div class="result-row"><div class="result-lbl">Analysis</div><div class="result-val" style="font-size:11px;white-space:pre-wrap">'+esc(data.exploit_analysis||'')+'</div></div>';
        if(data.recommendations&&data.recommendations.length){
          h+='<div class="result-row"><div class="result-lbl">Actions</div><div class="result-val" style="font-size:11px">';
          data.recommendations.forEach(function(r,i){h+='<div>'+(i+1)+'. '+esc(r)+'</div>';});
          h+='</div></div>';
        }
        h+='<div class="result-row"><div class="result-lbl">Summary</div><div class="result-val" style="font-size:11px">'+esc(data.summary||'')+'</div></div>';
        if(data._meta)h+='<div class="result-row"><div class="result-lbl" style="color:#64748b">Cost</div><div class="result-val" style="font-size:10px;color:#64748b">'+esc(data._meta.model)+' — '+(data._meta.input_tokens||0)+' in / '+(data._meta.output_tokens||0)+' out — '+(data._meta.elapsed_ms||0)+'ms</div></div>';
        h+='</div>';
        c.innerHTML=h;
      }
      /* Auto-hunt the source IP after Claude analysis */
      var ipEl=document.querySelector('.smart-ip');
      if(ipEl) autoHunt(ipEl.dataset.ip);
    })
    .catch(function(){btn.innerHTML='&#x274C; Error';btn.style.color='#ef4444';
      setTimeout(function(){btn.innerHTML='&#x1F52C; AI DEEP';btn.style.color='#d97706';btn.disabled=false;},5000);});
}

function huntIP(ip,btn){
  btn.disabled=true;btn.innerHTML='&#x23F3; Hunting...';btn.style.color='#eab308';
  fetch('/attacker_hunting/'+encodeURIComponent(ip)+'/hunt',{method:'POST',credentials:'same-origin'})
    .then(function(r){return r.json();})
    .then(function(data){
      if(data.detail){btn.innerHTML='&#x274C; '+(data.detail||'').substring(0,40);btn.style.color='#ef4444';
        setTimeout(function(){btn.innerHTML='&#x1F3AF; Hunt IP';btn.style.color='#f59e0b';btn.disabled=false;},4000);return;}
      var thr=(data.ai_summary&&data.ai_summary.threat_level)?data.ai_summary.threat_level:(data.threat_level||'DONE');
      var tc={'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e'}[thr]||'#22c55e';
      btn.innerHTML='&#x1F3AF; '+thr;btn.style.color=tc;btn.disabled=false;
      var c=document.getElementById('hunt-result-container');
      if(c){
        var h='<div class="hunt-section"><h4>&#x1F3AF; Attacker Hunt Result</h4>';
        h+='<div class="result-row"><div class="result-lbl">Threat</div><div class="result-val" style="color:'+tc+';font-weight:700">'+esc(thr)+'</div></div>';
        if(data.abuse_score!=null)h+='<div class="result-row"><div class="result-lbl">Abuse Score</div><div class="result-val">'+data.abuse_score+'</div></div>';
        if(data.country)h+='<div class="result-row"><div class="result-lbl">Country</div><div class="result-val">'+esc(data.country)+'</div></div>';
        if(data.asn_org)h+='<div class="result-row"><div class="result-lbl">ASN</div><div class="result-val" style="font-size:10px">'+esc(data.asn_org)+'</div></div>';
        if(data.internal_tags&&data.internal_tags.length)h+='<div class="result-row"><div class="result-lbl">Tags</div><div class="result-val" style="color:#f59e0b">'+data.internal_tags.map(esc).join(', ')+'</div></div>';
        h+='<div class="result-row"><div class="result-lbl">Profile</div><div class="result-val"><a href="/attacker_hunting/'+encodeURIComponent(ip)+'" style="color:#f59e0b" target="_blank">Full Profile &rarr;</a></div></div>';
        h+='</div>';
        c.innerHTML=h;
      }
    })
    .catch(function(){btn.innerHTML='&#x274C; Error';btn.style.color='#ef4444';
      setTimeout(function(){btn.innerHTML='&#x1F3AF; Hunt IP';btn.style.color='#f59e0b';btn.disabled=false;},4000);});
}
</script>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Event: {eid_short}</title>
<style>{SHARED_CSS}{extra_css}</style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
{nav_bar_html("dashboard")}
<main id="main-content" class="page">
{body}
</main>
{js}
</body>
</html>"""
