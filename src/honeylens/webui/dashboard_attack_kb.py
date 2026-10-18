"""
webui/dashboard_attack_kb.py — Attack Knowledge Base Pages (Idea 27)
=====================================================================
Renders /attack/info/{type} detail pages and /attack/kb list page.
Uses shared CSS, nav bar, and drawer for consistency.
"""

from __future__ import annotations

import json

from honeylens.webui.shared import SHARED_CSS, drawer_html, esc, nav_bar_html, page_header_html

_KB_CSS = """
/* Knowledge Base specific styles */
.kb-header{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.kb-title{font-size:18px;font-weight:700;color:var(--text)}
.kb-badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:10px;font-weight:700;text-transform:uppercase}
.kb-badge-cat{background:var(--bg3);border:1px solid var(--border);color:var(--accent)}
.kb-badge-sev{border:1px solid}
.sev-critical{background:#dc262620;border-color:#dc2626;color:#ef4444}
.sev-high{background:#d9770620;border-color:#d97706;color:#f59e0b}
.sev-medium{background:#ca8a0420;border-color:#ca8a04;color:#eab308}
.sev-low{background:#16a34a20;border-color:#16a34a;color:#22c55e}
.sev-info{background:#0891b220;border-color:#0891b2;color:#22d3ee}

.kb-section{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:14px}
.kb-section h4{font-size:13px;font-weight:700;color:var(--accent);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.kb-section p,.kb-section li{font-size:12px;line-height:1.7;color:var(--text2)}

.kb-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:14px}
.kb-stat{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center}
.kb-stat .val{font-size:20px;font-weight:700;color:var(--accent)}
.kb-stat .lbl{font-size:10px;color:var(--text2);margin-top:2px}
.kb-trend-up{color:#22c55e}
.kb-trend-down{color:#ef4444}

.kb-cve-row{display:grid;grid-template-columns:140px 1fr 70px 50px;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);font-size:11px;align-items:center}
.kb-cve-row:last-child{border-bottom:none}
.kb-cve-id{font-family:var(--mono);color:var(--accent);font-weight:600}

.kb-payload{background:var(--bg1);border:1px solid var(--border);border-radius:6px;padding:10px;font-family:var(--mono);font-size:11px;color:var(--text2);margin:6px 0;overflow-x:auto;white-space:pre-wrap;word-break:break-all}

.kb-mitre-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-family:var(--mono);font-weight:600;background:#8b5cf620;border:1px solid #8b5cf644;color:#a78bfa;margin:2px 4px 2px 0}

.kb-ref{font-size:11px;color:var(--accent);text-decoration:none}
.kb-ref:hover{text-decoration:underline}

.kb-list-row{display:grid;grid-template-columns:140px 1fr 80px 80px 100px;gap:10px;padding:10px 12px;border-bottom:1px solid var(--border);font-size:12px;align-items:center}
.kb-list-row:hover{background:var(--bg3)}
.kb-list-row a{color:var(--accent);text-decoration:none;font-weight:600}
.kb-list-row a:hover{text-decoration:underline}
"""


def _sev_class(sev):
    return f"sev-{(sev or 'info').lower()}"


def _trend_html(val):
    if val is None:
        return '<span style="color:var(--text2)">—</span>'
    arrow = "↑" if val > 0 else "↓" if val < 0 else "→"
    cls = "kb-trend-up" if val > 0 else "kb-trend-down" if val < 0 else ""
    return f'<span class="{cls}">{arrow} {abs(val):.1f}%</span>'


def attack_kb_detail_html(definition, rules=None, cves=None):
    """Render the full attack type KB detail page."""
    d = definition
    at = esc(d.get("attack_type", "?"))
    name = esc(d.get("display_name", at))
    sev = (d.get("default_severity") or "info").lower()

    # Header
    content = f"""<div class="kb-header">
<span class="kb-title">{name}</span>
<span class="kb-badge kb-badge-cat">{esc(d.get("category") or "—")}</span>
<span class="kb-badge kb-badge-sev {_sev_class(sev)}">{sev.upper()}</span>"""
    if d.get("owasp_category"):
        content += f'<span class="kb-badge kb-badge-cat">{esc(d["owasp_category"])}</span>'
    content += f'<span style="margin-left:auto;font-size:11px;color:var(--text2)">Type: <code>{at}</code></span>'
    content += "</div>"

    # Short description
    content += f'<p style="font-size:13px;color:var(--text);margin-bottom:14px">{esc(d.get("short_description") or "")}</p>'

    # Sensor stats
    content += '<div class="kb-stats">'
    content += f'<div class="kb-stat"><div class="val">{d.get("observed_count") or 0:,}</div><div class="lbl">Events Observed</div></div>'
    content += f'<div class="kb-stat"><div class="val">{d.get("observed_unique_ips") or 0:,}</div><div class="lbl">Unique IPs</div></div>'
    fs = d.get("first_observed")
    ls = d.get("last_observed")
    content += f'<div class="kb-stat"><div class="val" style="font-size:12px">{str(fs)[:10] if fs else "—"}</div><div class="lbl">First Seen</div></div>'
    content += f'<div class="kb-stat"><div class="val" style="font-size:12px">{str(ls)[:10] if ls else "—"}</div><div class="lbl">Last Seen</div></div>'
    content += f'<div class="kb-stat"><div class="val" style="font-size:14px">{_trend_html(d.get("trend_7d"))}</div><div class="lbl">7-day Trend</div></div>'
    content += f'<div class="kb-stat"><div class="val" style="font-size:14px">{_trend_html(d.get("trend_30d"))}</div><div class="lbl">30-day Trend</div></div>'
    content += "</div>"

    # Full description
    if d.get("full_description"):
        content += (
            f'<div class="kb-section"><h4>Overview</h4><p>{esc(d["full_description"])}</p></div>'
        )

    # How it works
    if d.get("how_it_works"):
        content += (
            f'<div class="kb-section"><h4>How It Works</h4><p>{esc(d["how_it_works"])}</p></div>'
        )

    # Impact
    if d.get("impact"):
        content += f'<div class="kb-section"><h4>Impact</h4><p>{esc(d["impact"])}</p></div>'

    # Detection rules — expandable with descriptions
    if rules:
        content += '<div class="kb-section"><h4>Detection Rules (' + str(len(rules)) + ")</h4>"
        for r in rules[:50]:
            rn = esc(r.get("rule_name", ""))
            rs = (r.get("severity") or "medium").lower()
            lh = str(r.get("last_hit") or "—")[:16]
            hits = r.get("hit_count") or 0
            desc = r.get("description") or ""
            regex_exp = r.get("regex_explanation") or ""
            tp_note = r.get("true_positive_note") or ""
            fp_note = r.get("false_positive_note") or ""
            tuning = r.get("tuning_guidance") or ""
            has_detail = bool(desc or regex_exp)

            content += '<details style="margin-bottom:4px;border:1px solid var(--border);border-radius:6px;overflow:hidden">'
            content += '<summary style="padding:8px 12px;cursor:pointer;display:flex;align-items:center;gap:10px;font-size:12px;background:var(--bg3)">'
            content += f'<span style="font-family:var(--mono);color:var(--text);flex:1">{rn}</span>'
            content += f'<span class="kb-badge kb-badge-sev {_sev_class(rs)}" style="font-size:9px">{rs}</span>'
            content += f'<span style="color:var(--text2);font-size:11px;min-width:60px;text-align:right">{hits:,} hits</span>'
            content += f'<span style="color:var(--text2);font-size:10px;min-width:90px;text-align:right">{esc(lh)}</span>'
            content += "</summary>"
            if has_detail:
                content += '<div style="padding:10px 14px;font-size:12px;border-top:1px solid var(--border);background:var(--bg2)">'
                if desc:
                    content += f'<p style="margin-bottom:6px"><b>Description:</b> {esc(desc)}</p>'
                if regex_exp:
                    content += f'<p style="margin-bottom:6px;color:var(--text2)"><b>Regex:</b> {esc(regex_exp)}</p>'
                if tp_note:
                    content += f'<p style="margin-bottom:6px"><b style="color:var(--green)">True Positive:</b> {esc(tp_note)}</p>'
                if fp_note:
                    content += f'<p style="margin-bottom:6px"><b style="color:var(--orange)">False Positive:</b> {esc(fp_note)}</p>'
                if tuning:
                    content += f'<p><b style="color:var(--accent)">Tuning:</b> {esc(tuning)}</p>'
                content += "</div>"
            content += "</details>"
        content += "</div>"

    # MITRE ATT&CK
    mitre_t = d.get("mitre_techniques")
    mitre_tac = d.get("mitre_tactics")
    if mitre_t or mitre_tac:
        if isinstance(mitre_t, str):
            try:
                mitre_t = json.loads(mitre_t)
            except Exception:
                mitre_t = []
        if isinstance(mitre_tac, str):
            try:
                mitre_tac = json.loads(mitre_tac)
            except Exception:
                mitre_tac = []
        content += '<div class="kb-section"><h4>MITRE ATT&amp;CK</h4>'
        if mitre_t:
            content += '<p style="margin-bottom:6px"><b>Techniques:</b> '
            content += " ".join(f'<span class="kb-mitre-badge">{esc(t)}</span>' for t in mitre_t)
            content += "</p>"
        if mitre_tac:
            content += "<p><b>Tactics:</b> " + ", ".join(esc(t) for t in mitre_tac) + "</p>"
        content += "</div>"

    # Notable CVEs
    notable = d.get("notable_cves")
    if isinstance(notable, str):
        try:
            notable = json.loads(notable)
        except Exception:
            notable = []
    if cves or notable:
        all_cves = cves or []
        if not all_cves and notable:
            all_cves = notable
        content += '<div class="kb-section"><h4>Notable CVEs</h4>'
        for c in (all_cves or [])[:10]:
            if isinstance(c, dict):
                cid = esc(c.get("cve_id") or c.get("cve", ""))
                cname = esc(c.get("cve_name") or c.get("name", ""))
                prod = esc(c.get("product", ""))
                note = esc(c.get("description") or c.get("note", ""))
                content += f'<div class="kb-cve-row"><span class="kb-cve-id">{cid}</span><span>{cname} — {prod}</span><span style="font-size:10px;color:var(--text2)">{note[:80]}</span><span></span></div>'
        content += "</div>"

    # Example payloads
    examples = d.get("example_payloads")
    if isinstance(examples, str):
        try:
            examples = json.loads(examples)
        except Exception:
            examples = []
    if examples:
        content += '<div class="kb-section"><h4>Example Payloads (from sensor)</h4>'
        for ex in (examples or [])[:5]:
            p = ex.get("payload", str(ex)) if isinstance(ex, dict) else str(ex)
            content += f'<div class="kb-payload">{esc(p[:300])}</div>'
        content += "</div>"

    # Prevention & Remediation
    if d.get("prevention") or d.get("remediation"):
        content += '<div class="kb-section"><h4>Prevention &amp; Remediation</h4>'
        if d.get("prevention"):
            content += f"<p><b>Prevention:</b> {esc(d['prevention'])}</p>"
        if d.get("remediation"):
            content += f'<p style="margin-top:8px"><b>Remediation:</b> {esc(d["remediation"])}</p>'
        content += "</div>"

    # Threat actors / malware
    actors = d.get("threat_actors")
    malware = d.get("malware_families")
    tools = d.get("tools_used")
    if actors or malware or tools:
        if isinstance(actors, str):
            try:
                actors = json.loads(actors)
            except Exception:
                actors = []
        if isinstance(malware, str):
            try:
                malware = json.loads(malware)
            except Exception:
                malware = []
        if isinstance(tools, str):
            try:
                tools = json.loads(tools)
            except Exception:
                tools = []
        content += '<div class="kb-section"><h4>Threat Context</h4>'
        if actors:
            content += "<p><b>Threat Actors:</b> " + ", ".join(esc(a) for a in actors) + "</p>"
        if malware:
            content += "<p><b>Malware Families:</b> " + ", ".join(esc(m) for m in malware) + "</p>"
        if tools:
            content += "<p><b>Tools Used:</b> " + ", ".join(esc(t) for t in tools) + "</p>"
        content += "</div>"

    # References
    refs = d.get("references_")
    if isinstance(refs, str):
        try:
            refs = json.loads(refs)
        except Exception:
            refs = []
    if refs:
        content += '<div class="kb-section"><h4>References</h4><ul style="padding-left:16px">'
        for ref in (refs or [])[:10]:
            if isinstance(ref, dict):
                title = esc(ref.get("title", ref.get("url", "")))
                url = ref.get("url", "")
                content += f'<li><a class="kb-ref" href="{esc(url)}" target="_blank" rel="noopener">{title}</a></li>'
        content += "</ul></div>"

    # Metadata
    content += '<div style="margin-top:16px;font-size:10px;color:var(--text2);display:flex;gap:16px;flex-wrap:wrap">'
    content += f"<span>Generated by: <b>{esc(d.get('generated_by') or '—')}</b> ({esc(d.get('generated_model') or '—')})</span>"
    content += f"<span>Reviewed: {'Yes' if d.get('analyst_reviewed') else 'No'}</span>"
    content += f"<span>Updated: {str(d.get('updated_at') or '—')[:16]}</span>"
    content += "</div>"

    return _kb_page(f"{name} ({at})", content)


def attack_kb_list_html(types):
    """Render the KB overview page listing all attack types."""
    content = f'<p style="margin-bottom:14px;font-size:13px;color:var(--text2)">{len(types)} attack types in knowledge base</p>'

    content += '<div class="kb-section">'
    content += '<div class="kb-list-row" style="font-weight:700;color:var(--accent);border-bottom:2px solid var(--border)">'
    content += "<span>Type</span><span>Description</span><span>Severity</span><span>Events</span><span>Last Seen</span></div>"

    for t in types:
        at = esc(t.get("attack_type", ""))
        esc(t.get("display_name", at))
        desc = esc((t.get("short_description") or "")[:80])
        sev = (t.get("default_severity") or "info").lower()
        count = t.get("observed_count") or 0
        ls = str(t.get("last_observed") or "—")[:10]
        content += '<div class="kb-list-row">'
        content += f'<a href="/attack/info/{at}">{at}</a>'
        content += f'<span style="color:var(--text2)">{desc}</span>'
        content += f'<span class="kb-badge kb-badge-sev {_sev_class(sev)}" style="font-size:9px">{sev}</span>'
        content += f"<span>{count:,}</span>"
        content += f'<span style="font-size:10px;color:var(--text2)">{esc(ls)}</span>'
        content += "</div>"
    content += "</div>"

    return _kb_page("Attack Knowledge Base", content)


def _kb_page(title, content):
    """Wrap content in the shared page layout."""
    sub_nav = """<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
  <a href="/attack/kb" style="padding:5px 13px;background:var(--bg3);border:1px solid var(--border);border-radius:5px;color:var(--text2);font-size:11px;font-weight:600;text-decoration:none">Knowledge Base</a>
  <a href="/classifier/stats" style="padding:5px 13px;background:var(--bg3);border:1px solid var(--border);border-radius:5px;color:var(--text2);font-size:11px;font-weight:600;text-decoration:none">Classifier Stats</a>
  <a href="/classifier/rules" style="padding:5px 13px;background:var(--bg3);border:1px solid var(--border);border-radius:5px;color:var(--text2);font-size:11px;font-weight:600;text-decoration:none">Rules</a>
  <a href="/attack/types" style="padding:5px 13px;background:var(--bg3);border:1px solid var(--border);border-radius:5px;color:var(--text2);font-size:11px;font-weight:600;text-decoration:none">Attack Types</a>
</div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} — Hybrid Intelligence Sensor</title>
<style>{SHARED_CSS}{_KB_CSS}</style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
{nav_bar_html("akb")}
{page_header_html(title, eyebrow="Investigate", description="Attack Knowledge Base — observed techniques, rules, and CVEs")}
<main id="main-content" class="page">
{sub_nav}
{content}
</main>
{drawer_html()}
</body>
</html>"""
