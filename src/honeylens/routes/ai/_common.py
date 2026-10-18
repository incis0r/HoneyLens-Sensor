"""
routes/ai.py — AI Analysis Routes
====================================
Extracted from api.py (Phase 1 refactor).
26 routes for AI triage, Claude analysis, rule management, cost tracking.
"""

from __future__ import annotations

import html
import json
import logging
import re
from typing import Optional

import psycopg2.extras
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

# Bug fix 2026-05-04: previously imported analyze_event (Sonnet, deep, ~$0.012/event)
# under the name claude_triage_event — every event went through Sonnet at ~4x the
# intended cost. This imports the actual triage_event (Haiku, ~$0.003/event).
from honeylens.analysis.claude_analyzer import is_claude_available
from honeylens.analysis.claude_analyzer import triage_event as claude_triage_event
from honeylens.analysis.rule_validator import validate_rule
from honeylens.database import db_cursor
from honeylens.intelligence.scanner_exclusions import is_known_scanner
from honeylens.routes._helpers import (
    _EVENT_ID_RE,
    db,
    esc,
    html_response,
    valid_event_id,
    wants_html,
)
from honeylens.routes.hunting import _attacker_hunting_tables_exist

_HAS_CLAUDE = True

logger = logging.getLogger("api")


def _ai_not_configured_html():
    from honeylens.webui.dashboard_ai import _ai_not_configured_html

    return _ai_not_configured_html()


def _ai_dashboard_html(data):
    from honeylens.webui.dashboard_ai import _ai_dashboard_html

    return _ai_dashboard_html(data)


def _ai_rules_html():
    from honeylens.webui.dashboard_ai import _ai_rules_html

    return _ai_rules_html()


def ai_subnav(active=""):
    """Shared AI-section secondary nav (see webui.dashboard_ai.ai_subnav)."""
    from honeylens.webui.dashboard_ai import ai_subnav as _s

    return _s(active)


def _ai_subnav(active: str = "stats") -> str:
    """Sub-navigation bar for AI dashboard pages."""
    tabs = [
        ("stats", "/ai/stats", "Overview"),
        ("zero-days", "/ai/zero-days", "Zero-Days"),
        ("cves", "/ai/cves", "CVEs"),
        ("timeline", "/ai/timeline", "Timeline"),
        ("search", "/ai/search", "Search"),
        ("rules", "/ai/rules/suggested", "Rules"),
        ("cost", "/ai/cost", "Cost"),
    ]
    h = '<div style="display:flex;gap:8px;padding:6px 22px;background:var(--bg2);border-bottom:1px solid var(--border);flex-wrap:wrap;">'
    for key, href, label in tabs:
        if key == active:
            h += f'<a class="nav-btn" href="{href}" style="background:var(--accent);color:#000;border-color:var(--accent);">{label}</a>'
        else:
            h += f'<a class="nav-btn" href="{href}">{label}</a>'
    h += "</div>"
    return h


def _zd_colour(score: int) -> str:
    """Colour for a 0-100 zero-day probability."""
    if score >= 90:
        return "#ef4444"
    if score >= 70:
        return "#f97316"
    if score >= 50:
        return "#eab308"
    return "#22c55e"


def _nov_colour(score: int) -> str:
    """Colour for a 0-10 triage novelty score."""
    return {10: "#ef4444", 9: "#ef4444", 8: "#f97316", 7: "#eab308", 6: "#22c55e"}.get(
        int(score or 0), "#94a3b8"
    )


def _render_candidate_table(request, rows, *, active, subnav_key, title, subtitle, headline):
    """Shared render for the 0-day / high-novelty event tables.

    headline = "zd" (rank by zero_day_score, 0-100) or "novelty" (0-10).
    """
    import html as _h

    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, sortable_table_js

    def e(v) -> str:
        """Escape anything that reached us from the event store or from a model.

        `suggested_rule_name`, `known_cve` and `triage_class` are fields the AI analyzer
        writes straight from the model's parsed response (`store_deep_result` passes
        `result.get(...)` through unvalidated), and the model's input is the attacker's
        payload. So these columns carry attacker-influenced text, and rendering them raw
        put script into the analyst's page. The CSP shipped on 2026-10-18 does not save us
        here: `script-src` still carries `'unsafe-inline'` for the dashboards' inline
        handlers, which is exactly the case it cannot block.
        """
        return _h.escape(str(v if v is not None else ""))

    hcol = "0-Day Score" if headline == "zd" else "Novelty"
    page = f"""<!DOCTYPE html><html><head><title>{_h.escape(title)}</title>
<style>{SHARED_CSS}</style></head><body>{nav_bar_html("ai")}{ai_subnav(active)}
<div style="padding:20px">
<h2 style="color:#e2e8f0;margin-bottom:4px">{_h.escape(title)}</h2>
<p style="color:#64748b;font-size:12px;margin-bottom:16px">{e(subtitle)}</p>
<table><thead><tr><th>{hcol}</th><th>Novelty</th><th>Class</th><th>IP</th><th>Protocol</th><th>Port</th><th>CVE</th><th>Reasoning</th><th>Rule Suggested</th><th>Date</th><th>Details</th></tr></thead><tbody>"""
    for r in rows:
        ns = r.get("novelty_score", 0) or 0
        zd = r.get("zero_day_score")
        if headline == "zd":
            hval = zd if zd is not None else 0
            hc = _zd_colour(hval)
            hcell = f"{hval}"
        else:
            hval = ns
            hc = _nov_colour(ns)
            hcell = f"{ns}"
        nc = _nov_colour(ns)
        ts = (r.get("timestamp") or "")[:16]
        ip_val = r.get("src_ip") or ""
        ip_clean = ip_val.split("/")[0] if "/" in ip_val else ip_val
        eid = r.get("event_id", "")
        page += f'<tr><td style="color:{hc};font-weight:800;font-size:16px;text-align:center">{hcell}</td>'
        page += f'<td style="color:{nc};text-align:center">{ns}</td>'
        page += f'<td><span style="color:{nc}">{e(r.get("triage_class"))}</span></td>'
        page += f'<td><a href="/attacker_hunting/{e(ip_clean)}" style="color:#22d3ee">{e(ip_clean)}</a></td>'
        page += f"<td>{e(r.get('protocol'))}</td><td>{e(r.get('dst_port'))}</td>"
        page += f'<td style="color:#f87171">{e(r.get("known_cve"))}</td>'
        page += f'<td style="font-size:11px;color:#94a3b8;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{_h.escape(str(r.get("triage_reasoning", "") or "")[:120])}</td>'
        page += f'<td style="color:#34d399;font-size:10px">{e(r.get("suggested_rule_name"))}</td>'
        page += f'<td style="color:#64748b;font-size:10px">{e(ts)}</td>'
        page += f'<td><a href="/ai/analysis/{e(eid)}" style="color:#38bdf8;font-size:10px" title="AI analysis">AI</a>'
        page += f' <a href="/event_full/{e(eid)}" style="color:#94a3b8;font-size:10px" title="Full event">Event</a></td></tr>'
    page += f"</tbody></table><p style='color:#64748b;font-size:11px;margin-top:8px'>{len(rows)} events</p>"
    page += f"<script>{sortable_table_js()}</script></div></body></html>"
    return HTMLResponse(page)


def _analysis_detail_html(event_id: str, r: dict, ev: dict) -> str:
    """Render the AI-analysis detail page for a single event."""
    import html as _h
    import json as _j

    from honeylens.webui.shared import SHARED_CSS, nav_bar_html, page_header_html

    cls = (r.get("triage_class") or "").upper()
    kind = {"CRITICAL": "red", "SUSPICIOUS": "orange", "KNOWN": "yellow", "NOISE": "text3"}.get(
        cls, "text3"
    )
    nov = r.get("novelty_score")
    zd = r.get("zero_day_score")
    ip = (ev.get("src_ip") or "").split("/")[0]

    meta = []
    if nov is not None:
        meta.append(f"Novelty {nov}/10")
    if zd is not None:
        meta.append(f"0-Day {zd}/100")
    if r.get("triage_model"):
        meta.append(f"triage: {r['triage_model']}")
    if r.get("deep_model"):
        meta.append(f"deep: {r['deep_model']}")
    if r.get("timestamp"):
        meta.append(str(r["timestamp"])[:19])
    hdr = page_header_html(
        "AI Analysis",
        eyebrow="Investigate · AI",
        description=f"Event {event_id[:16]}…",
        status=(cls or "—", kind),
        metadata=meta,
    )

    def block(title, body, colour="#c5cdd8"):
        if body is None or body == "":
            return ""
        return (
            f'<div style="margin:14px 0"><div style="color:#64748b;'
            f"font-size:11px;text-transform:uppercase;letter-spacing:.5px;"
            f'margin-bottom:4px">{title}</div><div style="color:{colour};'
            f"font-size:13px;line-height:1.5;white-space:pre-wrap;"
            f'word-break:break-word">{body}</div></div>'
        )

    def jblock(title, val):
        if not val:
            return ""
        try:
            txt = _j.dumps(val, indent=2, default=str)
        except (TypeError, ValueError):
            txt = str(val)
        return block(
            title, f'<code style="font-size:11px">{_h.escape(txt)}</code>', colour="#94a3b8"
        )

    parts = [hdr, '<div style="padding:0 20px 24px">']

    # Event context + navigation
    ctx = []
    if ev.get("protocol"):
        ctx.append(f"{_h.escape(str(ev['protocol']))}")
    if ev.get("dst_port"):
        ctx.append(f"port {_h.escape(str(ev['dst_port']))}")
    if ip:
        ctx.append(
            f'<a href="/attacker_hunting/{_h.escape(ip)}" style="color:#22d3ee">{_h.escape(ip)}</a>'
        )
    if ev.get("attack_types"):
        ctx.append(_h.escape(str(ev["attack_types"])))
    parts.append(
        '<div style="color:#8899aa;font-size:12px;margin:8px 0 4px">' + " · ".join(ctx) + "</div>"
    )
    parts.append(
        f'<div style="margin-bottom:12px"><a href="/event_full/{event_id}" '
        f'style="color:#38bdf8;font-size:12px">Full event ›</a> &nbsp; '  # noqa: RUF001 — celowy glif w HTML
        f'<a href="/ai/zero-days" style="color:#64748b;font-size:12px">‹ 0-Day Candidates</a></div>'  # noqa: RUF001 — celowy glif w HTML
    )

    parts.append(block("Triage reasoning", _h.escape(str(r.get("triage_reasoning") or ""))))
    if r.get("known_cve"):
        parts.append(block("Known CVE", _h.escape(str(r["known_cve"])), colour="#f87171"))
    parts.append(
        block("Deep verdict", _h.escape(str(r.get("claude_verdict") or "")), colour="#f472b6")
    )
    parts.append(block("Attack type", _h.escape(str(r.get("claude_attack_type") or ""))))
    parts.append(block("Deep summary", _h.escape(str(r.get("claude_summary") or ""))))
    parts.append(jblock("Deep analysis", r.get("deep_analysis")))
    parts.append(jblock("Triage IOCs", r.get("triage_iocs")))
    if r.get("suggested_rule_name") or r.get("suggested_rule_regex"):
        parts.append(
            block(
                "Suggested rule",
                _h.escape(str(r.get("suggested_rule_name") or ""))
                + "<br>"
                + '<code style="font-size:11px;color:#94a3b8">'
                + _h.escape(str(r.get("suggested_rule_regex") or ""))
                + "</code>",
                colour="#34d399",
            )
        )
    parts.append(block("MITRE", _h.escape(str(r.get("suggested_mitre") or ""))))
    if ev.get("payload"):
        parts.append(
            block(
                "Payload (first 2 KB)",
                f'<code style="font-size:11px;color:#94a3b8">'
                f"{_h.escape(str(ev['payload']))}</code>",
            )
        )

    # Raw row (everything, collapsible)
    rows_html = ""
    for k in sorted(r.keys()):
        v = r[k]
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (dict, list)):
            try:
                v = _j.dumps(v, default=str)
            except (TypeError, ValueError):
                v = str(v)
        rows_html += (
            f'<tr><td style="color:#64748b;padding:2px 12px 2px 0;'
            f'vertical-align:top">{_h.escape(k)}</td>'
            f'<td style="color:#94a3b8;word-break:break-word">'
            f"{_h.escape(str(v)[:2000])}</td></tr>"
        )
    parts.append(
        f'<details style="margin-top:16px"><summary style="color:#64748b;'
        f'font-size:12px;cursor:pointer">Raw analysis record</summary>'
        f'<table style="margin-top:8px;font-size:12px">{rows_html}</table></details>'
    )

    parts.append("</div>")
    return (
        f"<!DOCTYPE html><html><head><title>AI Analysis {event_id[:12]}</title>"
        f"<style>{SHARED_CSS}</style></head><body>{nav_bar_html('ai')}"
        f'{ai_subnav("candidates")}<main id="main-content" class="page">'
        + "".join(parts)
        + "</main></body></html>"
    )


def _infer_attack_type(rule_name: str) -> str:
    """Infer attack_type from rule_name patterns. Always returns UPPERCASE."""
    name = rule_name.lower()
    mapping = [
        ("sqli", "SQLI"),
        ("xss", "XSS"),
        ("rce", "RCE"),
        ("lfi", "LFI"),
        ("rfi", "RFI"),
        ("cmd", "RCE"),
        ("ssrf", "SSRF"),
        ("xxe", "XXE"),
        ("deserial", "RCE"),
        ("brute", "CREDENTIAL"),
        ("cred", "CREDENTIAL"),
        ("scan", "SCANNER"),
        ("enum", "SCANNER"),
        ("traversal", "LFI"),
        ("log4", "LOG4SHELL"),
        ("cve", "CVE_EXPLOIT"),
        ("overflow", "RCE"),
        ("inject", "SQLI"),
        ("exploit", "CVE_EXPLOIT"),
        ("ssti", "SSTI"),
        ("crlf", "CRLF"),
        ("ldap", "LDAPI"),
        ("shellshock", "SHELLSHOCK"),
        ("proto", "PROTO_ABUSE"),
        ("php", "PHP"),
        ("session", "CREDENTIAL"),
    ]
    for pattern, atype in mapping:
        if pattern in name:
            return atype
    return "AI_DETECTED"


def _severity_from_triage(triage_class: str, novelty: int) -> str:
    """Map AI triage class + novelty to severity."""
    cls = (triage_class or "").upper()
    if cls == "CRITICAL":
        return "CRITICAL"
    if cls == "SUSPICIOUS" and novelty and novelty >= 7:
        return "HIGH"
    if cls == "SUSPICIOUS":
        return "HIGH"
    return "MEDIUM"


__all__ = [
    "_EVENT_ID_RE",
    "_HAS_CLAUDE",
    "APIRouter",
    "HTMLResponse",
    "HTTPException",
    "JSONResponse",
    "Optional",
    "Request",
    "_ai_dashboard_html",
    "_ai_not_configured_html",
    "_ai_rules_html",
    "_ai_subnav",
    "_analysis_detail_html",
    "_attacker_hunting_tables_exist",
    "_infer_attack_type",
    "_nov_colour",
    "_render_candidate_table",
    "_severity_from_triage",
    "_zd_colour",
    "ai_subnav",
    "claude_triage_event",
    "db",
    "db_cursor",
    "esc",
    "html",
    "html_response",
    "is_claude_available",
    "is_known_scanner",
    "json",
    "logger",
    "logging",
    "psycopg2",
    "re",
    "valid_event_id",
    "validate_rule",
    "wants_html",
]
