"""
webui/shared.py — Shared WebUI Components
==========================================
Foundation module providing unified CSS, navigation, event action buttons,
drawer-based event detail, and security helpers (CSP nonce, CSRF tokens,
input sanitisation) used by all dashboard modules.

Style reference: ICS/OT CERT dashboard (the project's gold standard).

Compatible with Python 3.9+.
"""

from __future__ import annotations

import html as _html
import secrets
from typing import Any

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------


def generate_csp_nonce() -> str:
    """Generate a cryptographic nonce for Content-Security-Policy script-src.

    Called from nowhere yet, on purpose. The policy shipped in
    ``api.AuthMiddleware._add_security_headers`` uses ``'unsafe-inline'`` because the
    dashboards still put behaviour in inline ``onclick=`` attributes, which no nonce can
    cover — and a nonce in ``script-src`` *disables* ``'unsafe-inline'``, so switching
    now would break every one of those handlers at once. This helper, and the ``nonce``
    argument already plumbed through :func:`html_page`, are the second half of the job:
    move the inline handlers to ``addEventListener``, then mint a nonce per request.
    """
    return secrets.token_urlsafe(32)


def generate_csrf_token() -> str:
    """Generate a CSRF token for state-changing forms/buttons."""
    return secrets.token_urlsafe(32)


def esc(value) -> str:
    """Escape value for safe HTML embedding. Handles None and non-string types."""
    if value is None:
        return ""
    s = str(value)
    # Strip NUL bytes and control chars (except newline/tab)
    s = s.replace("\x00", "").replace("\r", "")
    return _html.escape(s, quote=True)


def esc_attr(value) -> str:
    """Escape value for use in HTML attributes (stricter: also escapes newlines)."""
    s = esc(value)
    return s.replace("\n", " ").replace("\t", " ")


def esc_js(value) -> str:
    """Escape value for embedding in JavaScript string literals."""
    s = str(value) if value is not None else ""
    s = s.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\x00", "")
    s = s.replace("<", "\\x3c").replace(">", "\\x3e")
    return s


def validate_ip(ip: str) -> bool:
    """Validate IP address string."""
    import ipaddress

    try:
        ipaddress.ip_address(ip.split("/")[0] if ip and "/" in ip else ip)
        return True
    except (ValueError, AttributeError):
        return False


def strip_cidr(ip: str) -> str:
    """Strip CIDR suffix from PostgreSQL INET cast (e.g. '1.2.3.4/32' → '1.2.3.4')."""
    if ip and "/" in ip:
        return ip.split("/")[0]
    return ip or ""


# ---------------------------------------------------------------------------
# CSS Variables — ICS/OT dark theme (project standard)
# ---------------------------------------------------------------------------

SHARED_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e14;--bg1:#0d131e;--bg2:#111820;--bg3:#1a2230;--bg4:#263045;
  --border:#1e2a3a;--text:#c5cdd8;--text2:#8899aa;--text3:#64748b;
  --accent:#22d3ee;--red:#ef4444;--orange:#f97316;--yellow:#eab308;--green:#22c55e;
  --purple:#a78bfa;--pink:#f472b6;--hunt:#f59e0b;
  --font:'IBM Plex Sans','Segoe UI',system-ui,sans-serif;
  --mono:'JetBrains Mono',Consolas,'Courier New',monospace;
}
html,body{height:100%;background:var(--bg);color:var(--text);
  font-family:var(--font);font-size:13px;
  /* Always reserve the scrollbar gutter so page-to-page content-height changes
     don't alter the viewport width — otherwise the wrapping top nav (.topbar-nav,
     flex-wrap) reflows and items like AKB jump rows/sides between pages. */
  overflow-y:scroll;scrollbar-gutter:stable}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

/* Top bar */
.topbar{background:linear-gradient(90deg,#0a0f1e,#0f2040 50%,#0a1628);
  border-bottom:2px solid var(--border);padding:10px 22px;
  display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100;
  flex-wrap:wrap}
.logo{font-size:18px;font-weight:800;color:var(--accent);white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
.logo span{color:var(--orange)}
.logo-mark{height:22px;width:22px;display:inline-block}
.topbar-nav{display:flex;gap:6px;flex-wrap:wrap;margin-left:14px}
.nav-btn{padding:4px 11px;border-radius:5px;border:1px solid var(--border);
  background:var(--bg3);color:var(--text2);cursor:pointer;font-family:inherit;
  font-size:11px;font-weight:600;text-decoration:none;display:inline-block;
  transition:all .15s;white-space:nowrap}
.nav-btn:hover{background:var(--bg4);color:var(--text);text-decoration:none}
.nav-btn.active{background:var(--accent);color:#000;border-color:var(--accent)}

/* Grouped navigation (WEBUI_NEW_SHELL) — five product areas as native
   <details> disclosures: open on click (reliable across browsers + touch),
   keyboard-accessible, no JS. Also opens on hover as a mouse enhancement. */
.nav-areas{display:flex;gap:4px;margin:0 0 0 14px;flex-wrap:wrap;align-items:center}
.navgrp{position:relative}
summary.nav-area{list-style:none;padding:5px 12px;border-radius:5px;
  border:1px solid var(--border);background:var(--bg3);color:var(--text2);
  font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap;user-select:none;
  display:inline-flex;align-items:center;gap:5px}
summary.nav-area::-webkit-details-marker{display:none}
summary.nav-area::marker{content:""}
summary.nav-area::after{content:"▾";font-size:9px;color:var(--text3)}
summary.nav-area:hover,details[open]>summary.nav-area{background:var(--bg4);color:var(--text)}
summary.nav-area.active{color:var(--accent);border-color:var(--accent)}
.nav-menu{position:absolute;top:calc(100% + 5px);left:0;min-width:190px;
  background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:5px;
  z-index:250;box-shadow:0 8px 24px rgba(0,0,0,.5);list-style:none;margin:0}
.nav-item{display:block;padding:6px 10px;border-radius:4px;color:var(--text2);
  font-size:12px;font-weight:600;white-space:nowrap;text-decoration:none}
.nav-item:hover{background:var(--bg4);color:var(--text);text-decoration:none}
.nav-item.active,.nav-item[aria-current=page]{background:var(--accent);color:#000}
.nav-user{margin-left:auto;display:inline;margin:0;padding:0}

/* Accessibility foundations */
.skip-link{position:absolute;left:-9999px;top:0;background:var(--accent);color:#000;
  padding:8px 14px;z-index:300;border-radius:0 0 6px 0;font-weight:700}
.skip-link:focus{left:0}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001ms!important;
    animation-iteration-count:1!important;transition-duration:.001ms!important}
}

/* Shared page header (page_header_html) */
.page-hdr{margin-bottom:16px}
.page-hdr .eyebrow{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--text3);margin-bottom:3px}
.page-hdr .ph-row{display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap}
.page-hdr h1{font-size:19px;font-weight:800;color:var(--text);margin:0}
.page-hdr .ph-actions{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.page-hdr .ph-desc{color:var(--text2);font-size:12px;margin-top:4px}
.page-hdr .ph-meta{display:flex;gap:14px;flex-wrap:wrap;margin-top:6px;font-size:11px;color:var(--text3)}
.btn{padding:5px 13px;border-radius:5px;border:1px solid var(--border);background:var(--bg3);color:var(--text2);cursor:pointer;font-family:inherit;font-size:12px;font-weight:600;text-decoration:none;display:inline-block;transition:all .15s}
.btn:hover{background:var(--bg4);color:var(--text);text-decoration:none}
.btn-accent{background:var(--accent);color:#000;border-color:var(--accent)}

/* Secondary navigation (subnav_html) */
.subnav{display:flex;gap:4px;flex-wrap:nowrap;overflow-x:auto;border-bottom:1px solid var(--border);margin-bottom:14px}
.subnav a{padding:6px 12px;color:var(--text2);font-size:12px;font-weight:600;border-bottom:2px solid transparent;white-space:nowrap;text-decoration:none}
.subnav a:hover{color:var(--text);text-decoration:none}
.subnav a.active,.subnav a[aria-current=page]{color:var(--accent);border-bottom-color:var(--accent)}

/* Page */
.page{padding:18px 22px}

/* KPI grid */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));
  gap:10px;margin-bottom:16px}
.kpi{background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:12px 14px}
.kpi-lbl{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.7px;margin-bottom:5px}
.kpi-val{font-size:24px;font-weight:800;line-height:1}

/* Panels */
.panel{background:var(--bg2);border:1px solid var(--border);border-radius:7px;overflow:hidden;margin-bottom:14px}
.panel-hdr{padding:8px 13px;background:var(--bg3);border-bottom:1px solid var(--border);
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:var(--text2);
  display:flex;justify-content:space-between;align-items:center}
.panel-cnt{color:var(--accent)}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px}

/* Tables */
table{width:100%;border-collapse:collapse}
th{background:var(--bg3);padding:7px 10px;text-align:left;color:var(--text3);
  font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;
  position:sticky;top:0;white-space:nowrap;cursor:pointer;user-select:none}
th:hover{color:var(--text2)}
td{padding:6px 10px;border-bottom:1px solid #1a2a40;font-size:12px;white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:hover td{background:#0e1f35}
.empty{color:var(--text3);text-align:center;padding:20px!important}

/* Cell helpers */
.ip{color:var(--pink);font-family:var(--mono);font-size:12px;cursor:pointer}
.ip:hover{text-decoration:underline}
.port{color:#fbbf24;font-family:var(--mono);font-size:11px}
.mono{font-family:var(--mono);font-size:11px}
.ts{color:var(--text3);font-size:11px}
.dim{color:var(--text3)}
.trunc{max-width:150px;overflow:hidden;text-overflow:ellipsis}

/* Severity / threat pills */
.sev-pill{display:inline-block;padding:2px 7px;border-radius:3px;
  font-size:10px;font-weight:800;border:1px solid}
.tag-pill{display:inline-block;padding:1px 7px;border-radius:8px;font-size:10px;
  background:var(--bg4);color:var(--text2);margin:1px;cursor:pointer}
.tag-pill:hover{background:var(--bg3);color:var(--text)}
.atk-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;
  margin:1px;background:#ef444422;color:#f87171;border:1px solid #ef444444}

/* Filter bar */
.filter-bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;
  padding:9px 12px;background:var(--bg2);border:1px solid var(--border);
  border-radius:7px;margin-bottom:10px}
.filter-bar label{font-size:11px;color:var(--text2)}
select,input[type=text]{background:var(--bg3);border:1px solid var(--border);
  color:var(--text);font-family:inherit;font-size:12px;padding:4px 9px;
  border-radius:4px;outline:none}
select:focus,input:focus{border-color:var(--accent)}

/* Section title */
.sec-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;
  color:var(--text2);border-left:3px solid var(--accent);padding-left:10px;
  margin:18px 0 10px}

/* Drawer (event detail) */
.ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);
  backdrop-filter:blur(2px);z-index:200}
.ov.on{display:block}
.drawer{position:fixed;top:0;right:0;width:min(840px,96vw);height:100vh;
  background:#080f1d;border-left:2px solid var(--border);overflow-y:auto;
  z-index:201;transform:translateX(100%);
  transition:transform .22s cubic-bezier(.4,0,.2,1);display:flex;flex-direction:column}
.drawer.on{transform:translateX(0)}
.drw-hdr{position:sticky;top:0;background:#080f1d;border-bottom:1px solid var(--border);
  padding:11px 18px;display:flex;align-items:center;gap:10px;z-index:1}
.drw-title{font-size:12px;font-weight:700;color:var(--accent);
  text-transform:uppercase;letter-spacing:.7px;flex:1}
.drw-sev{display:inline-block;padding:2px 10px;border-radius:3px;
  font-size:11px;font-weight:800;border:1px solid}
.drw-close{background:var(--bg3);border:1px solid var(--border);color:var(--text2);
  padding:4px 12px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:12px}
.drw-close:hover{background:#ef444420;border-color:#ef444440;color:var(--red)}
.drw-body{padding:15px 18px;flex:1}

/* Drawer sections */
.dsec{margin-bottom:13px;background:var(--bg2);border:1px solid var(--border);
  border-radius:6px;overflow:hidden}
.dhdr{padding:6px 13px;background:var(--bg3);border-bottom:1px solid var(--border);
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:var(--text2);
  display:flex;justify-content:space-between;align-items:center}
.drow{display:grid;grid-template-columns:150px 1fr;padding:6px 13px;
  border-bottom:1px solid #0f1c30;font-size:12px;align-items:start}
.drow:last-child{border-bottom:none}
.drow:hover{background:#0c1829}
.dk{color:var(--text3);font-size:10px;text-transform:uppercase;letter-spacing:.5px;
  padding-top:2px;white-space:nowrap}
.dv{font-family:monospace;color:var(--text);word-break:break-all;line-height:1.5}
.dv a{color:var(--accent);text-decoration:none}
.dv a:hover{text-decoration:underline}

/* Action link buttons */
.drw-actions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:13px}
.act-link{background:var(--bg3);border:1px solid var(--border);padding:4px 11px;
  border-radius:4px;font-size:11px;font-family:monospace;text-decoration:none;
  color:var(--text2);font-weight:600;cursor:pointer}
.act-link.primary{color:var(--accent)}
.act-link:hover{background:var(--bg4);color:var(--text);text-decoration:none}

/* Payload block */
.payload-blk{font-family:monospace;font-size:11px;color:#7db5d8;
  background:#040b16;border:1px solid var(--border);border-radius:4px;
  padding:10px 12px;white-space:pre-wrap;word-break:break-all;
  max-height:180px;overflow-y:auto;line-height:1.5}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bg4);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--border)}

/* Severity colors */
.sev-crit{color:var(--red)}.sev-high{color:var(--orange)}
.sev-med{color:var(--yellow)}.sev-low{color:var(--green)}

/* MITRE links */
.tech-link{color:#f87171;text-decoration:none;font-family:monospace;font-weight:700}
.tech-link:hover{text-decoration:underline}

/* Button states */
.hunt-btn{background:#f59e0b22;border:1px solid var(--hunt);color:var(--hunt);
  padding:3px 10px;border-radius:6px;cursor:pointer;font-size:11px;
  font-family:inherit;white-space:nowrap}
.hunt-btn:hover{background:#f59e0b44}
.hunt-btn:disabled{opacity:0.5;cursor:wait}

/* Responsive */
@media(max-width:900px){
  .two-col{grid-template-columns:1fr}
  .topbar-nav{margin-left:0}
}
"""


# ---------------------------------------------------------------------------
# Navigation bar
# ---------------------------------------------------------------------------

NAV_LINKS = [
    ("dashboard", "/", "Dashboard"),
    ("ics", "/ics/stats", "\U0001f3ed ICS/OT"),
    ("mitre", "/mitre/matrix", "\U0001f3af ATT&CK"),
    ("classifier", "/classifier/stats", "\U0001f4ca Classifier"),
    ("akb", "/attack/kb", "\U0001f4d6 AKB"),
    ("threats", "/classifier/top-threats", "\U0001f525 Threats"),
    ("ai", "/ai/stats", "\U0001f9e0 AI"),
    ("hunting", "/attacker_hunting", "\U0001f3af Hunting"),
    ("mitm", "/mitm", "\U0001f6e1 MiTM"),
    ("ja4", "/ja4/detected", "\U0001f50d JA4"),
    ("cve", "/cve/dashboard", "\U0001f6e1 CVE"),
    ("llm", "/llm/dashboard", "\U0001f916 LLM"),
    ("canary", "/canary/stats", "\U0001f424 AI Canary"),
    (
        "suricata",
        "/suricata/stats",
        '<img src="/suricata/icon.svg" style="height:14px;width:14px;vertical-align:-2px;display:inline-block"> Suricata',
        True,
    ),
    ("archives", "/archive/stats", "\U0001f4e6 Archives"),
    ("admin", "/sensor_admin", "\u2699\ufe0f Admin"),
]


# Grouped navigation taxonomy — the five product areas (WEBUI_NEW_SHELL).
# Keys reference NAV_LINKS above so hrefs/labels stay single-sourced. Every
# NAV_LINKS key must appear in exactly one group (asserted by the nav tests).
NAV_GROUPS = [
    ("overview", "Overview", ["dashboard", "threats"]),
    ("investigate", "Investigate", ["hunting", "mitre", "cve", "akb", "ja4"]),
    ("detection", "Detection", ["classifier", "suricata", "ai", "mitm"]),
    ("deception", "Deception", ["ics", "llm", "canary"]),
    ("operations", "Operations", ["archives", "admin"]),
]


def _logout_form_html() -> str:
    return (
        '<form method="POST" action="/logout" class="nav-user">'
        '<button type="submit" class="nav-btn" style="cursor:pointer;color:#ef4444;'
        'border-color:#ef444444" title="Sign out">\U0001f6aa Logout</button></form>'
    )


def _nav_bar_flat(active: str, version: str) -> str:
    """Legacy flat top navigation (WEBUI_NEW_SHELL off)."""
    h = '<div class="topbar">\n'
    h += '  <div class="logo"><img src="/logo-mark.png" class="logo-mark" alt=""> Honey<span>Lens</span></div>\n'
    if version:
        h += f'  <span style="font-size:10px;color:var(--text3);font-family:var(--mono)">v{esc(version)}</span>\n'
    h += '  <div class="topbar-nav">\n'
    for entry in NAV_LINKS:
        key, href, label = entry[0], entry[1], entry[2]
        raw = entry[3] if len(entry) > 3 else False
        cls = "nav-btn active" if key == active else "nav-btn"
        rendered = label if raw else esc(label)
        h += f'    <a class="{cls}" href="{esc_attr(href)}">{rendered}</a>\n'
    h += "    " + _logout_form_html() + "\n"
    h += "  </div>\n"
    h += "</div>\n"
    return h


def nav_bar_html(active: str = "") -> str:
    """Shared top navigation. Grouped + accessible when WEBUI_NEW_SHELL is on,
    otherwise the legacy flat bar. `active` = nav key of the current page."""
    try:
        from honeylens.version import VERSION
    except Exception:
        VERSION = ""
    from honeylens.config import WEBUI_NEW_SHELL

    if not WEBUI_NEW_SHELL:
        return _nav_bar_flat(active, VERSION)

    links = {e[0]: e for e in NAV_LINKS}
    active_area = ""
    for akey, _alabel, keys in NAV_GROUPS:
        if active in keys:
            active_area = akey
            break

    h = '<nav class="topbar" aria-label="Primary">\n'
    h += '  <a class="logo" href="/" style="text-decoration:none"><img src="/logo-mark.png" class="logo-mark" alt=""> Honey<span>Lens</span></a>\n'
    if VERSION:
        h += f'  <span style="font-size:10px;color:var(--text3);font-family:var(--mono)">v{esc(VERSION)}</span>\n'
    h += '  <div class="nav-areas">\n'
    for akey, alabel, keys in NAV_GROUPS:
        acls = "nav-area active" if akey == active_area else "nav-area"
        h += f'    <details class="navgrp"><summary class="{acls}">{esc(alabel)}</summary>\n'
        h += '      <ul class="nav-menu">\n'
        for k in keys:
            e = links.get(k)
            if not e:
                continue
            key, href, label = e[0], e[1], e[2]
            raw = e[3] if len(e) > 3 else False
            rendered = label if raw else esc(label)
            cur = ' aria-current="page"' if key == active else ""
            icls = "nav-item active" if key == active else "nav-item"
            h += f'        <li><a class="{icls}"{cur} href="{esc_attr(href)}">{rendered}</a></li>\n'
        h += "      </ul>\n    </details>\n"
    h += "  </div>\n"
    h += "  " + _logout_form_html() + "\n"
    h += "</nav>\n"
    return h


# ---------------------------------------------------------------------------
# Page wrapper
# ---------------------------------------------------------------------------


def html_page(
    title: str,
    body: str,
    active_nav: str = "",
    extra_css: str = "",
    extra_head: str = "",
    nonce: str = "",
) -> str:
    """
    Wrap body content in a full HTML page with shared styles, nav bar, and security headers.

    Args:
        title: Page <title>
        body: HTML body content (inside .page div)
        active_nav: Key for active nav button highlighting
        extra_css: Additional CSS to inject
        extra_head: Additional <head> content (e.g. <meta> tags)
        nonce: CSP nonce for inline scripts (if empty, scripts use 'unsafe-inline')
    """
    nonce_attr = f' nonce="{esc_attr(nonce)}"' if nonce else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="strict-origin-when-cross-origin">
<link rel="icon" href="/favicon.ico" type="image/x-icon">
<title>{esc(title)} — HoneyLens</title>
<style{nonce_attr}>{SHARED_CSS}{extra_css}</style>
{extra_head}
</head>
<body>
<a class="skip-link" href="#main-content">Skip to content</a>
{nav_bar_html(active_nav)}
<main id="main-content" class="page">
{body}
</main>
{drawer_html()}
{event_actions_js(nonce)}
{sortable_table_js()}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Page header + secondary navigation (WebUI IA phase 1)
# ---------------------------------------------------------------------------


def page_header_html(title, description="", eyebrow="", status=None, metadata=(), actions=()):
    """Standard page header: eyebrow (product area), title + optional actions,
    description, and status/scope metadata.

    Args:
        title: page title (h1)
        description: one-line purpose/scope
        eyebrow: product-area label shown above the title
        status: (label, kind) e.g. ("Live", "green"); kind is a theme colour name
        metadata: iterable of short strings (time range, last updated, source…)
        actions: iterable of pre-built HTML strings (buttons/links — caller-trusted)
    """
    h = '<div class="page-hdr">'
    if eyebrow:
        h += f'<div class="eyebrow">{esc(eyebrow)}</div>'
    h += '<div class="ph-row"><h1>' + esc(title) + "</h1>"
    if status:
        lbl, kind = status if isinstance(status, (tuple, list)) else (status, "green")
        h += (
            f'<span class="sev-pill" style="color:var(--{esc_attr(kind)});'
            f'border-color:var(--{esc_attr(kind)})">{esc(lbl)}</span>'
        )
    if actions:
        h += '<div class="ph-actions">' + "".join(actions) + "</div>"
    h += "</div>"
    if description:
        h += f'<div class="ph-desc">{esc(description)}</div>'
    if metadata:
        h += (
            '<div class="ph-meta">' + "".join(f"<span>{esc(m)}</span>" for m in metadata) + "</div>"
        )
    h += "</div>"
    return h


def subnav_html(items, active=""):
    """Secondary (section) navigation shown under the page header.

    `items` = iterable of (key, href, label). The entry whose key == `active`
    is marked with aria-current="page"."""
    h = '<nav class="subnav" aria-label="Section">'
    for key, href, label in items:
        cur = ' aria-current="page"' if key == active else ""
        cls = ' class="active"' if key == active else ""
        h += f'<a{cls}{cur} href="{esc_attr(href)}">{esc(label)}</a>'
    h += "</nav>"
    return h


# ---------------------------------------------------------------------------
# Event detail drawer (shared skeleton)
# ---------------------------------------------------------------------------


def drawer_html() -> str:
    """
    Shared drawer HTML skeleton + JS for event detail.
    Appears on all pages that show events. Activated by JS.
    """
    return """
<div class="ov" id="ov" onclick="closeDrawer()"></div>
<div class="drawer" id="drw">
  <div class="drw-hdr">
    <div class="drw-title" id="drwTitle">Event Detail</div>
    <span class="drw-sev" id="drwSev"></span>
    <button class="drw-close" onclick="closeDrawer()">✕ Close</button>
  </div>
  <div class="drw-body" id="drwBody">
    <div style="color:var(--text3);text-align:center;padding:40px">Select an event</div>
  </div>
</div>
"""


# ---------------------------------------------------------------------------
# Sortable table JS (shared across all dashboards)
# ---------------------------------------------------------------------------


def sortable_table_js() -> str:
    """JavaScript that makes ALL <th> in tables sortable — including AJAX-built tables.
    Uses event delegation on document so it works for tables created after page load."""
    return """<script>
(function(){
  function doSort(th){
    var table=th.closest('table');if(!table)return;
    var tbody=table.tBodies[0]||table;
    var rows=Array.from(tbody.rows);
    if(rows.length<1)return;
    var idx=Array.from(th.parentNode.cells).indexOf(th);
    if(idx<0)return;
    var asc=th.dataset.sortDir!=='asc';
    th.dataset.sortDir=asc?'asc':'desc';
    // Reset siblings
    Array.from(th.parentNode.cells).forEach(function(h){h.classList.remove('sorted-asc','sorted-desc');});
    th.classList.add(asc?'sorted-asc':'sorted-desc');
    rows.sort(function(a,b){
      var ac=a.cells[idx],bc=b.cells[idx];
      if(!ac||!bc)return 0;
      var av=ac.textContent.trim(),bv=bc.textContent.trim();
      // Dates (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
      if(/^\\d{4}-\\d{2}-\\d{2}/.test(av)&&/^\\d{4}-\\d{2}-\\d{2}/.test(bv)){var da=new Date(av),db=new Date(bv);if(!isNaN(da)&&!isNaN(db))return asc?da-db:db-da;}
      // Numeric (including comma-separated)
      var an=parseFloat(av.replace(/,/g,'')),bn=parseFloat(bv.replace(/,/g,''));
      if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;
      // IP addresses
      if(/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/.test(av)&&/^\\d{1,3}\\./.test(bv)){
        var ap=av.split('.').map(Number),bp=bv.split('.').map(Number);
        for(var i=0;i<4;i++){var d=(ap[i]||0)-(bp[i]||0);if(d)return asc?d:-d;}
        return 0;
      }
      // Severity ordering
      var sevMap={'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'INFO':0};
      if(sevMap[av]!==undefined&&sevMap[bv]!==undefined)return asc?sevMap[av]-sevMap[bv]:sevMap[bv]-sevMap[av];
      // Text
      return asc?av.localeCompare(bv):bv.localeCompare(av);
    });
    rows.forEach(function(r){tbody.appendChild(r);});
  }
  // Event delegation — works for ALL tables including AJAX-built ones
  document.addEventListener('click',function(e){
    var th=e.target.closest('th');
    if(th&&th.closest('table'))doSort(th);
  });
})();
</script>
<style>
th{cursor:pointer;user-select:none;position:relative;white-space:nowrap;transition:background .15s;}
th:hover{background:rgba(34,211,238,0.12)!important;color:#22d3ee;}
th::after{content:' \\25B4\\25BE';font-size:8px;color:#334155;margin-left:3px;}
th.sorted-asc::after{content:' \\25B2';font-size:10px;color:var(--accent,#22d3ee);}
th.sorted-desc::after{content:' \\25BC';font-size:10px;color:var(--accent,#22d3ee);}
tbody tr:hover,table tr:hover{background:rgba(34,211,238,0.04)!important;}
</style>"""


# ---------------------------------------------------------------------------
# Event action buttons JS (full 6-button set)
# ---------------------------------------------------------------------------


def event_actions_js(nonce: str = "") -> str:
    """
    Shared JavaScript providing:
      - esc() for HTML escaping
      - eventActionButtons(eventId, srcIp) — 6-button bar
      - aiAnalyze(eventId, btn) — AI analysis trigger
      - huntIP(ip, btn) — Attacker hunting trigger
      - openDrawer(eventId, opt) / closeDrawer() — drawer management
      - renderDrawerContent(ev) — render event data in drawer
      - sevColor(s) / sevBg(s) — severity colour helpers

    All fetch() calls use same-origin credentials.
    """
    nonce_attr = f' nonce="{esc_attr(nonce)}"' if nonce else ""
    return f"""<script{nonce_attr}>
/* --- Shared event action functions --- */

/* Check if a deep-analysis backend is available (sets window._claudeAvailable
   — name kept for backward compat across the codebase; the value now reflects
   whichever backend the configured AI_DEEP_BACKEND / .env wiring resolves to). */
window._claudeAvailable = false;
window._aiDeepBackend   = null;   /* "openai" | "claude" | null */
window._aiDeepModel     = null;
fetch('/ai/deep-status', {{credentials:'same-origin'}})
  .then(function(r){{ return r.json(); }})
  .then(function(d){{
    window._claudeAvailable = d.available === true;
    window._aiDeepBackend   = d.backend || null;
    window._aiDeepModel     = d.deep_model || d.model || null;
  }})
  .catch(function(){{ window._claudeAvailable = false; }});

function esc(s) {{
  if (s == null) return '';
  var d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}}

var _sevColors = {{CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#22c55e'}};
var _sevBg     = {{CRITICAL:'#ef444420',HIGH:'#f9731620',MEDIUM:'#eab30820',LOW:'#22c55e20'}};
function sevColor(s) {{ return _sevColors[(s||'').toUpperCase()] || '#94a3b8'; }}
function sevBg(s) {{ return _sevBg[(s||'').toUpperCase()] || '#ffffff10'; }}

function eventActionButtons(eventId, srcIp) {{
  var h = '<div class="drw-actions">';
  h += '<a href="/event_full/' + esc(eventId) + '" target="_blank" class="act-link primary">&#x1F4CB; Event Details</a>';
  h += '<a href="/payload/' + esc(eventId) + '" target="_blank" class="act-link">&#x1F4C4; Payload</a>';
  h += '<a href="/pcap/' + esc(eventId) + '" target="_blank" class="act-link">&#x1F4E6; PCAP</a>';
  h += '<a href="/attack_event/' + esc(eventId) + '" target="_blank" class="act-link">&#x26A0; Attacks</a>';
  h += '<button class="act-link" style="cursor:pointer" '
     + 'onclick="aiAnalyze(\\'' + esc(eventId) + '\\',this)">&#x1F9E0; AI Analyze</button>';
  if (window._claudeAvailable) {{
    h += '<button class="act-link" style="cursor:pointer" '
       + 'onclick="claudeAnalyze(\\'' + esc(eventId) + '\\',this)">&#x1F52C; AI DEEP</button>';
  }}
  if (srcIp) {{
    h += '<button class="act-link" style="cursor:pointer" '
       + 'onclick="huntIP(\\'' + esc(srcIp) + '\\',this)">&#x1F3AF; Hunt IP</button>';
  }}
  h += '</div>';
  return h;
}}

function aiAnalyze(eventId, btn) {{
  btn.disabled = true;
  btn.innerHTML = '&#x23F3; Analysing...';
  btn.style.color = '#eab308';
  fetch('/ai/analyze/' + encodeURIComponent(eventId), {{method:'POST',credentials:'same-origin'}})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      if (data.detail) {{
        btn.innerHTML = '&#x274C; ' + data.detail.substring(0, 40);
        btn.style.color = '#ef4444';
        setTimeout(function() {{ btn.innerHTML = '&#x1F9E0; AI Analyze'; btn.style.color='#a78bfa'; btn.disabled=false; }}, 4000);
        return;
      }}
      var cls = data.triage_class || '?';
      var cc = {{'CRITICAL':'#ef4444','SUSPICIOUS':'#f97316','KNOWN':'#38bdf8','NOISE':'#64748b'}}[cls] || '#94a3b8';
      btn.innerHTML = '&#x1F9E0; ' + cls;
      btn.style.color = cc;
      btn.disabled = false;

      // Append AI result to drawer body
      var drwBody = document.getElementById('drwBody');
      if (drwBody) {{
        var existing = document.getElementById('ai-result-sec');
        if (existing) existing.remove();
        var sec = document.createElement('div');
        sec.id = 'ai-result-sec';
        sec.className = 'dsec';
        var h = '<div class="dhdr">&#x1F9E0; AI Analysis</div>';
        h += '<div class="drow"><div class="dk">Class</div><div class="dv" style="color:'+cc+';font-weight:700">'+esc(cls)+'</div></div>';
        h += '<div class="drow"><div class="dk">Confidence</div><div class="dv">'+(data.confidence||0)+'%</div></div>';
        h += '<div class="drow"><div class="dk">Novelty</div><div class="dv">'+(data.novelty_score||0)+'/10</div></div>';
        h += '<div class="drow"><div class="dk">Reasoning</div><div class="dv" style="font-size:11px">'+esc(data.reasoning||'')+'</div></div>';
        if (data.known_cve) h += '<div class="drow"><div class="dk">CVE</div><div class="dv" style="color:#f87171">'+esc(data.known_cve)+'</div></div>';
        if (data.zero_day_score != null) {{
          var zc = data.zero_day_score >= 70 ? '#ef4444' : data.zero_day_score >= 40 ? '#f97316' : '#22c55e';
          h += '<div class="drow"><div class="dk">0-Day Score</div><div class="dv" style="color:'+zc+';font-weight:700">'+data.zero_day_score+'%</div></div>';
        }}
        if (data.deep_analysis) {{
          var da = data.deep_analysis;
          if (da.exploit_type) h += '<div class="drow"><div class="dk">Exploit</div><div class="dv">'+esc(da.exploit_type)+'</div></div>';
          if (da.attack_objective) h += '<div class="drow"><div class="dk">Objective</div><div class="dv" style="font-size:11px">'+esc(da.attack_objective)+'</div></div>';
          if (da.suggested_rule_name) h += '<div class="drow"><div class="dk">Rule</div><div class="dv" style="color:#a78bfa">'+esc(da.suggested_rule_name)+'</div></div>';
          if (da.summary) h += '<div class="drow"><div class="dk">Summary</div><div class="dv" style="font-size:11px">'+esc(da.summary)+'</div></div>';
        }}
        if (data.iocs && data.iocs.length) h += '<div class="drow"><div class="dk">IOCs</div><div class="dv" style="font-size:10px;color:#f97316">'+data.iocs.map(esc).join(', ')+'</div></div>';
        sec.innerHTML = h;
        drwBody.appendChild(sec);
      }}
    }})
    .catch(function(err) {{
      btn.innerHTML = '&#x274C; Error';
      btn.style.color = '#ef4444';
      setTimeout(function() {{ btn.innerHTML = '&#x1F9E0; AI Analyze'; btn.style.color='#a78bfa'; btn.disabled=false; }}, 4000);
    }});
}}

function huntIP(ip, btn) {{
  btn.disabled = true;
  btn.innerHTML = '&#x23F3; Hunting...';
  btn.style.color = '#eab308';
  fetch('/attacker_hunting/' + encodeURIComponent(ip) + '/hunt', {{method:'POST',credentials:'same-origin'}})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      if (data.detail) {{
        btn.innerHTML = '&#x274C; ' + (data.detail||'').substring(0, 50);
        btn.style.color = '#ef4444';
        setTimeout(function() {{ btn.innerHTML = '&#x1F3AF; Hunt IP'; btn.style.color='#f59e0b'; btn.disabled=false; }}, 4000);
        return;
      }}
      var thr = data.threat_level || '?';
      var tc = {{'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e'}}[thr] || '#94a3b8';
      btn.innerHTML = '&#x1F3AF; ' + thr;
      btn.style.color = tc;
      btn.disabled = false;

      // Append hunt result to drawer body
      var drwBody = document.getElementById('drwBody');
      if (drwBody) {{
        var existing = document.getElementById('hunt-result-sec');
        if (existing) existing.remove();
        var sec = document.createElement('div');
        sec.id = 'hunt-result-sec';
        sec.className = 'dsec';
        var h = '<div class="dhdr">&#x1F3AF; Attacker Hunt Result</div>';
        h += '<div class="drow"><div class="dk">IP</div><div class="dv"><a href="/attacker_hunting/'+esc(ip)+'" target="_blank">'+esc(ip)+'</a></div></div>';
        h += '<div class="drow"><div class="dk">Threat</div><div class="dv" style="color:'+tc+';font-weight:700">'+esc(thr)+'</div></div>';
        h += '<div class="drow"><div class="dk">Intent</div><div class="dv">'+esc(data.intent||'UNKNOWN')+'</div></div>';
        h += '<div class="drow"><div class="dk">Abuse</div><div class="dv">'+(data.abuse_score!=null?data.abuse_score+'/100':'—')+'</div></div>';
        if (data.tags && data.tags.length) {{
          h += '<div class="drow"><div class="dk">Tags</div><div class="dv">';
          data.tags.forEach(function(t){{ h += '<span class="tag-pill">'+esc(t)+'</span> '; }});
          h += '</div></div>';
        }}
        if (data.mitre_techniques && data.mitre_techniques.length) {{
          h += '<div class="drow"><div class="dk">MITRE</div><div class="dv" style="font-size:10px">'+data.mitre_techniques.map(esc).join(', ')+'</div></div>';
        }}
        h += '<div class="drow"><div class="dk">APT Candidates</div><div class="dv">'+(data.apt_candidates||0)+'</div></div>';
        if (data.ai_summary) {{
          h += '<div class="drow"><div class="dk">AI Summary</div><div class="dv" style="font-size:11px">'+esc(data.ai_summary)+'</div></div>';
        }}
        h += '<div style="padding:6px 13px"><a href="/attacker_hunting/'+esc(ip)+'" target="_blank" style="color:var(--hunt);font-size:11px">View Full Profile →</a></div>';
        sec.innerHTML = h;
        drwBody.appendChild(sec);
      }}
    }})
    .catch(function(err) {{
      btn.innerHTML = '&#x274C; Error';
      btn.style.color = '#ef4444';
      setTimeout(function() {{ btn.innerHTML = '&#x1F3AF; Hunt IP'; btn.style.color='#f59e0b'; btn.disabled=false; }}, 4000);
    }});
}}

function claudeAnalyze(eventId, btn) {{
  /* Function name retained for backward compat with inline onclick="" handlers
     across the codebase. The visible label and backend are now backend-agnostic
     ("AI DEEP") and dispatch is decided server-side by /ai/deep-analyze. */
  btn.disabled = true;
  btn.innerHTML = '&#x23F3; AI Deep...';
  btn.style.color = '#eab308';
  fetch('/ai/deep-analyze/' + encodeURIComponent(eventId), {{method:'POST',credentials:'same-origin'}})
    .then(function(r) {{ return r.json(); }})
    .then(function(data) {{
      if (data.detail || data.error) {{
        btn.innerHTML = '&#x274C; ' + (data.detail || data.error || '').substring(0, 40);
        btn.style.color = '#ef4444';
        setTimeout(function() {{ btn.innerHTML = '&#x1F52C; AI DEEP'; btn.style.color='#d97706'; btn.disabled=false; }}, 5000);
        return;
      }}
      var v = data.verdict || '?';
      var vc = {{'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e','INFO':'#38bdf8'}}[v] || '#94a3b8';
      btn.innerHTML = '&#x1F52C; ' + v;
      btn.style.color = vc;
      btn.disabled = false;

      var drwBody = document.getElementById('drwBody');
      if (drwBody) {{
        var existing = document.getElementById('claude-result-sec');
        if (existing) existing.remove();
        var sec = document.createElement('div');
        sec.id = 'claude-result-sec';
        sec.className = 'dsec';
        var _backend = esc(String(data._backend || window._aiDeepBackend || 'AI').toUpperCase());
        var _model   = esc(data._deep_model || window._aiDeepModel || '');
        var h = '<div class="dhdr" style="color:#d97706">&#x1F52C; AI DEEP Analysis ('+_backend+(_model?' &mdash; '+_model:'')+')</div>';
        h += '<div class="drow"><div class="dk">Verdict</div><div class="dv" style="color:'+vc+';font-weight:700">'+esc(v)+' ('+esc(data.confidence||'?')+'% confidence)</div></div>';
        h += '<div class="drow"><div class="dk">Attack Type</div><div class="dv">'+esc(data.attack_type||'\u2014')+'</div></div>';
        if (data.technique) h += '<div class="drow"><div class="dk">MITRE</div><div class="dv"><span class="tech-link">'+esc(data.technique)+'</span> \u2014 '+esc(data.tactic||'')+'</div></div>';
        if (data.cve) h += '<div class="drow"><div class="dk">CVE</div><div class="dv" style="color:#f87171;font-weight:700">'+esc(data.cve)+'</div></div>';
        if (data.zero_day_probability != null) {{
          var zc = data.zero_day_probability >= 70 ? '#ef4444' : data.zero_day_probability >= 40 ? '#f97316' : '#22c55e';
          h += '<div class="drow"><div class="dk">0-Day Prob</div><div class="dv" style="color:'+zc+';font-weight:700">'+data.zero_day_probability+'%</div></div>';
        }}
        if (data.kill_chain_phase) h += '<div class="drow"><div class="dk">Kill Chain</div><div class="dv">'+esc(data.kill_chain_phase)+'</div></div>';
        if (data.threat_actor) h += '<div class="drow"><div class="dk">Threat Actor</div><div class="dv" style="color:var(--red);font-weight:700">'+esc(data.threat_actor)+'</div></div>';
        h += '<div class="drow"><div class="dk">Analysis</div><div class="dv" style="font-size:11px;white-space:pre-wrap">'+esc(data.exploit_analysis||'')+'</div></div>';
        if (data.indicators_of_compromise && data.indicators_of_compromise.length) {{
          h += '<div class="drow"><div class="dk">IOCs</div><div class="dv" style="font-size:10px;color:#f97316">'+data.indicators_of_compromise.map(esc).join('<br>')+'</div></div>';
        }}
        if (data.recommendations && data.recommendations.length) {{
          h += '<div class="drow"><div class="dk">Actions</div><div class="dv" style="font-size:11px">';
          data.recommendations.forEach(function(r,i){{ h += '<div style="margin:2px 0">'+esc((i+1)+'. '+r)+'</div>'; }});
          h += '</div></div>';
        }}
        // "Related CVEs" (the LLM's speculative "related even if not exact" list) is not
        // shown: it attached unrelated/other-vendor CVEs to a single payload (e.g. a
        // FortiManager CVE on a Citrix request). The authoritative CVE is the primary one
        // above, from the rules + the validated verdict.
        h += '<div class="drow"><div class="dk">Summary</div><div class="dv" style="font-size:11px">'+esc(data.summary||'')+'</div></div>';
        if (data._meta) {{
          h += '<div class="drow"><div class="dk">Cost</div><div class="dv dim" style="font-size:10px">'+esc(data._meta.model)+' \u2014 '
            +(data._meta.input_tokens||0)+' in / '+(data._meta.output_tokens||0)+' out tokens \u2014 '
            +(data._meta.elapsed_ms||0)+'ms</div></div>';
        }}
        sec.innerHTML = h;
        drwBody.appendChild(sec);
      }}
    }})
    .catch(function(err) {{
      btn.innerHTML = '&#x274C; Error';
      btn.style.color = '#ef4444';
      setTimeout(function() {{ btn.innerHTML = '&#x1F52C; AI DEEP'; btn.style.color='#d97706'; btn.disabled=false; }}, 5000);
    }});
}}

function openDrawer() {{
  document.getElementById('drw').classList.add('on');
  document.getElementById('ov').classList.add('on');
}}

function closeDrawer() {{
  document.getElementById('drw').classList.remove('on');
  document.getElementById('ov').classList.remove('on');
}}

function renderDrawerEvent(ev) {{
  var sev = (ev.severity || ev.ai_threat_level || ev.scan_score > 0.7 ? 'HIGH' : 'LOW').toUpperCase();
  var eid = ev.event_id || '';
  var srcIp = ev.src_ip || '';

  document.getElementById('drwTitle').textContent = 'Event ' + eid.substring(0,16) + '…';
  var sevEl = document.getElementById('drwSev');
  sevEl.textContent = sev;
  sevEl.style.cssText = 'color:'+sevColor(sev)+';background:'+sevBg(sev)+';border-color:'+sevColor(sev)+'44;';

  var h = '';
  h += eventActionButtons(eid, srcIp);

  // Overview section
  h += '<div class="dsec"><div class="dhdr">Overview</div>';
  var fields = [
    ['Event ID', eid],
    ['Timestamp', ev.timestamp || ''],
    ['Source', ev.source || ''],
    ['Protocol', (ev.protocol||'').toUpperCase()],
    ['Src IP', srcIp],
    ['Src Port', ev.src_port],
    ['Dst IP', ev.dst_ip || ''],
    ['Dst Port', ev.dst_port],
    ['Scan Score', ev.scan_score],
    ['Entropy', ev.port_entropy || ev.entropy],
    ['JA3', ev.ja3 || ''],
    ['Attack Types', ev.attack_types || ''],
  ];
  for (var i=0; i<fields.length; i++) {{
    var k=fields[i][0], v=fields[i][1];
    if (v == null || v === '') continue;
    var vs = esc(String(v));
    if (k === 'Src IP') vs = '<span class="ip" onclick="closeDrawer();location.href=\\'/events_ip/'+esc(srcIp)+'\\'">'+esc(srcIp)+'</span>';
    if (k === 'Protocol') vs = '<span style="color:var(--accent);font-weight:700">'+esc((ev.protocol||'').toUpperCase())+'</span>';
    h += '<div class="drow"><div class="dk">'+esc(k)+'</div><div class="dv">'+vs+'</div></div>';
  }}
  h += '</div>';

  // Payload section
  if (ev.payload) {{
    h += '<div class="dsec"><div class="dhdr">Payload</div>';
    h += '<div class="payload-blk">' + esc((ev.payload||'').substring(0,2000)) + '</div>';
    h += '</div>';
  }}

  document.getElementById('drwBody').innerHTML = h;
  openDrawer();
}}
</script>"""


# ---------------------------------------------------------------------------
# Helper: KPI card generation
# ---------------------------------------------------------------------------


def kpi_html(items: list[tuple[str, Any, str]]) -> str:
    """
    Generate KPI grid cards.
    items: list of (label, value, colour)
    """
    h = '<div class="kpi-grid">'
    for label, val, color in items:
        fval = f"{val:,}" if isinstance(val, (int, float)) else esc(str(val))
        h += (
            f'<div class="kpi"><div class="kpi-lbl">{esc(label)}</div>'
            f'<div class="kpi-val" style="color:{esc_attr(color)}">{fval}</div></div>'
        )
    h += "</div>"
    return h


# ---------------------------------------------------------------------------
# Helper: Severity badge
# ---------------------------------------------------------------------------


def severity_badge(sev: str) -> str:
    """Render a colour-coded severity/threat badge."""
    s = (sev or "UNKNOWN").upper()
    colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
        "UNKNOWN": "#64748b",
    }
    bgs = {
        "CRITICAL": "#ef444422",
        "HIGH": "#f9731622",
        "MEDIUM": "#eab30822",
        "LOW": "#22c55e22",
        "UNKNOWN": "#64748b22",
    }
    c = colors.get(s, "#64748b")
    b = bgs.get(s, "#64748b22")
    return f'<span class="sev-pill" style="color:{c};background:{b};border-color:{c}44">{esc(s)}</span>'


# ---------------------------------------------------------------------------
# Helper: Data table
# ---------------------------------------------------------------------------


def data_table(columns: list[str], rows: list[list[Any]], empty_msg: str = "No data") -> str:
    """
    Generate a styled data table.
    columns: header labels
    rows: list of lists (same length as columns)
    """
    h = "<table><thead><tr>"
    for col in columns:
        h += f"<th>{esc(col)}</th>"
    h += "</tr></thead><tbody>"
    if not rows:
        h += f'<tr><td colspan="{len(columns)}" class="empty">{esc(empty_msg)}</td></tr>'
    else:
        for row in rows:
            h += "<tr>"
            for cell in row:
                # If cell is already HTML (starts with <), don't escape
                cell_str = str(cell) if cell is not None else ""
                if cell_str.startswith("<"):
                    h += f"<td>{cell_str}</td>"
                else:
                    h += f"<td>{esc(cell_str)}</td>"
            h += "</tr>"
    h += "</tbody></table>"
    return h


# ---------------------------------------------------------------------------
# Helper: Panel card
# ---------------------------------------------------------------------------


def panel(title: str, content: str, count: int | None = None) -> str:
    """Wrap content in an ICS-style panel card."""
    cnt = f'<span class="panel-cnt">{count:,}</span>' if count is not None else ""
    return f'<div class="panel"><div class="panel-hdr">{esc(title)}{cnt}</div>{content}</div>'


# ---------------------------------------------------------------------------
# Not configured placeholder
# ---------------------------------------------------------------------------


def not_configured_html(
    title: str, icon: str, message: str, hint: str = "", active_nav: str = ""
) -> str:
    """Render a 'not configured' placeholder page."""
    body = (
        f'<div style="text-align:center;padding:60px 20px">'
        f'<div style="font-size:3rem">{icon}</div>'
        f'<h2 style="color:var(--orange);margin:16px 0">{esc(title)}</h2>'
        f'<p style="color:var(--text2)">{esc(message)}</p>'
    )
    if hint:
        body += f'<p style="color:var(--text3);margin-top:8px"><code>{esc(hint)}</code></p>'
    body += "</div>"
    return html_page(title, body, active_nav)
