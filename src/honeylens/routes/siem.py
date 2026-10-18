"""routes/siem.py — Admin /admin/siem Settings page + JSON API.

Exposes the SIEM-forwarder configuration for read-only inspection plus a
rate-limited "test send" button. Admin-only.

Routes:
    GET  /admin/siem                     HTML page (default) or JSON
    GET  /admin/siem/status.json         JSON status snapshot
    POST /admin/siem/test-send           {forwarder: "name"} → run synthetic event
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from honeylens.siem import get_manager
from honeylens.siem.base import make_test_event

logger = logging.getLogger("routes.siem")
router = APIRouter(tags=["Admin / SIEM"])

# Per-process rate limiter for /test-send: max 1/sec/forwarder.
_LAST_TEST_SEND: dict[str, float] = {}
_TEST_SEND_INTERVAL = 1.0


def _admin_only(request: Request) -> None:
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")


def _status_dict() -> dict[str, Any]:
    mgr = get_manager()
    return mgr.status()


@router.get("/admin/siem/status.json")
def siem_status_json(request: Request) -> JSONResponse:
    _admin_only(request)
    logger.info("admin %s viewed SIEM status", getattr(request.state, "user", "unknown"))
    return JSONResponse(_status_dict())


@router.post("/admin/siem/test-send")
def siem_test_send(request: Request, body: dict[str, str]) -> JSONResponse:
    _admin_only(request)
    name = (body or {}).get("forwarder", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="missing 'forwarder'")
    now = time.time()
    last = _LAST_TEST_SEND.get(name, 0.0)
    if (now - last) < _TEST_SEND_INTERVAL:
        retry_after = _TEST_SEND_INTERVAL - (now - last)
        raise HTTPException(status_code=429, detail=f"rate-limited, retry in {retry_after:.1f}s")
    _LAST_TEST_SEND[name] = now
    mgr = get_manager()
    ev = make_test_event(sensor_hostname=mgr.sensor_hostname)
    result = mgr.test_send(name, ev)
    logger.info(
        "admin %s test-send %s → %s",
        getattr(request.state, "user", "unknown"),
        name,
        result.get("ok"),
    )
    return JSONResponse(result)


@router.get("/admin/siem")
def siem_page(request: Request) -> HTMLResponse:
    _admin_only(request)
    logger.info("admin %s viewed /admin/siem", getattr(request.state, "user", "unknown"))
    snap = _status_dict()
    return HTMLResponse(_render(snap))


# ---------------------------------------------------------------------- #
# HTML rendering — minimal, server-side, no JS framework                 #
# ---------------------------------------------------------------------- #

_PAGE_TEMPLATE = """<!doctype html>
<html><head>
<meta charset="utf-8">
<title>SIEM Forwarders — HoneyLens Admin</title>
<style>
  body  {{ font-family: ui-sans-serif, system-ui, sans-serif; background: #0b1220;
          color: #cbd5e1; margin: 0; padding: 24px; }}
  h1    {{ margin: 0 0 16px 0; font-size: 22px; color: #e2e8f0; }}
  .meta {{ color: #94a3b8; font-size: 12px; margin-bottom: 20px; }}
  table {{ border-collapse: collapse; font-size: 13px; width: 100%;
           background: #111820; border: 1px solid #1e2a3a; border-radius: 8px;
           overflow: hidden; }}
  th    {{ background: #1a2230; color: #94a3b8; text-align: left; padding: 8px 12px;
           font-size: 11px; text-transform: uppercase; letter-spacing: .7px; }}
  td    {{ padding: 8px 12px; border-top: 1px solid #1e2a3a; vertical-align: top; }}
  .pill {{ display:inline-block; padding:2px 8px; border-radius:4px;
           font-size:11px; font-weight:600; font-family:monospace; }}
  .ok        {{ background:#22c55e30; color:#22c55e; border:1px solid #22c55e60; }}
  .warn      {{ background:#eab30830; color:#eab308; border:1px solid #eab30860; }}
  .err       {{ background:#ef444430; color:#ef4444; border:1px solid #ef444460; }}
  .neutral   {{ background:#475569; color:#cbd5e1; border:1px solid #64748b; }}
  button {{ background:#22d3ee; color:#0b1220; border:0; padding:4px 10px;
           border-radius:4px; font-size:11px; font-weight:600; cursor:pointer; }}
  button:disabled {{ background:#475569; color:#94a3b8; cursor:not-allowed; }}
  code  {{ background:#1e293b; padding:2px 6px; border-radius:3px; color:#7dd3fc;
           font-size:11px; }}
  .summary {{ display:flex; gap:16px; margin-bottom:16px; }}
  .summary-card {{ background:#111820; border:1px solid #1e2a3a;
                   border-radius:7px; padding:10px 14px; }}
  .summary-card .label {{ font-size:10px; color:#64748b; text-transform:uppercase;
                          letter-spacing:.7px; }}
  .summary-card .value {{ font-size:20px; font-weight:800; color:#e2e8f0; }}
  .empty {{ padding:24px; text-align:center; color:#94a3b8; font-size:13px; }}
</style>
</head><body>

<h1>SIEM Forwarders</h1>
<p class="meta">Sensor hostname: <code>{hostname}</code> &middot;
   Queue depth: <code>{qdepth}/{qsize}</code> &middot;
   Dropped (overflow): <code>{dropped}</code><br>
   Configuration source: <code>SIEM_FORWARDERS_JSON</code> environment variable.
</p>

<div class="summary">
  <div class="summary-card">
    <div class="label">Forwarders</div>
    <div class="value">{n_total}</div>
  </div>
  <div class="summary-card">
    <div class="label">Enabled</div>
    <div class="value" style="color:#22c55e">{n_enabled}</div>
  </div>
  <div class="summary-card">
    <div class="label">Failing</div>
    <div class="value" style="color:#ef4444">{n_failing}</div>
  </div>
</div>

{forwarders_table}

<script>
async function testSend(name) {{
  const btn = document.getElementById('btn-' + name);
  if (!btn) return;
  btn.disabled = true;
  btn.textContent = 'sending...';
  try {{
    const resp = await fetch('/admin/siem/test-send', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ forwarder: name }})
    }});
    const data = await resp.json();
    btn.textContent = data.ok ? 'sent ✓' : 'failed ✗';
    btn.style.background = data.ok ? '#22c55e' : '#ef4444';
    if (!data.ok) alert('Test send failed: ' + (data.error || 'unknown'));
    setTimeout(() => location.reload(), 1500);
  }} catch (e) {{
    btn.textContent = 'error';
    btn.style.background = '#ef4444';
    alert('Request error: ' + e);
  }}
}}
</script>

</body></html>
"""

_TABLE_HEADER = """<table>
<thead><tr>
  <th>Name</th><th>Type</th><th>Endpoint</th><th>Status</th>
  <th>Sent</th><th>Failed</th><th>Last error</th><th>Test</th>
</tr></thead><tbody>
"""

_TABLE_FOOTER = "</tbody></table>"


def _render(snap: dict[str, Any]) -> str:
    forwarders: list[dict[str, Any]] = snap.get("forwarders", []) or []
    n_total = len(forwarders)
    n_enabled = sum(1 for f in forwarders if f.get("enabled"))
    n_failing = sum(1 for f in forwarders if f.get("last_error") and f.get("enabled"))

    if not forwarders:
        body = '<div class="empty">No SIEM forwarders configured. Set <code>SIEM_FORWARDERS_JSON</code> in <code>/opt/sensor/.env</code> and restart sensor-api.</div>'
    else:
        rows = []
        for fw in forwarders:
            name = _safe(fw.get("name", "?"))
            ftype = _safe(fw.get("type", "?"))
            endpoint = _format_endpoint(fw)
            status_pill = _status_pill(fw)
            sent = fw.get("send_count", 0)
            failed = fw.get("fail_count", 0)
            last_err = _safe(fw.get("last_error", ""))[:120] or "—"
            disabled_attr = "" if fw.get("enabled") else "disabled"
            rows.append(
                f"<tr><td><code>{name}</code></td>"
                f"<td>{ftype}</td>"
                f"<td>{endpoint}</td>"
                f"<td>{status_pill}</td>"
                f"<td style='text-align:right'>{sent:,}</td>"
                f"<td style='text-align:right'>{failed:,}</td>"
                f"<td style='color:#ef4444;font-size:11px'>{last_err}</td>"
                f"<td><button id='btn-{name}' onclick=\"testSend('{name}')\" {disabled_attr}>Test</button></td>"
                f"</tr>"
            )
        body = _TABLE_HEADER + "\n".join(rows) + _TABLE_FOOTER

    return _PAGE_TEMPLATE.format(
        hostname=_safe(snap.get("sensor_hostname", "?")),
        qdepth=snap.get("queue_depth", 0),
        qsize=snap.get("queue_size", 0),
        dropped=snap.get("dropped_count", 0),
        n_total=n_total,
        n_enabled=n_enabled,
        n_failing=n_failing,
        forwarders_table=body,
    )


def _safe(s: Any) -> str:
    """HTML-escape a value for safe rendering."""
    import html as _html

    return _html.escape(str(s), quote=True)


def _format_endpoint(fw: dict[str, Any]) -> str:
    t = fw.get("type")
    if t == "syslog":
        return _safe(f"{fw.get('host', '?')}:{fw.get('port', '?')} ({fw.get('transport', '?')})")
    if t == "wazuh":
        return _safe(f"{fw.get('host', '?')}:{fw.get('port', '?')}")
    if t in ("loki", "splunk", "elastic"):
        return _safe(fw.get("base_url", "?"))
    if t == "webhook":
        return _safe(fw.get("url", "?"))
    return "—"


def _status_pill(fw: dict[str, Any]) -> str:
    if not fw.get("enabled"):
        return '<span class="pill neutral">disabled</span>'
    breaker_open = (fw.get("breaker_open_until") or 0) > time.time()
    if breaker_open:
        return '<span class="pill err">circuit&nbsp;open</span>'
    if fw.get("last_error"):
        return '<span class="pill warn">degraded</span>'
    if fw.get("send_count", 0) > 0:
        return '<span class="pill ok">healthy</span>'
    return '<span class="pill neutral">idle</span>'
