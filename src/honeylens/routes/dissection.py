"""routes/dissection.py — Admin /admin/dissection page + JSON API.

Idea 30 Phase 0 — runtime management of the `ebpf_dissection_ports` table.
sensor.py reconciles the BPF map from this table every
EBPF_DISSECTION_RECONCILE_SEC seconds, so adding/removing a port here is
effective without restarting the daemon.

Routes:
    GET    /admin/dissection                List ports (HTML or JSON)
    POST   /admin/dissection/port           Add/update a port
    DELETE /admin/dissection/port/{port}    Disable a port
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from honeylens.database import legacy_get_db
from honeylens.dissection import build_desired_state, quantize_depth

logger = logging.getLogger("routes.dissection")
router = APIRouter(tags=["Admin / eBPF Dissection"])


def _admin_only(request: Request) -> None:
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")


def _wants_json(request: Request) -> bool:
    accept = (request.headers.get("accept") or "").lower()
    return "json" in accept and "html" not in accept


def _fetch_db_rows() -> list[dict[str, Any]]:
    conn = legacy_get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT port, capture_depth, retain_hours, enabled,
               reason, added_by, added_at, updated_at
          FROM ebpf_dissection_ports
         ORDER BY port
    """)
    rows = []
    for r in cur.fetchall():
        rows.append(
            {
                "port": int(r[0]),
                "capture_depth": int(r[1]),
                "retain_hours": int(r[2]),
                "enabled": bool(r[3]),
                "reason": r[4] or "",
                "added_by": r[5] or "",
                "added_at": r[6].isoformat() if r[6] else None,
                "updated_at": r[7].isoformat() if r[7] else None,
            }
        )
    conn.close()
    return rows


def _list_html(rows: list[dict[str, Any]], effective: dict[int, int]) -> str:
    from honeylens.webui.shared import SHARED_CSS, nav_bar_html

    tbody = []
    db_ports = {r["port"]: r for r in rows}
    all_ports = sorted(set(db_ports.keys()) | set(effective.keys()))
    for port in all_ports:
        db = db_ports.get(port)
        eff_depth = effective.get(port)
        if db:
            source = "DB"
            depth = db["capture_depth"]
            enabled = db["enabled"]
            retain = db["retain_hours"]
            reason = db["reason"]
            by = db["added_by"]
        else:
            source = "config"
            depth = eff_depth
            enabled = True
            retain = "-"
            reason = "(from EBPF_DISSECTION_PORTS)"
            by = "-"
        live = "✓" if eff_depth else "·"
        tbody.append(
            f"<tr><td>{port}</td><td>{depth}</td><td>{retain}</td>"
            f'<td style="color:{"#22c55e" if enabled else "#94a3b8"}">{"enabled" if enabled else "disabled"}</td>'
            f"<td>{live}</td><td>{source}</td>"
            f"<td>{reason or ''}</td><td>{by}</td></tr>"
        )
    rows_html = (
        "\n".join(tbody)
        or '<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:20px">No ports configured</td></tr>'
    )
    return f"""<!DOCTYPE html><html><head><title>eBPF Dissection — Admin</title>
<style>{SHARED_CSS}
body {{ background:#0b1219; color:#cbd5e1; font-family: -apple-system, sans-serif; padding:18px }}
table {{ width:100%; border-collapse:collapse; font-size:12px; margin-top:12px }}
th, td {{ padding:6px 10px; border-bottom:1px solid #1e2a3a; text-align:left }}
th {{ color:#64748b; text-transform:uppercase; font-size:10px }}
form input, form select {{ padding:5px 8px; margin-right:8px; background:#0f172a; color:#e2e8f0; border:1px solid #1e2a3a; border-radius:4px }}
form button {{ padding:5px 12px; background:#0ea5e9; color:#fff; border:0; border-radius:4px; cursor:pointer }}
.live-yes {{ color:#22c55e }} .live-no {{ color:#475569 }}
</style></head><body>
{nav_bar_html()}
<h2>eBPF Full Dissection — Port Management</h2>
<p style="color:#94a3b8;font-size:12px">
Idea 30 Phase 0. Listed ports get up to <code>capture_depth</code> bytes of
TCP payload preserved in <code>sensor_events.full_payload</code>. The BPF
map is reconciled every 30s — additions are effective without restart.
The <strong>Live</strong> column shows whether the port is currently
applied in the in-memory map (✓ = yes, · = pending or disabled).
</p>

<form method="POST" action="/admin/dissection/port" style="margin:14px 0; padding:12px; background:#111820; border:1px solid #1e2a3a; border-radius:6px">
  <strong style="color:#22d3ee">Add or update a port:</strong><br>
  <label>Port <input type="number" name="port" min="1" max="65535" required></label>
  <label>Depth
    <select name="capture_depth">
      <option value="256">256 (default)</option>
      <option value="1024">1024</option>
      <option value="4096" selected>4096 (full)</option>
    </select>
  </label>
  <label>Retain hrs <input type="number" name="retain_hours" value="168" min="1" max="8760"></label>
  <label>Reason <input type="text" name="reason" placeholder="CVE / hunt context" size="40"></label>
  <button type="submit">Add/Update</button>
</form>

<table>
<thead><tr><th>Port</th><th>Depth</th><th>Retain (h)</th><th>State</th><th>Live</th><th>Source</th><th>Reason</th><th>By</th></tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</body></html>"""


@router.get("/admin/dissection")
def dissection_list(request: Request):
    _admin_only(request)
    rows = _fetch_db_rows()
    effective = build_desired_state()
    if _wants_json(request):
        return JSONResponse(
            {
                "db_rows": rows,
                "effective": {str(k): v for k, v in effective.items()},
            }
        )
    return HTMLResponse(_list_html(rows, effective))


@router.post("/admin/dissection/port")
async def dissection_add_port(request: Request):
    _admin_only(request)
    body: dict[str, Any] = {}
    ct = (request.headers.get("content-type") or "").lower()
    if "application/json" in ct:
        try:
            body = await request.json()
        except Exception:
            body = {}
    else:
        form = await request.form()
        body = dict(form)

    try:
        port = int(body.get("port", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="port must be an integer") from None
    if not (1 <= port <= 65535):
        raise HTTPException(status_code=400, detail="port out of range")

    try:
        depth = quantize_depth(int(body.get("capture_depth", 4096)))
    except (TypeError, ValueError):
        depth = 4096
    try:
        retain = int(body.get("retain_hours", 168))
    except (TypeError, ValueError):
        retain = 168
    if not (1 <= retain <= 8760):
        retain = 168
    reason = (body.get("reason") or "").strip()[:500]
    added_by = getattr(request.state, "user", "unknown")

    conn = legacy_get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO ebpf_dissection_ports
            (port, capture_depth, retain_hours, enabled, reason, added_by)
        VALUES (%s, %s, %s, TRUE, %s, %s)
        ON CONFLICT (port) DO UPDATE SET
            capture_depth = EXCLUDED.capture_depth,
            retain_hours  = EXCLUDED.retain_hours,
            enabled       = TRUE,
            reason        = EXCLUDED.reason,
            added_by      = EXCLUDED.added_by,
            updated_at    = NOW()
    """,
        (port, depth, retain, reason, added_by),
    )
    conn.commit()
    conn.close()

    logger.info(
        "admin %s set ebpf dissection port=%d depth=%d retain=%dh reason=%r",
        added_by,
        port,
        depth,
        retain,
        reason,
    )
    if _wants_json(request):
        return JSONResponse(
            {"ok": True, "port": port, "capture_depth": depth, "retain_hours": retain}
        )
    # Redirect back to the list page on form submit
    return HTMLResponse(
        '<meta http-equiv="refresh" content="0;url=/admin/dissection">', status_code=303
    )


@router.delete("/admin/dissection/port/{port}")
def dissection_disable_port(request: Request, port: int):
    _admin_only(request)
    if not (1 <= port <= 65535):
        raise HTTPException(status_code=400, detail="port out of range")
    conn = legacy_get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE ebpf_dissection_ports SET enabled=FALSE, updated_at=NOW() WHERE port = %s", (port,)
    )
    n = cur.rowcount
    conn.commit()
    conn.close()
    logger.info(
        "admin %s disabled ebpf dissection port=%d (rows=%d)",
        getattr(request.state, "user", "unknown"),
        port,
        n,
    )
    return JSONResponse({"ok": True, "port": port, "disabled": n > 0})
