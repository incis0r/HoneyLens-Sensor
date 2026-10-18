"""
routes/_helpers.py — Shared helpers for all route modules
==========================================================
Extracted from api.py to eliminate duplication across route modules.
These are internal helpers, not API endpoints.
"""

from __future__ import annotations

import contextvars
import html as html_module
import ipaddress
import logging
import re
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse

from honeylens import config
from honeylens.database import legacy_get_db, return_db

logger = logging.getLogger("api")

# ─── Input Validation ────────────────────────────────────────────────────

_EVENT_ID_RE = re.compile(r"^[a-zA-Z0-9_]{3,64}$")
_PROTOCOL_RE = re.compile(r"^[A-Za-z0-9./ +-]{1,64}$")

# ─── Subnet exclusion (display filter) ───────────────────────────────────
# Was a module-level `_LOCAL_SUBNET = "192.168.0.0/24"` copied into three route modules, so
# every sensor filtered OUR lab range no matter whose network it stood in — on a client
# sensor the predicate matched nothing and the dashboards showed all the internal management
# and monitoring traffic. Now it comes from config.DASHBOARD_EXCLUDE_SUBNETS and takes a
# list, because a sensor can sit in more than one internal range.
#
# These are display filters only; the events remain ingested, stored and classified. Use the
# predicate `NOT (src_ip <<= ANY(%s::inet[]))` in your query and pass EXCLUDED_SUBNETS as the
# parameter. An empty list is honoured as "exclude nothing": no array element can match, so
# the NOT keeps every row.
EXCLUDED_SUBNETS: list[str] = list(config.DASHBOARD_EXCLUDE_SUBNETS)


def valid_event_id(event_id: str) -> bool:
    return bool(_EVENT_ID_RE.match(event_id))


def valid_protocol(name: str) -> bool:
    return bool(_PROTOCOL_RE.match(name))


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.split("/")[0] if ip and "/" in ip else ip)
        return True
    except ValueError:
        return False


def strip_cidr(ip: str) -> str:
    """Strip CIDR suffix: '1.2.3.4/32' → '1.2.3.4'."""
    if ip and "/" in ip:
        return ip.split("/")[0]
    return ip or ""


# ─── Database ────────────────────────────────────────────────────────────

# Connections handed out by db() during one HTTP request.
#
# db() returns a NEW psycopg2 connection (legacy_get_db), and 98 route handlers
# take one without a try/finally. On the happy path CPython's refcounting closes
# it when the handler returns. On the error path it does not: the traceback holds
# the frame, the frame holds the connection, and it stays open in
# "idle in transaction (aborted)" for as long as the exception is referenced.
#
# Observed on sensor-a 2026-08-27: one failing query (a missing mitm_events column)
# leaked one connection per dashboard poll — 11 in six hours — until the API
# could no longer serve anything and /ics/stats, /ai/stats and / all timed out.
# A ten-day-old aborted connection had been sitting on another host too.
#
# The middleware in api.py opens a scope per request and closes whatever is left
# in it, so a leak is impossible regardless of what a handler does. This is a
# safety net, not a licence: new code should use `with db_cursor() as cur`.
_request_conns: contextvars.ContextVar[list | None] = contextvars.ContextVar(
    "_hl_request_conns", default=None
)


def begin_request_conn_scope():
    """Start tracking db() connections for the current request. Returns a token."""
    return _request_conns.set([])


def close_request_conns(token) -> int:
    """Roll back and return every connection db() handed out in this scope.

    Returns how many were still open — a non-zero count means a handler leaked,
    which is worth logging even though it is now harmless.
    """
    conns: Any = _request_conns.get() or []
    try:
        _request_conns.reset(token)
    except ValueError:
        pass  # scope crossed a task boundary; the list is still ours to drain
    leaked = 0
    for conn in conns:
        try:
            if conn.closed:
                return_db(conn)  # also discard a broken underlying connection
                continue
            leaked += 1
            try:
                conn.rollback()
            except Exception as exc:  # the connection may already be unusable
                logging.getLogger(__name__).debug("ignored: %s", exc)
            return_db(conn)
        except Exception as exc:  # cleanup must never raise into the response path
            logging.getLogger(__name__).debug("ignored: %s", exc)
    return leaked


def db():
    """Return a pooled database connection.

    Registered with the current request scope when there is one, so it cannot be
    leaked by a handler that raises before closing it.
    """
    conn = legacy_get_db()
    bucket = _request_conns.get()
    if bucket is not None:
        bucket.append(conn)
    return conn


# ─── Request Helpers ─────────────────────────────────────────────────────


def wants_html(request: Request | None) -> bool:
    """Whether to serve the WebUI (HTML) rather than the JSON API for a dual
    endpoint.

    Serve HTML **only** when the client explicitly asks for it: ``?format=html``,
    or an Accept header that contains ``text/html`` (top-level browser page
    navigation). Everything else gets JSON — crucially including ``Accept: */*``,
    which is what the dashboards' own ``fetch()``/XHR data calls (and curl, and
    header-less internal fan-out requests) send. Defaulting ``*/*`` to HTML breaks
    those data widgets ("Error loading events"), so it must map to JSON.
    """
    if request is None:
        return False
    fmt = request.query_params.get("format")
    if fmt == "html":
        return True
    if fmt == "json":
        return False
    accept = request.headers.get("accept", "")
    # Only a genuine page navigation asks for text/html (and not JSON-first).
    if "text/html" in accept and "application/json" not in accept.split("text/html")[0]:
        return True
    return False


def esc(value) -> str:
    """HTML-escape a value."""
    return html_module.escape(str(value)) if value is not None else ""


def html_response(
    title: str,
    data,
    request: Request,
    table_type: str = "auto",
    back_url: str = "/",
    extra_html_top: str = "",
):
    """Generate HTML or JSON response based on client preference."""
    if not wants_html(request):
        return data
    from honeylens.webui.endpoint_generic import _generate_endpoint_html

    content = _generate_endpoint_html(title, data, table_type, back_url, str(request.url.path))
    if extra_html_top:
        content = content.replace(
            '<div class="container">', f'<div class="container">{extra_html_top}', 1
        )
    return HTMLResponse(content=content)
