"""
api.py — Sensor Intelligence REST API + Web Dashboard
======================================================
FastAPI service with embedded dark-themed dashboard, basic auth, TLS.
All dashboard queries exclude the sensor's own internal ranges (DASHBOARD_EXCLUDE_SUBNETS).

Endpoints:
    GET /                           Embedded web dashboard
    GET /events?limit=200           Recent events (external only)
    GET /events_ip/{ip}             Events from specific source IP
    GET /event_full/{event_id}      Full event detail
    GET /payload/{event_id}         Raw payload text
    GET /pcap/{event_id}            PCAP file download
    GET /temporal                   Event counts per minute
    GET /top_scanners               Top source IPs
    GET /top_ports                  Top targeted ports
    GET /protocols                  Protocol distribution stats
    GET /protocol/{name}            Events filtered by protocol
    GET /sources                    Source distribution
    GET /ja3_stats                  JA3 fingerprint frequency
    GET /ja4_stats                  JA4+ fingerprint stats (summary, identified threats)
    GET /ja4/{fingerprint}          Events by JA4 fingerprint
    GET /attack_stats               Attack type summary stats
    GET /attack_rules               Per-rule breakdown
    GET /attack/types               List all attack types with counts
    GET /attack/type/{type}         Events by attack type (optional ?protocol= filter)
    GET /attack/type/{type}/http    HTTP-related events by attack type
    GET /attack/rule/{rule_name}    Events matching specific rule
    GET /attack_type/{type}         Legacy: events by attack type
    GET /attack_event/{event_id}    Attack patterns for specific event
    GET /search/rule                Search events by rule name with pagination

    --- FortiGate Honeypot ---
    GET /fortigate/events           Recent FortiGate honeypot events
    GET /fortigate/stats            FortiGate honeypot statistics
    GET /fortigate/credentials      Captured FortiGate credentials

    --- Honeypot Summary ---
    GET /honeypots/summary          Summary stats for all honeypots

    --- MiTM Detection ---
    GET  /mitm/events               Recent MiTM detection events
    GET  /mitm/stats                MiTM detection statistics
    GET  /mitm/arp-cache            Current ARP cache state
    GET  /mitm/summary              Dashboard summary
    POST /mitm/acknowledge/{id}     Acknowledge an event
    POST /mitm/false_positive/{id}  Mark event as false positive

    --- Admin Panel (requires admin role) ---
    GET  /sensor_admin              Admin panel dashboard
    GET  /sensor_admin/stats        Dashboard statistics
    GET  /sensor_admin/status       System service status
    GET  /sensor_admin/users        List all users
    POST /sensor_admin/users        Create new user
    GET  /sensor_admin/users/{id}   Get user details
    PUT  /sensor_admin/users/{id}   Update user
    DELETE /sensor_admin/users/{id} Delete user (soft delete)
    POST /sensor_admin/users/{id}/reset_password  Reset user password
    GET  /sensor_admin/audit        Admin audit log
    GET  /sensor_admin/export/attackers  Export attacker IPs (legacy, see /export/attackers)

    --- Attacker Export (Hunting Verdicts) ---
    GET  /export/attackers              Export CRITICAL/HIGH attacker IPs
                                        ?format=text|csv|json|iptables|nftables|pf|mikrotik|cisco|stix
                                        ?threat=CRITICAL,HIGH  ?min_abuse=80  ?days=30
                                        ?tag=SSH_BRUTER  ?country=CN  ?min_events=10
    GET  /export/attackers/summary      Quick stats for exportable attackers

    --- Claude Deep Analysis (External AI) ---
    POST /ai/claude-analyze/{event_id}  Trigger Claude Sonnet deep analysis
    GET  /ai/claude-status              Check Claude integration status

Start:
    python api.py                   # TLS on port 3433
    python api.py --no-tls          # plain HTTP (dev only)

Requires: Python >= 3.9
"""

from __future__ import annotations

import html
import ipaddress
import json
import logging
import re
import secrets
import sys
from pathlib import Path
from typing import ClassVar

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from honeylens.analysis.claude_analyzer import (
    ANTHROPIC_DEEP_MODEL as _CLAUDE_DEEP_MODEL,
)
from honeylens.analysis.claude_analyzer import (
    ANTHROPIC_TRIAGE_MODEL as _CLAUDE_TRIAGE_MODEL,
)
from honeylens.analysis.claude_analyzer import (
    analyze_event as claude_analyze_event,
)
from honeylens.analysis.claude_analyzer import (
    is_auto_enabled as is_claude_auto_enabled,
)
from honeylens.analysis.claude_analyzer import (
    is_claude_available,
)
from honeylens.auth.admin_routes import router as admin_router
from honeylens.auth.session_manager import (
    SESSION_COOKIE_NAME as _COOKIE_NAME,
)
from honeylens.auth.session_manager import (
    SESSION_LIFETIME_HOURS as _SESSION_TTL_H,
)
from honeylens.auth.session_manager import (
    SESSION_LIFETIME_REMEMBER_HOURS as _SESSION_TTL_REM_H,
)
from honeylens.auth.session_manager import (
    check_login_rate_limit as _check_rate_limit,
)
from honeylens.auth.session_manager import (
    create_session as _create_session,
)
from honeylens.auth.session_manager import (
    record_login_attempt as _record_login_attempt,
)
from honeylens.auth.session_manager import (
    revoke_session as _revoke_session,
)
from honeylens.auth.session_manager import (
    validate_session as _validate_session,
)
from honeylens.auth.user_manager import authenticate_user
from honeylens.config import (
    API_AUTH_PASSWORD,
    API_AUTH_USERNAME,
    API_PORT,
    API_TLS_PORT,
    ENABLED_PLUGINS,
    TLS_CERT_FILE,
    TLS_KEY_FILE,
    TLS_KEY_TYPE,
    TLS_RSA_BITS,
    get_api_bind_address,
)

# GeoIP lookup (optional)
from honeylens.geoip import get_country_code
from honeylens.honeypots import units
from honeylens.intelligence.whitelist import is_whitelisted
from honeylens.plugins import HoneyLensCoreAdapter, load_plugins
from honeylens.routes._helpers import begin_request_conn_scope, close_request_conns
from honeylens.routes.ai import router as ai_router
from honeylens.routes.canary import router as canary_router
from honeylens.routes.classifier import router as classifier_router
from honeylens.routes.core import router as core_router
from honeylens.routes.dissection import router as dissection_router
from honeylens.routes.export import router as export_router
from honeylens.routes.hunting import router as hunting_router
from honeylens.routes.ics import router as ics_router
from honeylens.routes.intelligence import router as intel_router
from honeylens.routes.ja4 import router as ja4_router
from honeylens.routes.siem import router as siem_router
from honeylens.webui.endpoint_generic import (
    _generate_endpoint_html,
)

_HAS_GEOIP = True
# Whitelist (optional)

_HAS_WHITELIST = True
# Attack classifier rule listing (optional)

_HAS_CLASSIFIER = True
# Admin routes (optional — requires auth.py, user_manager.py)

_HAS_ADMIN = True
# Claude external AI (optional — requires anthropic SDK + config)

_HAS_CLAUDE = True
# OpenAI external AI (optional — requires openai SDK + config)
try:
    from honeylens.analysis.openai_analyzer import (
        OPENAI_DEEP_MODEL as _OPENAI_DEEP_MODEL,
    )
    from honeylens.analysis.openai_analyzer import (
        OPENAI_TRIAGE_MODEL as _OPENAI_TRIAGE_MODEL,
    )
    from honeylens.analysis.openai_analyzer import (
        analyze_event as openai_analyze_event,
    )
    from honeylens.analysis.openai_analyzer import (
        is_openai_available,
    )

    _HAS_OPENAI = True
except ImportError:
    _HAS_OPENAI = False
    _OPENAI_TRIAGE_MODEL = ""
    _OPENAI_DEEP_MODEL = ""

    def is_openai_available() -> bool:
        return False


def _select_deep_backend():
    """Return (backend_tag, deep_model, available_fn, analyze_fn) for the
    deep analysis backend that should service /ai/deep-analyze and
    /ai/claude-analyze (alias) requests.

    Mirrors the dispatcher logic in analysis/ai_analyzer._build_engine():
      - AI_DEEP_BACKEND=openai (with key)        → OpenAI
      - AI_DEEP_BACKEND=claude (with key)        → Claude
      - else OPENAI_API_KEY set                  → OpenAI
      - else ANTHROPIC_API_KEY set               → Claude
      - else                                      → no backend
    """
    from honeylens.env import env

    provider = env("AI_PROVIDER", "openai").strip().lower()
    deep_override = env("AI_DEEP_BACKEND", "").strip().lower()
    has_openai_key = bool(
        env("NOUS_API_KEY", "").strip() if provider == "nous" else env("OPENAI_API_KEY", "").strip()
    )
    has_claude_key = bool(env("ANTHROPIC_API_KEY", "").strip())

    # Explicit overrides
    if deep_override == "openai" and _HAS_OPENAI and has_openai_key:
        return (provider, _OPENAI_DEEP_MODEL, is_openai_available, openai_analyze_event)
    if deep_override == "claude" and _HAS_CLAUDE and has_claude_key:
        return ("claude", _CLAUDE_DEEP_MODEL, is_claude_available, claude_analyze_event)

    # Default cascade (OpenAI preferred when both available)
    if _HAS_OPENAI and has_openai_key:
        return (provider, _OPENAI_DEEP_MODEL, is_openai_available, openai_analyze_event)
    if _HAS_CLAUDE and has_claude_key:
        return ("claude", _CLAUDE_DEEP_MODEL, is_claude_available, claude_analyze_event)

    # Nothing configured
    def _not_available():
        return False

    def _no_analyze(event_id, store=True):
        return {"error": "No deep analysis backend configured"}

    return (None, None, _not_available, _no_analyze)


# Blog publisher (optional — requires blog_publisher.py + BLOG config)
try:
    from honeylens.config import BLOG as _BLOG_CFG
    from honeylens.publishing.blog_publisher import BlogPublisher

    _HAS_BLOG = _BLOG_CFG.get("enabled", False)
    _blog_publisher = BlogPublisher(_BLOG_CFG) if _HAS_BLOG else None
except ImportError:
    _HAS_BLOG = False
    _BLOG_CFG = {}
    _blog_publisher = None

# Scanner exclusions (optional — skip known research scanners)

_HAS_SCANNER_EXCLUSIONS = True
# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("api")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Sensor Intelligence API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Include admin panel routes if available
if _HAS_ADMIN and admin_router:
    app.include_router(admin_router)
    logger.info("Admin panel enabled at /sensor_admin")


# UI graphics are package data (webui/*.png, *.ico); paths are computed once at
# import time, so the handler never does a stat() on the request path.
_WEBUI_DIR = Path(__file__).parent / "webui"
_ASSETS: dict[str, tuple[Path, str]] = {
    "/favicon.ico": (_WEBUI_DIR / "favicon.ico", "image/x-icon"),
    "/logo.png": (_WEBUI_DIR / "logo.png", "image/png"),
    "/logo-mark.png": (_WEBUI_DIR / "favicon-32x32.png", "image/png"),  # hexagon only
}
_ASSETS = {route: (path, mime) for route, (path, mime) in _ASSETS.items() if path.is_file()}


def _asset_response(route: str) -> Response:
    hit = _ASSETS.get(route)
    if hit is None:
        return Response(status_code=204)
    path, mime = hit
    return FileResponse(path, media_type=mime)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return _asset_response("/favicon.ico")


# Brand logo (used on the login page; public so it loads pre-auth)
@app.get("/logo.png", include_in_schema=False)
async def logo():
    return _asset_response("/logo.png")


# Brand mark (hexagon only — used as the top-left nav logo)
@app.get("/logo-mark.png", include_in_schema=False)
async def logo_mark():
    return _asset_response("/logo-mark.png")


SURICATA_ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
  <!-- Meerkat (Suricata suricatta) standing upright -->
  <!-- Body -->
  <ellipse cx="32" cy="42" rx="10" ry="16" fill="#c8956c"/>
  <!-- Belly -->
  <ellipse cx="32" cy="44" rx="6" ry="12" fill="#e8d5b7"/>
  <!-- Head -->
  <circle cx="32" cy="20" r="9" fill="#c8956c"/>
  <!-- Face mask -->
  <ellipse cx="32" cy="21" rx="6" ry="7" fill="#e8d5b7"/>
  <!-- Eyes - dark patches -->
  <ellipse cx="28" cy="18" rx="3.5" ry="3" fill="#4a3728"/>
  <ellipse cx="36" cy="18" rx="3.5" ry="3" fill="#4a3728"/>
  <!-- Eyeballs -->
  <circle cx="28.5" cy="18" r="1.5" fill="#fff"/>
  <circle cx="35.5" cy="18" r="1.5" fill="#fff"/>
  <circle cx="29" cy="18" r="0.8" fill="#111"/>
  <circle cx="36" cy="18" r="0.8" fill="#111"/>
  <!-- Nose -->
  <ellipse cx="32" cy="23" rx="2" ry="1.2" fill="#4a3728"/>
  <!-- Ears -->
  <circle cx="25" cy="14" r="3" fill="#c8956c"/>
  <circle cx="25" cy="14" r="1.8" fill="#e8a07a"/>
  <circle cx="39" cy="14" r="3" fill="#c8956c"/>
  <circle cx="39" cy="14" r="1.8" fill="#e8a07a"/>
  <!-- Arms -->
  <rect x="21" y="36" width="4" height="10" rx="2" fill="#c8956c" transform="rotate(-5 23 41)"/>
  <rect x="39" y="36" width="4" height="10" rx="2" fill="#c8956c" transform="rotate(5 41 41)"/>
  <!-- Feet -->
  <ellipse cx="28" cy="58" rx="4" ry="2.5" fill="#a07850"/>
  <ellipse cx="36" cy="58" rx="4" ry="2.5" fill="#a07850"/>
  <!-- Tail -->
  <path d="M38 52 Q46 48 44 40" stroke="#a07850" stroke-width="3" stroke-linecap="round" fill="none"/>
</svg>"""


@app.get("/suricata/icon.svg", include_in_schema=False)
async def suricata_icon():
    return Response(
        content=SURICATA_ICON_SVG,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )


# Event ID regex — SHA-256 = 64 hex chars
_EVENT_ID_RE = re.compile(r"^[a-zA-Z0-9_]{3,64}$")

# Safe protocol name regex — alphanumeric, dot, dash, slash, plus, space
_PROTOCOL_RE = re.compile(r"^[A-Za-z0-9./ +-]{1,64}$")


# ---------------------------------------------------------------------------
# Authentication middleware (session + Basic Auth)
# ---------------------------------------------------------------------------

# Try to import user authentication

_HAS_USER_AUTH = True
# Try to import session management

_HAS_SESSIONS = True


class _SessionUser:
    """Wrapper around session dict to support attribute access (e.g. user.is_admin).
    Makes session-authenticated users compatible with admin_routes.py
    which expects User-object-style attribute access."""

    def __init__(self, d):
        self._d = d

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._d.get(name)

    def get(self, key, default=None):
        return self._d.get(key, default)

    def to_dict(self, include_sensitive=False):
        return dict(self._d)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware supporting (in priority order):
    1. Session cookie (sensor_sid) — primary for browser/dashboard
    2. Basic Auth — fallback for API clients, CLI tools, scripts
    3. Legacy config.py credentials — backward compatibility

    Public paths (no auth required): /login, /health
    """

    PUBLIC_PATHS: ClassVar[set[str]] = {
        "/login",
        "/health",
        "/favicon.ico",
        "/logo.png",
        "/logo-mark.png",
    }

    async def dispatch(self, request: Request, call_next):
        import base64

        path = request.url.path

        # Public routes — no auth required
        if path in self.PUBLIC_PATHS:
            request.state.user = None
            request.state.is_admin = False
            request.state.auth_method = "none"
            response = await call_next(request)
            self._add_security_headers(response)
            return response

        # --- 1. Try session cookie first (browser/dashboard) ---
        if _HAS_SESSIONS:
            session_token = request.cookies.get(_COOKIE_NAME)
            if session_token:
                user = _validate_session(session_token)
                if user:
                    request.state.user = _SessionUser(user)
                    request.state.is_admin = user.get("is_admin", False)
                    request.state.auth_method = "session"
                    # Update last_login periodically (not every request)
                    self._touch_last_login(user)
                    response = await call_next(request)
                    self._add_security_headers(response)
                    return response
                else:
                    # Invalid/expired session — clear cookie, redirect to login
                    if "text/html" in request.headers.get("Accept", ""):
                        from fastapi.responses import RedirectResponse

                        response = RedirectResponse(url="/login", status_code=303)
                        response.delete_cookie(_COOKIE_NAME, path="/")
                        self._add_security_headers(response)
                        return response
                    # API client with stale cookie — fall through to Basic Auth

        # --- 2. Try Basic Auth (API clients, curl, scripts) ---
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("utf-8")
                username, password = decoded.split(":", 1)
            except (ValueError, UnicodeDecodeError) as e:
                logger.debug("Basic auth decode failed: %s", e)
                response = Response(status_code=401, content="Bad credentials")
                self._add_security_headers(response)
                return response

            # Database authentication
            authenticated = False
            user_obj = None

            if _HAS_USER_AUTH:
                user_obj = authenticate_user(username, password)
                if user_obj:
                    authenticated = True
                    request.state.user = user_obj
                    request.state.is_admin = user_obj.is_admin

            # Fallback to legacy config.py credentials.
            #
            # Guarded on a non-empty configured password. API_AUTH_PASSWORD defaults
            # to "" in config.py, so without this check `sensor` with an EMPTY
            # password satisfied both compare_digest calls and was granted
            # is_admin=True. On a sensor with 60443 open that is an unauthenticated
            # read of the whole event store from the internet. Verified exploitable
            # 2026-08-26 before this guard was added.
            if not authenticated and API_AUTH_PASSWORD:
                if secrets.compare_digest(username, API_AUTH_USERNAME) and secrets.compare_digest(
                    password, API_AUTH_PASSWORD
                ):
                    authenticated = True
                    request.state.user = None
                    request.state.is_admin = True  # Legacy auth has full access

            if authenticated:
                request.state.auth_method = "basic"
                response = await call_next(request)
                self._add_security_headers(response)
                return response

        # --- 3. No valid auth ---
        #
        # These denials get the security headers too. They used to return bare, which meant
        # the responses an unauthenticated client sees — the redirect to the login page and
        # the Basic challenge — were the only ones on the service without HSTS or
        # X-Frame-Options, and now without a CSP. A scanner reaching the service without
        # credentials sees exactly these.
        if "text/html" in request.headers.get("Accept", ""):
            # Browser — redirect to login page
            from fastapi.responses import RedirectResponse

            response = RedirectResponse(url="/login", status_code=303)
        else:
            # API client — return 401 with Basic Auth challenge
            response = Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Sensor API"'},
                content="Unauthorized",
            )
        self._add_security_headers(response)
        return response

    # Cache: user_id → last time we updated last_login in DB
    _login_touch_cache: ClassVar[dict[int, float]] = {}
    _LOGIN_TOUCH_INTERVAL = 3600  # update DB at most once per hour

    @classmethod
    def _touch_last_login(cls, session_user: dict):
        """Update users.last_login periodically for session-authenticated users.
        Without this, last_login only reflects the initial login (session creation),
        not the most recent activity."""
        import time as _time

        uid = session_user.get("user_id")
        if not uid:
            return
        now = _time.time()
        last_touch = cls._login_touch_cache.get(uid, 0)
        if now - last_touch < cls._LOGIN_TOUCH_INTERVAL:
            return
        cls._login_touch_cache[uid] = now
        try:
            from honeylens.database import db_cursor

            with db_cursor() as cur:
                cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (uid,))
        except Exception as e:
            logger.debug("last_login update failed for uid=%s: %s", uid, e)

    @staticmethod
    def _add_security_headers(response):
        """Add security headers to every response."""
        if not hasattr(response, "headers"):
            return
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        # Cross-Origin-Embedder-Policy is deliberately NOT set. ZAP asks for
        # `require-corp`, which would block every cross-origin subresource that does not
        # opt in — that is Leaflet from cdnjs and the basemap tiles from arcgisonline,
        # i.e. the whole hunting map. The advice is right in general and wrong for this app.
        #
        # Content-Security-Policy: the origins below are the ones the pages actually load,
        # enumerated from the source rather than copied from a template — Leaflet and
        # markercluster (script, style), basemap tiles (img), EPSS scores fetched from
        # api.first.org (connect). Everything else the dashboards fetch is same-origin.
        #
        # `'unsafe-inline'` on script-src is interim and the reason is worth knowing: the
        # dashboards carry well over a hundred inline event-handler attributes (onclick=
        # and friends), which a nonce cannot cover — and adding a nonce *disables*
        # 'unsafe-inline', so it would break all of them at once. That is why
        # webui.shared.generate_csp_nonce() exists but is called from nowhere: the nonce
        # path only becomes available once those handlers move to addEventListener.
        # What this policy buys today, with no refactor: an injected <script src=...> will
        # not load, forms cannot be retargeted off-origin, <base> cannot be rewritten,
        # and nothing can frame us. It does not stop inline script — that needs the nonce.
        response.headers["Content-Security-Policy"] = "; ".join(
            (
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
                "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
                "img-src 'self' data: https://cdnjs.cloudflare.com https://server.arcgisonline.com",
                "connect-src 'self' https://api.first.org",
                "font-src 'self' data:",
                "object-src 'none'",
                "frame-src 'none'",
                "base-uri 'self'",
                "form-action 'self'",
                "frame-ancestors 'none'",
            )
        )
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )
        try:
            del response.headers["server"]
        except KeyError:
            pass  # silent: header may not exist
        response.headers["Server"] = "Apache"


app.add_middleware(AuthMiddleware)


class DbConnScopeMiddleware:
    """Close every connection db() handed out during a request.

    Deliberately a raw ASGI middleware rather than BaseHTTPMiddleware: the latter
    runs the downstream app in a separate anyio task, and a ContextVar set in its
    dispatch() is not reliably visible there. A plain ASGI middleware runs in the
    same task, so the scope opened here is the one the route handler sees — and
    sync handlers reach it too, because anyio copies the context into the thread
    it runs them on.

    Without this, any handler that raises before closing its connection leaves it
    open in "idle in transaction (aborted)". See routes/_helpers.db for what that
    cost on a live sensor.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        token = begin_request_conn_scope()
        try:
            await self.app(scope, receive, send)
        finally:
            leaked = close_request_conns(token)
            if leaked:
                logger.warning(
                    "db(): %d connection(s) left open by %s %s — closed by the "
                    "request scope; the handler should use `with db_cursor()`",
                    leaked,
                    scope.get("method", "?"),
                    scope.get("path", "?"),
                )


app.add_middleware(DbConnScopeMiddleware)


# ---------------------------------------------------------------------------
# Login / Logout Routes
# ---------------------------------------------------------------------------


def _login_page_html(error: str = "") -> str:
    """Render the login page HTML (dark theme, no JS dependencies)."""
    error_html = ""
    if error:
        error_html = (
            '<div style="background:#ef444420;border:1px solid #ef444466;'
            "border-radius:6px;padding:10px 14px;color:#fca5a5;font-size:13px;"
            f'margin-bottom:16px">{html.escape(error)}</div>'
        )

    return (
        """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login — Hybrid Intelligence Sensor</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0e14;color:#c5cdd8;font-family:'IBM Plex Sans',-apple-system,sans-serif;
  display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.login-card{background:#111820;border:1px solid #1e2a3a;border-radius:10px;padding:36px;
  width:100%%;max-width:380px;box-shadow:0 8px 40px rgba(0,0,0,0.4)}
.logo{text-align:center;margin-bottom:24px}
.logo-icon{font-size:2.4rem;color:#f59e0b;display:block;margin-bottom:8px}
.logo-img{width:160px;height:auto;margin-bottom:10px}
.logo-text{font-size:1rem;font-weight:600;color:#e2e8f0;letter-spacing:0.02em}
.logo-sub{font-size:0.72rem;color:#64748b;margin-top:2px}
label{display:block;font-size:0.78rem;color:#8899aa;margin-bottom:4px;
  text-transform:uppercase;letter-spacing:0.05em}
input[type=text],input[type=password]{width:100%%;padding:10px 12px;
  background:#0a0e14;border:1px solid #1e2a3a;border-radius:6px;
  color:#e2e8f0;font-size:14px;font-family:inherit;margin-bottom:14px;
  transition:border-color 0.15s}
input:focus{outline:none;border-color:#22d3ee}
.remember{display:flex;align-items:center;gap:8px;margin-bottom:18px;font-size:0.82rem;color:#8899aa}
.remember input{width:auto;margin:0}
button{width:100%%;padding:11px;background:#22d3ee;color:#000;border:none;border-radius:6px;
  font-size:14px;font-weight:600;font-family:inherit;cursor:pointer;transition:background 0.15s}
button:hover{background:#06b6d4}
button:active{background:#0891b2}
.footer{text-align:center;margin-top:20px;font-size:0.7rem;color:#475569}
</style>
</head>
<body>
<div class="login-card">
  <div class="logo">
    <img src="/logo.png" alt="HoneyLens" class="logo-img">
    <div class="logo-text">Hybrid Intelligence Sensor</div>
    <div class="logo-sub">Threat Detection Platform</div>
  </div>
  """
        + error_html
        + """
  <form method="POST" action="/login" autocomplete="off">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" required autofocus>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required>
    <div class="remember">
      <input type="checkbox" id="remember" name="remember" value="on">
      <label for="remember" style="margin:0;text-transform:none;letter-spacing:0">Remember me (30 days)</label>
    </div>
    <button type="submit">Sign In</button>
  </form>
  <div class="footer">Authenticated sessions &middot; TLS 1.3 &middot; HttpOnly cookies</div>
</div>
</body>
</html>"""
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Render login page. If already authenticated via session, redirect to dashboard."""
    if _HAS_SESSIONS:
        session_token = request.cookies.get(_COOKIE_NAME)
        if session_token:
            user = _validate_session(session_token)
            if user:
                return RedirectResponse(url="/", status_code=303)
    return HTMLResponse(_login_page_html())


@app.post("/login")
async def login_submit(request: Request):
    """Process login form submission. Create session on success."""
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    remember = str(form.get("remember", "")) == "on"

    client_ip = ""
    if request.client:
        client_ip = request.client.host

    # Rate limiting
    if _HAS_SESSIONS and _check_rate_limit(client_ip):
        return HTMLResponse(
            _login_page_html("Too many login attempts. Please try again later."),
            status_code=429,
        )

    # Record attempt for rate limiting
    if _HAS_SESSIONS:
        _record_login_attempt(client_ip)

    # Authenticate
    user_obj = None
    authenticated = False

    if _HAS_USER_AUTH:
        user_obj = authenticate_user(username, password)
        if user_obj:
            authenticated = True

    # Fallback to legacy config.py credentials — same empty-password guard as the
    # middleware above; the login form reaches this code by a different path.
    if not authenticated and API_AUTH_PASSWORD:
        if secrets.compare_digest(username, API_AUTH_USERNAME) and secrets.compare_digest(
            password, API_AUTH_PASSWORD
        ):
            authenticated = True

    if not authenticated:
        return HTMLResponse(
            _login_page_html("Invalid username or password"),
            status_code=401,
        )

    # Create session
    if _HAS_SESSIONS and user_obj:
        session_token = _create_session(
            user_id=user_obj.id,
            ip=client_ip,
            user_agent=request.headers.get("User-Agent", ""),
            persistent=remember,
        )

        expiry_secs = _SESSION_TTL_REM_H * 3600 if remember else _SESSION_TTL_H * 3600

        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            key=_COOKIE_NAME,
            value=session_token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=expiry_secs,
            path="/",
        )

        # Audit log
        try:
            from honeylens.auth.auth import log_admin_action

            log_admin_action(
                user_obj.id,
                "login",
                details={"persistent": remember, "ip": client_ip},
                ip_address=client_ip,
            )
        except Exception as e:
            logger.debug("Failed to log admin login action: %s", e)

        return response
    else:
        # Legacy auth fallback (no sessions) — redirect with Basic Auth
        return RedirectResponse(url="/", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    """Revoke session and clear cookie."""
    if _HAS_SESSIONS:
        session_token = request.cookies.get(_COOKIE_NAME)
        if session_token:
            _revoke_session(session_token, reason="logout")

    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(_COOKIE_NAME, path="/")
    return response


# ---------------------------------------------------------------------------
# DB helper
# ---------------------------------------------------------------------------


def db():
    """Return a new psycopg2 connection.

    Thin wrapper around core.database.legacy_get_db() so api.py stays
    consistent with the rest of the codebase (central DB_CONFIG, no
    duplicated connect calls). Pool-backed db_cursor() is preferred for
    new code.
    """
    from honeylens.database import legacy_get_db

    return legacy_get_db()


def _check_attack_columns():
    """Detect if attack_types column and attack_patterns table exist."""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'sensor_events' AND column_name = 'attack_types'
            )
        """)
        has_col = cur.fetchone()[0]
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_name = 'attack_patterns'
            )
        """)
        has_tbl = cur.fetchone()[0]
        conn.close()
        return has_col, has_tbl
    except Exception as e:
        logger.debug("Schema introspection failed: %s", e)
        return False, False


# Detect at import time — cached for the process lifetime
_HAS_ATTACK_COL, _HAS_ATTACK_TBL = _check_attack_columns()


# ---------------------------------------------------------------------------
# Safe SQL Query Builders
# ---------------------------------------------------------------------------
# These functions build SQL queries without string interpolation from
# user-controlled input. The column selections are hardcoded based on
# schema detection at import time.


def _build_events_query(extra_where: str = "", table_alias: str = "") -> str:
    """
    Build a safe SELECT query for sensor_events.

    Args:
        extra_where: Additional WHERE clause conditions (use %s for params)
        table_alias: Table alias prefix (e.g., "se." for joins)

    Returns:
        SQL query string with %s placeholders for parameters
    """
    prefix = f"{table_alias}." if table_alias else ""

    # Base columns - always included
    base_cols = f"""
        {prefix}event_id, {prefix}source, {prefix}src_ip::text, {prefix}src_port,
        {prefix}protocol, {prefix}dst_port,
        EXTRACT(EPOCH FROM {prefix}timestamp)::double precision,
        {prefix}scan_score, {prefix}port_entropy"""

    # Conditionally add attack_types column
    if _HAS_ATTACK_COL:
        cols = f"{base_cols}, {prefix}attack_types"
    else:
        cols = base_cols

    return cols


def _build_events_query_with_ja3(table_alias: str = "") -> str:
    """Build SELECT columns including ja3 field."""
    prefix = f"{table_alias}." if table_alias else ""

    base_cols = f"""
        {prefix}event_id, {prefix}source, {prefix}src_ip::text, {prefix}src_port,
        {prefix}protocol, {prefix}dst_port,
        EXTRACT(EPOCH FROM {prefix}timestamp)::double precision,
        {prefix}scan_score, {prefix}port_entropy, {prefix}ja3"""

    if _HAS_ATTACK_COL:
        return f"{base_cols}, {prefix}attack_types"
    return base_cols


# ---------------------------------------------------------------------------
# HTML View Helper for API Endpoints
# ---------------------------------------------------------------------------
# When accessed from WebUI (Accept: text/html or ?format=html), endpoints
# return a rendered HTML page. Direct API access returns raw JSON.


def _wants_html(request: Request) -> bool:
    """Check if client wants HTML response (WebUI) vs JSON (API)."""
    # Check query parameter first
    if request.query_params.get("format") == "html":
        return True
    # Check Accept header
    accept = request.headers.get("accept", "")
    # If Accept header prefers HTML over JSON
    if "text/html" in accept and "application/json" not in accept.split("text/html")[0]:
        return True
    return False


def _events_search_bar_html(
    ip=None,
    protocol=None,
    rule=None,
    attack_type=None,
    port=None,
    ja4=None,
    q=None,
    limit=50,
    page=1,
    total=0,
    total_pages=1,
    base_url="/events",
):
    """Generate search/filter bar HTML for event listing pages."""

    def _v(val):
        return html.escape(str(val)) if val else ""

    # Build query string preserving current filters
    def _qs(**overrides):
        params = {
            "ip": ip,
            "protocol": protocol,
            "rule": rule,
            "attack_type": attack_type,
            "port": port,
            "ja4": ja4,
            "q": q,
            "limit": limit,
        }
        params.update(overrides)
        parts = [f"{k}={html.escape(str(v))}" for k, v in params.items() if v]
        return f"{base_url}?{'&'.join(parts)}" if parts else base_url

    prev_link = (
        f'<a href="{_qs(page=page - 1)}" style="color:var(--accent);">← Prev</a>'
        if page > 1
        else '<span style="color:#555;">← Prev</span>'
    )
    next_link = (
        f'<a href="{_qs(page=page + 1)}" style="color:var(--accent);">Next →</a>'
        if page < total_pages
        else '<span style="color:#555;">Next →</span>'
    )

    return f'''<div style="background:#111820;border:1px solid #1e2a3a;border-radius:8px;padding:16px;margin-bottom:16px;">
  <form method="GET" action="{base_url}" style="display:flex;flex-wrap:wrap;gap:8px;align-items:end;">
    <div style="flex:1;min-width:120px;">
      <label style="display:block;font-size:11px;color:#8899aa;margin-bottom:3px;">IP Address</label>
      <input name="ip" value="{_v(ip)}" placeholder="e.g. 192.168" style="width:100%;padding:6px 8px;background:#0a0e14;border:1px solid #1e2a3a;border-radius:4px;color:#c5cdd8;font-size:13px;">
    </div>
    <div style="flex:1;min-width:100px;">
      <label style="display:block;font-size:11px;color:#8899aa;margin-bottom:3px;">Protocol</label>
      <input name="protocol" value="{_v(protocol)}" placeholder="tcp/udp/http" style="width:100%;padding:6px 8px;background:#0a0e14;border:1px solid #1e2a3a;border-radius:4px;color:#c5cdd8;font-size:13px;">
    </div>
    <div style="flex:1;min-width:100px;">
      <label style="display:block;font-size:11px;color:#8899aa;margin-bottom:3px;">Rule / Attack Type</label>
      <input name="rule" value="{_v(rule)}" placeholder="sql_injection" style="width:100%;padding:6px 8px;background:#0a0e14;border:1px solid #1e2a3a;border-radius:4px;color:#c5cdd8;font-size:13px;">
    </div>
    <div style="flex:0 0 80px;">
      <label style="display:block;font-size:11px;color:#8899aa;margin-bottom:3px;">Port</label>
      <input name="port" value="{_v(port)}" placeholder="443" type="number" style="width:100%;padding:6px 8px;background:#0a0e14;border:1px solid #1e2a3a;border-radius:4px;color:#c5cdd8;font-size:13px;">
    </div>
    <div style="flex:1;min-width:120px;">
      <label style="display:block;font-size:11px;color:#8899aa;margin-bottom:3px;">JA3/JA4 Fingerprint</label>
      <input name="ja4" value="{_v(ja4)}" placeholder="t13d..." style="width:100%;padding:6px 8px;background:#0a0e14;border:1px solid #1e2a3a;border-radius:4px;color:#c5cdd8;font-size:13px;">
    </div>
    <div style="flex:1;min-width:120px;">
      <label style="display:block;font-size:11px;color:#8899aa;margin-bottom:3px;">Free Search</label>
      <input name="q" value="{_v(q)}" placeholder="keyword" style="width:100%;padding:6px 8px;background:#0a0e14;border:1px solid #1e2a3a;border-radius:4px;color:#c5cdd8;font-size:13px;">
    </div>
    <div style="flex:0 0 70px;">
      <label style="display:block;font-size:11px;color:#8899aa;margin-bottom:3px;">Per Page</label>
      <select name="limit" style="width:100%;padding:6px 8px;background:#0a0e14;border:1px solid #1e2a3a;border-radius:4px;color:#c5cdd8;font-size:13px;">
        {"".join(f'<option value="{n}"{"selected" if limit == n else ""}>{n}</option>' for n in [25, 50, 100])}
      </select>
    </div>
    <button type="submit" style="padding:6px 16px;background:#22d3ee;color:#0a0e14;border:none;border-radius:4px;font-weight:600;cursor:pointer;height:32px;">Search</button>
    <a href="{base_url}" style="padding:6px 12px;color:#8899aa;font-size:12px;text-decoration:none;">Clear</a>
  </form>
  <div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px;font-size:12px;color:#8899aa;">
    <span>{total:,} results</span>
    <div style="display:flex;gap:12px;align-items:center;">
      {prev_link}
      <span>Page {page} of {total_pages}</span>
      {next_link}
    </div>
  </div>
</div>'''


def _html_response(
    title: str,
    data,
    request: Request,
    table_type: str = "auto",
    back_url: str = "/",
    extra_html_top: str = "",
) -> Response:
    """
    Generate HTML or JSON response based on client preference.

    Args:
        title: Page title
        data: Data to display (list of dicts or dict)
        request: FastAPI request object
        table_type: "events", "stats", "attacks", "auto"
        back_url: URL for back button
        extra_html_top: HTML to inject before the main table

    Returns:
        HTMLResponse for WebUI, raw data for API (FastAPI handles JSON serialization)
    """
    if not _wants_html(request):
        # Return data directly - FastAPI will serialize to JSON
        return data

    # Generate HTML table from data
    html_content = _generate_endpoint_html(title, data, table_type, back_url, str(request.url.path))
    if extra_html_top:
        # SECURITY: extra_html_top must be trusted HTML (internally constructed).
        # Never pass user input here — it is injected raw into the page.
        html_content = html_content.replace(
            '<div class="container">', f'<div class="container">{extra_html_top}', 1
        )
    return HTMLResponse(content=html_content)


# ---------------------------------------------------------------------------
# WebUI Module Imports (Idea 4 — separated HTML rendering)
# ---------------------------------------------------------------------------
# HTML rendering functions extracted to webui/ package.
# REST routes remain here; they call webui functions for HTML responses.


def _valid_event_id(event_id: str) -> bool:
    return bool(_EVENT_ID_RE.match(event_id))


def _valid_protocol(name: str) -> bool:
    return bool(_PROTOCOL_RE.match(name))


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.split("/")[0] if ip and "/" in ip else ip)
        return True
    except ValueError:
        return False


def _strip_cidr(ip: str) -> str:
    """
    Strip CIDR suffix from IP address (e.g., '185.180.141.2/32' -> '185.180.141.2').
    PostgreSQL INET type casts to text with /32 suffix for single hosts.
    """
    if ip and "/" in ip:
        return ip.split("/")[0]
    return ip or ""


def _get_country(ip: str) -> str:
    """Get country code for IP. Returns PIRATE for whitelisted IPs."""
    if not ip:
        return "??"
    if is_whitelisted(ip):
        return "PIRATE"
    return get_country_code(ip)


# ---------------------------------------------------------------------------
# Embedded Dashboard HTML
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------

# Core event routes → moved to routes/core.py
app.include_router(core_router)

# JA3/JA4+ routes → moved to routes/ja4.py
app.include_router(ja4_router)

# Attack/KB routes → moved to routes/classifier.py (appended)

# ---------------------------------------------------------------------------
# Main — TLS bootstrap + uvicorn
# ---------------------------------------------------------------------------


def _ensure_certs():
    """Auto-generate self-signed certs if missing."""
    if Path(TLS_CERT_FILE).exists() and Path(TLS_KEY_FILE).exists():
        return
    logger.info("TLS certs not found — generating self-signed certificate")
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    Path(TLS_CERT_FILE).parent.mkdir(parents=True, exist_ok=True)

    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
    if TLS_KEY_TYPE == "ec":
        key = ec.generate_private_key(ec.SECP384R1())
    else:
        key = rsa.generate_private_key(65537, TLS_RSA_BITS)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "sensor-api"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sensor"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .sign(key, hashes.SHA384())
    )

    with Path(TLS_KEY_FILE).open("wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    with Path(TLS_CERT_FILE).open("wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    logger.info("Self-signed cert written to %s", TLS_CERT_FILE)


# ---------------------------------------------------------------------------
# FortiGate Honeypot Endpoints
# ---------------------------------------------------------------------------


@app.get("/fortigate/events")
def fortigate_events(request: Request, limit: int = 200):
    """Get recent FortiGate honeypot events."""
    limit = min(max(limit, 1), 1000)

    conn = db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT event_id, timestamp, src_ip::text, src_port, dst_port,
               protocol, attack_types, payload
        FROM sensor_events
        WHERE source = 'fortigate-honeypot'
        ORDER BY timestamp DESC
        LIMIT %s
    """,
        (limit,),
    )

    rows = cur.fetchall()
    conn.close()

    result = []
    for r in rows:
        # Parse payload for event details
        payload_data = {}
        if r[7]:
            try:
                payload_data = json.loads(r[7])
            except (json.JSONDecodeError, TypeError):  # silent: raw payload display fallback
                pass

        result.append(
            {
                "event_id": r[0],
                "timestamp": r[1].isoformat() if r[1] else None,
                "src_ip": r[2],
                "src_port": r[3],
                "dst_port": r[4],
                "protocol": r[5],
                "attack_types": r[6],
                "event_type": payload_data.get("event_type", ""),
                "path": payload_data.get("path", ""),
                "method": payload_data.get("method", ""),
            }
        )

    if _wants_html(request):
        return _html_response("FortiGate Honeypot Events", result, request, "events")
    return result


@app.get("/fortigate/stats")
def fortigate_stats(request: Request):
    """Get FortiGate honeypot statistics."""
    conn = db()
    cur = conn.cursor()

    # Total events (7d)
    cur.execute("""
        SELECT COUNT(*) FROM sensor_events
        WHERE source = 'fortigate-honeypot'
          AND timestamp >= NOW() - INTERVAL '7 days'
    """)
    total_events = cur.fetchone()[0]

    # Events today
    cur.execute("""
        SELECT COUNT(*) FROM sensor_events
        WHERE source = 'fortigate-honeypot'
          AND timestamp >= CURRENT_DATE
    """)
    events_today = cur.fetchone()[0]

    # Unique IPs (7d)
    cur.execute("""
        SELECT COUNT(DISTINCT src_ip) FROM sensor_events
        WHERE source = 'fortigate-honeypot'
          AND timestamp >= NOW() - INTERVAL '7 days'
    """)
    unique_ips = cur.fetchone()[0]

    # Attack type breakdown (7d)
    cur.execute("""
        SELECT UPPER(attack_types) AS attack_types, COUNT(*) as cnt
        FROM sensor_events
        WHERE source = 'fortigate-honeypot'
          AND attack_types IS NOT NULL
          AND timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY UPPER(attack_types)
        ORDER BY cnt DESC
        LIMIT 20
    """)
    attack_breakdown = [{"attack_types": r[0], "count": r[1]} for r in cur.fetchall()]

    # Top source IPs (7d)
    cur.execute("""
        SELECT src_ip::text, COUNT(*) as cnt
        FROM sensor_events
        WHERE source = 'fortigate-honeypot'
          AND timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY src_ip
        ORDER BY cnt DESC
        LIMIT 10
    """)
    top_ips = [{"ip": r[0], "count": r[1]} for r in cur.fetchall()]

    # CVE detection counts
    cur.execute("""
        SELECT rule_name, COUNT(*) as cnt
        FROM attack_patterns
        WHERE attack_type = 'FORTI_ATTACK'
          AND rule_name LIKE 'forti_cve%'
          AND created_at >= NOW() - INTERVAL '7 days'
        GROUP BY rule_name
        ORDER BY cnt DESC
    """)
    cve_detections = [{"rule": r[0], "count": r[1]} for r in cur.fetchall()]

    conn.close()

    result = {
        "total_events": total_events,
        "events_today": events_today,
        "unique_ips": unique_ips,
        "attack_breakdown": attack_breakdown,
        "top_ips": top_ips,
        "cve_detections": cve_detections,
    }

    if _wants_html(request):
        return _html_response("FortiGate Honeypot Stats", result, request, "stats")
    return result


@app.get("/fortigate/credentials")
def fortigate_credentials(request: Request, limit: int = 100):
    """Get captured FortiGate credentials (credential harvesting events)."""
    limit = min(max(limit, 1), 500)

    conn = db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT event_id, timestamp, src_ip::text, payload
        FROM sensor_events
        WHERE source = 'fortigate-honeypot'
          AND (attack_types LIKE '%%FORTI_CRED%%' OR attack_types LIKE '%%CREDENTIAL%%')
        ORDER BY timestamp DESC
        LIMIT %s
    """,
        (limit,),
    )

    rows = cur.fetchall()
    conn.close()

    result = []
    for r in rows:
        payload_data = {}
        if r[3]:
            try:
                payload_data = json.loads(r[3])
            except (json.JSONDecodeError, TypeError):  # silent: raw payload display fallback
                pass

        data = payload_data.get("data", {})
        result.append(
            {
                "event_id": r[0],
                "timestamp": r[1].isoformat() if r[1] else None,
                "src_ip": r[2],
                "username": data.get("username", ""),
                "password": data.get("password", data.get("credential", "")),
                "path": payload_data.get("path", ""),
            }
        )

    if _wants_html(request):
        return _html_response("FortiGate Captured Credentials", result, request, "events")
    return result


# ---------------------------------------------------------------------------
# Honeypot Summary Endpoint (all honeypots)
# ---------------------------------------------------------------------------


@app.get("/honeypots/summary")
def honeypots_summary(request: Request):
    """Get summary stats for all honeypots."""
    conn = db()
    cur = conn.cursor()

    # Get counts per honeypot source (last 24h only — full scan is too slow)
    cur.execute("""
        SELECT source, COUNT(*) as total,
               0 as unique_ips
        FROM sensor_events
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
          AND source IN ('honeypotng', 'k8s-honeypot', 'k8s_honeypot',
                         'fortigate-honeypot', 'fortigate_honeypot',
                         'llm-honeypot', 'honeypot-ssh', 'honeypot-http',
                         'honeypot-ftp', 'honeypot-telnet', 'honeypot-smtp',
                         'honeypot-modbus', 'honeypot-s7comm', 'honeypot-bacnet',
                         'honeypot-mqtt', 'honeypot-rdp', 'honeypot-vnc',
                         'honeypot-sip', 'honeypot-ldap', 'honeypot-adb',
                         'honeypot-afp', 'honeypot-cassandra', 'honeypot-rsync',
                         'honeypot-dahua', 'honeypot-dnp3', 'honeypot-enip',
                         'honeypot-iec104', 'honeypot-opcua', 'honeypot-oracle')
        GROUP BY source
        ORDER BY total DESC
    """)

    honeypots = []
    total_events = 0
    total_ips = 0
    for r in cur.fetchall():
        honeypots.append(
            {
                "source": r[0],
                "total_events": r[1],
                "unique_ips": r[2],
            }
        )
        total_events += r[1]
        total_ips += r[2]

    totals = (total_events, total_ips)

    conn.close()

    result = {
        "honeypots": honeypots,
        "total_events": totals[0],
        "total_unique_ips": totals[1],
    }

    if _wants_html(request):
        return _html_response("Honeypot Summary", result, request, "stats")
    return result


@app.get("/honeypots/health")
def honeypots_health():
    """Health check for all honeypot services — JSON status of each (units from the manifest)."""

    results = units.all_status()
    active = sum(1 for s in results.values() if s == "active")
    return {"honeypots": results, "active": active, "total": len(results)}


@app.post("/honeypots/{protocol}/toggle")
async def honeypot_toggle(protocol: str, request: Request):
    """Start or stop a specific honeypot service. Admin only."""
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    unit = units.unit_for(protocol)
    if not unit:
        raise HTTPException(status_code=400, detail=f"Unknown protocol: {protocol}")

    try:
        action, was_active = units.toggle(unit)
    except Exception as e:
        logger.warning("honeypot unit %s toggle failed: %s", unit, e)
        return {"error": f"Failed to toggle {unit}"}
    return {
        "protocol": protocol,
        "unit": unit,
        "action": action,
        "previous": "active" if was_active else "inactive",
    }


# ---------------------------------------------------------------------------
# MiTM Detection Endpoints
# ---------------------------------------------------------------------------


# ICS/OT + LLM + CVE routes → moved to routes/ics.py
app.include_router(ics_router)

# MiTM + Suricata + MITRE routes → moved to routes/intelligence.py
app.include_router(intel_router)

# Classifier routes → moved to routes/classifier.py
app.include_router(classifier_router)

# Routes — Archive Search
# ---------------------------------------------------------------------------


# Archive routes → moved to routes/export.py
app.include_router(export_router)

# AI Analysis routes → moved to routes/ai.py (Phase 1 refactor)
# ---------------------------------------------------------------------------
app.include_router(ai_router)


# Attacker Hunting + Export routes → moved to routes/hunting.py
app.include_router(hunting_router)

# Admin: SIEM forwarder settings + status + test-send.
app.include_router(siem_router)

# Admin: eBPF Full Dissection runtime port management (Idea 30 Phase 0).
app.include_router(dissection_router)

app.include_router(canary_router)

# ---------------------------------------------------------------------------
# Plugins
# ---------------------------------------------------------------------------
# Construct the HoneyLensCore adapter and load any plugin listed in
# config.ENABLED_PLUGINS. Plugins call core.register_route_module(...) which
# mounts their routers onto `app`, so this MUST come after every static
# include_router(...) call above (so plugin routes can override OSS routes
# if a plugin chooses to, or simply add new routes under their own prefix).
_plugin_core = HoneyLensCoreAdapter(fastapi_app=app)
_loaded_plugins = load_plugins(_plugin_core, ENABLED_PLUGINS)
logger.info("plugins loaded: %s", _loaded_plugins or "(none)")


# ---------------------------------------------------------------------------
# AI Deep Analysis — dispatches to whichever backend is configured
# (OpenAI gpt-5-mini / Claude Sonnet / future). The Anthropic-specific
# endpoint paths are kept as aliases for backward compat with existing
# UI fetch() calls.
# ---------------------------------------------------------------------------


def _do_deep_analyze(event_id: str, request: Request):
    if not getattr(request.state, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    if not _valid_event_id(event_id):
        raise HTTPException(400, "Invalid event ID")
    backend, model, avail_fn, analyze_fn = _select_deep_backend()
    if backend is None or not avail_fn():
        raise HTTPException(
            503,
            "No deep analysis backend available. Configure either "
            "OPENAI_API_KEY (with the openai SDK) or ANTHROPIC_API_KEY "
            "(with the anthropic SDK) in /opt/sensor/.env and ensure "
            "USE_EXTERNAL_AI=True in config.py.",
        )
    try:
        result = analyze_fn(event_id, store=True)
        if isinstance(result, dict):
            err = result.get("error") or ""
            if err:
                if "not found" in err.lower():
                    raise HTTPException(404, err)
                # Surface budget / credit / quota errors as 402 so the UI can
                # distinguish from generic 503s.
                if any(k in err.lower() for k in ("credit", "quota", "budget", "billing")):
                    raise HTTPException(402, err)
            result.setdefault("_backend", backend)
            result.setdefault("_deep_model", model)
        return result
    except HTTPException:
        raise
    except RuntimeError as e:
        raise HTTPException(503, str(e)) from e
    except Exception as e:
        raise HTTPException(500, f"{backend} deep analysis failed: {e}") from e


@app.post("/ai/deep-analyze/{event_id}")
def deep_analyze(event_id: str, request: Request):
    """Trigger AI deep analysis for a specific event using the configured
    backend (OpenAI / Claude). Stores result in ai_analysis +
    claude_analysis_log and auto-hunts the source IP."""
    return _do_deep_analyze(event_id, request)


@app.post("/ai/claude-analyze/{event_id}")
def claude_deep_analyze(event_id: str, request: Request):
    """Legacy alias for /ai/deep-analyze/{event_id}. Kept so existing UI
    fetch() calls and external integrations keep working after the
    rename. New code should call /ai/deep-analyze instead."""
    return _do_deep_analyze(event_id, request)


def _deep_status_dict():
    """Diagnostic snapshot of the active deep-analysis backend."""
    backend, model, avail_fn, _ = _select_deep_backend()
    diag = {
        "backend": backend or "none",
        "available": bool(avail_fn()) if backend else False,
        "deep_model": model,
        "has_openai_module": _HAS_OPENAI,
        "has_claude_module": _HAS_CLAUDE,
        "auto_enabled": False,
    }
    from honeylens.env import env

    provider = env("AI_PROVIDER", "openai").strip().lower()
    try:
        diag["openai_key_set"] = bool(
            env("NOUS_API_KEY", "").strip()
            if provider == "nous"
            else env("OPENAI_API_KEY", "").strip()
        )
        diag["provider"] = provider
        diag["nous_key_set"] = bool(env("NOUS_API_KEY", "").strip())
    except Exception:
        diag["openai_key_set"] = False
        diag["nous_key_set"] = False
    try:
        diag["claude_key_set"] = bool(env("ANTHROPIC_API_KEY", "").strip())
    except Exception:
        diag["claude_key_set"] = False
    try:
        diag["ai_deep_backend"] = env("AI_DEEP_BACKEND", "").strip() or None
    except Exception:
        diag["ai_deep_backend"] = None
    if _HAS_CLAUDE:
        try:
            diag["auto_enabled"] = bool(is_claude_auto_enabled())
        except Exception as exc:
            logging.getLogger(__name__).debug("ignored: %s", exc)
    if backend in ("openai", "nous"):
        diag["model"] = _OPENAI_DEEP_MODEL
        diag["triage_model"] = _OPENAI_TRIAGE_MODEL
    elif backend == "claude":
        diag["model"] = _CLAUDE_DEEP_MODEL
        diag["triage_model"] = _CLAUDE_TRIAGE_MODEL
    if not diag["available"]:
        reasons = []
        if not (diag["has_openai_module"] or diag["has_claude_module"]):
            reasons.append("Neither openai nor anthropic SDK installed")
        if not (diag["openai_key_set"] or diag["claude_key_set"]):
            reasons.append("Neither OPENAI_API_KEY nor ANTHROPIC_API_KEY set")
        diag["reason"] = "; ".join(reasons) or "unknown"
    return diag


@app.get("/ai/deep-status")
def deep_status(request: Request):
    """Return which deep-analysis backend is currently active and its
    diagnostic state. Used by the UI to decide whether to show the AI
    Deep button and what model name to display."""
    return _deep_status_dict()


@app.get("/ai/claude-status")
def claude_status(request: Request):
    """Legacy alias for /ai/deep-status. Returns the same diagnostic
    snapshot but flattens the response for callers that expected the
    old Claude-only field names."""
    return _deep_status_dict()


# ---------------------------------------------------------------------------
# Blog Publisher (Idea 24 — Threat Intel Blog)
# ---------------------------------------------------------------------------


# Blog routes → moved to routes/export.py

# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Entry point of ``honeylens-api`` (systemd unit sensor-api).

    By default TLS on ``API_TLS_PORT`` with a self-signed certificate generated on
    first start; ``--no-tls`` serves HTTP on ``API_PORT`` (behind a reverse proxy).
    """
    args = sys.argv[1:] if argv is None else argv
    no_tls = "--no-tls" in args
    bind_host = get_api_bind_address()

    if no_tls:
        logger.info("Starting API on http://%s:%s (no TLS)", bind_host, API_PORT)
        uvicorn.run(app, host=bind_host, port=API_PORT)
        return 0
    _ensure_certs()
    logger.info("Starting API on https://%s:%s", bind_host, API_TLS_PORT)
    uvicorn.run(
        app,
        host=bind_host,
        port=API_TLS_PORT,
        ssl_certfile=str(TLS_CERT_FILE),
        ssl_keyfile=str(TLS_KEY_FILE),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
