#!/usr/bin/env python3
"""
honeypot_fortigate.py — FortiGate Admin Interface Honeypot
============================================================
High-fidelity FortiGate firewall management interface honeypot.
Captures credentials, API exploitation attempts, and CVE probes.

Mimics FortiOS 7.4.x web interface with realistic:
- Login page (/login, /ng/login)
- Authentication flow (/logincheck)
- API endpoints (/api/v2/*)
- SSL VPN endpoints (/remote/*)
- HTTP headers and cookies

Detected attacks:
- CVE-2022-40684 (Authentication bypass via Forwarded header)
- CVE-2023-27997 (SSL VPN heap overflow)
- CVE-2024-21762 (Out-of-bounds write)
- Credential harvesting
- Admin enumeration
- Config backup attempts

Default ports: 443, 8443, 10443

Usage:
    python honeypot_fortigate.py
    python honeypot_fortigate.py --port 8443
    python honeypot_fortigate.py --no-tls  # Development only

Requires: aiohttp, ssl
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import secrets
import ssl
import sys
import time
from datetime import UTC, datetime
from typing import Any, ClassVar, TextIO

from honeylens.eventlog_lock import log_lock
from honeylens.honeypots import deception_waf
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.body_capture import capture as _capture_body


async def _read_body(request):
    try:
        return await request.read()
    except Exception:
        return b""


try:
    from aiohttp import web
except ImportError:
    print("ERROR: aiohttp required. Install with: pip install aiohttp")
    sys.exit(1)

try:
    from honeylens.intelligence import ai_canary
except ImportError:  # canary is optional
    ai_canary = None  # type: ignore[assignment]  # optional module, idiom from the mypy docs


# Bytes of a request body carried verbatim in the event line. The sink applies the same
# ceiling to 1.0-format decoys (honeypots/sink.py), so a request does not get a different
# budget for arriving at this decoy.
# Canonical definition lives in body_capture; imported so there is one value.

# A typed request key rather than a bare string: aiohttp 3.14 warns on the latter, and
# the warning is right — two middlewares picking the same string would collide silently.
_BODY_KEY: web.RequestKey[bytes] = web.RequestKey("honeylens_body")


def _body_middleware_factory():
    """Read every request body once, before the handler runs, and keep it on the request.

    Most handlers here never read the body at all: they answer from the path and the
    headers, which is enough to be believable and was never enough to be evidence.
    Measured over the 30-day window on 2026-10-25: **5 046 POSTs across the fleet and
    not one stored body** — 3 310 of them on one sensor, where this decoy takes almost all
    the HTTP traffic. Two handlers did capture, with 512-byte and 256-byte samples of
    their own.

    Doing it in middleware rather than in each handler means a new route cannot
    reintroduce the gap by forgetting. aiohttp caches the read, so a handler that later
    calls `request.read()` or `request.post()` still works and reads nothing twice;
    `client_max_size` (1 MiB by default) is what bounds it on the wire.
    """

    @web.middleware
    async def _capture_request_body(request: web.Request, handler):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            request[_BODY_KEY] = await _read_body(request)
        return await handler(request)

    return _capture_request_body


# =============================================================================
# Configuration
# =============================================================================

# Default values (overridden by config.py if available)
DEFAULT_TLS_CERT = "./certs/fortigate.crt"
DEFAULT_TLS_KEY = "./certs/fortigate.key"
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_PORTS = [10443, 20443]
DEFAULT_LOG_FILE = "/var/log/honeypot_fortigate.json"

# Fake FortiGate identity defaults
DEFAULT_MODEL = "FortiGate-60F"
DEFAULT_VERSION = "7.4.3"
DEFAULT_BUILD = "2573"
DEFAULT_SERIAL = "FGT60FTK22000001"
DEFAULT_HOSTNAME = "FW-EDGE-01"
DEFAULT_VDOM = "root"

# Try to load from config.py
try:
    from honeylens.config import get_fortigate_config

    _cfg = get_fortigate_config()
    TLS_CERT_FILE = _cfg.get("tls_cert", DEFAULT_TLS_CERT)
    TLS_KEY_FILE = _cfg.get("tls_key", DEFAULT_TLS_KEY)
    LISTEN_HOST = _cfg.get("bind_host", DEFAULT_LISTEN_HOST)
    DEFAULT_PORTS = _cfg.get("ports", DEFAULT_PORTS)
    LOG_FILE = _cfg.get("log_file", DEFAULT_LOG_FILE)
    FORTIGATE_MODEL = _cfg.get("model", DEFAULT_MODEL)
    FORTIOS_VERSION = _cfg.get("version", DEFAULT_VERSION)
    FORTIOS_BUILD = _cfg.get("build", DEFAULT_BUILD)
    SERIAL_NUMBER = _cfg.get("serial", DEFAULT_SERIAL)
    HOSTNAME = _cfg.get("hostname", DEFAULT_HOSTNAME)
    VDOM_NAME = DEFAULT_VDOM
except ImportError:
    TLS_CERT_FILE = DEFAULT_TLS_CERT
    TLS_KEY_FILE = DEFAULT_TLS_KEY
    LISTEN_HOST = DEFAULT_LISTEN_HOST
    LOG_FILE = DEFAULT_LOG_FILE
    FORTIGATE_MODEL = DEFAULT_MODEL
    FORTIOS_VERSION = DEFAULT_VERSION
    FORTIOS_BUILD = DEFAULT_BUILD
    SERIAL_NUMBER = DEFAULT_SERIAL
    HOSTNAME = DEFAULT_HOSTNAME
    VDOM_NAME = DEFAULT_VDOM

# =============================================================================
# Logging Setup
# =============================================================================

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("fortigate-honeypot")


# =============================================================================
# FortiGate Honeypot Class
# =============================================================================


class FortiGateHoneypot:
    """High-fidelity FortiGate Admin Interface Honeypot."""

    def __init__(self, log_file: str = LOG_FILE):
        self.sessions: dict[str, dict[str, Any]] = {}
        self.log_file_path = log_file
        self._log_file: TextIO | None = None
        self._ensure_log_file()

    def _ensure_log_file(self):
        """Ensure log file is open."""
        if self._log_file is None:
            try:
                os.makedirs(os.path.dirname(self.log_file_path), exist_ok=True)
            except (
                OSError,
                ValueError,
            ) as exc:  # silent: log dir may already exist or path is invalid
                logging.getLogger(__name__).debug("ignored: %s", exc)
            try:
                self._log_file = open(self.log_file_path, "a", buffering=1)
            except OSError as e:
                logger.debug("Cannot open log file %s: %s, using stdout", self.log_file_path, e)
                self._log_file = sys.stdout

    def log_event(self, event_type: str, data: dict[str, Any], request: web.Request):
        """Log honeypot event to JSON file."""
        try:
            peername = request.transport.get_extra_info("peername") if request.transport else None
            src_port = peername[1] if peername else 0
        except (TypeError, IndexError):
            src_port = 0

        # Sanitize headers (remove sensitive internal data)
        headers = {}
        for k, v in request.headers.items():
            headers[k] = v[:500] if len(v) > 500 else v

        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "honeypot": "fortigate",
            "event_type": event_type,
            "src_ip": request.remote or "unknown",
            "src_port": src_port,
            "method": request.method,
            "path": str(request.path),
            "query": str(request.query_string) if request.query_string else "",
            "user_agent": request.headers.get("User-Agent", "")[:500],
            "headers": headers,
            "data": data,
        }

        # What was sent, not only where. The middleware has already read it, so this
        # costs nothing and applies to every route including ones added later. Bodies
        # are kept verbatim, credentials included — see honeypots/body_capture.py, which
        # argues that case and puts redaction at publication rather than at capture.
        body = request.get(_BODY_KEY)
        if body:
            fields = _capture_body(body, str(request.path), request.headers.get("Content-Type", ""))
            for key, value in fields.items():
                data.setdefault(key, value)
            event["raw_hex"] = body[:MAX_RAW_EVENT_BYTES].hex()

        try:
            if self._log_file is not None:
                with log_lock(self.log_file_path):
                    self._log_file.write(json.dumps(event) + "\n")
                    self._log_file.flush()
        except OSError as e:
            logger.debug("Log write failed: %s", e)

        logger.info("[%s] %s %s %s", event_type, request.remote, request.method, request.path)

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def generate_session_id(self) -> str:
        """Generate realistic FortiGate session ID."""
        return secrets.token_hex(16)

    def generate_csrf_token(self) -> str:
        """Generate CSRF token (32 hex chars)."""
        return secrets.token_hex(16)

    def generate_apscookie_name(self) -> str:
        """Generate realistic APSCOOKIE name."""
        return f"APSCOOKIE_{secrets.token_hex(4).upper()}"

    def generate_apscookie_value(self) -> str:
        """Generate realistic APSCOOKIE value (base64-like)."""
        return base64.b64encode(secrets.token_bytes(24)).decode("ascii")

    def get_standard_headers(self) -> dict[str, str]:
        """Return standard FortiGate response headers.

        Real FortiOS 6.x/7.x sends an obfuscated literal `xxxxxxxx-xxxxx`
        as the Server header — Fortinet deliberately doesn't disclose the
        underlying web stack. Returning `nginx` here would be an obvious
        tell: Shodan, Censys, and nmap-service-probes all key product
        detection off this exact string, and any attacker who's profiled
        a real FortiGate would spot the mismatch immediately.
        """
        return {
            "Server": "xxxxxxxx-xxxxx",
            "X-Frame-Options": "SAMEORIGIN",
            "Content-Security-Policy": "frame-ancestors 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        }

    def _has_valid_session(self, request: web.Request) -> bool:
        """Check if request has a valid session cookie."""
        for cookie_name, cookie_value in request.cookies.items():
            if cookie_name.startswith("APSCOOKIE_") and cookie_value:
                return True
        return False

    def _detect_cve(self, request: web.Request) -> str | None:
        """Detect known CVE exploitation patterns."""
        path = str(request.path).lower()
        headers = {k.lower(): v for k, v in request.headers.items()}

        # CVE-2022-40684 - Authentication bypass via Forwarded header
        forwarded = headers.get("forwarded", "")
        if forwarded:
            if "for=" in forwarded.lower():
                if any(x in forwarded.lower() for x in ["127.0.0.1", "localhost", "::1"]):
                    return "CVE-2022-40684"

        # Also check X-Forwarded-For manipulation
        xff = headers.get("x-forwarded-for", "")
        if xff and any(x in xff.lower() for x in ["127.0.0.1", "localhost"]):
            if "/api/v2/" in path:
                return "CVE-2022-40684-XFF"

        # CVE-2023-27997 - SSL VPN heap overflow
        if "/remote/hostcheck_validate" in path:
            return "CVE-2023-27997"
        if "/remote/fgt_lang" in path:
            return "CVE-2023-27997-PROBE"

        # CVE-2024-21762 - Out-of-bounds write via CMDB
        if "/api/v2/cmdb/" in path and request.method in ("PUT", "POST"):
            content_length = request.headers.get("Content-Length", "0")
            try:
                if int(content_length) > 10000:
                    return "CVE-2024-21762"
            except ValueError as exc:  # silent: non-numeric Content-Length
                logging.getLogger(__name__).debug("ignored: %s", exc)

        return None

    # =========================================================================
    # Login Page Handler
    # =========================================================================

    async def handle_login_page(self, request: web.Request) -> web.Response:
        """Serve the FortiGate login page."""
        # Check for CVE attempts
        cve = self._detect_cve(request)
        if cve:
            self.log_event("CVE_ATTEMPT", {"cve": cve}, request)

        self.log_event("LOGIN_PAGE", {"redirect": request.query.get("redirect", "")}, request)

        # Generate session tokens
        apscookie_name = self.generate_apscookie_name()
        csrf_token = self.generate_csrf_token()

        html = self._render_login_page(csrf_token)

        headers = self.get_standard_headers()
        headers["Content-Type"] = "text/html; charset=utf-8"

        response = web.Response(text=html, headers=headers)
        try:
            response.set_cookie(apscookie_name, "", path="/", secure=True, httponly=True)
            response.set_cookie("ccsrftoken", csrf_token, path="/", secure=True)
        except Exception as e:
            logger.warning("Cookie setting error: %s", e)

        return response

    def _render_login_page(self, csrf_token: str) -> str:
        """Render the FortiGate login HTML."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>{HOSTNAME}</title>
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        html, body {{
            height: 100%;
            background: #1e2329;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            font-size: 14px;
            color: #c7c7c7;
        }}
        body {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }}
        .lang-selector {{
            position: absolute;
            top: 15px;
            right: 20px;
        }}
        .lang-selector select {{
            background: #2d343d;
            border: 1px solid #3d4654;
            color: #888;
            padding: 6px 12px;
            border-radius: 3px;
            font-size: 12px;
            cursor: pointer;
        }}
        .login-wrapper {{
            width: 100%;
            max-width: 400px;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .logo-text {{
            font-size: 28px;
            font-weight: 300;
            color: #da3743;
            letter-spacing: 3px;
        }}
        .logo-text span {{
            font-weight: 600;
        }}
        .login-box {{
            background: #252b33;
            border-radius: 4px;
            padding: 40px 35px;
            box-shadow: 0 4px 25px rgba(0, 0, 0, 0.5);
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        .form-group label {{
            display: block;
            font-size: 13px;
            color: #888;
            margin-bottom: 8px;
            font-weight: 400;
        }}
        .form-input {{
            width: 100%;
            padding: 12px 15px;
            background: #2d343d;
            border: 1px solid #3d4654;
            border-radius: 3px;
            color: #fff;
            font-size: 14px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }}
        .form-input:focus {{
            outline: none;
            border-color: #da3743;
            box-shadow: 0 0 0 2px rgba(218, 55, 67, 0.2);
        }}
        .form-input::placeholder {{
            color: #555;
        }}
        .checkbox-row {{
            display: flex;
            align-items: center;
            margin-bottom: 25px;
        }}
        .checkbox-row input[type="checkbox"] {{
            width: 16px;
            height: 16px;
            margin-right: 10px;
            cursor: pointer;
        }}
        .checkbox-row label {{
            font-size: 13px;
            color: #888;
            cursor: pointer;
            user-select: none;
        }}
        .login-btn {{
            width: 100%;
            padding: 14px;
            background: #da3743;
            border: none;
            border-radius: 3px;
            color: #fff;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .login-btn:hover {{
            background: #c4303b;
        }}
        .login-btn:active {{
            background: #b02a35;
        }}
        .login-btn:disabled {{
            background: #555;
            cursor: not-allowed;
        }}
        .error-message {{
            background: rgba(218, 55, 67, 0.15);
            border: 1px solid rgba(218, 55, 67, 0.3);
            color: #e57373;
            padding: 12px 15px;
            border-radius: 3px;
            margin-bottom: 20px;
            font-size: 13px;
            display: none;
        }}
        .footer {{
            margin-top: 25px;
            text-align: center;
            font-size: 11px;
            color: #555;
        }}
        .footer .model {{
            color: #777;
        }}
        .footer .sep {{
            margin: 0 8px;
            color: #444;
        }}
        .spinner {{
            display: none;
            width: 16px;
            height: 16px;
            border: 2px solid #fff;
            border-top-color: transparent;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        .login-btn.loading .spinner {{
            display: inline-block;
        }}
        .login-btn.loading {{
            pointer-events: none;
        }}
    </style>
</head>
<body>
    <div class="lang-selector">
        <select id="langSelect" onchange="changeLang(this.value)">
            <option value="en" selected>English</option>
            <option value="zh_CN">简体中文</option>
            <option value="zh_TW">繁體中文</option>
            <option value="ja">日本語</option>
            <option value="ko">한국어</option>
            <option value="fr">Français</option>
            <option value="de">Deutsch</option>
            <option value="es">Español</option>
            <option value="pt">Português</option>
        </select>
    </div>

    <div class="login-wrapper">
        <div class="logo">
            <div class="logo-text">FORTI<span>NET</span></div>
        </div>

        <div class="login-box">
            <div class="error-message" id="errorMsg"></div>

            <form id="loginForm" method="POST" action="/logincheck">
                <input type="hidden" name="ajax" value="1">
                <input type="hidden" name="redir" value="/ng/page/p/system/dashboard">

                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" class="form-input"
                           placeholder="admin" autocomplete="username" autocapitalize="off"
                           autocorrect="off" spellcheck="false" autofocus>
                </div>

                <div class="form-group">
                    <label for="secretkey">Password</label>
                    <input type="password" id="secretkey" name="secretkey" class="form-input"
                           placeholder="" autocomplete="current-password">
                </div>

                <div class="checkbox-row">
                    <input type="checkbox" id="rememberMe" name="rememberme" value="1">
                    <label for="rememberMe">Remember Me</label>
                </div>

                <button type="submit" class="login-btn" id="loginBtn">
                    <span class="spinner"></span>
                    <span class="btn-text">Login</span>
                </button>
            </form>
        </div>

        <div class="footer">
            <span class="model">{FORTIGATE_MODEL}</span>
            <span class="sep">|</span>
            <span>v{FORTIOS_VERSION} build{FORTIOS_BUILD}</span>
            <span class="sep">|</span>
            <span>VDOM: {VDOM_NAME}</span>
        </div>
    </div>

    <script>
    (function() {{
        var form = document.getElementById('loginForm');
        var btn = document.getElementById('loginBtn');
        var errorDiv = document.getElementById('errorMsg');
        var csrfToken = '{csrf_token}';

        form.addEventListener('submit', function(e) {{
            e.preventDefault();
            btn.classList.add('loading');
            errorDiv.style.display = 'none';

            var formData = new FormData(form);

            fetch('/logincheck', {{
                method: 'POST',
                body: formData,
                headers: {{
                    'X-CSRFTOKEN': csrfToken
                }},
                credentials: 'same-origin'
            }})
            .then(function(resp) {{ return resp.json(); }})
            .then(function(data) {{
                btn.classList.remove('loading');
                if (data.redirect) {{
                    window.location.href = data.redirect;
                }} else if (data.error) {{
                    errorDiv.textContent = data.error;
                    errorDiv.style.display = 'block';
                }}
            }})
            .catch(function(err) {{
                btn.classList.remove('loading');
                errorDiv.textContent = 'Unable to connect. Please try again.';
                errorDiv.style.display = 'block';
            }});
        }});

        function changeLang(lang) {{
            // Language change - just reload for honeypot
            console.log('Language:', lang);
        }}
        window.changeLang = changeLang;
    }})();
    </script>
</body>
</html>"""

    # =========================================================================
    # Login Check Handler (Credential Capture)
    # =========================================================================

    async def handle_logincheck(self, request: web.Request) -> web.Response:
        """Handle login form submission - capture credentials."""
        try:
            # Check for CVE attempts
            cve = self._detect_cve(request)
            if cve:
                self.log_event("CVE_ATTEMPT", {"cve": cve, "endpoint": "/logincheck"}, request)

            # Parse form data
            try:
                data = await request.post()
                username = str(data.get("username", ""))[:100]
                password = str(data.get("secretkey", ""))[:200]
                csrf = str(data.get("csrftoken", ""))[:50]
                ajax = str(data.get("ajax", "0"))
                redir = str(data.get("redir", ""))[:200]
                remember = str(data.get("rememberme", ""))
            except Exception as e:
                logger.debug("Failed to parse login POST body: %s", e)
                username = password = csrf = ajax = redir = remember = ""

            # Log credential capture
            self.log_event(
                "CREDENTIAL_CAPTURE",
                {
                    "username": username,
                    "password": password,
                    "csrf_token": csrf,
                    "ajax": ajax,
                    "redirect": redir,
                    "remember_me": remember,
                    "x_csrftoken": request.headers.get("X-CSRFTOKEN", ""),
                },
                request,
            )

            # Generate new session
            session_id = self.generate_session_id()
            apscookie_name = self.generate_apscookie_name()
            apscookie_value = self.generate_apscookie_value()
            new_csrf = self.generate_csrf_token()

            # Store session
            self.sessions[session_id] = {
                "username": username,
                "created": time.time(),
                "ip": request.remote,
            }

            # Always accept credentials and redirect
            redirect_url = redir if redir else "/ng/page/p/system/dashboard"

            response_data = {
                "redirect": redirect_url,
                "status": "success",
            }

            headers = self.get_standard_headers()

            # A granted admin session is a credential-like artefact, so it earns a
            # canary (Idea 52) the same way a K8s Secret read does.
            if (
                ai_canary is not None
                and ai_canary.enabled()
                and ai_canary.carrier_enabled("FORTIGATE_LOGIN")
            ):
                _nonce, _canary_headers = ai_canary.issue(
                    "fortigate",
                    "/logincheck",
                    request.headers.get("Host", ""),
                    origin_src_ip=(request.remote or ""),
                    context="FortiGate admin session",
                )
                headers.update(_canary_headers)

            # web.json_response() sets Content-Type: application/json itself;
            # adding it to `headers` too makes aiohttp raise ValueError
            # ("passing both Content-Type header and content_type ... forbidden").
            # Every other handler here passes get_standard_headers() untouched.
            response = web.json_response(response_data, headers=headers)

            # Set session cookies
            try:
                response.set_cookie(
                    apscookie_name,
                    apscookie_value,
                    path="/",
                    secure=True,
                    httponly=True,
                    max_age=86400,
                )
                response.set_cookie("ccsrftoken", new_csrf, path="/", secure=True)
            except Exception as e:
                logger.warning("Cookie setting error: %s", e)

            return response

        except Exception as e:
            logger.exception("Error in handle_logincheck: %s", e)
            # Return a basic response even on error
            return web.json_response(
                {"redirect": "/ng/page/p/system/dashboard", "status": "success"},
                headers=self.get_standard_headers(),
            )

    # =========================================================================
    # Dashboard Handler
    # =========================================================================

    async def handle_dashboard(self, request: web.Request) -> web.Response:
        """Serve fake dashboard after login."""
        cve = self._detect_cve(request)
        if cve:
            self.log_event("CVE_ATTEMPT", {"cve": cve, "endpoint": str(request.path)}, request)

        self.log_event("DASHBOARD_ACCESS", {"path": str(request.path)}, request)

        if not self._has_valid_session(request):
            # Redirect to login
            return web.HTTPFound("/ng/login?redirect=" + str(request.path))

        html = self._render_dashboard()
        headers = self.get_standard_headers()
        headers["Content-Type"] = "text/html; charset=utf-8"

        return web.Response(text=html, headers=headers)

    def _render_dashboard(self) -> str:
        """Render fake FortiGate dashboard."""
        uptime_days = secrets.randbelow(90) + 10
        uptime_hours = secrets.randbelow(24)
        uptime_mins = secrets.randbelow(60)
        sessions = secrets.randbelow(5000) + 500
        cpu_usage = secrets.randbelow(30) + 5
        mem_usage = secrets.randbelow(40) + 20

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{HOSTNAME} - Dashboard</title>
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #1e2329;
            color: #c7c7c7;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            font-size: 14px;
        }}
        .header {{
            background: #252b33;
            padding: 0 20px;
            height: 50px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #3d4654;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 100;
        }}
        .header-left {{
            display: flex;
            align-items: center;
            gap: 20px;
        }}
        .logo {{
            color: #da3743;
            font-size: 16px;
            font-weight: 500;
            letter-spacing: 1px;
        }}
        .logo span {{ font-weight: 700; }}
        .header-info {{
            display: flex;
            gap: 15px;
            font-size: 12px;
            color: #888;
        }}
        .header-right {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .header-right a {{
            color: #888;
            text-decoration: none;
            font-size: 12px;
        }}
        .header-right a:hover {{ color: #fff; }}
        .sidebar {{
            width: 220px;
            background: #252b33;
            position: fixed;
            left: 0;
            top: 50px;
            bottom: 0;
            overflow-y: auto;
            border-right: 1px solid #3d4654;
        }}
        .sidebar-menu {{
            padding: 10px 0;
        }}
        .menu-item {{
            display: block;
            padding: 12px 20px;
            color: #888;
            text-decoration: none;
            font-size: 13px;
            border-left: 3px solid transparent;
            transition: all 0.2s;
        }}
        .menu-item:hover {{
            background: #2d343d;
            color: #fff;
        }}
        .menu-item.active {{
            background: #2d343d;
            color: #fff;
            border-left-color: #da3743;
        }}
        .main {{
            margin-left: 220px;
            margin-top: 50px;
            padding: 20px;
            min-height: calc(100vh - 50px);
        }}
        .page-title {{
            font-size: 18px;
            font-weight: 500;
            margin-bottom: 20px;
            color: #fff;
        }}
        .widgets {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
        }}
        .widget {{
            background: #252b33;
            border-radius: 4px;
            padding: 20px;
        }}
        .widget-title {{
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 15px;
        }}
        .widget-value {{
            font-size: 32px;
            font-weight: 600;
            color: #4caf50;
        }}
        .widget-value.warning {{ color: #ff9800; }}
        .widget-value.danger {{ color: #f44336; }}
        .widget-label {{
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }}
        .info-table {{
            width: 100%;
        }}
        .info-table tr {{
            border-bottom: 1px solid #3d4654;
        }}
        .info-table tr:last-child {{
            border-bottom: none;
        }}
        .info-table td {{
            padding: 8px 0;
            font-size: 13px;
        }}
        .info-table td:first-child {{
            color: #888;
            width: 40%;
        }}
        .info-table td:last-child {{
            color: #fff;
        }}
        .loading-overlay {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(30, 35, 41, 0.9);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s;
        }}
        .loading-overlay.show {{
            opacity: 1;
            visibility: visible;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-left">
            <div class="logo">FORTI<span>GATE</span></div>
            <div class="header-info">
                <span>{HOSTNAME}</span>
                <span>VDOM: {VDOM_NAME}</span>
            </div>
        </div>
        <div class="header-right">
            <a href="#">admin</a>
            <a href="/logout">Logout</a>
        </div>
    </div>

    <div class="sidebar">
        <div class="sidebar-menu">
            <a href="#" class="menu-item active">Dashboard</a>
            <a href="#" class="menu-item">Network</a>
            <a href="#" class="menu-item">Policy & Objects</a>
            <a href="#" class="menu-item">Security Profiles</a>
            <a href="#" class="menu-item">VPN</a>
            <a href="#" class="menu-item">User & Authentication</a>
            <a href="#" class="menu-item">WiFi & Switch</a>
            <a href="#" class="menu-item">Log & Report</a>
            <a href="#" class="menu-item">System</a>
        </div>
    </div>

    <div class="main">
        <div class="page-title">Dashboard</div>

        <div class="widgets">
            <div class="widget">
                <div class="widget-title">System Information</div>
                <table class="info-table">
                    <tr><td>Hostname</td><td>{HOSTNAME}</td></tr>
                    <tr><td>Serial Number</td><td>{SERIAL_NUMBER}</td></tr>
                    <tr><td>Firmware</td><td>v{FORTIOS_VERSION} build{FORTIOS_BUILD}</td></tr>
                    <tr><td>Mode</td><td>NAT</td></tr>
                    <tr><td>Uptime</td><td>{uptime_days} days {uptime_hours}:{uptime_mins:02d}</td></tr>
                    <tr><td>System Time</td><td>{datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
                </table>
            </div>

            <div class="widget">
                <div class="widget-title">Sessions</div>
                <div class="widget-value">{sessions:,}</div>
                <div class="widget-label">Active Sessions</div>
            </div>

            <div class="widget">
                <div class="widget-title">CPU</div>
                <div class="widget-value{" warning" if cpu_usage > 50 else ""}">{cpu_usage}%</div>
                <div class="widget-label">Usage</div>
            </div>

            <div class="widget">
                <div class="widget-title">Memory</div>
                <div class="widget-value{" warning" if mem_usage > 60 else ""}">{mem_usage}%</div>
                <div class="widget-label">Usage</div>
            </div>

            <div class="widget">
                <div class="widget-title">License</div>
                <table class="info-table">
                    <tr><td>FortiCare</td><td style="color:#4caf50">Valid</td></tr>
                    <tr><td>FortiGuard AV</td><td style="color:#4caf50">Valid</td></tr>
                    <tr><td>FortiGuard IPS</td><td style="color:#4caf50">Valid</td></tr>
                    <tr><td>FortiGuard Web</td><td style="color:#4caf50">Valid</td></tr>
                </table>
            </div>

            <div class="widget">
                <div class="widget-title">Administrators</div>
                <table class="info-table">
                    <tr><td>admin</td><td>Online</td></tr>
                    <tr><td>backup-admin</td><td style="color:#666">Offline</td></tr>
                </table>
            </div>
        </div>
    </div>

    <div class="loading-overlay" id="loadingOverlay">
        <div style="color:#888">Loading...</div>
    </div>

    <script>
    // Simulate dashboard loading
    setTimeout(function() {{
        document.getElementById('loadingOverlay').classList.remove('show');
    }}, 500);
    </script>
</body>
</html>"""

    # =========================================================================
    # API Handlers
    # =========================================================================

    async def handle_api_status(self, request: web.Request) -> web.Response:
        """Handle /api/v2/monitor/system/status."""
        cve = self._detect_cve(request)
        if cve:
            self.log_event("CVE_ATTEMPT", {"cve": cve, "endpoint": str(request.path)}, request)

        self.log_event("API_PROBE", {"endpoint": "/api/v2/monitor/system/status"}, request)

        if not self._has_valid_session(request):
            return web.json_response(
                {"http_status": 401, "error": "Not Authorized", "cli_error": 13},
                status=401,
                headers=self.get_standard_headers(),
            )

        return web.json_response(
            {
                "http_method": "GET",
                "results": {
                    "model_name": FORTIGATE_MODEL,
                    "model_number": FORTIGATE_MODEL,
                    "model": FORTIGATE_MODEL,
                    "hostname": HOSTNAME,
                    "serial": SERIAL_NUMBER,
                    "version": f"v{FORTIOS_VERSION}",
                    "build": int(FORTIOS_BUILD),
                    "vdom": VDOM_NAME,
                    "current_time": int(time.time()),
                },
                "vdom": VDOM_NAME,
                "path": "system",
                "name": "status",
                "status": "success",
                "http_status": 200,
                "serial": SERIAL_NUMBER,
                "version": f"v{FORTIOS_VERSION}",
                "build": int(FORTIOS_BUILD),
            },
            headers=self.get_standard_headers(),
        )

    async def handle_api_admin(self, request: web.Request) -> web.Response:
        """Handle /api/v2/cmdb/system/admin - admin enumeration."""
        cve = self._detect_cve(request)
        if cve:
            self.log_event("CVE_ATTEMPT", {"cve": cve, "endpoint": str(request.path)}, request)

        self.log_event("ADMIN_ENUMERATION", {"endpoint": str(request.path)}, request)

        if not self._has_valid_session(request):
            return web.json_response(
                {"http_status": 401, "error": "Not Authorized", "cli_error": 13},
                status=401,
                headers=self.get_standard_headers(),
            )

        # Return realistic fake admin list
        return web.json_response(
            {
                "http_method": "GET",
                "results": [
                    {
                        "name": "admin",
                        "q_origin_key": "admin",
                        "wildcard": "disable",
                        "remote-auth": "disable",
                        "password": "ENC XXXXXXXXXXXXXXXXXXXX",
                        "trusthost1": "0.0.0.0 0.0.0.0",
                        "accprofile": "super_admin",
                        "comments": "",
                        "vdom": [{"name": VDOM_NAME, "q_origin_key": VDOM_NAME}],
                        "two-factor": "disable",
                    },
                    {
                        "name": "backup-admin",
                        "q_origin_key": "backup-admin",
                        "wildcard": "disable",
                        "remote-auth": "disable",
                        "password": "ENC XXXXXXXXXXXXXXXXXXXX",
                        "trusthost1": "10.0.0.0 255.0.0.0",
                        "accprofile": "super_admin",
                        "comments": "Backup administrator",
                        "vdom": [{"name": VDOM_NAME, "q_origin_key": VDOM_NAME}],
                        "two-factor": "disable",
                    },
                    {
                        "name": "netops",
                        "q_origin_key": "netops",
                        "wildcard": "disable",
                        "remote-auth": "disable",
                        "password": "ENC XXXXXXXXXXXXXXXXXXXX",
                        "trusthost1": "10.10.0.0 255.255.0.0",
                        "accprofile": "prof_admin",
                        "comments": "Network operations",
                        "vdom": [{"name": VDOM_NAME, "q_origin_key": VDOM_NAME}],
                        "two-factor": "enable",
                    },
                    {
                        "name": "readonly",
                        "q_origin_key": "readonly",
                        "wildcard": "disable",
                        "remote-auth": "enable",
                        "remote-group": "LDAP-Admins",
                        "password": "ENC XXXXXXXXXXXXXXXXXXXX",
                        "trusthost1": "0.0.0.0 0.0.0.0",
                        "accprofile": "read_only",
                        "comments": "Read-only audit",
                        "vdom": [{"name": VDOM_NAME, "q_origin_key": VDOM_NAME}],
                        "two-factor": "disable",
                    },
                    {
                        "name": "api_user",
                        "q_origin_key": "api_user",
                        "wildcard": "disable",
                        "remote-auth": "disable",
                        "password": "ENC XXXXXXXXXXXXXXXXXXXX",
                        "trusthost1": "10.0.0.50 255.255.255.255",
                        "accprofile": "api_profile",
                        "comments": "API automation",
                        "vdom": [{"name": VDOM_NAME, "q_origin_key": VDOM_NAME}],
                        "two-factor": "disable",
                    },
                ],
                "vdom": VDOM_NAME,
                "path": "system",
                "name": "admin",
                "status": "success",
                "http_status": 200,
                "serial": SERIAL_NUMBER,
                "version": f"v{FORTIOS_VERSION}",
                "build": int(FORTIOS_BUILD),
            },
            headers=self.get_standard_headers(),
        )

    async def handle_api_admin_specific(self, request: web.Request) -> web.Response:
        """Handle /api/v2/cmdb/system/admin/{username}."""
        username = request.match_info.get("username", "admin")

        cve = self._detect_cve(request)
        if cve:
            self.log_event("CVE_ATTEMPT", {"cve": cve, "target_user": username}, request)

        self.log_event("ADMIN_LOOKUP", {"target_username": username}, request)

        if not self._has_valid_session(request):
            return web.json_response(
                {"http_status": 401, "error": "Not Authorized", "cli_error": 13},
                status=401,
                headers=self.get_standard_headers(),
            )

        # Known fake admins
        fake_admins = {
            "admin": {"accprofile": "super_admin", "trusthost1": "0.0.0.0 0.0.0.0"},
            "backup-admin": {"accprofile": "super_admin", "trusthost1": "10.0.0.0 255.0.0.0"},
            "netops": {"accprofile": "prof_admin", "trusthost1": "10.10.0.0 255.255.0.0"},
            "readonly": {"accprofile": "read_only", "trusthost1": "0.0.0.0 0.0.0.0"},
            "api_user": {"accprofile": "api_profile", "trusthost1": "10.0.0.50 255.255.255.255"},
        }

        if username in fake_admins:
            admin = fake_admins[username]
            return web.json_response(
                {
                    "http_method": "GET",
                    "results": [
                        {
                            "name": username,
                            "q_origin_key": username,
                            "password": "ENC XXXXXXXXXXXXXXXXXXXX",
                            "accprofile": admin["accprofile"],
                            "trusthost1": admin["trusthost1"],
                            "vdom": [{"name": VDOM_NAME}],
                        }
                    ],
                    "status": "success",
                    "http_status": 200,
                },
                headers=self.get_standard_headers(),
            )
        else:
            return web.json_response(
                {
                    "http_method": "GET",
                    "results": [],
                    "status": "success",
                    "http_status": 200,
                },
                headers=self.get_standard_headers(),
            )

    async def handle_api_generic(self, request: web.Request) -> web.Response:
        """Handle generic API calls."""
        cve = self._detect_cve(request)
        if cve:
            self.log_event("CVE_ATTEMPT", {"cve": cve, "endpoint": str(request.path)}, request)

        self.log_event(
            "API_PROBE", {"endpoint": str(request.path), "method": request.method}, request
        )

        if not self._has_valid_session(request):
            return web.json_response(
                {"http_status": 401, "error": "Not Authorized", "cli_error": 13},
                status=401,
                headers=self.get_standard_headers(),
            )

        return web.json_response(
            {
                "http_method": request.method,
                "status": "success",
                "http_status": 200,
                "results": [],
            },
            headers=self.get_standard_headers(),
        )

    async def handle_config_backup(self, request: web.Request) -> web.Response:
        """Handle config backup attempt - high-value target."""
        cve = self._detect_cve(request)

        self.log_event(
            "CONFIG_BACKUP_ATTEMPT",
            {
                "cve": cve,
                "severity": "HIGH",
            },
            request,
        )

        if not self._has_valid_session(request):
            return web.json_response(
                {"http_status": 401, "error": "Not Authorized"},
                status=401,
                headers=self.get_standard_headers(),
            )

        # Deny config download
        return web.json_response(
            {"http_status": 403, "error": "Permission denied", "cli_error": 7},
            status=403,
            headers=self.get_standard_headers(),
        )

    # =========================================================================
    # Remote/SSL VPN Handlers (Exploit Probes)
    # =========================================================================

    async def handle_remote_fgt_lang(self, request: web.Request) -> web.Response:
        """Handle /remote/fgt_lang - language file probe."""
        cve = self._detect_cve(request)

        self.log_event(
            "EXPLOIT_PROBE",
            {
                "probe_type": "fgt_lang",
                "potential_cve": cve or "CVE-2022-42475",
            },
            request,
        )

        return web.json_response(
            {
                "lang": "en",
                "supported": ["en", "zh_CN", "zh_TW", "ja", "ko", "fr", "de", "es", "pt"],
                "default": "en",
            },
            headers=self.get_standard_headers(),
        )

    async def handle_remote_hostcheck(self, request: web.Request) -> web.Response:
        """Handle /remote/hostcheck_validate - CVE-2023-27997 probe."""
        self.log_event(
            "EXPLOIT_PROBE",
            {
                "probe_type": "hostcheck_validate",
                "potential_cve": "CVE-2023-27997",
                "severity": "CRITICAL",
            },
            request,
        )

        # Return fake successful validation
        headers = self.get_standard_headers()
        headers["Content-Type"] = "text/plain"

        return web.Response(text="1", headers=headers)

    async def handle_remote_logincheck(self, request: web.Request) -> web.Response:
        """Handle /remote/logincheck - SSL VPN login attempt."""
        try:
            data = await request.post()
            username = str(data.get("username", ""))[:100]
            credential = str(data.get("credential", data.get("secretkey", "")))[:200]
            realm = str(data.get("realm", ""))[:50]
        except Exception as e:
            logger.debug("Failed to parse SSLVPN login body: %s", e)
            username = credential = realm = ""

        self.log_event(
            "SSLVPN_LOGIN_ATTEMPT",
            {
                "username": username,
                "credential": credential,
                "realm": realm,
            },
            request,
        )

        headers = self.get_standard_headers()
        headers["Content-Type"] = "text/plain"

        return web.Response(text="ret=0,redir=/remote/login", headers=headers)

    async def handle_remote_login_page(self, request: web.Request) -> web.Response:
        """Handle /remote/login - SSL VPN login page."""
        self.log_event("SSLVPN_PAGE", {"path": str(request.path)}, request)

        # Redirect to main login
        return web.HTTPFound("/login")

    async def handle_remote_info(self, request: web.Request) -> web.Response:
        """Handle /remote/info - SSL VPN info disclosure."""
        self.log_event(
            "EXPLOIT_PROBE",
            {
                "probe_type": "remote_info",
            },
            request,
        )

        return web.json_response(
            {
                "version": f"v{FORTIOS_VERSION}",
                "build": FORTIOS_BUILD,
            },
            headers=self.get_standard_headers(),
        )

    # =========================================================================
    # CGI/Config Probes
    # =========================================================================

    async def handle_cgi_probe(self, request: web.Request) -> web.Response:
        """Handle /cgi-bin/* probes."""
        self.log_event(
            "EXPLOIT_PROBE",
            {
                "probe_type": "cgi_bin",
                "path": str(request.path),
            },
            request,
        )

        return web.Response(
            text="403 Forbidden",
            status=403,
            content_type="text/html",
            headers=self.get_standard_headers(),
        )

    async def handle_config_probe(self, request: web.Request) -> web.Response:
        """Handle /config/* probes."""
        self.log_event(
            "EXPLOIT_PROBE",
            {
                "probe_type": "config_directory",
                "path": str(request.path),
            },
            request,
        )

        return web.Response(
            text="403 Forbidden",
            status=403,
            content_type="text/html",
            headers=self.get_standard_headers(),
        )

    async def handle_sensitive_file(self, request: web.Request) -> web.Response:
        """Handle sensitive file probes (.htaccess, .git, etc.)."""
        self.log_event(
            "EXPLOIT_PROBE",
            {
                "probe_type": "sensitive_file",
                "path": str(request.path),
            },
            request,
        )

        return web.Response(
            text="403 Forbidden",
            status=403,
            content_type="text/html",
            headers=self.get_standard_headers(),
        )

    # =========================================================================
    # Static Assets
    # =========================================================================

    async def handle_favicon(self, request: web.Request) -> web.Response:
        """Serve Fortinet favicon."""
        # Minimal 16x16 ICO file (red square - Fortinet brand color)
        # In production, use actual Fortinet favicon
        ico_data = bytes(
            [
                0x00,
                0x00,
                0x01,
                0x00,
                0x01,
                0x00,
                0x10,
                0x10,
                0x00,
                0x00,
                0x01,
                0x00,
                0x20,
                0x00,
                0x68,
                0x04,
                0x00,
                0x00,
                0x16,
                0x00,
                0x00,
                0x00,
                0x28,
                0x00,
                0x00,
                0x00,
                0x10,
                0x00,
                0x00,
                0x00,
                0x20,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x20,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x04,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        )
        # Fill with red pixels (DA3743 = Fortinet red)
        red_pixel = bytes([0x43, 0x37, 0xDA, 0xFF])  # BGRA
        ico_data += red_pixel * 256  # 16x16 pixels

        return web.Response(
            body=ico_data, content_type="image/x-icon", headers=self.get_standard_headers()
        )

    async def handle_logout(self, request: web.Request) -> web.Response:
        """Handle logout."""
        self.log_event("LOGOUT", {}, request)
        return web.HTTPFound("/login")

    async def handle_404(self, request: web.Request) -> web.Response:
        """Handle unknown routes."""
        cve = self._detect_cve(request)
        if cve:
            self.log_event("CVE_ATTEMPT", {"cve": cve, "path": str(request.path)}, request)

        _unknown = {"path": str(request.path), "method": request.method}
        # What was sent, not only where. Bounded + credential-redacted.
        _unknown.update(
            _capture_body(
                await _read_body(request),
                str(request.path),
                request.headers.get("Content-Type", ""),
            )
        )
        self.log_event("UNKNOWN_PATH", _unknown, request)

        return web.Response(
            text="404 Not Found",
            status=404,
            content_type="text/html",
            headers=self.get_standard_headers(),
        )

    # =========================================================================
    # FortiWeb CVE-2025-64446 — auth bypass + arbitrary file upload chain
    # =========================================================================
    # Goal: turn the public PoC's three-stage exploit into three rich captured
    # events instead of three drive-by 404s. The honeypot pretends each stage
    # succeeded so the attacker progresses through the chain and we get the
    # full payload (admin name, password, uploaded file body, requested
    # webshell path). No real privilege ever changes hands.

    # Markers we look for in uploaded webshell bodies. Strings are concatenated
    # at runtime to keep editor security scanners from flagging them as live
    # code; they are detection signatures, not invocations.
    _FORTIWEB_SHELL_MARKERS: ClassVar = [
        "<?" + "php",
        "ev" + "al(",
        "sys" + "tem(",
        "ex" + "ec(",
        "pass" + "thru(",
        "shell_" + "exec",
        "/bin/" + "bash",
        "/dev/" + "tcp/",
        "bash " + "-i",
        "<?" + "=",
        "phpinfo" + "(",
        "file_" + "put_contents",
    ]

    async def handle_fortiweb_user_local_add(self, request: web.Request) -> web.Response:
        """Stage 1: POST /api/v2.0/user/local.add with `"../../mkey"` traversal.

        Real FortiWeb < 8.0.2 has a path-traversal flaw on this endpoint that
        creates an admin account without authentication when the user `name`
        contains `../../mkey`. We accept any JSON body, capture credentials,
        flag the traversal, and return a believable success response so the
        attacker proceeds to stage 2.
        """
        body_text = ""
        body_json: dict[str, Any] = {}
        try:
            body_bytes = await request.read()
            body_text = body_bytes[:4096].decode("utf-8", errors="replace")
            try:
                body_json = json.loads(body_text)
            except (json.JSONDecodeError, ValueError):
                body_json = {}
        except Exception as exc:
            logging.getLogger(__name__).debug("ignored: %s", exc)

        traversal_hit = ".." in body_text and ("mkey" in body_text or "../../" in body_text)
        captured_user = body_json.get("name") or body_json.get("username")
        captured_pass = body_json.get("password") or body_json.get("passwd")

        self.log_event(
            "FORTIWEB_AUTHBYPASS",
            {
                "cve": "CVE-2025-64446",
                "stage": 1,
                "endpoint": "/api/v2.0/user/local.add",
                "severity": "CRITICAL",
                "traversal_detected": bool(traversal_hit),
                "captured_user": captured_user,
                "captured_password": captured_pass,
                # The body also arrives through log_event's capture (verbatim, bounded
                # by body_capture.MAX_CAPTURE). This stays as the decoded JSON view of
                # the stage-1 request, which is what the stage fields are read against.
                "stage_body_text": body_text[:4096],
            },
            request,
        )

        # Believable FortiWeb success response — make the attacker proceed to stage 2.
        return web.json_response(
            {
                "results": {
                    "status": "success",
                    "message": "User added successfully",
                },
                "http_method": "POST",
                "http_status": 200,
                "name": captured_user or "admin",
                "vdom": "root",
                "size": 1,
                "matched_count": 1,
                "next_idx": 0,
            },
            headers=self.get_standard_headers(),
        )

    async def handle_fortiweb_maintenance_backup(self, request: web.Request) -> web.Response:
        """Stage 2: POST /api/v2.0/system/maintenance/backup uploads webshell.

        The PoC abuses the backup-restore endpoint to write attacker-controlled
        bytes to the web root. We capture up to 16 KB of the upload (most
        webshells are small), flag known shell signatures, and return success
        so stage 3 fires.
        """
        body_bytes = b""
        try:
            body_bytes = await request.read()
        except Exception as exc:
            logging.getLogger(__name__).debug("ignored: %s", exc)

        body_sample = body_bytes[: 16 * 1024]
        sample_text = body_sample.decode("utf-8", errors="replace")
        shell_markers = [m for m in self._FORTIWEB_SHELL_MARKERS if m in sample_text]

        self.log_event(
            "FORTIWEB_FILE_UPLOAD",
            {
                "cve": "CVE-2025-64446",
                "stage": 2,
                "endpoint": "/api/v2.0/system/maintenance/backup",
                "severity": "CRITICAL",
                "body_size": len(body_bytes),
                "shell_markers": shell_markers,
                # 256 bytes of hex was not a sample of a webshell, it was its first
                # line. The upload itself is captured by log_event, verbatim.
                "stage_body_text": sample_text[:4096],
                "content_type": request.headers.get("Content-Type", ""),
            },
            request,
        )

        # Believable FortiWeb backup-restore success response.
        return web.json_response(
            {
                "results": {
                    "status": "success",
                    "message": "Configuration restored. Reboot may be required.",
                },
                "http_method": "POST",
                "http_status": 200,
            },
            headers=self.get_standard_headers(),
        )

    async def handle_fortiweb_dat_file(self, request: web.Request) -> web.Response:
        """Stage 3: GET /<name>.dat triggers the dropped webshell.

        On a real exploited box this would execute the PHP webshell and (in
        the public PoC) start a reverse shell to the attacker. Our honeypot
        returns a 200 with empty body — the attacker sees "request succeeded"
        but no shell connection ever materialises. The event is the high-value
        capture: we know the webshell filename they expected to run.
        """
        path = str(request.path)
        self.log_event(
            "FORTIWEB_RCE_TRIGGER",
            {
                "cve": "CVE-2025-64446",
                "stage": 3,
                "endpoint": path,
                "severity": "CRITICAL",
                "expected_shell_filename": path.lstrip("/"),
                "user_agent": request.headers.get("User-Agent", ""),
            },
            request,
        )

        # Return 200 with empty body. Believable because the attacker's curl
        # gets HTTP 200; no payload execution ever happens.
        return web.Response(
            body=b"",
            status=200,
            content_type="application/octet-stream",
            headers=self.get_standard_headers(),
        )

    # =========================================================================
    # Route Setup
    # =========================================================================

    def setup_routes(self, app: web.Application):
        """Configure all routes."""
        # Login routes
        app.router.add_get("/", self.handle_login_page)
        app.router.add_get("/login", self.handle_login_page)
        app.router.add_get("/ng/login", self.handle_login_page)
        app.router.add_post("/logincheck", self.handle_logincheck)
        app.router.add_get("/logout", self.handle_logout)

        # Dashboard routes
        app.router.add_get("/ng/page/p/system/dashboard", self.handle_dashboard)
        app.router.add_get("/ng/page/{path:.*}", self.handle_dashboard)
        app.router.add_get("/ng/{path:.*}", self.handle_dashboard)

        # API - specific routes before generic
        app.router.add_get("/api/v2/monitor/system/status", self.handle_api_status)
        app.router.add_get("/api/v2/monitor/system/config/backup", self.handle_config_backup)
        app.router.add_get("/api/v2/cmdb/system/admin/{username}", self.handle_api_admin_specific)
        app.router.add_get("/api/v2/cmdb/system/admin", self.handle_api_admin)
        app.router.add_route("*", "/api/v2/{path:.*}", self.handle_api_generic)

        # Remote/SSL VPN exploit probes
        app.router.add_get("/remote/fgt_lang", self.handle_remote_fgt_lang)
        app.router.add_route("*", "/remote/hostcheck_validate", self.handle_remote_hostcheck)
        app.router.add_route("*", "/remote/logincheck", self.handle_remote_logincheck)
        app.router.add_get("/remote/login", self.handle_remote_login_page)
        app.router.add_get("/remote/info", self.handle_remote_info)
        app.router.add_get("/remote/{path:.*}", self.handle_remote_login_page)

        # CGI/config probes
        app.router.add_route("*", "/cgi-bin/{path:.*}", self.handle_cgi_probe)
        app.router.add_route("*", "/config/{path:.*}", self.handle_config_probe)
        app.router.add_get("/.htaccess", self.handle_sensitive_file)
        app.router.add_get("/.git/{path:.*}", self.handle_sensitive_file)
        app.router.add_get("/.env", self.handle_sensitive_file)

        # Static assets
        app.router.add_get("/favicon.ico", self.handle_favicon)

        # FortiWeb CVE-2025-64446 chain (registered before the catch-all so it
        # captures these probes instead of letting them fall to handle_404).
        app.router.add_post("/api/v2.0/user/local.add", self.handle_fortiweb_user_local_add)
        app.router.add_post(
            "/api/v2.0/system/maintenance/backup", self.handle_fortiweb_maintenance_backup
        )
        # /<anything>.dat in the web root catches the public PoC's pwned.dat
        # plus any variant filename the attacker uses.
        app.router.add_get(r"/{name:[^/]+\.dat}", self.handle_fortiweb_dat_file)

        # Catch-all (must be last)
        app.router.add_route("*", "/{path:.*}", self.handle_404)

        # Fake-vendor WAF canary (off by default): one consistent appliance identity across
        # every decoy surface on this sensor. See honeypots/deception_waf.py.
        app.on_response_prepare.append(deception_waf.on_response_prepare)


# =============================================================================
# Main Entry Point
# =============================================================================


def _mask_server_banner() -> None:
    """Mask aiohttp's default ``Server`` with the FortiGate banner everywhere — including the
    400/431 responses aiohttp emits for malformed requests *before* the app runs, which the
    per-response handlers cannot reach. Without this an oversized header returns
    ``Server: Python/… aiohttp/…`` — an instant "this is a Python honeypot" fingerprint
    (the same trap fixed on the NetScaler/SharePoint decoys)."""
    try:
        from aiohttp import web_response

        web_response.SERVER_SOFTWARE = "xxxxxxxx-xxxxx"
    except Exception as exc:  # pragma: no cover
        logger.debug("could not mask aiohttp banner: %s", exc)


async def run_server(host: str, ports: list[int], use_tls: bool = True):
    """Start the FortiGate honeypot server."""
    _mask_server_banner()
    honeypot = FortiGateHoneypot()

    app = web.Application(middlewares=[_body_middleware_factory()])
    honeypot.setup_routes(app)

    # Create SSL context if TLS enabled
    ssl_ctx = None
    if use_tls:
        if not os.path.exists(TLS_CERT_FILE) or not os.path.exists(TLS_KEY_FILE):  # noqa: ASYNC240 — a single stat, not worth a thread
            logger.error("TLS cert/key not found: %s, %s", TLS_CERT_FILE, TLS_KEY_FILE)
            logger.info(
                "Generate with: openssl req -x509 -newkey rsa:2048 -keyout fortigate.key -out fortigate.crt -days 365 -nodes"
            )
            sys.exit(1)

        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
        # Allow older TLS for compatibility with scanners
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    runner = web.AppRunner(app)
    await runner.setup()

    sites = []
    for port in ports:
        try:
            site = web.TCPSite(runner, host, port, ssl_context=ssl_ctx)
            await site.start()
            proto = "https" if use_tls else "http"
            logger.info("FortiGate honeypot listening on %s://%s:%d", proto, host, port)
            sites.append(site)
        except OSError as e:
            logger.warning("Could not bind to port %d: %s", port, e)

    if not sites:
        logger.error("No ports available. Exiting.")
        sys.exit(1)

    logger.info("FortiGate honeypot ready. Press Ctrl+C to stop.")
    logger.info("Fake device: %s (%s v%s)", HOSTNAME, FORTIGATE_MODEL, FORTIOS_VERSION)

    # Run forever
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError as exc:  # silent: server shutdown
        logging.getLogger(__name__).debug("ignored: %s", exc)
    finally:
        await runner.cleanup()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="FortiGate Admin Interface Honeypot")
    parser.add_argument("--host", default=LISTEN_HOST, help="Bind address")
    parser.add_argument(
        "--port",
        type=int,
        action="append",
        dest="ports",
        help="Port(s) to listen on (can specify multiple)",
    )
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS (dev only)")
    parser.add_argument("--log-file", default=LOG_FILE, help="Log file path")

    args = parser.parse_args()

    ports = args.ports if args.ports else DEFAULT_PORTS

    try:
        asyncio.run(run_server(args.host, ports, use_tls=not args.no_tls))
    except KeyboardInterrupt:
        logger.info("Shutting down...")


if __name__ == "__main__":
    main()
