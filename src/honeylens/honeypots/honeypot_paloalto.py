#!/usr/bin/env python3
"""
honeypot_paloalto.py — Palo Alto PAN-OS Honeypot
==================================================
High-fidelity PAN-OS firewall honeypot covering:
  Phase A: Management WebUI + CVE detection
  Phase B: GlobalProtect Portal/Gateway
  Phase C: XML API

Mimics PAN-OS 11.x management interface with realistic:
- Login page (/php/login.php)
- GlobalProtect portal/gateway (/global-protect/*, /ssl-vpn/*)
- XML API (/api/?type=keygen|op|config|commit)
- HTTP fingerprinting (empty Server header, PHPSESSID, PAN-OS ETag)

Detected CVEs:
- CVE-2024-0012 (Auth bypass via X-PAN-AUTHCHECK header)
- CVE-2024-9474 (Privilege escalation via command injection in user param)
- CVE-2025-0108 (Auth bypass via path confusion / double-encoded traversal)
- CVE-2024-3400 (GlobalProtect RCE via SESSID path traversal)
- CVE-2021-3064 (HTTP smuggling on GlobalProtect)

Default port: 4443 (TLS)

Usage:
    python honeypots/honeypot_paloalto.py
    python honeypots/honeypot_paloalto.py --port 4443
    python honeypots/honeypot_paloalto.py --no-tls

Requires: aiohttp, ssl
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import re
import secrets
import ssl
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from typing import Any, TextIO

from honeylens.eventlog_lock import log_lock
from honeylens.honeypots import deception_waf
from honeylens.honeypots.body_capture import capture as _capture_body


async def _read_body(request):
    """Best-effort raw body. aiohttp caches the read, so calling this after a handler
    has already consumed the stream returns the same bytes rather than blocking."""
    try:
        return await request.read()
    except Exception:  # a decoy must answer even when the client lies about length
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

# =============================================================================
# Configuration
# =============================================================================

DATA_DIR = os.environ.get("PANOS_DATA_DIR", "/opt/sensor/data/paloalto")
IDENTITY_DIR = os.path.join(DATA_DIR, "identity")
TLS_DIR = os.path.join(DATA_DIR, "tls")
TEMPLATE_DIR = os.path.join(DATA_DIR, "templates")

DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_PORTS = [4443]
DEFAULT_LOG_FILE = "/var/log/honeypot_paloalto.json"

# Try loading from sensor config
try:
    from honeylens.config import env

    LOG_FILE = env("PALOALTO_LOG_FILE", DEFAULT_LOG_FILE)
    LISTEN_HOST = env("PALOALTO_LISTEN_HOST", DEFAULT_LISTEN_HOST)
except ImportError:
    LOG_FILE = os.environ.get("PALOALTO_LOG_FILE", DEFAULT_LOG_FILE)
    LISTEN_HOST = DEFAULT_LISTEN_HOST


def _load_identity() -> dict:
    """Load identity from init script output."""
    identity = {
        "serial": "015101005200",
        "model": "PA-850",
        "hostname": "PA-850",
        "mac": "00:1b:17:aa:bb:cc",
        "etag_seed": "67373e00",
        "sw_version": "11.1.4",
        "app_version": "8933-8901",
        "av_version": "4820-5290",
        "threat_version": "8933-8901",
        "logdb_version": "11.1.4",
    }
    try:
        for field in ("serial", "model", "hostname", "mac", "etag_seed"):
            path = os.path.join(IDENTITY_DIR, field)
            if os.path.isfile(path):
                with open(path) as f:
                    identity[field] = f.read().strip()
        ver_path = os.path.join(IDENTITY_DIR, "version.json")
        if os.path.isfile(ver_path):
            with open(ver_path) as f:
                vdata = json.load(f)
                for k in (
                    "sw_version",
                    "app_version",
                    "av_version",
                    "threat_version",
                    "logdb_version",
                ):
                    if k in vdata:
                        identity[k] = vdata[k]
    except Exception as e:
        logger.debug("Identity load fallback: %s", e)
    return identity


def _load_template(name: str) -> str:
    """Load a pre-generated template file."""
    path = os.path.join(TEMPLATE_DIR, name)
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return f"(template {name} not found — run init_paloalto_honeypot.sh)"


IDENTITY = _load_identity()

# =============================================================================
# Logging
# =============================================================================

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("paloalto-honeypot")


# =============================================================================
# PAN-OS Login Page HTML
# =============================================================================


def _render_login_page() -> str:
    model = IDENTITY["model"]
    version = IDENTITY["sw_version"]
    hostname = IDENTITY["hostname"]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Palo Alto Networks - Login</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:#1a1f25; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       color:#c7c7c7; display:flex; justify-content:center; align-items:center; min-height:100vh; }}
.login-container {{ width:400px; }}
.logo {{ text-align:center; margin-bottom:30px; }}
.logo svg {{ width:200px; height:40px; }}
.logo-text {{ fill:#fff; font-size:18px; font-weight:700; font-family:sans-serif; }}
.login-box {{ background:#252b33; border-radius:4px; box-shadow:0 4px 20px rgba(0,0,0,.3);
              padding:40px; }}
.login-box h2 {{ color:#fff; font-size:16px; font-weight:400; margin-bottom:24px; text-align:center; }}
.form-group {{ margin-bottom:16px; }}
.form-group label {{ display:block; font-size:12px; color:#8a9098; margin-bottom:6px; }}
.form-group input {{ width:100%; padding:10px 12px; background:#2d343d; border:1px solid #3d4654;
                     color:#fff; border-radius:3px; font-size:14px; outline:none; }}
.form-group input:focus {{ border-color:#4a9eff; }}
.login-btn {{ width:100%; padding:10px; background:#4a9eff; color:#fff; border:none;
              border-radius:3px; font-size:14px; cursor:pointer; margin-top:8px; }}
.login-btn:hover {{ background:#3d8ee6; }}
.footer {{ text-align:center; margin-top:20px; font-size:11px; color:#555b63; }}
.footer .model {{ color:#8a9098; }}
</style>
</head>
<body>
<div class="login-container">
    <div class="logo">
        <svg viewBox="0 0 200 40" xmlns="http://www.w3.org/2000/svg">
            <text x="100" y="28" text-anchor="middle" class="logo-text">PALO ALTO NETWORKS</text>
        </svg>
    </div>
    <div class="login-box">
        <h2>Log In</h2>
        <form method="POST" action="/php/login.php">
            <div class="form-group">
                <label for="user">Username</label>
                <input type="text" id="user" name="user" autocomplete="username" autofocus>
            </div>
            <div class="form-group">
                <label for="passwd">Password</label>
                <input type="password" id="passwd" name="passwd" autocomplete="current-password">
            </div>
            <input type="hidden" name="challengePwd" value="">
            <button type="submit" name="ok" value="Login" class="login-btn">Log In</button>
        </form>
    </div>
    <div class="footer">
        <span class="model">{model}</span> &middot; v{version} &middot; {hostname}
    </div>
</div>
</body>
</html>"""


# =============================================================================
# GlobalProtect Portal HTML
# =============================================================================


def _render_gp_portal_page() -> str:
    return """<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Palo Alto Networks - GlobalProtect Portal</title>
<style>
body { background:#1a1f25; color:#c7c7c7; font-family:sans-serif;
       display:flex; justify-content:center; align-items:center; min-height:100vh; }
.gp-box { background:#252b33; padding:40px; border-radius:4px; width:400px;
           box-shadow:0 4px 20px rgba(0,0,0,.3); text-align:center; }
h2 { color:#fff; font-size:16px; margin-bottom:20px; }
.form-group { margin-bottom:14px; text-align:left; }
.form-group label { display:block; font-size:12px; color:#8a9098; margin-bottom:4px; }
.form-group input { width:100%; padding:10px; background:#2d343d; border:1px solid #3d4654;
                    color:#fff; border-radius:3px; font-size:14px; }
.btn { width:100%; padding:10px; background:#4a9eff; color:#fff; border:none;
       border-radius:3px; cursor:pointer; margin-top:8px; }
</style>
</head><body>
<div class="gp-box">
    <h2>GlobalProtect Portal</h2>
    <form method="POST" action="/global-protect/login.esp">
        <div class="form-group"><label>Username</label><input name="user" type="text"></div>
        <div class="form-group"><label>Password</label><input name="passwd" type="password"></div>
        <input type="hidden" name="ok" value="Login">
        <input type="hidden" name="prot" value="https:">
        <input type="hidden" name="clientVer" value="4100">
        <button type="submit" class="btn">Log In</button>
    </form>
</div>
</body></html>"""


# =============================================================================
# PaloAltoHoneypot Class
# =============================================================================


class PaloAltoHoneypot:
    """High-fidelity Palo Alto PAN-OS Honeypot."""

    def __init__(self, log_file: str = LOG_FILE):
        self.sessions: dict[str, dict[str, Any]] = {}
        self.api_keys: dict[str, str] = {}  # fake API key -> username
        self.log_file_path = log_file
        self._log_file: TextIO | None = None
        self._ensure_log_file()
        self._start_time = time.time()

    # =========================================================================
    # Logging
    # =========================================================================

    def _ensure_log_file(self):
        if self._log_file is not None:
            return
        try:
            os.makedirs(os.path.dirname(self.log_file_path), exist_ok=True)
        except (OSError, ValueError) as exc:  # silent: log dir may already exist or path is invalid
            logging.getLogger(__name__).debug("ignored: %s", exc)
        try:
            self._log_file = open(self.log_file_path, "a", buffering=1)
        except OSError as e:
            logger.debug("Cannot open log file %s: %s, using stdout", self.log_file_path, e)
            self._log_file = sys.stdout

    # Cap raw-body capture at 8 KB. The on-the-wire CVE-2026-0300 PoC
    # bodies are 2.2-2.3 KB; 8 KB gives ~3x headroom for variants without
    # bloating the JSON log file or pushing the row past Postgres TOAST
    # break-even.
    _RAW_BODY_CAP = 8 * 1024

    def log_event(
        self, event_type: str, data: dict[str, Any], request: web.Request, body: bytes | None = None
    ):
        """Log honeypot event to JSON file.

        If `body` is provided (raw bytes from the request), it is captured
        as base64 (to survive non-UTF-8 bytes like the binary tail of a
        BoF exploit body) under `raw_body_b64`, with `raw_body_len`
        recording the original length so we know whether truncation
        happened at the cap.
        """
        try:
            peername = request.transport.get_extra_info("peername") if request.transport else None
            src_port = peername[1] if peername else 0
        except (TypeError, IndexError):
            src_port = 0

        headers = {}
        for k, v in request.headers.items():
            headers[k] = v[:500]

        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "honeypot": "paloalto",
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

        if body is not None and len(body) > 0:
            event["raw_body_len"] = len(body)
            event["raw_body_b64"] = base64.b64encode(body[: self._RAW_BODY_CAP]).decode("ascii")

        try:
            if self._log_file is not None:
                with log_lock(self.log_file_path):
                    self._log_file.write(json.dumps(event) + "\n")
                    self._log_file.flush()
        except OSError as e:
            logger.debug("Log write failed: %s", e)

        logger.info("[%s] %s %s %s", event_type, request.remote, request.method, request.path)

    # =========================================================================
    # PAN-OS HTTP Headers
    # =========================================================================

    def get_standard_headers(self) -> dict[str, str]:
        """Return PAN-OS management interface headers."""
        etag_seed = IDENTITY.get("etag_seed", "67373e00")
        etag_prefix = secrets.token_hex(3)
        etag_mid = secrets.token_hex(2)
        return {
            "Server": "",  # PAN-OS uses empty Server header
            "X-FRAME-OPTIONS": "SAMEORIGIN",
            "Cache-Control": "no-store, no-cache, must-revalidate, post-check=0, pre-check=0",
            "Pragma": "no-cache",
            "Expires": "Thu, 19 Nov 1981 08:52:00 GMT",
            "ETag": f'"{etag_prefix}-{etag_mid}-{etag_seed}"',
        }

    def _make_response(
        self,
        text: str = "",
        content_type: str = "text/html; charset=utf-8",
        status: int = 200,
        extra_headers: dict | None = None,
    ) -> web.Response:
        """Build response with PAN-OS headers and PHPSESSID cookie."""
        headers = self.get_standard_headers()
        headers["Content-Type"] = content_type
        if extra_headers:
            headers.update(extra_headers)
        resp = web.Response(text=text, status=status, headers=headers)
        session_id = secrets.token_hex(16)
        resp.set_cookie("PHPSESSID", session_id, path="/", httponly=True)
        return resp

    # =========================================================================
    # CVE Detection
    # =========================================================================

    def _detect_cves(self, request: web.Request) -> list[dict[str, str]]:
        """Detect known PAN-OS CVE exploitation attempts."""
        cves = []
        path = request.path
        raw_path = request.path_qs

        # CVE-2024-0012: X-PAN-AUTHCHECK: off
        authcheck = request.headers.get("X-PAN-AUTHCHECK", "").strip().lower()
        if authcheck == "off":
            cves.append(
                {
                    "cve": "CVE-2024-0012",
                    "detail": "X-PAN-AUTHCHECK header set to 'off'",
                    "severity": "CRITICAL",
                }
            )

        # CVE-2024-9474: command injection in createRemoteAppwebSession user param
        if "createRemoteAppwebSession" in path:
            body = ""
            if hasattr(request, "_read_bytes") and request._read_bytes:
                body = request._read_bytes.decode(errors="ignore")
            if re.search(r"[`$|;&]", body) or re.search(r"[`$|;&]", raw_path):
                cves.append(
                    {
                        "cve": "CVE-2024-9474",
                        "detail": "Command injection in createRemoteAppwebSession",
                        "severity": "CRITICAL",
                    }
                )
            else:
                cves.append(
                    {
                        "cve": "CVE-2024-9474",
                        "detail": "Access to createRemoteAppwebSession endpoint",
                        "severity": "HIGH",
                    }
                )

        # CVE-2025-0108: double-encoded path traversal via /unauth/
        if "/unauth/" in raw_path:
            decoded = urllib.parse.unquote(urllib.parse.unquote(raw_path))
            if ".." in decoded:
                cves.append(
                    {
                        "cve": "CVE-2025-0108",
                        "detail": f"Double-encoded path traversal: {raw_path[:200]}",
                        "severity": "CRITICAL",
                    }
                )

        # CVE-2024-3400: SESSID cookie path traversal on GlobalProtect
        sessid = request.cookies.get("SESSID", "")
        if sessid and (".." in sessid or "${" in sessid or "`" in sessid):
            cves.append(
                {
                    "cve": "CVE-2024-3400",
                    "detail": f"SESSID path traversal: {sessid[:200]}",
                    "severity": "CRITICAL",
                }
            )

        # CVE-2021-3064: HTTP smuggling indicators
        cl = request.headers.get("Content-Length")
        te = request.headers.get("Transfer-Encoding")
        if cl and te:
            cves.append(
                {
                    "cve": "CVE-2021-3064",
                    "detail": "CL+TE HTTP smuggling attempt",
                    "severity": "CRITICAL",
                }
            )

        # .js.map suffix bypass (CVE-2024-0012 variant)
        if path.endswith(".js.map"):
            real_path = path.rsplit(".js.map", 1)[0]
            if "/php/" in real_path or "/api/" in real_path:
                cves.append(
                    {
                        "cve": "CVE-2024-0012",
                        "detail": f".js.map suffix bypass: {path[:200]}",
                        "severity": "CRITICAL",
                    }
                )

        return cves

    def _log_cves(self, cves: list[dict], request: web.Request):
        """Log all detected CVEs."""
        for cve in cves:
            self.log_event("CVE_ATTEMPT", cve, request)

    # =========================================================================
    # Phase A: Management WebUI
    # =========================================================================

    async def handle_root_redirect(self, request: web.Request) -> web.Response:
        """GET / -> 302 to /php/login.php (exact PAN-OS behaviour)."""
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)
        self.log_event("ROOT_ACCESS", {}, request)
        headers = self.get_standard_headers()
        headers["Location"] = "/php/login.php"
        resp = web.Response(status=302, headers=headers)
        resp.set_cookie("PHPSESSID", secrets.token_hex(16), path="/", httponly=True)
        return resp

    async def handle_login_page(self, request: web.Request) -> web.Response:
        """GET /php/login.php — serve PAN-OS login page."""
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)
        self.log_event("LOGIN_PAGE", {}, request)
        return self._make_response(_render_login_page())

    async def handle_login_submit(self, request: web.Request) -> web.Response:
        """POST /php/login.php — capture credentials AND raw body.

        Reads the raw body bytes BEFORE form parsing so we can record the
        full request (covers CVE-2026-0300 BoF probes, oversized POSTs,
        non-form bodies, binary tails) — request.post() consumes the
        stream so we have to manually parse_qs after raw-read.
        """
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)

        # Raw body capture must come BEFORE any form parse — once the
        # stream is read, request.post() returns empty.
        raw_body = b""
        try:
            raw_body = await request.read()
        except Exception as e:
            logger.debug("Failed to read raw POST body: %s", e)

        # Form parse — manual parse_qs from the raw bytes.
        form: dict[str, str] = {}
        if raw_body:
            try:
                parsed = urllib.parse.parse_qs(
                    raw_body.decode("utf-8", errors="replace"),
                    max_num_fields=200,
                )
                form = {k: v[0] for k, v in parsed.items() if v}
            except Exception as e:
                logger.debug("Failed to form-parse POST body: %s", e)

        username = form.get("user", "")[:100]
        password = form.get("passwd", "")[:200]

        is_default = username == "admin" and password == "admin"
        event_type = "DEFAULT_CREDENTIAL_ATTEMPT" if is_default else "CREDENTIAL_CAPTURE"
        severity = "HIGH" if is_default else "MEDIUM"

        self.log_event(
            event_type,
            {
                "username": username,
                "password": password,
                "challenge_pwd": form.get("challengePwd", "")[:50],
                "default_creds": is_default,
                "severity": severity,
            },
            request,
            body=raw_body,
        )

        # Always "succeed" — redirect to dashboard
        session_id = secrets.token_hex(16)
        self.sessions[session_id] = {
            "username": username,
            "created": time.time(),
            "ip": request.remote,
        }

        resp = self._make_response(
            json.dumps({"status": "success", "redirect": "/php/dashboard.php"}),
            content_type="application/json",
        )
        return resp

    async def handle_unauth(self, request: web.Request) -> web.Response:
        """ALL methods on /unauth/* — unauthenticated zone (CVE-2025-0108 target).

        Capture raw body for POST/PUT/PATCH so an exploit dropping its
        payload into the unauth zone is preserved end-to-end.
        """
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)

        raw_body = b""
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                raw_body = await request.read()
            except Exception as e:
                logger.debug("Failed to read raw unauth body: %s", e)

        self.log_event(
            "UNAUTH_ACCESS",
            {"path": request.path[:200]},
            request,
            body=raw_body if raw_body else None,
        )
        return self._make_response("", status=403)

    async def handle_create_remote_session(self, request: web.Request) -> web.Response:
        """POST /php/utils/createRemoteAppwebSession.php — CVE-2024-9474 target."""
        cves = self._detect_cves(request)

        try:
            body = await request.read()
            body_str = body.decode(errors="ignore")[:2000]
        except Exception as e:
            logger.debug("Failed to read request body: %s", e)
            body_str = ""

        # Check for command injection in user param
        user_match = re.search(r"user=([^&]*)", body_str)
        user_val = urllib.parse.unquote(user_match.group(1)) if user_match else ""
        if re.search(r"[`$|;&]", user_val):
            if not any(c["cve"] == "CVE-2024-9474" for c in cves):
                cves.append(
                    {
                        "cve": "CVE-2024-9474",
                        "detail": f"Command injection in user param: {user_val[:200]}",
                        "severity": "CRITICAL",
                    }
                )

        if cves:
            self._log_cves(cves, request)

        self.log_event(
            "CREATE_REMOTE_SESSION",
            {
                "body": body_str[:500],
                "user_param": user_val[:200],
            },
            request,
            body=body if isinstance(body, (bytes, bytearray)) else None,
        )

        return self._make_response(
            json.dumps({"@status": "success", "result": ""}), content_type="application/json"
        )

    async def handle_dashboard(self, request: web.Request) -> web.Response:
        """GET /php/dashboard.php or other post-auth pages."""
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)
        self.log_event("DASHBOARD_ACCESS", {"path": request.path[:200]}, request)
        # Return login redirect (session expired)
        headers = self.get_standard_headers()
        headers["Location"] = "/php/login.php"
        return web.Response(status=302, headers=headers)

    # =========================================================================
    # Phase B: GlobalProtect Portal/Gateway
    # =========================================================================

    async def handle_gp_prelogin(self, request: web.Request) -> web.Response:
        """GET/POST /global-protect/prelogin.esp or /ssl-vpn/prelogin.esp"""
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)

        client_ver = request.query.get("clientVer", "")
        client_os = request.query.get("clientos", "")

        self.log_event(
            "GP_PRELOGIN",
            {
                "client_ver": client_ver,
                "client_os": client_os,
                "user_agent": request.headers.get("User-Agent", "")[:200],
                "endpoint": request.path,
            },
            request,
        )

        version = IDENTITY["sw_version"]
        xml = f"""<prelogin-response>
  <status>Success</status>
  <ccusername/>
  <autosubmit>false</autosubmit>
  <authentication-message>Enter login credentials</authentication-message>
  <username-label>Username</username-label>
  <password-label>Password</password-label>
  <panos-version>{version}</panos-version>
  <license>yes</license>
  <license-v6>yes</license-v6>
  <saml-auth-status>0</saml-auth-status>
</prelogin-response>"""
        return self._make_response(xml, content_type="application/xml")

    async def handle_gp_login(self, request: web.Request) -> web.Response:
        """POST /global-protect/login.esp or /ssl-vpn/login.esp"""
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)

        # Read raw body BEFORE form parse — see handle_login_submit comment.
        raw_body = b""
        try:
            raw_body = await request.read()
        except Exception as e:
            logger.debug("Failed to read raw GP login body: %s", e)

        form: dict[str, str] = {}
        if raw_body:
            try:
                parsed = urllib.parse.parse_qs(
                    raw_body.decode("utf-8", errors="replace"),
                    max_num_fields=200,
                )
                form = {k: v[0] for k, v in parsed.items() if v}
            except Exception as e:
                logger.debug("Failed to form-parse GP login body: %s", e)

        username = form.get("user", "")[:100]
        password = form.get("passwd", "")[:200]
        computer = form.get("computer", "")[:100]
        client_ip = form.get("client-ip", "")[:50]
        os_ver = form.get("os-version", "")[:100]
        client_os = form.get("clientos", "")[:50]
        gp_ver = form.get("clientgpversion", "")[:20]
        host_id = form.get("host-id", "")[:100]

        # CVE-2026-0257 (PAN-OS GlobalProtect auth-override cookie forgery).
        # No benign GP client sends portal-(prelogon)userauthcookie to a
        # fresh /login.esp POST — the only legitimate path is the auth-override
        # re-auth flow which goes through the gateway, not this endpoint.
        # Truncate the forged blob to 512B for storage (full blob in raw_body).
        portal_authcookie = form.get("portal-userauthcookie", "")[:512]
        portal_prelogon_cookie = form.get("portal-prelogonuserauthcookie", "")[:512]
        is_cve_2026_0257 = bool(portal_authcookie or portal_prelogon_cookie)

        # Rapid7 observed-kit artifacts (2026-05-17 / 2026-05-21 waves):
        # spoofed MAC and the two operator-machine names.
        is_kit_mac = "aa:bb:cc:dd:ee:ff" in raw_body.decode("latin-1", errors="ignore").lower()
        is_kit_machine = computer in ("GP-CLIENT", "DESKTOP-GP01")

        is_gp_client = "PAN GlobalProtect" in request.headers.get("User-Agent", "")

        # CVE-2026-0257 raises severity HIGH; kit-artifact matches without
        # the cookie still bump to MEDIUM-HIGH for follow-up analysis.
        if is_cve_2026_0257:
            severity = "HIGH"
            attack_type = "cve_2026_0257_authbypass"
            self._log_cves(
                [
                    {
                        "cve": "CVE-2026-0257",
                        "detail": (
                            f"portal-userauthcookie field present ({len(portal_authcookie)}B)"
                            if portal_authcookie
                            else f"portal-prelogonuserauthcookie field present "
                            f"({len(portal_prelogon_cookie)}B)"
                        ),
                        "severity": "HIGH",
                    }
                ],
                request,
            )
        elif is_kit_mac or is_kit_machine:
            severity = "MEDIUM"
            attack_type = "cve_2026_0257_kit_artifact"
        else:
            severity = "MEDIUM"
            attack_type = None

        self.log_event(
            "GP_LOGIN",
            {
                "username": username,
                "password": password,
                "computer": computer,
                "client_ip": client_ip,
                "os_version": os_ver,
                "client_os": client_os,
                "gp_version": gp_ver,
                "host_id": host_id,
                "is_gp_client": is_gp_client,
                "endpoint": request.path,
                "severity": severity,
                "attack_type": attack_type,
                "cve_2026_0257_authbypass": is_cve_2026_0257,
                "portal_userauthcookie": portal_authcookie,
                "portal_prelogonuserauthcookie": portal_prelogon_cookie,
                "kit_mac_spoofed": is_kit_mac,
                "kit_machine_name": is_kit_machine,
            },
            request,
            body=raw_body,
        )

        # Return auth cookie (fake)
        auth_cookie = secrets.token_hex(16)
        xml = f"""<jnlp>
  <application-desc>
    <argument>PAN_GP_AUTH</argument>
    <argument>{auth_cookie}</argument>
    <argument>{IDENTITY["hostname"]}</argument>
    <argument>{username}</argument>
    <argument>auth-cookie</argument>
    <argument>4100</argument>
  </application-desc>
</jnlp>"""
        resp = self._make_response(xml, content_type="application/xml")
        resp.set_cookie("SESSID", secrets.token_hex(16), path="/", httponly=True)
        return resp

    async def handle_gp_portal(self, request: web.Request) -> web.Response:
        """GET /global-protect/portal/portal.esp"""
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)
        self.log_event("GP_PORTAL_PAGE", {}, request)
        return self._make_response(_render_gp_portal_page())

    async def handle_gp_getconfig(self, request: web.Request) -> web.Response:
        """POST /global-protect/getconfig.esp or /ssl-vpn/getconfig.esp"""
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)

        self.log_event("GP_GETCONFIG", {"endpoint": request.path}, request)

        hostname = IDENTITY["hostname"]
        xml = f"""<policy>
  <gateways>
    <external>
      <list>
        <entry name="{hostname}">
          <ip><ipv4>{hostname}</ipv4></ip>
          <priority>1</priority>
          <manual>yes</manual>
        </entry>
      </list>
    </external>
  </gateways>
</policy>"""
        return self._make_response(xml, content_type="application/xml")

    async def handle_gp_hipreport(self, request: web.Request) -> web.Response:
        """POST /ssl-vpn/hipreport.esp — CVE-2024-3400 target."""
        cves = self._detect_cves(request)

        sessid = request.cookies.get("SESSID", "")
        if sessid and (".." in sessid or "${" in sessid or "`" in sessid):
            if not any(c["cve"] == "CVE-2024-3400" for c in cves):
                cves.append(
                    {
                        "cve": "CVE-2024-3400",
                        "detail": f"SESSID path traversal on hipreport.esp: {sessid[:200]}",
                        "severity": "CRITICAL",
                    }
                )

        if cves:
            self._log_cves(cves, request)

        try:
            data = await request.post()
            body_data = {k: str(v)[:200] for k, v in data.items()}
        except Exception as e:
            logger.debug("Failed to parse POST body: %s", e)
            body_data = {}

        self.log_event(
            "GP_HIPREPORT",
            {
                "sessid": sessid[:200],
                "body": body_data,
                "severity": "HIGH" if sessid else "MEDIUM",
            },
            request,
        )

        # Return 403 (real PAN-OS returns 403 when file is created = exploitable)
        return self._make_response("", status=403)

    async def handle_gp_logout(self, request: web.Request) -> web.Response:
        """POST /global-protect/logout.esp or /ssl-vpn/logout.esp"""
        self.log_event("GP_LOGOUT", {"endpoint": request.path}, request)
        return self._make_response(
            "<response><status>Success</status></response>", content_type="application/xml"
        )

    # =========================================================================
    # Phase C: XML API
    # =========================================================================

    async def handle_api(self, request: web.Request) -> web.Response:
        """Handle /api/ endpoint — keygen, op, config, commit."""
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)

        api_type = request.query.get("type", "")

        if api_type == "keygen":
            return await self._api_keygen(request)
        elif api_type == "op":
            return await self._api_op(request)
        elif api_type == "config":
            return await self._api_config(request)
        elif api_type == "commit":
            return await self._api_commit(request)
        else:
            self.log_event(
                "API_UNKNOWN",
                {
                    "type": api_type,
                    "query": str(request.query_string)[:500],
                },
                request,
            )
            xml = '<response status="error" code="400"><result><msg>Invalid request</msg></result></response>'
            return self._make_response(xml, content_type="application/xml", status=400)

    async def _api_keygen(self, request: web.Request) -> web.Response:
        """POST /api/?type=keygen — capture credentials, return fake API key."""
        username = request.query.get("user", "")[:100]
        password = request.query.get("password", "")[:200]

        # Also check POST body
        if not username:
            try:
                data = await request.post()
                username = str(data.get("user", ""))[:100]
                password = str(data.get("password", ""))[:200]
            except Exception as e:
                logger.debug("Failed to parse API POST body: %s", e)

        if not username:
            self.log_event("API_KEYGEN_INVALID", {}, request)
            xml = '<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>'
            return self._make_response(xml, content_type="application/xml", status=403)

        # Generate fake API key (base64, ~120 chars like real PAN-OS)
        fake_key_data = f"{username}:{password}:{secrets.token_hex(32)}"
        fake_key = base64.b64encode(fake_key_data.encode()).decode()

        self.api_keys[fake_key] = username

        is_default = username == "admin" and password == "admin"
        self.log_event(
            "API_KEYGEN",
            {
                "username": username,
                "password": password,
                "api_key": fake_key[:40] + "...",
                "default_creds": is_default,
                "severity": "HIGH",
            },
            request,
        )

        xml = f'<response status="success"><result><key>{fake_key}</key></result></response>'

        # An issued API key is exactly the artefact an AI agent is sent to analyse,
        # so it is worth a canary (Idea 52) — same reasoning as the K8s Secret read.
        canary_headers = {}
        if (
            ai_canary is not None
            and ai_canary.enabled()
            and ai_canary.carrier_enabled("PANOS_KEYGEN")
        ):
            _nonce, canary_headers = ai_canary.issue(
                "panos",
                "/api/?type=keygen",
                request.headers.get("Host", ""),
                origin_src_ip=(request.remote or ""),
                context="PAN-OS API key",
            )

        return self._make_response(
            xml, content_type="application/xml", extra_headers=canary_headers or None
        )

    async def _api_op(self, request: web.Request) -> web.Response:
        """Handle /api/?type=op&cmd=<xml> — operational commands."""
        cmd = request.query.get("cmd", "")
        api_key = request.query.get("key", "") or request.headers.get("X-PAN-KEY", "")

        self.log_event(
            "API_OP",
            {
                "cmd": cmd[:500],
                "api_key": api_key[:40] + "..." if api_key else "",
            },
            request,
        )

        # Parse the XML command and return appropriate response
        cmd_lower = cmd.lower()

        if "<show><system><info>" in cmd_lower:
            sysinfo = _load_template("show_system_info.txt")
            xml = f'<response status="success"><result><system>\n{sysinfo}</system></result></response>'
        elif "<show><session><info>" in cmd_lower:
            xml = """<response status="success"><result>
num-max:           262142
num-active:        1847
num-mcast:         0
num-udp:           312
num-icmp:          5
num-predict:       0
num-bcast:         0
num-installed:     1847
num-tcp:           1530
</result></response>"""
        elif "<show><interface>" in cmd_lower:
            ifaces = _load_template("show_interface_all.txt")
            xml = f'<response status="success"><result>\n{ifaces}</result></response>'
        else:
            xml = '<response status="success"><result></result></response>'

        return self._make_response(xml, content_type="application/xml")

    async def _api_config(self, request: web.Request) -> web.Response:
        """Handle /api/?type=config — get/set/show configuration."""
        action = request.query.get("action", "get")
        xpath = request.query.get("xpath", "")
        api_key = request.query.get("key", "") or request.headers.get("X-PAN-KEY", "")

        severity = "MEDIUM"
        if action in ("set", "edit", "delete", "rename", "move"):
            severity = "CRITICAL"

        self.log_event(
            "API_CONFIG",
            {
                "action": action,
                "xpath": xpath[:500],
                "api_key": api_key[:40] + "..." if api_key else "",
                "severity": severity,
            },
            request,
        )

        if action in ("set", "edit", "delete"):
            # Config modification attempt
            self.log_event(
                "API_CONFIG_WRITE",
                {
                    "action": action,
                    "xpath": xpath[:500],
                    "severity": "CRITICAL",
                },
                request,
            )

        if action == "get" or action == "show":
            # Return minimal config fragment
            xml = f"""<response status="success">
<result>
  <config>
    <devices><entry name="localhost.localdomain">
      <deviceconfig><system>
        <hostname>{IDENTITY["hostname"]}</hostname>
        <ip-address>10.0.0.1</ip-address>
        <timezone>US/Pacific</timezone>
        <update-server>updates.paloaltonetworks.com</update-server>
      </system></deviceconfig>
    </entry></devices>
  </config>
</result>
</response>"""
        else:
            xml = '<response status="success"><msg>command succeeded</msg></response>'

        return self._make_response(xml, content_type="application/xml")

    async def _api_commit(self, request: web.Request) -> web.Response:
        """Handle /api/?type=commit — log as CRITICAL."""
        api_key = request.query.get("key", "") or request.headers.get("X-PAN-KEY", "")
        cmd = request.query.get("cmd", "")

        self.log_event(
            "API_COMMIT",
            {
                "cmd": cmd[:500],
                "api_key": api_key[:40] + "..." if api_key else "",
                "severity": "CRITICAL",
            },
            request,
        )

        xml = """<response status="success" code="19">
<result><msg><line>Commit job enqueued with jobid 42</line></msg><job>42</job></result>
</response>"""
        return self._make_response(xml, content_type="application/xml")

    # =========================================================================
    # Catch-all & Static Resources
    # =========================================================================

    async def handle_images(self, request: web.Request) -> web.Response:
        """Serve static image paths (return 1x1 transparent PNG)."""
        # 1x1 transparent PNG
        pixel = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIABQAB"
            "Nl7BcQAAAABJRU5ErkJggg=="
        )
        return web.Response(
            body=pixel, content_type="image/png", headers=self.get_standard_headers()
        )

    async def handle_styles(self, request: web.Request) -> web.Response:
        """Serve fake CSS."""
        return self._make_response("/* PAN-OS styles */", content_type="text/css")

    async def handle_catchall(self, request: web.Request) -> web.Response:
        """Catch-all for unmatched paths."""
        cves = self._detect_cves(request)
        if cves:
            self._log_cves(cves, request)
        _unknown = {
            "path": request.path[:300],
            "method": request.method,
        }
        # Record what was actually sent, not just where it was aimed. Bounded and
        # credential-redacted; see honeypots/body_capture.py.
        _unknown.update(
            _capture_body(
                await _read_body(request), request.path, request.headers.get("Content-Type", "")
            )
        )
        self.log_event("UNKNOWN_PATH", _unknown, request)
        return self._make_response("", status=404)

    # =========================================================================
    # Phase E: Captive Portal
    # =========================================================================

    async def handle_captive_redirect(self, request: web.Request) -> web.Response:
        """Catch-all on captive portal — redirect to uid.php login."""
        original_url = request.query.get("url", "http://www.example.com")
        self.log_event(
            "CAPTIVE_REDIRECT",
            {
                "original_url": original_url[:500],
                "path": request.path[:200],
            },
            request,
        )
        headers = self.get_standard_headers()
        fw_ip = request.host.split(":")[0] if request.host else "10.0.0.1"
        headers["Location"] = f"https://{fw_ip}:6082/php/uid.php?vsys=1&rule=0&url={original_url}"
        return web.Response(status=302, headers=headers)

    async def handle_captive_uid(self, request: web.Request) -> web.Response:
        """GET /php/uid.php — captive portal authentication page."""
        vsys = request.query.get("vsys", "1")
        rule = request.query.get("rule", "0")
        url = request.query.get("url", "")

        self.log_event(
            "CAPTIVE_AUTH_PAGE",
            {
                "vsys": vsys,
                "rule": rule,
                "redirect_url": url[:500],
            },
            request,
        )

        hostname = IDENTITY["hostname"]
        html = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Authentication Required</title>
<style>
body {{ background:#f5f5f5; font-family:-apple-system,sans-serif; display:flex;
       justify-content:center; align-items:center; min-height:100vh; margin:0; }}
.portal {{ background:#fff; padding:40px; border-radius:6px; width:380px;
           box-shadow:0 2px 10px rgba(0,0,0,.1); }}
.portal h2 {{ color:#333; font-size:18px; margin:0 0 6px; }}
.portal p {{ color:#666; font-size:13px; margin:0 0 24px; }}
.logo {{ color:#da3743; font-weight:700; font-size:12px; letter-spacing:1px;
         margin-bottom:20px; }}
.form-group {{ margin-bottom:14px; }}
.form-group label {{ display:block; font-size:12px; color:#666; margin-bottom:4px; }}
.form-group input {{ width:100%; padding:10px; border:1px solid #ddd; border-radius:3px;
                     font-size:14px; box-sizing:border-box; }}
.btn {{ width:100%; padding:10px; background:#4a9eff; color:#fff; border:none;
        border-radius:3px; font-size:14px; cursor:pointer; }}
.btn:hover {{ background:#3d8ee6; }}
.footer {{ text-align:center; margin-top:16px; font-size:10px; color:#999; }}
</style>
</head><body>
<div class="portal">
    <div class="logo">PALO ALTO NETWORKS</div>
    <h2>Authentication Required</h2>
    <p>Please enter your credentials to access the network.</p>
    <form method="POST" action="/php/uid.php?vsys={vsys}&rule={rule}&url={url}">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="user" autocomplete="username" autofocus>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" autocomplete="current-password">
        </div>
        <button type="submit" class="btn">Authenticate</button>
    </form>
    <div class="footer">{hostname} &mdash; Captive Portal</div>
</div>
</body></html>"""
        return self._make_response(html)

    async def handle_captive_login(self, request: web.Request) -> web.Response:
        """POST /php/uid.php — captive portal credential capture.

        This is the CVE-2026-0300 attack surface (PAN-OS User-ID
        Authentication Portal). Raw body capture is essential here:
        BoF exploit bodies are 2-3 KB of padding + shellcode, and the
        binary tail won't survive UTF-8 decode — base64 it.
        """
        # Read raw body BEFORE form parse — see handle_login_submit comment.
        raw_body = b""
        try:
            raw_body = await request.read()
        except Exception as e:
            logger.debug("Failed to read raw POST body: %s", e)

        form: dict[str, str] = {}
        if raw_body:
            try:
                parsed = urllib.parse.parse_qs(
                    raw_body.decode("utf-8", errors="replace"),
                    max_num_fields=200,
                )
                form = {k: v[0] for k, v in parsed.items() if v}
            except Exception as e:
                logger.debug("Failed to form-parse POST body: %s", e)

        username = form.get("user", "")[:100]
        password = form.get("password", "")[:200]
        redirect_url = request.query.get("url", "")
        vsys = request.query.get("vsys", "1")

        self.log_event(
            "CAPTIVE_LOGIN",
            {
                "username": username,
                "password": password,
                "vsys": vsys,
                "redirect_url": redirect_url[:500],
                "severity": "MEDIUM",
            },
            request,
            body=raw_body,
        )

        # "Success" — redirect to original URL
        if redirect_url:
            headers = self.get_standard_headers()
            headers["Location"] = redirect_url
            return web.Response(status=302, headers=headers)

        return self._make_response(
            "<html><body><p>Authentication successful. You may now access the network.</p></body></html>"
        )

    async def handle_captive_cp(self, request: web.Request) -> web.Response:
        """GET /php/cp.php — captive portal page."""
        self.log_event("CAPTIVE_CP_PAGE", {}, request)
        return await self.handle_captive_uid(request)

    # =========================================================================
    # Route Setup
    # =========================================================================

    def setup_routes(self, app: web.Application):
        """Register all routes for management interface."""
        # Phase A: Management WebUI
        app.router.add_get("/", self.handle_root_redirect)
        app.router.add_get("/php/login.php", self.handle_login_page)
        app.router.add_post("/php/login.php", self.handle_login_submit)
        app.router.add_route(
            "*",
            "/php/utils/createRemoteAppwebSession.php{suffix:.*}",
            self.handle_create_remote_session,
        )
        app.router.add_route("*", r"/unauth/{path:.*}", self.handle_unauth)
        app.router.add_get(r"/php/{path:.*}", self.handle_dashboard)

        # Phase B: GlobalProtect
        app.router.add_route("*", "/global-protect/prelogin.esp", self.handle_gp_prelogin)
        app.router.add_route("*", "/ssl-vpn/prelogin.esp", self.handle_gp_prelogin)
        app.router.add_route("*", "/global-protect/login.esp", self.handle_gp_login)
        app.router.add_route("*", "/ssl-vpn/login.esp", self.handle_gp_login)
        app.router.add_get("/global-protect/portal/portal.esp", self.handle_gp_portal)
        app.router.add_route("*", "/global-protect/getconfig.esp", self.handle_gp_getconfig)
        app.router.add_route("*", "/ssl-vpn/getconfig.esp", self.handle_gp_getconfig)
        app.router.add_route("*", "/ssl-vpn/hipreport.esp", self.handle_gp_hipreport)
        app.router.add_route("*", "/global-protect/logout.esp", self.handle_gp_logout)
        app.router.add_route("*", "/ssl-vpn/logout.esp", self.handle_gp_logout)

        # Phase C: XML API
        app.router.add_route("*", "/api/", self.handle_api)

        # Static resources
        app.router.add_get(r"/images/{path:.*}", self.handle_images)
        app.router.add_get(r"/styles/{path:.*}", self.handle_styles)

        # Fake-vendor WAF canary (off by default): one consistent appliance identity across
        # every decoy surface on this sensor. See honeypots/deception_waf.py.
        app.on_response_prepare.append(deception_waf.on_response_prepare)
        app.router.add_get(r"/global-protect/portal/css/{path:.*}", self.handle_styles)

        # Catch-all (must be last)
        app.router.add_route("*", r"/{path:.*}", self.handle_catchall)

    def setup_captive_routes(self, app: web.Application):
        """Register routes for captive portal (separate app on ports 6082/6080)."""
        app.router.add_get("/php/uid.php", self.handle_captive_uid)
        app.router.add_post("/php/uid.php", self.handle_captive_login)
        app.router.add_get("/php/cp.php", self.handle_captive_cp)
        app.router.add_route("*", r"/{path:.*}", self.handle_captive_redirect)

        # Fake-vendor WAF canary (off by default): the captive portal presents the same WAF
        # identity as the management app so the appliance is consistent. See deception_waf.py.
        app.on_response_prepare.append(deception_waf.on_response_prepare)


# =============================================================================
# Server Startup
# =============================================================================


def _mask_server_banner() -> None:
    """Mask aiohttp's default ``Server`` to match PAN-OS (empty Server) on the 400/431
    responses aiohttp emits for malformed requests *before* the app runs, which the
    per-response handlers cannot reach. Without this an oversized header returns
    ``Server: Python/… aiohttp/…`` — an instant honeypot fingerprint (the same trap fixed on
    the NetScaler/SharePoint decoys). One global covers both the management and captive apps."""
    try:
        from aiohttp import web_response

        web_response.SERVER_SOFTWARE = ""
    except Exception as exc:  # pragma: no cover
        logger.debug("could not mask aiohttp banner: %s", exc)


async def run_server(
    host: str, ports: list[int], use_tls: bool = True, captive_ports: list[int] | None = None
):
    _mask_server_banner()
    honeypot = PaloAltoHoneypot()

    # --- Management app (Phases A-C) ---
    app = web.Application()
    honeypot.setup_routes(app)

    ssl_ctx = None
    if use_tls:
        cert_file = os.path.join(TLS_DIR, "management.crt")
        key_file = os.path.join(TLS_DIR, "management.key")

        if not os.path.exists(cert_file) or not os.path.exists(key_file):  # noqa: ASYNC240 — a single stat, not worth a thread
            logger.error("TLS cert/key not found: %s, %s", cert_file, key_file)
            logger.error("Run: scripts/init_paloalto_honeypot.sh")
            sys.exit(1)

        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(cert_file, key_file)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    runner = web.AppRunner(app)
    await runner.setup()
    runners = [runner]

    sites = []
    for port in ports:
        try:
            site = web.TCPSite(runner, host, port, ssl_context=ssl_ctx)
            await site.start()
            proto = "https" if use_tls else "http"
            logger.info("PAN-OS honeypot listening on %s://%s:%d", proto, host, port)
            logger.info(
                "  Model: %s  Serial: %s  Version: %s",
                IDENTITY["model"],
                IDENTITY["serial"],
                IDENTITY["sw_version"],
            )
            sites.append(site)
        except OSError as e:
            logger.warning("Could not bind to port %d: %s", port, e)

    # --- Captive Portal app (Phase E) ---
    if captive_ports:
        captive_app = web.Application()
        honeypot.setup_captive_routes(captive_app)

        # Captive portal TLS (separate cert)
        captive_ssl = None
        if use_tls:
            captive_cert = os.path.join(TLS_DIR, "captive.crt")
            captive_key = os.path.join(TLS_DIR, "captive.key")
            if os.path.exists(captive_cert) and os.path.exists(captive_key):  # noqa: ASYNC240 — a single stat, not worth a thread
                captive_ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                captive_ssl.load_cert_chain(captive_cert, captive_key)
                captive_ssl.minimum_version = ssl.TLSVersion.TLSv1_2

        captive_runner = web.AppRunner(captive_app)
        await captive_runner.setup()
        runners.append(captive_runner)

        for port in captive_ports:
            try:
                # Port 6082 = HTTPS, port 6080/6081 = HTTP
                use_ssl = captive_ssl if port == 6082 else None
                site = web.TCPSite(captive_runner, host, port, ssl_context=use_ssl)
                await site.start()
                proto = "https" if use_ssl else "http"
                logger.info("PAN-OS captive portal listening on %s://%s:%d", proto, host, port)
                sites.append(site)
            except OSError as e:
                logger.warning("Could not bind captive portal to port %d: %s", port, e)

    if not sites:
        logger.error("No ports bound — exiting")
        for r in runners:
            await r.cleanup()
        sys.exit(1)

    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError as exc:  # silent: server shutdown
        logging.getLogger(__name__).debug("ignored: %s", exc)
    finally:
        for r in runners:
            await r.cleanup()


def main():
    global LOG_FILE

    parser = argparse.ArgumentParser(description="Palo Alto PAN-OS Honeypot (Phases A-E)")
    parser.add_argument("--host", default=LISTEN_HOST, help="Bind address")
    parser.add_argument(
        "--port",
        type=int,
        action="append",
        dest="ports",
        help="Management listen port (can specify multiple)",
    )
    parser.add_argument(
        "--captive-port",
        type=int,
        action="append",
        dest="captive_ports",
        help="Captive portal port (default: 6082 6080)",
    )
    parser.add_argument("--no-captive", action="store_true", help="Disable captive portal")
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS")
    parser.add_argument("--log-file", default=LOG_FILE, help="JSON log file path")
    args = parser.parse_args()

    if args.log_file != LOG_FILE:
        LOG_FILE = args.log_file

    ports = args.ports if args.ports else DEFAULT_PORTS

    captive_ports = None
    if not args.no_captive:
        captive_ports = args.captive_ports if args.captive_ports else [6082, 6080]

    asyncio.run(run_server(args.host, ports, use_tls=not args.no_tls, captive_ports=captive_ports))


if __name__ == "__main__":
    main()
