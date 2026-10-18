"""
honeypot.py — Multi-Protocol Honeypot Service (Rewritten)
==========================================================
High-interaction honeypot with protocol-aware responders.

Requires: Python >= 3.9 (Rocky Linux 9 default)

Supported protocols:
  - HTTP / HTTPS (Flask web honeypot + TLS)
  - SSH          (banner + auth capture)
  - Telnet       (login prompt emulation)
  - FTP          (banner + auth)
  - SMTP         (EHLO/MAIL/RCPT conversation)
  - Modbus TCP   (function code 0x03/0x04 read holding/input registers)
  - MQTT         (CONNECT/CONNACK handshake)
  - MySQL        (greeting + auth handshake)
  - PostgreSQL   (startup + auth)
  - Oracle TNS   (REFUSE/ACCEPT handshake)
  - Java RMI     (registry stub)
  - RDP          (x224 + MCS connect)
  - Auto-detect  (payload-based classification)

Security:
  - All server banners are generic / spoofed — no version leakage
  - TLS support on HTTPS/MQTTS ports using honeypot certificate
  - Structured JSON logging per connection

Run as root (needed for privileged ports and traffic dumps):
    sudo python honeypot.py
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import os
import re
import socket as socket_module
import ssl
import struct
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, cast

import werkzeug.serving
from flask import Flask, render_template_string, request

from honeylens.config import (
    HONEY_TLS_CERT,
    HONEY_TLS_CIPHERS,
    HONEY_TLS_KEY,
    HONEYPOTNG_LOG_DIR,
    HONEYPOTNG_PATTERNS_FILE,
    HONEYPOTNG_SERVICES,
    HONEYPOTNG_TRAFFIC_DIR,
    HONEYWEB_ACCESS_LOG,
    HONEYWEB_CONSOLE_LOG,
    HONEYWEB_HOST,
    HONEYWEB_LOG_DIR,
    HONEYWEB_PORT,
    HONEYWEB_TLS_PORT,
    TLS_MIN_VERSION,
)
from honeylens.eventlog_lock import append_line
from honeylens.honeypots.honeypots_config import get_profile as _get_profile
from honeylens.honeypots.sink import public_port

# JA3 fingerprinting
try:
    from honeylens.classification.ja3 import identify_ja3, parse_client_hello, parse_server_hello

    _HAS_JA3 = True
except ImportError:
    _HAS_JA3 = False
    parse_client_hello = None  # type: ignore[assignment]
    parse_server_hello = None  # type: ignore[assignment]
    identify_ja3 = None  # type: ignore[assignment]

# ===========================================================================
# Directory bootstrap
# ===========================================================================


# ===========================================================================
# Logging
# ===========================================================================

logger = logging.getLogger("honeypot")

# Also log to stderr
_sh = logging.StreamHandler()
_sh.setLevel(logging.INFO)
_sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_sh)


# ===========================================================================
# Utility
# ===========================================================================


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _tag(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sanitize(text: str) -> str:
    text = text.replace("\x00", "").replace("\u0000", "")
    return re.sub(r"[\x00-\x1F\x7F]", "", text).strip()


def _log_event(port: int, protocol: str, peer: tuple, extra: dict | None = None) -> None:
    """Append a JSON event to the per-protocol log file.

    ``port`` is the bound port; the event carries the protocol port (``public_port``) —
    in a container the process binds 30022 for SSH and the host DNATs 22 to it.
    """
    port = public_port(port) or port
    entry = {
        "timestamp": now_iso(),
        "protocol": protocol,
        "peer_ip": peer[0],
        "peer_port": peer[1],
        "port": port,
    }
    if extra:
        entry.update(extra)

    log_path = Path(HONEYPOTNG_LOG_DIR) / f"{protocol}_{port}.json"
    append_line(log_path, json.dumps(entry, default=str))


# ===========================================================================
# TLS context for honeypot services
# ===========================================================================


def _make_honey_ssl_ctx() -> ssl.SSLContext | None:
    """Create an SSL context for TLS-enabled honeypot ports.

    If the cert/key pair is absent, auto-generates a self-signed cert so that
    MQTT-TLS (port 8883) and HTTPS work immediately without manual setup.
    """
    if not (os.path.exists(HONEY_TLS_CERT) and os.path.exists(HONEY_TLS_KEY)):
        logger.warning("Honeypot TLS cert/key not found — attempting auto-generation")
        try:
            import subprocess as _sp  # nosec B404 — fixed openssl command below

            os.makedirs(os.path.dirname(HONEY_TLS_CERT), exist_ok=True)
            # Generate RSA 2048 key + self-signed cert (10-year validity)
            _sp.run(  # noqa: S603 # nosec B603 B607 — fixed openssl command, arguments as a list
                [  # noqa: S607
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    HONEY_TLS_KEY,
                    "-out",
                    HONEY_TLS_CERT,
                    "-days",
                    "3650",
                    "-nodes",
                    "-subj",
                    "/C=PL/ST=Silesia/L=Bytom/O=HoneypotNG/CN=honeypot.local",
                ],
                check=True,
                capture_output=True,
            )
            logger.info("Auto-generated honeypot TLS cert: %s", HONEY_TLS_CERT)
        except Exception as _e:
            logger.warning("Auto-cert generation failed: %s — TLS ports will be plain TCP", _e)
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    try:
        # Set minimum version per config
        if TLS_MIN_VERSION == "TLSv1.3":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        ctx.set_ciphers(HONEY_TLS_CIPHERS)
        ctx.load_cert_chain(certfile=HONEY_TLS_CERT, keyfile=HONEY_TLS_KEY)
    except (ValueError, ssl.SSLError, OSError) as _e:
        # Degrade to plain TCP (same contract as the cert-missing path) instead
        # of crashing at import — e.g. a platform SSL lib without TLS 1.3.
        logger.warning("TLS context setup failed (%s) — TLS ports will be plain TCP", _e)
        return None

    logger.info("Honeypot TLS context created (min=%s)", TLS_MIN_VERSION)
    return ctx


_honey_ssl_ctx = _make_honey_ssl_ctx()


def _extract_tls_metadata(writer: asyncio.StreamWriter) -> dict | None:
    """
    Extract TLS session metadata from an established TLS connection.
    Returns dict with cipher, version, SNI, client cert info if available.
    """
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if not ssl_obj:
            return None

        tls_info = {}

        # Cipher suite and TLS version
        cipher = ssl_obj.cipher()
        if cipher:
            tls_info["cipher_name"] = cipher[0]  # e.g. "TLS_AES_256_GCM_SHA384"
            tls_info["cipher_version"] = cipher[1]  # e.g. "TLSv1.3"
            tls_info["cipher_bits"] = cipher[2]  # e.g. 256

        # TLS version negotiated
        tls_info["tls_version"] = ssl_obj.version()  # e.g. "TLSv1.3"

        # Server Name Indication (SNI) — what hostname client requested
        sni = writer.get_extra_info("server_hostname") or getattr(ssl_obj, "server_hostname", None)
        if sni:
            tls_info["sni"] = sni

        # ALPN negotiated protocol (e.g. "h2", "http/1.1")
        try:
            alpn = ssl_obj.selected_alpn_protocol()
            if alpn:
                tls_info["alpn"] = alpn
        except AttributeError as exc:  # silent: ALPN not available in this SSL version
            logging.getLogger(__name__).debug("ignored: %s", exc)

        # NPN protocol (older, less common)
        try:
            npn = ssl_obj.selected_npn_protocol()
            if npn:
                tls_info["npn"] = npn
        except AttributeError as exc:  # silent: NPN not available in this SSL version
            logging.getLogger(__name__).debug("ignored: %s", exc)

        # Client certificate info (if client provided one)
        try:
            client_cert = ssl_obj.getpeercert()
            if client_cert:
                tls_info["client_cert"] = {
                    "subject": dict(x[0] for x in client_cert.get("subject", [])),
                    "issuer": dict(x[0] for x in client_cert.get("issuer", [])),
                    "serial": client_cert.get("serialNumber"),
                    "not_before": client_cert.get("notBefore"),
                    "not_after": client_cert.get("notAfter"),
                }
        except (ValueError, ssl.SSLError):
            pass  # silent: no client cert or not verified

        # Session info
        try:
            session = ssl_obj.session
            if session:
                tls_info["session_reused"] = ssl_obj.session_reused
        except AttributeError as exc:  # silent: session_reused not available in this SSL version
            logging.getLogger(__name__).debug("ignored: %s", exc)

        # Compression (should be None for security)
        try:
            comp = ssl_obj.compression()
            if comp:
                tls_info["compression"] = comp
        except AttributeError as exc:  # silent: compression() not available in this SSL version
            logging.getLogger(__name__).debug("ignored: %s", exc)

        return tls_info if tls_info else None

    except Exception as e:
        logger.debug("TLS metadata extraction failed: %s", e)
        return None


# ===========================================================================
# Pattern memory (for NG auto-detect dedup)
# ===========================================================================


def _load_patterns(path) -> dict:
    """Read the auto-detect dedup memory, tolerating a missing/empty/corrupt file.

    Dedup memory is a convenience, never a reason to refuse to start: an empty or
    corrupt file (e.g. an operator truncating logs in this directory) used to raise
    JSONDecodeError at import time and take the whole honeypot down.
    """
    if not Path(path).exists():
        return {}
    try:
        with open(path) as f:
            loaded = json.load(f)
    except (ValueError, OSError) as exc:
        logger.warning("Could not load %s (%s) — starting with empty pattern memory", path, exc)
        return {}
    if not isinstance(loaded, dict):
        logger.warning("%s is not a JSON object — starting with empty pattern memory", path)
        return {}
    return loaded


known_patterns: dict = _load_patterns(HONEYPOTNG_PATTERNS_FILE)


def _save_patterns() -> None:
    with open(HONEYPOTNG_PATTERNS_FILE, "w") as f:
        json.dump(known_patterns, f)


# ===========================================================================
# SUBSYSTEM 1 — Web Honeypot (Flask)
# ===========================================================================

_LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - SwiftTrans Logistics</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f4f4f4;
      color: #333;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
    }
    .container {
      background-color: #fff;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 4px 8px rgba(0,0,0,0.1);
      text-align: center;
      max-width: 400px;
      width: 100%;
    }
    .container h1  { font-size: 24px; color: #0073e6; }
    .container input[type="text"],
    .container input[type="password"] {
      width: 100%; padding: 10px; margin: 8px 0;
      border: 1px solid #ccc; border-radius: 4px;
    }
    .container input[type="submit"] {
      width: 100%; padding: 10px;
      background-color: #0073e6; color: white;
      border: none; border-radius: 4px; cursor: pointer;
    }
    .container input[type="submit"]:hover { background-color: #005bb5; }
    .footer-text { font-size: 12px; color: #888; margin-top: 10px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>SwiftTrans Logistics Portal</h1>
    <p>Please log in to access your account</p>
    <form method="POST" action="/login">
      <label for="username">Username:</label><br>
      <input type="text" id="username" name="username" required><br><br>
      <label for="password">Password:</label><br>
      <input type="password" id="password" name="password" required><br><br>
      <input type="submit" value="Login">
    </form>
    <p class="footer-text">SwiftTrans Logistics &copy; 2024</p>
  </div>
</body>
</html>
"""

flask_app = Flask(__name__)

# --- Spoof Werkzeug's transport-level Server header ---
# Flask after_request only sets response headers, but Werkzeug's
# WSGIRequestHandler injects its own "Server: Werkzeug/x.x Python/x.x"
# at the HTTP transport layer. We must patch both levels.
#
# CVE-2026-23918 bait: advertise Apache 2.4.66 + mod_http2 to passive
# scanners. Aligned with hp_http.py and honeypots_config.py http profile.
_APACHE_BANNER = "Apache/2.4.66 (Ubuntu) mod_http2/2.0.32"
# server_version in werkzeug is a read-only property according to the stubs; we swap the
# class attribute, hence a cast instead of type: ignore (mypy versions differ in how they see it).
cast(Any, werkzeug.serving.WSGIRequestHandler).server_version = _APACHE_BANNER


# Suppress Flask/Werkzeug default headers to hide server info
@flask_app.after_request
def _strip_server_header(response):
    response.headers.pop("Server", None)
    response.headers["Server"] = "Apache/2.4.66 (Ubuntu) mod_http2/2.0.32"
    response.headers["Upgrade"] = "h2,h2c"
    response.headers.pop("X-Powered-By", None)
    return response


@flask_app.route("/")
def home():
    # _LOGIN_HTML is a module-level constant; no user input is interpolated.
    # nosemgrep: python.flask.security.audit.render-template-string.render-template-string
    # nosemgrep: python.flask.security.audit.render-template-string.render-template-string
    return render_template_string(_LOGIN_HTML)  # fixed decoy template, no input data


@flask_app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    client_ip = (
        request.headers.get("X-Real-IP")
        or request.headers.get("X-Forwarded-For")
        or request.remote_addr
    )

    log_data = {
        "timestamp": now_iso(),
        "ip_address": client_ip,
        "username": username,
        "password": password,
        "user_agent": request.headers.get("User-Agent", ""),
        "method": request.method,
        "path": request.path,
        "headers": dict(request.headers),
    }

    try:
        with open(HONEYWEB_ACCESS_LOG, "a") as lf:
            json.dump(log_data, lf, default=str)
            lf.write("\n")
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
        logger.info(
            "Credential capture from %s — user: %s", client_ip, username
        )  # honeypot: a captured login is the evidence
    except Exception as exc:
        logger.error("Failed to write access log: %s", exc)

    return "Login failed. Please try again.", 401


# Catch-all for path enumeration attempts
@flask_app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catch_all(path):
    client_ip = request.headers.get("X-Real-IP") or request.remote_addr
    log_data = {
        "timestamp": now_iso(),
        "ip_address": client_ip,
        "method": request.method,
        "path": f"/{path}",
        "user_agent": request.headers.get("User-Agent", ""),
        "body": request.get_data(as_text=True)[:2048],
    }
    try:
        with open(HONEYWEB_ACCESS_LOG, "a") as lf:
            json.dump(log_data, lf, default=str)
            lf.write("\n")
    except Exception as e:
        logger.debug("Failed to write honeyweb access log: %s", e)
    return "Not Found", 404


def _run_flask() -> None:
    logger.info("Web honeypot (HTTP) starting on %s:%s", HONEYWEB_HOST, HONEYWEB_PORT)
    flask_app.run(host=HONEYWEB_HOST, port=HONEYWEB_PORT, use_reloader=False)


def _run_flask_tls() -> None:
    if not (os.path.exists(HONEY_TLS_CERT) and os.path.exists(HONEY_TLS_KEY)):
        logger.warning("Skipping HTTPS honeypot — no TLS cert")
        return
    logger.info("Web honeypot (HTTPS) starting on %s:%s", HONEYWEB_HOST, HONEYWEB_TLS_PORT)
    flask_app.run(
        host=HONEYWEB_HOST,
        port=HONEYWEB_TLS_PORT,
        ssl_context=(HONEY_TLS_CERT, HONEY_TLS_KEY),
        use_reloader=False,
    )


# ===========================================================================
# SUBSYSTEM 2 — Protocol Responders
# ===========================================================================
# Each responder follows the real protocol as closely as practical
# to maximize attacker engagement while logging everything.
# Server banners are generic — never expose real versions.
# ===========================================================================


class BaseResponder:
    """Base class for protocol-specific responders."""

    protocol = "unknown"

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
        peer: tuple,
        tls_info: dict | None = None,
    ) -> None:
        raise NotImplementedError

    def _log_with_tls(
        self,
        port: int,
        protocol: str,
        peer: tuple,
        extra: dict | None = None,
        tls_info: dict | None = None,
    ) -> None:
        """Log event with TLS metadata included if available."""
        log_data = extra.copy() if extra else {}
        if tls_info:
            log_data["tls"] = tls_info
        _log_event(port, protocol, peer, log_data)


# ---- SSH ----
class SSHResponder(BaseResponder):
    protocol = "ssh"
    # Real OpenSSH always emits a version — a versionless banner is a
    # near-pathognomonic honeypot tell. Sourced from ssh profile so the
    # legacy responder matches hp_ssh.py.
    BANNER = (
        _get_profile("ssh").get("banner", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5") + "\r\n"
    ).encode()

    async def handle(self, reader, writer, port, peer, tls_info=None):
        writer.write(self.BANNER)
        await writer.drain()

        try:
            client_banner = await asyncio.wait_for(reader.readline(), timeout=30)
            decoded = _sanitize(client_banner.decode(errors="ignore"))
            _log_event(
                port,
                self.protocol,
                peer,
                {
                    "phase": "banner_exchange",
                    "client_banner": decoded,
                },
            )
            logger.info("[SSH] %s:%d banner: %s", peer[0], peer[1], decoded[:120])

            # Read further data (key exchange, auth attempts)
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=60)
                if not data:
                    break
                _log_event(
                    port,
                    self.protocol,
                    peer,
                    {
                        "phase": "data",
                        "hex": data[:256].hex(),
                        "size": len(data),
                    },
                )
        except (TimeoutError, ConnectionError) as exc:  # silent: connection cleanup
            logging.getLogger(__name__).debug("ignored: %s", exc)


# ---- Telnet ----
class TelnetResponder(BaseResponder):
    protocol = "telnet"

    async def handle(self, reader, writer, port, peer, tls_info=None):
        # IAC DO/WILL negotiation (minimal)
        writer.write(
            b"\xff\xfd\x01"  # IAC DO ECHO
            b"\xff\xfd\x1f"  # IAC DO NAWS
            b"\xff\xfb\x01"  # IAC WILL ECHO
            b"\xff\xfb\x03"
        )  # IAC WILL SGA
        await writer.drain()

        writer.write(b"\r\nSwiftTrans Gateway\r\nlogin: ")
        await writer.drain()

        try:
            username = await asyncio.wait_for(reader.readline(), timeout=60)
            username = _sanitize(username.decode(errors="ignore"))

            writer.write(b"Password: ")
            await writer.drain()

            password = await asyncio.wait_for(reader.readline(), timeout=60)
            password = _sanitize(password.decode(errors="ignore"))

            _log_event(
                port,
                self.protocol,
                peer,
                {
                    "phase": "auth",
                    "username": username,
                    "password": password,
                },
            )
            logger.info("[Telnet] %s auth: %s / %s", peer[0], username, password)

            writer.write(b"\r\nLogin incorrect\r\n")
            await writer.drain()

            # Allow retries
            for _ in range(2):
                writer.write(b"login: ")
                await writer.drain()
                u = await asyncio.wait_for(reader.readline(), timeout=30)
                writer.write(b"Password: ")
                await writer.drain()
                p = await asyncio.wait_for(reader.readline(), timeout=30)
                _log_event(
                    port,
                    self.protocol,
                    peer,
                    {
                        "phase": "auth_retry",
                        "username": _sanitize(u.decode(errors="ignore")),
                        "password": _sanitize(p.decode(errors="ignore")),
                    },
                )
                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()

        except (TimeoutError, ConnectionError) as exc:  # silent: connection cleanup
            logging.getLogger(__name__).debug("ignored: %s", exc)


# ---- FTP ----
class FTPResponder(BaseResponder):
    protocol = "ftp"

    async def handle(self, reader, writer, port, peer, tls_info=None):
        writer.write(b"220 FTP server ready.\r\n")
        await writer.drain()

        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=60)
                if not line:
                    break
                cmd = _sanitize(line.decode(errors="ignore")).upper()
                _log_event(port, self.protocol, peer, {"command": cmd})

                if cmd.startswith("USER"):
                    writer.write(b"331 Password required.\r\n")
                elif cmd.startswith("PASS"):
                    _log_event(
                        port,
                        self.protocol,
                        peer,
                        {
                            "phase": "auth",
                            "raw": _sanitize(line.decode(errors="ignore")),
                        },
                    )
                    writer.write(b"530 Login incorrect.\r\n")
                elif cmd.startswith("QUIT"):
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break
                elif cmd.startswith("SYST"):
                    writer.write(b"215 UNIX Type: L8\r\n")
                elif cmd.startswith("FEAT"):
                    writer.write(b"211-Features:\r\n UTF8\r\n211 End\r\n")
                else:
                    writer.write(b"500 Unknown command.\r\n")
                await writer.drain()
        except (TimeoutError, ConnectionError) as exc:  # silent: connection cleanup
            logging.getLogger(__name__).debug("ignored: %s", exc)


# ---- SMTP ----
class SMTPResponder(BaseResponder):
    protocol = "smtp"

    async def handle(self, reader, writer, port, peer, tls_info=None):
        writer.write(b"220 mail.swifttrans.local ESMTP ready\r\n")
        await writer.drain()

        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=60)
                if not line:
                    break
                cmd = _sanitize(line.decode(errors="ignore"))
                _log_event(port, self.protocol, peer, {"command": cmd})
                upper = cmd.upper()

                if upper.startswith("EHLO") or upper.startswith("HELO"):
                    writer.write(b"250-mail.swifttrans.local\r\n250 OK\r\n")
                elif upper.startswith("MAIL FROM"):
                    writer.write(b"250 OK\r\n")
                elif upper.startswith("RCPT TO"):
                    writer.write(b"250 OK\r\n")
                elif upper.startswith("DATA"):
                    writer.write(b"354 Start mail input\r\n")
                    await writer.drain()
                    body_lines = []
                    while True:
                        dline = await asyncio.wait_for(reader.readline(), timeout=60)
                        text = dline.decode(errors="ignore").rstrip("\r\n")
                        if text == ".":
                            break
                        body_lines.append(text)
                    _log_event(
                        port,
                        self.protocol,
                        peer,
                        {
                            "phase": "data",
                            "body": "\n".join(body_lines)[:4096],
                        },
                    )
                    writer.write(b"250 OK\r\n")
                elif upper.startswith("QUIT"):
                    writer.write(b"221 Bye\r\n")
                    await writer.drain()
                    break
                elif upper.startswith("AUTH"):
                    _log_event(port, self.protocol, peer, {"phase": "auth", "raw": cmd})
                    writer.write(b"535 Authentication failed\r\n")
                else:
                    writer.write(b"502 Command not implemented\r\n")
                await writer.drain()
        except (TimeoutError, ConnectionError) as exc:  # silent: connection cleanup
            logging.getLogger(__name__).debug("ignored: %s", exc)


# ---- Modbus TCP ----
class ModbusResponder(BaseResponder):
    protocol = "modbus"

    async def handle(self, reader, writer, port, peer, tls_info=None):
        """Respond to Modbus TCP requests (FC 0x01-0x04, 0x05, 0x06)."""
        try:
            while True:
                header = await asyncio.wait_for(reader.readexactly(7), timeout=60)
                if len(header) < 7:
                    break

                txn_id = struct.unpack(">H", header[0:2])[0]
                struct.unpack(">H", header[2:4])[0]
                length = struct.unpack(">H", header[4:6])[0]
                unit_id = header[6]

                if length < 1 or length > 65535:
                    break

                pdu = await asyncio.wait_for(reader.readexactly(length - 1), timeout=30)
                fc = pdu[0]

                # Extract address and value for write operations
                address = None
                value = None
                quantity = None

                if fc in (0x01, 0x02, 0x03, 0x04) and len(pdu) >= 5:
                    # Read operations: FC + Address(2) + Quantity(2)
                    address = struct.unpack(">H", pdu[1:3])[0]
                    quantity = struct.unpack(">H", pdu[3:5])[0]
                elif fc == 0x05 and len(pdu) >= 5:
                    # Write Single Coil: FC + Address(2) + Value(2)
                    address = struct.unpack(">H", pdu[1:3])[0]
                    value = struct.unpack(">H", pdu[3:5])[0]
                elif fc == 0x06 and len(pdu) >= 5:
                    # Write Single Register: FC + Address(2) + Value(2)
                    address = struct.unpack(">H", pdu[1:3])[0]
                    value = struct.unpack(">H", pdu[3:5])[0]
                elif fc == 0x0F and len(pdu) >= 6:
                    # Write Multiple Coils: FC + Address(2) + Quantity(2) + ByteCount + Data
                    address = struct.unpack(">H", pdu[1:3])[0]
                    quantity = struct.unpack(">H", pdu[3:5])[0]
                elif fc == 0x10 and len(pdu) >= 6:
                    # Write Multiple Registers: FC + Address(2) + Quantity(2) + ByteCount + Data
                    address = struct.unpack(">H", pdu[1:3])[0]
                    quantity = struct.unpack(">H", pdu[3:5])[0]

                # Build full frame hex for binary detection
                full_frame = header + pdu

                # Determine if this is a write operation (attack indicator)
                is_write = fc in (0x05, 0x06, 0x0F, 0x10, 0x16, 0x17)
                is_recon = fc in (0x07, 0x08, 0x11, 0x2B)
                is_illegal = fc in range(90, 101) or fc in range(125, 128)

                event_data = {
                    "txn_id": txn_id,
                    "unit_id": unit_id,
                    "fc": fc,
                    "fc_name": _MODBUS_FC_NAMES.get(fc, "unknown"),
                    "pdu_hex": pdu.hex(),
                    "frame_hex": full_frame.hex(),
                    "hex": full_frame.hex(),  # For binary detection
                    "is_write": is_write,
                    "is_recon": is_recon,
                    "is_illegal": is_illegal,
                }

                if address is not None:
                    event_data["address"] = address
                if value is not None:
                    event_data["value"] = value
                if quantity is not None:
                    event_data["quantity"] = quantity

                _log_event(port, self.protocol, peer, event_data)

                # Log with more detail
                if is_write:
                    logger.warning(
                        "[Modbus] %s WRITE FC=%d unit=%d addr=%s val=%s",
                        peer[0],
                        fc,
                        unit_id,
                        address,
                        value,
                    )
                elif is_recon:
                    logger.info("[Modbus] %s RECON FC=%d unit=%d", peer[0], fc, unit_id)
                elif is_illegal:
                    logger.warning("[Modbus] %s ILLEGAL FC=%d unit=%d", peer[0], fc, unit_id)
                else:
                    logger.info("[Modbus] %s FC=%d unit=%d", peer[0], fc, unit_id)

                # Build response based on function code
                if fc in (0x01, 0x02):
                    # Read Coils / Discrete Inputs — return 1 byte of zeros
                    resp_pdu = bytes([fc, 1, 0x00])
                elif fc in (0x03, 0x04):
                    # Read Holding/Input Registers — return 2 registers
                    resp_pdu = bytes([fc, 4, 0x00, 0x00, 0x00, 0x00])
                elif fc == 0x05:
                    # Write Single Coil — echo back
                    resp_pdu = pdu
                elif fc == 0x06:
                    # Write Single Register — echo back
                    resp_pdu = pdu
                else:
                    # Illegal function — exception response
                    resp_pdu = bytes([fc | 0x80, 0x01])

                resp_header = struct.pack(">HHH", txn_id, 0, len(resp_pdu) + 1)
                writer.write(resp_header + bytes([unit_id]) + resp_pdu)
                await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: connection cleanup


# Modbus function code names for logging
_MODBUS_FC_NAMES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Slave ID",
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x2B: "Read Device Identification",
}


# ---- MQTT ----
class MQTTResponder(BaseResponder):
    protocol = "mqtt"

    async def handle(self, reader, writer, port, peer, tls_info=None):
        try:
            # Read CONNECT packet
            first_byte = await asyncio.wait_for(reader.readexactly(1), timeout=30)
            pkt_type = (first_byte[0] >> 4) & 0x0F

            # Decode remaining length (variable-length encoding)
            remaining = 0
            shift = 0
            for _ in range(4):
                b = await reader.readexactly(1)
                remaining |= (b[0] & 0x7F) << shift
                shift += 7
                if not (b[0] & 0x80):
                    break

            if remaining > 1048576:  # 1MB max MQTT payload
                logger.warning("[MQTT] Oversized payload from %s: %d bytes", peer[0], remaining)
                return
            payload = await asyncio.wait_for(reader.readexactly(remaining), timeout=30)

            _log_event(
                port,
                self.protocol,
                peer,
                {
                    "phase": "connect",
                    "pkt_type": pkt_type,
                    "payload_hex": payload[:128].hex(),
                },
            )

            # Extract client ID and credentials if present
            if pkt_type == 1 and len(payload) > 10:
                # Skip protocol name + level + flags + keepalive
                idx = 0
                # Protocol name length
                if idx + 2 <= len(payload):
                    pname_len = struct.unpack(">H", payload[idx : idx + 2])[0]
                    idx += 2 + pname_len
                # Protocol level
                if idx < len(payload):
                    idx += 1
                # Connect flags
                connect_flags = payload[idx] if idx < len(payload) else 0
                idx += 1
                # Keep alive
                idx += 2
                # Client ID
                if idx + 2 <= len(payload):
                    cid_len = struct.unpack(">H", payload[idx : idx + 2])[0]
                    idx += 2
                    client_id = payload[idx : idx + cid_len].decode(errors="ignore")
                    idx += cid_len
                    _log_event(
                        port,
                        self.protocol,
                        peer,
                        {
                            "phase": "client_id",
                            "client_id": client_id,
                        },
                    )

                # Username (bit 7 of connect_flags)
                if connect_flags & 0x80 and idx + 2 <= len(payload):
                    ulen = struct.unpack(">H", payload[idx : idx + 2])[0]
                    idx += 2
                    username = payload[idx : idx + ulen].decode(errors="ignore")
                    idx += ulen
                    _log_event(
                        port,
                        self.protocol,
                        peer,
                        {
                            "phase": "auth",
                            "username": username,
                        },
                    )

                # Password (bit 6)
                if connect_flags & 0x40 and idx + 2 <= len(payload):
                    plen = struct.unpack(">H", payload[idx : idx + 2])[0]
                    idx += 2
                    password = payload[idx : idx + plen].decode(errors="ignore")
                    _log_event(
                        port,
                        self.protocol,
                        peer,
                        {
                            "phase": "auth_password",
                            "password": password,
                        },
                    )

            # Send CONNACK (connection accepted, session not present)
            connack = bytes([0x20, 0x02, 0x00, 0x00])
            writer.write(connack)
            await writer.drain()

            # Keep reading packets and respond properly to each type
            while True:
                hdr_byte = await asyncio.wait_for(reader.read(1), timeout=120)
                if not hdr_byte:
                    break

                pkt_type_byte = hdr_byte[0]
                pkt_type_num = (pkt_type_byte >> 4) & 0x0F

                # Decode remaining length
                remaining = 0
                shift = 0
                for _ in range(4):
                    b = await reader.readexactly(1)
                    remaining |= (b[0] & 0x7F) << shift
                    shift += 7
                    if not (b[0] & 0x80):
                        break

                body = (
                    await asyncio.wait_for(reader.readexactly(remaining), timeout=30)
                    if remaining
                    else b""
                )

                _log_event(
                    port,
                    self.protocol,
                    peer,
                    {
                        "phase": "packet",
                        "pkt_type": pkt_type_num,
                        "hex": (bytes([pkt_type_byte]) + body)[:256].hex(),
                    },
                )

                # SUBSCRIBE (type 8) — reply with SUBACK granting all requested QoS
                if pkt_type_num == 8 and len(body) >= 2:
                    packet_id = body[0:2]  # message identifier
                    # Parse topic filters and collect QoS levels requested
                    idx = 2
                    return_codes = []
                    while idx < len(body):
                        if idx + 2 > len(body):
                            break
                        topic_len = (body[idx] << 8) | body[idx + 1]
                        idx += 2
                        if idx + topic_len > len(body):
                            break
                        topic = body[idx : idx + topic_len].decode(errors="ignore")
                        idx += topic_len
                        qos = body[idx] if idx < len(body) else 0
                        idx += 1
                        return_codes.append(min(qos, 2))  # grant requested QoS
                        _log_event(
                            port,
                            self.protocol,
                            peer,
                            {
                                "phase": "subscribe",
                                "topic": topic,
                                "qos": qos,
                            },
                        )
                    # SUBACK: fixed header 0x90, remaining = 2 + len(return_codes)
                    suback = bytes([0x90, 2 + len(return_codes)]) + packet_id + bytes(return_codes)
                    writer.write(suback)
                    await writer.drain()

                # UNSUBSCRIBE (type 10) — reply with UNSUBACK
                elif pkt_type_num == 10 and len(body) >= 2:
                    packet_id = body[0:2]
                    unsuback = bytes([0xB0, 0x02]) + packet_id
                    writer.write(unsuback)
                    await writer.drain()

                # PUBLISH (type 3) — reply with PUBACK for QoS 1
                elif pkt_type_num == 3:
                    flags = pkt_type_byte & 0x0F
                    qos = (flags >> 1) & 0x03
                    if qos == 1 and len(body) >= 4:
                        packet_id = body[2:4]
                        puback = bytes([0x40, 0x02]) + packet_id
                        writer.write(puback)
                        await writer.drain()

                # PINGREQ (type 12) — reply with PINGRESP
                elif pkt_type_num == 12:
                    writer.write(bytes([0xD0, 0x00]))
                    await writer.drain()

                # DISCONNECT (type 14) — client is done
                elif pkt_type_num == 14:
                    break

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: connection cleanup


# ---- MySQL ----
class MySQLResponder(BaseResponder):
    protocol = "mysql"

    async def handle(self, reader, writer, port, peer, tls_info=None):
        # MySQL greeting packet — generic, no version leak
        # Protocol: 10, Version: 5.7.x (generic), Thread ID, Auth plugin
        bytearray()
        version = b"5.7.99\x00"
        thread_id = struct.pack("<I", 1)
        salt1 = b"\x41\x42\x43\x44\x45\x46\x47\x48"  # 8 byte scramble
        cap_low = struct.pack("<H", 0xF7FF)
        charset = b"\x21"  # utf8
        status = struct.pack("<H", 0x0002)
        cap_high = struct.pack("<H", 0x0081)
        auth_len = b"\x15"  # 21 bytes
        reserved = b"\x00" * 10
        salt2 = b"\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x00"
        auth_plug = b"mysql_native_password\x00"

        payload = (
            b"\x0a"
            + version
            + thread_id
            + salt1
            + b"\x00"
            + cap_low
            + charset
            + status
            + cap_high
            + auth_len
            + reserved
            + salt2
            + auth_plug
        )

        pkt_len = struct.pack("<I", len(payload))[:3]
        seq = b"\x00"
        writer.write(pkt_len + seq + payload)
        await writer.drain()

        try:
            # Read client handshake response
            hdr = await asyncio.wait_for(reader.readexactly(4), timeout=30)
            length = struct.unpack("<I", hdr[:3] + b"\x00")[0]
            body = await asyncio.wait_for(reader.readexactly(length), timeout=30)

            # Extract username from handshake response
            # Skip capabilities(4) + max_packet(4) + charset(1) + reserved(23)
            idx = 32
            username_end = body.find(b"\x00", idx)
            username = (
                body[idx:username_end].decode(errors="ignore") if username_end > idx else "unknown"
            )

            _log_event(
                port,
                self.protocol,
                peer,
                {
                    "phase": "auth",
                    "username": username,
                    "client_hex": body[:64].hex(),
                },
            )
            logger.info("[MySQL] %s auth user: %s", peer[0], username)

            # Send ERR packet — access denied
            err_payload = (
                b"\xff"
                + struct.pack("<H", 1045)
                + b"#28000"
                + f"Access denied for user '{username}'".encode()
                + b"\x00"
            )
            err_len = struct.pack("<I", len(err_payload))[:3]
            writer.write(err_len + b"\x02" + err_payload)
            await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: connection cleanup


# ---- PostgreSQL ----
class PostgresResponder(BaseResponder):
    protocol = "postgres"

    async def handle(self, reader, writer, port, peer, tls_info=None):
        try:
            # Read startup message
            hdr = await asyncio.wait_for(reader.readexactly(4), timeout=30)
            msg_len = struct.unpack(">I", hdr)[0]
            body = await asyncio.wait_for(reader.readexactly(msg_len - 4), timeout=30)

            # Check for SSLRequest (80877103)
            if msg_len == 8 and struct.unpack(">I", body)[0] == 80877103:
                writer.write(b"N")  # Refuse SSL (or S to accept)
                await writer.drain()
                # Read actual startup message
                hdr = await asyncio.wait_for(reader.readexactly(4), timeout=30)
                msg_len = struct.unpack(">I", hdr)[0]
                body = await asyncio.wait_for(reader.readexactly(msg_len - 4), timeout=30)

            # Parse startup params (key=val pairs separated by \x00)
            params = {}
            parts = body[4:].split(b"\x00")  # skip protocol version
            for i in range(0, len(parts) - 1, 2):
                k = parts[i].decode(errors="ignore")
                v = parts[i + 1].decode(errors="ignore") if i + 1 < len(parts) else ""
                if k:
                    params[k] = v

            username = params.get("user", "unknown")
            database = params.get("database", "unknown")

            _log_event(
                port,
                self.protocol,
                peer,
                {
                    "phase": "startup",
                    "username": username,
                    "database": database,
                    "params": params,
                },
            )
            logger.info("[PG] %s user=%s db=%s", peer[0], username, database)

            # Send AuthenticationMD5Password (R, type=5, salt)
            salt = b"\x01\x02\x03\x04"
            auth_msg = b"R" + struct.pack(">I", 12) + struct.pack(">I", 5) + salt
            writer.write(auth_msg)
            await writer.drain()

            # Read password message
            await asyncio.wait_for(reader.readexactly(1), timeout=30)
            pw_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=30)
            pw_len = struct.unpack(">I", pw_hdr)[0]
            pw_body = await asyncio.wait_for(reader.readexactly(pw_len - 4), timeout=30)

            _log_event(
                port,
                self.protocol,
                peer,
                {
                    "phase": "auth",
                    "password_hash": pw_body.hex(),
                },
            )

            # Send ErrorResponse — auth failed
            err = b"SFATAL\x00VFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00"
            writer.write(b"E" + struct.pack(">I", len(err) + 4) + err)
            await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: connection cleanup


# ---- Oracle TNS ----
class OracleResponder(BaseResponder):
    protocol = "oracle"

    async def handle(self, reader, writer, port, peer, tls_info=None):
        try:
            # Read TNS connect packet header (8 bytes minimum)
            hdr = await asyncio.wait_for(reader.readexactly(8), timeout=30)
            pkt_len = struct.unpack(">H", hdr[0:2])[0]
            pkt_type = hdr[4]  # 1=connect, 2=accept, 4=refuse

            remaining = pkt_len - 8
            if remaining > 0 and remaining < 8192:
                body = await asyncio.wait_for(reader.readexactly(remaining), timeout=30)
            else:
                body = b""

            _log_event(
                port,
                self.protocol,
                peer,
                {
                    "phase": "connect",
                    "tns_type": pkt_type,
                    "body_hex": body[:256].hex(),
                    "connect_data": body.decode(errors="ignore")[:512],
                },
            )
            logger.info("[Oracle] %s TNS type=%d len=%d", peer[0], pkt_type, pkt_len)

            # Send TNS REFUSE
            refuse_data = (
                b"(DESCRIPTION=(ERR=12505)(VSNNUM=0)(ERROR_STACK=(ERROR=(CODE=12505)(EMFI=4))))"
            )
            refuse_len = 8 + len(refuse_data)
            refuse_hdr = struct.pack(">H", refuse_len) + b"\x00\x00" + b"\x04\x00\x00\x00"
            writer.write(refuse_hdr + refuse_data)
            await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: connection cleanup


# ---- Java RMI ----
class JavaRMIResponder(BaseResponder):
    protocol = "java-rmi"
    # RMI protocol magic: JRMI + version + protocol type
    RMI_MAGIC = b"JRMI"

    async def handle(self, reader, writer, port, peer, tls_info=None):
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=30)
            if not data:
                return

            _log_event(
                port,
                self.protocol,
                peer,
                {
                    "phase": "initial",
                    "hex": data[:256].hex(),
                    "is_rmi": data[:4] == self.RMI_MAGIC,
                },
            )

            if data[:4] == self.RMI_MAGIC:
                # Send protocol ACK + endpoint info
                # N = 0x4E (protocol not supported — keeps it simple)
                writer.write(b"\x4e\x00\x0elocalhost\x00\x00\x00\x00\x00\x00\xc4\x12")
                await writer.drain()
            else:
                # Just echo for unknown sub-protocol
                writer.write(data[:64])
                await writer.drain()

            # Read more data
            while True:
                more = await asyncio.wait_for(reader.read(4096), timeout=60)
                if not more:
                    break
                _log_event(
                    port,
                    self.protocol,
                    peer,
                    {
                        "phase": "data",
                        "hex": more[:256].hex(),
                    },
                )

        except (TimeoutError, ConnectionError) as exc:  # silent: connection cleanup
            logging.getLogger(__name__).debug("ignored: %s", exc)


# ---- RDP ----
class RDPResponder(BaseResponder):
    protocol = "rdp"

    async def handle(self, reader, writer, port, peer, tls_info=None):
        try:
            # Read X.224 Connection Request
            data = await asyncio.wait_for(reader.read(4096), timeout=30)
            if not data:
                return

            _log_event(
                port,
                self.protocol,
                peer,
                {
                    "phase": "x224_request",
                    "hex": data[:256].hex(),
                    "size": len(data),
                },
            )
            logger.info("[RDP] %s connection request (%d bytes)", peer[0], len(data))

            # Send X.224 Connection Confirm (TPKT + X224 CC)
            # This is a minimal valid response
            tpkt = b"\x03\x00"  # version, reserved
            x224_cc = b"\x0e"  # length indicator
            x224_cc += b"\xd0"  # CC (1101 0000)
            x224_cc += b"\x00\x00"  # DST-REF
            x224_cc += data[7:9] if len(data) > 8 else b"\x00\x00"  # SRC-REF echo
            x224_cc += b"\x00"  # class
            # RDP Negotiation Response
            x224_cc += b"\x02\x00\x08\x00\x00\x00\x00\x00"  # TYPE_RDP_NEG_RSP, protocol 0
            total_len = 4 + len(x224_cc)
            tpkt += struct.pack(">H", total_len)

            writer.write(tpkt + x224_cc)
            await writer.drain()

            # Read MCS Connect Initial / further data
            while True:
                more = await asyncio.wait_for(reader.read(8192), timeout=60)
                if not more:
                    break
                _log_event(
                    port,
                    self.protocol,
                    peer,
                    {
                        "phase": "data",
                        "hex": more[:512].hex(),
                        "size": len(more),
                    },
                )

        except (TimeoutError, ConnectionError) as exc:  # silent: connection cleanup
            logging.getLogger(__name__).debug("ignored: %s", exc)


# ---- SMB/CIFS (port 445) ----
class SMBResponder(BaseResponder):
    """
    SMB honeypot — speaks enough of the SMB2 protocol to lure attackers
    through Negotiate → Session Setup → Tree Connect → file operations.

    Goals:
      1. Capture NTLM authentication attempts (credentials, hashes)
      2. Capture named pipe access (lateral movement indicators)
      3. Capture file operation attempts (exe/dll uploads, SAM/NTDS access)
      4. Detect EternalBlue/SMBGhost/DoublePulsar probes
      5. Log all SMB commands for attack classifier enrichment

    Protocol flow we support:
      Client → SMB2 Negotiate → Server responds with SMB2 Negotiate Response
      Client → SMB2 Session Setup (NTLM) → Server sends NTLM Challenge
      Client → SMB2 Session Setup (NTLM Auth) → Server accepts
      Client → SMB2 Tree Connect → Server accepts
      Client → SMB2 Create / Read / Write / IOCTL → logged + generic response
    """

    protocol = "smb"

    # SMB2 magic
    SMB2_MAGIC = b"\xfeSMB"
    SMB1_MAGIC = b"\xffSMB"

    # NetBIOS session header helper
    @staticmethod
    def _nb_header(payload: bytes) -> bytes:
        """Wrap SMB2 payload in NetBIOS session header (4 bytes)."""
        length = len(payload)
        return b"\x00" + length.to_bytes(3, "big") + payload

    # SMB2 command codes
    CMD_NEGOTIATE = 0x0000
    CMD_SESSION_SETUP = 0x0001
    CMD_LOGOFF = 0x0002
    CMD_TREE_CONNECT = 0x0003
    CMD_TREE_DISC = 0x0004
    CMD_CREATE = 0x0005
    CMD_CLOSE = 0x0006
    CMD_FLUSH = 0x0007
    CMD_READ = 0x0008
    CMD_WRITE = 0x0009
    CMD_LOCK = 0x000A
    CMD_IOCTL = 0x000B
    CMD_CANCEL = 0x000C
    CMD_ECHO = 0x000D
    CMD_QUERY_DIR = 0x000E
    CMD_CHANGE_NOTIFY = 0x000F
    CMD_QUERY_INFO = 0x0010
    CMD_SET_INFO = 0x0011
    CMD_OPLOCK_BREAK = 0x0012

    CMD_NAMES: ClassVar = {
        0x0000: "Negotiate",
        0x0001: "SessionSetup",
        0x0002: "Logoff",
        0x0003: "TreeConnect",
        0x0004: "TreeDisconnect",
        0x0005: "Create",
        0x0006: "Close",
        0x0007: "Flush",
        0x0008: "Read",
        0x0009: "Write",
        0x000A: "Lock",
        0x000B: "IOCTL",
        0x000C: "Cancel",
        0x000D: "Echo",
        0x000E: "QueryDirectory",
        0x000F: "ChangeNotify",
        0x0010: "QueryInfo",
        0x0011: "SetInfo",
        0x0012: "OplockBreak",
    }

    # NTLM constants
    NTLMSSP_MAGIC = b"NTLMSSP\x00"

    def __init__(self):
        import os as _os

        # Generate a stable challenge per instance (8 bytes)
        self._ntlm_challenge = _os.urandom(8)
        self._session_id = 0x0000000000040000
        self._tree_id = 0x00000001
        self._server_guid = _os.urandom(16)
        # Track sessions for per-connection state
        self._hostname = "WIN-SENSOR01"
        self._domain = "WORKGROUP"
        self._share_name = "SHARE$"

    def _smb2_header(
        self,
        command: int,
        status: int = 0,
        credit_charge: int = 1,
        credits: int = 1,
        flags: int = 0x00000001,  # SMB2_FLAGS_SERVER_TO_REDIR
        message_id: int = 0,
        session_id: int = 0,
        tree_id: int = 0,
    ) -> bytes:
        """Build a 64-byte SMB2 header."""
        hdr = self.SMB2_MAGIC  # [0:4]   ProtocolId
        hdr += struct.pack("<H", 64)  # [4:6]   StructureSize
        hdr += struct.pack("<H", credit_charge)  # [6:8]   CreditCharge
        hdr += struct.pack("<I", status)  # [8:12]  Status (NT_STATUS)
        hdr += struct.pack("<H", command)  # [12:14] Command
        hdr += struct.pack("<H", credits)  # [14:16] CreditResponse
        hdr += struct.pack("<I", flags)  # [16:20] Flags
        hdr += struct.pack("<I", 0)  # [20:24] NextCommand
        hdr += struct.pack("<Q", message_id)  # [24:32] MessageId
        hdr += struct.pack("<I", 0)  # [32:36] Reserved
        hdr += struct.pack("<I", tree_id)  # [36:40] TreeId
        hdr += struct.pack("<Q", session_id)  # [40:48] SessionId
        hdr += b"\x00" * 16  # [48:64] Signature
        return hdr

    def _negotiate_response(self, msg_id: int = 0) -> bytes:
        """SMB2 Negotiate Response — advertise SMB 2.0.2 / 2.1 / 3.0."""
        hdr = self._smb2_header(self.CMD_NEGOTIATE, message_id=msg_id, credits=1)
        # StructureSize(65) + SecurityMode(signing enabled) + DialectRevision(0x0210 = SMB2.1)
        body = struct.pack("<H", 65)  # StructureSize
        body += struct.pack("<H", 0x01)  # SecurityMode (signing enabled)
        body += struct.pack("<H", 0x0210)  # DialectRevision (SMB 2.1)
        body += struct.pack("<H", 0)  # NegotiateContextCount
        body += self._server_guid  # ServerGuid (16 bytes)
        body += struct.pack(
            "<I", 0x0000002F
        )  # Capabilities (DFS|leasing|large MTU|multi-channel|persistent|dir-leasing)
        body += struct.pack("<I", 1048576)  # MaxTransactSize (1MB)
        body += struct.pack("<I", 1048576)  # MaxReadSize
        body += struct.pack("<I", 1048576)  # MaxWriteSize
        body += struct.pack("<Q", 0)  # SystemTime (placeholder)
        body += struct.pack("<Q", 0)  # ServerStartTime
        # Security buffer — point to NTLM negotiate token (GSS-API/SPNEGO wrapper)
        sec_blob = self._gss_spnego_init()
        64 + 64 + 2  # SMB2 hdr + body so far + padding
        body += struct.pack("<H", 128)  # SecurityBufferOffset (from start of header)
        body += struct.pack("<H", len(sec_blob))  # SecurityBufferLength
        body += struct.pack("<I", 0)  # NegotiateContextOffset
        body += sec_blob
        return self._nb_header(hdr + body)

    def _gss_spnego_init(self) -> bytes:
        """Minimal SPNEGO NegTokenInit advertising NTLMSSP."""
        # This is a simplified ASN.1/DER SPNEGO token
        # OID 1.3.6.1.5.5.2 (SPNEGO), mechType NTLMSSP (1.2.840.113554.1.2.2.10)
        # Simplified: just advertise raw NTLMSSP
        return b""

    def _ntlm_challenge_msg(self) -> bytes:
        """Build NTLM Type 2 (Challenge) message."""
        # NTLMSSP header
        msg = self.NTLMSSP_MAGIC
        msg += struct.pack("<I", 2)  # Type 2 (Challenge)
        # Target name (domain)
        domain_bytes = self._domain.encode("utf-16-le")
        target_offset = 56  # fixed offset after the header fields
        msg += struct.pack("<HHI", len(domain_bytes), len(domain_bytes), target_offset)
        # Negotiate flags
        flags = (
            0x00028233  # NTLM, Unicode, Target info, 56-bit, 128-bit
            | 0x00020000  # NTLMSSP_NEGOTIATE_TARGET_INFO
            | 0x00008000
        )  # NTLMSSP_NEGOTIATE_NTLM
        msg += struct.pack("<I", flags)
        # Server challenge (8 bytes) — the key for cracking
        msg += self._ntlm_challenge
        msg += b"\x00" * 8  # Reserved
        # Target info (simplified — domain name)
        target_info = b""
        # MsvAvNbDomainName (type 2)
        target_info += struct.pack("<HH", 2, len(domain_bytes)) + domain_bytes
        # MsvAvNbComputerName (type 1)
        host_bytes = self._hostname.encode("utf-16-le")
        target_info += struct.pack("<HH", 1, len(host_bytes)) + host_bytes
        # MsvAvEOL (type 0)
        target_info += struct.pack("<HH", 0, 0)

        target_info_offset = target_offset + len(domain_bytes)
        msg += struct.pack("<HHI", len(target_info), len(target_info), target_info_offset)
        # Pad to target_offset then append domain + target_info
        # We need msg to be exactly target_offset bytes before domain
        pad_needed = target_offset - len(msg)
        if pad_needed > 0:
            msg += b"\x00" * pad_needed
        msg += domain_bytes
        msg += target_info
        return msg

    def _session_setup_response(
        self,
        msg_id: int,
        ntlm_token: bytes,
        status: int = 0xC0000016,  # STATUS_MORE_PROCESSING_REQUIRED
    ) -> bytes:
        """SMB2 Session Setup Response with NTLM token."""
        hdr = self._smb2_header(
            self.CMD_SESSION_SETUP, status=status, message_id=msg_id, session_id=self._session_id
        )
        body = struct.pack("<H", 9)  # StructureSize
        body += struct.pack("<H", 0)  # SessionFlags
        # Security buffer
        body += struct.pack("<H", 72)  # SecurityBufferOffset
        body += struct.pack("<H", len(ntlm_token))  # SecurityBufferLength
        body += ntlm_token
        return self._nb_header(hdr + body)

    def _tree_connect_response(self, msg_id: int) -> bytes:
        """SMB2 Tree Connect Response."""
        hdr = self._smb2_header(
            self.CMD_TREE_CONNECT,
            message_id=msg_id,
            session_id=self._session_id,
            tree_id=self._tree_id,
        )
        body = struct.pack("<H", 16)  # StructureSize
        body += struct.pack("<B", 0x01)  # ShareType (DISK)
        body += struct.pack("<B", 0)  # Reserved
        body += struct.pack("<I", 0x00000030)  # ShareFlags
        body += struct.pack("<I", 0x001F01FF)  # Capabilities
        body += struct.pack("<I", 0x001F01FF)  # MaximalAccess (FILE_ALL_ACCESS)
        return self._nb_header(hdr + body)

    def _error_response(
        self,
        command: int,
        msg_id: int,
        status: int = 0xC0000022,  # STATUS_ACCESS_DENIED
    ) -> bytes:
        """Generic SMB2 Error Response."""
        hdr = self._smb2_header(
            command,
            status=status,
            message_id=msg_id,
            session_id=self._session_id,
            tree_id=self._tree_id,
        )
        body = struct.pack("<H", 9)  # StructureSize
        body += struct.pack("<B", 0)  # ErrorContextCount
        body += struct.pack("<B", 0)  # Reserved
        body += struct.pack("<I", 0)  # ByteCount
        body += b"\x00"  # ErrorData (1 byte min)
        return self._nb_header(hdr + body)

    def _parse_smb2_header(self, data: bytes) -> dict:
        """Parse SMB2 header from raw bytes (after NetBIOS header)."""
        if len(data) < 64:
            return {}
        return {
            "magic": data[0:4],
            "struct_size": struct.unpack("<H", data[4:6])[0],
            "credit_charge": struct.unpack("<H", data[6:8])[0],
            "status": struct.unpack("<I", data[8:12])[0],
            "command": struct.unpack("<H", data[12:14])[0],
            "credits": struct.unpack("<H", data[14:16])[0],
            "flags": struct.unpack("<I", data[16:20])[0],
            "next_command": struct.unpack("<I", data[20:24])[0],
            "message_id": struct.unpack("<Q", data[24:32])[0],
            "tree_id": struct.unpack("<I", data[36:40])[0],
            "session_id": struct.unpack("<Q", data[40:48])[0],
        }

    def _extract_ntlm_info(self, data: bytes) -> dict:
        """Extract NTLM authentication details from Session Setup payload."""
        info: dict[str, Any] = {}
        ntlm_pos = data.find(self.NTLMSSP_MAGIC)
        if ntlm_pos < 0:
            return info
        ntlm_data = data[ntlm_pos:]
        if len(ntlm_data) < 12:
            return info
        msg_type = struct.unpack("<I", ntlm_data[8:12])[0]
        info["ntlm_type"] = msg_type

        if msg_type == 1:
            # Negotiate — extract flags and domain/workstation if present
            info["ntlm_phase"] = "negotiate"
            if len(ntlm_data) >= 16:
                info["ntlm_flags"] = f"0x{struct.unpack('<I', ntlm_data[12:16])[0]:08x}"

        elif msg_type == 3:
            # Auth — extract domain, username, workstation, NTLMv2 hash
            info["ntlm_phase"] = "authenticate"
            try:
                # LmChallengeResponse
                lm_len = struct.unpack("<H", ntlm_data[12:14])[0]
                lm_off = struct.unpack("<I", ntlm_data[16:20])[0]
                # NtChallengeResponse
                nt_len = struct.unpack("<H", ntlm_data[20:22])[0]
                nt_off = struct.unpack("<I", ntlm_data[24:28])[0]
                # Domain
                dom_len = struct.unpack("<H", ntlm_data[28:30])[0]
                dom_off = struct.unpack("<I", ntlm_data[32:36])[0]
                # User
                usr_len = struct.unpack("<H", ntlm_data[36:38])[0]
                usr_off = struct.unpack("<I", ntlm_data[40:44])[0]
                # Workstation
                ws_len = struct.unpack("<H", ntlm_data[44:46])[0]
                ws_off = struct.unpack("<I", ntlm_data[48:52])[0]

                if dom_len and dom_off:
                    info["domain"] = ntlm_data[dom_off : dom_off + dom_len].decode(
                        "utf-16-le", errors="replace"
                    )
                if usr_len and usr_off:
                    info["username"] = ntlm_data[usr_off : usr_off + usr_len].decode(
                        "utf-16-le", errors="replace"
                    )
                if ws_len and ws_off:
                    info["workstation"] = ntlm_data[ws_off : ws_off + ws_len].decode(
                        "utf-16-le", errors="replace"
                    )

                # Capture NTLMv2 hash (first 16 bytes of NT response = NTProofStr)
                if nt_len >= 24 and nt_off:
                    nt_response = ntlm_data[nt_off : nt_off + nt_len]
                    info["nt_proof_str"] = nt_response[:16].hex()
                    info["nt_response_hex"] = nt_response[:64].hex()
                    info["nt_response_len"] = nt_len
                    # Build hashcat-compatible NTLMv2 hash line:
                    # username::domain:challenge:NTProofStr:NTresponse_without_first_16_bytes
                    if nt_len > 16:
                        user = info.get("username", "unknown")
                        domain = info.get("domain", "")
                        challenge_hex = self._ntlm_challenge.hex()
                        nt_proof = nt_response[:16].hex()
                        nt_rest = nt_response[16:].hex()
                        info["ntlmv2_hash"] = (
                            f"{user}::{domain}:{challenge_hex}:{nt_proof}:{nt_rest}"
                        )

                if lm_len and lm_off:
                    info["lm_response_hex"] = ntlm_data[lm_off : lm_off + min(lm_len, 32)].hex()

            except (struct.error, IndexError):
                pass  # silent: malformed packet data

        return info

    def _extract_tree_path(self, data: bytes, hdr_len: int = 64) -> str:
        """Extract the share path from a Tree Connect request body."""
        try:
            body = data[hdr_len:]
            if len(body) < 8:
                return ""
            # StructureSize(9) + Reserved(2) + PathOffset(2) + PathLength(2)
            path_offset = struct.unpack("<H", body[4:6])[0]
            path_length = struct.unpack("<H", body[6:8])[0]
            # PathOffset is from start of SMB2 header
            abs_offset = path_offset
            if abs_offset + path_length <= len(data):
                return data[abs_offset : abs_offset + path_length].decode(
                    "utf-16-le", errors="replace"
                )
        except (struct.error, IndexError):
            pass  # silent: malformed packet data
        return ""

    def _extract_create_filename(self, data: bytes, hdr_len: int = 64) -> str:
        """Extract filename from Create request."""
        try:
            body = data[hdr_len:]
            if len(body) < 56:
                return ""
            # Create request body: StructureSize(57), ..., NameOffset(46:48), NameLength(48:50)
            name_offset = struct.unpack("<H", body[44:46])[0]
            name_length = struct.unpack("<H", body[46:48])[0]
            if name_offset and name_length:
                abs_off = name_offset
                if abs_off + name_length <= len(data):
                    return data[abs_off : abs_off + name_length].decode(
                        "utf-16-le", errors="replace"
                    )
        except (struct.error, IndexError):
            pass  # silent: malformed packet data
        return ""

    async def handle(self, reader, writer, port, peer, tls_info=None):
        """Main SMB honeypot handler."""
        msg_counter = 0

        try:
            while True:
                # Read NetBIOS session header (4 bytes) + SMB data
                nb_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=60)
                nb_len = int.from_bytes(nb_hdr[1:4], "big")
                if nb_len > 0x100000 or nb_len < 4:  # sanity: max 1MB
                    _log_event(
                        port,
                        self.protocol,
                        peer,
                        {
                            "phase": "invalid_nb_length",
                            "nb_length": nb_len,
                            "hex": nb_hdr.hex(),
                        },
                    )
                    break

                smb_data = await asyncio.wait_for(reader.readexactly(nb_len), timeout=60)

                # ── SMB1 detection (legacy / EternalBlue probes) ──
                if smb_data[:4] == self.SMB1_MAGIC:
                    smb1_cmd = smb_data[4] if len(smb_data) > 4 else 0
                    _log_event(
                        port,
                        self.protocol,
                        peer,
                        {
                            "phase": "smb1_detected",
                            "smb1_command": f"0x{smb1_cmd:02X}",
                            "hex": smb_data[:256].hex(),
                            "size": len(smb_data),
                            "alert": "SMBv1 probe — potential EternalBlue/DoublePulsar",
                        },
                    )
                    logger.warning(
                        "[SMB] %s sent SMBv1 (cmd=0x%02X) — potential exploit probe",
                        peer[0],
                        smb1_cmd,
                    )

                    # Send SMB1 Negotiate Response pointing to SMB2
                    # (or just close — attackers expecting SMB1 will try harder)
                    # Respond with a minimal SMB1 Negotiate Response that says "use SMB2"
                    smb1_resp = self.SMB1_MAGIC
                    smb1_resp += b"\x72"  # Negotiate command
                    smb1_resp += b"\x00\x00\x00\x00"  # Status OK
                    smb1_resp += b"\x98"  # Flags
                    smb1_resp += b"\x53\xc8"  # Flags2
                    smb1_resp += b"\x00" * 24  # Padding
                    smb1_resp += b"\x11\x00"  # WordCount + dialect index = 0xFF (SMB2)
                    smb1_resp += b"\xff" * 17  # minimal parameters
                    writer.write(self._nb_header(smb1_resp))
                    await writer.drain()
                    continue

                # ── SMB2+ handling ──
                if smb_data[:4] != self.SMB2_MAGIC:
                    _log_event(
                        port,
                        self.protocol,
                        peer,
                        {
                            "phase": "unknown_protocol",
                            "hex": smb_data[:256].hex(),
                            "size": len(smb_data),
                        },
                    )
                    break

                hdr = self._parse_smb2_header(smb_data)
                if not hdr:
                    break

                cmd = hdr["command"]
                msg_id = hdr["message_id"]
                cmd_name = self.CMD_NAMES.get(cmd, f"Unknown(0x{cmd:04X})")

                # Log every SMB2 command
                log_entry = {
                    "phase": "smb2_command",
                    "command": cmd_name,
                    "command_id": f"0x{cmd:04X}",
                    "message_id": msg_id,
                    "session_id": f"0x{hdr['session_id']:016X}",
                    "tree_id": f"0x{hdr['tree_id']:08X}",
                    "flags": f"0x{hdr['flags']:08X}",
                    "hex": smb_data[:512].hex(),
                    "size": len(smb_data),
                }

                # ── Negotiate ──
                if cmd == self.CMD_NEGOTIATE:
                    # Parse requested dialects
                    dialects = []
                    try:
                        body = smb_data[64:]
                        if len(body) >= 36:
                            dialect_count = struct.unpack("<H", body[2:4])[0]
                            for i in range(min(dialect_count, 16)):
                                off = 36 + i * 2
                                if off + 2 <= len(body):
                                    d = struct.unpack("<H", body[off : off + 2])[0]
                                    dialects.append(f"0x{d:04X}")
                    except (struct.error, IndexError):
                        pass  # silent: malformed packet data
                    log_entry["dialects"] = dialects
                    _log_event(port, self.protocol, peer, log_entry)
                    logger.info("[SMB] %s Negotiate (dialects: %s)", peer[0], dialects)

                    writer.write(self._negotiate_response(msg_id))
                    await writer.drain()

                # ── Session Setup (NTLM auth) ──
                elif cmd == self.CMD_SESSION_SETUP:
                    ntlm_info = self._extract_ntlm_info(smb_data)
                    log_entry.update(ntlm_info)
                    _log_event(port, self.protocol, peer, log_entry)

                    if ntlm_info.get("ntlm_phase") == "negotiate":
                        # Send NTLM Challenge (Type 2)
                        logger.info("[SMB] %s NTLM Negotiate → sending Challenge", peer[0])
                        challenge = self._ntlm_challenge_msg()
                        resp = self._session_setup_response(
                            msg_id,
                            challenge,
                            status=0xC0000016,  # STATUS_MORE_PROCESSING_REQUIRED
                        )
                        writer.write(resp)
                        await writer.drain()

                    elif ntlm_info.get("ntlm_phase") == "authenticate":
                        # Log the juicy stuff
                        user = ntlm_info.get("username", "?")
                        domain = ntlm_info.get("domain", "?")
                        ws = ntlm_info.get("workstation", "?")
                        logger.warning(
                            "[SMB] %s NTLM Auth: %s\\%s from %s", peer[0], domain, user, ws
                        )
                        if ntlm_info.get("ntlmv2_hash"):
                            logger.warning(
                                "[SMB] %s NTLMv2 hash captured: %s",
                                peer[0],
                                ntlm_info["ntlmv2_hash"][:80],
                            )

                        # Accept the session (let them keep going)
                        resp = self._session_setup_response(
                            msg_id,
                            b"",
                            status=0x00000000,  # STATUS_SUCCESS
                        )
                        writer.write(resp)
                        await writer.drain()
                    else:
                        # Generic session setup — send challenge anyway
                        challenge = self._ntlm_challenge_msg()
                        resp = self._session_setup_response(msg_id, challenge, status=0xC0000016)
                        writer.write(resp)
                        await writer.drain()

                # ── Tree Connect ──
                elif cmd == self.CMD_TREE_CONNECT:
                    share_path = self._extract_tree_path(smb_data)
                    log_entry["share_path"] = share_path
                    _log_event(port, self.protocol, peer, log_entry)
                    logger.info("[SMB] %s TreeConnect → %s", peer[0], share_path)

                    writer.write(self._tree_connect_response(msg_id))
                    await writer.drain()

                # ── Create (file open) ──
                elif cmd == self.CMD_CREATE:
                    filename = self._extract_create_filename(smb_data)
                    log_entry["filename"] = filename
                    _log_event(port, self.protocol, peer, log_entry)
                    logger.info("[SMB] %s Create → %s", peer[0], filename)

                    # Respond with STATUS_ACCESS_DENIED (common honeypot strategy)
                    writer.write(self._error_response(cmd, msg_id, 0xC0000022))
                    await writer.drain()

                # ── IOCTL (often exploit-related) ──
                elif cmd == self.CMD_IOCTL:
                    # Extract IOCTL code
                    ioctl_code = ""
                    try:
                        body = smb_data[64:]
                        if len(body) >= 8:
                            ctl = struct.unpack("<I", body[4:8])[0]
                            ioctl_code = f"0x{ctl:08X}"
                            log_entry["ioctl_code"] = ioctl_code
                            # Known dangerous IOCTLs
                            if ctl == 0x00144064:
                                log_entry["alert"] = "FSCTL_PIPE_TRANSCEIVE — named pipe RPC"
                            elif ctl == 0x001401D4:
                                log_entry["alert"] = "FSCTL_DFS_GET_REFERRALS — DFS abuse"
                            elif ctl == 0x00140204:
                                log_entry["alert"] = "FSCTL_VALIDATE_NEGOTIATE_INFO"
                    except (struct.error, IndexError):
                        pass  # silent: malformed packet data
                    _log_event(port, self.protocol, peer, log_entry)
                    logger.info("[SMB] %s IOCTL %s", peer[0], ioctl_code)

                    writer.write(self._error_response(cmd, msg_id, 0xC00000BB))  # NOT_SUPPORTED
                    await writer.drain()

                # ── Write ──
                elif cmd == self.CMD_WRITE:
                    # Capture write data
                    try:
                        body = smb_data[64:]
                        if len(body) >= 48:
                            write_offset = struct.unpack("<Q", body[8:16])[0]
                            write_length = struct.unpack("<I", body[4:8])[0]
                            data_offset = struct.unpack("<H", body[2:4])[0]
                            log_entry["write_offset"] = write_offset
                            log_entry["write_length"] = write_length
                            # Capture first 512 bytes of written data
                            if data_offset and data_offset < len(smb_data):
                                write_data = smb_data[
                                    data_offset : data_offset + min(write_length, 512)
                                ]
                                log_entry["write_data_hex"] = write_data.hex()
                                log_entry["write_data_preview"] = write_data[:128].decode(
                                    "utf-8", errors="replace"
                                )
                    except (struct.error, IndexError):
                        pass  # silent: malformed packet data
                    _log_event(port, self.protocol, peer, log_entry)
                    logger.warning(
                        "[SMB] %s Write attempt (%d bytes)",
                        peer[0],
                        log_entry.get("write_length", 0),
                    )

                    writer.write(self._error_response(cmd, msg_id, 0xC0000022))
                    await writer.drain()

                # ── Read ──
                elif cmd == self.CMD_READ:
                    _log_event(port, self.protocol, peer, log_entry)
                    logger.info("[SMB] %s Read request", peer[0])
                    writer.write(self._error_response(cmd, msg_id, 0xC0000022))
                    await writer.drain()

                # ── QueryDirectory / QueryInfo / SetInfo ──
                elif cmd in (self.CMD_QUERY_DIR, self.CMD_QUERY_INFO, self.CMD_SET_INFO):
                    _log_event(port, self.protocol, peer, log_entry)
                    logger.info("[SMB] %s %s", peer[0], cmd_name)
                    writer.write(self._error_response(cmd, msg_id, 0xC0000022))
                    await writer.drain()

                # ── Close / Logoff / TreeDisconnect / Echo ──
                elif cmd in (self.CMD_CLOSE, self.CMD_LOGOFF, self.CMD_TREE_DISC, self.CMD_ECHO):
                    _log_event(port, self.protocol, peer, log_entry)
                    logger.info("[SMB] %s %s", peer[0], cmd_name)
                    # Send success for these
                    resp_hdr = self._smb2_header(
                        cmd,
                        status=0,
                        message_id=msg_id,
                        session_id=self._session_id,
                        tree_id=self._tree_id,
                    )
                    # Minimal body: StructureSize(4)
                    resp_body = struct.pack("<H", 4) + b"\x00\x00"
                    writer.write(self._nb_header(resp_hdr + resp_body))
                    await writer.drain()

                # ── Everything else ──
                else:
                    log_entry["alert"] = f"Unhandled SMB2 command: {cmd_name}"
                    _log_event(port, self.protocol, peer, log_entry)
                    logger.info("[SMB] %s unhandled command %s", peer[0], cmd_name)
                    writer.write(self._error_response(cmd, msg_id, 0xC00000BB))
                    await writer.drain()

                msg_counter += 1
                if msg_counter > 200:  # safety limit
                    break

        except asyncio.IncompleteReadError as exc:  # silent: client disconnected mid-read
            logging.getLogger(__name__).debug("ignored: %s", exc)
        except TimeoutError:
            pass  # silent: connection cleanup
        except ConnectionError as exc:  # silent: connection cleanup
            logging.getLogger(__name__).debug("ignored: %s", exc)
        except Exception as exc:
            logger.debug("[SMB] %s error: %s", peer[0] if peer else "?", exc)
            _log_event(
                port,
                self.protocol,
                peer,
                {
                    "phase": "error",
                    "error": str(exc),
                    "messages_processed": msg_counter,
                },
            )


# ---- HTTP (raw TCP, not Flask) ----
class HTTPResponder(BaseResponder):
    protocol = "http"
    # CVE-2026-23918 bait — Apache 2.4.66 mod_http2 advertisement.
    RESPONSE = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.66 (Ubuntu) mod_http2/2.0.32\r\n"
        b"Upgrade: h2,h2c\r\n"
        b"Content-Type: text/html\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"<html><body><h1>It works!</h1></body></html>\r\n"
    )

    def _parse_http_request(self, data: bytes) -> dict:
        """Parse HTTP request into structured components."""
        result: dict[str, Any] = {
            "method": None,
            "path": None,
            "version": None,
            "headers": {},
            "body": None,
            "query_string": None,
            "uri_decoded": None,
        }

        try:
            # Split headers and body
            if b"\r\n\r\n" in data:
                header_part, body = data.split(b"\r\n\r\n", 1)
                result["body"] = body.decode(errors="ignore")[:8192]
            else:
                header_part = data

            lines = header_part.decode(errors="ignore").split("\r\n")

            # Parse request line
            if lines:
                request_line = lines[0].split(" ", 2)
                if len(request_line) >= 2:
                    result["method"] = request_line[0]
                    result["path"] = request_line[1]

                    # Extract query string
                    if "?" in result["path"]:
                        _path, qs = result["path"].split("?", 1)
                        result["query_string"] = qs

                    # URL decode for attack detection
                    try:
                        import urllib.parse

                        result["uri_decoded"] = urllib.parse.unquote(result["path"])
                    except Exception as e:
                        logger.debug("URI decode failed: %s", e)

                if len(request_line) >= 3:
                    result["version"] = request_line[2]

            # Parse headers
            for line in lines[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    result["headers"][key.lower()] = value

        except Exception as e:
            result["parse_error"] = str(e)

        return result

    async def handle(self, reader, writer, port, peer, tls_info: dict | None = None):
        try:
            # Read full request (may need multiple reads for large POSTs)
            data = await asyncio.wait_for(reader.read(16384), timeout=30)
            if not data:
                return

            # Parse HTTP request structure
            http_parsed = self._parse_http_request(data)

            # Determine protocol string based on TLS
            proto = "https" if tls_info else "http"

            # Build comprehensive log entry
            log_entry = {
                "phase": "request",
                "raw": _sanitize(data.decode(errors="ignore"))[:8192],
                "method": http_parsed.get("method"),
                "path": http_parsed.get("path"),
                "query_string": http_parsed.get("query_string"),
                "uri_decoded": http_parsed.get("uri_decoded"),
                "http_version": http_parsed.get("version"),
                "headers": http_parsed.get("headers"),
                "body": http_parsed.get("body"),
                "body_size": len(http_parsed.get("body") or ""),
                "user_agent": http_parsed.get("headers", {}).get("user-agent"),
                "host": http_parsed.get("headers", {}).get("host"),
                "content_type": http_parsed.get("headers", {}).get("content-type"),
                "content_length": http_parsed.get("headers", {}).get("content-length"),
            }

            # Add TLS metadata if present
            if tls_info:
                log_entry["tls"] = tls_info
                log_entry["is_encrypted"] = True
            else:
                log_entry["is_encrypted"] = False

            _log_event(port, proto, peer, log_entry)

            # Log summary
            method = http_parsed.get("method", "?")
            path = http_parsed.get("path", "/")[:80]
            tls_tag = f" [TLS:{tls_info.get('tls_version')}]" if tls_info else ""
            logger.info("[HTTP%s] %s:%d %s %s", tls_tag, peer[0], peer[1], method, path)

            writer.write(self.RESPONSE)
            await writer.drain()

        except (TimeoutError, ConnectionError) as exc:  # silent: connection cleanup
            logging.getLogger(__name__).debug("ignored: %s", exc)


# ---- Auto-detect (payload-based classification) ----
class AutoDetectResponder(BaseResponder):
    protocol = "auto"

    # Map protocol hints to responder classes
    RESPONDERS: ClassVar = {
        "ssh": SSHResponder,
        "telnet": TelnetResponder,
        "ftp": FTPResponder,
        "smtp": SMTPResponder,
        "modbus": ModbusResponder,
        "mqtt": MQTTResponder,
        "mysql": MySQLResponder,
        "postgres": PostgresResponder,
        "oracle": OracleResponder,
        "java-rmi": JavaRMIResponder,
        "rdp": RDPResponder,
        "smb": SMBResponder,
        "http": HTTPResponder,
        "https": HTTPResponder,
    }

    def _classify(self, data: bytes) -> str:
        """Classify protocol from initial payload bytes."""
        if not data:
            return "unknown"
        if data[:3] == b"SSH":
            return "ssh"
        if data[:4] == b"JRMI":
            return "java-rmi"
        if b"GET " in data[:16] or b"POST " in data[:16] or b"HTTP" in data[:16]:
            return "http"
        if data[:2] == b"\x16\x03":
            return "tls"
        # SMB: NetBIOS session header (0x00) followed by SMB1 or SMB2 magic
        if len(data) >= 8 and data[0:1] == b"\x00":
            if data[4:8] == b"\xfeSMB" or data[4:8] == b"\xffSMB":
                return "smb"
        # SMB without NetBIOS header (direct TCP)
        if data[:4] == b"\xfeSMB" or data[:4] == b"\xffSMB":
            return "smb"
        if data[0:1] == b"\x03" and data[2:3] in (b"\x00", b"\x01"):
            return "rdp"
        # MQTT CONNECT: first nibble = 1 (packet type)
        if (data[0] >> 4) == 1:
            return "mqtt"
        # Modbus: bytes 2-3 = protocol ID = 0x0000
        if len(data) >= 7 and data[2:4] == b"\x00\x00":
            return "modbus"
        # PostgreSQL startup (length prefix + protocol version 3.0)
        if len(data) >= 8:
            try:
                struct.unpack(">I", data[0:4])[0]
                version = struct.unpack(">I", data[4:8])[0]
                if version == 196608 or version == 80877103:  # 3.0 or SSLRequest
                    return "postgres"
            except struct.error as exc:  # silent: malformed packet data
                logging.getLogger(__name__).debug("ignored: %s", exc)
        # Telnet IAC
        if data[0:1] == b"\xff":
            return "telnet"
        return "unknown"

    async def handle(self, reader, writer, port, peer, tls_info: dict | None = None):
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=30)
            if not data:
                return

            detected = self._classify(data)
            tag = _tag(data)

            log_entry = {
                "phase": "classify",
                "detected": detected,
                "tag": tag[:16],
                "hex": data[:128].hex(),
            }
            if tls_info:
                log_entry["tls"] = tls_info

            _log_event(port, "auto", peer, log_entry)
            logger.info("[Auto] %s:%d detected=%s tag=%s", peer[0], peer[1], detected, tag[:12])

            # Track patterns
            if tag not in known_patterns:
                known_patterns[tag] = {
                    "first_seen": now_iso(),
                    "protocol": detected,
                    "peer": list(peer),
                    "port": port,
                }
                _save_patterns()

            # Delegate to specific responder if we recognized the protocol
            if detected in self.RESPONDERS:
                # We already consumed the initial data, so we need to handle
                # protocols that need it. For simplicity, log and continue.
                pass

            # Echo loop for unrecognized traffic
            writer.write(data[:64])
            await writer.drain()

            while True:
                more = await asyncio.wait_for(reader.read(4096), timeout=60)
                if not more:
                    break
                _log_event(
                    port,
                    f"auto/{detected}",
                    peer,
                    {
                        "phase": "data",
                        "hex": more[:256].hex(),
                    },
                )
                writer.write(more[:64])
                await writer.drain()

        except (TimeoutError, ConnectionError) as exc:  # silent: connection cleanup
            logging.getLogger(__name__).debug("ignored: %s", exc)


# ===========================================================================
# Protocol responder registry
# ===========================================================================

_RESPONDER_MAP = {
    "ssh": SSHResponder(),
    "telnet": TelnetResponder(),
    "ftp": FTPResponder(),
    "smtp": SMTPResponder(),
    "modbus": ModbusResponder(),
    "mqtt": MQTTResponder(),
    "mqtts": MQTTResponder(),  # same protocol, TLS wrapping at transport
    "mysql": MySQLResponder(),
    "mssql": MySQLResponder(),  # similar enough greeting for capture
    "postgres": PostgresResponder(),
    "oracle": OracleResponder(),
    "java-rmi": JavaRMIResponder(),
    "rdp": RDPResponder(),
    "smb": SMBResponder(),
    "http": HTTPResponder(),
    "https": HTTPResponder(),
    "auto": AutoDetectResponder(),
    # ICS protocols — use auto for now
    "s7comm": AutoDetectResponder(),
    "ethernet-ip": AutoDetectResponder(),
    "bacnet": AutoDetectResponder(),
    "vnc": AutoDetectResponder(),
}


# ===========================================================================
# Connection handler
# ===========================================================================


async def handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int,
    protocol_hint: str,
) -> None:
    peer = writer.get_extra_info("peername")
    if not peer:
        writer.close()
        return
    peer_ip, peer_port = peer[0], peer[1]

    # Extract TLS metadata if this is a TLS connection
    tls_metadata = _extract_tls_metadata(writer)

    tls_tag = ""
    if tls_metadata is not None:
        tls_tag = f" [TLS:{tls_metadata.get('tls_version', '?')}]"
        # Log TLS connection details
        _log_event(
            port,
            f"{protocol_hint}_tls_handshake",
            (peer_ip, peer_port),
            {
                "tls": tls_metadata,
                "cipher": tls_metadata.get("cipher_name"),
                "tls_version": tls_metadata.get("tls_version"),
                "sni": tls_metadata.get("sni"),
                "alpn": tls_metadata.get("alpn"),
            },
        )

    logger.info(
        "[+] Connection %s:%d -> port %d (hint=%s%s)",
        peer_ip,
        peer_port,
        port,
        protocol_hint,
        tls_tag,
    )

    responder = _RESPONDER_MAP.get(protocol_hint, AutoDetectResponder())

    try:
        await responder.handle(reader, writer, port, (peer_ip, peer_port), tls_info=tls_metadata)
    except Exception as exc:
        logger.error("Handler error on port %d from %s: %s", port, peer_ip, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception as exc:
            logging.getLogger(__name__).debug("ignored: %s", exc)
        logger.debug("[-] Closed %s:%d (port %d)", peer_ip, peer_port, port)


# ===========================================================================
# Async server launcher (with optional TLS + JA3 fingerprinting)
# ===========================================================================

_TLS_PROTOCOLS = {"https", "mqtts"}

# Global storage for JA3 data keyed by (ip, port) — short-lived, auto-expires
_ja3_cache: dict[tuple[str, int], dict] = {}


def _peek_ja3_from_socket(sock: socket_module.socket) -> dict | None:
    """
    Peek at socket data to extract JA3 from ClientHello without consuming data.
    Uses MSG_PEEK so the TLS handshake can proceed normally.
    """
    try:
        # Set socket to non-blocking temporarily
        original_blocking = sock.getblocking()
        sock.setblocking(False)

        try:
            # Peek at data without consuming it
            peeked = sock.recv(2048, socket_module.MSG_PEEK)

            if peeked and len(peeked) >= 5 and peeked[0] == 0x16:
                # This looks like a TLS ClientHello
                ja3_info = parse_client_hello(peeked)
                return ja3_info
        except BlockingIOError as exc:  # silent: no data available yet for JA3 peek
            logging.getLogger(__name__).debug("ignored: %s", exc)
        except Exception as e:
            logger.debug("JA3 peek failed: %s", e)
        finally:
            sock.setblocking(original_blocking)

    except Exception as e:
        logger.debug("JA3 capture setup failed: %s", e)

    return None


async def handle_connection_with_ja3(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int,
    protocol_hint: str,
) -> None:
    """Connection handler that extracts JA3 fingerprint for TLS connections."""
    peer = writer.get_extra_info("peername")
    if not peer:
        writer.close()
        return
    peer_ip, peer_port = peer[0], peer[1]

    # Extract TLS metadata (this works after handshake completes)
    tls_metadata = _extract_tls_metadata(writer)

    # For TLS connections, try to get JA3 from cache (if we captured it)
    ja3_data = _ja3_cache.pop((peer_ip, peer_port), None)

    # Merge JA3 data into TLS metadata
    if ja3_data and tls_metadata:
        tls_metadata["ja3_hash"] = ja3_data.get("ja3_hash")
        tls_metadata["ja3_string"] = ja3_data.get("ja3_string")
        # SNI from JA3 parsing might be more reliable
        if ja3_data.get("sni") and not tls_metadata.get("sni"):
            tls_metadata["sni"] = ja3_data.get("sni")

    tls_tag = ""
    if tls_metadata is not None:
        ja3_short = tls_metadata.get("ja3_hash", "")[:8]
        tls_tag = f" [TLS:{tls_metadata.get('tls_version', '?')}]"
        if ja3_short:
            tls_tag += f" [JA3:{ja3_short}...]"

        # Log TLS connection details with JA3
        _log_event(
            port,
            f"{protocol_hint}_tls_handshake",
            (peer_ip, peer_port),
            {
                "tls": tls_metadata,
                "cipher": tls_metadata.get("cipher_name") if tls_metadata else None,
                "tls_version": tls_metadata.get("tls_version") if tls_metadata else None,
                "sni": tls_metadata.get("sni") if tls_metadata else None,
                "alpn": tls_metadata.get("alpn") if tls_metadata else None,
                "ja3_hash": tls_metadata.get("ja3_hash") if tls_metadata else None,
                "ja3_string": tls_metadata.get("ja3_string") if tls_metadata else None,
            },
        )

    logger.info(
        "[+] Connection %s:%d -> port %d (hint=%s%s)",
        peer_ip,
        peer_port,
        port,
        protocol_hint,
        tls_tag,
    )

    responder = _RESPONDER_MAP.get(protocol_hint, AutoDetectResponder())

    try:
        await responder.handle(reader, writer, port, (peer_ip, peer_port), tls_info=tls_metadata)
    except Exception as exc:
        logger.error("Handler error on port %d from %s: %s", port, peer_ip, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception as exc:
            logging.getLogger(__name__).debug("ignored: %s", exc)
        logger.debug("[-] Closed %s:%d (port %d)", peer_ip, peer_port, port)


class JA3CaptureProtocol(asyncio.Protocol):
    """
    Low-level protocol that captures JA3 from ClientHello before SSL handshake.
    This runs as the initial protocol, captures JA3, then hands off to SSL.
    """

    def __init__(
        self, port: int, proto_hint: str, ssl_ctx: ssl.SSLContext, on_connection_made, loop
    ):
        self.port = port
        self.proto_hint = proto_hint
        self.ssl_ctx = ssl_ctx
        self.on_connection_made = on_connection_made
        self.loop = loop
        self.transport = None
        self.peer = None
        self.buffer = b""
        self.ja3_captured = False

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")

    def data_received(self, data):
        if self.ja3_captured:
            return

        self.buffer += data

        # Check if we have a complete ClientHello
        if len(self.buffer) >= 5 and self.buffer[0] == 0x16:
            # Parse record length
            record_len = struct.unpack(">H", self.buffer[3:5])[0]

            if len(self.buffer) >= 5 + record_len:
                # We have the full ClientHello
                ja3_info = parse_client_hello(self.buffer)

                if ja3_info and self.peer:
                    logger.info(
                        "[JA3-PRE] %s:%d -> %s (SNI: %s)",
                        self.peer[0],
                        self.peer[1],
                        ja3_info.get("ja3_hash", "?"),
                        ja3_info.get("sni", "-"),
                    )

                    # Store in cache for the connection handler
                    _ja3_cache[(self.peer[0], self.peer[1])] = ja3_info

                    # Log immediately
                    _log_event(
                        self.port,
                        f"{self.proto_hint}_ja3_fingerprint",
                        (self.peer[0], self.peer[1]),
                        {
                            "ja3_hash": ja3_info.get("ja3_hash"),
                            "ja3_string": ja3_info.get("ja3_string"),
                            "sni": ja3_info.get("sni"),
                            "tls_version_offered": ja3_info.get("tls_version_str"),
                            "cipher_suites": ja3_info.get("cipher_suites", [])[:10],
                            "extensions": ja3_info.get("extensions", [])[:10],
                        },
                    )

                self.ja3_captured = True

                # Now upgrade to TLS
                # Unfortunately we can't easily hand this off, so we close
                # and let the retry mechanism handle it
                # In production, you'd use start_tls() here

    def connection_lost(self, exc):
        pass


async def _run_ja3_capture_server(port: int, proto_hint: str) -> None:
    """
    Run a secondary server that captures JA3 fingerprints.
    This uses raw sockets to peek at ClientHello before TLS handshake.
    """
    # Create a raw socket server that peeks at connections
    server_sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
    server_sock.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)

    # We can't actually bind to the same port, so this approach won't work directly
    # Instead, we need to integrate JA3 capture into the main server flow
    pass


async def _run_ng_honeypot() -> None:
    """Run the NG honeypot with JA3 fingerprinting support."""
    servers = []

    for port, proto_hint in HONEYPOTNG_SERVICES.items():
        use_tls = proto_hint in _TLS_PROTOCOLS and _honey_ssl_ctx is not None

        try:
            # Use our JA3-aware connection handler
            server = await asyncio.start_server(
                functools.partial(handle_connection_with_ja3, port=port, protocol_hint=proto_hint),
                "0.0.0.0",
                port,
                ssl=_honey_ssl_ctx if use_tls else None,
            )

            tls_tag = " [TLS+JA3]" if use_tls else ""
            logger.info("[+] Honeypot listening on port %d (%s%s)", port, proto_hint, tls_tag)
            servers.append(server)

        except OSError as exc:
            logger.error("[!] Cannot bind port %d (%s): %s", port, proto_hint, exc)

    if not servers:
        logger.error("No honeypot ports could be bound — exiting")
        return

    await asyncio.gather(*(s.serve_forever() for s in servers))


# ===========================================================================
# Entry point
# ===========================================================================


def _prepare_dirs() -> None:
    """Log and traffic-capture directories — in 0.9 created at import time, which broke the
    import under a user without rights to /opt/logs (tests, tools)."""
    for _d in (HONEYWEB_LOG_DIR, HONEYPOTNG_LOG_DIR, HONEYPOTNG_TRAFFIC_DIR):
        os.makedirs(_d, exist_ok=True)


def main() -> int:
    """Entry point for ``honeylens-hp-legacy`` (monolith: Flask HTTP/HTTPS + NG honeypots on asyncio)."""
    from honeylens.logging_setup import setup_logging

    _prepare_dirs()
    setup_logging(log_file=HONEYWEB_CONSOLE_LOG)

    # Flask HTTP in daemon thread
    flask_thread = threading.Thread(target=_run_flask, daemon=True)
    flask_thread.start()
    logger.info("[+] Web honeypot (HTTP) started on %s:%s", HONEYWEB_HOST, HONEYWEB_PORT)

    # Flask HTTPS in daemon thread
    flask_tls_thread = threading.Thread(target=_run_flask_tls, daemon=True)
    flask_tls_thread.start()

    # asyncio NG honeypot on main thread
    try:
        asyncio.run(_run_ng_honeypot())
    except KeyboardInterrupt:
        logger.info("Honeypot stopped by user.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
