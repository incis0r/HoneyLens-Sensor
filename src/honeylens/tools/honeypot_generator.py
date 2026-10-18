#!/usr/bin/env python3
"""
honeypot_generator.py — Custom Honeypot Generator from Device Profiles
=======================================================================
Reads a device profile JSON (created by device_profiler.py) and generates
a standalone honeypot that mimics the profiled device — same banners,
web UI, login pages, headers, and response patterns.

Idea 33 — Phase 2

Usage:
    python honeypot_generator.py --profile librenms
    python honeypot_generator.py --profile tplink-switch --port 8080
    python honeypot_generator.py --profile librenms --generate-only
    python honeypot_generator.py --list
    python honeypot_generator.py --run librenms --port 9080
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
from datetime import UTC, datetime
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("honeypot-gen")

PROFILE_DIR = os.environ.get(
    "HONEYPOT_PROFILE_DIR",
    "/opt/sensor/custom_honeypots" if os.path.isdir("/opt/sensor") else "./custom_honeypots",
)

try:
    from honeylens.database import legacy_get_db as _legacy_get_db

    _HAS_DB = True
except ImportError:
    _HAS_DB = False


def load_profile(name: str) -> dict | None:
    """Load a device profile JSON."""
    path = os.path.join(PROFILE_DIR, f"{name}.json")
    if not os.path.exists(path):
        logger.error("Profile not found: %s", path)
        return None
    with open(path) as f:
        return json.load(f)


class CustomHoneypot:
    """A honeypot generated from a device profile."""

    def __init__(self, profile: dict, listen_port: int = 0):
        self.profile = profile
        self.name = profile.get("name", "unknown")
        self.vendor = profile.get("vendor", "unknown")
        self.web_ui = profile.get("web_ui") or {}
        self.services = profile.get("services", [])
        self.listen_port = listen_port
        self.event_count = 0
        self._db_conn: Any = None

        # Pre-build response cache from profile
        self._pages = {}
        self._headers = {}
        self._assets = {}
        self._login_form = self.web_ui.get("login_form")
        self._title = self.web_ui.get("title", "Device")
        self._server = self.web_ui.get("server", "")
        self._favicon = self.web_ui.get("favicon")
        self._redirects = {
            r["from"].split("/", 3)[-1] if "/" in r["from"] else "/": r["to"]
            for r in self.web_ui.get("redirects", [])
            if r.get("to")
        }

        # Build page cache
        for path, page in self.web_ui.get("pages", {}).items():
            if page.get("body"):
                self._pages[path] = page

        # Build asset cache
        for path, asset in self.web_ui.get("static_assets", {}).items():
            self._assets[path] = asset

        # Default headers from profile
        self._headers = dict(self.web_ui.get("headers", {}))
        # Remove hop-by-hop headers
        for h in [
            "Transfer-Encoding",
            "Connection",
            "Keep-Alive",
            "Content-Length",
            "Content-Encoding",
        ]:
            self._headers.pop(h, None)

        # SSH banner
        self._ssh_banner = None
        for svc in self.services:
            if svc.get("port") == 22 and svc.get("banner"):
                self._ssh_banner = svc["banner"]

        logger.info(
            "Honeypot '%s' ready — %d pages, %d assets, SSH=%s, login=%s",
            self.name,
            len(self._pages),
            len(self._assets),
            bool(self._ssh_banner),
            bool(self._login_form),
        )

    def _log_event(
        self,
        src_ip: str,
        method: str,
        path: str,
        headers: dict | None = None,
        body: str | None = None,
        event_type: str = "HTTP_REQUEST",
    ):
        """Log honeypot event."""
        self.event_count += 1
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "source": f"custom-honeypot-{self.name}",
            "src_ip": src_ip,
            "event_type": event_type,
            "method": method,
            "path": path,
            "vendor": self.vendor,
            "profile": self.name,
        }
        if headers:
            event["user_agent"] = headers.get("User-Agent", "")
        if body:
            event["body"] = body[:1000]

        # Detect attack patterns
        if (
            self._login_form
            and method == "POST"
            and any(f in path for f in ("/login", "/logincheck", "/signin"))
        ):
            event["event_type"] = "CREDENTIAL_CAPTURE"
            if body:
                event["credentials"] = body[:500]
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
            logger.warning("[%s] CREDENTIAL CAPTURE from %s: %s", self.name, src_ip, path)
        elif "admin" in path.lower() and method == "PUT":
            event["event_type"] = "EXPLOIT_ATTEMPT"
            logger.warning("[%s] EXPLOIT ATTEMPT from %s: %s %s", self.name, src_ip, method, path)
        elif any(p in path for p in ("/.git", "/.env", "/config/", "/../")):
            event["event_type"] = "RECON_PROBE"
        elif path in ("/", "/login", "/index.html"):
            event["event_type"] = "RECON_VISIT"

        # Log to DB if available
        if _HAS_DB:
            self._log_to_db(event)

        # Console log
        logger.info("[%s] %s %s %s from %s", self.name, event["event_type"], method, path, src_ip)

    def _log_to_db(self, event: dict):
        """Log event to sensor_events table."""
        try:
            if not self._db_conn or self._db_conn.closed:
                self._db_conn = _legacy_get_db()

            eid = hashlib.sha256(
                f"{event['timestamp']}-{event['src_ip']}-{event['path']}-{secrets.token_hex(4)}".encode()
            ).hexdigest()

            cur = self._db_conn.cursor()
            cur.execute(
                """
                INSERT INTO sensor_events (event_id, timestamp, source, protocol, src_ip, dst_port, payload)
                VALUES (%s, NOW(), %s, 'TCP', %s::inet, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
            """,
                (
                    eid,
                    event["source"],
                    event["src_ip"],
                    self.listen_port,
                    json.dumps(event, default=str),
                ),
            )
            self._db_conn.commit()
        except Exception as e:
            logger.debug("DB log error: %s", e)
            try:
                self._db_conn.rollback()
            except Exception:
                self._db_conn = None

    async def handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an HTTP connection — respond with cloned device pages."""
        peername = writer.get_extra_info("peername")
        src_ip = peername[0] if peername else "0.0.0.0"

        try:
            # Read request
            request_data = await asyncio.wait_for(reader.read(8192), timeout=10)
            if not request_data:
                writer.close()
                return

            request_text = request_data.decode("utf-8", errors="replace")
            lines = request_text.split("\r\n")
            if not lines:
                writer.close()
                return

            # Parse request line
            parts = lines[0].split(" ", 2)
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            # Parse headers
            req_headers = {}
            body = ""
            in_body = False
            for line in lines[1:]:
                if in_body:
                    body += line
                elif line == "":
                    in_body = True
                elif ":" in line:
                    key, val = line.split(":", 1)
                    req_headers[key.strip()] = val.strip()

            # Log event
            self._log_event(src_ip, method, path, req_headers, body if method == "POST" else None)

            # Generate response
            status, resp_headers, resp_body = self._route(method, path, req_headers, body)

            # Build HTTP response
            response = f"HTTP/1.1 {status}\r\n"
            if self._server:
                response += f"Server: {self._server}\r\n"
            response += f"Date: {datetime.now(UTC).strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\n"
            for k, v in resp_headers.items():
                response += f"{k}: {v}\r\n"
            if isinstance(resp_body, bytes):
                response += f"Content-Length: {len(resp_body)}\r\n"
                response += "Connection: close\r\n\r\n"
                writer.write(response.encode("utf-8") + resp_body)
            else:
                resp_bytes = resp_body.encode("utf-8") if resp_body else b""
                response += f"Content-Length: {len(resp_bytes)}\r\n"
                response += "Connection: close\r\n\r\n"
                writer.write(response.encode("utf-8") + resp_bytes)

            await writer.drain()
        except (
            TimeoutError
        ) as _exc:  # silent: client went idle during response, normal for HTTP honeypots
            logging.getLogger(__name__).debug("ignored: %s", _exc)
        except Exception as e:
            logger.debug("Connection error: %s", e)
        finally:
            try:
                writer.close()
            except Exception as _exc:  # silent: best-effort socket close in cleanup path
                logging.getLogger(__name__).debug("ignored: %s", _exc)

    def _route(self, method: str, path: str, headers: dict, body: str):
        """Route request to appropriate handler. Returns (status, headers, body)."""
        resp_headers = {}
        # Copy relevant headers from profile
        for k in (
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Set-Cookie",
            "Cache-Control",
            "Pragma",
        ):
            if k in self._headers:
                resp_headers[k] = self._headers[k]

        # Strip query string for matching
        clean_path = path.split("?")[0]

        # Favicon
        if clean_path == "/favicon.ico" and self._favicon:
            resp_headers["Content-Type"] = "image/x-icon"
            return "200 OK", resp_headers, base64.b64decode(self._favicon)

        # Static assets
        if clean_path in self._assets:
            asset = self._assets[clean_path]
            resp_headers["Content-Type"] = asset.get("content_type", "application/octet-stream")
            if asset.get("body"):
                return "200 OK", resp_headers, asset["body"]
            elif asset.get("body_b64"):
                return "200 OK", resp_headers, base64.b64decode(asset["body_b64"])
            return "200 OK", resp_headers, ""

        # Check redirects
        for from_path, to_url in self._redirects.items():
            if clean_path == "/" or clean_path == from_path:
                # Make redirect relative to honeypot
                parsed = to_url
                if "://" in to_url:
                    parsed = "/" + to_url.split("/", 3)[-1] if to_url.count("/") >= 3 else "/"
                resp_headers["Location"] = parsed
                return "302 Found", resp_headers, ""

        # Pages from profile
        if clean_path in self._pages:
            page = self._pages[clean_path]
            resp_headers["Content-Type"] = page.get("content_type", "text/html; charset=utf-8")
            status_code = page.get("status", 200)
            status_text = {
                200: "OK",
                301: "Moved Permanently",
                302: "Found",
                403: "Forbidden",
                404: "Not Found",
            }.get(status_code, "OK")

            page_body = page.get("body", "")
            # Sanitise — remove real IPs from the profile target
            target = self.profile.get("target", "")
            if target:
                page_body = page_body.replace(target, "127.0.0.1")

            return f"{status_code} {status_text}", resp_headers, page_body

        # Login form handler — capture credentials on POST
        if method == "POST" and self._login_form:
            # Return login page again (failed login)
            login_path = self._login_form.get("url", "/login")
            if "://" in login_path:
                login_path = "/" + login_path.split("/", 3)[-1]
            if login_path in self._pages:
                resp_headers["Content-Type"] = "text/html; charset=utf-8"
                page_body = self._pages[login_path].get("body", "")
                target = self.profile.get("target", "")
                if target:
                    page_body = page_body.replace(target, "127.0.0.1")
                return "200 OK", resp_headers, page_body

        # Default — return a minimal page matching the device style
        resp_headers["Content-Type"] = "text/html; charset=utf-8"
        return (
            "404 Not Found",
            resp_headers,
            f"<html><head><title>{self._title}</title></head><body><h1>404</h1></body></html>",
        )

    async def handle_ssh(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle SSH connection — send banner then close."""
        peername = writer.get_extra_info("peername")
        src_ip = peername[0] if peername else "0.0.0.0"

        try:
            banner = self._ssh_banner or "SSH-2.0-OpenSSH_8.7"
            writer.write(f"{banner}\r\n".encode())
            await writer.drain()

            # Wait for client banner
            data = await asyncio.wait_for(reader.read(1024), timeout=10)
            data.decode("utf-8", errors="replace").strip() if data else ""

            self._log_event(src_ip, "CONNECT", "/ssh", event_type="SSH_CONNECT")

            # Wait for more data (auth attempts)
            try:
                data2 = await asyncio.wait_for(reader.read(4096), timeout=15)
                if data2:
                    self._log_event(src_ip, "AUTH", "/ssh", event_type="SSH_AUTH_ATTEMPT")
            except (
                TimeoutError
            ) as _exc:  # silent: client did not send auth attempt within 15s, normal
                logging.getLogger(__name__).debug("ignored: %s", _exc)
        except Exception as e:
            logger.debug("SSH honeypot session error: %s", e)
        finally:
            try:
                writer.close()
            except Exception as _exc:  # silent: best-effort socket close in cleanup path
                logging.getLogger(__name__).debug("ignored: %s", _exc)

    async def run(self, http_port: int = 0, ssh_port: int = 0):
        """Start the honeypot servers."""
        servers = []

        if http_port:
            self.listen_port = http_port
            srv = await asyncio.start_server(self.handle_http, "0.0.0.0", http_port)
            servers.append(srv)
            logger.info(
                "[%s] HTTP honeypot listening on port %d (mimicking %s %s)",
                self.name,
                http_port,
                self.vendor,
                self._title,
            )

        if ssh_port and self._ssh_banner:
            srv = await asyncio.start_server(self.handle_ssh, "0.0.0.0", ssh_port)
            servers.append(srv)
            logger.info(
                "[%s] SSH honeypot listening on port %d (banner: %s)",
                self.name,
                ssh_port,
                self._ssh_banner,
            )

        if not servers:
            logger.error("No ports configured. Use --port and/or --ssh-port")
            return

        logger.info("[%s] Custom honeypot running. Press Ctrl+C to stop.", self.name)

        try:
            await asyncio.gather(*(s.serve_forever() for s in servers))
        except (
            asyncio.CancelledError
        ) as _exc:  # silent: normal shutdown path when the loop is cancelled
            logging.getLogger(__name__).debug("ignored: %s", _exc)
        finally:
            for s in servers:
                s.close()
            logger.info("[%s] Stopped. Total events: %d", self.name, self.event_count)


def generate_systemd_unit(profile_name: str, http_port: int, ssh_port: int = 0) -> str:
    """Generate a systemd service unit file for a custom honeypot.

    The paths are 1.0's: the sensor tree under the ``sensor`` service account, a ``.venv``,
    and the generator reached as a module. They used to be 0.9's ``/opt/sensor/venv`` with a
    relative ``tools/honeypot_generator.py``, which in 1.0 is not a path that exists — the
    unit this function printed could not start. It also needs the env file, because the
    honeypot writes events through ``honeylens.database``, and a system unit's ``%h`` is
    root's home, so the location cannot be abbreviated.
    """
    ssh_arg = f" --ssh-port {ssh_port}" if ssh_port else ""
    return f"""[Unit]
Description=HoneyLens — Custom Honeypot ({profile_name})
After=network.target postgresql.service
Wants=network.target

[Service]
Type=simple
User=sensor
Group=sensor
WorkingDirectory=/home/sensor/sensor-1.0
Environment=HONEYLENS_ENV_FILE=/home/sensor/honeylens-state/.env
ExecStart=/home/sensor/sensor-1.0/.venv/bin/python -m honeylens.tools.honeypot_generator \
--run {profile_name} --port {http_port}{ssh_arg}
Restart=on-failure
RestartSec=5
MemoryMax=256M
CPUQuota=20%

[Install]
WantedBy=multi-user.target
"""


def main():
    parser = argparse.ArgumentParser(description="Custom Honeypot Generator from Device Profiles")
    parser.add_argument("--profile", "-p", help="Profile name to generate honeypot from")
    parser.add_argument("--run", "-r", help="Run honeypot from profile name")
    parser.add_argument("--port", type=int, default=0, help="HTTP listen port")
    parser.add_argument("--ssh-port", type=int, default=0, help="SSH listen port")
    parser.add_argument("--list", "-l", action="store_true", help="List available profiles")
    parser.add_argument(
        "--generate-systemd", action="store_true", help="Generate systemd unit file"
    )
    parser.add_argument("--test", "-t", help="Test profile by name — start, make request, stop")
    args = parser.parse_args()

    if args.list:
        from honeylens.tools.device_profiler import list_profiles

        profiles = list_profiles()
        if not profiles:
            print("No profiles found. Run device_profiler.py first.")
            return
        print(f"{'Name':<25} {'Vendor':<15} {'Type':<12} {'Services':<10} {'Target'}")
        print("-" * 75)
        for p in profiles:
            print(
                f"{p['name']:<25} {p['vendor']:<15} {p['device_type']:<12} {p['services']:<10} {p['target']}"
            )
        return

    if args.generate_systemd:
        if not args.profile or not args.port:
            print("Need --profile and --port for systemd generation")
            return
        unit = generate_systemd_unit(args.profile, args.port, args.ssh_port)
        filename = f"sensor-custom-{args.profile}.service"
        print(unit)
        print(f"\n# Save as: /etc/systemd/system/{filename}")
        print(f"# Then: sudo systemctl enable --now {filename}")
        return

    if args.test:
        profile = load_profile(args.test)
        if not profile:
            return
        hp = CustomHoneypot(profile)
        port = args.port or 19999

        import threading
        import urllib.request

        loop = asyncio.new_event_loop()
        srv = None

        async def _start():
            nonlocal srv
            srv = await asyncio.start_server(hp.handle_http, "127.0.0.1", port)
            logger.info("Test server on http://127.0.0.1:%d", port)
            await srv.serve_forever()

        def _run_server():
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(_start())
            except (
                asyncio.CancelledError
            ) as _exc:  # silent: normal shutdown of the background event loop
                logging.getLogger(__name__).debug("ignored: %s", _exc)

        t = threading.Thread(target=_run_server, daemon=True)
        t.start()
        time.sleep(1)

        paths = ["/", "/login", "/favicon.ico", "/robots.txt", "/api/"]
        ok = 0
        for path in paths:
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
                # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                resp = urllib.request.urlopen(req, timeout=5)  # nosec B310
                status = resp.status
                size = len(resp.read())
                print(f"  PASS  {path:30s} -> {status} ({size} bytes)")
                ok += 1
            except urllib.error.HTTPError as e:
                print(f"  PASS  {path:30s} -> {e.code}")
                ok += 1
            except Exception as e:
                print(f"  FAIL  {path:30s} -> {e}")

        loop.call_soon_threadsafe(loop.stop)
        print(f"\nResults: {ok}/{len(paths)} passed, {hp.event_count} events logged")
        return

    if args.run:
        profile = load_profile(args.run)
        if not profile:
            return
        if not args.port and not args.ssh_port:
            print("Need --port and/or --ssh-port")
            return
        hp = CustomHoneypot(profile)
        try:
            asyncio.run(hp.run(http_port=args.port, ssh_port=args.ssh_port))
        except KeyboardInterrupt as _exc:  # silent: user pressed Ctrl+C, clean exit
            logging.getLogger(__name__).debug("ignored: %s", _exc)
        return

    if args.profile:
        profile = load_profile(args.profile)
        if not profile:
            return
        hp = CustomHoneypot(profile)
        print(f"\nProfile '{args.profile}' loaded successfully.")
        print(f"  Vendor:      {hp.vendor}")
        print(f"  Title:       {hp._title}")
        print(f"  Server:      {hp._server}")
        print(f"  Pages:       {len(hp._pages)}")
        print(f"  Assets:      {len(hp._assets)}")
        print(f"  SSH Banner:  {hp._ssh_banner or 'none'}")
        print(f"  Login Form:  {'Yes' if hp._login_form else 'No'}")
        tcp_fp = profile.get("tcp_fingerprint")
        if tcp_fp and tcp_fp.get("ttl"):
            print(f"  TTL:         {tcp_fp.get('ttl')}")
            print(f"  TCP Window:  {tcp_fp.get('tcp_window')}")
            print(f"  MSS:         {tcp_fp.get('mss')}")
            print(f"  OS Guess:    {tcp_fp.get('os_guess')}")
            print("\n  eBPF TTL Deception (match real device):")
            print(f"    TTL={tcp_fp['ttl']}  Window={tcp_fp.get('tcp_window', 'auto')}")
        print("\nTo run:")
        print(f"  python honeypot_generator.py --run {args.profile} --port 8080")
        if hp._ssh_banner:
            print(
                f"  python honeypot_generator.py --run {args.profile} --port 8080 --ssh-port 2222"
            )
        print("\nTo generate systemd service:")
        print(
            f"  python honeypot_generator.py --profile {args.profile} --port 8080 --generate-systemd"
        )
        return

    parser.print_help()


if __name__ == "__main__":
    main()
