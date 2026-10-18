"""
honeypots/hp_http.py — Modular HTTP honeypot service
=====================================================
Captures HTTP requests, extracts credentials and attack indicators,
returns a realistic response page.

Run standalone:  python -m honeypots.hp_http
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import urllib.parse
from typing import ClassVar

from honeylens.honeypots import shell_bait
from honeylens.honeypots._base import BaseHoneypot, log_event

# Imported after _base, which puts the project root on sys.path — this module is also
# started as a script, and an import above that bootstrap silently falls back.
from honeylens.honeypots.body_capture import MAX_CAPTURE
from honeylens.honeypots.body_capture import capture as capture_body


class HTTPHoneypot(BaseHoneypot):
    PROTOCOL = "http"
    DEFAULT_PORT = 80
    TTL_PROFILE = "linux"

    def __init__(self):
        super().__init__()
        self.server_header = self.profile.get(
            "server_header", "Apache/2.4.66 (Ubuntu) mod_http2/2.0.32"
        )
        self.powered_by = self.profile.get("powered_by", "PHP/7.4.3")
        self.title = self.profile.get("title", "Welcome")
        self.upgrade = self.profile.get("upgrade", "h2,h2c")

    # ------------------------------------------------------------------ parse
    def _parse_request(self, data: bytes) -> dict:
        """Parse raw HTTP bytes into structured components."""
        result: dict = {
            "method": None,
            "path": None,
            "version": None,
            "headers": {},
            "body": None,
            "body_raw": b"",
            "query_string": None,
        }
        try:
            if b"\r\n\r\n" in data:
                hdr_part, body = data.split(b"\r\n\r\n", 1)
                # No truncation here: body_capture.MAX_CAPTURE is the single ceiling,
                # and it is applied where the event is built. A second, smaller cap in
                # the parser silently cost us everything past 8 KB of a POST.
                result["body"] = body.decode(errors="ignore")
                result["body_raw"] = body
            else:
                hdr_part = data

            lines = hdr_part.decode(errors="ignore").split("\r\n")
            if lines:
                parts = lines[0].split(" ", 2)
                if len(parts) >= 2:
                    result["method"] = parts[0]
                    result["path"] = parts[1]
                    if "?" in parts[1]:
                        _, qs = parts[1].split("?", 1)
                        result["query_string"] = qs
                if len(parts) >= 3:
                    result["version"] = parts[2]

            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    result["headers"][k.lower()] = v
        except Exception as exc:
            result["parse_error"] = str(exc)
        return result

    # -------------------------------------------------------------- classify
    _ATTACK_PATTERNS: ClassVar[list[tuple]] = [
        (r"\.\./|\.\.\\|%2e%2e", "path_traversal", "HIGH"),
        (r"(?:union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*--)", "sql_injection", "HIGH"),
        (r"<script|javascript:|on\w+\s*=", "xss", "MEDIUM"),
        (r"/etc/passwd|/etc/shadow|/proc/self", "lfi", "HIGH"),
        (r"cmd\.exe|/bin/(?:sh|bash)|powershell", "rce_attempt", "CRITICAL"),
        (r"wp-login|wp-admin|xmlrpc\.php", "wordpress_scan", "LOW"),
        (r"\.env|\.git/|config\.php", "info_disclosure", "MEDIUM"),
    ]

    # CVE-2026-23918 recon shapes — paired with the Server: Apache/2.4.66
    # bait. Hits land here BEFORE the generic _ATTACK_PATTERNS so the more
    # specific tag wins. Severity stays LOW on its own (recon, not exploit);
    # promotion to HIGH happens via the Suricata SID 9026500/9026503 fire
    # or the AI triage stage seeing the recon+exploit chain across events.
    #
    # v2 (2026-05-29): removed generic python-(requests|httpx|urllib3) from
    # the UA pattern after day-1 telemetry showed they collide with cloud-
    # secrets hunters, MCP probers, and Elasticsearch enumeration. Kept the
    # h2-library-specific identifiers (python-h2, h2, hyper-h2) plus the
    # CVE-named and Apache-named recon kits.
    _CVE_2026_23918_UA_RE = re.compile(
        r"^(?:python-h2|h2|hyper-h2|"
        r"CVE-?2026-?23918[-_]?\w*|apache[-_]?2[._]?4[._]?66[-_]?\w*)/",
        re.IGNORECASE,
    )

    def _classify(self, path: str, body: str | None, headers: dict | None = None) -> tuple | None:
        """Return (attack_type, severity) for the first matching pattern."""
        # CVE-2026-23918 recon: explicit h2c upgrade attempt against our
        # HTTP/1.1 honeypot. Real browsers never do this; the exploit's
        # HTTP/1.1 fallback path does.
        if headers:
            upgrade = (headers.get("upgrade") or "").lower()
            if "h2c" in upgrade or "h2" in upgrade.split(","):
                return "cve_2026_23918_recon", "MEDIUM"
            ua = headers.get("user-agent") or ""
            if self._CVE_2026_23918_UA_RE.match(ua):
                return "cve_2026_23918_recon", "LOW"

        text = urllib.parse.unquote(path or "")
        if body:
            text += " " + body
        text_lower = text.lower()
        for pattern, atype, sev in self._ATTACK_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return atype, sev
        return None

    # -------------------------------------------------------------- creds
    @staticmethod
    def _extract_credentials(headers: dict, body: str | None) -> dict | None:
        """Pull credentials from Basic-Auth header or POST body."""
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth.split(" ", 1)[1]).decode(errors="ignore")
                user, _, pw = decoded.partition(":")
                return {"username": user, "password": pw, "source": "basic_auth"}
            except Exception as exc:
                logging.getLogger(__name__).debug("ignored: %s", exc)
        if body:
            m = re.search(
                r"(?:user(?:name)?|login)=([^&]+).*?(?:pass(?:word)?|pwd)=([^&]+)", body, re.I
            )
            if m:
                return {
                    "username": urllib.parse.unquote_plus(m.group(1)),
                    "password": urllib.parse.unquote_plus(m.group(2)),
                    "source": "post_body",
                }
        return None

    # -------------------------------------------------------------- response
    def _build_response(self) -> bytes:
        html = (
            f"<html><head><title>{self.title}</title></head>"
            f"<body><h1>{self.title}</h1>"
            f"<p>It works!</p></body></html>\r\n"
        )
        return (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: {self.server_header}\r\n"
            f"X-Powered-By: {self.powered_by}\r\n"
            f"Upgrade: {self.upgrade}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(html)}\r\n"
            f"Connection: close\r\n"
            f"\r\n{html}"
        ).encode()

    # -------------------------------------------------------------- handler
    async def _read_request(self, reader) -> bytes:
        """Read headers, then keep reading until Content-Length is satisfied.

        A single `read()` returns whatever one TCP segment happened to carry, so a
        POST larger than the MTU used to be recorded with its body cut at the packet
        boundary — the bigger the payload, the more of it was lost. Bounded by
        MAX_CAPTURE (plus headers) so a client still cannot make us buffer without
        limit.
        """
        data = await asyncio.wait_for(reader.read(16384), timeout=30)
        if not data or b"\r\n\r\n" not in data:
            return data

        head, body = data.split(b"\r\n\r\n", 1)
        want = 0
        for line in head.decode(errors="ignore").split("\r\n")[1:]:
            if line.lower().startswith("content-length:"):
                try:
                    want = int(line.split(":", 1)[1].strip())
                except ValueError:
                    want = 0
                break

        want = min(want, MAX_CAPTURE)
        while len(body) < want:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(min(65536, want - len(body))), timeout=10
                )
            except TimeoutError:
                break  # a stalled sender still leaves us what did arrive
            if not chunk:
                break
            body += chunk
        return head + b"\r\n\r\n" + body

    async def handle_connection(self, reader, writer, peer):
        data = await self._read_request(reader)
        if not data:
            return

        req = self._parse_request(data)
        hdrs = req.get("headers", {})

        event: dict = {
            "phase": "request",
            "method": req["method"],
            "path": req["path"],
            "query_string": req["query_string"],
            "http_version": req["version"],
            "user_agent": hdrs.get("user-agent"),
            "host": hdrs.get("host"),
            "content_type": hdrs.get("content-type"),
            "headers": hdrs,
            "dst_port": self.port,
            # Verbatim, credentials included — the body is the evidence.
            # See honeypots/body_capture.py.
            **capture_body(
                req.get("body_raw") or b"", req["path"] or "", hdrs.get("content-type", "")
            ),
        }

        creds = self._extract_credentials(hdrs, req["body"])
        if creds:
            event["credentials"] = creds

        attack = self._classify(req["path"], req["body"], hdrs)
        attack_type = attack[0] if attack else None
        severity = attack[1] if attack else None

        # Decided before the event is logged, so the record says what we served.
        # A shell hunt is only worth answering if we can later tell which reply
        # produced the follow-up request. See honeypots/shell_bait.py.
        mode = shell_bait.decide(req["path"], hdrs.get("host"))
        if mode:
            event["response_mode"] = mode

        # Keep the bytes only when the payload rides in the body. A GET adds
        # nothing a parsed request does not already carry, and storing raw for
        # every scan would bloat the table for no evidentiary gain.
        log_event(
            self.PROTOCOL,
            peer,
            event,
            attack_type=attack_type,
            severity=severity,
            raw=data if req.get("body_raw") else None,
        )

        self.logger.info(
            "[HTTP] %s:%d %s %s%s%s",
            peer[0],
            peer[1],
            req["method"] or "?",
            (req["path"] or "/")[:80],
            f" [{attack_type}]" if attack_type else "",
            f" -> {mode}" if mode else "",
        )

        writer.write(shell_bait.build(mode, self.server_header) if mode else self._build_response())
        await writer.drain()


if __name__ == "__main__":
    HTTPHoneypot().run()
