"""Low-interaction HTTP server emulating a multi-CVE-vulnerable nginx.

No real nginx, no code-execution path. It presents a realistic vulnerable-version
banner, classifies and logs every request against the CVE catalog, and serves a
fake-crash oracle (drops the connection without a response) whenever it sees an
overflow-class trigger — so an attacker's success check behaves as it would
against a real vulnerable worker that just died.
"""

from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .detector import SourceTracker, classify
from .eventlog import EventLog, build_event

try:
    from honeylens.intelligence import ai_canary
except ImportError:  # canary is optional; hp_nginx sets sys.path
    ai_canary = None  # type: ignore[assignment]  # optional module, idiom from the mypy docs

try:
    from honeylens.honeypots import ai_endpoints
except ImportError:
    ai_endpoints = None  # type: ignore[assignment]  # optional module, idiom from the mypy docs

# A version inside CVE-2026-42533's vulnerable range (0.9.6-1.31.2); also draws
# generic version scanners.
SERVER_BANNER = "nginx/1.31.2"
MAX_BODY = 1 << 20  # 1 MiB cap on bodies we read
MAX_RAW_CAPTURE = int(os.environ.get("HONEYPOT_RAW_CAPTURE_BYTES", 64 * 1024))


class _CapturingReader:
    """Tees everything the HTTP machinery reads off the socket into a buffer.

    Raw capture cannot be done by reassembling the request afterwards.
    BaseHTTPRequestHandler consumes the request line and headers before our
    handler is entered, and it normalises what it parses — header case, folded
    continuation lines, the exact whitespace. Bytes rebuilt from those pieces are
    a rendering of the request, not the request, and the whole point of storing
    them is to be able to say the stored bytes are what arrived. So capture at the
    only place where that is still true: as they are read.

    Delegates everything else to the real reader, so it stays a drop-in for the
    buffered socket file `socketserver` hands us.
    """

    def __init__(self, wrapped, limit: int):
        self._wrapped = wrapped
        self._limit = limit
        self.captured = bytearray()

    def reset(self) -> None:
        """Start a fresh capture. Called per request, not per connection.

        `protocol_version = "HTTP/1.1"` means keep-alive: several requests share
        one socket. Without this, request two would be stored carrying request
        one in front of it.
        """
        del self.captured[:]

    def _tee(self, chunk):
        if chunk:
            room = self._limit - len(self.captured)
            if room > 0:
                self.captured += chunk[:room]
        return chunk

    def read(self, *a, **kw):
        return self._tee(self._wrapped.read(*a, **kw))

    def readline(self, *a, **kw):
        return self._tee(self._wrapped.readline(*a, **kw))

    def readinto(self, buf):
        n = self._wrapped.readinto(buf)
        if n:
            self._tee(bytes(memoryview(buf)[:n]))
        return n

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


def make_handler(event_log: EventLog, tracker: SourceTracker) -> type:
    class NginxHoneypotHandler(BaseHTTPRequestHandler):
        server_version = SERVER_BANNER
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # silence stderr access logging
            pass

        def setup(self):
            super().setup()
            self._capture = _CapturingReader(self.rfile, MAX_RAW_CAPTURE)
            self.rfile = self._capture  # type: ignore[assignment]

        def handle_one_request(self):
            self._capture.reset()
            super().handle_one_request()

        def _handle(self, method: str):
            raw_path = self.path.encode("latin-1")
            length = min(int(self.headers.get("Content-Length", 0) or 0), MAX_BODY)
            body = self.rfile.read(length) if length else b""
            headers = {k: v for k, v in self.headers.items()}
            src_ip = self.client_address[0]

            detection = classify(method, raw_path, headers, body, http_version=self.request_version)
            attack_class = tracker.observe(src_ip, detection, now=time.time())
            event = build_event(src_ip, method, raw_path, headers, body, detection, attack_class)

            # Raw bytes ride on the event under a private key: the sensor-side sink
            # stores them verbatim, the JSON log drops them (see EventLog.emit).
            # Only requests that carried a body, matching hp_http — a parsed GET
            # already records everything a scan tells us, and storing raw for every
            # probe would bloat the table for no evidentiary gain. Bodies are where
            # the evidence lives: the CVE-2024-4577 loaders arrive in one.
            if body:
                event["_raw"] = bytes(self._capture.captured)

            # AI-endpoint bait: scanners hunt /v1/models & friends by path on whatever
            # HTTP port answers, not on our dedicated LLM port, so serve them here.
            # Checked before the event is emitted so a probe produces one enriched
            # event rather than two, and before the overflow oracle because an AI
            # path is a discovery probe, not a memory-corruption attempt.
            bait = (
                ai_endpoints.handle(
                    method, self.path, host=headers.get("Host", ""), src_ip=src_ip, body=body
                )
                if ai_endpoints is not None
                else None
            )
            if bait is not None:
                status, payload, bait_headers, bait_event = bait
                event["ai_endpoint"] = bait_event
                event_log.emit(event)
                self._respond(
                    status,
                    json.dumps(payload).encode() + b"\n",
                    method=method,
                    content_type="application/json",
                    extra_headers=bait_headers,
                )
                return

            event_log.emit(event)

            # Fake-crash oracle: on any overflow-class trigger, drop the
            # connection without a response, mimicking a crashed worker.
            if detection.is_overflow:
                self.close_connection = True
                return

            # A leak-class hit is the response an AI triage agent is most likely to
            # be pointed at, so that is where the canary rides (Idea 52). Overflow
            # hits return above — a crashed worker sends no headers at all.
            canary = {}
            if (
                ai_canary is not None
                and detection.matched
                and ai_canary.enabled()
                and ai_canary.carrier_enabled("NGINX_LEAK")
            ):
                _nonce, canary = ai_canary.issue(
                    "nginx",
                    self.path,
                    headers.get("Host", ""),
                    origin_src_ip=src_ip,
                    context=f"{detection.cve_id or 'NGINX'} response",
                )

            if raw_path.startswith(b"/api/"):
                self._respond(200, b"endpoint migrated\n", method=method, extra_headers=canary)
            elif self.path == "/":
                self._respond(200, b"ok\n", method=method, extra_headers=canary)
            else:
                self._respond(
                    404,
                    b"<html><head><title>404 Not Found</title>"
                    b"</head><body>404 Not Found</body></html>\n",
                    method=method,
                    content_type="text/html",
                    extra_headers=canary,
                )

        def _respond(
            self,
            code: int,
            body: bytes,
            method: str = "GET",
            content_type: str = "text/plain",
            extra_headers: dict | None = None,
        ):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            for _k, _v in (extra_headers or {}).items():
                self.send_header(_k, _v)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(body)
            self.close_connection = True

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_HEAD(self):
            self._handle("HEAD")

        def do_PUT(self):
            self._handle("PUT")

    return NginxHoneypotHandler


def serve(bind: str, port: int, event_log: EventLog) -> ThreadingHTTPServer:
    """Build and return a running-ready honeypot server."""
    handler = make_handler(event_log, SourceTracker())
    return ThreadingHTTPServer((bind, port), handler)
