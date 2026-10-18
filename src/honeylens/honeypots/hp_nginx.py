"""
honeypots/hp_nginx.py — NGINX honeypot (multi-CVE, HTTP + HTTPS)
================================================================

Wraps the stdlib-only detection engine at honeypots/nginx/ with:
- a cleartext HTTP listener (default 8080) and a TLS listener (default 8443)
  sharing one CVE-signature catalog
- ALPN-h2 routing on the TLS listener -> CVE-2026-49975 "HTTP/2 Bomb" inspector
- a HoneyLens EventLog subclass that writes into sensor_events via log_event()
- a per-source leak-path tracker that flags chained (leak + overflow) attacks

Tracked CVEs live in honeypots/nginx/signatures.py (CVE-2026-42533 script-engine
overflow, CVE-2026-42945 Rift, CVE-2013-2028 chunked, CVE-2017-7529 range,
CVE-2022-41741 mp4, CVE-2021-23017 resolver banner-draw, CVE-2026-49975 h2 bomb).

Run standalone:  python -m honeypots.hp_nginx
"""

from __future__ import annotations

import logging
import os
import re
import ssl
import sys
import threading
import time as _time
from http.server import ThreadingHTTPServer
from typing import Any

from honeylens.honeypots._base import log_event
from honeylens.honeypots.h2bomb import inspect_h2_connection
from honeylens.honeypots.nginx.detector import SourceTracker
from honeylens.honeypots.nginx.eventlog import EventLog
from honeylens.honeypots.nginx.server import make_handler

_LOG = "hp_nginx"

SEVERITY_BY_CONFIDENCE = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "none": "INFO"}

# Back-compat: map the 42945 attack_class to its emitted label when a detection
# doesn't carry an explicit attack_type (older engine builds).
ATTACK_TYPE_BY_CLASS = {
    "cve-2026-42945-dos": "cve_2026_42945_dos",
    "cve-2026-42945-rce": "cve_2026_42945_rce",
    "cve-2026-42533": "NGINX_CVE_2026_42533",
    "cve-2026-42533-leak": "NGINX_CVE_2026_42533_LEAK",
}


def _env(name: str, default: str) -> str:
    """Read HP_NGINX_<name>, falling back to the legacy HP_NGINX_RIFT_<name>."""
    return os.environ.get(f"HP_NGINX_{name}", os.environ.get(f"HP_NGINX_RIFT_{name}", default))


_LEAK_PROBE_PATHS = re.compile(
    r"(?:/etc/(?:passwd|shadow|hostname)|"
    r"/proc/(?:self|cpuinfo|cmdline)|"
    r"/admin|/status|/server-status|/nginx_status|/manager|"
    r"/\.env|/\.git/|/config\.php|/wp-config|/composer\.json|/package\.json|"
    r"/api/v[0-9]+/(?:debug|info|version|metrics)|"
    r"/swagger|/openapi|/api-docs|/graphql|"
    r"\.\./|%2e%2e|"  # path traversal
    r"\\x[0-9a-f]{2}|"  # hex-encoded bytes in path (hex-leak probe)
    r"format=%[a-z])",  # format-string-style param
    re.IGNORECASE,
)


# Fields produced by honeypots/body_capture.capture(). Copied across verbatim rather
# than rebuilt, so widening the capture module never needs an edit here. `body_len` is
# handled separately because it is always present, including for a body-less GET.
_BODY_FIELDS = (
    "body_sample",
    "body_sample_b64",
    "body_encoding",
    "body_truncated",
    "body_high_value",
)


def _user_agent(http: dict) -> str:
    """Pull the User-Agent out of an engine event, whatever case it arrived in."""
    headers = http.get("headers") or {}
    for key, value in headers.items():
        if key.lower() == "user-agent":
            return value
    return ""


# How much of the request body to carry in the `payload` string itself.
#
# The body was already being captured into metadata (`body_sample`), but `payload`
# — the field that shows in the event list, in exports, in reports and in a plain
# SQL grep — carried only `POST / body_len=702`. So the evidence existed and was
# invisible unless you knew to open the metadata. Asked for directly on
# 2026-08-30: "can we get the body instead of body_len".
#
# Bounded because bodies are read up to MAX_BODY (1 MiB) and `payload` is stored on
# every event; the cap keeps a flood of large POSTs from bloating the table. The
# full body stays in metadata regardless, so nothing is lost by the cap.
_PAYLOAD_BODY_BYTES = int(_env("PAYLOAD_BODY_BYTES", "8192"))


def _payload_with_body(summary: str, body_fields: dict) -> str:
    """Append the captured body to the payload summary, bounded and marked."""
    body = body_fields.get("body_sample")
    if not body:
        return summary
    shown = body[:_PAYLOAD_BODY_BYTES]
    out = summary + "\n" + shown
    if len(body) > len(shown):
        out += f"\n...[payload truncated at {_PAYLOAD_BODY_BYTES} bytes; full body in metadata]"
    elif body_fields.get("body_truncated"):
        # The capture layer itself already cut it — say so rather than implying
        # this is the whole request.
        out += "\n...[body truncated by capture]"
    return out


def _body_fields(http: dict) -> dict:
    """Lift the captured-body fields out of an engine event, omitting absent ones.

    A GET keeps no body keys at all: in analysis "no body" and "an empty body" are
    different observations, and collapsing them costs a distinction we rely on.
    """
    return {k: http[k] for k in _BODY_FIELDS if k in http}


class _LeakPathTracker:
    """Tracks per-source leak-probe paths over a sliding window.

    When a source later (or earlier — same window) triggers an overflow, the
    wrapper emits an extra `chained_attack:<n_probes>` indicator so downstream
    gets a single-event flag for the chain shape.
    """

    def __init__(self, window_seconds: float = 1800.0):
        self.window = window_seconds
        self._seen: dict = {}  # src_ip -> [(ts, path), ...]
        self._lock = threading.Lock()

    def observe_path(self, src_ip: str, path: str, now: float, force: bool = False) -> None:
        # `force` records a leak probe detected by signature (e.g. a CVE-2026-42533
        # long-URI capture leak) even when the path is not a known leak-eliciting path.
        if not force and not _LEAK_PROBE_PATHS.search(path):
            return
        with self._lock:
            rec = self._seen.setdefault(src_ip, [])
            rec.append((now, path[:256]))  # bound the key — 42533 leak URIs can be ~8 KB
            cutoff = now - self.window
            rec[:] = [(t, p) for (t, p) in rec if t >= cutoff]

    def leak_probe_count(self, src_ip: str, now: float) -> int:
        with self._lock:
            rec = self._seen.get(src_ip) or []
            cutoff = now - self.window
            rec = [(t, p) for (t, p) in rec if t >= cutoff]
            self._seen[src_ip] = rec
            return len({p for _, p in rec})


class HoneyLensEventLog(EventLog):
    """Bridge engine JSON events into HoneyLens sensor_events.

    Optional JSON-lines file output stays available as a side-channel (set
    HP_NGINX_JSON_LOG=/path). A _LeakPathTracker per source adds a
    `chained_attack` indicator when an overflow arrives from a source that also
    probed leak-looking paths in the chain window.
    """

    PROTOCOL = "nginx"  # honeypot identity -> source=honeypot-nginx

    def __init__(
        self,
        path: str | None = None,
        dst_port: int = 8443,
        wire_protocol: str = "HTTPS",
        chain_window_seconds: float = 1800.0,
    ):
        super().__init__(path=path, also_stdout=False)
        self.dst_port = dst_port
        self.wire_protocol = wire_protocol
        self._logger = logging.getLogger(_LOG)
        self._leak_tracker = _LeakPathTracker(window_seconds=chain_window_seconds)
        self._chain_window = chain_window_seconds

    def emit(self, event: dict) -> None:
        super().emit(event)  # keep file/stdout behaviour if configured

        bait = event.get("ai_endpoint")
        if bait:
            self._emit_ai_endpoint_probe(event, bait)
            return

        det = event.get("detection") or {}
        http = event.get("http") or {}
        attack_class = det.get("attack_class") or "none"
        attack_type = det.get("attack_type") or ATTACK_TYPE_BY_CLASS.get(attack_class)
        severity = SEVERITY_BY_CONFIDENCE.get(det.get("confidence") or "none")
        cve_id = det.get("cve_id") or event.get("cve") or ""
        method = http.get("method") or "?"
        path = http.get("path") or ""
        body_len = http.get("body_len") or 0
        indicators = list(det.get("indicators") or [])

        src_ip = event.get("src_ip") or "0.0.0.0"
        peer = (src_ip, 0)
        now = _time.time()

        # Record leak probes: known leak-eliciting paths, or a signature-detected
        # CVE-2026-42533 capture-leak (the long-URI info-leak primitive).
        is_leak_probe = (attack_class or "").endswith("-leak") or any(
            i.startswith("cve_2026_42533_leak") for i in indicators
        )
        self._leak_tracker.observe_path(src_ip, path, now, force=is_leak_probe)

        # Chain flag: an overflow trigger from a source that also probed
        # leak-eliciting paths in the window.
        is_overflow = bool(det.get("is_overflow"))
        if is_overflow:
            n_probes = self._leak_tracker.leak_probe_count(src_ip, now)
            if n_probes > 0:
                indicators.append(f"chained_attack:{n_probes}")
                if severity in ("LOW", "MEDIUM"):
                    severity = "HIGH"
                self._logger.warning(
                    "[NGINX] chained_attack: %s sent %d leak-probe path(s) in the "
                    "last %.0fs before the %s overflow trigger",
                    src_ip,
                    n_probes,
                    self._chain_window,
                    cve_id or attack_class,
                )

        body_fields = _body_fields(http)
        payload_summary = f"{method} {path} body_len={body_len}"
        if indicators:
            payload_summary += " indicators=" + ",".join(indicators)
        payload_summary = _payload_with_body(payload_summary, body_fields)

        log_event(
            self.PROTOCOL,
            peer,
            {
                "phase": "request",
                "method": method,
                "path": path,
                "body_len": body_len,
                "cve": cve_id,
                "indicators": indicators,
                "attack_class": attack_class,
                "rule": attack_class if attack_class != "none" else "nginx_event",
                "payload": payload_summary,
                "dst_port": self.dst_port,
                "headers": http.get("headers") or {},
                # Also lifted out as a plain string: the classifier only reads string
                # metadata values, so a User-Agent left inside the headers dict is
                # stored but never matched against any rule.
                "user_agent": _user_agent(http),
                # The engine already captured the body (honeypots/nginx/eventlog.py ->
                # body_capture). Carrying only body_len out of it was the whole defect:
                # `POST / body_len=705` was stored and the 705 bytes discarded.
                # Since 2026-08-30 the body is also in `payload` above, bounded —
                # metadata keeps it in full.
                **body_fields,
            },
            attack_type=attack_type,
            severity=severity,
            proto=self.wire_protocol,
            # Present only for requests that carried a body (nginx/server.py). Until
            # this was wired the nginx honeypot stored no raw bytes at all, which
            # showed up in the CVE-2024-4577 case: the loaders arriving on :8443 had
            # a reconstructed body and nothing to prove it byte-for-byte, while the
            # identical ones on the alternate HTTP port did.
            raw=event.get("_raw"),
        )

        if attack_type:
            self._logger.info(
                "[NGINX] %s -> %s %s (%s, %s)",
                src_ip,
                method,
                path,
                cve_id or attack_class,
                severity,
            )

    def _emit_ai_endpoint_probe(self, event: dict, bait: dict) -> None:
        """Record a probe for an exposed AI endpoint (OpenAI/Ollama paths).

        Kept apart from the CVE path: this is reconnaissance against a bait surface,
        not an nginx exploitation attempt, so it must not inherit a CVE attack class.
        The canary handed out with the reply travels in the event (``canary_nonce``,
        ``carrier``) and the ingest registers it — the same path as for the K8s
        honeypot, now that no honeypot owns a database connection.
        """
        src_ip = event.get("src_ip") or "0.0.0.0"
        http = event.get("http") or {}
        path = bait.get("path") or http.get("path") or ""
        method = bait.get("method") or http.get("method") or "?"

        log_event(
            self.PROTOCOL,
            (src_ip, 0),
            {
                "phase": "request",
                "action": bait.get("action"),
                "method": method,
                "path": path,
                "flavour": bait.get("flavour"),
                "model_requested": bait.get("model_requested"),
                "canary_nonce": bait.get("canary_nonce"),
                "carrier": "ai_endpoint_bait" if bait.get("canary_nonce") else None,
                "origin_protocol": bait.get("origin_protocol") or "ai-endpoint",
                "rule": bait.get("rule_name"),
                "payload": f"{method} {path} ai_endpoint={bait.get('flavour')}",
                "dst_port": self.dst_port,
            },
            attack_type=bait.get("attack_type"),
            severity="MEDIUM",
            proto=self.wire_protocol,
            # An AI-endpoint probe with a body is a POST to /v1/chat/completions or
            # similar — the prompt is the interesting part and worth having verbatim.
            raw=event.get("_raw"),
        )

        self._logger.info(
            "[NGINX] %s -> AI endpoint probe %s %s (%s)", src_ip, method, path, bait.get("flavour")
        )


def _build_ssl_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5")
    # Offer HTTP/2 so CVE-2026-49975 "HTTP/2 Bomb" clients negotiate h2 and
    # get routed to the bomb inspector. http/1.1 clients are unaffected.
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except (
        NotImplementedError
    ) as exc:  # ALPN unavailable in this OpenSSL build — h2 path simply won't engage
        logging.getLogger(__name__).debug("ignored: %s", exc)
    return ctx


def _wrap_handler_with_alpn(base_handler_cls, dst_port: int):
    """Route an ALPN-negotiated 'h2' connection to the CVE-2026-49975 bomb
    inspector instead of the HTTP/1.1 parser. http/1.1 / no-ALPN falls through.
    """

    class _ALPNDispatchHandler(base_handler_cls):
        def handle(self):
            alpn = None
            try:
                alpn = self.connection.selected_alpn_protocol()
            except Exception:
                alpn = None
            if alpn != "h2":
                return super().handle()
            try:
                result = inspect_h2_connection(self.connection, self.client_address)
            except Exception as exc:  # never let the inspector crash the thread
                logging.getLogger(_LOG).debug("h2bomb error: %s", exc)
                return
            event = {
                "phase": "h2_inspect",
                "alpn": "h2",
                "dst_port": dst_port,
                "initial_window_size": result.initial_window_size,
                "frame_counts": result.frame_counts,
                "window_update_min_increment": result.window_update_min_increment,
                "indicators": result.attack_types,
            }
            if result.is_bomb:
                log_event(
                    "nginx",
                    self.client_address,
                    event,
                    attack_type=",".join(result.attack_types),
                    severity=result.severity,
                    proto="HTTPS",
                )
                logging.getLogger(_LOG).info(
                    "[NGINX] h2bomb %s %s win=%s frames=%s",
                    self.client_address[0],
                    ",".join(result.attack_types),
                    result.initial_window_size,
                    result.frame_counts,
                )
            else:
                log_event("nginx", self.client_address, event, proto="HTTPS")

    return _ALPNDispatchHandler


class _TimeoutHTTPSServer(ThreadingHTTPServer):
    """Bounded accept backlog + per-connection TLS timeout, with the handshake
    deferred to the worker thread.

    The listening socket stays a plain TCP socket: if it is SSL-wrapped,
    ``accept()`` runs the TLS handshake inline in the single accept thread, so
    one client that stalls mid-ClientHello blocks the accept loop, the backlog
    fills, and the honeypot goes silent while still reporting "active" (observed
    fleet-wide 2026-06-11 -> 06-29). Instead we accept the raw TCP connection
    (fast, never blocks), set a hard timeout, wrap with TLS *without*
    handshaking, and run the bounded handshake in the per-connection worker
    thread. A slow/aborted handshake can then only ever cost one worker.
    """

    request_queue_size = 128
    daemon_threads = True
    handshake_timeout = float(_env("HANDSHAKE_TIMEOUT", "10"))
    ssl_context: ssl.SSLContext | None = None

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(self.handshake_timeout)
        if self.ssl_context is None:
            raise RuntimeError("TLS server started without an SSL context")
        tls = self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return tls, addr

    def finish_request(self, request, client_address):
        try:
            request.do_handshake()
        except (ssl.SSLError, OSError):
            return  # slow / broken / aborted handshake — drop quietly
        super().finish_request(request, client_address)

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, OSError)):
            return
        super().handle_error(request, client_address)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    log = logging.getLogger(_LOG)

    bind = _env("BIND", "0.0.0.0")
    tls_port = int(_env("PORT", "8443"))
    http_port = int(_env("HTTP_PORT", "8080"))  # 0 disables the cleartext listener
    certfile = os.environ.get(
        "HP_NGINX_CERT", os.environ.get("HP_NGINX_RIFT_CERT", "/opt/sensor/certs/nginx.crt")
    )
    keyfile = os.environ.get(
        "HP_NGINX_KEY", os.environ.get("HP_NGINX_RIFT_KEY", "/opt/sensor/certs/nginx.key")
    )
    json_log = (
        os.environ.get("HP_NGINX_JSON_LOG") or os.environ.get("HP_NGINX_RIFT_JSON_LOG") or None
    )
    window = float(_env("WINDOW", "120"))
    chain_window = float(_env("CHAIN_WINDOW", "1800"))

    servers: list[tuple[str, int, Any]] = []

    # TLS listener (8443) — ALPN h2 -> HTTP/2 bomb inspector, h1 -> catalog.
    # HP_NGINX_PORT=0 disables it (cleartext-only / local test).
    if tls_port:
        tls_log = HoneyLensEventLog(
            path=json_log,
            dst_port=tls_port,
            wire_protocol="HTTPS",
            chain_window_seconds=chain_window,
        )
        tls_handler = _wrap_handler_with_alpn(
            make_handler(tls_log, SourceTracker(window_seconds=window)), tls_port
        )
        httpd_tls = _TimeoutHTTPSServer((bind, tls_port), tls_handler)
        httpd_tls.ssl_context = _build_ssl_context(certfile, keyfile)
        servers.append(("TLS", tls_port, httpd_tls))
        log.info(
            "NGINX honeypot (TLS) on %s:%d cert=%s window=%.0fs chain=%.0fs "
            "backlog=%d handshake_timeout=%.0fs",
            bind,
            tls_port,
            certfile,
            window,
            chain_window,
            httpd_tls.request_queue_size,
            httpd_tls.handshake_timeout,
        )

    # Cleartext HTTP listener (8080) — same catalog, most nginx probes are HTTP.
    if http_port:
        http_log = HoneyLensEventLog(
            path=json_log,
            dst_port=http_port,
            wire_protocol="HTTP",
            chain_window_seconds=chain_window,
        )
        http_handler = make_handler(http_log, SourceTracker(window_seconds=window))
        httpd_http = ThreadingHTTPServer((bind, http_port), http_handler)
        httpd_http.daemon_threads = True
        servers.append(("HTTP", http_port, httpd_http))
        log.info("NGINX honeypot (cleartext) on %s:%d", bind, http_port)

    if not servers:
        log.error("no listeners configured (HP_NGINX_PORT and HP_NGINX_HTTP_PORT both 0)")
        return 1

    # Run every listener but the last in a daemon thread; block on the last.
    threads = []
    for _name, _port, srv in servers[:-1]:
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        threads.append(t)
    try:
        servers[-1][2].serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down NGINX honeypot")
    finally:
        for _name, _port, srv in servers:
            srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
