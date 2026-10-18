"""Capture HTTP requests aiohttp rejects *before* the application runs (todo E7 / NetScaler P0).

aiohttp's parser answers malformed, oversized or non-HTTP requests itself — 400 (bad request /
bad method, e.g. a TLS ClientHello to an HTTP port), 413 (payload too large), 431 (headers too
large), 505 (version) — before the router or any handler. A decoy that only records inside its
handler never sees these, so it cannot say how much hostile malformed input it dropped. The
internal NetScaler review flagged that as an open P0: "parser-level rejections still bypass
recording, so there is no way to know how much of what was never recorded mattered."

This wraps aiohttp's ``RequestHandler`` to record each pre-handler rejection — the peer, the
status, the parser's offending-byte message, and the raw bytes last received — through a
callback the decoy routes to its normal emit path.

Fails safe: if aiohttp's internals are not the shape we expect, `make_capturing_factory`
returns the stock factory unchanged, so the decoy still serves. Capture is best-effort;
serving is not.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from aiohttp import web
from aiohttp.web_protocol import RequestHandler

logger = logging.getLogger(__name__)

# How many bytes of a rejected request to keep — enough to see the method/line/TLS record that
# tripped the parser, without storing a flood for high-volume garbage on port 80.
_SNIPPET = 2048

# on_reject receives: {"peer": (ip, port), "status": int, "reason": str, "raw": bytes,
#                      "dst_port": int | None, "scheme": "http" | "https"}
OnReject = Callable[[dict[str, Any]], None]


def make_capturing_factory(server: web.Server, on_reject: OnReject) -> Callable[[], RequestHandler]:
    """Return a protocol factory that behaves exactly like ``server`` (the AppRunner's Server)
    but records every pre-handler rejection via ``on_reject``. Returns ``server`` itself if
    aiohttp's internals are not reachable, so serving is never put at risk by the capture."""
    try:
        loop = server._loop
        kwargs = server._kwargs
    except AttributeError as exc:  # pragma: no cover - aiohttp internals moved
        logger.warning(
            "pre-parser capture unavailable (aiohttp internals changed: %s); serving without it",
            exc,
        )
        return server

    class _CapturingRequestHandler(RequestHandler):
        def __init__(self, *a: Any, **k: Any) -> None:
            super().__init__(*a, **k)
            self._first_bytes = b""

        def data_received(self, data: bytes) -> None:
            # Keep the opening bytes of the connection; on a parse failure this is the evidence,
            # since aiohttp's error path does not hand the raw buffer to handle_error.
            try:
                if data and len(self._first_bytes) < _SNIPPET:
                    self._first_bytes = (self._first_bytes + data)[:_SNIPPET]
            except Exception as e:  # pragma: no cover - capture bookkeeping must not break parsing
                logger.debug("pre-parser snippet capture failed: %s", e)
            return super().data_received(data)

        def handle_error(
            self,
            request: Any,
            status: int = 500,
            exc: BaseException | None = None,
            message: str | None = None,
        ) -> web.StreamResponse:
            resp = super().handle_error(request, status, exc, message)
            try:
                # Attribution is the SOCKET peer. On the PROXY-protocol path that is already the
                # real client (the listener's transport view rewrites peername). A header-based
                # reverse proxy (X-Real-IP / X-Forwarded-For) cannot be honoured here — the request
                # failed to parse, so there is no trusted header to read — so behind one of those a
                # pre-parser reject is attributed to the edge, not the client. That is a known
                # limitation of capturing unparseable input, not a spoofable field.
                peer: tuple[str, int] = ("0.0.0.0", 0)
                dst_port: int | None = None
                scheme = "http"
                transport = self.transport
                if transport is not None:
                    pn = transport.get_extra_info("peername")
                    if pn:
                        peer = (pn[0], pn[1])
                    sn = transport.get_extra_info("sockname")
                    if sn:
                        dst_port = sn[1]
                    if transport.get_extra_info("sslcontext") is not None:
                        scheme = "https"
                reason = getattr(exc, "message", None) or message or (str(exc) if exc else None)
                on_reject(
                    {
                        "peer": peer,
                        "status": int(status),
                        "reason": str(reason or f"HTTP {status}")[:500],
                        "raw": bytes(self._first_bytes),
                        "dst_port": dst_port,
                        "scheme": scheme,
                    }
                )
            except Exception as e:  # never let capture break the error response path
                logger.debug("pre-parser capture failed: %s", e)
            return resp

    def factory() -> RequestHandler:
        return _CapturingRequestHandler(server, loop=loop, **kwargs)

    return factory
