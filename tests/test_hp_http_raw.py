"""The HTTP decoy passes the raw request bytes only when there is a body to keep.

Raw is evidence for a payload carried in the body (a loader, a web shell); for a bare
GET the parsed request already is the whole request, and storing raw would double every
scanner hit for nothing. 0.9 pinned this by grepping the source; this drives the handler.
"""

from __future__ import annotations

import asyncio

from honeylens.honeypots import hp_http
from tests.ics_fakes import FakeReader, FakeWriter


def _run(monkeypatch, raw: bytes):
    seen: list[dict] = []
    monkeypatch.setattr(hp_http, "log_event", lambda *a, **kw: seen.append(kw) or {})
    hp = hp_http.HTTPHoneypot.__new__(hp_http.HTTPHoneypot)
    hp.__init__()
    asyncio.run(hp.handle_connection(FakeReader(raw), FakeWriter(), ("203.0.113.9", 40000)))
    assert len(seen) == 1
    return seen[0].get("raw")


def test_a_request_with_a_body_carries_raw(monkeypatch):
    raw = b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nuser=admin!"
    assert _run(monkeypatch, raw) == raw


def test_a_bare_get_carries_no_raw(monkeypatch):
    assert _run(monkeypatch, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
