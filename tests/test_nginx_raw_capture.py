"""Raw request capture in the nginx honeypot.

The CVE-2024-4577 campaign arrives on two of our ports. On :8888 the HTTP
honeypot stored the request bytes; on :8443 the nginx honeypot stored none, so
half the evidence for the same campaign rested on a reconstruction. This pins the
capture and, more importantly, pins that what is stored is what arrived.

The property under test is byte equality with the wire, not "a request that looks
like the one we sent". Reassembling from `self.requestline` and `self.headers`
would pass a laxer test while storing something http.server had already
normalised — which is exactly the evidence a reconstruction cannot give.
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import ThreadingHTTPServer

import pytest

from honeylens.honeypots.nginx.detector import SourceTracker
from honeylens.honeypots.nginx.eventlog import EventLog
from honeylens.honeypots.nginx.server import _CapturingReader, make_handler


class _Collector(EventLog):
    """Captures events in-process, the way the sensor-side sink does."""

    def __init__(self):
        super().__init__(path=None, also_stdout=False)
        self.events = []

    def emit(self, event):
        super().emit(event)  # exercises the JSON path too
        self.events.append(event)


@pytest.fixture
def server():
    log = _Collector()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(log, SourceTracker()))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv, log
    srv.shutdown()
    srv.server_close()


def send(srv, raw: bytes, read_reply=True) -> None:
    """Write bytes straight onto the socket — no client library normalising them."""
    s = socket.create_connection(srv.server_address, timeout=5)
    try:
        s.sendall(raw)
        if read_reply:
            s.settimeout(2)
            try:
                s.recv(65535)
            except (TimeoutError, ConnectionResetError):
                pass  # the fake-crash oracle drops some connections
    finally:
        s.close()


def wait(log, n=1, timeout=5.0):
    import time

    end = time.time() + timeout
    while time.time() < end:
        if len(log.events) >= n:
            return log.events
        time.sleep(0.02)
    raise AssertionError(f"expected {n} event(s), got {len(log.events)}")


def test_a_post_body_is_stored_exactly_as_it_arrived(server):
    srv, log = server
    body = b'<?php shell_exec(base64_decode("ZWNobyBoaQ==")) ?>'
    raw = (
        b"POST /index.php?%ADd+auto_prepend_file=php://input HTTP/1.1\r\n"
        b"Host: victim\r\nUser-Agent: curl/8.4.0\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    send(srv, raw)
    ev = wait(log)[0]
    assert ev["_raw"] == raw, "stored bytes must equal the bytes sent"


def test_odd_header_casing_and_spacing_survive(server):
    """The reason this is a tee and not a reconstruction.

    http.server lowercases header lookups and rebuilds folded lines; anything
    assembled from its parsed view loses the original spelling. An analyst reading
    stored evidence needs the spelling — it is often the only fingerprint
    separating two tools sending the same exploit.
    """
    srv, log = server
    body = b"x=1"
    raw = (
        b"POST /t HTTP/1.1\r\nHost: v\r\n"
        b"cOnTeNt-TyPe:    application/x-www-form-urlencoded\r\n"
        b"X-Odd:\tvalue-after-tab\r\n"
        b"Content-Length: 3\r\n\r\n" + body
    )
    send(srv, raw)
    ev = wait(log)[0]
    assert ev["_raw"] == raw
    assert b"cOnTeNt-TyPe:    application" in ev["_raw"]
    assert b"X-Odd:\tvalue-after-tab" in ev["_raw"]


def test_the_honeypot_answers_one_request_per_connection(server):
    """Documents why the capture reset is defensive rather than load-bearing.

    `protocol_version` is HTTP/1.1, which would normally mean keep-alive, but
    `_respond` sets `Connection: close` and `close_connection` on every reply — so
    in practice each connection carries one request and each gets a fresh reader
    from `setup()`. Pinned because the reset below only matters if this changes,
    and a future keep-alive would otherwise silently start prefixing every stored
    request with the one before it.
    """
    srv, log = server
    send(srv, b"POST /x HTTP/1.1\r\nHost: v\r\nContent-Length: 1\r\n\r\nA")
    ev = wait(log)[0]
    assert ev["http"]["headers"].get("Content-Length") == "1"
    s = socket.create_connection(srv.server_address, timeout=5)
    try:
        s.sendall(b"POST /y HTTP/1.1\r\nHost: v\r\nContent-Length: 1\r\n\r\nB")
        s.settimeout(3)
        reply = b""
        while True:
            chunk = s.recv(65535)
            if not chunk:
                break
            reply += chunk
    except (TimeoutError, ConnectionResetError):
        pass
    finally:
        s.close()
    assert b"Connection: close" in reply


def test_a_second_request_does_not_inherit_the_first(server):
    """If keep-alive is ever enabled, each request must still stand alone.

    Driven through the reader directly: the honeypot closes connections today, so
    a socket-level version of this would pass without exercising anything.
    """
    import io

    r = _CapturingReader(io.BytesIO(b"REQ-ONEREQ-TWO"), limit=1 << 16)
    r.read(7)
    assert bytes(r.captured) == b"REQ-ONE"
    r.reset()
    r.read(7)
    assert bytes(r.captured) == b"REQ-TWO", "capture carried the previous request"


def test_a_get_stores_no_raw(server):
    """Deliberate, and the same policy as hp_http.

    A bodyless probe tells us nothing the parsed event does not already record, and
    keeping raw for every scan grows the table without adding evidence.
    """
    srv, log = server
    send(srv, b"GET /?a=1 HTTP/1.1\r\nHost: v\r\nConnection: close\r\n\r\n")
    ev = wait(log)[0]
    assert "_raw" not in ev


def test_the_json_log_never_carries_raw_bytes(server):
    """LOG_SCHEMA.md documents the JSON lines as stable for external ingestion.

    Raw bytes are not JSON, and base64 in the file would duplicate what the sink
    already stores. If this ever regresses, `json.dumps` raises rather than
    silently changing the schema — so assert the drop explicitly.
    """
    srv, log = server
    body = b"payload"
    send(srv, b"POST /x HTTP/1.1\r\nHost: v\r\nContent-Length: 7\r\n\r\n" + body)
    ev = wait(log)[0]
    assert ev["_raw"] == b"POST /x HTTP/1.1\r\nHost: v\r\nContent-Length: 7\r\n\r\npayload"
    line = json.dumps(EventLog.serialisable(ev))
    assert "_raw" not in line
    assert json.loads(line)["http"]["method"] == "POST"


def test_capture_is_bounded():
    """A 1 MiB body must not become a 1 MiB row. hp_http caps at the same value."""
    import io

    r = _CapturingReader(io.BytesIO(b"A" * 5000), limit=100)
    r.read(5000)
    assert len(r.captured) == 100


def test_the_reader_is_a_drop_in_for_the_socket_file():
    """It must delegate whatever http.server reaches for; a missing attribute would
    surface as a broken honeypot rather than a failed test."""
    import io

    inner = io.BytesIO(b"line one\r\nline two\r\n")
    r = _CapturingReader(inner, limit=1 << 16)
    assert r.readline() == b"line one\r\n"
    buf = bytearray(4)
    assert r.readinto(buf) == 4
    assert bytes(r.captured) == b"line one\r\nline"
    assert r.readable() is True  # delegated
    r.close()  # delegated
    assert inner.closed
