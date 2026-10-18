"""The Kubernetes decoy must read the whole request before it answers.

The five handlers dispatched as soon as `\r\n\r\n` appeared in the buffer — the moment
the *headers* are complete — then answered and closed the connection. For a GET that is
right. For a POST the body we recorded was whatever happened to share the first TCP
segment with the headers, and the rest was never read.

What that cost, measured on 2026-10-23: a PHP2Shell exploitation POST to `sensor-a`:8001 was
stored with `body_len=128` for a body of roughly 20 KB, and the decoy's row and
Suricata's alert on the same request sat 68 seconds apart — the decoy had answered and
closed while the client was still writing. Four such requests across two sensors, with
offsets of 65-70 s. The `honeypot-nginx` decoy, which reads the body before writing its
row, alerts in the same second it captures.

The property under test is therefore about *timing*, not shape: no event may be written
until the declared body has arrived, and what is written must be the bytes that arrived.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from honeylens.honeypots import honeypot_k8s as k8s

FIELD = b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'


class _Transport:
    """Minimal asyncio transport: records what was written and when it closed."""

    def __init__(self, peer=("203.0.113.9", 51234)):
        self.written = b""
        self.closed = False
        self._peer = peer

    def get_extra_info(self, name, default=None):
        return self._peer if name == "peername" else default

    def write(self, data):
        self.written += data

    def close(self):
        self.closed = True


@pytest.fixture
def events(monkeypatch):
    """Collect the event lines the decoy would append, without touching the log file."""
    collected = []
    monkeypatch.setattr(k8s, "append_line", lambda path, line: collected.append(json.loads(line)))
    return collected


def captured(events: list) -> dict:
    """The event that is the record of the request.

    The kubectl-proxy listener writes a routing note and then delegates, so :8001 emits
    two rows per request — which is visible in the stored data as a 15-byte
    `POST /index.php` row next to the one that carries the body.
    """
    with_body = [e for e in events if "body_len" in e]
    assert len(with_body) == 1, f"expected one record of the request, got {len(with_body)}"
    return with_body[0]


def _post(body: bytes, path: str = "/index.php", extra: bytes = b"") -> bytes:
    return (
        b"POST " + path.encode() + b" HTTP/1.1\r\n"
        b"Host: 198.51.100.7:8001\r\n"
        b"Content-Type: multipart/form-data; boundary=P2SB\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n" + extra + b"\r\n" + body
    )


def _body(size: int = 2048) -> bytes:
    return b"--P2SB\r\n" + FIELD + b"\r\n\r\n<?php system('id'); ?>" + b"A" * size + b"\r\n--P2SB--"


async def _feed(chunks, handler_cls=k8s.KubectlProxyHandler, port=8001):
    """Drive the protocol with the request split across TCP segments."""
    proto = handler_cls(port)
    transport = _Transport()
    proto.connection_made(transport)
    for chunk in chunks:
        proto.data_received(chunk)
        await asyncio.sleep(0)
    return proto, transport


def test_the_decoy_waits_for_a_body_split_across_segments(events):
    """The headers arriving is not the request arriving."""
    body = _body()
    request = _post(body)
    head, _, rest = request.partition(b"\r\n\r\n")

    async def scenario():
        _proto, transport = await _feed([head + b"\r\n\r\n", rest[:200], rest[200:]])
        return transport

    transport = asyncio.run(scenario())

    assert transport.written, "the decoy must still answer"
    ev = captured(events)
    assert ev["body_len"] == len(body), (
        f"body_len {ev['body_len']} != {len(body)} — the body was cut short again"
    )


def test_nothing_is_written_while_the_body_is_still_in_flight(events):
    """The defect was visible as an event timestamped before the request finished."""

    async def scenario():
        body = _body()
        head, _, rest = _post(body).partition(b"\r\n\r\n")
        _proto, transport = await _feed([head + b"\r\n\r\n", rest[:100]])
        return transport

    transport = asyncio.run(scenario())
    assert events == [], "an event was written for a request that had not arrived yet"
    assert not transport.closed, "the connection was closed with the body still coming"


def test_the_captured_body_is_the_bytes_that_arrived(events):
    r"""`parse_http_request` decodes with errors="replace" and rejoins on \r\n, so the
    capture has to come from the bytes, not from that reconstruction."""
    body = b"--P2SB\r\n" + FIELD + b"\r\n\r\n\x00\x01\x02\xff\xfe binary \n\n tail\r\n--P2SB--"

    asyncio.run(_feed([_post(body)]))

    ev = captured(events)
    assert ev["body_len"] == len(body)
    raw = bytes.fromhex(ev["raw_hex"])
    assert raw.endswith(body), "full_payload would not have held what the attacker sent"


def test_one_request_produces_one_record_of_itself(events):
    """The routing note must not carry the body too: one request, one stored body."""
    asyncio.run(_feed([_post(_body())]))
    assert sum(1 for e in events if "raw_hex" in e) == 1, (
        "the same request bytes were stored on more than one row"
    )


def test_the_field_name_reaches_the_event(events):
    """The point of the exercise: a content hunt must be able to find this request."""
    asyncio.run(_feed([_post(_body())]))
    line = json.dumps(captured(events))
    assert "PHP_SESSION_UPLOAD_PROGRESS" in line
    assert "<?php" in line


def test_a_get_still_answers_immediately(events):
    """No body is declared, so there is nothing to wait for."""

    async def scenario():
        _proto, transport = await _feed([b"GET /api/v1/namespaces HTTP/1.1\r\nHost: x\r\n\r\n"])
        return transport

    transport = asyncio.run(scenario())
    assert transport.written and transport.closed
    assert captured(events)["path"] == "/api/v1/namespaces"


def test_a_lying_content_length_does_not_silence_the_decoy(events, monkeypatch):
    """A real kube-apiserver answers. A slow-loris upload must not make this one mute."""
    monkeypatch.setattr(k8s, "BODY_WAIT_SECONDS", 0.05)

    async def scenario():
        request = b"POST /index.php HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\nonly-this"
        _proto, transport = await _feed([request])
        await asyncio.sleep(0.2)
        return transport

    transport = asyncio.run(scenario())
    assert transport.written, "the decoy went silent and identified itself as a decoy"
    assert captured(events)["body_len"] == len(b"only-this")


def test_an_unbounded_body_is_capped(monkeypatch, events):
    """A client that keeps writing must not be able to choose our memory budget."""
    monkeypatch.setattr(k8s, "MAX_REQUEST_BYTES", 4096)

    asyncio.run(_feed([_post(b"B" * 100000)]))

    assert len(bytes.fromhex(captured(events)["raw_hex"])) <= 4096


def test_a_chunked_body_is_waited_for(events):
    """One campaign actor on this surface used chunked encoding precisely because
    length-based inspection cannot follow it, so the Content-Length path is not enough."""
    chunked = b"POST /index.php HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
    body = b"10\r\n" + b"C" * 16 + b"\r\n0\r\n\r\n"

    async def scenario():
        proto, _transport = await _feed([chunked, body[:6]])
        mid = list(events)
        proto.data_received(body[6:])
        await asyncio.sleep(0)
        return mid

    mid = asyncio.run(scenario())
    assert mid == [], "answered before the terminating zero-length chunk"
    assert captured(events)["body_len"] == 16 + len(b"10\r\n\r\n0\r\n\r\n")


def test_every_listener_got_the_fix():
    """Five handlers had the same defect; a fix to one of them is not a fix."""
    for cls in (
        k8s.K8sApiHandler,
        k8s.KubeletApiHandler,
        k8s.EtcdApiHandler,
        k8s.DashboardHandler,
        k8s.KubectlProxyHandler,
    ):
        assert issubclass(cls, k8s._HttpRequestProtocol), cls.__name__
        assert cls.DISPATCH is not None, cls.__name__


def test_headers_that_never_complete_are_answered_on_a_deadline(events, monkeypatch):
    """Before the rewrite the handlers only ever dispatched on `\r\n\r\n`, so a client
    sending bare-LF headers — or simply stopping mid-header — parked the connection and
    got no answer at all. A real kube-apiserver answers."""
    monkeypatch.setattr(k8s, "BODY_WAIT_SECONDS", 0.05)

    async def scenario():
        _proto, transport = await _feed([b"GET /version HTTP/1.1\nHost: x\n\n"])
        await asyncio.sleep(0.2)
        return transport

    transport = asyncio.run(scenario())
    assert transport.written, "the decoy stayed silent and so identified itself"
