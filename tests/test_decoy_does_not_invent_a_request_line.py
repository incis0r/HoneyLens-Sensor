r"""A TLS handshake is recorded as one, not fabricated into a method and a path.

B2e. Measured 2026-11-04: 157 rows on `sensor-a` and 210 on `sensor-b` have a `raw_hex` beginning
`160301` -- a TLS record, almost always a ClientHello -- and a non-empty `metadata.path`.

`parse_http_request` decodes with `errors="replace"`, takes the first line, splits it on
spaces and returns `parts[0]` as the method and `parts[1]` as the path, with no check that
any of it is HTTP. Ciphertext containing a space therefore became a request line, and
`metadata.method` and `metadata.path` filled with replacement characters and binary. Those
rows are why the unlabelled-path table for the etcd decoy had garbage in it: the aggregation
was grouping on bytes the decoy made up.

The fix must not simply reject them. `_answer` dispatches only `if method and path`, so a
strict parser alone would mean *no event at all* for these connections -- 367 records of
someone speaking TLS to a cleartext port, deleted. That is the Phase A mistake in miniature
(binding sid 9026701 to nginx would have erased 1,040 rows of real h2c detection), so the
signal keeps its row and loses only the invention: the decoy records what arrived, says it
was not HTTP, and names TLS when the bytes say TLS.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.honeypots import honeypot_k8s as k8s

# A real ClientHello opening, taken from a `sensor-a` row's raw_hex: TLS record type 0x16,
# version 0x0301, then the handshake header and the client's own version 0x0303. The run of
# spaces is deliberate and is the whole mechanism -- a 0x20 byte in the ciphertext is what let
# the old parser split the "request line" into a method and a path.
TLS_CLIENT_HELLO = (
    bytes.fromhex("1603010100010000fc03031c3f91bb8ecb3e61cdc9affa50b6313f1bb4d3742e8bf1ebab")
    + b" " * 20
    + bytes.fromhex("0020")
)


class _Transport:
    def __init__(self, peer=("198.51.100.23", 44321)):
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
    collected: list[dict] = []
    monkeypatch.setattr(k8s, "append_line", lambda path, line: collected.append(json.loads(line)))
    return collected


def _drive(payload: bytes, handler_cls=k8s.EtcdApiHandler, port=2379):
    """Feed bytes and then force the deadline the real listener arms."""

    async def scenario():
        proto = handler_cls(port)
        transport = _Transport()
        proto.connection_made(transport)
        proto.data_received(payload)
        await asyncio.sleep(0)
        # TLS carries no \r\n\r\n, so the live decoy answers on BODY_WAIT_SECONDS.
        proto._answer()
        return transport

    return asyncio.run(scenario())


# ---------------------------------------------------------------------------
# The parser stops inventing
# ---------------------------------------------------------------------------


def test_a_tls_client_hello_is_not_a_request_line():
    method, path, _headers, _body = k8s.parse_http_request(TLS_CLIENT_HELLO)

    assert method is None, method
    assert path is None, path


@pytest.mark.parametrize(
    "first_line",
    [
        b"\x16\x03\x01\x01\x00\x01 \x00\xfc\x03\x03",
        b"\x00\x00\x00\x00 \x00\x00",
        b"\x05\x64 \x0b\x44\x01",
        b"garbage without a version",
        b"MiXeD /path HTTP/1.1",
    ],
)
def test_nothing_that_is_not_a_request_line_becomes_one(first_line):
    method, path, _h, _b = k8s.parse_http_request(first_line + b"\r\n\r\n")

    assert (method, path) == (None, None), (method, path)


@pytest.mark.parametrize(
    ("raw", "expect"),
    [
        (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", ("GET", "/")),
        (b"POST /v3/kv/put HTTP/1.1\r\nHost: x\r\n\r\n", ("POST", "/v3/kv/put")),
        (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", ("PRI", "*")),
        (b"OPTIONS sip:nm SIP/2.0\r\nHost: x\r\n\r\n", ("OPTIONS", "sip:nm")),
        (
            b"CONNECT proxy4.proxiesfood.com:443 HTTP/1.1\r\n\r\n",
            ("CONNECT", "proxy4.proxiesfood.com:443"),
        ),
        (b"GET /\r\n\r\n", ("GET", "/")),
    ],
)
def test_every_request_line_we_actually_see_still_parses(raw, expect):
    """Each of these is measured traffic on this fleet, the h2c preface and nmap's SIP probe
    included. `GET /` with no version is HTTP/0.9 shaped and scanners still send it."""
    method, path, _h, _b = k8s.parse_http_request(raw)

    assert (method, path) == expect


def test_a_bare_lf_request_still_parses():
    r"""Caught as a regression while writing this: `parse_http_request` splits only on `\r\n`,
    so a bare-LF request arrives as one long first "line". Validating that line as-is rejected
    a perfectly real request for holding control characters, the decoy answered nothing, and
    silence is itself how a honeypot gives itself away -- which is why
    `_HttpRequestProtocol` has a deadline at all."""
    method, path, _h, _b = k8s.parse_http_request(b"GET /version HTTP/1.1\nHost: x\n\n")

    assert (method, path) == ("GET", "/version")


# ---------------------------------------------------------------------------
# The connection is still recorded
# ---------------------------------------------------------------------------


def test_the_connection_is_still_recorded(events):
    """367 rows fleet-wide. Rejecting the bytes must not delete the evidence that they came."""
    _drive(TLS_CLIENT_HELLO)

    assert len(events) == 1, events


def test_the_record_says_it_was_not_http_and_names_tls(events):
    _drive(TLS_CLIENT_HELLO)
    ev = events[0]

    assert ev["event_type"] == "NON_HTTP_PAYLOAD"
    assert ev["wire_protocol"] == "tls"
    assert ev["dst_port"] == 2379


def test_the_record_invents_no_method_and_no_path(events):
    """The whole defect, stated as the thing that must not come back."""
    _drive(TLS_CLIENT_HELLO)
    ev = events[0]

    assert "path" not in ev, ev.get("path")
    assert "method" not in ev, ev.get("method")


def test_the_bytes_are_kept(events):
    _drive(TLS_CLIENT_HELLO)
    ev = events[0]

    assert bytes.fromhex(ev["raw_hex"]) == TLS_CLIENT_HELLO


def test_it_carries_a_payload_the_ingest_can_see(events):
    """The ingest's payload chain reads `payload`, `data`, `hex`, `raw`, `path`,
    `request_line` -- and `raw_hex` is in none of them. Without the decoy's own summary the
    row would store a NULL payload, `classify_event_row` would return early on it, and these
    rows would be unlabelled all over again."""
    _drive(TLS_CLIENT_HELLO)
    ev = events[0]

    assert ev.get("payload"), ev
    assert classify_event_row(payload=ev["payload"], protocol="http", metadata=ev)


def test_the_verdict_names_the_protocol_mismatch(events):
    _drive(TLS_CLIENT_HELLO)
    ev = events[0]

    hits = classify_event_row(payload=ev["payload"], protocol="http", metadata=ev)
    rules = {h[1] for h in hits}

    assert "tls_handshake_to_cleartext_port" in rules, rules


def test_the_connection_is_closed(events):
    transport = _drive(TLS_CLIENT_HELLO)

    assert transport.closed


def test_a_real_request_is_unaffected(events):
    """The etcd handler's own row, with its method and path, exactly as before."""
    _drive(b"GET /version HTTP/1.1\r\nHost: etcd\r\n\r\n")

    ev = events[0]
    assert ev["method"] == "GET"
    assert ev["path"] == "/version"
    assert "event_type" not in ev
