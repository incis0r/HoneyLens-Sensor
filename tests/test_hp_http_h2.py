"""The Apache decoy on :80 speaks HTTP/2 and records the connection — one event, no more.

The persona has advertised ``Server: Apache/2.4.66 (Ubuntu) mod_http2/2.0.32`` and
``Upgrade: h2,h2c`` for months while speaking only HTTP/1.1, so it hung up before any
client could send a HEADERS frame: 366 connections from 245 sources in 90 days, every one
answered with ``HTTP/1.1 200`` and a close. These tests drive the two entry paths — the
connection preface and the h2c ``Upgrade`` — through ``handle_connection``.

Three decisions are load-bearing here and each has its own test.

**One event per connection.** A 3456-stream flood writes exactly one row. The event store
holds ~5.1M rows under 30-day retention and a per-stream row would let one attacker own
the table.

**The decoy stays neutral.** It behaves like a patched httpd 2.4.71: it does not reflect
``Content-Length: []``, does not crash, does not stall, and does not implement the A/B
oracle the reference proof-of-concept uses to fingerprint a target. The version strings
are the only bait and the behaviour behind them is honest.

**The h2 path is off unless the operator switches it on**, per host, through the quadlet —
not through ``.env``.

The client side is the ``h2`` library itself, so the frames are the frames a real client
sends, and the response is read back with an ``h2`` client too: the body has to reach the
wire, not merely leave ``_answer`` without raising.
"""

from __future__ import annotations

import asyncio
import base64

import h2.config
import h2.connection
import h2.errors
import h2.events
import pytest

from honeylens.honeypots import cli, h2_capture, hp_http, manifest

PEER = ("203.0.113.9", 40000)


# --------------------------------------------------------------------------- fakes


class _Writer:
    """A peer that keeps everything written to it. ``FakeWriter`` calls that ``sent``."""

    def __init__(self) -> None:
        self.written = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        pass

    def get_extra_info(self, key, default=None):
        return PEER if key == "peername" else default

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


class _Reader:
    """Hands out ``data`` and then returns EOF, like a client that closed."""

    def __init__(self, data: bytes) -> None:
        self._buf = bytearray(data)

    async def read(self, n: int) -> bytes:
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk


class _SilentReader:
    """Hands out ``data`` and then goes quiet until someone cancels us."""

    def __init__(self, data: bytes) -> None:
        self._buf = bytearray(data)

    async def read(self, n: int) -> bytes:
        if self._buf:
            chunk = bytes(self._buf[:n])
            del self._buf[:n]
            return chunk
        await asyncio.Event().wait()
        return b""  # pragma: no cover — never reached


def _raiser(*_args, **_kwargs):
    raise RuntimeError("the h2 path is broken")


# ------------------------------------------------------------------- client bytes


def _req(path: str = "/", method: str = "GET", extra_headers=None, reset: bool = False):
    """One request: the 119618 shape (Content-Type present, no body) unless overridden."""
    headers = {"content-type": "text/plain"}
    headers.update(extra_headers or {})
    return (method, path, headers, reset)


def _shaped_req(path: str = "/"):
    """A request with exactly the CVE-2026-119618 header shape, not cancelled.

    END_STREAM on HEADERS, Content-Type present, Content-Length absent — the shape the
    reference proof-of-concept sends to make a vulnerable 2.4.70 reflect ``[]``.
    """
    return _req(path)


def _n_requests_each_reset(count: int):
    """``count`` requests, each cancelled straight after its HEADERS frame."""
    return [_req(f"/{i}", reset=True) for i in range(count)]


def _h2c_upgrade_bytes(path: str) -> bytes:
    """A real h2c client in one buffer: the ``Upgrade`` request, then what follows the 101.

    A client that upgrades pipelines its connection preface and its first HTTP/2 request
    straight behind the HTTP/1.1 headers, which is why the decoy's first ``read`` holds
    both and the bytes after ``\\r\\n\\r\\n`` have to reach the observer.
    """
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    settings = client.initiate_upgrade_connection()
    assert settings is not None
    client.send_headers(
        3,
        [
            (":method", "GET"),
            (":path", path),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            ("content-type", "text/plain"),
        ],
        end_stream=True,
    )
    return (
        b"GET /index.html HTTP/1.1\r\nHost: decoy.invalid\r\nUpgrade: h2c\r\n"
        b"HTTP2-Settings: " + settings + b"\r\nConnection: Upgrade, HTTP2-Settings\r\n\r\n"
    ) + client.data_to_send()


def _client_bytes(requests) -> bytes:
    """What an ``h2`` client puts on the wire for ``requests``, preface included."""
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    stream_id = 1
    for method, path, extra, reset in requests:
        client.send_headers(
            stream_id,
            [
                (":method", method),
                (":path", path),
                (":scheme", "http"),
                (":authority", "decoy.invalid"),
                *extra.items(),
            ],
            end_stream=True,
        )
        if reset:
            client.reset_stream(stream_id, error_code=h2.errors.ErrorCodes.CANCEL)
        stream_id += 2
    return client.data_to_send()


# ------------------------------------------------------------------ reading it back


def _h2_client_view(written: bytes) -> tuple[dict[str, str], bytes]:
    """Decode what the decoy wrote with a real ``h2`` client: stream 1's headers and body.

    Going through the library is the point: it is the only way to say the body reached the
    wire rather than being lost inside ``_answer``, whose failures are swallowed at debug
    level.
    """
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.send_headers(
        1,
        [(":method", "GET"), (":path", "/"), (":scheme", "http"), (":authority", "decoy.invalid")],
        end_stream=True,
    )
    client.data_to_send()
    headers: dict[str, str] = {}
    body = bytearray()
    for event in client.receive_data(bytes(written)):
        if isinstance(event, h2.events.ResponseReceived) and event.stream_id == 1:
            headers = {
                n.decode("utf-8", "replace"): v.decode("utf-8", "replace") for n, v in event.headers
            }
        elif isinstance(event, h2.events.DataReceived) and event.stream_id == 1:
            body += event.data
    return headers, bytes(body)


def _h2_streams_view(written: bytes, stream_ids=(1, 3)) -> dict[int, tuple[dict[str, str], bytes]]:
    """Per-stream ``(headers, body)`` for a connection that used more than one stream.

    ``_h2_client_view`` only reads stream 1, which cannot tell "served the page here and
    refused there" from "refused everywhere" — the distinction a mixed connection turns on.
    """
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    for stream_id in stream_ids:
        client.send_headers(
            stream_id,
            [
                (":method", "GET"),
                (":path", "/"),
                (":scheme", "http"),
                (":authority", "decoy.invalid"),
            ],
            end_stream=True,
        )
    client.data_to_send()
    out: dict[int, tuple[dict[str, str], bytes]] = {}
    for event in client.receive_data(bytes(written)):
        if isinstance(event, h2.events.ResponseReceived):
            decoded = {
                n.decode("utf-8", "replace"): v.decode("utf-8", "replace") for n, v in event.headers
            }
            out[event.stream_id] = (decoded, out.get(event.stream_id, ({}, b""))[1])
        elif isinstance(event, h2.events.DataReceived):
            seen_headers, seen_body = out.get(event.stream_id, ({}, b""))
            out[event.stream_id] = (seen_headers, seen_body + event.data)
    return out


def _decode_h2_response(written: bytes) -> bytes:
    """The body the decoy actually served on stream 1."""
    return _h2_client_view(written)[1]


def _reflected_content_length(written: bytes) -> str | None:
    """The ``content-length`` the decoy put on stream 1's response, if any.

    A vulnerable 2.4.70 shows the race here, as a reflected ``Content-Length: []``. We
    send no ``content-length`` at all on an HTTP/2 response — END_STREAM delimits the body
    and RFC 9113 does not require the header — so there is nothing to reflect and nothing
    for the proof-of-concept's oracle to read.
    """
    return _h2_client_view(written)[0].get("content-length")


# ------------------------------------------------------------------------ drivers


def _drive(monkeypatch, raw: bytes, *, cancel_after: float | None = None, reader=None):
    """Run one connection through the decoy; return (events written, the peer's writer)."""
    seen: list[dict] = []
    monkeypatch.setattr(
        hp_http,
        "log_event",
        lambda *a, **kw: seen.append({"data": a[2], **kw}) or {},
    )
    hp = hp_http.HTTPHoneypot()
    writer = _Writer()
    if cancel_after is None:
        asyncio.run(hp.handle_connection(reader or _Reader(raw), writer, PEER))
        return seen, writer

    async def run() -> None:
        task = asyncio.create_task(hp.handle_connection(_SilentReader(raw), writer, PEER))
        await asyncio.sleep(cancel_after)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    return seen, writer


def _run(monkeypatch, raw: bytes) -> list[dict]:
    """Today's decoy: the h2 flag untouched."""
    return _drive(monkeypatch, raw)[0]


def _run_h2(monkeypatch, raw: bytes, cancel_after: float | None = None) -> list[dict]:
    monkeypatch.setenv("HONEYLENS_H2_CAPTURE", "true")
    return _drive(monkeypatch, raw, cancel_after=cancel_after)[0]


def _run_h2_writer(monkeypatch, raw: bytes) -> _Writer:
    monkeypatch.setenv("HONEYLENS_H2_CAPTURE", "true")
    return _drive(monkeypatch, raw)[1]


def _run_upgrade(monkeypatch, raw: bytes) -> _Writer:
    monkeypatch.setenv("HONEYLENS_H2_CAPTURE", "true")
    return _drive(monkeypatch, raw)[1]


def _run_h2_both(monkeypatch, raw: bytes, *, reader=None):
    monkeypatch.setenv("HONEYLENS_H2_CAPTURE", "true")
    return _drive(monkeypatch, raw, reader=reader)


def _drive_with_writer(monkeypatch, raw: bytes, writer) -> list[dict]:
    """Drive one h2 connection against a caller-supplied peer, e.g. one that stops reading."""
    monkeypatch.setenv("HONEYLENS_H2_CAPTURE", "true")
    seen: list[dict] = []
    monkeypatch.setattr(
        hp_http, "log_event", lambda *a, **kw: seen.append({"data": a[2], **kw}) or {}
    )
    asyncio.run(hp_http.HTTPHoneypot().handle_connection(_Reader(raw), writer, PEER))
    return seen


class _SplitReader:
    """Hands ``data`` over in two segments, splitting at ``at``, then EOF."""

    def __init__(self, data: bytes, at: int) -> None:
        self._parts = [data[:at], data[at:]]

    async def read(self, n: int) -> bytes:
        while self._parts:
            part = self._parts.pop(0)
            if part:
                return part
        return b""


def _quadlet_for(name: str) -> str:
    return cli.quadlet(
        manifest.get(name),
        state_dir="/var/lib/honeylens",
        image_tag="1.0.0",
        registry="localhost",
    )


# -------------------------------------------------------------------------- tests


def test_a_preface_connection_writes_one_event_with_the_h2_shape(monkeypatch):
    seen = _run_h2(monkeypatch, _client_bytes(_n_requests_each_reset(3456)))
    assert len(seen) == 1
    event = seen[0]["data"] if "data" in seen[0] else seen[0]
    assert event["event_type"] == "H2_CONNECTION" and event["http_version"] == "2"
    assert event["h2_entry"] == "preface"


def test_the_event_sets_payload_explicitly_and_it_names_one_stream(monkeypatch):
    seen = _run_h2(monkeypatch, _client_bytes([_req("/a"), _req("/etc/passwd")]))
    payload = seen[0]["data"]["payload"]
    assert "/a" in payload  # the first stream
    assert "/etc/passwd" not in payload  # never a second stream's text
    assert len(payload) < 500


def test_an_upgrade_request_gets_a_101_and_is_observed(monkeypatch):
    seen, writer = _run_h2_both(
        monkeypatch,
        b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\n"
        b"HTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n"
        b"Connection: Upgrade, HTTP2-Settings\r\n\r\n",
    )
    assert b"101 Switching Protocols" in writer.written
    assert b"Upgrade: h2c" in writer.written
    # "...and is observed": the name promised an observation and the body used to check
    # only the two bytes above, so the test passed with no event written at all.
    assert len(seen) == 1
    assert seen[0]["data"]["event_type"] == "H2_CONNECTION"
    assert seen[0]["data"]["h2_entry"] == "upgrade"


def test_an_upgrade_observes_the_bytes_the_client_pipelined_behind_it(monkeypatch):
    # Not in the brief; found by inspection and fixed. The upgrade request and the HTTP/2
    # preface arrive in the SAME read, so the bytes after the request headers are the
    # client's preface and its first stream. Handing the observer nothing left every h2c
    # connection recorded as streams=0, bytes_in=0 — a row that says the decoy saw an
    # upgrade and nothing else, on exactly the connections this path exists for.
    seen = _run_h2(monkeypatch, _h2c_upgrade_bytes("/wp-login.php"))
    assert len(seen) == 1
    event = seen[0]["data"]
    assert event["h2_entry"] == "upgrade" and event["h2_error"] is None
    assert event["streams_opened"] == 1 and event["bytes_in"] > 0
    assert event["path"] == "/wp-login.php" and event["fields_from_stream"] == 3


_H2C_HEADERS = (
    b"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n"
    b"Connection: Upgrade, HTTP2-Settings\r\n"
)


def test_an_attack_on_the_upgrade_request_earns_the_verdict_it_earns_over_http_1_1(monkeypatch):
    # The upgrade request is evidence, not a handshake token. RFC 7540 makes it stream 1 of
    # the h2 connection, but its headers arrived over HTTP/1.1 and `h2` never sees them —
    # so without classifying it here, adding two headers to any HTTP/1.1 attack would make
    # it invisible. Attacker input does not gate our analysis.
    attack = b"GET /etc/passwd?x=1 HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n"
    plain = _run(monkeypatch, attack + b"\r\n")
    assert plain[0]["attack_type"] == "lfi" and plain[0]["severity"] == "HIGH"

    seen = _run_h2(monkeypatch, attack + _H2C_HEADERS + b"\r\n")
    assert len(seen) == 1
    event = seen[0]["data"]
    assert event["event_type"] == "H2_CONNECTION" and event["h2_entry"] == "upgrade"
    # The same verdict, at the same severity, merged into the connection's list.
    assert "lfi" in event["h2_verdicts"] and "lfi" in (seen[0]["attack_type"] or "")
    assert seen[0]["severity"] == "HIGH"
    # Its own key, so a reader cannot mistake it for a decoded HTTP/2 stream.
    assert event["upgrade_request"]["path"] == "/etc/passwd?x=1"
    assert event["upgrade_request"]["query_string"] == "x=1"
    assert event["upgrade_request"]["user_agent"] == "curl/8"
    # Nothing decoded in HTTP/2, so the convenience fields say what it asked for anyway.
    assert event["streams_opened"] == 0 and event["fields_from_upgrade_request"] is True
    assert event["path"] == "/etc/passwd?x=1" and "/etc/passwd" in event["payload"]


def test_the_frames_behind_the_upgrade_are_not_read_as_request_text(monkeypatch):
    # There is no request body on this path. What `_parse_request` calls the body is the
    # HTTP/2 preface and the frames pipelined behind it — the same bytes handed to the
    # observer as `prefix`. Classifying them as request text would double-count any verdict
    # `decide()` already earns per stream, and a text rule over binary HPACK can manufacture
    # one out of noise. Both frames below are valid SETTINGS whose identifiers h2 must
    # ignore, and their payload bytes spell request text: "/etc/passwd\0" invents `lfi`
    # where nothing asked for a file, and "login=a&pwd=b" invents a username and a
    # password nobody sent.
    lfi_frame = b"\x00\x00\x0c\x04\x00\x00\x00\x00\x00" + b"/etc/passwd\x00"
    creds_frame = b"\x00\x00\x12\x04\x00\x00\x00\x00\x00" + b"login=a&pwd=b" + b"\x00" * 5
    frames = h2_capture.PREFACE + lfi_frame + creds_frame
    seen = _run_h2(monkeypatch, b"GET / HTTP/1.1\r\nHost: x\r\n" + _H2C_HEADERS + b"\r\n" + frames)
    event = seen[0]["data"]
    assert event["bytes_in"] == len(frames)  # they WERE observed, as frames
    assert event["upgrade_request"]["verdicts"] == ["h2c_upgrade_recon"]
    assert "lfi" not in event["h2_verdicts"]
    assert "passwd" not in event["payload"]
    assert "credentials" not in event and "credentials" not in event["upgrade_request"]


def test_credentials_on_the_upgrade_request_are_captured(monkeypatch):
    # `_extract_credentials` runs on this request exactly as on an HTTP/1.1 one; a password
    # must not be lost because the client also asked to be upgraded.
    seen = _run_h2(
        monkeypatch,
        b"GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n"
        + _H2C_HEADERS
        + b"\r\n",
    )
    creds = seen[0]["data"]["upgrade_request"]["credentials"]
    assert creds == {"username": "admin", "password": "hunter2", "source": "basic_auth"}
    assert seen[0]["data"]["credentials"] == creds


def test_an_upgrade_without_settings_is_not_upgraded(monkeypatch):
    writer = _run_upgrade(monkeypatch, b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\n\r\n")
    assert b"101" not in writer.written and b"200 OK" in writer.written


def test_a_preface_then_silence_still_writes_one_event(monkeypatch):
    seen = _run_h2(monkeypatch, h2_capture.PREFACE, cancel_after=0.01)
    assert len(seen) == 1 and seen[0]["data"]["streams_opened"] == 0


def test_the_h2_path_is_off_unless_enabled(monkeypatch):
    monkeypatch.delenv("HONEYLENS_H2_CAPTURE", raising=False)
    seen = _run(monkeypatch, h2_capture.PREFACE)
    assert seen[0]["data"].get("event_type") != "H2_CONNECTION"
    assert seen[0]["data"]["method"] == "PRI"  # today's behaviour, unchanged


def test_an_exploding_h2_path_still_serves_http_1_1(monkeypatch):
    monkeypatch.setattr(h2_capture, "observe", _raiser)
    writer = _run_h2_writer(monkeypatch, h2_capture.PREFACE)
    assert b"HTTP/1.1 200" in writer.written


def test_a_shaped_stream_is_answered_like_a_patched_server(monkeypatch):
    # The operator's decision, 2026-11-12: the decoy stays neutral. A 2.4.70 reflects
    # Content-Length: [] on this stream; a patched 2.4.71 answers it ordinarily. We are
    # the patched one, and the Server header is the only bait.
    seen, writer = _run_h2_both(monkeypatch, _client_bytes([_shaped_req("/")]))
    body = _decode_h2_response(writer.written)
    assert b"It works!" in body
    assert _reflected_content_length(writer.written) is None
    # The stream we sent really does carry the shape, or this test would keep passing if
    # `_shaped_req` quietly stopped being shaped and the neutrality claim would be empty.
    assert seen[0]["data"]["shape_matches"] >= 1


def _host_headers(host: str, *, as_authority: bool, path: str = "/") -> list[tuple[str, str]]:
    """One stream's headers, claiming ``host`` in one of its two legal HTTP/2 spellings.

    RFC 9113 §8.3.1 permits the ``host`` header when ``:authority`` is absent, ``h2``
    accepts such a stream, and a real Apache honours it.
    """
    headers = [(":method", "GET"), (":path", path), (":scheme", "http")]
    if as_authority:
        headers.append((":authority", host))
    headers.append(("content-type", "text/plain"))
    if not as_authority:
        headers.append(("host", host))
    return headers


def _authority_request(authority: str, path: str = "/", *, as_authority: bool = True) -> bytes:
    """A preface connection whose one stream asks under ``authority``."""
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.send_headers(
        1, _host_headers(authority, as_authority=as_authority, path=path), end_stream=True
    )
    return client.data_to_send()


def _upgrade_then_stream(host: str, *, as_authority: bool, own_host: str = "ours") -> bytes:
    """An h2c upgrade under ``own_host``, then one stream on 3 claiming ``host``."""
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    settings = client.initiate_upgrade_connection()
    assert settings is not None
    client.send_headers(3, _host_headers(host, as_authority=as_authority), end_stream=True)
    return (
        b"GET / HTTP/1.1\r\nHost: " + own_host.encode() + b"\r\nUpgrade: h2c\r\n"
        b"HTTP2-Settings: " + settings + b"\r\nConnection: Upgrade, HTTP2-Settings\r\n\r\n"
    ) + client.data_to_send()


def test_a_foreign_host_is_refused_and_never_upgraded_or_observed(monkeypatch):
    # `shell_bait.py`: the foreign-host split "is not a nicety. It is what makes the bait
    # safe to run at all" — answering 200 with content under a domain that is not ours
    # manufactures evidence that THEIR site is compromised. Both h2 branches used to return
    # before `shell_bait.decide`, so `Upgrade: h2c` + `HTTP2-Settings` bought the full
    # Apache page where the same request without them got a 421. Two attacker-controlled
    # headers must not switch a safety guard off.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    request = b"GET /images.php HTTP/1.1\r\nHost: victim.example\r\n"

    plain, plain_writer = _run_h2_both(monkeypatch, request + b"\r\n")
    assert b"421 Misdirected Request" in plain_writer.written
    assert plain[0]["data"]["response_mode"] == "misdirected"

    seen, writer = _run_h2_both(monkeypatch, request + _H2C_HEADERS + b"\r\n")
    assert b"421 Misdirected Request" in writer.written
    assert b"101" not in writer.written  # not upgraded ...
    assert len(seen) == 1
    assert seen[0]["data"].get("event_type") != "H2_CONNECTION"  # ... and not observed
    assert seen[0]["data"]["response_mode"] == "misdirected"


def test_a_foreign_authority_on_an_h2_stream_is_refused_without_content(monkeypatch):
    # HTTP/2 carries the host per request, in `:authority`, so there is no HTTP/1.1 Host to
    # judge a bare preface connection by and the guard has to run per stream. Measured
    # before the fix: `:authority victim.example` was served `:status 200` and the page.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    seen, writer = _run_h2_both(monkeypatch, _authority_request("victim.example"))
    headers, body = _h2_client_view(writer.written)
    assert headers[":status"] == "421"
    assert body == b""
    assert b"It works!" not in writer.written  # not anywhere on the wire, not even once
    # Still recorded, and the row says what was served. A preface connection has no
    # HTTP/1.1 Host, so this mode can only come from the per-stream decision.
    assert seen[0]["data"]["event_type"] == "H2_CONNECTION"
    assert seen[0]["data"]["streams_opened"] == 1
    assert seen[0]["data"]["response_mode"] == "misdirected"

    # ... and our own name still gets the persona, or the guard would be a kill switch.
    _, ours = _run_h2_both(monkeypatch, _authority_request("decoy.invalid"))
    assert b"It works!" in _decode_h2_response(ours.written)


def test_the_bait_reply_survives_the_upgrade_and_the_row_says_so(monkeypatch):
    # The other `shell_bait` mode. A shell probe is answered with an empty 200 — what a
    # planted shell returns to a bare GET, no banner to fingerprint — and the bait is only
    # worth running if a follow-up request can be tied to the reply that caused it. Serving
    # the full Apache page over HTTP/2 instead, and dropping `response_mode` from the row,
    # would lose both halves of that.
    monkeypatch.setenv("HP_HTTP_SHELL_BAIT", "1")
    seen, writer = _run_h2_both(
        monkeypatch, b"GET /shell.php HTTP/1.1\r\nHost: x\r\n" + _H2C_HEADERS + b"\r\n"
    )
    assert b"101 Switching Protocols" in writer.written
    event = seen[0]["data"]
    assert event["event_type"] == "H2_CONNECTION"
    assert event["response_mode"] == "bait"
    assert b"It works!" not in writer.written  # the bait answers without content


def test_a_foreign_host_header_without_an_authority_is_refused_too(monkeypatch):
    # The second bypass of this one guard, and the same safety property as the first: the
    # guard read `:authority` only, and RFC 9113 §8.3.1 lets a client carry the host in a
    # `host` header when `:authority` is absent. h2 accepts such a stream (only a
    # `:authority`/`host` *disagreement* is a ProtocolError) and a real Apache honours it.
    # Measured before the fix, on BOTH entry paths: `:status 200`, `x-powered-by`, and the
    # full Apache page — bought with one attacker-controlled header choice instead of two.
    # See `shell_bait.host_claims` for the full set of spellings a host can arrive in.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")

    seen, writer = _run_h2_both(
        monkeypatch, _authority_request("victim.example", as_authority=False)
    )
    headers, body = _h2_client_view(writer.written)
    assert headers[":status"] == "421" and body == b""
    assert "x-powered-by" not in headers
    assert b"It works!" not in writer.written
    assert seen[0]["data"]["response_mode"] == "misdirected"
    # ... and the host the attacker claimed is on the row, not only in streams[0].headers.
    assert seen[0]["data"]["host"] == "victim.example"

    # The upgrade path reaches the same stream through different plumbing: the HTTP/1.1
    # Host is ours, so the 101 is granted, and stream 3 claims the foreign name instead.
    seen, writer = _run_h2_both(
        monkeypatch, _upgrade_then_stream("victim.example", as_authority=False)
    )
    streams = _h2_streams_view(writer.written[writer.written.index(b"\r\n\r\n") + 4 :])
    assert streams[3][0][":status"] == "421" and streams[3][1] == b""
    # Stream 1 — the upgraded request, under our own name — did get the page, and the row
    # has to say so as well as saying it refused stream 3.
    assert seen[0]["data"]["response_mode"] == "page,misdirected"
    assert seen[0]["data"]["host"] == "victim.example"


@pytest.mark.parametrize(
    ("target", "claimed"),
    [
        (b"http://victim.example/", "victim.example"),  # absolute-form, RFC 9112 §3.2.2
        (b"//victim.example/", "victim.example"),  # network-path-relative, RFC 3986 §4.2
        (b"victim.example:80", "victim.example:80"),  # authority-form, port kept verbatim
    ],
)
def test_a_foreign_host_in_the_request_target_is_refused(monkeypatch, target, claimed):
    # The fourth spelling of a host claim. RFC 9112 §3.2.2 has a server ignore `Host` in
    # favour of an absolute-form target's authority; we refuse on *either*, which is
    # stricter than that rule and stricter than httpd (whose `ap_parse_uri` takes the host
    # from the target only for a matching scheme or CONNECT, and does not resolve
    # `//host/path` at all). Reading `Host` alone meant `Host: decoy.invalid` laundered a
    # foreign name — measured, the full page over HTTP/1.1 and the 101 plus the page on
    # stream 1 over h2c.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    request = b"GET " + target + b" HTTP/1.1\r\nHost: decoy.invalid\r\n"

    plain, plain_writer = _run_h2_both(monkeypatch, request + b"\r\n")
    assert b"421 Misdirected Request" in plain_writer.written
    assert plain[0]["data"]["response_mode"] == "misdirected"
    # `host` is the claim we refused for, not whichever header happened to be last read:
    # it said `decoy.invalid` while the foreign name appeared nowhere, so no host-based
    # hunt could find the event. Recorded verbatim, port and all — `is_foreign_host`
    # normalises when deciding, the row keeps what was sent.
    assert plain[0]["data"]["host"] == claimed
    assert plain[0]["data"]["request_target_host"] == claimed

    seen, writer = _run_h2_both(monkeypatch, request + _H2C_HEADERS + b"\r\n")
    assert b"101" not in writer.written  # never upgraded ...
    assert b"421 Misdirected Request" in writer.written
    assert b"It works!" not in writer.written  # ... and never served, on either protocol
    assert seen[0]["data"].get("event_type") != "H2_CONNECTION"


@pytest.mark.parametrize(
    "target",
    [
        b"//images.php",  # a legal origin-form path with an empty first segment
        b"//x",
        b"//x/images.php",
        b"foo",  # neither a path nor a URI
        b"decoy.invalid:80",  # an authority-form naming our OWN host
    ],
)
def test_a_pseudo_authority_cannot_launder_a_foreign_host(monkeypatch, target):
    # The regression a precedence rule bought: reading the request-target "first, then
    # `Host`" means anything the parser calls an authority REPLACES the Host header, so
    # `GET //images.php` with a foreign `Host` stopped being refused — and with the bait on
    # it answered the empty 200 that tells a sweep the shell is here, under a stranger's
    # name. `//images.php` plus one slash is among the commonest shapes in shell-sweep
    # traffic. `host_claims` unions instead of replacing, so a claim that is sometimes a
    # path segment can only ADD refusals.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    monkeypatch.setenv("HP_HTTP_SHELL_BAIT", "true")
    request = b"GET " + target + b" HTTP/1.1\r\nHost: victim.example\r\n"

    plain, plain_writer = _run_h2_both(monkeypatch, request + b"\r\n")
    assert b"421 Misdirected Request" in plain_writer.written
    assert b"200 OK" not in plain_writer.written  # neither the page nor the bait
    assert plain[0]["data"]["response_mode"] == "misdirected"
    assert plain[0]["data"]["host"] == "victim.example"

    seen, writer = _run_h2_both(monkeypatch, request + _H2C_HEADERS + b"\r\n")
    assert b"101" not in writer.written
    assert seen[0]["data"].get("event_type") != "H2_CONNECTION"


@pytest.mark.parametrize("ows", [b"", b" ", b"\t", b"  ", b" \t "])
def test_a_foreign_host_sent_without_a_space_after_the_colon_is_refused(monkeypatch, ows):
    # RFC 9112 §5 is `field-line = field-name ":" OWS field-value OWS` and OWS may be
    # EMPTY. `Host:victim.example` is legal, httpd accepts it, and it is exactly what a
    # hand-rolled `printf 'GET / HTTP/1.1\r\nHost:x\r\n\r\n'` scanner sends. The parser
    # required `": "`, so the claim list handed to the resolver was empty and a correct
    # union refused nothing — the parser is the upstream gate, before any guard.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    monkeypatch.setenv("HP_HTTP_SHELL_BAIT", "true")
    seen, writer = _run_h2_both(
        monkeypatch, b"GET /images.php HTTP/1.1\r\nHost:" + ows + b"victim.example\r\n\r\n"
    )
    assert b"421 Misdirected Request" in writer.written
    assert b"200 OK" not in writer.written  # not the page, and not the bait's empty 200
    assert seen[0]["data"]["response_mode"] == "misdirected"
    assert seen[0]["data"]["host"] == "victim.example"


def test_credentials_sent_without_a_space_after_the_colon_are_captured(monkeypatch):
    # The half that costs evidence rather than safety. A header line without `": "` was
    # skipped entirely, so an `Authorization:Basic …` from any such client has been absent
    # from every HTTP/1.1 row this decoy ever wrote — a password we were handed and
    # dropped, and no backfill can recover it.
    seen = _run(
        monkeypatch,
        b"GET /admin HTTP/1.1\r\nHost:decoy.invalid\r\n"
        b"Authorization:Basic YWRtaW46aHVudGVyMg==\r\n\r\n",
    )
    assert seen[0]["data"]["credentials"] == {
        "username": "admin",
        "password": "hunter2",
        "source": "basic_auth",
    }


def test_a_content_type_without_a_space_after_the_colon_reaches_the_row(monkeypatch):
    # Same loss, the other fields: the whole header map was empty for such a client, so
    # `content_type`, `user_agent` and everything a rule reads from `headers` were absent.
    seen = _run(
        monkeypatch,
        b"POST /upload HTTP/1.1\r\nHost:decoy.invalid\r\n"
        b"Content-Type:application/x-www-form-urlencoded\r\n"
        b"User-Agent:sweeper/1.0\r\nContent-Length:11\r\n\r\nuser=admin!",
    )
    event = seen[0]["data"]
    assert event["content_type"] == "application/x-www-form-urlencoded"
    assert event["user_agent"] == "sweeper/1.0"
    assert event["headers"]["content-type"] == "application/x-www-form-urlencoded"
    assert event["headers"]["content-length"] == "11"


@pytest.mark.parametrize(
    ("label", "headers"),
    [
        ("obs-fold with SP", b"Host:\r\n victim.example\r\n"),
        ("obs-fold with HTAB", b"Host:\r\n\tvictim.example\r\n"),
        ("duplicate Host, foreign first", b"Host: victim.example\r\nHost: decoy.invalid\r\n"),
        ("duplicate Host, foreign last", b"Host: decoy.invalid\r\nHost: victim.example\r\n"),
    ],
)
def test_two_more_host_spellings_cannot_launder_a_foreign_name(monkeypatch, label, headers):
    # Both were parked on a rationale that was withdrawn: no 400 is needed, because the
    # union of claims settles them and `_parse_request` was throwing a claim away before
    # the union could see it. Last-wins dropped the FIRST `Host` value, and a continuation
    # line was skipped entirely so a folded `Host` produced an EMPTY claim list. Measured:
    # both served the full page, and both granted the 101 on the same parse.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    request = b"GET / HTTP/1.1\r\n" + headers

    plain, writer = _run_h2_both(monkeypatch, request + b"\r\n")
    assert b"421 Misdirected Request" in writer.written, label
    assert plain[0]["data"]["response_mode"] == "misdirected", label
    assert plain[0]["data"]["host"] == "victim.example", label

    upgraded, up_writer = _run_h2_both(monkeypatch, request + _H2C_HEADERS + b"\r\n")
    assert b"101" not in up_writer.written, label
    assert upgraded[0]["data"].get("event_type") != "H2_CONNECTION", label


@pytest.mark.parametrize(
    ("label", "headers"),
    [
        ("folded, ours", b"Host:\r\n decoy.invalid\r\n"),
        ("duplicated, both ours", b"Host: decoy.invalid\r\nHost: also.ours\r\n"),
    ],
)
def test_the_same_two_spellings_under_our_own_name_are_still_served(monkeypatch, label, headers):
    # The control direction. A folded or repeated `Host` naming nobody foreign must still
    # get the page, or the fix is a blanket refusal rather than a guard.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    seen, writer = _run_h2_both(monkeypatch, b"GET / HTTP/1.1\r\n" + headers + b"\r\n")
    assert b"HTTP/1.1 200 OK" in writer.written, label
    assert b"It works!" in writer.written, label
    assert "response_mode" not in seen[0]["data"], label


def test_a_space_before_the_colon_is_still_a_host_claim(monkeypatch):
    # The tenth instance of the same class, and this test was half of why it survived: it
    # pinned the odd key with OUR OWN host as its only input, so the matrix locked the
    # vector in with no foreign-name control — the one thing the rest of the host-claim work
    # was careful to add. Measured before: `Host : victim.example` served the full Apache
    # page under a stranger's domain and granted the 101 on the same parse, because the
    # parser decides which spellings exist and the claim set came back empty.
    #
    # No 400 is needed, exactly as with obs-fold: a header whose STRIPPED name is `host` is
    # a `Host` claim. RFC 9112 §5.1 would have us reject the request; we refuse to answer
    # for the name instead, which is the thing that matters here.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")

    seen, writer = _run_h2_both(monkeypatch, b"GET / HTTP/1.1\r\nHost : victim.example\r\n\r\n")
    assert b"421 Misdirected Request" in writer.written
    assert seen[0]["data"]["response_mode"] == "misdirected"
    assert seen[0]["data"]["host"] == "victim.example"
    # The odd key survives verbatim on the row: it is evidence of how the request was
    # built, and only the CLAIM is read from the stripped name.
    assert seen[0]["data"]["headers"]["host "] == "victim.example"
    assert "host" not in seen[0]["data"]["headers"]

    # ... the h2c path grants nothing on that parse either ...
    _, upgraded = _run_h2_both(
        monkeypatch, b"GET / HTTP/1.1\r\nHost : victim.example\r\n" + _H2C_HEADERS + b"\r\n"
    )
    assert b"101" not in upgraded.written
    assert b"It works!" not in upgraded.written

    # ... and the control direction, which is what the vector hid behind: our own name in
    # the same odd spelling is still served.
    ours, ours_writer = _run_h2_both(monkeypatch, b"GET / HTTP/1.1\r\nHost : decoy.invalid\r\n\r\n")
    assert b"HTTP/1.1 200 OK" in ours_writer.written
    assert b"It works!" in ours_writer.written
    assert "response_mode" not in ours[0]["data"]
    assert ours[0]["data"]["headers"]["host "] == "decoy.invalid"


def test_a_folded_host_with_a_space_before_the_colon_is_a_claim_too(monkeypatch):
    # The two odd spellings together, because the fold branch compares the field-name as
    # well and would have missed a `"host "` key.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    seen, writer = _run_h2_both(monkeypatch, b"GET / HTTP/1.1\r\nHost :\r\n victim.example\r\n\r\n")
    assert b"421 Misdirected Request" in writer.written
    assert seen[0]["data"]["host"] == "victim.example"


def test_a_credential_is_attributed_to_the_stream_that_sent_it(monkeypatch):
    # Two independent `setdefault` calls let the second land when the first was a no-op, so
    # an upgrade request's Basic credential was recorded with `credentials_from_stream: 3`
    # while stream 3's own `login=…&pwd=…` never reached the field. The row named a stream
    # as the source of something it did not send — the misattribution class `_h2_payload`
    # cites the 61-verdict lesson for, two screens above where it reappeared.
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    settings = client.initiate_upgrade_connection()
    assert settings is not None
    stream_body = b"login=streamuser&pwd=streampass"
    client.send_headers(
        3,
        [
            (":method", "POST"),
            (":path", "/p"),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(stream_body))),
        ],
    )
    client.send_data(3, stream_body, end_stream=True)
    upgrade_basic = base64.b64encode(b"upgradeuser:upgradepass")
    seen, _ = _run_h2_both(
        monkeypatch,
        b"GET / HTTP/1.1\r\nHost: decoy.invalid\r\nUpgrade: h2c\r\n"
        b"HTTP2-Settings: " + settings + b"\r\n"
        b"Authorization: Basic " + upgrade_basic + b"\r\n"
        b"Connection: Upgrade, HTTP2-Settings\r\n\r\n" + client.data_to_send(),
    )
    event = seen[0]["data"]
    # The upgrade request's credential wins, because it is read first and a row carries one
    # `credentials` field — but then NOTHING claims a stream supplied it.
    assert event["credentials"]["username"] == "upgradeuser"
    assert "credentials_from_stream" not in event
    # The stream's own body is still on the record, so the second pair is not lost.
    assert event["streams"][0]["body"] == stream_body.decode()

    # With no upgrade credential in the way, the stream's pair is captured AND named.
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.send_headers(
        1,
        [
            (":method", "POST"),
            (":path", "/p"),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(stream_body))),
        ],
    )
    client.send_data(1, stream_body, end_stream=True)
    seen, _ = _run_h2_both(monkeypatch, client.data_to_send())
    assert seen[0]["data"]["credentials"]["username"] == "streamuser"
    assert seen[0]["data"]["credentials_from_stream"] == 1


def test_undecodable_body_bytes_do_not_fabricate_a_credential(monkeypatch):
    # One word, `replace` against `ignore`, and the row claimed a captured credential that
    # was never one: U+FFFD characters that `_extract_credentials` then read as content.
    # The HTTP/1.1 path decodes with `ignore` and captured nothing from these bytes, and
    # parity with it is the whole claim this capture makes.
    payload = b"\xff\xfe\x00login=\xc3\x28\xc3\x28&pwd=\x80\x81\x82"
    over_http11 = _run(
        monkeypatch,
        b"POST /u HTTP/1.1\r\nHost: decoy.invalid\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload,
    )
    assert over_http11[0]["data"].get("credentials") is None

    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.send_headers(
        1,
        [
            (":method", "POST"),
            (":path", "/u"),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(payload))),
        ],
    )
    client.send_data(1, payload, end_stream=True)
    seen, _ = _run_h2_both(monkeypatch, client.data_to_send())
    event = seen[0]["data"]
    assert event.get("credentials") is None  # the same answer as HTTP/1.1
    assert "\ufffd" not in event["streams"][0]["body"]
    # ... and a decodable body on the same path is still captured, so this is not a
    # blanket refusal to read bodies.
    good = b"login=admin&pwd=hunter2"
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.send_headers(
        1,
        [
            (":method", "POST"),
            (":path", "/u"),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(good))),
        ],
    )
    client.send_data(1, good, end_stream=True)
    seen, _ = _run_h2_both(monkeypatch, client.data_to_send())
    assert seen[0]["data"]["credentials"]["password"] == "hunter2"


def test_the_decoy_classifies_a_stream_past_the_record_ceiling(monkeypatch):
    # The wiring half of the same fix. `h2_capture` classifies every stream only if the
    # decoy hands it a classifier, and nothing checked that it does — so passing
    # `classify=None` from here would have put the whole fix back while every unit test
    # stayed green.
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    stream_id = 1
    for path in ["/a", "/b", "/c", "/d", "/e", "/etc/passwd"]:
        client.send_headers(
            stream_id,
            [
                (":method", "GET"),
                (":path", path),
                (":scheme", "http"),
                (":authority", "decoy.invalid"),
                ("content-type", "text/plain"),
            ],
            end_stream=True,
        )
        stream_id += 2
    seen, _ = _run_h2_both(monkeypatch, client.data_to_send())
    event = seen[0]["data"]
    assert len(event["streams"]) == 5  # the sixth record was dropped ...
    assert "lfi" in event["h2_verdicts"]  # ... and its verdict reached the row anyway
    assert seen[0]["severity"] == "HIGH"
    assert "lfi" in seen[0]["attack_type"]


def test_the_row_leads_with_the_name_that_explains_its_severity(monkeypatch):
    # The wiring half of the column ordering: `attack_type_field` sorts only when it is
    # given the severity map, and nothing checked that the decoy passes it. Measured
    # before: a CRITICAL row whose one greppable column held two 49975 names and nothing
    # explaining the CRITICAL.
    payload = b"cmd=/bin/sh -c id"
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
    for _ in range(20):  # h2bomb's drip floor, so a third verdict name fires too
        client.increment_flow_control_window(1)
    client.send_headers(
        1,
        [
            (":method", "POST"),
            (":path", "/upload"),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            ("content-type", "text/plain"),
            ("content-length", str(len(payload))),
        ],
    )
    client.send_data(1, payload, end_stream=True)
    seen, _ = _run_h2_both(monkeypatch, client.data_to_send())
    event = seen[0]["data"]
    assert seen[0]["severity"] == "CRITICAL"
    # More names than fit in 64 characters, so the ordering decides what survives.
    assert len(event["h2_verdicts"]) >= 3  # more names than the 64 characters can hold
    assert len(seen[0]["attack_type"]) <= 64
    assert seen[0]["attack_type"].split(",")[0] == "rce_attempt"
    # ... while `h2_verdicts` keeps precedence order for a reader.
    assert event["h2_verdicts"][0].startswith("cve_2026_49975")


def test_credentials_in_an_http2_data_body_are_captured(monkeypatch):
    # Goal 5's credential half. The same bytes over HTTP/1.1 yielded
    # `{'username': 'admin', 'password': 'hunter2'}`; over HTTP/2 they yielded nothing,
    # because the DATA payload was discarded before anything could read it.
    payload = b"cmd=/bin/sh -c id&login=admin&pwd=hunter2"
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.send_headers(
        1,
        [
            (":method", "POST"),
            (":path", "/upload"),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(payload))),
        ],
    )
    client.send_data(1, payload, end_stream=True)
    seen, _ = _run_h2_both(monkeypatch, client.data_to_send())
    event = seen[0]["data"]
    assert event["credentials"] == {
        "username": "admin",
        "password": "hunter2",
        "source": "post_body",
    }
    assert event["credentials_from_stream"] == 1
    assert seen[0]["attack_type"].startswith("rce_attempt")
    assert seen[0]["severity"] == "CRITICAL"
    # The body is evidence for a rule, not for the greppable one-line summary.
    assert "/bin/sh" not in event["payload"]


def test_a_header_name_starting_with_a_colon_keeps_the_name_it_always_had(monkeypatch):
    # The OWS fix searches for the colon from index 1, not 0, and that is a deliberate
    # choice with a cost if it is "simplified": a malformed client sending `:method: GET`
    # over HTTP/1.1 has always been recorded under `':method'`, and searching from 0 would
    # split it into an empty name and drop the line. Pinned so that fixing one evidence
    # loss cannot quietly introduce another.
    seen = _run(
        monkeypatch,
        b"GET / HTTP/1.1\r\n:method: GET\r\n:authority:victim.example\r\nHost: x\r\n\r\n",
    )
    headers = seen[0]["data"]["headers"]
    assert headers[":method"] == "GET"
    assert headers[":authority"] == "victim.example"  # and the no-OWS form of it too
    assert headers["host"] == "x"


def test_the_h2_row_reports_the_host_the_stream_named_not_a_path_segment(monkeypatch):
    # `host_claims` lists the target authority first because that is the order it looks,
    # not an order of authority. Taking the first claim put a path segment in the one
    # column a host-based hunt reads: `:path '//images.php'` recorded `host='images.php'`
    # while the stream had plainly named itself in `:authority`. Only a FOREIGN claim is
    # worth displacing what the stream said about itself.
    for path, authority, expected in [
        ("//images.php", "decoy.invalid", "decoy.invalid"),
        ("http://a.example/x", "b.example", "b.example"),
        ("/", "decoy.invalid", "decoy.invalid"),
        # ... and a stream that named itself only in the `host` header, with a pseudo
        # authority in `:path`, still reports the name it gave rather than that segment.
        ("//images.php", None, "named.example"),
    ]:
        client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
        client.initiate_connection()
        headers = [(":method", "GET"), (":path", path), (":scheme", "http")]
        if authority is not None:
            headers.append((":authority", authority))
        headers.append(("content-type", "text/plain"))
        if authority is None:
            headers.append(("host", "named.example"))
        client.send_headers(1, headers, end_stream=True)
        seen, _ = _run_h2_both(monkeypatch, client.data_to_send())
        assert seen[0]["data"]["host"] == expected, path

    # ... and a foreign claim still displaces it, which is the whole reason the field is
    # overwritten at all.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.send_headers(
        1,
        [
            (":method", "GET"),
            (":path", "http://victim.example/x"),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            ("content-type", "text/plain"),
        ],
        end_stream=True,
    )
    seen, _ = _run_h2_both(monkeypatch, client.data_to_send())
    assert seen[0]["data"]["host"] == "victim.example"


def test_a_mangled_request_line_cannot_launder_a_foreign_host(monkeypatch):
    # `GET\t/ HTTP/1.1` makes `_parse_request` read `HTTP/1.1` as the target, which the
    # authority parser then reports as the claim `HTTP`. Under a precedence rule that
    # replaced a foreign `Host`; under the union it is one more claim and the foreign one
    # still decides.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    seen, writer = _run_h2_both(monkeypatch, b"GET\t/ HTTP/1.1\r\nHost: victim.example\r\n\r\n")
    assert b"421 Misdirected Request" in writer.written
    assert seen[0]["data"]["response_mode"] == "misdirected"


def test_a_foreign_host_in_an_absolute_h2_path_is_refused(monkeypatch):
    # The HTTP/2 twin: `:path` carrying an absolute URI while `:authority` names us. A
    # conformant client never does this — RFC 9113 §8.3.1 confines `:path` to the path — so
    # refusing costs nothing, and under the union it is simply the fifth spelling.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.send_headers(
        1,
        [
            (":method", "GET"),
            (":path", "http://victim.example/"),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            ("content-type", "text/plain"),
        ],
        end_stream=True,
    )
    seen, writer = _run_h2_both(monkeypatch, client.data_to_send())
    headers, body = _h2_client_view(writer.written)
    assert headers[":status"] == "421" and body == b""
    assert b"It works!" not in writer.written
    assert seen[0]["data"]["response_mode"] == "misdirected"
    assert seen[0]["data"]["host"] == "victim.example"


def test_the_preface_row_claims_a_reply_only_once_it_went_out(monkeypatch):
    # H3's standard, applied to the side it did not cover. The token is recorded while the
    # reply is still only queued, so a peer that dies mid-flush left the row claiming
    # `page` with `bytes_out=51` — the handshake alone — and `It works!` never on the wire.
    # A `bytes_out > 0` gate cannot catch that, because the handshake already made the
    # tally non-zero; the token has to be kept only if the tally grew past the mark taken
    # before its own reply was queued.
    healthy, writer = _run_h2_both(monkeypatch, _authority_request("decoy.invalid"))
    assert healthy[0]["data"]["response_mode"] == "page"
    assert b"It works!" in bytes(writer.written)

    class _DiesAfterHandshake(_Writer):
        def __init__(self) -> None:
            super().__init__()
            self.writes = 0

        def write(self, data: bytes) -> None:
            self.writes += 1
            if self.writes > 1:
                raise BrokenPipeError("the peer has gone")
            super().write(data)

    dead = _DiesAfterHandshake()
    seen = _drive_with_writer(monkeypatch, _authority_request("decoy.invalid"), dead)
    event = seen[0]["data"]
    assert event["bytes_out"] > 0  # the handshake did get out ...
    assert b"It works!" not in bytes(dead.written)  # ... the reply did not
    assert "response_mode" not in event  # so the row claims nothing


def test_the_bait_is_not_served_under_a_third_party_name(monkeypatch):
    # The sharpest shape of the same bug: the bait's empty 200 is the reply that tells a
    # sweep "the shell is here". Served under someone else's domain it is evidence that
    # THEIR site is compromised — precisely what `shell_bait`'s split exists to prevent.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    monkeypatch.setenv("HP_HTTP_SHELL_BAIT", "true")
    spelled_as_host = _run_h2_both(
        monkeypatch, b"GET /images.php HTTP/1.1\r\nHost: victim.example\r\n\r\n"
    )
    assert b"421 Misdirected Request" in spelled_as_host[1].written

    seen, writer = _run_h2_both(
        monkeypatch,
        b"GET http://victim.example/images.php HTTP/1.1\r\nHost: decoy.invalid\r\n\r\n",
    )
    assert b"421 Misdirected Request" in writer.written
    assert b"200 OK" not in writer.written
    assert seen[0]["data"]["response_mode"] == "misdirected"


@pytest.mark.parametrize("host", ["user@victim.example", "user:pass@victim.example"])
def test_userinfo_does_not_hide_a_foreign_host(monkeypatch, host):
    # `is_foreign_host` normalised the port and a trailing dot but not userinfo, so
    # `user@victim.example` matched nothing and was served the full page on all three entry
    # points. RFC 9113 §8.3.1 makes such a `:authority` malformed and RFC 9110 §7.2 has no
    # userinfo in `Host` — we were more permissive than both the RFC and Apache, in the
    # direction that serves content under someone else's name.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    plain = _run_h2_both(monkeypatch, f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    assert b"421 Misdirected Request" in plain[1].written

    seen, writer = _run_h2_both(monkeypatch, _authority_request(host))
    headers, body = _h2_client_view(writer.written)
    assert headers[":status"] == "421" and body == b""
    assert seen[0]["data"]["response_mode"] == "misdirected"


def test_the_upgrade_row_claims_a_reply_only_once_it_went_out(monkeypatch):
    # The seed stated intent, not outcome: `response_mode` read `page` while `bytes_out=0`
    # showed the reply never left. That is the same mistake as seeding the preface path,
    # which was rejected because a reset flood answers nothing — the standard holds on both
    # sides. Here the reply really does go out, and the row says so.
    served, writer = _run_h2_both(
        monkeypatch, b"GET / HTTP/1.1\r\nHost: x\r\n" + _H2C_HEADERS + b"\r\n"
    )
    assert served[0]["data"]["response_mode"] == "page"
    assert served[0]["data"]["bytes_out"] > 0
    assert b"It works!" in bytes(writer.written)

    # ... and here it does not, because the capture broke after the 101 was written.
    monkeypatch.setattr(hp_http.HTTPHoneypot, "_h2c_request_record", _raiser)
    seen, broken = _run_h2_both(
        monkeypatch, b"GET / HTTP/1.1\r\nHost: x\r\n" + _H2C_HEADERS + b"\r\n"
    )
    event = seen[0]["data"]
    assert event["bytes_out"] == 0
    assert b"It works!" not in bytes(broken.written)
    assert "response_mode" not in event  # no reply claimed, because none was made


def test_an_empty_settings_header_is_not_an_upgrade_anywhere(monkeypatch):
    # Three places read `settings_header`: the 101 gate, `_response_modes`, and
    # `h2_capture.observe`'s choice of `initiate_upgrade_connection` vs
    # `initiate_connection`. They were spelled two ways and agreed only because
    # `_h2c_settings` cannot return `b""` today — so a future relaxation would have granted
    # a 101 to a connection the observer started as a plain one and never answered on
    # stream 1, with the row claiming `page`. Injected here rather than waited for.
    monkeypatch.setattr(hp_http.HTTPHoneypot, "_h2c_settings", lambda self, hdrs: b"")
    seen, writer = _run_h2_both(
        monkeypatch, b"GET / HTTP/1.1\r\nHost: x\r\n" + _H2C_HEADERS + b"\r\n"
    )
    assert b"101" not in writer.written  # no upgrade was granted ...
    assert b"HTTP/1.1 200 OK" in writer.written  # ... and today's reply was served
    assert len(seen) == 1
    assert seen[0]["data"].get("event_type") != "H2_CONNECTION"


def test_the_fail_closed_reply_keeps_the_persona(monkeypatch):
    # A bare `:status 200` with no `server` among replies that all carry `server: Apache/…`
    # is itself a fingerprint, and the decoy's whole value is that its behaviour matches its
    # banner. Fail closed on the body, not on the persona.
    monkeypatch.setattr(hp_http.HTTPHoneypot, "_h2_response_for", _raiser)
    writer = _run_h2_writer(monkeypatch, _authority_request("decoy.invalid"))
    headers, body = _h2_client_view(writer.written)
    assert body == b""  # still no content
    assert headers["server"].startswith("Apache/")


def test_a_mixed_connection_records_both_serving_and_refusing(monkeypatch):
    # `shell_bait.decide` returns None for "serve the page", which has no token — so a
    # connection that served stream 1 and refused stream 3 recorded `misdirected` alone and
    # the row said we refused when we had also served. Measured on both entry paths.
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", "victim.example")
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.send_headers(1, _host_headers("decoy.invalid", as_authority=True), end_stream=True)
    client.send_headers(3, _host_headers("victim.example", as_authority=True), end_stream=True)
    # A second refusal, so the join has to de-duplicate rather than repeat itself.
    client.send_headers(5, _host_headers("victim.example", as_authority=True), end_stream=True)
    seen, writer = _run_h2_both(monkeypatch, client.data_to_send())

    streams = _h2_streams_view(writer.written, stream_ids=(1, 3, 5))
    assert streams[1][0][":status"] == "200" and b"It works!" in streams[1][1]
    assert streams[3][0][":status"] == "421" and streams[3][1] == b""
    assert streams[5][0][":status"] == "421" and streams[5][1] == b""
    # Both facts, de-duplicated, in the order they were decided.
    assert seen[0]["data"]["response_mode"] == "page,misdirected"


def test_the_per_stream_guard_fails_closed_if_it_raises(monkeypatch):
    # `response_for` is the one hook in this path that carries a safety property, and its
    # exception handler used to resolve to "serve the connection's response", which on a
    # preface connection is the full Apache page under whatever name was claimed. A guard
    # that fails open is not a guard. Not reachable today; the direction still has to be
    # right, because that handler exists for the failure nobody predicted.
    monkeypatch.setattr(hp_http.HTTPHoneypot, "_h2_response_for", _raiser)
    seen, writer = _run_h2_both(monkeypatch, _authority_request("victim.example"))
    headers, body = _h2_client_view(writer.written)
    assert headers[":status"] == "200" and body == b""  # answered, without content
    assert b"It works!" not in writer.written
    # Still observed: refusing to serve is not refusing to record.
    assert seen[0]["data"]["event_type"] == "H2_CONNECTION"
    assert seen[0]["data"]["streams_opened"] == 1


def test_a_preface_split_across_segments_is_still_observed(monkeypatch):
    # The preface carries \r\n\r\n at offset 16, so `_read_request` used to split there,
    # find no Content-Length, and return early — and `startswith(PREFACE)` then failed.
    # Measured: one segment gave a full H2_CONNECTION row, the same bytes split at 20 gave
    # `method=PRI`, split at 1 gave nothing. One extra send() is free to arrange, so this
    # is one attacker-controlled choice turning our own analysis off, not a rarity.
    raw = _authority_request("decoy.invalid", "/etc/passwd")
    whole = _run_h2_both(monkeypatch, raw)[0][0]["data"]
    assert whole["event_type"] == "H2_CONNECTION"
    for at in (1, 16, 20, len(h2_capture.PREFACE) - 1):
        seen = _run_h2_both(monkeypatch, b"", reader=_SplitReader(raw, at))[0]
        assert len(seen) == 1, at
        event = seen[0]["data"]
        assert event["event_type"] == "H2_CONNECTION", at
        assert event["path"] == "/etc/passwd", at
        assert "lfi" in event["h2_verdicts"], at


def test_the_upgraded_request_is_answered_on_stream_one(monkeypatch):
    # `initiate_upgrade_connection` leaves stream 1 half-closed with no StreamEnded, so
    # `_answer` — which is driven by StreamEnded — never fired for it and a client that
    # upgraded and waited hung until a budget or EOF. A real mod_http2 answers at once, so
    # that silence is a fingerprint on the exact path this feature exists for.
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    settings = client.initiate_upgrade_connection()
    assert settings is not None
    writer = _run_upgrade(
        monkeypatch,
        b"GET /index.html HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\n"
        b"HTTP2-Settings: " + settings + b"\r\n\r\n",
    )
    # Read the frames back as the upgrading client would: it too starts from
    # initiate_upgrade_connection, so stream 1 exists on its side.
    peer = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    peer.initiate_upgrade_connection(settings)
    status, body = None, bytearray()
    for event in peer.receive_data(bytes(writer.written).split(b"\r\n\r\n", 1)[1]):
        if isinstance(event, h2.events.ResponseReceived) and event.stream_id == 1:
            status = dict(event.headers)[b":status"]
        elif isinstance(event, h2.events.DataReceived) and event.stream_id == 1:
            body += event.data
    assert status == b"200"
    assert b"It works!" in bytes(body)


def test_a_broken_capture_after_the_101_never_falls_back_to_http_1_1(monkeypatch):
    # Once the 101 is on the wire this is an HTTP/2 connection, whatever broke inside the
    # observer. Falling through to the HTTP/1.1 block ran `capture_body`,
    # `_extract_credentials` and `_classify` over the preface and the frames — fabricating
    # credentials out of frame bytes, which `_h2c_request_record` exists to prevent — and
    # put an HTTP/1.1 200 after a 101, which no server emits.
    monkeypatch.setattr(h2_capture, "observe", _raiser)
    frames = h2_capture.PREFACE + b"\x00\x00\x0c\x04\x00\x00\x00\x00\x00/etc/passwd\x00"
    seen, writer = _run_h2_both(
        monkeypatch, b"GET / HTTP/1.1\r\nHost: x\r\n" + _H2C_HEADERS + b"\r\n" + frames
    )
    assert b"200 OK" not in writer.written  # no 200 after a 101
    assert bytes(writer.written).endswith(b"Connection: Upgrade\r\n\r\n")
    assert len(seen) == 1
    event = seen[0]["data"]
    assert event["event_type"] == "H2_CONNECTION"
    assert event["h2_incomplete"] == "capture_error" and event["h2_error"] == "RuntimeError"
    assert "body_sample" not in event and "credentials" not in event
    assert "lfi" not in event["h2_verdicts"]


def test_a_raise_while_preparing_the_h2_path_is_inside_the_fail_safe(monkeypatch):
    # Building the response and the upgrade record both run our own code over
    # attacker-shaped input, and they used to sit outside the `try`. Nothing there raises
    # today — four malformed `Authorization: Basic` values were checked — but the whole
    # point of that guard is the failure nobody predicted, so it has to cover them.
    monkeypatch.setattr(hp_http.HTTPHoneypot, "_h2_response", _raiser)
    writer = _run_h2_writer(monkeypatch, h2_capture.PREFACE)
    assert b"HTTP/1.1 200" in writer.written  # not committed: HTTP/1.1, as always

    monkeypatch.setattr(hp_http.HTTPHoneypot, "_h2c_request_record", _raiser)
    seen, upgraded = _run_h2_both(
        monkeypatch, b"GET / HTTP/1.1\r\nHost: x\r\n" + _H2C_HEADERS + b"\r\n"
    )
    assert b"101 Switching Protocols" in upgraded.written
    assert b"200 OK" not in upgraded.written  # committed: still no 200 after a 101
    assert len(seen) == 1 and seen[0]["data"]["h2_incomplete"] == "capture_error"


def test_the_settings_in_the_upgrade_header_are_tallied(monkeypatch):
    # On the upgrade path the client's opening SETTINGS arrive base64url in the header and
    # never cross the wire as a frame, so the gate cannot see them and
    # settings_initial_window_size read None on every upgraded connection — losing the
    # clearest marker of a CVE-2026-49975 bomb on a campaign that is live.
    zero_window = base64.urlsafe_b64encode(b"\x00\x04\x00\x00\x00\x00")
    seen = _run_h2(
        monkeypatch,
        b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\n"
        b"HTTP2-Settings: " + zero_window + b"\r\n\r\n",
    )
    event = seen[0]["data"]
    assert event["settings_initial_window_size"] == 0
    assert "cve_2026_49975_zero_window" in event["h2_verdicts"]
    # Accounting only: a header is not a frame.
    assert event["frames_total"] == 0


def test_the_quadlet_carries_the_flag_only_when_the_operator_sets_it(monkeypatch):
    monkeypatch.delenv("H2_CAPTURE_ENABLED", raising=False)
    assert "HONEYLENS_H2_CAPTURE" not in _quadlet_for("http")
    monkeypatch.setenv("H2_CAPTURE_ENABLED", "true")
    assert "Environment=HONEYLENS_H2_CAPTURE=true" in _quadlet_for("http")
