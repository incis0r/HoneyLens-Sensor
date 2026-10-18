"""The HTTP/2 connection observer: what arrived, under hard budgets, never raising.

The Apache persona on port 80 has been advertising ``Upgrade: h2,h2c`` and a
``mod_http2`` version inside the CVE-2026-119618 range for months, and 366 connections
from 245 sources answered it with an HTTP/2 preface — which the HTTP/1.1 decoy hung up
on. ``h2_capture.observe`` lets those clients finish their sentence and reports one
connection-scoped observation.

The client side of these tests is the ``h2`` library itself, so the frames are the
frames a real client sends (Huffman-encoded, static-indexed) rather than bytes written
to match the parser under test. The two deliberately malformed cases are hand-rolled,
because no library will emit them.
"""

from __future__ import annotations

import asyncio

import h2.config
import h2.connection
import h2.errors
import h2.settings
import pytest

from honeylens.honeypots.body_capture import MAX_CAPTURE
from honeylens.honeypots.h2_capture import (
    MAX_BODY_CAPTURE,
    PREFACE,
    H2Budgets,
    H2Observation,
    H2Stream,
    attack_type_field,
    decide,
    observe,
)
from tests.ics_fakes import FakeReader, FakeWriter


def _observe(data: bytes, **kwargs) -> H2Observation:
    """Drive the observer over the fake stream pair and return its one observation."""
    return asyncio.run(observe(FakeReader(data), FakeWriter(), entry="preface", **kwargs))


def _req(path: str = "/", method: str = "GET", extra_headers=None, reset: bool = False):
    """One request: the 119618 shape (Content-Type present, no body) unless overridden."""
    headers = {"content-type": "text/plain"}
    headers.update(extra_headers or {})
    return (method, path, headers, reset)


def _n_requests_each_reset(count: int):
    """``count`` requests, each cancelled straight after its HEADERS frame."""
    return [_req(f"/{i}", reset=True) for i in range(count)]


def _kib_of_headers(kib: int) -> dict[str, str]:
    """``kib`` KiB of distinct header padding, well past any sane header-list ceiling."""
    return {f"x-pad-{i:04d}": "A" * 1024 for i in range(kib)}


def _client_bytes(requests, *, initial_window_size: int | None = None, window_updates=()) -> bytes:
    """What an ``h2`` client puts on the wire for ``requests``, preface included."""
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    if initial_window_size is not None:
        client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: initial_window_size})
    for increment in window_updates:
        client.increment_flow_control_window(increment)
    stream_id = 1
    for item in requests:
        method, path, extra, reset = item if len(item) == 4 else (*item, False)
        headers = [
            (":method", method),
            (":path", path),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            *extra.items(),
        ]
        client.send_headers(stream_id, headers, end_stream=True)
        if reset:
            client.reset_stream(stream_id, error_code=h2.errors.ErrorCodes.CANCEL)
        stream_id += 2
    return client.data_to_send()


def _frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    """A raw HTTP/2 frame, for the shapes no library will emit."""
    return (
        len(payload).to_bytes(3, "big")
        + bytes([ftype, flags])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def _continuation_flood(count: int) -> bytes:
    """A header block that never ends: one HEADERS frame plus ``count`` CONTINUATIONs."""
    return (
        PREFACE
        + _frame(0x4, 0x00, 0)  # empty SETTINGS
        + _frame(0x1, 0x00, 1, b"\x82")  # HEADERS, no END_HEADERS: the block stays open
        + _frame(0x9, 0x00, 1) * count
    )


def test_a_preface_and_one_request_is_observed():
    # one GET with Content-Type and no body
    obs = _observe(_client_bytes([("GET", "/", {"content-type": "text/plain"})]))
    assert obs.entry == "preface"
    assert obs.streams_opened == 1 and obs.headers_frames == 1
    assert obs.streams[0].path == "/" and obs.streams[0].method == "GET"
    assert obs.h2_error is None


def test_counters_match_the_frames_sent():
    obs = _observe(_client_bytes(_n_requests_each_reset(20)))
    assert obs.headers_frames == 20
    assert obs.rst_stream_total == 20 and obs.rst_stream_cancel == 20


def test_a_flood_is_bounded_and_keeps_only_a_few_streams():
    obs = _observe(_client_bytes(_n_requests_each_reset(3456)))
    # `==`, not `<=`. `<=` passes when it keeps NONE, which is exactly the state a batched
    # `receive_data` produced — h2 raises without returning the events it had already
    # built, so one refused frame discarded every stream decoded in that call. This
    # assertion sat in a test named "keeps only a few streams" and hid that for five
    # review rounds.
    assert len(obs.streams) == H2Budgets().keep_streams
    assert obs.frames_total <= H2Budgets().max_frames
    assert obs.goaway_sent is True and obs.goaway_reason == "frame_budget"


def test_a_continuation_flood_hits_the_budget_and_does_not_grow_a_buffer():
    obs = _observe(_continuation_flood(count=500))
    assert obs.continuation_frames <= H2Budgets().max_continuation
    assert obs.goaway_sent is True and obs.goaway_reason == "continuation_budget"


def test_a_protocol_error_is_recorded_with_its_reason_and_bytes():
    obs = _observe(PREFACE + b"\x00\x00\x08\x04\x00\x00\x00\x00\x01garbage!")
    assert obs.h2_error is not None
    assert obs.h2_error_reason and len(obs.h2_error_reason) <= 500
    assert obs.raw.startswith(PREFACE)


def test_the_window_counters_are_collected_for_the_49975_overlap():
    obs = _observe(_client_bytes([], initial_window_size=0, window_updates=[1, 1, 1]))
    assert obs.settings_initial_window_size == 0
    assert obs.window_update_count == 3 and obs.window_update_min_increment == 1


def test_an_empty_connection_still_returns_an_observation():
    obs = _observe(PREFACE)
    assert obs.streams_opened == 0 and obs.h2_error is None


def test_an_oversized_header_list_is_refused_not_buffered():
    # HPACK is a compression format: an unbounded header table is a decompression
    # bomb, which is why h2bomb refuses to decode HPACK at all. We do decode it.
    obs = _observe(_client_bytes([_req("/", extra_headers=_kib_of_headers(64))]))
    assert obs.goaway_sent is True
    assert obs.goaway_reason in {"header_list_budget", "protocol_error"}
    assert obs.bytes_in <= H2Budgets().max_bytes
    # The refusal has to be *ours*. h2's own default ceiling is 65536, which 64 KiB of
    # padding also exceeds, so "some protocol error happened" would still pass with both
    # decoder pins deleted. A message naming our budget is the only thing that guards
    # them against the cleanup the module's docstring warns about.
    assert obs.h2_error == "DenialOfServiceError"
    assert "16384" in (obs.h2_error_reason or "")
    tighter = _observe(
        _client_bytes([_req("/", extra_headers=_kib_of_headers(64))]),
        budgets=H2Budgets(max_header_list_size=2048),
    )
    assert "2048" in (tighter.h2_error_reason or "")


def test_a_tightened_hpack_table_still_decodes_a_request():
    # Tightening a budget must never destroy the capture the budget protects. hpack
    # asserts header_table_size <= max_allowed_table_size on *every* decode, so pinning
    # only the allowance would make the first HEADERS frame of every connection raise,
    # with no attacker participation, and the module would report plausible-looking
    # observations while capturing no headers at all.
    obs = _observe(
        _client_bytes([("GET", "/admin", {"content-type": "text/plain"})]),
        budgets=H2Budgets(max_header_table_size=512),
    )
    assert obs.h2_error is None
    assert obs.streams_opened == 1 and obs.streams[0].path == "/admin"
    assert obs.streams[0].content_type == "text/plain"


def test_a_header_value_that_is_not_utf8_still_produces_a_stream_record():
    # HTTP/2 never required header bytes to be UTF-8, and they are attacker-controlled.
    # One invalid byte must not make a stream's decoded evidence — and with it the
    # CVE-2026-119618 shape — unobservable: attacker input does not gate our analysis.
    obs = _observe(_client_bytes([("GET", "/", {"content-type": b"text/plain\x80"})]))
    assert obs.h2_error is None
    assert obs.streams_opened == 1
    assert obs.streams[0].content_type == "text/plain�"
    assert obs.streams[0].has_content_length is False
    assert obs.streams[0].end_stream is True


class _StalledWriter:
    """A peer that reads our handshake and then stops reading: the next ``drain`` parks.

    `FakeWriter.drain` is a no-op and never applies backpressure, so it cannot show the
    failure this covers.
    """

    def __init__(self, stall_after: int = 1):
        self.sent = bytearray()
        self.drains = 0
        self.stalled = asyncio.Event()
        self._stall_after = stall_after

    def write(self, data: bytes) -> None:
        self.sent.extend(data)

    async def drain(self) -> None:
        self.drains += 1
        if self.drains <= self._stall_after:
            return
        self.stalled.set()
        await asyncio.Event().wait()

    def get_extra_info(self, key, default=None):
        return default

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


def test_a_peer_that_stops_reading_cannot_park_the_observer():
    # An unbounded drain() is all it takes to hold this coroutine past max_seconds and
    # into the decoy's CONNECTION_TIMEOUT, where the cancellation discards every counter
    # already tallied — attacker input stopping us from recording what we had observed,
    # without a single malformed byte. The write side is bounded by the same clock.
    writer = _StalledWriter()
    obs = asyncio.run(
        observe(
            FakeReader(_client_bytes([("GET", "/", {"content-type": "text/plain"})])),
            writer,
            entry="preface",
            budgets=H2Budgets(max_seconds=0.05),
        )
    )
    assert writer.stalled.is_set()  # we really did park in drain()
    assert obs.goaway_reason == "time_budget"
    assert obs.goaway_sent is False  # nothing got through, and we do not claim it did
    assert obs.duration_ms < 1000  # ... and we came back anyway
    assert obs.streams_opened == 1 and obs.streams[0].path == "/"  # keeping the evidence


def test_the_outbound_budget_stops_us_amplifying():
    # 40 pipelined streams that are never cancelled, each answered with 8 KiB: tens of
    # kilobytes in must not buy megabytes out. The cancelled-stream flood costs nothing
    # because every send raises StreamClosedError, which does not cover this case.
    body = b"X" * 8192
    obs = _observe(
        _client_bytes(
            [_req(f"/{i}") for i in range(40)],
            initial_window_size=2**24,
            window_updates=[2**24],
        ),
        response_body=body,
    )
    assert obs.goaway_sent is True and obs.goaway_reason == "outbound_budget"
    assert obs.bytes_out >= H2Budgets().max_bytes_out
    assert obs.bytes_out <= H2Budgets().max_bytes_out + len(body) + 1024


class _SilentReader:
    """A client that sends its frames and then goes quiet until someone cancels it."""

    def __init__(self, data: bytes):
        self._data = data
        self.exhausted = asyncio.Event()

    async def read(self, n: int) -> bytes:
        if self._data:
            chunk, self._data = self._data[:n], self._data[n:]
            return chunk
        self.exhausted.set()
        await asyncio.Event().wait()
        return b""  # pragma: no cover — never reached


def test_the_caller_keeps_its_observation_when_the_connection_is_cancelled():
    # CancelledError keeps propagating — cancellation is not an error — so the caller
    # owns the observation instead and reads it in its own finally. Without this seam a
    # client that sends the preface and goes silent until CONNECTION_TIMEOUT produces no
    # event at all, and the design requires exactly one per connection.
    async def run() -> H2Observation:
        holder = H2Observation(entry="preface")
        reader = _SilentReader(_client_bytes([("GET", "/", {"content-type": "text/plain"})]))
        task = asyncio.create_task(observe(reader, FakeWriter(), entry="preface", obs=holder))
        await asyncio.wait_for(reader.exhausted.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return holder

    obs = asyncio.run(run())
    assert obs.streams_opened == 1 and obs.headers_frames == 1
    assert obs.streams[0].path == "/" and obs.streams[0].ended_by == "complete"


def test_a_clock_that_raises_does_not_escape_observe():
    # The clock is injected, so reading it is the caller's code running inside ours, and
    # "observe never raises" must not depend on it behaving.
    def broken() -> float:
        raise RuntimeError("the clock is gone")

    obs = asyncio.run(observe(FakeReader(PREFACE), FakeWriter(), entry="preface", monotonic=broken))
    assert isinstance(obs, H2Observation)
    assert obs.h2_error is None and obs.duration_ms == 0


def test_the_prefix_the_caller_already_read_is_counted_against_the_byte_budget():
    # bytes_in <= max_bytes is advertised as holding by construction, and Task 6 supplies
    # the prefix: capping only the socket reads would leave the guarantee false.
    budgets = H2Budgets(max_bytes=1024)
    obs = asyncio.run(
        observe(
            FakeReader(b""),
            FakeWriter(),
            entry="preface",
            prefix=PREFACE + _frame(0x4, 0x00, 0) * 200,
            budgets=budgets,
        )
    )
    assert obs.bytes_in == budgets.max_bytes
    assert obs.goaway_reason == "byte_budget"
    assert obs.h2_error is None


def test_the_upgrade_settings_header_is_applied_and_a_bad_one_does_not_raise():
    # ``entry="upgrade"`` was a label until the decoy could actually be upgraded: h2c
    # carries the client's opening SETTINGS in the HTTP2-Settings header rather than in a
    # frame, so the connection has to start with initiate_upgrade_connection(header).
    # Deleting that branch makes the garbage case stop being an error.
    good = asyncio.run(
        observe(
            FakeReader(PREFACE),
            FakeWriter(),
            entry="upgrade",
            settings_header=b"AAMAAABkAAQAoAAAAAIAAAAA",
        )
    )
    assert good.entry == "upgrade"
    assert good.h2_error is None and good.goaway_reason is None
    bad = asyncio.run(
        observe(
            FakeReader(PREFACE),
            FakeWriter(),
            entry="upgrade",
            settings_header=b"!!! not base64 !!!",
        )
    )
    assert bad.h2_error is not None and bad.goaway_reason == "protocol_error"


# ---------------------------------------------------------------------------
# What `observe` produces under volume
#
# `decide` is pinned by 37 tests against hand-built observations. What the
# observer actually produces when a read carries hundreds of frames was
# covered by one assertion that passed at zero, and a Critical hid behind it
# for five rounds. These drive the real thing.
# ---------------------------------------------------------------------------


def _shaped_flood(count: int, *, resets: str, path: str = "/etc/passwd") -> bytes:
    """``count`` shaped requests with their resets interleaved or batched after them.

    The reference capture interleaves. Batching them is one `send()` apart and was a
    different verdict, a different severity and a different campaign.
    """
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    stream_id, opened = 1, []
    for _ in range(count):
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
        if resets == "interleaved":
            client.reset_stream(stream_id, error_code=h2.errors.ErrorCodes.CANCEL)
        opened.append(stream_id)
        stream_id += 2
    if resets == "batched":
        for opened_id in opened:
            client.reset_stream(opened_id, error_code=h2.errors.ErrorCodes.CANCEL)
    return client.data_to_send()


def _classify(path, body=None, headers=None):
    """The decoy's own classifier, so these tests see the verdicts the row would carry."""
    from honeylens.honeypots.hp_http import HTTPHoneypot

    return HTTPHoneypot.__new__(HTTPHoneypot)._classify(path, body, headers)


def test_more_streams_than_the_concurrency_ceiling_are_still_observed():
    # `max_concurrent_streams` is 100 and a 16 KiB read holds ~900 small HEADERS frames,
    # so the ceiling was reached inside ONE `receive_data` call — and h2 raises without
    # returning the events it had already built. Measured before: 100 shaped streams gave
    # `shape_matches=100`, and 101 of the same gave 0, kept 0, and the wrong CVE.
    obs = _observe(_shaped_flood(101, resets="none"))
    assert obs.streams_opened >= 101
    assert obs.shape_matches >= 101
    assert len(obs.streams) == H2Budgets().keep_streams
    verdicts, severity = decide(obs, _classify)
    assert "cve_2026_119618_probe" in verdicts
    assert severity == "HIGH"  # `lfi` on the path, which the bomb verdict never carried


def test_a_shaped_flood_with_its_resets_batched_is_still_a_flood():
    # The same attack as the interleaved order, one `send()` apart. It read as
    # `cve_2026_49975_hpack_bomb`/MEDIUM with `shape_matches=0`, mis-attributing the
    # connection to a different live campaign. 900 streams and their 900 resets fit inside
    # the frame budget, so the reset ratio is readable and the flood verdict can fire.
    obs = _observe(_shaped_flood(900, resets="batched"))
    assert obs.shape_matches == 900
    assert obs.rst_stream_total == 900
    verdicts, severity = decide(obs, _classify)
    assert "cve_2026_119618_flood" in verdicts
    assert "cve_2026_49975_hpack_bomb" not in verdicts
    assert severity == "HIGH"

    # ... and the interleaved order, which always worked, still reads the same way.
    interleaved = _observe(_shaped_flood(900, resets="interleaved"))
    assert "cve_2026_119618_flood" in decide(interleaved, _classify)[0]


def test_a_stream_past_the_record_ceiling_is_still_classified():
    # `_record_request` tested EVERY stream for the 119618 shape but only the five kept
    # records were classified, so five harmless streams hid the sixth: `/a /b /c /d /e`
    # then `/etc/passwd` lost `lfi` and dropped from HIGH to MEDIUM. Half of one lesson
    # was applied and the other half was not, in the same function.
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
    obs = _observe(client.data_to_send(), classify=_classify)
    assert len(obs.streams) == H2Budgets().keep_streams  # the sixth record was dropped ...
    assert obs.stream_verdicts == {"lfi": "HIGH"}  # ... and its verdict was not
    verdicts, severity = decide(obs, _classify)
    assert "lfi" in verdicts and severity == "HIGH"


def test_a_body_in_a_data_frame_is_captured_and_classified():
    # Goal 5: an attack carried over HTTP/2 keeps the verdict it would have got over
    # HTTP/1.1. The DATA payload was discarded and `classify` was always called with
    # `body=None`, so the same bytes that earned `rce_attempt`/CRITICAL over HTTP/1.1
    # earned `h2_prior_knowledge`/LOW here — a classification bypass the decoy published
    # about itself. A DATA frame's bytes belong to exactly one stream, which is what makes
    # this safe where a connection-scoped buffer would not be.
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
    obs = _observe(client.data_to_send(), classify=_classify)
    assert obs.streams[0].body == payload.decode()
    verdicts, severity = decide(obs, _classify)
    assert "rce_attempt" in verdicts and severity == "CRITICAL"


def test_a_data_body_is_bounded_per_stream():
    # The same ceiling the HTTP/1.1 path applies to a request body, so neither protocol
    # keeps more of the same evidence than the other — and the connection's own
    # `max_bytes` bounds the sum across streams far below five times this.
    #
    # The body has to be LARGER than the ceiling or this proves nothing: an earlier version
    # sent 40 KB against a 64 KiB ceiling and asserted `<=`, which is the same decorative
    # shape as the `<=` that hid a Critical for five rounds. The ceiling is tightened here
    # rather than the body grown, because a client cannot send past the flow-control window
    # we advertise without a WINDOW_UPDATE it never receives in an offline test.
    assert H2Budgets().max_body == MAX_BODY_CAPTURE == MAX_CAPTURE  # == the HTTP/1.1 ceiling
    budgets = H2Budgets(max_bytes=1 << 20, max_body=4096)
    body = b"A" * 16384
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    client.initiate_connection()
    client.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 2**24})
    client.increment_flow_control_window(2**24)
    client.send_headers(
        1,
        [
            (":method", "POST"),
            (":path", "/u"),
            (":scheme", "http"),
            (":authority", "decoy.invalid"),
            ("content-type", "text/plain"),
        ],
    )
    for offset in range(0, len(body), 8192):
        client.send_data(1, body[offset : offset + 8192])
    client.send_data(1, b"", end_stream=True)
    obs = _observe(client.data_to_send(), budgets=budgets, classify=_classify)
    assert len(obs.streams[0].body) == budgets.max_body  # cut exactly at the ceiling
    assert obs.data_frames > 0


def test_a_classifier_that_raises_says_so_once_and_leaves_it_on_the_row():
    # A silent swallow here is how a lost verdict hides, and two Critical findings landed
    # in exactly this seam. DEBUG was not enough.
    def broken(path, body=None, headers=None):
        raise RuntimeError("the rule table is gone")

    obs = _observe(_shaped_flood(3, resets="none"), classify=broken)
    assert obs.classify_error is not None
    assert "RuntimeError" in obs.classify_error
    assert obs.streams_opened == 3  # ... and the observation is otherwise intact
    assert decide(obs, broken)[0] == ["cve_2026_119618_probe"]


def test_the_heaviest_verdict_name_survives_the_attack_type_column():
    # The spec caps the joined list with the heaviest verdict first. Precedence order put
    # two 49975 names in the 64 characters and dropped the `rce_attempt` that was the only
    # thing explaining a CRITICAL row.
    obs = H2Observation(entry="preface")
    obs.settings_initial_window_size = 0
    obs.window_update_count = 3
    obs.window_update_min_increment = 1
    obs.streams.append(H2Stream(stream_id=1, path="/bin/sh"))
    verdicts, severity = decide(obs, _classify)
    assert severity == "CRITICAL"
    column = attack_type_field(verdicts, obs.verdict_severities)
    assert column is not None
    assert column.split(",")[0] == "rce_attempt"
    assert len(column) <= 64
    # `h2_verdicts` keeps precedence order, which is the right order for a reader.
    assert verdicts[0].startswith("cve_2026_49975")


def test_the_persona_page_fits_in_one_frame():
    # `_answer` sends the body in one `send_data` and does not chunk to
    # SETTINGS_MAX_FRAME_SIZE, and h2's failure there is swallowed at debug level — so a
    # page grown past 16 KiB would serve NOTHING while looking healthy.
    from honeylens.honeypots.hp_http import HTTPHoneypot

    decoy = HTTPHoneypot()
    _headers, body = decoy._h2_response()
    assert 0 < len(body) <= 16384
