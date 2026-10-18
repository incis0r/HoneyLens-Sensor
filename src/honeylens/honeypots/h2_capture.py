"""honeypots/h2_capture.py — observe one HTTP/2 connection on the Apache decoy (:80)

The HTTP decoy wears ``Server: Apache/2.4.66 (Ubuntu) mod_http2/2.0.32`` and advertises
``Upgrade: h2,h2c``; both version strings sit inside the vulnerable range of
CVE-2026-119618, a data race in ``mod_http2`` reached by a specific HTTP/2 *header
shape*. For months the decoy has been unable to see anyone take that bait, because it
spoke only HTTP/1.1 and hung up on the connection preface. This module holds enough
HTTP/2 connection state to let a client finish its sentence, and reports what arrived.

**It decodes HPACK deliberately — the opposite of ``h2bomb.py``.** The sibling inspector
on the 8443 ALPN path states a non-amplification principle: it never decodes HPACK,
never builds the dynamic table, never holds a stream open, so an HPACK bomb cannot land
on it. The 119618 shape cannot be decided that way: ``content-type`` present and
``content-length`` absent are invisible on the wire the moment a client Huffman-encodes
them or references them from the HPACK static table, which every library-based attacker
does. So we decode, and because we decode, the header-list and dynamic-table ceilings in
`H2Budgets` are not optional — HPACK is a compression format and an unbounded header
table is a decompression bomb. Every ceiling here is enforced in code, not advertised
and hoped for: ``h2`` pushes our SETTINGS into its HPACK decoder only once the peer ACKs
them, and a hostile peer never has to ACK.

**The observation is connection-scoped on purpose.** Today's `pre_parser_capture` work
established that a connection-scoped buffer must not be classified as a request: 32 of
405 stored rejects held more than one request, and rendering them into the payload would
have earned 61 verdicts belonging to *other* requests on the same connection. That
objection does not apply here, because the event this feeds **is** the connection: one
row per HTTP/2 connection carrying counters for the whole of it, plus the decoded
headers of its first few streams as separate per-stream records, so a verdict for a
stream is still decided from that stream's own fields.

`observe` never raises. A protocol error, a malformed frame, a hostile encoding or an
I/O error is recorded in ``h2_error``/``h2_error_reason`` and returned as an observation,
the way `pre_parser_capture` keeps the reason a parser refused input: input a parser
refuses is exactly the input worth keeping. ``asyncio.CancelledError`` is *not* caught —
cancellation stays cancellation — so a caller that must emit an event even then passes
its own `H2Observation` in as ``obs`` and reads it in its ``finally``. Both the read and
the write side are bounded by the injected clock, because an unbounded ``drain()`` on a
peer that has stopped reading is all it takes to hold this coroutine past the decoy's
``CONNECTION_TIMEOUT`` and lose the counters already tallied.

Durations come from a monotonic clock passed in, never from timestamps: the fleet runs
one host in UTC and the rest in Europe/Warsaw and the offset is not constant.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings

from honeylens.honeypots import h2bomb
from honeylens.honeypots.body_capture import MAX_CAPTURE
from honeylens.honeypots.sink import MAX_RAW_CAPTURE

try:  # h2 refuses a header block longer than this many frames itself (see below).
    from h2.frame_buffer import CONTINUATION_BACKLOG as _H2_CONTINUATION_BACKLOG
except ImportError:  # pragma: no cover — h2 moved the constant; keep its 4.x value
    _H2_CONTINUATION_BACKLOG = 64

logger = logging.getLogger(__name__)

#: The client connection preface (RFC 9113 §3.4), the 24 bytes 245 sources already send.
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_FRAME_HEADER = 9
_T_DATA = 0x0
_T_HEADERS = 0x1
_T_RST_STREAM = 0x3
_T_SETTINGS = 0x4
_T_GOAWAY = 0x7
_T_WINDOW_UPDATE = 0x8
_T_CONTINUATION = 0x9

_FLAG_ACK = 0x01
_SETTINGS_INITIAL_WINDOW_SIZE = 0x4
_ERROR_CANCEL = 0x8

# SETTINGS_MAX_FRAME_SIZE stays at the protocol default: no negotiation upward.
_MAX_FRAME_SIZE = 16384
_READ_CHUNK = 16384
# pre_parser_capture truncates a parser's reason to 500 characters; so do we.
_REASON_MAX = 500

#: Per-stream DATA ceiling: the same one the HTTP/1.1 path applies to a request body, so
#: the two protocols keep the same amount of the same evidence. The sum across streams is
#: bounded far below 5x this by the connection's own ``max_bytes``.
MAX_BODY_CAPTURE = MAX_CAPTURE
# How long the closing GOAWAY may take when the lifetime budget is already spent. Short,
# because by then the only question is whether the peer is still reading at all.
_GOAWAY_WRITE_GRACE = 0.5

_DEFAULT_RESPONSE_HEADERS: tuple[tuple[str, str], ...] = (
    (":status", "200"),
    ("content-type", "text/html; charset=utf-8"),
)


@dataclass
class H2Stream:
    """One stream's decoded request, and how it ended.

    Every field after ``stream_id`` carries the flags its own shape test and its own
    `_classify()` call read, so the row can explain each label it holds.
    """

    stream_id: int
    method: str | None = None
    path: str | None = None
    authority: str | None = None
    scheme: str | None = None
    content_type: str | None = None
    has_content_length: bool = False
    end_stream: bool = False
    header_count: int = 0
    ended_by: str | None = None  # "complete" | "reset" | "open"
    verdict: str | None = None
    # This stream's DATA payload as text, bounded by ``body_capture.MAX_CAPTURE``, kept
    # only for a stream whose record survived the ``keep_streams`` ceiling.
    #
    # **A DATA frame's bytes belong to exactly one stream, and that is the whole
    # difference** from the connection-scoped buffer `pre_parser_capture` documents: there
    # is no second request's text to misattribute here. Without it, an attack carried in an
    # HTTP/2 body earned no verdict at all — measured,
    # ``cmd=/bin/sh -c id&login=admin&pwd=hunter2`` was ``rce_attempt``/CRITICAL with
    # credentials over HTTP/1.1 and ``h2_prior_knowledge``/LOW with nothing over HTTP/2,
    # which is a classification bypass the decoy published about itself.
    #
    # Decoded per DATA frame with ``errors="ignore"`` — the same way the HTTP/1.1 path
    # decodes a request body, because this field is read by the same two consumers and
    # ``replace`` let them read U+FFFD as content. A multi-byte character split across two
    # frames therefore loses those bytes here; the verbatim bytes stay in ``raw`` and reach
    # ``full_payload`` either way.
    body: str = ""
    # Every decoded header, lower-cased name -> value, last duplicate wins. Kept so the
    # event can read ``user_agent`` from the first stream, and so the decoy can read an
    # ``authorization`` header off it. It is never handed to `classify`, whose header
    # branches are HTTP/1.1 rules: see `classify_stream`.
    headers: dict[str, str] = field(default_factory=dict)
    # Every ``host`` header value this stream sent, in order, because `headers` above is
    # last-wins and the foreign-host guard needs the union of all of them. The HTTP/1.1
    # parser has kept `host_values` for exactly this reason since the day last-wins served
    # the full page to a request whose FIRST ``Host`` named a stranger — `shell_bait`'s
    # `host_claims` records that measurement — and this is the HTTP/2 arm of the same rule.
    #
    # Nothing reaches here with more than one value today: h2 refuses a duplicate ``Host``
    # at the wire, because ``validate_inbound_headers`` defaults to True and
    # ``RequestReceived`` is never raised. The list is here anyway, because that is one
    # flag's worth of protection, held by another library, over a guard this decoy has
    # already had bypassed four times by legal spellings — and because a module whose
    # stated philosophy is that input a parser refuses is the input worth keeping has a
    # standing reason to reach for that flag.
    host_values: list[str] = field(default_factory=list)


def is_119618_shape(stream: H2Stream) -> bool:
    """Whether this stream has the request shape CVE-2026-119618 needs (mod_http2 race).

    | condition                 | required |
    |---------------------------|----------|
    | END_STREAM on HEADERS     | yes (no request body) |
    | Content-Length            | absent   |
    | Content-Type              | present  |
    | method                    | not CONNECT |

    The same shape reaches the wire in several HPACK encodings: header names as literal
    ASCII (the reference proof of concept), Huffman-coded, or referenced from the static
    table (what python-h2, nghttp2, Go and curl emit), where no readable ``content-type``
    appears in the bytes at all. The encodings differ on the wire and not here: HPACK has
    already been decoded by the time this runs, which is why a text rule cannot see this
    shape and this predicate can.

    Never raises: a stream with no method, or whose pseudo-headers were duplicated or
    missing, is ordinary hostile input and simply does not match.
    """
    return (
        stream.end_stream
        and stream.content_type is not None
        and not stream.has_content_length
        and stream.method is not None
        and stream.method != "CONNECT"
    )


@dataclass
class H2Budgets:
    """Every ceiling this parser of hostile input obeys, chosen before the code was
    written. Note the absence of a stream ceiling: the frame budget already bounds the
    stream count, because every new stream costs at least one HEADERS frame.
    """

    max_bytes: int = 262144
    # Symmetric with max_bytes, and for the same reason read the other way round: a decoy
    # that answers more than this on one connection is being used as an amplifier.
    max_bytes_out: int = 262144
    max_frames: int = 2000
    max_continuation: int = 64
    max_seconds: float = 30.0
    max_concurrent_streams: int = 100
    max_header_list_size: int = 16384
    max_header_table_size: int = 4096
    keep_streams: int = 5
    # Per-stream DATA ceiling, defaulting to the one the HTTP/1.1 path applies to a request
    # body so neither protocol keeps more of the same evidence than the other. The sum
    # across streams is bounded far below ``keep_streams`` times this by ``max_bytes``.
    max_body: int = MAX_BODY_CAPTURE


@dataclass
class H2Observation:
    """What one HTTP/2 connection said. One of these becomes exactly one event."""

    entry: str  # "preface" | "upgrade"
    duration_ms: int = 0
    streams_opened: int = 0
    headers_frames: int = 0
    rst_stream_total: int = 0
    rst_stream_cancel: int = 0
    max_concurrent_streams_seen: int = 0
    data_frames: int = 0
    continuation_frames: int = 0
    bytes_in: int = 0
    bytes_out: int = 0  # what answering cost us, so the amplification ratio is readable
    frames_total: int = 0
    goaway_sent: bool = False
    goaway_reason: str | None = None
    settings_initial_window_size: int | None = None
    window_update_count: int = 0
    window_update_min_increment: int | None = None
    streams: list[H2Stream] = field(default_factory=list)
    # Connection-wide: counts every stream with the 119618 shape, kept record or not.
    shape_matches: int = 0
    # Connection-wide too, and for the same reason: verdict name -> severity for EVERY
    # stream `classify` labelled, kept record or not. `_record_request` tested every stream
    # for the shape but only the five kept records were ever classified, so five harmless
    # streams hid the sixth — measured, `/a /b /c /d /e` then `/etc/passwd` lost `lfi` and
    # dropped from HIGH to MEDIUM. Bounded by the number of distinct verdict names the
    # decoy's own pattern table can produce, not by the stream count.
    stream_verdicts: dict[str, str] = field(default_factory=dict)
    # Set the first time `classify` raises, and logged once. A silent swallow here is how
    # a lost verdict hides; two Critical findings landed in exactly this seam.
    classify_error: str | None = None
    # Verdict name -> severity, for every verdict `decide` concluded. `decide` fills it as
    # it goes; it is what lets `attack_type_field` put the heaviest name first instead of
    # truncating it away.
    verdict_severities: dict[str, str] = field(default_factory=dict)
    h2_error: str | None = None
    h2_error_reason: str | None = None
    h2_error_protocol: bool = False
    raw: bytes = b""


# ---------------------------------------------------------------------------
# Verdicts
#
# Three families look almost identical on the wire: CVE-2026-119618 (shaped HEADERS, each
# cancelled at once), CVE-2023-44487 Rapid Reset (HEADERS then RST_STREAM in a loop, which
# botnets have done for years) and CVE-2026-49975 (an HPACK bomb, which is also a HEADERS
# flood and is live on this fleet). Only the header shape separates the first two, so
# without the split every stale DoS bot arrives labelled as a 2026 pre-auth RCE attempt.

# Streams carrying the 119618 shape before a connection stops being a probe. 50 is
# h2bomb._FLOOD_COUNT: one client then reads the same on :80 and on :8443. The reference
# capture has 3456 shaped streams (69x the floor); a single probe has 1. A person poking
# with curl or a scanner checking the version sends a handful, so the floor sits well
# above that and ~70x below the real run. Never raise it above h2bomb's value.
SHAPE_FLOOD_STREAMS = h2bomb._FLOOD_COUNT

# RST_STREAM frames (any error code) per HEADERS frame for a flood. The reference run is
# 3456/3458 = 0.9994: each request is torn down as soon as it is sent. CANCEL is the
# proof-of-concept's choice, not a precondition: the race fires on stream teardown and
# any reset code causes one. 0.9 leaves room for the few streams left open at the budget
# cut or the GOAWAY, and still excludes a client that opens many streams and lets most of
# them finish. The same ratio gates Rapid Reset.
FLOOD_RESET_RATIO = 0.9

_ATTACK_TYPE_MAX = 64  # width of the attack_type column

_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _rank(label: str | None) -> int:
    """No severity ranks below every label, including one we do not recognise.

    hp_http decides the vocabulary (it returns CRITICAL for an RCE). A label added there
    later and missing from the table must still beat ``None``, or the event would lose its
    severity silently; it ranks 0, below every known label. `decide` logs it where it
    enters, and a test pins the vocabulary so a new severity is caught before production.
    """
    if label is None:
        return -1
    return _SEVERITY_RANK.get(label, 0)


def heavier(a: str | None, b: str | None) -> str | None:
    """The heavier of two severities, by `_rank`. Public because the caller has one more
    severity to fold in than `decide` can see: the h2c upgrade request's, which arrived
    over HTTP/1.1 and so is classified by the decoy, not here."""
    return a if _rank(a) >= _rank(b) else b


def is_protocol_error(exc: BaseException) -> bool:
    """Did the peer break HTTP/2, or did it simply go away?

    ``h2`` draws this line itself: every protocol-level failure it raises derives from
    ``h2.exceptions.H2Error``, while a transport failure (``ConnectionResetError``,
    ``TimeoutError``) and a bug of ours (``TypeError``) do not. Reading the library's
    hierarchy keeps the distinction out of string matching on an error message, and keeps
    our own crash from being published as something an attacker did.
    """
    return isinstance(exc, h2.exceptions.H2Error)


def decide(
    obs: H2Observation,
    classify: Callable[[str | None, str | None, dict | None], tuple[str, str] | None],
) -> tuple[list[str], str | None]:
    """Turn one observation into verdicts, in precedence order, and the heaviest severity.

    Precedence: CVE-2026-49975 markers, then Rapid Reset, then the 119618 shape (flood or
    probe), then ``h2_prior_knowledge`` if nothing at all fired on a ``preface`` connection
    (an ``upgrade`` one negotiated, so it never gets that baseline). The verdicts are additive,
    not exclusive: a connection can be a reset flood and carry a shaped probe, and both
    are reported. Only a 119618 flood suppresses ``h2_rapid_reset``, since that flood *is*
    a reset flood and naming both would count one fact twice. Then each kept stream's own
    ``classify`` verdict is appended, so a path or body attack carried over HTTP/2 keeps the
    label it has over HTTP/1.1. Decided from the counters alone: ``goaway_reason`` is a
    resource label, not an attack signal, and is never read here.

    49975 is checked first because its bomb is a HEADERS flood too. ``headers_count`` is
    HEADERS plus CONTINUATION frames, exactly what ``h2bomb.inspect_h2_connection`` counts
    on :8443 (a CONTINUATION train is the bomb's canonical delivery), so one client reads
    the same on both ports. ``settings_initial_window_size`` stays ``None`` when the peer
    declared none.

    That count also fits every reset flood, so a *lone* ``hpack_bomb`` (no zero-window, no
    window-drip marker) is dropped when the volume is already explained by a reset flood
    or by 50+ shaped streams AND no CONTINUATION frame contributed to it. Both
    explanations cover streams and neither ever explains CONTINUATION frames, so any
    CONTINUATION leaves the volume unexplained and the bomb stands. Dropping the bomb
    does not itself add a verdict; ``h2_rapid_reset`` and the 119618 verdicts are decided
    on their own conditions below.

    There are two reset counters and one of them decides. ``rst_stream_total`` (any reset
    code; NO_ERROR and REFUSED_STREAM are used in the wild) gates both floods, Rapid Reset
    and 119618, since teardown is what matters and an attacker picks the code.
    ``rst_stream_cancel`` decides nothing; it stays in the observation for the reader, to
    record that the resets matched the reference capture's code.

    Stream verdicts come from two places and are unioned, because each sees what the
    other cannot — see the loop below and `classify_stream`, which is the one place that
    decides what the classifier is shown (the path and the DATA body, never the headers).

    An ``upgrade`` connection whose capture failed before the upgrade request was judged
    therefore carries no verdict at all. That is deliberate: the row no longer claims prior
    knowledge for a negotiated connection, and with no decoy verdict the ingest falls back
    to the central rule set instead of being suppressed.

    Never raises: a classify that fails costs that stream its label, not the event.
    """
    verdicts: list[str] = []
    severity: str | None = None

    def add(name: str, sev: str | None) -> None:
        nonlocal severity
        if name not in verdicts:
            verdicts.append(name)
            if sev is not None and sev not in _SEVERITY_RANK:
                logger.warning("unrecognised severity %r on %r ranks below LOW", sev, name)
            if sev is not None:
                obs.verdict_severities[name] = sev
        severity = heavier(severity, sev)

    headers = max(obs.headers_frames, 0)
    resets = max(obs.rst_stream_total, 0)
    reset_ratio = resets / headers if headers else 0.0  # Rapid Reset: any reset code
    # SHAPE_FLOOD_STREAMS does a second job here: HEADERS frames before a reset flood counts
    # as a flood. Same number on purpose (one order of magnitude with h2bomb's floor, one
    # knob), but the meanings differ: change one and check the other.
    reset_flood = headers >= SHAPE_FLOOD_STREAMS and reset_ratio >= FLOOD_RESET_RATIO
    shaped = obs.shape_matches >= 1

    bomb, bomb_sev = h2bomb.evaluate_49975(
        initial_window_size=obs.settings_initial_window_size,
        window_update_count=obs.window_update_count,
        window_update_min_increment=obs.window_update_min_increment,
        headers_count=headers + max(obs.continuation_frames, 0),
    )
    # The probe selector above (`shaped`, >= 1) and the volume test below (>=
    # SHAPE_FLOOD_STREAMS) read the same counter on purpose: one shaped stream selects the
    # probe verdict but explains no volume. Collapsing them lets a single shaped stream
    # hide a bomb; do not tidy them into one.
    # Both explanations cover *streams*; neither explains CONTINUATION frames, so any
    # CONTINUATION leaves the volume unexplained and the bomb stands.
    explained = (obs.shape_matches >= SHAPE_FLOOD_STREAMS or reset_flood) and (
        obs.continuation_frames <= 0
    )
    if set(bomb) == {"cve_2026_49975_hpack_bomb"} and explained:
        bomb, bomb_sev = [], None
    for name in bomb:
        add(name, bomb_sev)

    if obs.shape_matches >= SHAPE_FLOOD_STREAMS and reset_ratio >= FLOOD_RESET_RATIO:
        add("cve_2026_119618_flood", "HIGH")
    else:
        if reset_flood and not bomb:
            add("h2_rapid_reset", "MEDIUM")
        if shaped:
            # Known limit: "probe" carries no volume. A flood of shaped requests with no
            # resets (no teardown, no race) also lands here, as does one stray shaped
            # stream; the counters in the event are what a reader must look at.
            add("cve_2026_119618_probe", "MEDIUM")

    # Two sources, unioned, because each sees what the other cannot. The kept records are
    # re-classified here because by now they also carry their DATA body, which did not
    # exist when their HEADERS arrived; `obs.stream_verdicts` holds what every stream's
    # path earned at that moment, including the ones the `keep_streams` ceiling threw away.
    # Reading only the kept records let five harmless streams hide the sixth.
    for stream in obs.streams:
        result = classify_stream(stream, classify, obs)
        if result:
            add(result[0], result[1])
    for name, severity_of in obs.stream_verdicts.items():
        add(name, severity_of)

    # Nothing above fired, so this connection gets whichever of two honest things is true.
    #
    # A peer that broke the protocol sent us something: measured on sensor-h 2026-11-13,
    # one source opened 40 connections in a second and every one died on "Error decoding
    # header block: Incomplete Huffman string". Eight reached the 49975 CONTINUATION floor;
    # the other 32 did not and were labelled `h2_prior_knowledge`, which says nothing
    # happened. The name is neutral on purpose -- an undecodable header block is what we
    # know, not that it was exploiting anything named -- and it is not withheld from an
    # ``upgrade`` connection, because the upgrade request's own row says a client asked to
    # upgrade and does not say it then sent a header block we could not read.
    #
    # Prior knowledge means the client assumed HTTP/2 without negotiating, and it stays the
    # label for a peer that offered nothing (57 bytes and a reset, three times in the same
    # corpus). A connection that arrived by ``Upgrade: h2c`` negotiated, so the baseline
    # would be false for it: the upgrade request's own verdict names that connection
    # instead (see `hp_http._log_h2`).
    if not verdicts:
        if obs.h2_error_protocol:
            add("h2_protocol_error", "LOW")
        elif obs.entry != "upgrade":
            add("h2_prior_knowledge", "LOW")
    return verdicts, severity


def attack_type_field(verdicts: list[str], severity_of: dict[str, str] | None = None) -> str | None:
    """Join verdicts for the 64-character ``attack_type`` column, **heaviest name first**.

    This is still a lossy summary — whole names are dropped from the tail rather than cut
    in half — but what survives is now the part that explains the row's severity. Given
    `decide`'s ``verdict_severities``, the names are ordered by severity rank, descending,
    and the sort is stable so precedence order still decides within one band.

    Precedence order alone was wrong, and the spec said so: it caps the list with the
    heaviest verdict first. Measured cost of the order this used to use — a 49975 client
    that also requests ``/bin/sh``:

        verdicts:    [zero_window, window_drip, hpack_bomb, rce_attempt]
        severity:    CRITICAL
        attack_type: 'cve_2026_49975_zero_window,cve_2026_49975_window_drip'
        dropped:     ['cve_2026_49975_hpack_bomb', 'rce_attempt']

    A CRITICAL row whose one greppable column held nothing that explained the CRITICAL.
    ``h2_verdicts`` keeps precedence order, which is the right order for a reader; this
    column answers a different question and gets a different order.

    Without ``severity_of`` the order is unchanged, so a caller that has only names keeps
    today's behaviour rather than silently getting a different one.
    """
    if severity_of:
        verdicts = sorted(verdicts, key=lambda name: -_rank(severity_of.get(name)))
    kept: list[str] = []
    length = 0
    for name in verdicts:
        if len(name) > _ATTACK_TYPE_MAX:
            continue  # a name that can never fit is skipped; it does not end the list
        extra = len(name) + (1 if kept else 0)
        if length + extra > _ATTACK_TYPE_MAX:
            break  # a name that merely does not fit ends the list: no lighter name jumps the queue
        kept.append(name)
        length += extra
    return ",".join(kept) or None


Classify = Callable[[str | None, str | None, dict | None], "tuple[str, str] | None"]


def classify_stream(
    stream: H2Stream, classify: Classify | None, obs: H2Observation
) -> tuple[str, str] | None:
    """Run the decoy's classifier over one stream and record what it said, connection-wide.

    ``body`` is passed, ``headers`` is not. That asymmetry is deliberate and both halves
    were decided by measurement: the header branches are HTTP/1.1 rules (``Upgrade: h2c``,
    a User-Agent pattern) that would label every honest ``python-h2`` client as recon, and
    HTTP/2 forbids ``upgrade`` anyway — while the body is a DATA frame's payload, belongs
    to this one stream, and carries attacks that the path alone cannot show.

    Never raises: a classifier that fails costs that stream its label, not the event. It
    says so **once per connection at WARNING**, not at DEBUG, and leaves
    ``classify_error`` on the row. Two Critical findings landed in this exact seam, and a
    silent swallow is how the next one would hide.
    """
    if classify is None:
        return None
    try:
        result = classify(stream.path, stream.body or None, None)
    except Exception as exc:
        if obs.classify_error is None:
            obs.classify_error = f"{type(exc).__name__}: {exc}"[:_REASON_MAX]
            logger.warning(
                "classify failed on stream %s; this connection's stream verdicts are "
                "incomplete: %s",
                stream.stream_id,
                exc,
            )
        return None
    if result:
        stream.verdict = result[0]
        # Connection-wide, so a verdict survives the `keep_streams` ceiling. First
        # severity for a name wins; the names are a fixed, small set.
        obs.stream_verdicts.setdefault(result[0], result[1])
    return result


class _Gate:
    """The frame-level budget gate: every byte ``h2`` sees passes through here first.

    It does two jobs that have to happen together. It *counts* what arrived, from the
    frame headers themselves rather than from the events ``h2`` chooses to surface —
    ``h2`` merges CONTINUATION frames into one mutant HEADERS frame and reports nothing
    for a frame it refused, so an event-derived tally would under-report exactly the
    floods this decoy exists to measure. And it *stops*: every budget is re-checked
    before each individual frame is admitted, so a flood arriving in one read is cut at
    the budget rather than after it.
    """

    def __init__(self, obs: H2Observation, budgets: H2Budgets) -> None:
        self._obs = obs
        self._budgets = budgets
        self._buf = bytearray()
        self._awaiting_preface = True
        self._seen: set[int] = set()
        self._open: set[int] = set()
        # h2's FrameBuffer raises ProtocolError once a header block holds more than
        # CONTINUATION_BACKLOG frames. Our ceiling has to bite first, or a CONTINUATION
        # flood would be recorded as a protocol error instead of as what it is.
        self._continuation_ceiling = min(budgets.max_continuation, _H2_CONTINUATION_BACKLOG - 1)
        self.breach: str | None = None

    def close_stream(self, stream_id: int) -> None:
        """A stream that is no longer open stops counting towards concurrency."""
        self._open.discard(stream_id)

    def feed(self, data: bytes) -> list[bytes]:
        """Tally ``data`` and return what ``h2`` may see, **one frame per item**.

        Bytes of a frame that has not fully arrived are held back (h2 would only buffer
        them itself), and nothing past a budget breach is returned at all.

        A list, not one buffer, and that is the whole point. ``h2.receive_data`` collects
        its events in a local list and **raises without returning it** when any frame is
        refused, so handing it a whole read discarded every request already decoded in that
        call. A 16 KiB read holds ~900 small HEADERS frames and reaches our own
        ``max_concurrent_streams`` inside one call, because answers are only produced from
        the batch after the batch is parsed. Measured on 3456 shaped streams: with the
        resets interleaved (the proof-of-concept's order) the connection read as
        ``cve_2026_119618_flood``/HIGH, and with the same resets batched after the headers
        it read as ``cve_2026_49975_hpack_bomb``/MEDIUM with ``shape_matches=0`` — the same
        attack, one ``send()`` apart, mis-attributed to a different live campaign. Feeding
        frame by frame keeps everything decoded before the refusal, and lets
        `_handle_events` answer and close each stream before the next HEADERS is parsed.
        """
        if self.breach is not None:
            return []
        self._buf.extend(data)
        out: list[bytes] = []
        if self._awaiting_preface:
            preface = bytearray()
            if not self._take_preface(preface):
                return [bytes(preface)] if preface else []
            if preface:
                out.append(bytes(preface))
        while self.breach is None:
            if len(self._buf) < _FRAME_HEADER:
                break
            length = int.from_bytes(self._buf[0:3], "big")
            total = _FRAME_HEADER + length
            if len(self._buf) < total:
                break
            frame = bytes(self._buf[:total])
            self.breach = self._refusal(frame)
            if self.breach is not None:
                break
            del self._buf[:total]
            self._tally(frame)
            out.append(frame)
        return out

    def _take_preface(self, out: bytearray) -> bool:
        """Pass the 24-byte preface through to h2 (which validates it) but do not try to
        read it as a frame. Returns False while there is not enough to decide."""
        if len(self._buf) < len(PREFACE):
            if PREFACE.startswith(bytes(self._buf)):
                return False
            self._awaiting_preface = False  # not a preface at all; let h2 say so
            return True
        if bytes(self._buf[: len(PREFACE)]) == PREFACE:
            out += self._buf[: len(PREFACE)]
            del self._buf[: len(PREFACE)]
        self._awaiting_preface = False
        return True

    def _refusal(self, frame: bytes) -> str | None:
        """The budget this frame would breach, if it were admitted."""
        if frame[3] == _T_CONTINUATION and self._obs.continuation_frames + 1 > (
            self._continuation_ceiling
        ):
            return "continuation_budget"
        if self._obs.frames_total + 1 > self._budgets.max_frames:
            return "frame_budget"
        return None

    def _tally(self, frame: bytes) -> None:
        obs = self._obs
        ftype = frame[3]
        flags = frame[4]
        stream_id = int.from_bytes(frame[5:9], "big") & 0x7FFFFFFF
        payload = frame[_FRAME_HEADER:]
        obs.frames_total += 1
        if ftype == _T_HEADERS:
            obs.headers_frames += 1
            if stream_id and stream_id not in self._seen:
                self._seen.add(stream_id)
                self._open.add(stream_id)
                obs.streams_opened += 1
                obs.max_concurrent_streams_seen = max(
                    obs.max_concurrent_streams_seen, len(self._open)
                )
        elif ftype == _T_CONTINUATION:
            obs.continuation_frames += 1
        elif ftype == _T_DATA:
            obs.data_frames += 1
        elif ftype == _T_RST_STREAM:
            obs.rst_stream_total += 1
            if len(payload) >= 4 and int.from_bytes(payload[:4], "big") == _ERROR_CANCEL:
                obs.rst_stream_cancel += 1
            self._open.discard(stream_id)
        elif ftype == _T_WINDOW_UPDATE and len(payload) >= 4:
            increment = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
            obs.window_update_count += 1
            if (
                obs.window_update_min_increment is None
                or increment < obs.window_update_min_increment
            ):
                obs.window_update_min_increment = increment
        elif ftype == _T_SETTINGS and not flags & _FLAG_ACK:
            tally_settings_payload(obs, payload)


def tally_settings_payload(obs: H2Observation, payload: bytes) -> None:
    """Read ``INITIAL_WINDOW_SIZE`` out of a SETTINGS payload, wherever it came from.

    Last value wins: an h2 client advertises the default 65535 in its opening SETTINGS and
    only then sends the 0 that is the CVE-2026-49975 smoking gun.

    Shared with the h2c upgrade path, where the client's opening SETTINGS arrive
    base64url-encoded in the ``HTTP2-Settings`` header and never cross the wire as a frame.
    Without this the marker read ``None`` on every upgraded connection, so an h2c-delivered
    49975 bomb lost its clearest evidence — on a campaign that is live. Accounting only: a
    header is not a frame and nothing here touches ``frames_total``.
    """
    for i in range(0, len(payload) - 5, 6):
        if int.from_bytes(payload[i : i + 2], "big") == _SETTINGS_INITIAL_WINDOW_SIZE:
            obs.settings_initial_window_size = int.from_bytes(payload[i + 2 : i + 6], "big")


def _server_connection(budgets: H2Budgets) -> h2.connection.H2Connection:
    """A server-side h2 connection with every ceiling from ``budgets`` in force.

    ``header_encoding`` is deliberately left unset, so h2 hands us the header *bytes*
    and `_text` decodes them with ``errors="replace"``. With ``header_encoding="utf-8"``
    h2 decodes inside the library and raises ``UnicodeDecodeError`` on the first byte
    that is not valid UTF-8 — and header values are attacker-controlled bytes that HTTP/2
    never required to be UTF-8. That would have been a one-byte switch for making a
    stream's decoded evidence, and with it the 119618 shape, unobservable. Attacker input
    must not gate our analysis.
    """
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=False),
    )
    conn.local_settings = h2.settings.Settings(
        client=False,
        initial_values={
            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: budgets.max_concurrent_streams,
            h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE: budgets.max_header_list_size,
            h2.settings.SettingCodes.HEADER_TABLE_SIZE: budgets.max_header_table_size,
            h2.settings.SettingCodes.MAX_FRAME_SIZE: _MAX_FRAME_SIZE,
        },
    )
    conn.max_inbound_frame_size = _MAX_FRAME_SIZE
    # h2 only hands our SETTINGS to its HPACK decoder when the peer ACKs them, and a
    # hostile peer never has to ACK. Pin both HPACK ceilings now, so the decompression
    # bomb is refused by the decoder and not merely discouraged by a SETTINGS frame.
    conn.decoder.max_header_list_size = budgets.max_header_list_size
    # Both halves of the table pin, or tightening the budget destroys the capture it
    # protects: hpack asserts ``header_table_size <= max_allowed_table_size`` on *every*
    # decode, so lowering only the allowance would make the first HEADERS frame of every
    # connection raise InvalidTableSizeError with no attacker participation at all.
    conn.decoder.max_allowed_table_size = budgets.max_header_table_size
    conn.decoder.header_table_size = budgets.max_header_table_size
    return conn


def _text(value: Any) -> str:
    """A header name or value as text, whatever the attacker's encoding was.

    ``errors="replace"`` is the point: a header that is not valid UTF-8 still yields a
    usable record, because a stream must not become unobservable over an encoding.
    """
    if isinstance(value, str):
        return value
    return bytes(value).decode("utf-8", "replace")


def _contains_goaway(data: bytes) -> bool:
    """Whether ``data`` holds a GOAWAY frame, so ``goaway_sent`` says what it means."""
    offset = 0
    while offset + _FRAME_HEADER <= len(data):
        if data[offset + 3] == _T_GOAWAY:
            return True
        offset += _FRAME_HEADER + int.from_bytes(data[offset : offset + 3], "big")
    return False


async def _write(writer: Any, data: bytes) -> None:
    writer.write(data)
    await writer.drain()


async def _flush(
    conn: h2.connection.H2Connection,
    writer: Any,
    obs: H2Observation,
    allowance: float,
) -> bool:
    """Put whatever h2 has queued on the wire within ``allowance`` seconds.

    Returns False when the peer could not be written to — gone, or simply not reading —
    and the caller then stops writing to it. **The time bound is the whole point.** A
    peer that sends its frames and stops reading closes its TCP receive window, and an
    unbounded ``drain()`` parks this coroutine there indefinitely: past ``max_seconds``,
    into the decoy's ``CONNECTION_TIMEOUT``, where the cancellation discards every
    counter already tallied. Attacker input would then have stopped us recording what we
    had already observed, without a single malformed byte.

    Never raises: serving is best-effort and a peer that has gone is not an error worth
    losing the observation over.
    """
    try:
        data = conn.data_to_send()
    except Exception as exc:
        logger.debug("ignored: %s", exc)
        return True
    if not data:
        return True
    if allowance <= 0:
        obs.goaway_reason = obs.goaway_reason or "time_budget"
        return False
    try:
        await asyncio.wait_for(_write(writer, data), allowance)
    except TimeoutError:
        obs.goaway_reason = obs.goaway_reason or "time_budget"
        return False
    except Exception as exc:
        logger.debug("ignored: %s", exc)
        return False
    obs.bytes_out += len(data)
    if _contains_goaway(data):
        obs.goaway_sent = True
    return True


def _answer(
    conn: h2.connection.H2Connection,
    stream_id: int,
    headers: list[tuple[str, str]],
    body: bytes,
) -> None:
    """Serve the decoy's static response on a completed stream.

    A stream the client cancelled in the same batch of frames is already closed inside
    h2 and raises here; under a reset flood that is the normal case, and it must not end
    the connection or lose the observation.
    """
    try:
        conn.send_headers(stream_id, headers, end_stream=not body)
        if body:
            conn.send_data(stream_id, body, end_stream=True)
    except Exception as exc:
        logger.debug("ignored: %s", exc)


def _record_request(
    event: h2.events.RequestReceived,
    *,
    obs: H2Observation,
    kept: dict[int, H2Stream],
    budgets: H2Budgets,
    classify: Classify | None = None,
) -> None:
    """Keep this stream's decoded request, up to ``keep_streams`` of them.

    Past that ceiling the connection is described by its counters alone: a flood must
    cost a bounded number of records, or we have built the attacker a tool. Every stream is
    still tested for the 119618 shape **and classified**, kept or not: both are
    connection-wide, and for the same reason. Half of that lesson was applied here and the
    other half was not, so a flood's sixth stream could carry `/etc/passwd` past a guard
    that had already filled its five record slots with `/a` to `/e`.

    Seven cheap alternation regexes over a path, bounded by the frame budget.
    """
    record = H2Stream(stream_id=event.stream_id, ended_by="open")
    record.header_count = len(event.headers or [])
    record.end_stream = event.stream_ended is not None
    for name, value in event.headers or []:
        key = _text(name).lower()
        record.headers[key] = _text(value)
        if key == "host":
            record.host_values.append(_text(value))
        if key == ":method":
            record.method = _text(value)
        elif key == ":path":
            record.path = _text(value)
        elif key == ":authority":
            record.authority = _text(value)
        elif key == ":scheme":
            record.scheme = _text(value)
        elif key == "content-type":
            record.content_type = _text(value)
        elif key == "content-length":
            record.has_content_length = True
    if is_119618_shape(record):
        obs.shape_matches += 1
    # Before the ceiling, so a verdict is not a privilege of the first five streams. A
    # kept record is classified again in `decide`, by then carrying its DATA body too.
    classify_stream(record, classify, obs)
    if len(kept) >= budgets.keep_streams:
        return
    kept[event.stream_id] = record
    obs.streams.append(record)


#: Chooses the response for one stream from its decoded request, or from ``None`` when the
#: stream was past ``keep_streams`` and no record of it was kept. It exists because the
#: decoy's reply is not always the same page: a stream whose host names a domain that is
#: not ours must not be answered with content, and only the decoy knows which domains
#: those are. Should not raise; `_reply_for` answers without content if it does.
ResponseFor = Callable[["H2Stream | None"], "tuple[list[tuple[str, str]], bytes]"]


def _reply_for(
    record: H2Stream | None,
    headers: list[tuple[str, str]],
    body: bytes,
    response_for: ResponseFor | None,
) -> tuple[list[tuple[str, str]], bytes]:
    """The response for one stream: the caller's per-stream choice, or the fixed one.

    **The failure direction is deliberate.** ``response_for`` is the one hook here that
    carries a safety property — it is where the decoy refuses to serve content under a
    domain that is not its own — so if it raises we drop the **body** and keep nothing
    else from the connection's response. A guard that fails open is not a guard, and
    "serve the page under whatever name was claimed" is not an acceptable resolution of an
    unexpected exception. Serving stays best-effort; serving *content* does not.

    The headers are kept precisely because they are the persona: a bare ``:status 200``
    with no ``server`` among replies that all carry ``server: Apache/…`` is itself a
    fingerprint, and the decoy's whole value is that its behaviour matches its banner.
    """
    if response_for is None:
        return headers, body
    try:
        return response_for(record)
    except Exception as exc:
        logger.debug("ignored: %s", exc)
        return headers, b""


async def _handle_events(
    events: Iterable[Any],
    *,
    conn: h2.connection.H2Connection,
    writer: Any,
    obs: H2Observation,
    gate: _Gate,
    kept: dict[int, H2Stream],
    bodies: dict[int, int],
    budgets: H2Budgets,
    headers: list[tuple[str, str]],
    body: bytes,
    response_for: ResponseFor | None,
    classify: Classify | None,
    remaining: Callable[[], float],
    writable: bool,
) -> bool:
    """React to one batch of h2 events: record the requests, answer what completed.

    Each answer is flushed as it is produced, so the outbound tally is exact before the
    next one is queued. That is what bounds `max_bytes_out`: a batch can hold hundreds of
    completed streams, and queueing them all into h2's buffer before measuring would be
    the amplification the budget exists to prevent. Once the outbound budget is spent, or
    the peer has stopped reading, we stop *answering* but keep *recording* — recording is
    the job. Returns whether the peer is still writable.
    """
    for event in events:
        if isinstance(event, h2.events.RequestReceived):
            _record_request(event, obs=obs, kept=kept, budgets=budgets, classify=classify)
        elif isinstance(event, h2.events.StreamEnded):
            record = kept.get(event.stream_id)
            if record is not None and record.ended_by == "open":
                record.ended_by = "complete"
            gate.close_stream(event.stream_id)
            if obs.bytes_out >= budgets.max_bytes_out:
                obs.goaway_reason = obs.goaway_reason or "outbound_budget"
                continue
            if not writable:
                continue
            reply = _reply_for(record, headers, body, response_for)
            _answer(conn, event.stream_id, *reply)
            writable = await _flush(conn, writer, obs, remaining())
        elif isinstance(event, h2.events.StreamReset):
            record = kept.get(event.stream_id)
            if record is not None:
                record.ended_by = "reset"
            gate.close_stream(event.stream_id)
        elif isinstance(event, h2.events.DataReceived):
            # The body of a stream whose record we kept, bounded per stream by the same
            # ceiling the HTTP/1.1 path uses. `bodies` counts the bytes taken so far, so
            # the cap is on bytes rather than on characters a replacement may have widened.
            # The connection's own `max_bytes` bounds the sum across all streams.
            record = kept.get(event.stream_id)
            if record is not None and event.data:
                taken = bodies.get(event.stream_id, 0)
                room = budgets.max_body - taken
                if room > 0:
                    chunk = bytes(event.data)[:room]
                    # ``ignore``, not ``replace``, and the one word matters: the body
                    # goes to `classify` and to `_extract_credentials`, and `replace`
                    # turns undecodable bytes into U+FFFD characters that those two then
                    # read as content. Measured on
                    # ``b"\xff\xfe\x00login=\xc3\x28\xc3\x28&pwd=\x80\x81\x82"``:
                    # HTTP/1.1, which decodes with ``ignore``, captured no credential;
                    # HTTP/2 with ``replace`` captured ``{'username': '\ufffd(\ufffd(',
                    # ...}`` — a credential pair fabricated out of replacement characters,
                    # into a corpus `body_capture` calls a first-class analysis product.
                    # Parity with the HTTP/1.1 path is the whole claim of this capture, so
                    # it decodes the same way. The verbatim bytes stay in ``raw`` and reach
                    # ``full_payload``; nothing is lost, only not invented.
                    record.body += chunk.decode("utf-8", "ignore")
                    bodies[event.stream_id] = taken + len(chunk)
            try:
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            except Exception as exc:
                logger.debug("ignored: %s", exc)
    return writable


def _now(monotonic: Callable[[], float]) -> float:
    """Read the injected clock. Never raises: the clock is the caller's, and `observe`
    not raising must not depend on it behaving."""
    try:
        return monotonic()
    except Exception as exc:
        logger.debug("ignored: %s", exc)
        return 0.0


async def observe(
    reader: Any,
    writer: Any,
    *,
    entry: str,
    prefix: bytes = b"",
    budgets: H2Budgets | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    response_headers: list[tuple[str, str]] | None = None,
    response_body: bytes = b"",
    response_for: ResponseFor | None = None,
    classify: Classify | None = None,
    settings_header: bytes | None = None,
    obs: H2Observation | None = None,
) -> H2Observation:
    """Drive one HTTP/2 connection to its end and say what arrived.

    ``entry`` records how HTTP/2 was reached (``"preface"`` or ``"upgrade"``) and
    ``prefix`` is any bytes the caller has already read off the socket. The response
    served to each completed stream is passed in — the Apache persona's headers belong
    to the decoy, not to protocol mechanics, and importing it here would be circular.
    ``response_for`` overrides it per stream when the decoy needs to look at what that
    stream asked for: a stream whose ``:authority`` names a domain that is not the decoy's
    to answer for must not be served content, and only the decoy knows which those are.

    ``settings_header`` is the ``HTTP2-Settings`` field value, base64url as the client
    sent it, and it is what makes ``entry="upgrade"`` more than a label: h2c carries the
    client's opening SETTINGS in that header instead of in a frame, so the connection has
    to be started with ``initiate_upgrade_connection`` (which also puts stream 1 in the
    half-closed state the already-complete upgrade request leaves it in). A value h2
    cannot decode becomes this observation's ``h2_error`` like any other hostile input —
    but the caller should still screen it, because a client that sent no usable
    ``HTTP2-Settings`` was never entitled to the ``101`` in the first place. Its SETTINGS
    are tallied onto the observation like a frame's would be, and the upgraded request —
    already complete, and stream 1 by RFC 7540 §3.2 — is answered at once with
    ``response_headers``/``response_body``, because a real ``mod_http2`` answers it
    immediately and a client that upgrades and waits must not be left hanging.

    Pass ``obs`` to own the observation: it is filled in place and also returned, so a
    caller that is cancelled mid-connection can still read everything tallied so far out
    of its own instance, in its ``finally``. ``asyncio.CancelledError`` keeps
    propagating — cancellation is not an error and swallowing it is not our call — but
    with this seam it no longer costs the caller its event.

    Never raises anything else: every failure, including a budget value h2 rejects or a
    clock that misbehaves, becomes ``h2_error``/``h2_error_reason`` on the observation.
    """
    budget = budgets if budgets is not None else H2Budgets()
    observation = obs if obs is not None else H2Observation(entry=entry)
    observation.entry = entry  # one source of truth, whoever built the instance
    raw = bytearray()
    kept: dict[int, H2Stream] = {}
    # stream id -> DATA bytes already taken for that stream's body.
    bodies: dict[int, int] = {}
    # Built inside the try, not before it: a caller's budget value that h2's Settings
    # rejects must become this observation's h2_error, not an exception in the decoy.
    conn: h2.connection.H2Connection | None = None
    started = _now(monotonic)
    writable = True

    def remaining() -> float:
        """Seconds left of the connection's lifetime budget, for the write side."""
        return budget.max_seconds - (_now(monotonic) - started)

    try:
        headers = (
            list(response_headers)
            if response_headers is not None
            else list(_DEFAULT_RESPONSE_HEADERS)
        )
        conn = _server_connection(budget)
        gate = _Gate(observation, budget)
        if settings_header:
            # Applies the client's declared SETTINGS and queues the same preamble; the
            # client still sends the connection preface after the 101, so the gate's
            # preface handling is unchanged.
            conn.initiate_upgrade_connection(settings_header)
            # Those SETTINGS never cross the wire as a frame, so the gate cannot see them
            # and the 49975 window marker would read None on every upgraded connection.
            tally_settings_payload(observation, base64.urlsafe_b64decode(settings_header))
            # Stream 1 is the upgraded request, already complete and half-closed(remote):
            # h2 raises no StreamEnded for it, so nothing else will ever answer it.
            #
            # It is the only stream answered outside `_handle_events`, and so the only one
            # that passes through neither the `max_bytes_out` check nor `response_for`.
            # Both are correct here and neither is an oversight: `bytes_out` is 0 at this
            # point, one response cannot breach a 256 KiB outbound budget; and this
            # request's host was already judged over HTTP/1.1, before the caller wrote the
            # 101, which is what `response_headers`/`response_body` carry. A stream the
            # *client* opens after the upgrade is a different request and does go through
            # the per-stream guard.
            _answer(conn, 1, headers, response_body)
        else:
            conn.initiate_connection()
        writable = await _flush(conn, writer, observation, remaining())
        # Task 6 hands us the bytes it already read off the socket; they are evidence
        # like any other and are not exempt from the budget they are counted against.
        data = prefix[: budget.max_bytes]
        while True:
            if data:
                observation.bytes_in += len(data)
                if len(raw) < MAX_RAW_CAPTURE:
                    raw += data[: MAX_RAW_CAPTURE - len(raw)]
                frames = gate.feed(data)
                data = b""
                # One frame per `receive_data`, so a refusal costs us only the frame that
                # was refused. See `_Gate.feed`. The raise still propagates — it is a
                # protocol error and belongs on the record — but everything decoded before
                # it has already been handled and tallied.
                for frame in frames:
                    writable = await _handle_events(
                        conn.receive_data(frame),
                        conn=conn,
                        writer=writer,
                        obs=observation,
                        gate=gate,
                        kept=kept,
                        bodies=bodies,
                        budgets=budget,
                        headers=headers,
                        body=response_body,
                        response_for=response_for,
                        classify=classify,
                        remaining=remaining,
                        writable=writable,
                    )
                if writable:
                    writable = await _flush(conn, writer, observation, remaining())
            if gate.breach is not None and observation.goaway_reason is None:
                observation.goaway_reason = gate.breach
            if observation.goaway_reason is not None:
                break
            elapsed = _now(monotonic) - started
            if elapsed > budget.max_seconds:
                observation.goaway_reason = "time_budget"
                break
            if observation.bytes_in >= budget.max_bytes:
                observation.goaway_reason = "byte_budget"
                break
            want = min(_READ_CHUNK, budget.max_bytes - observation.bytes_in)
            try:
                data = await asyncio.wait_for(reader.read(want), budget.max_seconds - elapsed)
            except TimeoutError:
                observation.goaway_reason = "time_budget"
                break
            if not data:
                break
    except Exception as exc:
        observation.h2_error = type(exc).__name__
        observation.h2_error_reason = (str(exc) or type(exc).__name__)[:_REASON_MAX]
        observation.h2_error_protocol = is_protocol_error(exc)
        if observation.goaway_reason is None:
            observation.goaway_reason = "protocol_error"
    # Not attempted at all when the peer has stopped reading: the GOAWAY could not get
    # through, and trying would park us in exactly the drain `_flush` just escaped.
    if conn is not None and writable and observation.goaway_reason is not None:
        try:
            conn.close_connection(error_code=h2.errors.ErrorCodes.ENHANCE_YOUR_CALM)
        except Exception as exc:
            # h2 queues its own GOAWAY when it refuses a frame, so the connection is
            # already terminated on the protocol-error path; the flush below sends it.
            logger.debug("ignored: %s", exc)
        # A budget breach has no time left by definition, so the GOAWAY gets a small
        # fixed grace of its own rather than silently extending the connection.
        await _flush(conn, writer, observation, max(remaining(), _GOAWAY_WRITE_GRACE))
    observation.duration_ms = int(max(0.0, _now(monotonic) - started) * 1000)
    observation.raw = bytes(raw)
    return observation
