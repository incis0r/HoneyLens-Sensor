"""The protocol/transport discriminator has to survive into the row, and into both paths.

`h2_protocol_error` is decided from `H2Observation.h2_error_protocol`, which `observe()`
sets from `is_protocol_error(exc)` — see
`test_h2_baseline_is_not_for_failed_connections.py` for why the distinction exists at all
(32 of 40 connections from one source were labelled `h2_prior_knowledge` after dying on
``Error decoding header block: Incomplete Huffman string``).

Two things that file does not cover, because it tests `decide()` on an observation built
by hand:

**The row has to carry the discriminator.** `h2_error` and `h2_error_reason` reach
`metadata`; without `h2_error_protocol` beside them a hunt cannot ask which failures were
the peer's protocol and which were a reset or a bug of ours, and the only remaining
evidence is a verdict name — recoverable, but a verdict is a lossy summary and
`h2_error_reason` is a free-text message nobody should be matching on.

**`observe()` is not the only place an exception is caught.** `hp_http` has a second
handler for one that escapes the capture entirely, and it sets `h2_error` and
`h2_error_reason` without the discriminator. That path is reached only after the 101 has
gone out, so `entry == "upgrade"` and the baseline is withheld by design — which means an
``H2Error`` arriving there would have produced a row with **no verdict at all**, the
failure mode `removing-a-wrong-label-leaves-a-gap` names three times over.
"""

from __future__ import annotations

import h2.exceptions
import pytest

from honeylens.honeypots import h2_capture, hp_http

from .test_hp_http_h2 import _client_bytes, _h2c_upgrade_bytes, _run_h2

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _frame(ftype: int, flags: int, stream: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([ftype, flags])
        + stream.to_bytes(4, "big")
        + payload
    )


def _undecodable_header_block() -> bytes:
    """A real client's preface, then a HEADERS frame HPACK cannot decode.

    ``0x40`` is "literal header field with incremental indexing, new name"; ``0x8a``
    announces a 10-byte Huffman-coded name and only two bytes follow. `h2` raises
    ``ProtocolError("Error decoding header block: ...")`` — the shape measured on
    `sensor-h`, produced here by the library rather than asserted from a string.
    """
    return PREFACE + _frame(0x04, 0x00, 0, b"") + _frame(0x01, 0x05, 1, b"\x40\x8a\xff\xff")


def _one(seen: list[dict]) -> dict:
    assert len(seen) == 1, f"expected exactly one row, got {len(seen)}"
    return seen[0]["data"]


# ---------------------------------------------------------------------------
# The row carries the discriminator
# ---------------------------------------------------------------------------


def test_the_row_says_the_failure_was_the_peers_protocol(monkeypatch):
    event = _one(_run_h2(monkeypatch, _undecodable_header_block()))

    assert event["h2_error"] == "ProtocolError"
    assert event["h2_error_protocol"] is True, (
        "the row records the message but not which side of the line it fell on"
    )
    assert event["h2_verdicts"] == ["h2_protocol_error"]


def test_the_row_says_so_when_nothing_went_wrong(monkeypatch):
    """Present and False, not absent: a missing key and "no protocol error" are the same
    reading in SQL, and the second one is a claim."""
    event = _one(_run_h2(monkeypatch, _client_bytes([])))

    assert event["h2_error"] is None
    assert event["h2_error_protocol"] is False


# ---------------------------------------------------------------------------
# The second handler, after the 101
# ---------------------------------------------------------------------------


def _upgrade_where_capture_raises(monkeypatch, exc: BaseException) -> dict:
    async def boom(*_a, **_kw):
        raise exc

    monkeypatch.setattr(h2_capture, "observe", boom)
    monkeypatch.setattr(hp_http.h2_capture, "observe", boom, raising=False)
    return _one(_run_h2(monkeypatch, _h2c_upgrade_bytes("/")))


def test_a_protocol_error_escaping_the_capture_still_names_itself(monkeypatch):
    event = _upgrade_where_capture_raises(
        monkeypatch, h2.exceptions.ProtocolError("Error decoding header block")
    )

    assert event["h2_error"] == "ProtocolError"
    assert event["h2_error_protocol"] is True
    # `h2c_upgrade_recon` is the upgrade *request*'s own verdict, merged in by `_log_h2`
    # after `decide()` has run; both names are true of this connection and neither
    # subsumes the other, so the assertion is membership, not equality.
    assert "h2_protocol_error" in event["h2_verdicts"], (
        "an upgraded connection withholds the baseline, so without this the row reaches "
        "the store with no verdict for the failure at all"
    )
    assert "h2_prior_knowledge" not in event["h2_verdicts"]


@pytest.mark.parametrize(
    "exc",
    [TypeError("unsupported operand type(s)"), ConnectionResetError(104, "reset by peer")],
    ids=["our-bug", "transport"],
)
def test_a_failure_that_is_not_the_peers_protocol_earns_no_verdict_there(monkeypatch, exc):
    """The fix must not turn every escaped exception into an attacker's verdict."""
    event = _upgrade_where_capture_raises(monkeypatch, exc)

    assert event["h2_error_protocol"] is False
    assert "h2_protocol_error" not in event["h2_verdicts"]
