"""`h2_prior_knowledge` must not be the label on a connection that failed.

Measured on `sensor-h`, 2026-11-13 13:35:50: `200.234.113.36` opened 40 HTTP/2
connections inside one second, every one of them ending on
``Error decoding header block: Incomplete Huffman string``. Eight carried 63 CONTINUATION
frames and so reached ``evaluate_49975``'s ``headers_count >= 50`` floor, earning
`cve_2026_49975_hpack_bomb`. The other 32 carried no CONTINUATION frame and 1-5 HEADERS,
never reached the floor, and fell through to `h2_prior_knowledge` — the verdict `decide()`
adds *only when nothing at all fired on a preface connection*.

Something did fire. A truncated Huffman-coded header block is the same attack delivered
without the CONTINUATION train, and the decoy recorded it exactly, in ``h2_error`` and
``h2_error_reason``. `decide()` reads counters only, so the reason was collected and never
scored, and 32 rows of a malformed-HPACK burst are indistinguishable in a hunt from an
idle client opening a connection and saying nothing.

The three `66.132.x.x` rows in the same corpus show what the baseline is *for*: 57 bytes,
zero streams, the peer resetting after the preface. Those are labelled correctly. The name
is right for 3 rows and wrong for 32, so the fix is a name for the failure, not the
removal of the baseline.

**The discriminator is the kind of error, not its presence.** A peer that goes away sent us
nothing; a peer that sends an undecodable header block sent us something. `h2`'s own
exception hierarchy already draws that line — every protocol-level failure is an
``h2.exceptions.H2Error`` and ``ConnectionResetError`` is not — so the decoy records which
side of it the failure fell on, rather than `decide()` guessing from a string. That also
keeps a bug of *ours* from being published as an attacker's verdict.
"""

from __future__ import annotations

import h2.exceptions
import pytest

from honeylens.honeypots.h2_capture import H2Observation, decide, is_protocol_error


def _classify_none(path, body, headers):
    return None


def _obs(**kw) -> H2Observation:
    kw.setdefault("entry", "preface")
    return H2Observation(**kw)


def _failed_header_block(**kw) -> H2Observation:
    """One of the 32: a header block that could not be decoded, and nothing else."""
    kw.setdefault("headers_frames", 1)
    kw.setdefault("frames_total", 3)
    kw.setdefault("streams_opened", 1)
    kw.setdefault("continuation_frames", 0)
    kw.setdefault("shape_matches", 0)
    kw.setdefault("rst_stream_total", 0)
    return _obs(
        h2_error="ProtocolError",
        h2_error_reason="Error decoding header block: Incomplete Huffman string",
        h2_error_protocol=True,
        goaway_reason="protocol_error",
        **kw,
    )


# ---------------------------------------------------------------------------
# The line h2's own hierarchy draws
# ---------------------------------------------------------------------------


def test_an_h2_protocol_failure_is_recognised_as_one():
    """Real exception objects, not names: this is the library's own classification."""
    assert is_protocol_error(h2.exceptions.ProtocolError("Error decoding header block"))
    assert is_protocol_error(h2.exceptions.FrameDataMissingError("Frame data missing"))


def test_a_peer_going_away_is_not_a_protocol_failure():
    assert not is_protocol_error(ConnectionResetError(104, "Connection reset by peer"))
    assert not is_protocol_error(TimeoutError())


def test_a_failure_of_ours_is_not_a_protocol_failure():
    """Our own bug must never be published as something the attacker did."""
    assert not is_protocol_error(TypeError("unsupported operand type(s)"))


# ---------------------------------------------------------------------------
# The 32, the 8, and the 3
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("headers_frames", "frames_total"), [(1, 3), (2, 4), (5, 11), (4, 6), (0, 3)]
)
def test_a_malformed_header_block_is_not_prior_knowledge(headers_frames, frames_total):
    """The five observed sub-shapes of the 32, by their measured frame counts."""
    obs = _failed_header_block(headers_frames=headers_frames, frames_total=frames_total)
    verdicts, severity = decide(obs, _classify_none)

    assert "h2_prior_knowledge" not in verdicts, (
        "the row still claims nothing happened on a connection that failed to decode"
    )
    assert verdicts == ["h2_protocol_error"]
    assert severity == "LOW", "a malformed header block on its own exhausts nothing"


def test_the_same_burst_with_the_continuation_train_is_still_the_bomb():
    """The 8. Guards against over-correcting: the bomb already explains the volume, so
    adding a second name for the same connection would count one fact twice."""
    obs = _failed_header_block(headers_frames=4, frames_total=69, continuation_frames=63)
    verdicts, severity = decide(obs, _classify_none)

    assert verdicts == ["cve_2026_49975_hpack_bomb"]
    assert severity == "MEDIUM"


def test_a_peer_that_resets_after_the_preface_is_still_prior_knowledge():
    """The 3 x `66.132.x.x`: 57 bytes in, zero streams, no header block ever sent.

    This is the case that makes "any h2_error becomes a verdict" wrong. Nothing was
    offered to us, so the baseline is the honest label and must not move.
    """
    obs = _obs(
        headers_frames=0,
        frames_total=1,
        streams_opened=0,
        bytes_in=57,
        h2_error="ConnectionResetError",
        h2_error_reason="[Errno 104] Connection reset by peer",
        h2_error_protocol=False,
        goaway_reason="protocol_error",
    )
    verdicts, severity = decide(obs, _classify_none)

    assert verdicts == ["h2_prior_knowledge"]
    assert severity == "LOW"


def test_a_decoy_side_failure_does_not_become_an_attacker_verdict():
    """A `TypeError` in our own capture path is not evidence about the client."""
    obs = _obs(
        headers_frames=1,
        frames_total=3,
        h2_error="TypeError",
        h2_error_reason="unsupported operand type(s)",
        h2_error_protocol=False,
    )
    verdicts, _severity = decide(obs, _classify_none)

    assert verdicts == ["h2_prior_knowledge"]


def test_a_clean_connection_that_said_nothing_is_still_prior_knowledge():
    """No error at all: the baseline's original and correct case."""
    verdicts, severity = decide(_obs(headers_frames=0), _classify_none)
    assert verdicts == ["h2_prior_knowledge"] and severity == "LOW"


# ---------------------------------------------------------------------------
# The two rules this change must not break
# ---------------------------------------------------------------------------


def test_an_upgraded_connection_that_failed_still_gets_the_protocol_error():
    """The baseline is withheld from `upgrade` because the upgrade request's own row names
    that connection. It does not say the peer then sent an undecodable header block, so
    this name is not withheld — otherwise the H2 row carries no verdict at all.
    """
    obs = _failed_header_block(entry="upgrade")
    verdicts, _severity = decide(obs, _classify_none)

    assert verdicts == ["h2_protocol_error"]
    assert "h2_prior_knowledge" not in verdicts


def test_an_upgraded_connection_with_nothing_wrong_still_gets_no_baseline():
    """Unchanged behaviour, asserted here because the branch is being edited."""
    verdicts, _severity = decide(_obs(entry="upgrade", headers_frames=1), _classify_none)
    assert verdicts == []


@pytest.mark.parametrize(
    "obs_factory",
    [
        lambda: _failed_header_block(),
        lambda: _failed_header_block(headers_frames=4, frames_total=69, continuation_frames=63),
        lambda: _obs(headers_frames=0, h2_error="ConnectionResetError", h2_error_protocol=False),
        lambda: _obs(headers_frames=0),
    ],
    ids=["the-32", "the-8", "the-3", "clean"],
)
def test_no_preface_connection_is_left_without_a_verdict(obs_factory):
    """Removing a wrong label must not leave a gap: three times in this project a bad
    verdict turned out to be the row's only verdict."""
    verdicts, _severity = decide(obs_factory(), _classify_none)
    assert verdicts, "the row would reach the store with no verdict at all"
