"""The ICS frame contract: one entry point that returns a Frame for every input."""

import pytest

from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.ics.frame import DECODERS, SEMANTICS, Field, Frame, decode_hex


def _three_adjacent_fields(raw: bytes) -> Frame:
    fields = (
        Field("a", "A", 0, 1, raw[0], None),
        Field("b", "B", 1, 2, int.from_bytes(raw[1:3], "big"), None),
        Field("c", "C", 3, 1, raw[3], None),
    )
    return Frame("fake", len(raw), fields, None, None, None, None, None, False)


@pytest.fixture
def fake_decoder(monkeypatch):
    monkeypatch.setitem(DECODERS, "fake", _three_adjacent_fields)


def test_field_ranges_are_ascending_non_overlapping_and_start_at_zero(fake_decoder):
    """Defect pinned: fields that overlap or leave a gap paint the wrong bytes on screen."""
    f = decode_hex("fake", "2b0e0100")
    ends = [0] + [x.offset + x.length for x in f.fields]
    assert [x.offset for x in f.fields] == ends[:-1]


def test_tail_offset_is_where_the_fields_stop(fake_decoder):
    """Defect pinned: a tail that starts elsewhere than the last field's end hides or doubles bytes."""
    f = decode_hex("fake", "2b0e0100")
    assert f.tail_offset in (None, f.fields[-1].offset + f.fields[-1].length)


def test_a_protocol_with_no_decoder_is_undecodable_not_an_error():
    """Defect pinned: an unknown protocol must yield a Frame, not a KeyError."""
    f = decode_hex("melsec", "0102")
    assert f.fields == () and f.semantics is None
    assert "no decoder" in f.tail_reason and f.tail_offset == 0


def test_hex_that_is_not_hex_is_undecodable_not_an_error():
    """Defect pinned: bad stored hex (incl. whitespace that bytes.fromhex would swallow) must not raise."""
    for bad in (None, "", "abc", "zz", "2b0e01 0"):
        f = decode_hex("modbus", bad)
        assert f.fields == () and f.tail_reason == "stored bytes are not valid hex"


def test_a_decoder_that_raises_is_contained(monkeypatch):
    """Defect pinned: a raising decoder would cost an ics_events row or a 500."""
    monkeypatch.setitem(
        DECODERS, "crashtest", lambda raw: (_ for _ in ()).throw(ValueError("boom"))
    )
    f = decode_hex("crashtest", "00")
    assert f.fields == () and "decoder failed" in f.tail_reason


def test_semantics_none_and_anomaly_are_different_statements():
    """Defect pinned: None (not in spec table) must not be conflated with 'anomaly'."""
    assert "anomaly" in SEMANTICS and None not in SEMANTICS
    assert SEMANTICS == (
        "read",
        "enumerate",
        "discovery",
        "write",
        "command",
        "control",
        "anomaly",
    )


def test_truncated_is_set_when_length_equals_the_capture_cap(monkeypatch):
    """Defect pinned: a capped capture must be flagged, or a cut frame reads as complete."""
    monkeypatch.setitem(DECODERS, "fake", _three_adjacent_fields)
    full = decode_hex("fake", "00" * MAX_RAW_EVENT_BYTES)
    short = decode_hex("fake", "00" * 8)
    assert full.truncated is True and short.truncated is False


def test_a_decoder_returning_a_non_frame_is_contained(monkeypatch):
    """Defect pinned: a decoder returning None raised AttributeError out of decode()."""
    monkeypatch.setitem(DECODERS, "broken", lambda raw: None)
    f = decode_hex("broken", "0102")
    assert isinstance(f, Frame) and f.fields == () and f.tail_reason
