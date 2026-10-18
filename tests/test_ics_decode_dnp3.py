"""DNP3 decoder: the data link header, the transport and application control, the function code."""

import struct

import pytest

from honeylens.ics import decode
from honeylens.ics import dnp3 as dnp3_module
from tests.ics_frame_asserts import (
    assert_every_prefix_is_sane,
    assert_frame_sane,
    assert_value_types_are_stable,
    fuzz_decoder_directly,
)


def crc(data: bytes) -> int:
    """CRC-16/DNP, bitwise and independent of the decoder: reflected poly 0xA6BC, output xor."""
    reg = 0
    for byte in data:
        reg ^= byte
        for _ in range(8):
            reg = (reg >> 1) ^ 0xA6BC if reg & 1 else reg >> 1
    return reg ^ 0xFFFF


def frame(user: bytes, control: int = 0xC4, dst: int = 1, src: int = 1024, bad_crc=False) -> bytes:
    """A wire-accurate link frame: header + CRC, then 16-byte blocks each followed by a CRC."""
    head = bytes([0x05, 0x64, len(user) + 5, control]) + struct.pack("<HH", dst, src)
    out = head + struct.pack("<H", crc(head) ^ (1 if bad_crc else 0))
    for i in range(0, len(user), 16):
        block = user[i : i + 16]
        out += block + struct.pack("<H", crc(block))
    return out


def app(fc: int, objects: bytes = b"", ctrl: int = 0xC0, transport: int = 0xC0) -> bytes:
    return bytes([transport, ctrl, fc]) + objects


def test_the_crc_matches_the_published_check_value():
    """CRC-16/DNP of '123456789' is 0xEA82; the test's own CRC must agree before it is trusted."""
    assert crc(b"123456789") == 0xEA82


def test_delay_measurement_is_enumeration():
    """The observed DNP3 code (FC 23): a timing probe of the outstation."""
    raw = frame(app(23))
    f = decode("dnp3", raw)
    assert f.code == 23 and f.semantics == "enumerate"
    by = {x.name: x for x in f.fields}
    assert by["function_code"].value == 23 and by["function_code"].meaning == "Delay Measurement"
    assert by["destination"].value == 1 and by["source"].value == 1024
    assert by["start"].value == "0564" and "valid" in by["header_crc"].meaning
    assert by["function_code"].offset == 12 and f.tail_offset is None


def test_a_bad_header_crc_is_shown_not_rejected():
    """Scanners send bad CRCs; the decoder must still decode and say the CRC does not match."""
    f = decode("dnp3", frame(app(1), bad_crc=True))
    assert f.semantics == "read"
    assert "does not match" in next(x for x in f.fields if x.name == "header_crc").meaning


def test_read_is_a_read_and_objects_are_left_in_the_tail():
    f = decode("dnp3", frame(app(1, bytes([1, 2, 6]))))
    assert f.semantics == "read" and f.tail_offset == 13
    assert "object" in f.tail_reason


def test_operate_commands_restarts_and_unsolicited_control():
    assert decode("dnp3", frame(app(4))).semantics == "command"
    assert decode("dnp3", frame(app(13))).semantics == "control"
    assert decode("dnp3", frame(app(21))).semantics == "control"
    assert decode("dnp3", frame(app(2))).semantics == "write"


def test_a_continuation_segment_is_not_given_application_fields():
    """The first byte of a non-first segment is not an application control byte.

    Defect class: reading control/function from a segment whose FIR bit is clear."""
    f = decode("dnp3", frame(app(13, transport=0x01)))
    names = [x.name for x in f.fields]
    assert "function_code" not in names and "app_control" not in names
    assert f.code is None and f.semantics is None and "FIR" in f.tail_reason
    assert f.tail_offset == 11


def test_a_link_status_request_has_no_application_layer():
    f = decode("dnp3", frame(b"", control=0xC9))
    assert f.semantics == "discovery" and f.tail_offset is None
    assert next(x for x in f.fields if x.name == "link_control").value == 0xC9


def test_a_response_function_code_sent_as_a_request_is_an_anomaly_worded_as_a_response():
    """Defect class: 'not in the specification' for a code the specification defines."""
    f = decode("dnp3", frame(app(129)))
    assert f.semantics == "anomaly" and f.code == 129
    assert "response" in f.sentence and "not in the" not in f.sentence
    with_objects = decode("dnp3", frame(app(129, b"\x01\x02")))
    assert "response" in with_objects.tail_reason and "not in the" not in with_objects.tail_reason


def test_a_reserved_function_code_is_an_anomaly_worded_as_reserved():
    f = decode("dnp3", frame(app(200)))
    assert f.semantics == "anomaly" and f.code == 200 and "reserves" in f.sentence
    assert "response" not in f.sentence


def test_a_length_field_that_leaves_no_room_for_the_application_layer():
    f = decode("dnp3", frame(b"\xc0\xc0"))
    names = [x.name for x in f.fields]
    assert names[-2:] == ["transport_header", "app_control"] and f.code is None
    assert f.tail_offset == 12 and "only 2 byte(s) of user data" in f.tail_reason


def test_user_data_under_a_non_user_data_link_function_is_not_given_application_fields():
    """A link function other than 3 or 4 carries no user data; the layout is not assumed."""
    f = decode("dnp3", frame(app(13), control=0xC0))  # primary, function 0: reset link
    assert not any(x.name == "function_code" for x in f.fields)
    assert f.code is None and f.semantics is None and f.tail_offset == 10
    assert "0xc0" in f.tail_reason


def test_a_frame_that_is_not_a_link_frame_is_not_decoded():
    """Never apply the link layout without the 0x0564 start bytes: report what was seen."""
    f = decode("dnp3", b"\x01\x02\x03\x04")
    assert f.fields == () and f.tail_offset == 0 and "0x0102" in f.tail_reason


def test_a_frame_cut_before_and_inside_a_field():
    """Defect class: 'inside' for a field of which no byte was present."""
    raw = frame(app(13))
    before = decode("dnp3", raw[:2])
    assert before.tail_offset == 2 and "before the length" in before.tail_reason
    inside = decode("dnp3", raw[:5])  # destination is bytes 4-5
    assert inside.tail_offset == 4 and "inside the destination" in inside.tail_reason
    assert before.sentence is None and before.code is None
    fc_missing = decode("dnp3", raw[:12])
    assert "before the function_code" in fc_missing.tail_reason and fc_missing.code is None


_REQUESTS = {
    0: None, 1: "read", 2: "write", 3: "command", 4: "command", 5: "command", 6: "command",
    7: "command", 8: "command", 9: "command", 10: "command", 11: "command", 12: "command",
    13: "control", 14: "control", 15: None, 16: "control", 17: "control", 18: "control",
    19: None, 20: "control", 21: "control", 22: "write", 23: "enumerate", 24: "command",
    25: "read", 26: None, 27: "write", 28: "enumerate", 29: None, 30: None, 31: "command",
    32: None, 33: None,
}  # fmt: skip


@pytest.mark.parametrize("fc", [*_REQUESTS, 34, 35, 100, 128, 129, 130, 131, 132, 255])
def test_function_code_table_on_full_length_frames(fc):
    """MITRE keys off this mapping; every assigned code and the reserved boundaries are pinned."""
    raw = frame(app(fc))
    f = dnp3_module.decode(raw)
    assert f.code == fc
    expected = _REQUESTS[fc] if fc in _REQUESTS else "anomaly"
    assert f.semantics == expected
    assert_frame_sane(f, raw)


def test_a_frame_cut_at_every_length_is_a_sane_frame():
    for raw in (frame(app(1, bytes(range(40)))), frame(app(23)), frame(b"", control=0xC9)):
        assert_every_prefix_is_sane(dnp3_module.decode, raw)


def test_value_types_do_not_depend_on_length():
    frames = [decode("dnp3", frame(u)) for u in (app(1), app(1, bytes(30)), app(23), b"")]
    assert_value_types_are_stable(frames)


def test_empty_frame_is_undecodable():
    f = decode("dnp3", b"")
    assert f.fields == () and f.tail_offset == 0


def test_no_input_is_ever_raised_from_the_decoder_itself():
    """Property: dnp3.decode() directly, never through the dispatcher that contains errors."""
    fuzz_decoder_directly(
        dnp3_module.decode, 20000, (b"", b"\x05\x64", frame(app(1))[:10], frame(app(1))[:13])
    )
