"""EtherNet/IP decoder: the 24-byte encapsulation header, and the CIP service in SendRRData."""

import struct

import pytest

from honeylens.ics import decode
from honeylens.ics import enip as enip_module
from tests.ics_frame_asserts import (
    assert_every_prefix_is_sane,
    assert_frame_sane,
    assert_value_types_are_stable,
    fuzz_decoder_directly,
)


def encap(command: int, data: bytes = b"", session: int = 0, status: int = 0) -> bytes:
    """A complete encapsulation frame whose length field matches its data."""
    return struct.pack("<HHII8sI", command, len(data), session, status, b"\x01" * 8, 0) + data


def rr_data(cip: bytes) -> bytes:
    """SendRRData command-specific data: interface handle, timeout, null address, B2 item."""
    cpf = struct.pack("<HHHHH", 2, 0, 0, 0x00B2, len(cip)) + cip
    return struct.pack("<IH", 0, 5) + cpf


GET_ATTR = bytes([0x0E, 0x02, 0x20, 0x01, 0x24, 0x01])  # class 1 instance 1
WRITE_TAG = bytes([0x4D, 0x03, 0x91, 0x04]) + b"tag1" + bytes([0xC3, 0x00, 0x01, 0x00, 0x05, 0x00])
READ_TAG = bytes([0x4C, 0x03, 0x91, 0x04]) + b"tag1" + bytes([0x01, 0x00])


def test_list_identity_is_discovery_and_fully_placed():
    """The observed ENIP command (0x63); it is the broadcast that maps devices on a network."""
    f = decode("enip", encap(0x63))
    assert f.code == 0x63 and f.semantics == "discovery" and f.tail_offset is None
    by = {x.name: x for x in f.fields}
    assert by["command"].meaning == "ListIdentity" and by["sender_context"].value == "01" * 8
    assert f.fields[0].offset == 0 and f.fields[-1].offset + f.fields[-1].length == 24


def test_list_services_and_list_interfaces_are_enumeration():
    assert decode("enip", encap(0x04)).semantics == "enumerate"
    assert decode("enip", encap(0x64)).semantics == "enumerate"


def test_register_session_places_protocol_version_and_options():
    f = decode("enip", encap(0x65, struct.pack("<HH", 1, 0)))
    assert f.code == 0x65 and f.tail_offset is None
    assert {x.name: x.value for x in f.fields}["protocol_version"] == 1


def test_send_rr_data_reads_the_cip_service_it_carries():
    """Defect class: the decoy hid the CIP service in a separate key; the decoder reads the bytes."""
    f = decode("enip", encap(0x6F, rr_data(GET_ATTR), session=7))
    assert f.code == 0x6F and f.semantics == "read" and f.tail_offset is None
    by = {x.name: x for x in f.fields}
    assert by["cip_service"].value == 0x0E and by["cip_service"].meaning == "Get_Attribute_Single"
    assert by["request_path"].value == "20012401"
    assert f.sentence == "Sends the CIP service Get_Attribute_Single to the device"


def test_a_symbolic_tag_write_is_a_write_but_the_same_service_on_a_class_path_is_not_assumed():
    """Services 0x4b-0x63 are object-specific: only the symbolic segment confirms Logix tags.

    Defect class: applying one object's service table regardless of the target class."""
    tag = decode("enip", encap(0x6F, rr_data(WRITE_TAG)))
    assert tag.semantics == "write" and tag.tail_offset is not None
    assert next(x for x in tag.fields if x.name == "cip_service").meaning == "Write Tag"
    elsewhere = decode("enip", encap(0x6F, rr_data(bytes([0x4D, 0x02, 0x20, 0x01, 0x24, 0x01]))))
    assert elsewhere.semantics is None and elsewhere.code == 0x6F
    assert "object-specific" in elsewhere.sentence
    assert decode("enip", encap(0x6F, rr_data(READ_TAG))).semantics == "read"


def test_a_cip_response_in_a_request_frame_is_not_given_request_meaning():
    f = decode("enip", encap(0x6F, rr_data(bytes([0x8E, 0x00, 0x00, 0x00]))))
    assert f.semantics is None
    assert next(x for x in f.fields if x.name == "cip_service").meaning is None


def test_a_reserved_command_is_an_anomaly_and_legacy_is_not():
    """Defect: legacy commands were an anomaly while the reason text said the specification
    reserves them. Reserved is in the specification: semantics None, not out of it."""
    legacy = decode("enip", encap(0x0001, b"\x00\x00"))
    reserved = decode("enip", encap(0x1234, b"\x00\x00"))
    assert legacy.semantics is None and reserved.semantics == "anomaly"
    assert legacy.code == 0x0001 and "does not define" not in legacy.sentence
    assert "legacy" in legacy.tail_reason and "legacy" not in reserved.tail_reason
    assert legacy.tail_offset == 24 and reserved.code == 0x1234


def test_defined_commands_without_an_intent_have_no_semantics_and_are_not_anomalies():
    for cmd in (0x0000, 0x0066, 0x0070, 0x0072, 0x0073):
        f = decode("enip", encap(cmd))
        assert f.semantics is None, hex(cmd)


def test_bytes_after_the_encapsulation_length_go_to_the_tail():
    raw = encap(0x63) + b"\xde\xad"
    f = decode("enip", raw)
    assert f.tail_offset == 24 and "after the encapsulation length of 0" in f.tail_reason


def test_a_length_longer_than_the_capture_is_a_truncated_frame_not_an_error():
    raw = struct.pack("<HHII8sI", 0x6F, 200, 0, 0, b"\0" * 8, 0) + b"\x00\x00\x00\x00"
    f = decode("enip", raw)
    assert f.code == 0x6F and f.tail_offset == 28
    assert "before the timeout" in f.tail_reason
    assert all(x.offset + x.length <= len(raw) for x in f.fields)


def test_a_frame_cut_before_and_inside_a_header_field():
    """Defect class: 'inside' used where no byte of the field was present."""
    raw = encap(0x63)
    before = decode("enip", raw[:12])  # status complete, sender_context absent
    assert before.tail_offset == 12 and "before the sender_context" in before.tail_reason
    inside = decode("enip", raw[:16])
    assert inside.tail_offset == 12 and "inside the sender_context" in inside.tail_reason
    assert inside.code == 0x63 and inside.sentence == "ListIdentity (frame cut short)"
    one = decode("enip", raw[:1])
    assert one.code is None and one.sentence is None and "inside the command" in one.tail_reason


def test_send_rr_data_with_another_item_layout_is_not_given_cip_fields():
    """Never apply a sub-layout that was not confirmed: report the item type seen."""
    cpf = struct.pack("<HHHHH", 2, 0xA1, 4, 0x00B1, 0) + b"\x01\x02\x03\x04"
    f = decode("enip", encap(0x6F, struct.pack("<IH", 0, 5) + cpf))
    assert not any(x.name == "cip_service" for x in f.fields)
    assert "0x00a1" in f.tail_reason and f.semantics is None


def test_send_rr_data_cut_inside_the_request_path_keeps_what_fits():
    full = encap(0x6F, rr_data(GET_ATTR))
    cut = decode("enip", full[:-2])
    assert cut.semantics == "read" and cut.tail_offset is not None
    assert "request_path" in cut.tail_reason
    assert_frame_sane(cut, full[:-2])


_COMMANDS = {
    0x0000: None,
    0x0004: "enumerate",
    0x0063: "discovery",
    0x0064: "enumerate",
    0x0065: "enumerate",
    0x0066: None,
    0x0070: None,
    0x0072: None,
    0x0073: None,
}


@pytest.mark.parametrize(
    "cmd", [*_COMMANDS, 0x006F, 0x0001, 0x0003, 0x0005, 0x0062, 0x0067, 0x0071, 0x0074, 0xFFFF]
)
def test_command_semantics_table_on_full_length_frames(cmd):
    """MITRE keys off this; pin every defined command and the reserved neighbours either side."""
    data = struct.pack("<HH", 1, 0) if cmd == 0x65 else b""
    raw = encap(cmd, rr_data(GET_ATTR) if cmd == 0x6F else data)
    f = enip_module.decode(raw)
    assert f.code == cmd
    legacy = cmd in (0x0001, 0x0002, 0x0003)  # reserved by the specification: in it, so None
    if cmd == 0x6F:
        expected = "read"
    elif legacy:
        expected = None
    else:
        expected = "anomaly" if cmd not in _COMMANDS else _COMMANDS[cmd]
    assert f.semantics == expected
    assert_frame_sane(f, raw)


_CIP = {0x01: "read", 0x02: "write", 0x03: "read", 0x04: "write", 0x05: "control", 0x06: "control",
        0x07: "control", 0x08: "write", 0x09: "write", 0x0E: "read", 0x10: "write"}  # fmt: skip


@pytest.mark.parametrize("service", [*_CIP, 0x0A, 0x0B, 0x31, 0x32, 0x4B, 0x54, 0x7F])
def test_common_cip_service_table_on_full_length_frames(service):
    cip = bytes([service, 0x02, 0x20, 0x01, 0x24, 0x01])
    f = enip_module.decode(encap(0x6F, rr_data(cip)))
    assert f.semantics == _CIP.get(service)


def test_a_frame_cut_at_every_length_is_a_sane_frame():
    """Defect pinned: a frame cut at one particular byte made a decoder index past the end;
    random bytes rarely cut a valid frame at each boundary, so every boundary is walked."""
    for raw in (
        encap(0x63),
        encap(0x65, struct.pack("<HH", 1, 0)),
        encap(0x6F, rr_data(GET_ATTR)),
        encap(0x6F, rr_data(WRITE_TAG)),
    ):
        assert_every_prefix_is_sane(enip_module.decode, raw)


def test_value_types_do_not_depend_on_length():
    frames = [
        decode("enip", encap(0x63)),
        decode("enip", encap(0x65, struct.pack("<HH", 1, 0))),
        decode("enip", encap(0x6F, rr_data(GET_ATTR))),
        decode("enip", encap(0x6F, rr_data(WRITE_TAG))),
    ]
    assert_value_types_are_stable(frames)


def test_empty_frame_is_undecodable():
    f = decode("enip", b"")
    assert f.fields == () and f.tail_offset == 0 and f.code is None


def test_no_input_is_ever_raised_from_the_decoder_itself():
    """Property: enip.decode() directly, never through the dispatcher that contains errors."""
    fuzz_decoder_directly(
        enip_module.decode,
        44818,
        (b"", b"\x6f\x00", encap(0x6F)[:24], encap(0x6F, rr_data(GET_ATTR))[:36]),
    )


def test_a_short_data_item_is_not_called_a_cut_frame():
    """Defect: with a data item declaring 0 bytes and four more bytes inside the encapsulation
    length, the reason said the frame ended inside cip_service; no byte of it was missing."""
    cpf = struct.pack("<HHHHH", 2, 0, 0, 0x00B2, 0) + b"\xde\xad\xbe\xef"
    raw = encap(0x6F, struct.pack("<IH", 0, 5) + cpf)
    f = decode("enip", raw)
    assert f.tail_offset == raw.index(b"\xde\xad\xbe\xef")
    assert "data item declares 0 byte(s)" in f.tail_reason
    assert "frame ends" not in f.tail_reason and "cip_service" in f.tail_reason
