"""OPC UA decoder: the secure-channel header and the request type NodeId of a MSG body."""

import pytest

from honeylens.ics import decode, decode_hex
from honeylens.ics import opcua as opcua_module
from tests.ics_frame_asserts import (
    assert_every_prefix_is_sane,
    assert_frame_sane,
    assert_value_types_are_stable,
    fuzz_decoder_directly,
)

CHANNEL = "01000000" + "01000000" + "02000000" + "03000000"  # channel, token, sequence, request id
GET_ENDPOINTS = CHANNEL + "0100" + "ac01" + "0000"  # FourByte NodeId ns=0 id=428, then header bytes


def test_get_endpoints_is_enumeration_and_names_the_request():
    """The observed OPC UA code (service id 428); the tail is the request header, unplaced."""
    f = decode_hex("opcua", GET_ENDPOINTS)
    assert f.code == 428 and f.semantics == "enumerate"
    by = {x.name: x for x in f.fields}
    assert by["secure_channel_id"].value == 1 and by["sequence_number"].value == 2
    assert by["request_id"].value == 3
    assert by["type_id"].value == 428 and by["type_id"].meaning == "GetEndpointsRequest"
    assert f.tail_offset == len(bytes.fromhex(GET_ENDPOINTS)) - 2
    assert "request header" in f.tail_reason
    raw = bytes.fromhex(GET_ENDPOINTS)
    tid = by["type_id"]
    assert raw[tid.offset : tid.offset + tid.length] == bytes.fromhex("ac01")


def test_two_byte_and_numeric_nodeids_give_the_same_type_id_field():
    """Defect class: type_id was an int for one NodeId encoding and something else for another."""
    two = decode_hex("opcua", CHANNEL + "00" + "ff")
    four = decode_hex("opcua", CHANNEL + "01" + "00" + "ac01")
    numeric = decode_hex("opcua", CHANNEL + "02" + "0000" + "ac010000")
    assert two.code == 255 and four.code == 428 and numeric.code == 428
    assert_value_types_are_stable([two, four, numeric])
    assert numeric.semantics == "enumerate" and two.semantics is None


def test_a_node_id_in_another_namespace_is_not_given_a_meaning():
    """Defect class: applying namespace 0 meanings to an id from namespace 2."""
    f = decode_hex("opcua", CHANNEL + "01" + "02" + "ac01" + "0000")
    assert f.code is None and f.semantics is None and f.sentence is None
    assert "namespace 2" in f.tail_reason and f.tail_offset == 20
    assert next(x for x in f.fields if x.name == "type_id").meaning is None


def test_a_string_nodeid_is_not_given_numeric_fields():
    f = decode_hex("opcua", CHANNEL + "03" + "0200" + "050000006162636465")
    assert f.code is None and f.semantics is None
    assert "0x03" in f.tail_reason and f.tail_offset == 17


def test_an_undefined_nodeid_encoding_is_an_anomaly():
    """Encoding bytes 0-5 (with flag bits) are defined; 0x07 is out of specification."""
    f = decode_hex("opcua", CHANNEL + "07" + "0000")
    assert f.semantics == "anomaly" and f.code is None
    assert "0x07" in f.tail_reason and "not defined" in f.tail_reason


def test_write_is_a_write_and_call_is_a_command_and_read_is_a_read():
    assert decode_hex("opcua", CHANNEL + "0100a102").semantics == "write"  # 673
    assert decode_hex("opcua", CHANNEL + "0100c802").semantics == "command"  # 712
    assert decode_hex("opcua", CHANNEL + "01007702").semantics == "read"  # 631


def test_a_frame_cut_before_and_inside_a_field_is_worded_accordingly():
    """Defect class: 'inside' for a field of which no byte was present."""
    raw = bytes.fromhex(GET_ENDPOINTS)
    before = decode("opcua", raw[:16])
    assert before.tail_offset == 16 and "before the type_node_encoding" in before.tail_reason
    inside = decode("opcua", raw[:19])  # encoding 01, namespace 00, one of two id bytes
    assert inside.tail_offset == 18 and "inside the type_id" in inside.tail_reason
    assert inside.code is None and inside.sentence is None
    mid_channel = decode("opcua", raw[:6])
    assert "inside the token_id" in mid_channel.tail_reason


def test_a_sentence_exists_only_when_the_type_was_read():
    """Defect: 'type None (frame cut short)'."""
    raw = bytes.fromhex(GET_ENDPOINTS)
    assert decode("opcua", raw[:10]).sentence is None
    assert decode("opcua", raw[:21]).sentence is not None


_TABLE = {
    **dict.fromkeys((422, 428, 527, 533, 554), "enumerate"),
    **dict.fromkeys((631, 664, 751), "read"),
    **dict.fromkeys((488, 494, 500, 506, 673, 700), "write"),
    712: "command",
}
_KNOWN_NO_SEMANTICS = (446, 452, 461, 467, 473, 479, 560, 566, 763, 769, 775, 781, 787, 793, 799)


@pytest.mark.parametrize(
    "service", [*_TABLE, *_KNOWN_NO_SEMANTICS, 613, 619, 421, 429, 9999, 65535]
)
def test_semantics_table_on_full_length_frames(service):
    """MITRE keys off this mapping; every assigned id is pinned, with neighbours either side."""
    raw = bytes.fromhex(CHANNEL + "01" + "00") + service.to_bytes(2, "little") + b"\x00"
    f = opcua_module.decode(raw)
    assert f.code == service and f.semantics == _TABLE.get(service)
    assert_frame_sane(f, raw)


def test_a_frame_cut_at_every_length_is_a_sane_frame():
    """Defect pinned: a frame cut at one particular byte made a decoder index past the end;
    random bytes rarely cut a valid frame at each boundary, so every boundary is walked."""
    for hex_ in (GET_ENDPOINTS, CHANNEL + "00ff", CHANNEL + "02" + "0000" + "ac010000"):
        assert_every_prefix_is_sane(opcua_module.decode, bytes.fromhex(hex_))


def test_empty_frame_is_undecodable():
    f = decode("opcua", b"")
    assert f.fields == () and f.tail_offset == 0


def test_no_input_is_ever_raised_from_the_decoder_itself():
    """Property: opcua.decode() directly, never through the dispatcher that contains errors."""
    fuzz_decoder_directly(
        opcua_module.decode, 4840, (b"", bytes.fromhex(CHANNEL), bytes.fromhex(CHANNEL + "01"))
    )
