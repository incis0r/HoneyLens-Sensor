"""BACnet decoder: PDU type, service choice, object and property of a read or write."""

import pytest

from honeylens.ics import bacnet as bacnet_module
from honeylens.ics import decode, decode_hex
from tests.ics_frame_asserts import (
    assert_every_prefix_is_sane,
    assert_frame_sane,
    assert_value_types_are_stable,
    fuzz_decoder_directly,
)

READ_PROPERTY = "0005010c" + "0c02000001" + "1955"  # present-value of device 1
WRITE_PROPERTY = "0005020f" + "0c00400001" + "1955" + "3e4442c800003f"
WHO_IS = "1008"


def test_read_property_is_a_read_and_names_the_object_and_property():
    """The one BACnet code the sensors see (service 12); the screen must say what it reads."""
    f = decode_hex("bacnet", READ_PROPERTY)
    assert f.code == 12 and f.semantics == "read" and f.tail_offset is None
    by = {x.name: x for x in f.fields}
    assert by["invoke_id"].value == 1 and by["service_choice"].meaning == "ReadProperty"
    assert by["object_identifier"].meaning == "device" and by["object_identifier"].value == "8,1"
    assert (
        by["property_identifier"].value == 85
        and by["property_identifier"].meaning == "present-value"
    )
    assert f.sentence == "Reads present-value of device 1"
    raw = bytes.fromhex(READ_PROPERTY)
    obj = by["object_identifier"]
    assert raw[obj.offset : obj.offset + obj.length] == bytes.fromhex("0c02000001")


def test_write_property_is_a_write_and_leaves_its_value_in_the_tail():
    """The value encoding is not decoded, so it is reported as unplaced rather than invented."""
    f = decode_hex("bacnet", WRITE_PROPERTY)
    assert f.code == 15 and f.semantics == "write"
    assert f.sentence == "Writes present-value of analog-output 1"
    assert f.tail_offset == bytes.fromhex(WRITE_PROPERTY).index(0x3E)
    assert "byte(s) after the fields decoded" in f.tail_reason


def test_who_is_is_discovery_and_shares_code_8_with_a_confirmed_service():
    """Confirmed and unconfirmed services number separately; semantics must follow the PDU type."""
    f = decode_hex("bacnet", WHO_IS)
    assert f.code == 8 and f.semantics == "discovery" and f.tail_offset is None
    g = decode_hex("bacnet", "00050108")
    assert g.code == 8 and g.semantics == "write"  # AddListElement


def test_a_frame_cut_inside_a_field_says_inside_and_one_cut_before_says_before():
    """Defect class: 'inside' was written for fields of which no byte was present."""
    raw = bytes.fromhex(READ_PROPERTY)
    inside = decode("bacnet", raw[:8])  # object identifier cut after 3 of 5 bytes
    assert inside.tail_offset == 4
    assert "inside the object_identifier" in inside.tail_reason
    before = decode("bacnet", raw[:9])  # object complete, no property tag at all
    assert before.tail_offset == 9 and "before the property_identifier" in before.tail_reason
    assert all(x.offset + x.length <= 9 for x in before.fields)
    short = decode("bacnet", raw[:2])  # PDU type and max-response only
    assert "before the invoke_id" in short.tail_reason


def test_a_cut_frame_has_a_sentence_if_and_only_if_the_service_was_read():
    """Defect: 'type None (frame cut short)' was emitted when no code had been read."""
    raw = bytes.fromhex(READ_PROPERTY)
    assert decode("bacnet", raw[:3]).sentence is None and decode("bacnet", raw[:3]).code is None
    cut = decode("bacnet", raw[:6])
    assert cut.code == 12 and cut.sentence == "ReadProperty (frame cut short)"


def test_a_reserved_pdu_type_is_an_anomaly_and_its_bytes_are_not_placed():
    f = decode_hex("bacnet", "9000112233")
    assert f.semantics == "anomaly" and f.code is None
    assert f.tail_offset == 1 and "reserved" in f.tail_reason


def test_response_pdus_are_defined_but_not_decoded_and_are_not_anomalies():
    """Defect class: 'not in the specification' written for a PDU the specification defines."""
    f = decode_hex("bacnet", "2001ff")
    assert f.semantics is None and "Simple-ACK" in f.tail_reason
    assert "not in the" not in f.tail_reason


def test_an_unassigned_service_choice_has_no_semantics_and_is_not_an_anomaly():
    """Unassigned is not illegal: None says 'I do not know', anomaly says 'out of spec'."""
    f = decode_hex("bacnet", "000501ee0102")
    assert f.code == 0xEE and f.semantics is None and f.tail_offset == 4
    assert "not assigned" in f.tail_reason
    g = decode_hex("bacnet", "10ee")
    assert g.code == 0xEE and g.semantics is None


def test_a_segmented_request_places_sequence_and_window_before_the_service():
    """Defect class: reading byte 3 as the service of a segmented request mislabels it."""
    f = decode_hex("bacnet", "080a0105020c")
    names = [x.name for x in f.fields]
    assert names[-3:] == ["sequence_number", "window_size", "service_choice"]
    assert f.code == 12


def test_a_property_request_with_the_wrong_tag_is_not_given_object_fields():
    """Never apply a sub-layout that was not confirmed: the tag byte names the value seen."""
    f = decode_hex("bacnet", "0005010c" + "ff02000001")
    assert not any(x.name == "object_identifier" for x in f.fields)
    assert f.tail_offset == 4 and "0xff" in f.tail_reason


_CONFIRMED = {
    **dict.fromkeys((3, 4, 29), "enumerate"),
    **dict.fromkeys((5, 6, 12, 13, 14, 26, 28, 30, 33), "read"),
    **dict.fromkeys((7, 8, 9, 10, 11, 15, 16), "write"),
    **dict.fromkeys((17, 20), "control"),
    27: "command",
}
_UNCONFIRMED = {6: "command", 9: "command", 7: "discovery", 8: "discovery", 10: "write"}


def _full(confirmed: bool, code: int) -> bytes:
    if confirmed:
        raw = bytes([0x00, 0x05, 0x01, code])
        if code in (12, 15):
            raw += bytes.fromhex("0c000000011955")
        return raw
    return bytes([0x10, code])


@pytest.mark.parametrize("code", [*range(0, 34), 34, 100, 255])
def test_confirmed_semantics_table_on_full_length_frames(code):
    """MITRE keys off this mapping; pin every assigned service and the boundary at 33/34."""
    f = bacnet_module.decode(_full(True, code))
    assert f.code == code
    assert f.semantics == _CONFIRMED.get(code)
    assert_frame_sane(f, _full(True, code))
    if code in (12, 15):
        assert f.tail_offset is None or code == 15


@pytest.mark.parametrize("code", [*range(0, 15), 15, 200])
def test_unconfirmed_semantics_table_on_full_length_frames(code):
    f = bacnet_module.decode(_full(False, code))
    assert f.code == code and f.semantics == _UNCONFIRMED.get(code)


def test_a_frame_cut_at_every_length_is_a_sane_frame():
    """Defect pinned: a frame cut at one particular byte made a decoder index past the end;
    random bytes rarely cut a valid frame at each boundary, so every boundary is walked."""
    for raw in (
        bytes.fromhex(READ_PROPERTY),
        bytes.fromhex(WRITE_PROPERTY),
        bytes.fromhex(WHO_IS),
        bytes.fromhex("080a0105020c"),
    ):
        assert_every_prefix_is_sane(bacnet_module.decode, raw)


def test_value_types_do_not_depend_on_length():
    frames = [
        decode_hex("bacnet", h)
        for h in (
            READ_PROPERTY,
            WRITE_PROPERTY,
            WHO_IS,
            "080a0105020c",
            "0005010c0c0200000119" + "55",
        )
    ]
    assert_value_types_are_stable(frames)
    assert {type(x.value) for f in frames for x in f.fields if x.name == "object_identifier"} == {
        str
    }


def test_empty_frame_is_undecodable():
    f = decode("bacnet", b"")
    assert f.fields == () and f.code is None and f.tail_offset == 0


def test_no_input_is_ever_raised_from_the_decoder_itself():
    """Property: arbitrary bytes yield a sane Frame from bacnet.decode() directly.

    Defect: calling the dispatcher would hide a decoder that raises on every input."""
    fuzz_decoder_directly(
        bacnet_module.decode, 135, (b"", b"\x00\x05", b"\x10", b"\x00\x05\x01\x0c\x0c")
    )
