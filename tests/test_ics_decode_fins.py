"""FINS decoder: the 10-byte command header, the MRC/SRC pair, and memory-area requests."""

import pytest

from honeylens.ics import decode, decode_hex
from honeylens.ics import fins as fins_module
from tests.ics_frame_asserts import (
    assert_every_prefix_is_sane,
    assert_frame_sane,
    assert_value_types_are_stable,
    fuzz_decoder_directly,
)

HEADER = "80000200630000" + "0000" + "ff"  # ICF RSV GCT DNA DA1 DA2 SNA SA1 SA2 SID, 10 bytes
CONTROLLER_DATA = HEADER + "0501"
MEMORY_READ = HEADER + "0101" + "82" + "0064" + "00" + "000a"  # DM word 100, 10 items


def test_controller_data_read_is_enumeration_and_fully_placed():
    """The observed FINS command: MRC 5 SRC 1. Code is the MRC; the pair names it."""
    f = decode_hex("fins", CONTROLLER_DATA)
    assert f.code == 5 and f.semantics == "enumerate" and f.tail_offset is None
    by = {x.name: x for x in f.fields}
    assert by["mrc"].value == 5 and by["src"].value == 1
    assert by["src"].meaning == "Controller Data Read"
    assert by["icf"].offset == 0 and by["src"].offset == 11


def test_memory_area_read_places_area_address_and_count():
    f = decode_hex("fins", MEMORY_READ)
    by = {x.name: x for x in f.fields}
    assert f.semantics == "read" and f.tail_offset is None
    assert by["memory_area"].value == 0x82 and by["memory_area"].meaning == "DM word"
    assert by["address"].value == 100 and by["item_count"].value == 10
    assert f.sentence == "Reads 10 item(s) from the DM word area starting at address 100"


def test_memory_area_write_is_a_write_and_its_data_is_left_in_the_tail():
    raw = HEADER + "0102" + "82" + "0064" + "00" + "0001" + "1234"
    f = decode_hex("fins", raw)
    assert f.semantics == "write" and f.tail_offset == len(bytes.fromhex(raw)) - 2
    assert "2 byte(s)" in f.tail_reason


def test_run_and_stop_are_control_and_clock_write_is_a_command():
    assert decode_hex("fins", HEADER + "0401" + "ffff00").semantics == "control"
    assert decode_hex("fins", HEADER + "0402").semantics == "control"
    assert decode_hex("fins", HEADER + "0702" + "00" * 7).semantics == "command"


def test_a_response_icf_is_an_anomaly_as_a_request_and_keeps_its_header():
    """Defect class: a response frame decoded with request meaning. ICF bit 6 marks a response."""
    f = decode_hex("fins", "c0" + HEADER[2:] + "0501" + "0000")
    assert f.semantics == "anomaly" and f.code == 5
    assert "response" in f.tail_reason and f.tail_offset == 12
    assert next(x for x in f.fields if x.name == "src").meaning is None


def test_an_unknown_command_pair_has_no_semantics_and_is_not_an_anomaly():
    """Unassigned is not illegal: MRC 5 SRC 99 is a pair this decoder does not know."""
    f = decode_hex("fins", HEADER + "0563" + "00")
    assert f.code == 5 and f.semantics is None and f.tail_offset == 12
    assert "MRC 0x05 SRC 0x63" in f.tail_reason
    assert next(x for x in f.fields if x.name == "src").meaning is None


def test_a_memory_read_with_the_wrong_discriminator_is_not_given_memory_fields():
    """The area/address layout belongs to (1,1) and (1,2) only; other pairs keep theirs in the tail."""
    f = decode_hex("fins", HEADER + "0103" + "82" + "0064" + "00" + "000a")
    assert f.semantics == "write" and not any(x.name == "memory_area" for x in f.fields)
    assert f.tail_offset == 12


def test_a_frame_cut_before_and_inside_a_field():
    """Defect class: 'inside' for a field of which no byte was present."""
    raw = bytes.fromhex(MEMORY_READ)
    before = decode("fins", raw[:12])
    assert before.tail_offset == 12 and "before the memory_area" in before.tail_reason
    assert before.semantics == "read" and before.sentence == "Memory Area Read (frame cut short)"
    none_of_count = decode("fins", raw[:16])  # the item count would start at byte 16
    assert none_of_count.tail_offset == 16 and "before the item_count" in none_of_count.tail_reason
    inside = decode("fins", raw[:17])  # one of the count's two bytes
    assert inside.tail_offset == 16 and "inside the item_count" in inside.tail_reason
    assert all(x.offset + x.length <= 17 for x in inside.fields)


def test_a_cut_frame_has_a_sentence_if_and_only_if_the_mrc_was_read():
    """Defect: 'type None (frame cut short)' when no code had been read."""
    raw = bytes.fromhex(CONTROLLER_DATA)
    nothing = decode("fins", raw[:5])
    assert nothing.code is None and nothing.sentence is None
    mrc_only = decode("fins", raw[:11])
    assert mrc_only.code == 5 and mrc_only.semantics is None
    assert mrc_only.sentence == "FINS command 0x05 (frame cut short)"
    assert "before the src" in mrc_only.tail_reason


# (MRC, SRC) -> semantics; every other pair must be None.
_PAIRS = {
    (0x01, 0x01): "read", (0x01, 0x02): "write", (0x01, 0x03): "write", (0x01, 0x04): "read",
    (0x01, 0x05): "write", (0x02, 0x01): "read", (0x02, 0x02): "write", (0x02, 0x03): "write",
    (0x03, 0x06): "read", (0x03, 0x07): "write", (0x03, 0x08): "write",
    (0x04, 0x01): "control", (0x04, 0x02): "control",
    (0x05, 0x01): "enumerate", (0x05, 0x02): "enumerate",
    (0x06, 0x01): "read", (0x06, 0x20): "read",
    (0x07, 0x01): "read", (0x07, 0x02): "command",
    (0x21, 0x02): "read", (0x21, 0x03): "write",
    (0x22, 0x01): "enumerate", (0x22, 0x02): "read", (0x22, 0x03): "write", (0x22, 0x04): "write",
    (0x22, 0x05): "write", (0x22, 0x07): "write", (0x22, 0x08): "write",
    (0x23, 0x01): "write", (0x23, 0x02): "write",
}  # fmt: skip


@pytest.mark.parametrize(
    "pair",
    [*_PAIRS, (0x01, 0x00), (0x01, 0x06), (0x03, 0x05), (0x04, 0x03), (0x08, 0x01), (0xFF, 0xFF)],
)
def test_command_table_on_full_length_frames(pair):
    """MITRE keys off this mapping; every known pair and neighbouring unknown pairs are pinned."""
    raw = bytes.fromhex(HEADER) + bytes(pair) + b"\x82\x00\x01\x00\x00\x01"
    f = fins_module.decode(raw)
    assert f.code == pair[0] and f.semantics == _PAIRS.get(pair)
    assert_frame_sane(f, raw)


def test_a_frame_cut_at_every_length_is_a_sane_frame():
    """Defect pinned: a frame cut at one particular byte made a decoder index past the end;
    random bytes rarely cut a valid frame at each boundary, so every boundary is walked."""
    for raw in (
        bytes.fromhex(MEMORY_READ),
        bytes.fromhex(CONTROLLER_DATA),
        bytes.fromhex(HEADER + "0102820064000001" + "1234"),
    ):
        assert_every_prefix_is_sane(fins_module.decode, raw)


def test_value_types_do_not_depend_on_length():
    frames = [decode_hex("fins", h) for h in (CONTROLLER_DATA, MEMORY_READ, HEADER + "0401ffff00")]
    assert_value_types_are_stable(frames)


def test_empty_frame_is_undecodable():
    f = decode("fins", b"")
    assert f.fields == () and f.tail_offset == 0


def test_no_input_is_ever_raised_from_the_decoder_itself():
    """Property: fins.decode() directly, never through the dispatcher that contains errors."""
    fuzz_decoder_directly(
        fins_module.decode,
        9600,
        (
            b"",
            bytes.fromhex(HEADER),
            bytes.fromhex(HEADER + "0101"),
            b"\xc0" + bytes.fromhex(HEADER[2:]),
        ),
    )
