"""IEC-104 decoder: type id -> semantics, bare ASDU and APCI-prefixed frames."""

import random

import pytest

from honeylens.ics import decode, decode_hex
from honeylens.ics import iec104 as iec104_module

SC = "680e2a0000002d0106000100640000" + "01"


def test_single_command_is_a_command_and_decodes_to_the_end():
    """A C_SC_NA_1 is the one event an automation engineer came for, and in the
    store today it carries is_write=false, is_control=false and no technique."""
    f = decode_hex("iec104", SC)
    assert f.code == 45 and f.semantics == "command"
    assert f.tail_offset is None
    names = {x.name: x.value for x in f.fields}
    assert names["type_id"] == 45 and names["common_address"] == 1 and names["ioa"] == 100
    assert "100" in f.sentence
    assert "output 100" in f.sentence  # the page asserts this literal substring


def test_interrogation_command_is_enumeration():
    f = decode_hex("iec104", "64010600ffff00000014")
    assert f.code == 100 and f.semantics == "enumerate"


def test_reset_process_is_control_not_command():
    """Reset Process and Single Command both land on is_control; the screen must
    tell them apart, which is why semantics is a column."""
    f = decode_hex("iec104", "6901060001000000")
    assert f.semantics == "control"


def test_setpoint_is_a_command_that_also_writes():
    f = decode_hex("iec104", "3001060001006400000a00")
    assert f.semantics == "command"
    assert any(x.name == "value" for x in f.fields)


def test_an_unknown_type_id_leaves_semantics_unset_not_anomalous():
    """Type 0xfe is unassigned, not illegal: 'I do not know' is not 'out of spec'."""
    f = decode_hex("iec104", "fe010600010000000000")
    assert f.semantics is None and f.tail_reason is not None


def test_bare_asdu_and_apci_frame_decode_to_the_same_fields():
    """The store holds both shapes under different metadata keys; the ASDU fields
    must agree except for their offsets."""
    full = decode_hex("iec104", SC)
    bare = decode_hex("iec104", SC[12:])
    strip = lambda f: [(x.name, x.value) for x in f.fields if x.name != "control_field"]  # noqa: E731
    assert strip(full)[-len(strip(bare)) :] == strip(bare)
    assert bare.semantics == "command" and bare.tail_offset is None
    # the APCI prefix shifts offsets by six and every field still points at its own bytes
    raw = bytes.fromhex(SC)
    ioa = next(x for x in full.fields if x.name == "ioa")
    assert raw[ioa.offset : ioa.offset + ioa.length] == bytes([100, 0, 0])


def test_frame_cut_short_names_the_missing_field_and_stays_in_bounds():
    """A command whose command-qualifier byte is missing must not invent it."""
    raw = bytes.fromhex(SC)[:-1]
    f = decode("iec104", raw)
    assert f.semantics == "command" and f.tail_offset == len(raw)
    assert f.tail_reason and "sco" in f.tail_reason
    assert all(x.offset + x.length <= len(raw) for x in f.fields)


def test_no_input_is_ever_raised_into_the_caller():
    """Property: arbitrary bytes yield a Frame whose fields lie inside the input.

    Defect: it called the central decode(), which contains a raising decoder, so
    it passed even if iec104 raised on every input."""
    rng = random.Random(104)
    for _ in range(2000):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 24)))
        if rng.random() < 0.5 and raw:
            raw = b"\x68" + raw[1:]
        f = iec104_module.decode(raw)  # direct: a raise must fail, not become 'undecodable'
        assert all(x.offset + x.length <= len(raw) for x in f.fields)
        assert f.tail_offset is None or f.tail_offset <= len(raw)
        assert f.semantics != "anomaly"


_ELEMENT = {45: 1, 46: 1, 47: 1, 48: 3, 49: 3, 50: 5, 51: 4, 100: 1, 101: 1, 102: 0, 103: 7, 105: 1}


def _asdu(type_id: int) -> bytes:
    """A full-length bare ASDU: header, IOA 100, and a complete information element."""
    n = _ELEMENT.get(type_id, 2)
    return bytes([type_id, 1, 6, 0, 1, 0, 100, 0, 0]) + bytes([10, 0, 0, 0, 0, 0, 0][:n])


@pytest.mark.parametrize(
    ("type_id", "semantics"),
    [(1, "read"), (13, "read"), (40, "read"), (41, None), (44, None)]
    + [(t, "command") for t in range(45, 52)]
    + [(52, None), (99, None), (100, "enumerate"), (101, "enumerate"), (102, "enumerate")]
    + [(103, "command"), (104, None), (105, "control"), (106, None), (0xFE, None)],
)
def test_semantics_table_on_full_length_frames(type_id, semantics):
    """MITRE assignment keys off this mapping for every IEC-104 row; pin each id
    and each boundary (40/41, 44/45, 51/52, 99/100, 102/103/104/105) on complete frames.
    Defect: only short hand-built fixtures covered a handful of ids."""
    asdu = _asdu(type_id)
    apci = bytes([0x68, len(asdu) + 4, 0, 0, 0, 0]) + asdu
    for raw in (asdu, apci):
        f = iec104_module.decode(raw)
        assert f.code == type_id and f.semantics == semantics
        if type_id in _ELEMENT:
            assert f.tail_offset is None


def test_setpoint_on_a_full_frame_decodes_value_and_ends_cleanly():
    """Defect: the setpoint test ran on a frame missing its qualifier byte."""
    f = decode_hex("iec104", "300106000100640000" + "0a00" + "00")
    assert f.tail_offset is None
    assert {x.name: x.value for x in f.fields}["value"] == 10


def test_reset_process_on_a_full_frame_is_control_and_ends_cleanly():
    f = decode_hex("iec104", "690106000100640000" + "00")
    assert f.semantics == "control" and f.tail_offset is None


def test_short_capture_is_not_called_an_apci_frame_without_asdu():
    """Defect: a 6-byte capture whose length byte says 14 was reported as having no ASDU."""
    f = decode_hex("iec104", "680e2a0000" + "00")
    assert "without an ASDU" not in (f.tail_reason or f.sentence or "")
    assert f.tail_reason is not None
    u = decode_hex("iec104", "680407000000")
    assert u.sentence and "U-format" in u.sentence


def test_a_cut_short_frame_has_a_sentence_if_and_only_if_a_type_id_was_read():
    """Defect: a header cut before the type id produced the sentence 'type None
    (frame cut short)', asserting a type the bytes do not carry."""
    assert decode_hex("iec104", "680e2a000000").sentence is None  # cut at type_id
    assert decode_hex("iec104", "680e2a0000").sentence is None  # cut inside the control field
    assert decode_hex("iec104", "6901060001000000").sentence == "C_RP_NA_1 (frame cut short)"
    assert decode_hex("iec104", "3001060001006400000a00").sentence == "C_SE_NA_1 (frame cut short)"
    assert decode_hex("iec104", "fe0106").sentence == "type 254 (frame cut short)"


def test_the_decoy_and_the_decoder_name_every_type_the_same():
    """Defect: the decoy called type 51 `C_SE_ND_1 Setpoint Normalized w/o QOS` while the decoder
    (correctly) calls it `C_BO_NA_1`, so the row's function_name disagreed with its frame."""
    from honeylens.honeypots.hp_iec104 import ASDU_TYPE_NAMES
    from honeylens.ics import iec104

    for type_id, decoy_name in ASDU_TYPE_NAMES.items():
        spec = iec104._COMMANDS.get(type_id)
        if spec is not None:
            assert spec[0].split()[0] == decoy_name.split()[0], type_id
