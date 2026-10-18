"""Modbus decoder: fixtures are real rows measured in the production event store."""

import pytest

from honeylens.ics.frame import decode, decode_hex


def test_read_device_identification_is_enumeration():
    """Defect pinned: FC 43 / MEI 14 must read as enumeration and be fully placed."""
    f = decode_hex("modbus", "2b0e0100")
    assert f.code == 43 and f.semantics == "enumerate"
    assert f.tail_offset is None


def test_function_code_90_is_an_anomaly_with_an_unparsed_tail():
    """16 of 35 modbus rows on one sensor look like this. FC 90 is not in the
    specification, so the field layout after it is unknown and must stay unknown."""
    f = decode_hex("modbus", "5a0020001400000000000002")
    assert f.code == 90 and f.semantics == "anomaly"
    assert f.tail_offset == 1 and f.tail_reason is not None
    assert "90" in f.tail_reason and "specification" in f.tail_reason
    assert len(f.fields) == 1


def test_write_single_register_is_a_write_and_says_so_in_words():
    """Defect pinned: the sentence must name the register address, not only the code."""
    f = decode_hex("modbus", "060001000a")
    assert f.semantics == "write" and "1" in f.sentence and "10" in f.sentence
    assert f.tail_offset is None


def test_a_truncated_frame_keeps_what_fits():
    """Defect pinned: a field that runs past the end of the bytes would paint nothing real."""
    f = decode_hex("modbus", "0600")
    assert f.code == 6 and f.tail_reason is not None
    assert f.tail_offset == 1 and [x.name for x in f.fields] == ["function_code"]
    assert all(x.offset + x.length <= f.raw_len for x in f.fields)


def test_an_empty_frame_is_undecodable():
    assert decode_hex("modbus", "").fields == ()
    assert decode("modbus", b"").tail_reason


def test_multiple_register_write_places_its_data_by_byte_count():
    """Defect pinned: the data field length comes from byte_count, not from the frame end."""
    f = decode_hex("modbus", "10000100020400010002")
    assert f.semantics == "write" and f.tail_offset is None
    assert [x.name for x in f.fields][-1] == "data" and f.fields[-1].length == 4


def test_every_single_byte_function_code_decodes_without_raising():
    """Defect pinned: a decoder must return a Frame for any code, never raise."""
    for code in range(256):
        assert decode("modbus", bytes([code])).code == code


def test_a_single_register_write_keeps_data_as_hex_like_a_longer_one():
    """Defect pinned: data was an int for 2 bytes and a str for 4, so one field name
    carried two types."""
    one = decode_hex("modbus", "100001000102000a").fields[-1]
    two = decode_hex("modbus", "10000100020400010002").fields[-1]
    assert one.name == two.name == "data"
    assert one.value == "000a" and two.value == "00010002"


def test_diagnostics_reads_its_sub_function_and_data_as_numbers():
    f = decode_hex("modbus", "08000400ff")
    assert [x.value for x in f.fields[1:]] == [4, 255] and f.tail_offset is None


def test_exception_and_user_defined_codes_are_described_truthfully():
    """Defect pinned: FC 128 and FC 100 were reported as absent from the specification,
    which is false for exception-response and user-defined codes."""
    exc = decode_hex("modbus", "8302")
    assert exc.semantics == "anomaly" and "exception-response" in exc.tail_reason
    assert "does not define" not in exc.sentence
    user = decode_hex("modbus", "6400")
    assert user.semantics == "anomaly" and "user-defined" in user.tail_reason


def test_mei_type_other_than_14_is_not_given_read_device_id_fields():
    """Defect pinned: bytes after MEI type 13 were labelled with MEI 14 field names."""
    f = decode_hex("modbus", "2b0d0100")
    assert [x.name for x in f.fields] == ["function_code", "mei_type"]
    assert f.tail_offset == 2 and "13" in f.tail_reason


def test_a_frame_ending_before_a_field_says_before_not_inside():
    """Defect pinned: with no byte of the address present the reason said 'inside'."""
    assert "before" in decode_hex("modbus", "06").tail_reason
    assert "inside" in decode_hex("modbus", "0600").tail_reason


def test_bytes_after_the_defined_fields_go_to_the_tail():
    f = decode_hex("modbus", "060001000aff")
    assert f.tail_offset == 5 and "1 byte(s) after" in f.tail_reason


@pytest.mark.parametrize(
    "code,semantics",
    [(20, "read"), (21, "write"), (22, "write"), (23, "write"), (24, "read")],
)
def test_a_specified_but_undecoded_code_has_its_meaning_and_a_tail(code, semantics):
    """Defect: codes 20-24 got semantics=None ("I do not know this code"), so FC22/FC23, which the
    decoy answers as writes, landed as is_write=TRUE with no semantics and were counted by
    nothing on the screen. The meaning is known; only the field layout is not decoded."""
    f = decode_hex("modbus", f"{code:02x}0102")
    assert f.code == code and f.semantics == semantics
    assert f.fields[0].value == code and f.fields[0].meaning
    assert f.tail_offset == 1 and "not decoded" in f.tail_reason
    assert len(f.fields) == 1  # no layout is invented


def test_a_bare_undecoded_code_has_no_tail():
    f = decode_hex("modbus", "16")
    assert f.semantics == "write" and f.tail_offset is None


@pytest.mark.parametrize("code", [7, 11, 12])
def test_read_only_status_queries_are_reads_not_control(code):
    """Defect: FC7/FC11/FC12 were typed 'control' and so asserted T0816 Device Restart/Shutdown.
    They read a status register, a counter and a log; nothing is ordered. The decoy files FC7 as
    recon. FC8 Diagnostics stays 'control' on purpose (see _SPEC)."""
    assert decode_hex("modbus", f"{code:02x}").semantics == "read"


def test_diagnostics_stays_control():
    assert decode_hex("modbus", "0800000000").semantics == "control"
