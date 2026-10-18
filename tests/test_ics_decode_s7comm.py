"""S7comm decoder: TPKT, COTP, and the S7 header, job function or userdata subfunction."""

import struct

import pytest

from honeylens.ics import decode
from honeylens.ics import s7comm as s7_module
from tests.ics_frame_asserts import (
    assert_every_prefix_is_sane,
    assert_frame_sane,
    assert_value_types_are_stable,
    fuzz_decoder_directly,
)

CR_BODY = bytes.fromhex("11e0000000010 0c1020100c2020102c0010a".replace(" ", ""))


def tpkt(payload: bytes) -> bytes:
    return b"\x03\x00" + struct.pack(">H", len(payload) + 4) + payload


def dt(s7: bytes) -> bytes:
    return tpkt(bytes([0x02, 0xF0, 0x80]) + s7)


def s7_job(params: bytes, data: bytes = b"", pdu_ref: int = 1) -> bytes:
    return struct.pack(">BBHHHH", 0x32, 1, 0, pdu_ref, len(params), len(data)) + params + data


SETUP = s7_job(bytes.fromhex("f000000100010 1e0".replace(" ", "")))
READ_VAR = s7_job(bytes.fromhex("0401" + "120a10020001000184000000"))
WRITE_VAR = s7_job(bytes.fromhex("0501" + "120a10020001000184000000"), b"\x00\x04\x00\x08\x01")
SZL = (
    struct.pack(">BBHHHH", 0x32, 7, 0, 1, 8, 8)
    + bytes.fromhex("0001120411440100")
    + bytes.fromhex("ff09000400110000")
)


def test_a_cotp_connect_with_no_s7_job_is_a_session_setup():
    """The observed s7comm shape: semantics 'enumerate', NO code, and no invented function field."""
    raw = tpkt(CR_BODY)
    f = decode("s7comm", raw)
    assert f.semantics == "enumerate" and f.code is None and f.tail_offset is None
    names = [x.name for x in f.fields]
    assert "function_code" not in names and "s7_function" not in names
    by = {x.name: x for x in f.fields}
    assert by["cotp_pdu_type"].meaning == "Connection Request"
    assert by["calling_tsap"].value == "0100" and by["called_tsap"].value == "0102"
    assert by["tpdu_size"].value == "0a"
    assert f.sentence and "None" not in f.sentence


def test_the_same_connect_without_tpkt_decodes_to_the_same_semantics():
    """The port-102 dispatcher and the standalone decoy hand over different layers."""
    a = decode("s7comm", tpkt(CR_BODY))
    b = decode("s7comm", CR_BODY)
    assert b.semantics == "enumerate" and b.code is None
    assert [x.name for x in b.fields] == [x.name for x in a.fields][3:]


def test_setup_communication_is_a_function_code_and_enumeration():
    f = decode("s7comm", dt(SETUP))
    assert f.code == 0xF0 and f.semantics == "enumerate"
    fn = next(x for x in f.fields if x.name == "function_code")
    assert fn.meaning == "Setup Communication" and fn.offset == 7 + 10
    assert f.tail_offset is not None  # the negotiated sizes are not decoded


def test_read_var_reads_and_names_the_first_item():
    raw = dt(READ_VAR)
    f = decode("s7comm", raw)
    by = {x.name: x for x in f.fields}
    assert f.code == 4 and f.semantics == "read" and f.tail_offset is None
    assert by["item_count"].value == 1 and by["area"].value == 0x84 and by["area"].meaning == "DB"
    assert by["db_number"].value == 1 and by["address"].value == 0
    assert f.sentence == "Reads 1 item(s) from the PLC, the first from DB 1 at byte 0"
    assert raw[by["db_number"].offset : by["db_number"].offset + 2] == b"\x00\x01"


def test_write_var_is_a_write():
    f = decode("s7comm", dt(WRITE_VAR))
    assert f.code == 5 and f.semantics == "write" and "Writes" in f.sentence


def test_bare_s7_pdu_decodes_like_the_wrapped_one():
    """The dispatcher hands over the COTP payload, which starts at the S7 protocol id."""
    a, b = decode("s7comm", dt(READ_VAR)), decode("s7comm", READ_VAR)
    assert b.code == 4 and b.semantics == "read"
    assert [x.name for x in b.fields] == [x.name for x in a.fields][6:]
    assert b.fields[0].offset == 0


def test_read_szl_is_userdata_enumeration_without_a_code():
    f = decode("s7comm", dt(SZL))
    assert f.semantics == "enumerate" and f.code is None
    by = {x.name: x for x in f.fields}
    assert by["function_group"].meaning == "CPU functions" and by["subfunction"].value == 1
    assert "system status" in f.sentence


def test_plc_stop_and_pi_service_are_control_and_download_is_a_write():
    for fn in (0x28, 0x29):
        assert decode("s7comm", dt(s7_job(bytes([fn, 0, 0, 0])))).semantics == "control"
    assert decode("s7comm", dt(s7_job(bytes([0x1A, 0])))).semantics == "write"


def test_an_unknown_job_function_has_no_semantics_and_is_not_an_anomaly():
    """S7comm is not a closed public specification: an unlisted code is 'unknown', not 'illegal'."""
    f = decode("s7comm", dt(s7_job(bytes([0x99, 0, 0, 0]))))
    assert f.code == 0x99 and f.semantics is None and "0x99" in f.tail_reason


def test_a_response_pdu_is_defined_but_not_decoded():
    ack = struct.pack(">BBHHHHBB", 0x32, 3, 0, 1, 2, 0, 0, 0) + bytes([0xF0, 0])
    f = decode("s7comm", dt(ack))
    assert f.semantics is None and f.code is None and "response" in f.tail_reason


def test_cotp_data_that_is_not_s7_is_not_given_s7_fields():
    """Never apply the S7 layout without the 0x32 protocol id: report the byte seen."""
    f = decode("s7comm", tpkt(bytes([0x02, 0xF0, 0x80]) + bytes.fromhex("0d1a")))
    assert not any(x.name == "protocol_id" for x in f.fields)
    assert f.code is None and f.semantics is None and "0x0d" in f.tail_reason


def test_a_userdata_frame_with_an_unknown_parameter_head_is_not_given_subfunction_fields():
    pdu = struct.pack(">BBHHHH", 0x32, 7, 0, 1, 8, 0) + bytes.fromhex("ff01120411440100")
    f = decode("s7comm", dt(pdu))
    assert not any(x.name == "subfunction" for x in f.fields)
    assert f.semantics is None and "0xff0112" in f.tail_reason


def test_first_bytes_that_are_no_known_layer_are_not_decoded():
    f = decode("s7comm", bytes.fromhex("474554202f"))
    assert f.fields == () and f.tail_offset == 0 and "0x4745" in f.tail_reason


def test_bytes_after_the_tpkt_length_go_to_the_tail():
    raw = tpkt(CR_BODY) + b"\xaa\xbb"
    f = decode("s7comm", raw)
    assert f.semantics == "enumerate" and f.tail_offset == len(raw) - 2
    assert "after the TPKT length" in f.tail_reason


def test_a_frame_cut_before_and_inside_a_field():
    """Defect class: 'inside' written where no byte of the field was present."""
    raw = dt(READ_VAR)
    assert "inside the tpkt_length" in decode("s7comm", raw[:3]).tail_reason
    before = decode("s7comm", raw[:4])
    assert before.tail_offset == 4 and "before the cotp_length" in before.tail_reason
    assert before.code is None and before.sentence is None
    cut_fn = decode("s7comm", raw[:17])  # S7 header complete (7..16), no parameter bytes
    assert "before the function_code" in cut_fn.tail_reason and cut_fn.code is None
    cut_item = decode("s7comm", raw[:30])
    assert cut_item.code == 4 and cut_item.sentence == "Read Var (frame cut short)"
    assert cut_item.semantics == "read" and "inside" in cut_item.tail_reason


def test_a_cut_session_setup_still_says_what_it_is():
    cut = decode("s7comm", tpkt(CR_BODY)[:12])
    assert cut.tail_offset is not None and cut.code is None


_JOBS = {
    0x00: None, 0xF0: "enumerate", 0x04: "read", 0x05: "write", 0x1A: "write", 0x1B: "write",
    0x1C: "write", 0x1D: "read", 0x1E: "read", 0x1F: "read", 0x28: "control", 0x29: "control",
}  # fmt: skip


@pytest.mark.parametrize("fn", [*_JOBS, 0x01, 0x03, 0x06, 0x1B, 0x20, 0x27, 0x2A, 0xEF, 0xF1, 0xFF])
def test_job_function_table_on_full_length_frames(fn):
    """MITRE keys off this mapping; every known function and its neighbours are pinned."""
    params = bytes([fn, 0, 0, 0, 0, 0, 0, 0])
    raw = dt(s7_job(params))
    f = s7_module.decode(raw)
    assert f.code == fn and f.semantics == _JOBS.get(fn)
    assert_frame_sane(f, raw)


@pytest.mark.parametrize(
    ("group", "sub", "semantics"),
    [(4, 1, "enumerate"), (4, 2, None), (3, 1, "enumerate"), (3, 2, "enumerate"), (3, 3, "enumerate"),
     (7, 1, "read"), (7, 2, "command"), (7, 4, "command"), (5, 1, None), (1, 1, None), (15, 1, None)],
)  # fmt: skip
def test_userdata_table_on_full_length_frames(group, sub, semantics):
    params = bytes.fromhex("0001120411") + bytes([0x40 | group, sub, 0])
    pdu = struct.pack(">BBHHHH", 0x32, 7, 0, 1, 8, 0) + params
    raw = dt(pdu)
    f = s7_module.decode(raw)
    assert f.semantics == semantics and f.code is None
    assert_frame_sane(f, raw)


def test_a_frame_cut_at_every_length_is_a_sane_frame():
    for raw in (tpkt(CR_BODY), dt(SETUP), dt(READ_VAR), dt(WRITE_VAR), dt(SZL), READ_VAR, CR_BODY):
        assert_every_prefix_is_sane(s7_module.decode, raw)


def test_value_types_do_not_depend_on_length():
    frames = [decode("s7comm", x) for x in (tpkt(CR_BODY), dt(SETUP), dt(READ_VAR), dt(SZL))]
    assert_value_types_are_stable(frames)


def test_empty_frame_is_undecodable():
    f = decode("s7comm", b"")
    assert f.fields == () and f.tail_offset == 0


def test_no_input_is_ever_raised_from_the_decoder_itself():
    """Property: s7comm.decode() directly, never through the dispatcher that contains errors."""
    fuzz_decoder_directly(
        s7_module.decode, 102, (b"", b"\x03\x00", b"\x32\x01", dt(READ_VAR)[:12], tpkt(CR_BODY)[:9])
    )


def test_an_item_that_starts_wrong_is_not_given_s7any_fields_even_when_short():
    """Defect: with fewer than three item bytes the S7ANY check was skipped and two fields
    were painted on bytes whose first byte already contradicted the layout."""
    for item in (b"\x99\x99", b"\x99", b"\x12\x99", b"\x12\x0a\x99" + b"\x00" * 9):
        pdu = s7_job(bytes([0x04, 0x01]) + item)
        f = decode("s7comm", dt(pdu))
        assert not any(x.name in ("item_variable_spec", "item_address_length") for x in f.fields), (
            item
        )
        assert f.code == 4 and f.semantics == "read" and "S7ANY" in f.tail_reason
