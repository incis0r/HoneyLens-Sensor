import struct

from honeylens.honeypots.ics.base import (
    classify,
    cotp_connection_confirm,
    cotp_data,
    cotp_dt_payload,
    pack_tpkt,
    parse_tpkt,
)


def test_classify_taxonomy():
    assert classify("enumeration") == ("ics_enumeration", "LOW")
    assert classify("recon") == ("ics_recon_function_code", "MEDIUM")
    assert classify("write") == ("ics_write_attempt", "HIGH")
    assert classify("command") == ("ics_command_with_intent", "CRITICAL")


def test_classify_unknown_is_enumeration():
    assert classify("anything-else") == ("ics_enumeration", "LOW")


def test_tpkt_roundtrip():
    payload = b"\x02\xf0\x80hello"
    frame = pack_tpkt(payload)
    assert frame[:2] == b"\x03\x00"
    assert struct.unpack(">H", frame[2:4])[0] == len(payload) + 4
    got, rest = parse_tpkt(frame)
    assert got == payload and rest == b""


def test_cotp_cc_answers_cr():
    # minimal COTP CR: len, 0xE0 (CR), dst-ref(2), src-ref(2), class(1)
    cr = bytes([0x06, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00])
    cc = cotp_connection_confirm(cr)
    assert cc[1] == 0xD0  # CC TPDU code


def test_cotp_dt_payload_extracts():
    dt = cotp_data(b"\x32\x01\x00")  # S7-shaped payload
    assert cotp_dt_payload(dt) == b"\x32\x01\x00"
