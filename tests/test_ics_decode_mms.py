"""MMS decoder: TPKT, COTP, ISO session, presentation and the MMS PDU - or an unparsed frame.

The decoy's own approach (searching the first eight bytes for a service tag) is deliberately
not reproduced: the layers are walked in order, and a frame that does not follow them is
reported with the byte that broke the layering.
"""

import pytest

from honeylens.ics import decode
from honeylens.ics import mms as mms_module
from tests.ics_frame_asserts import (
    assert_every_prefix_is_sane,
    assert_frame_sane,
    assert_value_types_are_stable,
    fuzz_decoder_directly,
)


def tlv(tag: bytes | int, content: bytes = b"") -> bytes:
    tag = bytes([tag]) if isinstance(tag, int) else tag
    assert len(content) < 128
    return tag + bytes([len(content)]) + content


def tpkt(payload: bytes) -> bytes:
    return b"\x03\x00" + (len(payload) + 4).to_bytes(2, "big") + payload


def presentation(mms_pdu: bytes) -> bytes:
    """Session give-tokens + data-transfer SPDUs, then fully-encoded-data around the MMS PDU."""
    pdv = tlv(0x30, tlv(0x02, b"\x03") + tlv(0xA0, mms_pdu))
    return bytes.fromhex("01000100") + tlv(0x61, pdv)


def dt(session_payload: bytes) -> bytes:
    return tpkt(bytes([0x02, 0xF0, 0x80]) + session_payload)


def confirmed(service_tag: bytes, content: bytes = b"", invoke: int = 1) -> bytes:
    return tlv(0xA0, tlv(0x02, bytes([invoke])) + tlv(service_tag, content))


IDENTIFY = confirmed(b"\x82")
READ = confirmed(b"\xa4", bytes.fromhex("a1030a0100"))
WRITE = confirmed(b"\xa5", bytes.fromhex("a1030a0100"))
INITIATE = tlv(0xA8, bytes.fromhex("8001058101058201058301 0a".replace(" ", "")))
SESSION_CONNECT = bytes.fromhex("0d1a" + "00" * 26)
COTP_CR = bytes.fromhex("11e0000000010 0c1020100c2020102c0010a".replace(" ", ""))


def test_identify_is_enumeration_and_every_layer_is_placed():
    """MMS Identify (service 2) asks the server for vendor, model and revision."""
    raw = dt(presentation(IDENTIFY))
    f = decode("mms", raw)
    by = {x.name: x for x in f.fields}
    assert f.code == 2 and f.semantics == "enumerate"
    assert by["service"].meaning == "identify" and by["invoke_id"].value == 1
    assert by["mms_pdu"].meaning == "confirmed-RequestPDU"
    assert (
        by["presentation_pdu"].meaning == "fully-encoded-data"
        and by["session_spdus"].value == "01000100"
    )
    assert raw[by["service"].offset] == 0x82 and f.tail_offset is None
    assert f.sentence == "Sends the MMS identify request (invoke ID 1)"


def test_read_and_write_requests_are_a_read_and_a_write():
    r = decode("mms", dt(presentation(READ)))
    w = decode("mms", dt(presentation(WRITE)))
    assert (r.code, r.semantics) == (4, "read") and (w.code, w.semantics) == (5, "write")
    assert r.tail_offset is not None and "parameters" in r.tail_reason


def test_a_service_numbered_above_thirty_uses_the_two_byte_tag():
    """Defect class: reading 0xbf as the service and ignoring the number in the next byte."""
    start = decode("mms", dt(presentation(confirmed(b"\xbf\x28", b""))))  # start [40]
    file_open = decode("mms", dt(presentation(confirmed(b"\xbf\x48", b""))))  # fileOpen [72]
    assert (start.code, start.semantics) == (40, "control")
    assert (file_open.code, file_open.semantics) == (72, "read")
    svc = next(x for x in start.fields if x.name == "service")
    assert svc.length == 3 and svc.meaning == "start"


def test_initiate_request_is_a_session_setup_without_a_code():
    f = decode("mms", dt(presentation(INITIATE)))
    assert f.semantics == "enumerate" and f.code is None
    assert next(x for x in f.fields if x.name == "mms_pdu").meaning == "initiate-RequestPDU"
    assert not any(x.name == "service" for x in f.fields)


def test_a_session_connect_and_a_cotp_connect_are_session_setups():
    sc = decode("mms", dt(SESSION_CONNECT))
    cr = decode("mms", tpkt(COTP_CR))
    for f in (sc, cr):
        assert f.semantics == "enumerate" and f.code is None and f.sentence
    assert next(x for x in sc.fields if x.name == "session_type").meaning == "CONNECT"
    assert sc.tail_offset is not None and "presentation" in sc.tail_reason


def test_bare_session_payload_decodes_like_the_wrapped_one():
    """The port-102 dispatcher hands over the COTP payload, which starts at the session layer."""
    wrapped = decode("mms", dt(presentation(IDENTIFY)))
    bare = decode("mms", presentation(IDENTIFY))
    assert bare.code == 2 and bare.semantics == "enumerate"
    assert [x.name for x in bare.fields] == [x.name for x in wrapped.fields][6:]
    assert bare.fields[0].offset == 0


def test_the_decoys_direct_mms_shape_is_reported_not_guessed():
    """Defect pinned: the decoy located the service by searching the first eight bytes of a
    payload that has no session or presentation layer. That is not the wire layering."""
    direct = decode("mms", bytes.fromhex("a00902010 1a104820000".replace(" ", "")))
    assert direct.fields == () and direct.code is None and direct.semantics is None
    assert "0xa009" in direct.tail_reason
    via_cotp = decode("mms", dt(bytes.fromhex("a0090201 01a104820000".replace(" ", ""))))
    assert via_cotp.code is None and via_cotp.semantics is None
    assert "0xa0" in via_cotp.tail_reason and via_cotp.tail_offset == 7


def test_a_wrong_presentation_tag_is_not_given_mms_fields():
    """Never apply the MMS layout when the layer above it was not the expected one."""
    f = decode("mms", dt(bytes.fromhex("01000100") + tlv(0x62, tlv(0x30, b""))))
    assert not any(x.name == "mms_pdu" for x in f.fields)
    assert "0x62" in f.tail_reason and f.code is None and f.semantics is None


def test_responses_are_defined_but_not_requests():
    resp = confirmed(b"\x82")
    resp = bytes([0xA1]) + resp[1:]  # confirmed-ResponsePDU
    f = decode("mms", dt(presentation(resp)))
    assert f.semantics is None and f.code is None and "response" in f.tail_reason
    assert next(x for x in f.fields if x.name == "mms_pdu").meaning == "confirmed-ResponsePDU"


def test_conclude_request_has_no_semantics():
    f = decode("mms", dt(presentation(bytes([0x8B, 0x00]))))
    assert f.semantics is None and f.tail_offset is None
    assert next(x for x in f.fields if x.name == "mms_pdu").meaning == "conclude-RequestPDU"


def test_a_tag_outside_the_mms_pdu_choice_is_an_anomaly():
    """The MMSpdu CHOICE is closed (context tags 0-13); a private tag or number 30 is not in it."""
    for bad in (0xC1, 0x9E, 0x40):
        f = decode("mms", dt(presentation(tlv(bad, b""))))
        assert f.semantics == "anomaly" and "CHOICE" in f.sentence, hex(bad)


def test_a_frame_cut_before_and_inside_a_field():
    """Defect class: 'inside' written where no byte of the field was present."""
    raw = dt(presentation(IDENTIFY))
    assert "inside the tpkt_length" in decode("mms", raw[:3]).tail_reason
    before = decode("mms", raw[:4])
    assert before.tail_offset == 4 and "before the cotp_length" in before.tail_reason
    assert before.code is None and before.sentence is None
    cut = decode("mms", raw[:-1])  # the identify service tag's length byte is gone
    assert cut.code == 2 and cut.sentence == "identify (frame cut short)"
    assert "inside the service" in cut.tail_reason or "before the service" in cut.tail_reason


def test_a_cut_before_the_service_has_no_code_and_no_sentence():
    raw = dt(presentation(IDENTIFY))
    svc = next(x for x in decode("mms", raw).fields if x.name == "service")
    f = decode("mms", raw[: svc.offset])
    assert f.code is None and f.sentence is None and f.tail_offset == svc.offset
    assert "before the service" in f.tail_reason


_SERVICES = {
    **dict.fromkeys((0, 1, 2, 6, 9, 12, 15, 37, 45, 63, 64, 71, 77), "enumerate"),
    **dict.fromkeys((4, 29, 30, 31, 33, 65, 72, 73), "read"),
    **dict.fromkeys((3, 5, 7, 8, 10, 11, 13, 14, 16, 26, 27, 28, 32, 34, 36, 66, 75, 76), "write"),
    **dict.fromkeys((38, 39, 40, 41, 42, 43, 44), "control"),
}


def _service_frame(n: int) -> bytes:
    tag = bytes([0xA0 | n]) if n < 31 else bytes([0xBF, n])
    return dt(presentation(confirmed(tag, b"")))


@pytest.mark.parametrize("n", [*range(0, 78), 78, 100, 126])
def test_service_table_on_full_length_frames(n):
    """MITRE keys off this mapping; every confirmed service number 0-77 and the boundary above."""
    raw = _service_frame(n)
    f = mms_module.decode(raw)
    expected = _SERVICES.get(n) if n < 78 else "anomaly"  # MMS defines services 0-77 only
    assert f.code == n and f.semantics == expected
    assert_frame_sane(f, raw)


def test_a_frame_cut_at_every_length_is_a_sane_frame():
    for raw in (
        dt(presentation(IDENTIFY)),
        dt(presentation(READ)),
        dt(presentation(INITIATE)),
        dt(SESSION_CONNECT),
        tpkt(COTP_CR),
        _service_frame(72),
    ):
        assert_every_prefix_is_sane(mms_module.decode, raw)


def test_value_types_do_not_depend_on_length():
    frames = [
        decode("mms", dt(presentation(x)))
        for x in (IDENTIFY, READ, INITIATE, confirmed(b"\xbf\x48"))
    ]
    assert_value_types_are_stable(frames)


def test_empty_frame_is_undecodable():
    f = decode("mms", b"")
    assert f.fields == () and f.tail_offset == 0


def test_no_input_is_ever_raised_from_the_decoder_itself():
    """Property: mms.decode() directly, never through the dispatcher that contains errors."""
    fuzz_decoder_directly(
        mms_module.decode,
        61850,
        (b"", b"\x03\x00", b"\x01\x00\x01\x00\x61", dt(presentation(IDENTIFY))[:14], b"\x0d"),
    )
