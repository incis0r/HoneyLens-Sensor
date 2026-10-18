# tests/test_ics_mms.py
from honeylens.honeypots.honeypots_config import get_profile
from honeylens.honeypots.ics.mms import MmsHandler


def test_mms_initiate_then_identify():
    h = MmsHandler(get_profile("mms"))
    # MMS Initiate-Request (confirmed) — tag 0xA8 (initiate-RequestPDU)
    resp = h.handle_mms(b"\xa8\x03\x80\x01\x05")
    assert resp is not None and resp[0] == 0xA9  # initiate-ResponsePDU
    # MMS confirmed-Request Identify: invokeID + identify(0x82) service. A bare MMS PDU is
    # not what the decoder reads (it expects the session layer), so its kind is the neutral one.
    ident = h.handle_mms(b"\xa0\x09\x02\x01\x01\xa1\x04\x82\x00\x00\x00")
    assert b"SIEMENS" in ident and b"SIPROTEC 5" in ident and h.last_kind == "recon"


def test_mms_write_is_write():
    from tests.test_ics_decode_mms import WRITE, presentation

    h = MmsHandler(get_profile("mms"))
    # The kind is the decoder's, read through the session and presentation layers a real
    # client sends. A plain MMS Write is a write-attempt (HIGH), not command/CRITICAL.
    h.handle_mms(presentation(WRITE))
    assert h.last_kind == "write"
