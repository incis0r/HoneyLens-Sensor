# tests/test_ics_mms.py
from honeylens.honeypots.honeypots_config import get_profile
from honeylens.honeypots.ics.mms import MmsHandler


def test_mms_initiate_then_identify():
    h = MmsHandler(get_profile("mms"))
    # MMS Initiate-Request (confirmed) — tag 0xA8 (initiate-RequestPDU)
    resp = h.handle_mms(b"\xa8\x03\x80\x01\x05")
    assert resp is not None and resp[0] == 0xA9  # initiate-ResponsePDU
    # MMS confirmed-Request Identify: invokeID + identify(0x82) service
    ident = h.handle_mms(b"\xa0\x09\x02\x01\x01\xa1\x04\x82\x00\x00\x00")
    assert b"SIEMENS" in ident and b"SIPROTEC 5" in ident and h.last_kind == "recon"


def test_mms_bare_write_is_write():
    h = MmsHandler(get_profile("mms"))
    # confirmed-Request with a bare 'write' service tag (0xa5)
    # A bare MMS Write classifies as a write-attempt (HIGH), not command/CRITICAL.
    h.handle_mms(b"\xa0\x09\x02\x01\x02\xa1\x04\xa5\x00\x00\x00")
    assert h.last_kind == "write"
