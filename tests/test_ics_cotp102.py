# tests/test_ics_cotp102.py
from honeylens.honeypots.ics.cotp102 import route_dt_payload


def test_route_s7():
    _kind, who = route_dt_payload(b"\x32\x01\x00")
    assert who == "s7"


def test_route_mms_session():
    # ISO 8327 session CONNECT SPDU starts 0x0D
    _kind, who = route_dt_payload(b"\x0d\x00\x00")
    assert who == "mms"


def test_route_unknown():
    _kind, who = route_dt_payload(b"\xff\xff")
    assert who == "unknown"
