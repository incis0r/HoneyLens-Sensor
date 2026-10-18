# tests/test_ics_profinet.py
from honeylens.honeypots.honeypots_config import get_profile
from honeylens.honeypots.ics.profinet import ProfinetDatagramProtocol, build_im0
from tests.ics_fakes import FakeDatagramTransport


def test_im0_carries_siemens_identity():
    im0 = build_im0(get_profile("profinet"))
    assert b"\x00\x2a" in im0  # VendorID 0x002A big-endian
    assert b"6ES7 515-2AM01-0AB0" in im0
    assert b"plcxb1d0ed" in im0


def test_profinet_read_gets_reply_and_classifies(monkeypatch):
    events = []
    monkeypatch.setattr(
        "honeylens.honeypots.ics.profinet.log_event", lambda *a, **k: events.append((a, k))
    )
    t = FakeDatagramTransport()
    proto = ProfinetDatagramProtocol(profile=get_profile("profinet"))
    proto.connection_made(t)
    # a plausible PN-IO implicit read datagram (opnum 5 = Read in DCE/RPC)
    proto.datagram_received(b"\x04\x00" + b"\x05" + b"\x00" * 16, ("203.0.113.9", 49152))
    assert t.sent and b"6ES7" in t.sent[0][0]
    assert events[0][1].get("attack_type") == "ics_recon_function_code"
