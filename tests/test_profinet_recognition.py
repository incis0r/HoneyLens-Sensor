"""The PROFINET decoy answers DCE/RPC requests, and only those.

Reviewed 2026-11-20: ``datagram_received`` called every datagram of three bytes or more
reconnaissance and answered it with the identity block. Nothing checked that the datagram was
a connectionless DCE/RPC PDU (version 4, an 80-byte header, a body length that fits). On UDP
that is a reflector — any source address can be made to receive our reply — and it stamps an
industrial verdict on whatever a UDP sweep throws at 34964. The verdict was one constant; the
opnum that tells an identification read from a write or a control request (byte 68) was read
only by the decoder.

Now: a datagram that is not a DCE/RPC connectionless PDU is recorded as
``foreign_on_ics_port`` and gets **no reply**; only a request is answered; and the kind comes
from ``honeylens.ics.profinet``.
"""

from __future__ import annotations

import pytest

from honeylens.honeypots.honeypots_config import get_profile
from honeylens.honeypots.ics import profinet as pn
from honeylens.honeypots.ics.profinet import ProfinetDatagramProtocol, check_rpc
from tests.ics_fakes import FakeDatagramTransport
from tests.test_ics_decode_profinet import OTHER_IF, rpc

PEER = ("203.0.113.9", 49152)


@pytest.fixture
def send(monkeypatch):
    def _send(datagram: bytes):
        events = []

        def _log(protocol, peer, md, attack_type=None, severity=None, proto=None, raw=None):
            events.append({"md": md, "verdict": (attack_type, severity), "raw": raw})

        monkeypatch.setattr(pn, "log_event", _log)
        transport = FakeDatagramTransport()
        proto = ProfinetDatagramProtocol(profile=get_profile("profinet"))
        proto.connection_made(transport)
        proto.datagram_received(datagram, PEER)
        assert len(events) == 1
        return events[0], transport.sent

    return _send


def lying_length() -> bytes:
    good = bytearray(rpc(5))
    good[74:76] = (400).to_bytes(2, "little")
    return bytes(good)


@pytest.mark.parametrize(
    "datagram",
    [
        b"\x04\x00\x05" + b"\x00" * 16,  # version byte right, nothing else: the old test's probe
        b"\x00\x00\x00",
        b"GET / HTTP/1.1\r\n\r\n",
        b"\x05" + rpc(5)[1:],  # connection-oriented RPC version
        rpc(5, ptype=11),  # a connection-oriented packet type in a datagram
        rpc(5, ptype=200),
        rpc(5)[:79],
        lying_length(),
        b"\x01" * 600,
    ],
)
def test_a_datagram_that_is_not_dce_rpc_is_foreign_and_gets_no_reply(send, datagram):
    event, sent = send(datagram)

    assert sent == []
    md = event["md"]
    assert md["phase"] == "foreign_on_ics_port"
    assert md["ics"] is False
    assert md["dst_port"] == 34964
    assert event["verdict"] == ("SCANNER", "LOW")
    assert event["raw"] == datagram


@pytest.mark.parametrize(
    ("opnum", "verdict"),
    [
        (5, ("ics_enumeration", "LOW")),  # ReadImplicit: the identification read
        (2, ("ics_recon_function_code", "MEDIUM")),  # Read
        (3, ("ics_write_attempt", "HIGH")),  # Write
        (4, ("ics_command_with_intent", "CRITICAL")),  # Control
        (0, ("ics_recon_function_code", "MEDIUM")),  # Connect: no meaning assigned
        (77, ("ics_recon_function_code", "MEDIUM")),  # not defined for the interface
    ],
)
def test_a_request_is_answered_and_its_kind_is_the_decoders(send, opnum, verdict):
    event, sent = send(rpc(opnum, body=b"\x00" * 8))

    assert event["md"]["phase"] == "pnio_dgram"
    assert "ics" not in event["md"]
    assert event["md"]["frame_hex"] == rpc(opnum, body=b"\x00" * 8).hex()
    assert event["verdict"] == verdict
    assert len(sent) == 1 and b"6ES7" in sent[0][0]
    assert sent[0][1] == PEER


def test_a_request_on_another_interface_is_recorded_as_rpc_not_as_an_operation(send):
    event, _ = send(rpc(3, interface=OTHER_IF))

    assert event["md"]["phase"] == "pnio_dgram"
    assert event["verdict"] == ("ics_recon_function_code", "MEDIUM")


@pytest.mark.parametrize("ptype", [1, 2, 3, 6, 7])
def test_a_packet_that_is_not_a_request_is_recorded_and_not_answered(send, ptype):
    event, sent = send(rpc(5, ptype=ptype))

    assert event["md"]["phase"] == "pnio_dgram"
    assert sent == []


def test_big_endian_requests_are_recognised(send):
    event, sent = send(rpc(5, little=False, body=b"\x00" * 4))

    assert event["md"]["phase"] == "pnio_dgram"
    assert len(sent) == 1


def test_check_rpc_names_the_defect():
    assert check_rpc(rpc(5)) is None
    assert "80" in check_rpc(rpc(5)[:40])
    assert "version" in check_rpc(b"\x05" + rpc(5)[1:])
    assert "packet type" in check_rpc(rpc(5, ptype=11))
    assert "body" in check_rpc(lying_length())
