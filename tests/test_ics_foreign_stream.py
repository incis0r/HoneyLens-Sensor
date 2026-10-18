"""One shape for "this is not our protocol", shared by every industrial decoy.

Reviewed 2026-11-20, 30 days on three sensors: the IEC-104 defect fixed the day before was not
an exception. 383 of ~1,439 EtherNet/IP rows were TLS handshakes stored as ``ICS_RECON``; about
70% of the Fox rows were RDP, SMB, SIP and TLS; RDP on port 102 was given a COTP connection
confirm and stored as S7comm; OPC UA, FINS, DNP3 and Modbus dropped a foreign stream without a
row. A decoy either parsed bytes that were not its protocol or kept no evidence of them.

The rule the IEC-104 decoy already follows, now in one place: a stream that fails the decoy's
own recognition is recorded **once**, as ``foreign_on_ics_port`` with ``ics: False`` and the
verdict ``SCANNER``/LOW, and is never parsed.
"""

from __future__ import annotations

import asyncio

import pytest

from honeylens.honeypots import hp_iec104
from honeylens.honeypots.ics import foreign
from tests.ics_fakes import FakeReader

TLS = bytes.fromhex("160301020001000001fc0303") + b"\x00" * 40
HTTP = b"GET / HTTP/1.1\r\nHost: scanner.example\r\n\r\n"
RDP = bytes.fromhex("030000130ee000000000000100080003000000")
RDP_COOKIE = bytes.fromhex("0300002b26e00000000000") + b"Cookie: mstshash=hello\r\n"
SMB1 = b"\x00\x00\x00\x2f\xffSMB\x72" + b"\x00" * 20
SMB2 = b"\x00\x00\x00\x2f\xfeSMB\x40" + b"\x00" * 20


@pytest.mark.parametrize(
    ("data", "want"),
    [
        (TLS, "tls"),
        (HTTP, "http"),
        (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "http"),
        (b"SSH-2.0-Go\r\n", "ssh"),
        (RDP, "rdp"),
        (RDP_COOKIE, "rdp"),
        (SMB1, "smb"),
        (SMB2, "smb"),
        (b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\n", "fox"),
        (b"\x03\x00\x00\x16\x11\xd0\x00\x01", "tpkt"),
        (b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TCP nm\r\n", "text"),
        (bytes(range(1, 60)), "binary"),
        (b"", "empty"),
    ],
)
def test_the_guess_names_what_an_analyst_would(data, want):
    assert foreign.guess_foreign(data) == want


def test_a_foreign_event_is_not_an_ics_row_and_keeps_the_evidence():
    event = foreign.foreign_event(502, HTTP, "Modbus", "protocol identifier 0x2f20 is not 0")

    assert event["phase"] == "foreign_on_ics_port"
    assert event["ics"] is False
    assert event["dst_port"] == 502
    assert event["foreign_protocol"] == "http"
    assert event["rule"] == "not Modbus: http"
    assert event["defect"] == "protocol identifier 0x2f20 is not 0"
    assert event["client_bytes"] == len(HTTP)
    assert event["preview"].startswith("GET / HTTP/1.1..Host:")
    assert event["first_bytes_hex"] == HTTP.hex()
    assert "Modbus" in event["payload"] and "502" in event["payload"]
    assert foreign.FOREIGN_VERDICT == ("SCANNER", "LOW")


def test_the_evidence_kept_in_metadata_is_bounded():
    event = foreign.foreign_event(4840, b"A" * 5000, "OPC UA", "message type 'AAA'")

    assert event["client_bytes"] == 5000
    assert len(event["preview"]) == 200
    assert len(event["first_bytes_hex"]) == 128


def test_a_session_that_loses_framing_is_a_desync_not_a_foreign_stream():
    event = foreign.desync_event(44818, b"\xff" * 24, "EtherNet/IP", "unknown command 0xffff", 3)

    assert event["phase"] == "ics_desync"
    assert event["frames_before"] == 3
    assert "ics" not in event
    assert event["rule"] == "malformed frame after a valid session"
    assert foreign.DESYNC_VERDICT == ("ICS_RECON", "LOW")


def test_read_rest_collects_what_the_peer_already_sent():
    reader = FakeReader(b" HTTP/1.1\r\n\r\n")

    data = asyncio.run(foreign.read_rest(reader, b"GET /"))

    assert data == b"GET / HTTP/1.1\r\n\r\n"


def test_read_rest_survives_a_peer_that_is_gone():
    class Gone:
        async def read(self, n):
            raise ConnectionResetError

    assert asyncio.run(foreign.read_rest(Gone(), b"\x16\x03")) == b"\x16\x03"


def test_the_iec104_decoy_uses_the_shared_guess():
    assert hp_iec104.guess_foreign is foreign.guess_foreign
