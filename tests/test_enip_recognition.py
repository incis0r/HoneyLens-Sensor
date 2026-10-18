"""The EtherNet/IP decoy must recognise an encapsulation header, and take its verdict from the
decoder.

Reviewed 2026-11-20, 30 days on three sensors (`sensor-a`, `sensor-c`, `sensor-e`):

* 383 of about 1,439 `honeypot-enip` rows were TLS ClientHellos. Any 24 bytes were unpacked as
  an encapsulation header, so `16 03 01 ...` became command `CMD_0x0316`, was stored with
  `ICS_RECON` and was answered with an encapsulation reply. LDAP and other bytes landed as
  `CMD_0x8430`, `CMD_0x003A` and `CMD_0x5A00`.
* An HTTP request declares a length of 8,276 in the same two bytes and was dropped at the
  length check without a row.
* The decoy's own CIP table called service 0x52 "Read_Tag" and 0x53 "Write_Tag". They are
  Unconnected_Send and the fragmented tag services; Read Tag and Write Tag are 0x4C and 0x4D,
  which the decoy did not know. Forward_Open, Start and Stop earned nothing, and
  `SendUnitData` was `ICS_ATTACK` whatever it carried. `honeylens.ics.enip` had all of it right.
* `RegisterSession` carried no verdict: 36 rows, exactly the unlabelled ones.
"""

from __future__ import annotations

import asyncio
import random
import struct

import pytest

from honeylens.honeypots import hp_enip as hp
from tests.ics_fakes import FakeReader, FakeWriter
from tests.test_ics_decode_enip import GET_ATTR, READ_TAG, WRITE_TAG, encap, rr_data

PEER = ("203.0.113.9", 40000)
TLS = bytes.fromhex("160301020001000001fc0303") + bytes(range(64))
HTTP = b"GET / HTTP/1.1\r\nHost: scanner.example\r\nUser-Agent: x\r\n\r\n"
LDAP = bytes.fromhex("30840000002d02010163840000002404000a01000a0100020100020100010100")
LIST_IDENTITY = encap(0x63)
REGISTER = encap(0x65, struct.pack("<HH", 1, 0))


def header(command=0x63, length=0, session=0, status=0, options=0) -> bytes:
    return struct.pack("<HHII8sI", command, length, session, status, b"\x00" * 8, options)


@pytest.fixture
def run(monkeypatch):
    events: list[tuple[dict, str | None, str | None]] = []

    def _log(protocol, peer, data, attack_type=None, severity=None, **kw):
        events.append((data, attack_type, severity))

    monkeypatch.setattr(hp, "log_event", _log)

    def _run(stream: bytes):
        events.clear()
        writer = FakeWriter()
        asyncio.run(hp.ENIPHoneypot().handle_connection(FakeReader(stream), writer, PEER))
        return events, writer

    return _run


# ── recognition ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("command", [0x00, 0x04, 0x63, 0x64, 0x65, 0x66, 0x6F, 0x70, 0x72, 0x73])
def test_every_command_of_the_specification_is_recognised(command):
    session = 0 if command in (0x04, 0x63, 0x64, 0x65) else 7
    assert hp.check_encap(header(command, session=session)) is None


@pytest.mark.parametrize(
    ("data", "why"),
    [
        (TLS[:24], "command 0x0316"),
        (HTTP[:24], "command 0x4547"),
        (LDAP[:24], "command 0x8430"),
        (header(options=1), "options"),
        (header(status=0x65), "status"),
        (header(0x63, session=9), "session handle"),
        (header(0x6F, length=65512, session=1), "length"),
        (header(0x77), "command 0x0077"),
        (header(0x01), "command 0x0001"),
    ],
)
def test_what_is_not_an_encapsulation_request_is_refused_with_a_reason(data, why):
    defect = hp.check_encap(data)

    assert defect is not None and why in defect


def test_a_tls_handshake_is_one_foreign_event_and_gets_no_reply(run):
    events, writer = run(TLS)

    assert len(events) == 1
    data, attack_type, severity = events[0]
    assert (attack_type, severity) == ("SCANNER", "LOW")
    assert data["phase"] == "foreign_on_ics_port"
    assert data["ics"] is False
    assert data["foreign_protocol"] == "tls"
    assert data["client_bytes"] == len(TLS)
    assert "command" not in data
    assert writer.sent == b""


def test_an_http_request_is_recorded_instead_of_vanishing(run):
    events, writer = run(HTTP)

    assert [d["phase"] for d, _, _ in events] == ["foreign_on_ics_port"]
    assert events[0][0]["foreign_protocol"] == "http"
    assert events[0][0]["preview"].startswith("GET / HTTP/1.1")
    assert writer.sent == b""


def test_a_request_shorter_than_a_header_is_still_recorded(run):
    short = b"GET / HTTP/1.0\r\n\r\n"
    assert len(short) < 24

    events, writer = run(short)

    assert [d["phase"] for d, _, _ in events] == ["foreign_on_ics_port"]
    assert events[0][0]["client_bytes"] == len(short)
    assert writer.sent == b""


def test_a_connection_that_sends_nothing_writes_nothing(run):
    events, writer = run(b"")

    assert events == [] and writer.sent == b""


def test_framing_lost_after_a_valid_request_is_a_desync(run):
    events, writer = run(LIST_IDENTITY + TLS)

    assert [d["phase"] for d, _, _ in events] == ["enip_list_identity", "ics_desync"]
    assert events[1][1:] == ("ICS_RECON", "LOW")
    assert events[1][0]["frames_before"] == 1
    assert struct.unpack("<H", writer.sent[:2])[0] == 0x63  # only the ListIdentity was answered


def test_a_command_the_specification_does_not_define_is_answered_inside_a_session(run):
    """A device answers a well-formed header carrying an unknown command with status 1; only
    as the first thing on a connection is it a reason to doubt the stream."""
    events, writer = run(REGISTER + encap(0x77, b"\xaa\xbb", session=1))

    assert [d["phase"] for d, _, _ in events] == ["enip_register_session", "enip_unknown_command"]
    assert events[1][1:] == ("ICS_RECON", "MEDIUM")
    reply = writer.sent[28:]  # after the 28-byte RegisterSession reply
    assert struct.unpack("<HHII", reply[:12]) == (0x77, 0, 1, 1)


def test_command_data_cut_short_is_recorded(run):
    events, _ = run(header(0x6F, length=40, session=1) + b"\x00" * 10)

    assert [d["phase"] for d, _, _ in events] == ["enip_truncated"]
    assert events[0][1] == "ICS_RECON"


def test_no_input_raises(run):
    rng = random.Random(20261120)
    for _ in range(300):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 90)))
        run(blob)
        run(LIST_IDENTITY + blob)
        run(REGISTER + header(0x6F, length=len(blob), session=1) + blob)


# ── one table ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("frame", "rule", "verdict"),
    [
        (encap(0x00), "NOP", ("ICS_RECON", "LOW")),
        (encap(0x04), "ListServices", ("ICS_RECON", "LOW")),
        (LIST_IDENTITY, "ListIdentity", ("ICS_RECON", "LOW")),
        (encap(0x64), "ListInterfaces", ("ICS_RECON", "LOW")),
        (REGISTER, "RegisterSession", ("ICS_RECON", "LOW")),
    ],
)
def test_session_commands_take_their_verdict_from_the_decoder(run, frame, rule, verdict):
    events, _ = run(frame)

    assert len(events) == 1
    assert events[0][0]["rule"] == rule
    assert events[0][1:] == verdict


def cip(service: int, path: bytes, data: bytes = b"") -> bytes:
    return encap(0x6F, rr_data(bytes([service, len(path) // 2]) + path + data), session=1)


IDENTITY = bytes([0x20, 0x01, 0x24, 0x01])
CONNECTION_MANAGER = bytes([0x20, 0x06, 0x24, 0x01])
PCCC_OBJECT = bytes([0x20, 0x67, 0x24, 0x01])


def pccc(cmd: int, fnc: int) -> bytes:
    requestor = bytes([7]) + b"\x01\x00" + b"\x78\x56\x34\x12"
    return requestor + bytes([cmd, 0x00, 0x01, 0x00, fnc]) + b"\x02\x07\x89\x00\x00"


@pytest.mark.parametrize(
    ("frame", "rule", "verdict"),
    [
        (encap(0x6F, rr_data(GET_ATTR), session=1), "Get_Attribute_Single", ("ICS_RECON", "LOW")),
        (cip(0x01, IDENTITY), "Get_Attribute_All", ("ICS_RECON", "LOW")),
        (cip(0x10, IDENTITY, b"\x01\x00"), "Set_Attribute_Single", ("ICS_ATTACK", "HIGH")),
        (cip(0x05, IDENTITY), "Reset", ("ICS_ATTACK", "CRITICAL")),
        (cip(0x06, IDENTITY), "Start", ("ICS_ATTACK", "CRITICAL")),
        (cip(0x07, IDENTITY), "Stop", ("ICS_ATTACK", "CRITICAL")),
        (encap(0x6F, rr_data(READ_TAG), session=1), "Read Tag", ("ICS_RECON", "LOW")),
        (encap(0x6F, rr_data(WRITE_TAG), session=1), "Write Tag", ("ICS_ATTACK", "HIGH")),
        (cip(0x54, CONNECTION_MANAGER, b"\x0a\x0e"), "Forward_Open", ("ICS_RECON", "LOW")),
        (cip(0x52, CONNECTION_MANAGER, b"\x0a\x0e"), "Unconnected_Send", ("ICS_RECON", "LOW")),
        (cip(0x4B, PCCC_OBJECT, pccc(0x0F, 0xA2)), "Execute_PCCC", ("ICS_RECON", "LOW")),
        (cip(0x4B, PCCC_OBJECT, pccc(0x0F, 0xAA)), "Execute_PCCC", ("ICS_ATTACK", "HIGH")),
        (cip(0x4B, PCCC_OBJECT, pccc(0x0F, 0x80)), "Execute_PCCC", ("ICS_ATTACK", "CRITICAL")),
    ],
)
def test_a_cip_service_is_named_and_judged_by_the_decoder(run, frame, rule, verdict):
    events, _ = run(REGISTER + frame)

    data, attack_type, severity = events[1]
    assert data["phase"] == "enip_sendrr_cip"
    assert data["rule"] == rule
    assert data["cip_service_name"] == rule
    assert (attack_type, severity) == verdict


def test_service_0x52_on_a_class_path_is_no_longer_a_tag_read(run):
    events, _ = run(REGISTER + cip(0x52, CONNECTION_MANAGER, b"\x0a\x0e"))

    assert "Tag" not in events[1][0]["rule"]


def test_a_service_the_decoder_cannot_name_keeps_its_code(run):
    events, _ = run(REGISTER + cip(0x4B, IDENTITY))

    assert events[1][0]["rule"] == "CIP_0x4B"
    assert events[1][1] == "ICS_RECON"


def test_connected_data_is_not_an_attack_by_itself(run):
    events, _ = run(REGISTER + encap(0x70, b"\x00" * 16, session=1))

    assert events[1][0]["rule"] == "SendUnitData"
    assert events[1][1:] == ("ICS_RECON", "LOW")


def test_the_decoy_keeps_no_table_of_its_own():
    assert not hasattr(hp, "CIP_SERVICE_NAMES")
    assert not hasattr(hp, "ENIP_CMD_NAMES")
