"""The OPC UA decoy must recognise a transport header, record what is not one, and take its
service names and verdicts from the decoder.

Reviewed 2026-11-20, 30 days on three sensors (`sensor-a`, `sensor-c`, `sensor-e`), 933 rows:

* The decoy stored **zero** unparsed rows on a public port that certainly receives HTTP and TLS
  version scans. `GET ` and a TLS record both read as a message size outside 8..65535, the
  loop hit `break`, and nothing was written.
* Its service table had the wrong node ids: FindServers was listed as 426 (it is 422) and Call
  as 710 (it is 712). So 29 FindServers requests were stored as `Service_422` with no verdict
  and the FindServers reply could never be sent, and a real Call would have earned nothing.
  `honeylens.ics.opcua` had both right.
* `Hello` (349 rows), `OpenSecureChannel` (257) and `CloseSecureChannel` (37) carried no verdict,
  which is most of the family's 72% "unlabelled" share on traffic that was fully understood.
* `ActivateSessionRequest` was `ICS_ATTACK`: logging in is not an operation on the process.
"""

from __future__ import annotations

import asyncio
import random
import struct

import pytest

from honeylens.honeypots import hp_opcua as hp
from honeylens.ics import opcua as opcua_decoder
from tests.ics_fakes import FakeReader, FakeWriter

PEER = ("203.0.113.9", 40000)
TLS = bytes.fromhex("160301020001000001fc0303") + bytes(range(64))
HTTP = b"GET / HTTP/1.1\r\nHost: scanner.example\r\n\r\n"


def message(kind: bytes, body: bytes, chunk: bytes = b"F") -> bytes:
    return kind + chunk + struct.pack("<I", len(body) + 8) + body


def hello(url: bytes = b"opc.tcp://plc.example:4840") -> bytes:
    body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + struct.pack("<I", len(url)) + url
    return message(b"HEL", body)


OPEN = message(b"OPN", struct.pack("<I", 0) + b"\x00" * 40)
CLOSE = message(b"CLO", struct.pack("<I", 1) + b"\x00" * 12)


def request(service: int, tail: bytes = b"\x00" * 8) -> bytes:
    chan = struct.pack("<IIII", 1, 1, 2, 3)
    return message(b"MSG", chan + b"\x01\x00" + struct.pack("<H", service) + tail)


def raw_header(kind: bytes = b"HEL", chunk: bytes = b"F", size: int = 32) -> bytes:
    return kind + chunk + struct.pack("<I", size)


@pytest.fixture
def run(monkeypatch):
    events: list[tuple[dict, str | None, str | None]] = []

    def _log(protocol, peer, data, attack_type=None, severity=None, **kw):
        events.append((data, attack_type, severity))

    monkeypatch.setattr(hp, "log_event", _log)

    def _run(stream: bytes):
        events.clear()
        writer = FakeWriter()
        asyncio.run(hp.OpcuaHoneypot().handle_connection(FakeReader(stream), writer, PEER))
        return events, writer

    return _run


# ── recognition ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("kind", [b"HEL", b"OPN", b"MSG", b"CLO", b"ERR", b"ACK", b"RHE"])
def test_every_message_type_of_the_transport_is_recognised(kind):
    assert hp.check_header(raw_header(kind), first=False) is None


@pytest.mark.parametrize("chunk", [b"F", b"C", b"A"])
def test_a_message_may_be_chunked(chunk):
    assert hp.check_header(raw_header(b"MSG", chunk), first=False) is None


@pytest.mark.parametrize(
    ("data", "first", "why"),
    [
        (HTTP[:8], True, "message type"),
        (TLS[:8], True, "message type"),
        (raw_header(b"HEL", b"X"), True, "chunk type"),
        (raw_header(b"HEL", b"C"), True, "chunk type"),
        (raw_header(size=7), True, "size 7"),
        (raw_header(size=65536), True, "size 65536"),
        (raw_header(b"OPN"), True, "HEL"),
        (raw_header(b"MSG"), True, "HEL"),
        (b"HELF", True, "4 byte(s)"),
    ],
)
def test_what_is_not_a_transport_header_is_refused_with_a_reason(data, first, why):
    defect = hp.check_header(data, first=first)

    assert defect is not None and why in defect


@pytest.mark.parametrize(("stream", "guess"), [(HTTP, "http"), (TLS, "tls")])
def test_a_foreign_stream_is_one_event_and_gets_no_reply(run, stream, guess):
    events, writer = run(stream)

    assert len(events) == 1
    data, attack_type, severity = events[0]
    assert (attack_type, severity) == ("SCANNER", "LOW")
    assert data["phase"] == "foreign_on_ics_port"
    assert data["ics"] is False
    assert data["foreign_protocol"] == guess
    assert data["client_bytes"] == len(stream)
    assert writer.sent == b""


def test_a_stream_shorter_than_a_header_is_still_recorded(run):
    events, writer = run(b"\r\n\r\n")

    assert [d["phase"] for d, _, _ in events] == ["foreign_on_ics_port"]
    assert writer.sent == b""


def test_a_connection_that_sends_nothing_writes_nothing(run):
    events, writer = run(b"")

    assert events == [] and writer.sent == b""


def test_framing_lost_after_hello_is_a_desync(run):
    events, writer = run(hello() + HTTP)

    assert [d["phase"] for d, _, _ in events] == ["opcua_hello", "ics_desync"]
    assert events[1][1:] == ("ICS_RECON", "LOW")
    assert events[1][0]["frames_before"] == 1
    assert writer.sent[:3] == b"ACK" and writer.sent.count(b"ERRF") == 0


def test_a_message_cut_short_is_recorded(run):
    events, _ = run(hello() + raw_header(b"MSG", size=200) + b"\x00" * 20)

    assert [d["phase"] for d, _, _ in events] == ["opcua_hello", "opcua_truncated"]


def test_no_input_raises(run):
    rng = random.Random(20261120)
    for _ in range(300):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 90)))
        run(blob)
        run(hello() + blob)
        run(hello() + OPEN + message(b"MSG", blob))
        run(message(b"HEL", blob))
        run(hello() + message(b"OPN", blob))


# ── one table ────────────────────────────────────────────────────────────


def test_the_handshake_is_named_and_carries_a_verdict(run):
    events, _ = run(hello() + OPEN + CLOSE)

    assert [(d["rule"], at, sev) for d, at, sev in events] == [
        ("Hello", "ICS_RECON", "LOW"),
        ("OpenSecureChannel", "ICS_RECON", "LOW"),
        ("CloseSecureChannel", "ICS_RECON", "LOW"),
    ]
    assert events[0][0]["endpoint_url"] == "opc.tcp://plc.example:4840"


@pytest.mark.parametrize(
    ("service", "rule", "verdict"),
    [
        (422, "FindServersRequest", ("ICS_RECON", "LOW")),
        (428, "GetEndpointsRequest", ("ICS_RECON", "LOW")),
        (461, "CreateSessionRequest", ("ICS_RECON", "LOW")),
        (467, "ActivateSessionRequest", ("ICS_RECON", "LOW")),
        (527, "BrowseRequest", ("ICS_RECON", "LOW")),
        (631, "ReadRequest", ("ICS_RECON", "LOW")),
        (673, "WriteRequest", ("ICS_ATTACK", "HIGH")),
        (488, "AddNodesRequest", ("ICS_ATTACK", "HIGH")),
        (712, "CallRequest", ("ICS_ATTACK", "CRITICAL")),
        (9999, "Service_9999", ("ICS_RECON", "LOW")),
    ],
)
def test_a_service_is_named_and_judged_by_the_decoder(run, service, rule, verdict):
    events, _ = run(hello() + OPEN + request(service))

    data, attack_type, severity = events[2]
    assert data["phase"] == "opcua_request"
    assert data["rule"] == rule
    assert data["service_name"] == rule
    assert data["service_id"] == service
    assert (attack_type, severity) == verdict


def test_the_old_wrong_ids_mean_nothing(run):
    """426 and 710 are not service requests; the decoy used to call them FindServers and Call."""
    events, _ = run(hello() + OPEN + request(426) + request(710))

    assert [d["rule"] for d, _, _ in events[2:]] == ["Service_426", "Service_710"]
    assert all(at == "ICS_RECON" for _, at, _ in events[2:])


def test_find_servers_is_answered_with_its_own_response(run):
    _, writer = run(hello() + OPEN + request(422))

    reply = bytes(writer.sent)
    last = reply[reply.rindex(b"MSGF") :]
    # after the 8-byte header and the four channel words: FourByte NodeId, namespace 0
    assert struct.unpack("<BBH", last[24:28]) == (0x01, 0x00, 425)


def test_a_request_too_short_to_name_a_service_is_still_a_row(run):
    events, _ = run(hello() + OPEN + message(b"MSG", b"\x01\x00\x00\x00"))

    assert events[2][0]["phase"] == "opcua_request"
    assert events[2][1] == "ICS_RECON"


def test_the_decoy_keeps_no_table_of_its_own():
    assert not hasattr(hp, "SERVICE_CLASSIFICATION")
    assert hp.SERVICE_NAMES is opcua_decoder.SERVICE_NAMES
