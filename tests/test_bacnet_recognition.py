"""The BACnet/IP decoy must recognise a BVLC datagram, read its NPDU the way the standard lays
it out, record what it does not answer, and take its service names and verdicts from the
decoder.

Reviewed 2026-11-20, 30 days on three sensors (`sensor-a`, `sensor-c`, `sensor-e`), 1,479 rows:

* **The canonical device discovery was dropped without a row.** A global-broadcast Who-Is is
  `81 0b 00 0c 01 20 ff ff 00 ff 10 08`: the NPDU names a destination network, a one-byte
  address length and a hop count. The decoy read the length as two bytes (`00 ff` = 255),
  ran past the end of the datagram and returned. Six Who-Is rows in thirty days on three
  public sensors, every one of them the non-routed form.
* BVLC control functions (Register-Foreign-Device, Read-Broadcast-Distribution-Table,
  Read-Foreign-Device-Table) and network-layer messages were dropped with a debug line. The
  first is how a remote scanner asks a BBMD to forward broadcasts to it.
* The BVLC length was never compared with the datagram, and a datagram that was not BACnet
  left no row at all.
* The decoy's own service table called confirmed service 4 "CreateObject" and 8 "DeleteObject"
  (they are GetEnrollmentSummary and AddListElement; CreateObject is 10, DeleteObject 11) and
  knew six services. DeviceCommunicationControl, WritePropertyMultiple, AtomicWriteFile,
  TimeSynchronization and Who-Has had no name and no verdict. `honeylens.ics.bacnet` had the
  full table.
"""

from __future__ import annotations

import random
import struct

import pytest

from honeylens.honeypots import hp_bacnet as hp
from tests.ics_fakes import FakeDatagramTransport
from tests.test_ics_decode_bacnet import READ_PROPERTY, WHO_IS, WRITE_PROPERTY

PEER = ("203.0.113.9", 47808)
GLOBAL_WHO_IS = bytes.fromhex("810b000c0120ffff00ff1008")
HTTP = b"GET / HTTP/1.1\r\nHost: scanner.example\r\n\r\n"
DNS = bytes.fromhex("12340100000100000000000007657861") + b"mple\x03com\x00\x00\x01\x00\x01"


def bvlc(function: int, payload: bytes = b"") -> bytes:
    return struct.pack(">BBH", 0x81, function, len(payload) + 4) + payload


def unicast(apdu: bytes) -> bytes:
    return bvlc(0x0A, b"\x01\x00" + apdu)


def confirmed(service: int, data: bytes = b"") -> bytes:
    return bytes([0x00, 0x05, 0x01, service]) + data


@pytest.fixture
def run(monkeypatch):
    events: list[tuple[dict, str | None, str | None]] = []

    def _log(protocol, peer, data, attack_type=None, severity=None, **kw):
        events.append((data, attack_type, severity))

    monkeypatch.setattr(hp, "log_event", _log)
    proto = hp.BACnetProtocol(hp.BACnetHoneypot())
    transport = FakeDatagramTransport()
    proto.connection_made(transport)

    def _run(datagram: bytes):
        events.clear()
        transport.sent.clear()
        proto._handle_packet(datagram, PEER)
        return events, transport.sent

    return _run


# ── recognition ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "datagram",
    [
        GLOBAL_WHO_IS,
        unicast(bytes.fromhex(READ_PROPERTY)),
        bvlc(0x04, bytes([198, 51, 100, 7, 0xBA, 0xC0]) + b"\x01\x00\x10\x08"),
        bvlc(0x05, b"\x00\x3c"),
        bvlc(0x02),
        bvlc(0x06),
    ],
)
def test_a_bvlc_datagram_is_recognised(datagram):
    assert hp.check_bvlc(datagram) is None


@pytest.mark.parametrize(
    ("datagram", "why"),
    [
        (HTTP, "BVLC type 0x47"),
        (DNS, "BVLC type 0x12"),
        (b"\x81\x0a", "2 byte(s)"),
        (b"", "0 byte(s)"),
        (bvlc(0x7F), "BVLC function 0x7f"),
        (bvlc(0x0A, b"\x01\x00\x10\x08") + b"\x00", "length field"),
        (struct.pack(">BBH", 0x81, 0x0A, 400) + b"\x01\x00\x10\x08", "length field"),
        (bvlc(0x0A, b"\x02\x00\x10\x08"), "NPDU version 2"),
        (bvlc(0x0A, b"\x01"), "NPDU"),
        (bvlc(0x04, b"\x01\x00\x10\x08"), "NPDU"),
    ],
)
def test_what_is_not_bacnet_ip_is_refused_with_a_reason(datagram, why):
    defect = hp.check_bvlc(datagram)

    assert defect is not None and why in defect


@pytest.mark.parametrize(("datagram", "guess"), [(HTTP, "http"), (DNS, "binary")])
def test_a_foreign_datagram_is_one_event_and_gets_no_reply(run, datagram, guess):
    events, sent = run(datagram)

    assert len(events) == 1
    data, attack_type, severity = events[0]
    assert (attack_type, severity) == ("SCANNER", "LOW")
    assert data["phase"] == "foreign_on_ics_port"
    assert data["ics"] is False
    assert data["foreign_protocol"] == guess
    assert sent == []


def test_the_global_broadcast_who_is_is_a_row_and_is_answered(run):
    events, sent = run(GLOBAL_WHO_IS)

    assert len(events) == 1
    data, attack_type, severity = events[0]
    assert data["phase"] == "bacnet_unconfirmed"
    assert data["rule"] == "Who-Is"
    assert data["apdu_hex"] == "1008"
    assert (attack_type, severity) == ("ICS_RECON", "LOW")
    assert len(sent) == 1 and sent[0][1] == PEER
    assert sent[0][0][6:8] == b"\x10\x00"  # an I-Am


@pytest.mark.parametrize(
    ("npdu", "apdu"),
    [
        ("0100", WHO_IS),
        ("0120ffff00ff", WHO_IS),  # destination: every network
        ("01200005020a0bff", WHO_IS),  # destination with a two-byte address
        ("01080007030a0b0c", WHO_IS),  # source only: no hop count
        ("0128ffff00000701aaff", WHO_IS),  # destination and source, then the hop count
        ("0124ffff00ff", READ_PROPERTY),  # expecting-reply bit does not move anything
    ],
)
def test_the_apdu_is_found_behind_every_npdu_layout(run, npdu, apdu):
    events, _ = run(bvlc(0x0B, bytes.fromhex(npdu) + bytes.fromhex(apdu)))

    assert [d["apdu_hex"] for d, _, _ in events] == [apdu]


def test_an_npdu_that_ends_inside_its_addresses_is_a_row_not_a_guess(run):
    events, sent = run(bvlc(0x0B, bytes.fromhex("0120ffff06ff")))

    assert [d["phase"] for d, _, _ in events] == ["bacnet_malformed"]
    assert events[0][1] == "ICS_RECON"
    assert sent == []


@pytest.mark.parametrize(
    ("datagram", "rule", "verdict"),
    [
        (bvlc(0x05, b"\x00\x3c"), "Register-Foreign-Device", ("ICS_RECON", "LOW")),
        (bvlc(0x02), "Read-Broadcast-Distribution-Table", ("ICS_RECON", "LOW")),
        (bvlc(0x06), "Read-Foreign-Device-Table", ("ICS_RECON", "LOW")),
        (bvlc(0x01, bytes(10)), "Write-Broadcast-Distribution-Table", ("ICS_ATTACK", "HIGH")),
        (bvlc(0x08, bytes(6)), "Delete-Foreign-Device-Table-Entry", ("ICS_ATTACK", "HIGH")),
    ],
)
def test_a_bvlc_control_function_is_named_and_not_answered(run, datagram, rule, verdict):
    events, sent = run(datagram)

    assert len(events) == 1
    data, attack_type, severity = events[0]
    assert data["phase"] == "bacnet_bvlc"
    assert data["rule"] == rule
    assert data["bvlc_function"] == datagram[1]
    assert data["datagram_hex"] == datagram.hex()
    assert "apdu_hex" not in data and "frame_hex" not in data
    assert (attack_type, severity) == verdict
    assert sent == []


@pytest.mark.parametrize(
    ("message", "rule", "verdict"),
    [
        ("00", "Who-Is-Router-To-Network", ("ICS_RECON", "LOW")),
        ("12", "What-Is-Network-Number", ("ICS_RECON", "LOW")),
        ("0600", "Initialize-Routing-Table", ("ICS_RECON", "LOW")),  # no ports: a query
        ("06010005010100", "Initialize-Routing-Table", ("ICS_ATTACK", "HIGH")),
        ("090005", "Disconnect-Connection-To-Network", ("ICS_ATTACK", "CRITICAL")),
        ("7f", "Network message 0x7f", ("ICS_RECON", "LOW")),
    ],
)
def test_a_network_layer_message_is_named_and_not_answered(run, message, rule, verdict):
    events, sent = run(bvlc(0x0B, b"\x01\x80" + bytes.fromhex(message)))

    assert len(events) == 1
    data, attack_type, severity = events[0]
    assert data["phase"] == "bacnet_network"
    assert data["rule"] == rule
    assert (attack_type, severity) == verdict
    assert sent == []


def test_a_response_pdu_sent_at_the_decoy_is_recorded(run):
    events, sent = run(unicast(bytes.fromhex("300108")))  # a Complex-ACK nobody asked for

    assert [(d["phase"], d["rule"]) for d, _, _ in events] == [("bacnet_pdu", "Complex-ACK")]
    assert sent == []


def test_no_input_raises(run):
    rng = random.Random(20261120)
    for _ in range(600):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 60)))
        run(blob)
        run(bvlc(rng.choice([0x04, 0x09, 0x0A, 0x0B]), blob))
        run(bvlc(0x0B, b"\x01" + blob))
        run(unicast(blob))


# ── one table ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("apdu", "rule", "verdict"),
    [
        (bytes.fromhex(READ_PROPERTY), "ReadProperty", ("ICS_RECON", "LOW")),
        (confirmed(14), "ReadPropertyMultiple", ("ICS_RECON", "LOW")),
        (bytes.fromhex(WRITE_PROPERTY), "WriteProperty", ("ICS_ATTACK", "HIGH")),
        (confirmed(16), "WritePropertyMultiple", ("ICS_ATTACK", "HIGH")),
        (confirmed(7), "AtomicWriteFile", ("ICS_ATTACK", "HIGH")),
        (confirmed(10), "CreateObject", ("ICS_ATTACK", "HIGH")),
        (confirmed(11), "DeleteObject", ("ICS_ATTACK", "HIGH")),
        (confirmed(17), "DeviceCommunicationControl", ("ICS_ATTACK", "CRITICAL")),
        (confirmed(20), "ReinitializeDevice", ("ICS_ATTACK", "CRITICAL")),
        (confirmed(4), "GetEnrollmentSummary", ("ICS_RECON", "LOW")),
        (confirmed(0x63), "Confirmed_0x63", ("ICS_RECON", "LOW")),
    ],
)
def test_a_confirmed_service_is_named_and_judged_by_the_decoder(run, apdu, rule, verdict):
    events, _ = run(unicast(apdu))

    data, attack_type, severity = events[0]
    assert data["phase"] == "bacnet_confirmed"
    assert data["rule"] == rule and data["service_name"] == rule
    assert data["service"] == apdu[3]
    assert (attack_type, severity) == verdict


@pytest.mark.parametrize(
    ("apdu", "rule", "verdict"),
    [
        ("1008", "Who-Is", ("ICS_RECON", "LOW")),
        ("1007", "Who-Has", ("ICS_RECON", "LOW")),
        ("1006", "TimeSynchronization", ("ICS_ATTACK", "CRITICAL")),
        ("1009", "UTCTimeSynchronization", ("ICS_ATTACK", "CRITICAL")),
        ("100a", "WriteGroup", ("ICS_ATTACK", "HIGH")),
        ("1000", "I-Am", ("ICS_RECON", "LOW")),
        ("1063", "Unconfirmed_0x63", ("ICS_RECON", "LOW")),
    ],
)
def test_an_unconfirmed_service_is_named_and_judged_by_the_decoder(run, apdu, rule, verdict):
    events, _ = run(unicast(bytes.fromhex(apdu)))

    data, attack_type, severity = events[0]
    assert data["phase"] == "bacnet_unconfirmed"
    assert data["rule"] == rule
    assert (attack_type, severity) == verdict


def test_a_segmented_request_is_read_where_its_service_choice_is(run):
    """A segmented Confirmed-Request carries a sequence number and a window size before the
    service choice; the decoy used to read the sequence number as the service."""
    events, _ = run(unicast(bytes([0x08, 0x05, 0x01, 0x00, 0x04, 0x0F]) + b"\x0c\x00\x40\x00\x01"))

    assert events[0][0]["rule"] == "WriteProperty"
    assert events[0][0]["service"] == 0x0F


def test_every_row_keeps_the_whole_datagram(run):
    datagram = unicast(bytes.fromhex(READ_PROPERTY))

    events, _ = run(datagram)

    assert events[0][0]["datagram_hex"] == datagram.hex()
    assert events[0][0]["bvlc_function"] == 0x0A


def test_the_decoy_keeps_no_table_of_its_own():
    assert not hasattr(hp, "CONFIRMED_SERVICE_NAMES")
    assert not hasattr(hp, "UNCONFIRMED_SERVICE_NAMES")
    assert not hasattr(hp, "SVC_CREATE_OBJECT")
