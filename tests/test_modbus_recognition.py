"""The Modbus decoy must recognise an MBAP frame before it answers one, and take its verdict
from what the function code means.

Reviewed 2026-11-20, 30 days on `sensor-a`, `sensor-c` and `sensor-e` (2,774 rows):

* **No recognition.** The protocol identifier was read and thrown away and the length was
  bounded at 65535. An HTTP request left no row and no reply (the handler sat waiting for a
  12 KB "PDU"); a TLS ClientHello or any MBAP with length 1 raised ``IndexError``; protocol
  identifier 0x1234 was answered as valid. About a dozen stored rows are a DICOM association
  request (``ANY-SCP`` / ``FINDSCU``) filed as ``Read Coils`` with ``qty=33792`` — its bytes
  2-3 are zero, so the protocol identifier alone does not catch it; the request length the
  specification fixes for function codes 1-6 does.
* **A second table.** Function codes 1-4 earned no verdict, so the one register walk in the
  window (246 rows in a minute, addresses 0-1900 in blocks of 100) is unlabelled. "Function
  code 90-100" meant ``ICS_ATTACK``: 286 rows, all Schneider UMAS (FC 90), sub-functions 01,
  02, 03, 04, 06 and 20 — session init, identification and a memory-block *read*. Not one of
  them writes, starts or stops anything.
* **Crashes.** A quantity of 128 holding registers or 2,041 coils raised ``ValueError`` while
  building the reply.

The verdict now comes from ``honeylens.ics`` through ``ics.verdict``; the decoy keeps no
function-code classification of its own.
"""

from __future__ import annotations

import asyncio
import logging
import struct

import pytest

from honeylens.honeypots import hp_modbus as hp
from honeylens.ics import decode
from tests.ics_fakes import FakeReader, FakeWriter


def adu(pdu: bytes, txn: int = 1, unit: int = 1, proto: int = 0) -> bytes:
    return struct.pack(">HHHB", txn, proto, len(pdu) + 1, unit) + pdu


READ_HOLDING = bytes.fromhex("0300000004")
WRITE_REGISTER = bytes.fromhex("0600010002")
DEVICE_ID = bytes.fromhex("2b0e0100")
HTTP = b"GET / HTTP/1.1\r\nHost: scanner.example\r\nUser-Agent: x\r\n\r\n"
TLS = bytes.fromhex("1603010200010001fc0303") + bytes(range(64))
# A DICOM A-ASSOCIATE-RQ: PDU type 01, reserved 00, a four-byte length, protocol version 0001.
DICOM = (
    bytes.fromhex("0100000000cd0001") + b"\x00\x00ANY-SCP         FINDSCU         " + b"\x00" * 160
)


# --- 1. The MBAP header ------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "why"),
    [
        (adu(READ_HOLDING)[:7], None),
        (adu(READ_HOLDING, unit=255)[:7], None),
        (adu(READ_HOLDING, proto=0x1234)[:7], "protocol identifier"),
        (HTTP[:7], "protocol identifier"),
        (TLS[:7], "protocol identifier"),
        (struct.pack(">HHHB", 1, 0, 1, 1), "length"),
        (struct.pack(">HHHB", 1, 0, 0, 1), "length"),
        (struct.pack(">HHHB", 1, 0, 255, 1), "length"),
        (struct.pack(">HHHB", 1, 0, 0x3000, 1), "length"),
    ],
)
def test_check_mbap(header, why):
    defect = hp.check_mbap(header)

    assert (defect is None) if why is None else (defect is not None and why in defect)


# --- 2. The PDU --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pdu", "ok"),
    [
        (READ_HOLDING, True),
        (WRITE_REGISTER, True),
        (bytes.fromhex("10000100020400010002"), True),
        (bytes.fromhex("0f0001000a02ff03"), True),
        (DEVICE_ID, True),
        (bytes.fromhex("11"), True),
        (bytes.fromhex("5a0002"), True),  # an unlisted code has no length to check
        (bytes.fromhex("0300000004ff"), False),  # a read is exactly five bytes
        (bytes.fromhex("0100"), False),
        (DICOM[7 : 7 + 204], False),  # "Read Coils" of 204 bytes
        (bytes.fromhex("1000010002040001"), False),  # byte count says four, two present
        (bytes.fromhex("00"), False),  # function code 0 does not exist
    ],
)
def test_check_pdu(pdu, ok):
    assert (hp.check_pdu(pdu) is None) is ok


# --- 3. The stream -----------------------------------------------------------------


@pytest.fixture
def run(monkeypatch):
    """Drive the real connection handler; collect (event, attack_type, severity, raw)."""
    events: list[tuple[dict, str | None, str | None, bytes | None]] = []

    def _log(protocol, peer, data, attack_type=None, severity=None, proto=None, raw=None):
        events.append((data, attack_type, severity, raw))
        return {}

    monkeypatch.setattr(hp, "log_event", _log)

    def _run(stream: bytes):
        decoy = hp.ModbusHoneypot.__new__(hp.ModbusHoneypot)
        decoy.profile = {}
        decoy.port = 502
        decoy.logger = logging.getLogger("test-modbus")
        decoy.device_id, decoy.vendor = "Schneider Electric PM5560", "Schneider Electric"
        decoy.product, decoy.firmware, decoy.unit_id = "PM5560", "3.4.2", 1
        writer = FakeWriter()
        asyncio.run(decoy.handle_connection(FakeReader(stream), writer, ("203.0.113.9", 4000)))
        return events, writer

    return _run


@pytest.mark.parametrize(
    ("stream", "guess"),
    [(HTTP, "http"), (TLS, "tls"), (DICOM, "binary")],
    ids=["http", "tls", "dicom"],
)
def test_a_foreign_stream_is_one_scanner_event_and_gets_no_reply(run, stream, guess):
    events, writer = run(stream)

    assert len(events) == 1
    data, attack_type, severity, raw = events[0]
    assert (attack_type, severity) == ("SCANNER", "LOW")
    assert data["phase"] == "foreign_on_ics_port" and data["ics"] is False
    assert data["foreign_protocol"] == guess
    assert data["rule"] == f"not Modbus: {guess}"
    assert data["client_bytes"] == len(stream)
    assert "fc" not in data and "pdu_hex" not in data
    assert raw == stream
    assert bytes(writer.sent) == b""


def test_a_stream_that_ends_inside_the_header_is_still_recorded(run):
    events, _ = run(b"\x16\x03\x01")

    assert [d["phase"] for d, *_ in events] == ["foreign_on_ics_port"]


def test_a_connection_that_sends_nothing_writes_nothing(run):
    events, writer = run(b"")

    assert events == [] and bytes(writer.sent) == b""


def test_a_valid_session_that_loses_framing_is_a_desync(run):
    events, writer = run(adu(READ_HOLDING) + HTTP)

    assert [d["phase"] for d, *_ in events] == ["modbus_request", "ics_desync"]
    data, attack_type, severity, _ = events[1]
    assert (attack_type, severity) == ("ICS_RECON", "LOW")
    assert data["frames_before"] == 1 and "ics" not in data
    assert len(writer.sent) == 7 + 2 + 8  # the one read was answered, nothing after


def test_a_recognised_request_keeps_the_keys_the_ingest_reads(run):
    events, writer = run(adu(READ_HOLDING, txn=7, unit=3))

    data = events[0][0]
    assert data["phase"] == "modbus_request" and data["dst_port"] == 502
    assert data["fc"] == 3 and data["unit_id"] == 3 and data["txn_id"] == 7
    assert data["address"] == 0 and data["quantity"] == 4
    assert data["pdu_hex"] == READ_HOLDING.hex() and data["is_write"] is False
    assert data["rule"] == data["fc_name"] == "Read Holding Registers"
    assert bytes(writer.sent) == struct.pack(">HHHB", 7, 0, 11, 3) + b"\x03\x08" + bytes(8)


def test_pipelined_requests_are_each_answered(run):
    events, writer = run(
        adu(READ_HOLDING, txn=1) + adu(DEVICE_ID, txn=2) + adu(READ_HOLDING, txn=3)
    )

    assert [d["fc"] for d, *_ in events] == [3, 43, 3]
    assert bytes(writer.sent).count(b"\x00\x00\x00\x0b\x01\x03\x08") == 2


# --- 4. The verdict comes from the decoder -----------------------------------------


@pytest.mark.parametrize(
    ("pdu", "verdict"),
    [
        (bytes.fromhex("0100000010"), ("ICS_RECON", "LOW")),
        (bytes.fromhex("0200000010"), ("ICS_RECON", "LOW")),
        (READ_HOLDING, ("ICS_RECON", "LOW")),
        (bytes.fromhex("0400000004"), ("ICS_RECON", "LOW")),
        (DEVICE_ID, ("MODBUS_RECON", "LOW")),
        (bytes.fromhex("11"), ("MODBUS_RECON", "LOW")),
        (bytes.fromhex("050001ff00"), ("ICS_ATTACK", "HIGH")),
        (WRITE_REGISTER, ("ICS_ATTACK", "HIGH")),
        (bytes.fromhex("0f0001000a02ff03"), ("ICS_ATTACK", "HIGH")),
        (bytes.fromhex("10000100020400010002"), ("ICS_ATTACK", "HIGH")),
        (bytes.fromhex("160004f2f20025"), ("ICS_ATTACK", "HIGH")),
        (bytes.fromhex("17000000010000000102abcd"), ("ICS_ATTACK", "HIGH")),
        (bytes.fromhex("63"), ("ICS_RECON", "MEDIUM")),  # not in the specification: no order given
    ],
)
def test_verdict_by_function_code(run, pdu, verdict):
    events, _ = run(adu(pdu))

    assert (events[0][1], events[0][2]) == verdict


def test_a_register_walk_is_labelled(run):
    """`sensor-c`, 2026-11-19 21:52: FC 3 and FC 4 over addresses 0-1900, 246 rows, no verdict."""
    walk = b"".join(
        adu(struct.pack(">BHH", 3, addr, 100), txn=i) for i, addr in enumerate(range(0, 2000, 100))
    )

    events, _ = run(walk)

    assert len(events) == 20
    assert {(at, sev) for _, at, sev, _ in events} == {("ICS_RECON", "LOW")}


@pytest.mark.parametrize("sub", [0x01, 0x02, 0x03, 0x04, 0x06, 0x20])
def test_the_umas_requests_seen_on_the_fleet_are_not_attacks(run, sub):
    events, _ = run(adu(bytes([0x5A, 0x00, sub])))

    data, attack_type, _, _ = events[0]
    assert attack_type in ("ICS_RECON", "MODBUS_RECON")
    assert data["fc"] == 90 and data["rule"].startswith("UMAS ")
    assert data["is_write"] is False


@pytest.mark.parametrize(
    ("sub", "severity"),
    [(0x41, "CRITICAL"), (0x40, "CRITICAL"), (0x10, "CRITICAL"), (0x34, "HIGH"), (0x23, "HIGH")],
)
def test_a_umas_stop_or_download_is_an_attack(run, sub, severity):
    events, _ = run(adu(bytes([0x5A, 0x01, sub])))

    assert (events[0][1], events[0][2]) == ("ICS_ATTACK", severity)


def test_an_unknown_umas_function_is_an_anomaly_not_an_attack(run):
    events, _ = run(adu(bytes([0x5A, 0x00, 0xEE])))

    assert (events[0][1], events[0][2]) == ("ICS_RECON", "MEDIUM")


def test_the_decoder_names_the_umas_function():
    frame = decode("modbus", bytes.fromhex("5a0020001400000000000002"))

    by = {f.name: f for f in frame.fields}
    assert frame.code == 90 and frame.semantics == "read"
    assert by["function_code"].meaning == "Unity (UMAS)"
    assert by["umas_function"].value == 0x20 and by["umas_function"].meaning == "Read Memory Block"
    assert by["session_key"].value == 0


def test_is_write_follows_the_decoder(run):
    events, _ = run(adu(WRITE_REGISTER) + adu(bytes.fromhex("160004f2f20025")) + adu(READ_HOLDING))

    assert [d["is_write"] for d, *_ in events] == [True, True, False]


# --- 5. Nothing a peer sends raises -------------------------------------------------


@pytest.mark.parametrize(
    "pdu",
    [
        bytes.fromhex("0300000080"),  # 128 registers: 256 does not fit the byte count
        bytes.fromhex("03000007d0"),
        bytes.fromhex("01000007f9"),  # 2,041 coils
        bytes.fromhex("0100000000"),
        bytes.fromhex("030000ffff"),
    ],
)
def test_an_illegal_quantity_gets_exception_3_not_a_crash(run, pdu):
    events, writer = run(adu(pdu, txn=9))

    assert len(events) == 1
    assert bytes(writer.sent) == struct.pack(">HHHB", 9, 0, 3, 1) + bytes([pdu[0] | 0x80, 0x03])


def test_no_byte_string_raises(run):
    import random

    rng = random.Random(20261120)
    for _ in range(300):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        run(blob)
        run(adu(blob[:20]) + blob)
