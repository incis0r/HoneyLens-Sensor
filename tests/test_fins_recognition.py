"""The FINS decoy must recognise a FINS/TCP frame, record what is not one, and take a
command's name and verdict from the decoder.

Reviewed 2026-11-20, 30 days on `sensor-a` and `sensor-c` (356 rows, 163 sources):

* **Two tables that disagree.** The decoy's own (MRC, SRC) table named fourteen commands and
  got several wrong: ``03 06`` — Program Area Read — was "CPU Unit Status Read"; ``26 01`` and
  ``26 02`` are not FINS commands at all. Everything else was ``Unknown_*`` with
  ``ICS_RECON``: a Program Area Write (``03 07``), a Program Area Clear (``03 08``), a Forced
  Set/Reset (``23 01``) and a Memory Card Format (``22 04``) would all have been stored as
  reconnaissance. ``honeylens.ics.fins`` had them right the whole time.
* **Half the rows unlabelled.** 194 Node Address Requests carried no verdict, so the family
  read 54.5% unlabelled although 93% of its sources go on to a labelled command.
* **No record of a foreign stream.** A wrong magic, a short frame or an unhandled FINS/TCP
  command ended the connection without a row.

Only one command type reached the decoy in the window (Controller Data Read), so the verdicts
below are pinned from the protocol, not from traffic.
"""

from __future__ import annotations

import asyncio
import logging
import struct

import pytest

from honeylens.honeypots import hp_fins as hp
from tests.ics_fakes import FakeReader, FakeWriter
from tests.test_ics_decode_fins import CONTROLLER_DATA, HEADER, MEMORY_READ

HTTP = b"GET / HTTP/1.1\r\nHost: scanner.example\r\n\r\n"
TLS = bytes.fromhex("1603010200010001fc0303") + bytes(range(64))


def tcp(payload: bytes, command: int = 2, error: int = 0) -> bytes:
    return b"FINS" + struct.pack(">III", len(payload) + 8, command, error) + payload


def fins(mrc: int, src: int, data: bytes = b"") -> bytes:
    return tcp(bytes.fromhex(HEADER) + bytes([mrc, src]) + data)


NODE_REQUEST = tcp(b"\x00\x00\x00\x00", command=0)


# --- 1. The FINS/TCP header ---------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "why"),
    [
        (NODE_REQUEST[:16], None),
        (fins(5, 1)[:16], None),
        (HTTP[:16], "magic"),
        (TLS[:16], "magic"),
        (b"FINS" + struct.pack(">III", 7, 2, 0), "length"),
        (b"FINS" + struct.pack(">III", 70000, 2, 0), "length"),
        (b"FINS" + struct.pack(">III", 12, 9, 0), "command"),
        (b"FINS" + struct.pack(">III", 12, 0x46494E53, 0), "command"),
        (b"FINS" + struct.pack(">III", 12, 0, 3), "error code"),
        (b"FINS\x00\x00", "header"),
    ],
)
def test_check_fins_tcp(header, why):
    defect = hp.check_fins_tcp(header)

    assert (defect is None) if why is None else (defect is not None and why in defect)


# --- 2. The stream ------------------------------------------------------------------


@pytest.fixture
def run(monkeypatch):
    events: list[tuple[dict, str | None, str | None, bytes | None]] = []

    def _log(protocol, peer, data, attack_type=None, severity=None, proto=None, raw=None):
        events.append((data, attack_type, severity, raw))
        return {}

    monkeypatch.setattr(hp, "log_event", _log)

    def _run(stream: bytes):
        decoy = hp.FinsHoneypot.__new__(hp.FinsHoneypot)
        decoy.profile = {}
        decoy.port = 9600
        decoy.logger = logging.getLogger("test-fins")
        decoy.plc_model, decoy.vendor = "CJ2M-CPU33", "Omron Corporation"
        decoy.cpu_unit, decoy.firmware = "CJ2M", "V2.1"
        writer = FakeWriter()
        asyncio.run(decoy.handle_connection(FakeReader(stream), writer, ("203.0.113.9", 4000)))
        return events, writer

    return _run


@pytest.mark.parametrize(("stream", "guess"), [(HTTP, "http"), (TLS, "tls")], ids=["http", "tls"])
def test_a_foreign_stream_is_one_scanner_event_and_gets_no_reply(run, stream, guess):
    events, writer = run(stream)

    assert len(events) == 1
    data, attack_type, severity, raw = events[0]
    assert (attack_type, severity) == ("SCANNER", "LOW")
    assert data["phase"] == "foreign_on_ics_port" and data["ics"] is False
    assert data["rule"] == f"not FINS: {guess}"
    assert data["client_bytes"] == len(stream) and raw == stream
    assert "mrc" not in data and "frame_hex" not in data
    assert bytes(writer.sent) == b""


def test_a_stream_shorter_than_a_header_is_still_recorded(run):
    events, _ = run(b"SSH-2.0-Go\r\n")

    assert [d["foreign_protocol"] for d, *_ in events] == ["ssh"]


def test_a_connection_that_sends_nothing_writes_nothing(run):
    assert run(b"")[0] == []


def test_a_valid_session_that_loses_framing_is_a_desync(run):
    events, _ = run(NODE_REQUEST + HTTP)

    assert [d["phase"] for d, *_ in events] == ["fins_node_request", "ics_desync"]
    assert (events[1][1], events[1][2]) == ("ICS_RECON", "LOW")


def test_a_frame_too_short_to_carry_a_command_is_not_parsed(run):
    events, writer = run(tcp(bytes.fromhex(HEADER) + b"\x05"))

    assert [d["phase"] for d, *_ in events] == ["foreign_on_ics_port"]
    assert "command code" in events[0][0]["defect"]
    assert bytes(writer.sent) == b""


def test_a_server_side_tcp_command_from_a_client_is_recorded(run):
    """Command 1 is the server's node address reply. Recognisably FINS/TCP, so it is a row
    and not a foreign stream; the decoy has nothing to answer and the session ends."""
    events, writer = run(NODE_REQUEST + tcp(b"\x00\x00\x00\x01\x00\x00\x00\x02", command=1))

    assert [d["phase"] for d, *_ in events] == ["fins_node_request", "fins_tcp_command"]
    data, attack_type, severity, _ = events[1]
    assert data["tcp_command"] == 1
    assert (attack_type, severity) == ("ICS_RECON", "MEDIUM")
    assert len(writer.sent) == 24  # only the node address reply


# --- 3. Names and verdicts come from the decoder ------------------------------------


def test_the_node_address_request_has_a_verdict(run):
    """194 of the 356 rows: the opening negotiation, unlabelled until now."""
    events, writer = run(NODE_REQUEST)

    data, attack_type, severity, _ = events[0]
    assert data["phase"] == "fins_node_request" and data["rule"] == "Node Address Request"
    assert (attack_type, severity) == ("ICS_RECON", "LOW")
    assert bytes(writer.sent)[:4] == b"FINS"


@pytest.mark.parametrize(
    ("mrc", "src", "name", "verdict"),
    [
        (0x05, 0x01, "Controller Data Read", ("ICS_RECON", "LOW")),
        (0x01, 0x01, "Memory Area Read", ("ICS_RECON", "LOW")),
        (0x03, 0x06, "Program Area Read", ("ICS_RECON", "LOW")),  # was "CPU Unit Status Read"
        (0x06, 0x01, "Controller Status Read", ("ICS_RECON", "LOW")),
        (0x01, 0x02, "Memory Area Write", ("ICS_ATTACK", "HIGH")),
        (0x01, 0x03, "Memory Area Fill", ("ICS_ATTACK", "HIGH")),
        (0x02, 0x02, "Parameter Area Write", ("ICS_ATTACK", "HIGH")),
        (0x03, 0x07, "Program Area Write", ("ICS_ATTACK", "HIGH")),  # was Unknown_03_07, recon
        (0x03, 0x08, "Program Area Clear", ("ICS_ATTACK", "HIGH")),
        (0x22, 0x04, "Memory Card Format", ("ICS_ATTACK", "HIGH")),
        (0x23, 0x01, "Forced Set/Reset", ("ICS_ATTACK", "HIGH")),
        (0x04, 0x01, "Run", ("ICS_ATTACK", "CRITICAL")),
        (0x04, 0x02, "Stop", ("ICS_ATTACK", "CRITICAL")),
        (0x07, 0x02, "Clock Write", ("ICS_ATTACK", "CRITICAL")),
        (0x26, 0x02, "Unknown_26_02", ("ICS_RECON", "LOW")),  # not a FINS command
        (0x7E, 0x7E, "Unknown_7E_7E", ("ICS_RECON", "LOW")),
    ],
)
def test_name_and_verdict_by_command(run, mrc, src, name, verdict):
    events, _ = run(fins(mrc, src, b"\x82\x00\x64\x00\x00\x01\x00\x00"))

    data, attack_type, severity, _ = events[0]
    assert data["rule"] == data["mrc_src_name"] == name
    assert (attack_type, severity) == verdict


def test_a_response_frame_sent_as_a_request_is_an_anomaly(run):
    frame = bytearray(bytes.fromhex(CONTROLLER_DATA))
    frame[0] = 0xC0

    events, _ = run(tcp(bytes(frame)))

    assert (events[0][1], events[0][2]) == ("ICS_RECON", "MEDIUM")


def test_a_recognised_command_keeps_the_keys_the_ingest_reads(run):
    events, writer = run(NODE_REQUEST + tcp(bytes.fromhex(MEMORY_READ)))

    data = events[1][0]
    assert data["phase"] == "fins_request" and data["dst_port"] == 9600
    assert data["mrc"] == 1 and data["src"] == 1
    assert data["frame_hex"] == MEMORY_READ
    assert "MRC=01 SRC=01" in data["payload"]
    assert bytes(writer.sent).count(b"FINS") == 2


def test_the_stored_frame_is_bounded(run):
    events, _ = run(fins(0x01, 0x02, b"\x82\x00\x00\x00\x03\xe8" + b"\xab" * 1900))

    assert len(events[0][0]["frame_hex"]) == 2 * 1024


def test_the_decoy_has_no_command_table_of_its_own():
    assert not hasattr(hp, "FINS_COMMANDS")


# --- 4. Nothing a peer sends raises -------------------------------------------------


def test_no_byte_string_raises(run):
    import random

    rng = random.Random(20261120)
    for _ in range(300):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 60)))
        run(blob)
        run(b"FINS" + blob)
        run(NODE_REQUEST + tcp(blob) + blob)
