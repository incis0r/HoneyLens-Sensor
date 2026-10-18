"""The DNP3 decoy must recognise a data link frame, record the ones it used to skip, and take
its verdict from what the function code means.

Reviewed 2026-11-20, 30 days on `sensor-a`, `sensor-c` and `sensor-e`: **nine rows**, the smallest
family on the fleet, and all nine wrong.

* **A second table.** The decoy named twelve function codes and called every other one
  ``ICS_ATTACK``/MEDIUM. All nine stored rows are one identical 15-byte frame to broadcast
  address 65535: function code 0x17, Delay Measurement — a timing probe from census
  netblocks, stored as ``FC_23`` with an attack verdict. ``honeylens.ics.dnp3`` already had
  the full table; the same decoy would have filed Stop Application under "unknown".
* **Invisible frames.** A frame with no user data — ``REQUEST_LINK_STATUS``, ``RESET_LINK``,
  the standard way to ask whether an outstation is there — produced no row at all. That is
  the likeliest reason this decoy has nine rows in a month; what it lost cannot be measured
  from the store.
* **No record of a foreign stream.** Wrong start bytes ended the connection silently.
* **A crash.** Building any reply to a source address above 32767 raised ``struct.error`` in
  a dead ``struct.pack("<BBBhh", ...)`` whose result was discarded on the next line.

The header CRC is recorded, not enforced, as the decoder does: scanners send bad CRCs, and
``05 64`` plus a sane length is already a 1-in-65,536 accident for a foreign stream.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from honeylens.honeypots import hp_dnp3 as hp
from tests.ics_fakes import FakeReader, FakeWriter
from tests.test_ics_decode_dnp3 import app, frame

HTTP = b"GET / HTTP/1.1\r\nHost: scanner.example\r\n\r\n"
TLS = bytes.fromhex("1603010200010001fc0303") + bytes(range(64))
LINK_STATUS = frame(b"", control=0xC9)
RESET_LINK = frame(b"", control=0xC0)
DELAY_BROADCAST = frame(app(0x17), dst=65535, src=1)


# --- 1. The link header -------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "why"),
    [
        (frame(app(1))[:10], None),
        (LINK_STATUS, None),
        (frame(app(1), bad_crc=True)[:10], None),  # reported, not enforced
        (HTTP[:10], "start"),
        (TLS[:10], "start"),
        (b"\x05\x64\x04\xc4\x01\x00\x00\x04\x00\x00", "length"),
        (b"\x05\x64\x00\xc4\x01\x00\x00\x04\x00\x00", "length"),
        (b"\x05\x64\x05", "header"),
    ],
)
def test_check_link(header, why):
    defect = hp.check_link(header)

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
        decoy = hp.DNP3Honeypot.__new__(hp.DNP3Honeypot)
        decoy.profile = {}
        decoy.port = 20000
        decoy.logger = logging.getLogger("test-dnp3")
        decoy.station_address = 10
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
    assert data["rule"] == f"not DNP3: {guess}"
    assert data["client_bytes"] == len(stream) and raw == stream
    assert "fc" not in data and "frame_hex" not in data
    assert bytes(writer.sent) == b""


def test_a_stream_shorter_than_a_header_is_still_recorded(run):
    events, _ = run(b"\x16\x03\x01\x00")

    assert [d["phase"] for d, *_ in events] == ["foreign_on_ics_port"]


def test_a_connection_that_sends_nothing_writes_nothing(run):
    assert run(b"")[0] == []


def test_a_valid_session_that_loses_framing_is_a_desync(run):
    events, _ = run(frame(app(1, bytes([1, 2, 6]))) + HTTP)

    assert [d["phase"] for d, *_ in events] == ["dnp3_request", "ics_desync"]
    assert (events[1][1], events[1][2]) == ("ICS_RECON", "LOW")
    assert events[1][0]["frames_before"] == 1


def test_a_frame_cut_inside_its_user_data_is_recorded(run):
    whole = frame(app(1, bytes([1, 2, 6])))

    events, _ = run(whole[:-3])

    assert [d["phase"] for d, *_ in events] == ["foreign_on_ics_port"]
    assert "user data" in events[0][0]["defect"]


# --- 3. Frames the decoy used to skip -----------------------------------------------


def test_a_link_status_request_is_a_row(run):
    """The standard "is an outstation there" probe: no user data, so no row until now."""
    events, _ = run(LINK_STATUS)

    assert len(events) == 1
    data, attack_type, severity, _ = events[0]
    assert data["phase"] == "dnp3_link"
    assert data["rule"] == "Request Link Status"
    assert data["dl_control"] == 0xC9 and data["dl_dst"] == 1 and data["dl_src"] == 1024
    assert data["frame_hex"] == LINK_STATUS.hex()
    assert (attack_type, severity) == ("ICS_RECON", "LOW")
    assert "fc" not in data


def test_a_reset_link_is_a_row_and_the_session_goes_on(run):
    events, _ = run(RESET_LINK + frame(app(1, bytes([1, 2, 6]))))

    assert [d["phase"] for d, *_ in events] == ["dnp3_link", "dnp3_request"]
    assert events[0][0]["rule"] == "Reset Link States"


# --- 4. The verdict comes from the decoder ------------------------------------------


def test_the_nine_rows_of_the_fleet_are_a_delay_measurement_not_an_attack(run):
    events, _ = run(DELAY_BROADCAST)

    data, attack_type, severity, _ = events[0]
    assert data["fc"] == 0x17 and data["dl_dst"] == 65535
    assert data["rule"] == data["fc_name"] == "Delay Measurement"
    assert (attack_type, severity) == ("ICS_RECON", "LOW")


@pytest.mark.parametrize(
    ("fc", "name", "verdict"),
    [
        (0x01, "Read", ("ICS_RECON", "LOW")),
        (0x02, "Write", ("ICS_ATTACK", "HIGH")),
        (0x03, "Select", ("ICS_ATTACK", "CRITICAL")),
        (0x04, "Operate", ("ICS_ATTACK", "CRITICAL")),
        (0x05, "Direct Operate", ("ICS_ATTACK", "CRITICAL")),
        (0x06, "Direct Operate No Ack", ("ICS_ATTACK", "CRITICAL")),
        (0x0D, "Cold Restart", ("ICS_ATTACK", "CRITICAL")),
        (0x0E, "Warm Restart", ("ICS_ATTACK", "CRITICAL")),
        (0x11, "Start Application", ("ICS_ATTACK", "CRITICAL")),
        (0x12, "Stop Application", ("ICS_ATTACK", "CRITICAL")),
        (0x15, "Disable Unsolicited", ("ICS_ATTACK", "CRITICAL")),
        (0x1B, "Delete File", ("ICS_ATTACK", "HIGH")),
        (0x1C, "Get File Info", ("ICS_RECON", "LOW")),
        (0x00, "Confirm", ("ICS_RECON", "LOW")),
        (0x81, "FC_129", ("ICS_RECON", "MEDIUM")),  # a response sent as a request
        (0xC8, "FC_200", ("ICS_RECON", "MEDIUM")),  # reserved: nothing was ordered
    ],
)
def test_verdict_and_name_by_function_code(run, fc, name, verdict):
    events, _ = run(frame(app(fc)))

    data, attack_type, severity, _ = events[0]
    assert data["rule"] == name
    assert (attack_type, severity) == verdict


def test_a_continuation_segment_is_not_judged_by_a_byte_that_is_not_a_function_code(run):
    """Transport FIR clear: byte 2 of the user data is object data, not a function code.
    0x0D there is not a Cold Restart."""
    events, _ = run(frame(app(0x0D, transport=0x01)))

    data, attack_type, severity, _ = events[0]
    assert (attack_type, severity) == ("ICS_RECON", "LOW")
    assert "FIR" in data["decode_note"]


def test_a_recognised_request_keeps_the_keys_the_ingest_reads(run):
    wire = frame(app(1, bytes([1, 2, 6])), dst=10, src=3)

    events, writer = run(wire)

    data = events[0][0]
    assert data["phase"] == "dnp3_request" and data["dst_port"] == 20000
    assert data["fc"] == 1 and data["fc_name"] == "Read"
    assert data["dl_dst"] == 10 and data["dl_src"] == 3 and data["dl_control"] == 0xC4
    assert data["app_objects_hex"] == "010206"
    assert data["frame_hex"] == wire.hex() and data["station_address"] == 10
    assert data["header_crc_ok"] is True
    assert bytes(writer.sent)[:2] == b"\x05\x64"


def test_a_bad_header_crc_is_recorded_not_rejected(run):
    events, _ = run(frame(app(1), bad_crc=True))

    assert events[0][0]["phase"] == "dnp3_request"
    assert events[0][0]["header_crc_ok"] is False


# --- 5. Nothing a peer sends raises -------------------------------------------------


def test_a_source_address_above_32767_gets_its_reply(run):
    """``struct.pack("<BBBhh", ...)`` — a signed short for an unsigned address."""
    events, writer = run(frame(app(1), src=40000))

    assert len(events) == 1
    assert int.from_bytes(bytes(writer.sent)[4:6], "little") == 40000


def test_no_byte_string_raises(run):
    import random

    rng = random.Random(20261120)
    for _ in range(300):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 60)))
        run(blob)
        run(b"\x05\x64" + blob)
        run(frame(blob[:40], src=rng.randrange(65536), dst=rng.randrange(65536)) + blob)
