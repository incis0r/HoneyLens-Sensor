"""The IEC-104 decoy must recognise frames, not find them.

Measured 2026-11-19 on `sensor-e`, 30 days: `honeypot-iec104` held 631 rows, 86.1% of them
unlabelled, and the unlabelled ones were mostly not IEC-104 at all. The connection loop
skipped bytes until it met 0x68 and parsed whatever followed as an APDU. 0x68 is ASCII `h`,
so every `Host:`, `http/1.1`, `html` and `Sec-Fetch-` in a web scanner's request opened a
"frame". What the store actually holds under this decoy's name:

    payload the decoy wrote                 frame bytes, as text
    U-frame U-0x53                          h-Site: none\\r\\nSec-Fetch-User: ?1
    S-frame ACK rsn=14900                   h….example/scan Mozilla/5.0 (Macintosh
    I-frame TypeID=58 COT=28516 CA=3...     h-Dest: document\\r\\nSec-Fetch-Mode:
    I-frame TypeID=123 COT=28518            hello\\n{\\nfox.version=s:1.0   (a Niagara Fox hello)
    I-frame TypeID=46 C_DC_NA_1 Double Command   ...9\\x08http/1.0\\x08http/1.1  (TLS ALPN)

The last line is the expensive one. Replaying all 2,184 stored rows of the four sensors that
run this decoy through `check_apci` and `parse_asdu`:

    not IEC-104 at all                1,341 rows (61%)
    real frames                         843: TESTFR act 328, STARTDT act 287,
                                             station interrogation 201, STOPDT act 9, other 18
    rows carrying ICS_ATTACK             91, from about 28 sources
      of which a well-formed command      0

**Every `ICS_ATTACK` this decoy wrote in 30 days is false.** 77 of the 91 are one shape: the
ALPN list of a TLS ClientHello (65 of them read `http/0.9 http/1.0 http/1.1 spdy/1`), where an
`h` supplied the start byte and 0x2e the type id of a Double Command. The rest are other TLS bytes that
landed on types 47-51 and 103. A breaker-operate verdict, severity CRITICAL, on a substation
decoy, made out of a handshake — and no real command arrived to be told apart from it.

Four defects, each pinned below:

1. no stream gate — bytes were hunted for a start byte instead of being required to be one;
2. no APCI validation — any control octet with the right two low bits was a frame;
3. the cause of transmission was read as one 16-bit number, so it was wrong whenever the
   originator address was not zero (`COT=26632` is cause 8 from originator 104);
4. the type table stopped before the time-tagged commands (58-64), so a `C_DC_TA_1` — the
   same breaker operation with a timestamp — earned no verdict at all.

Suricata's ET SCADA rules were already naming the real session-control frames on the same
sensor (TESTFR 124 rows, STARTDT 75, station interrogation 88) while the decoy that received
them left the first two unlabelled.
"""

from __future__ import annotations

import asyncio

import pytest

from honeylens.honeypots import hp_iec104 as hp
from tests.ics_fakes import FakeReader, FakeWriter


def apdu(body: bytes) -> bytes:
    return bytes([0x68, len(body)]) + body


STARTDT = apdu(bytes.fromhex("07000000"))
TESTFR = apdu(bytes.fromhex("43000000"))
S_ACK = apdu(bytes.fromhex("01000400"))
# I-frame, ssn 0 / rsn 0, C_IC_NA_1 station interrogation, cause 6, CA 0xFFFF, IOA 0, QOI 20
INTERROGATION = apdu(bytes.fromhex("00000000" + "64010600ffff00000014"))
# C_DC_NA_1 double command, cause 6, originator 0x68, CA 1, IOA 0x10, DCO 0x81
DOUBLE_CMD_ASDU = bytes.fromhex("2e010668010010000081")
# C_DC_TA_1: the same command with a CP56Time2a time tag
DOUBLE_CMD_TA_ASDU = bytes.fromhex("3b010600010010000081" + "00000000000000")

HTTP = (
    b"GET /scan HTTP/1.1\r\nHost: scanner.example\r\nUser-Agent: Mozilla/5.0 (Macintosh)\r\n"
    b'Sec-Fetch-Site: none\r\nSec-Fetch-Dest: document\r\nsec-ch-ua: "Chromium"\r\n\r\n'
)
# A TLS ClientHello prefix carrying the ALPN list that produced the false Double Command.
TLS = (
    bytes.fromhex("1603010200010001fc0303")
    + bytes(32)
    + b"\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1"
    + (b"\x2e\x39\x08http/1.0\x08http/1.1" * 6)
)
FOX = b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\nhostName=s:xpvm\n};;\n"


# --- 1. APCI: a control field is one of three formats or it is not IEC-104 ---------


@pytest.mark.parametrize(
    "ctrl, length, kind",
    [
        ("07000000", 4, "U"),  # STARTDT act
        ("43000000", 4, "U"),  # TESTFR act
        ("13000000", 4, "U"),  # STOPDT act
        ("01000400", 4, "S"),
        ("00000000", 14, "I"),
        ("0200fe7f", 14, "I"),
    ],
)
def test_the_three_real_formats_are_recognised(ctrl, length, kind):
    assert hp.check_apci(bytes.fromhex(ctrl), length) == (kind, None)


@pytest.mark.parametrize(
    "ctrl, length, why",
    [
        (b"Site", 45, "U-format with an unassigned function"),  # 'S' = 0x53
        (bytes.fromhex("6f6d652f"), 104, "U-format with an unassigned function"),  # 'ome/'
        (bytes.fromhex("07000001"), 4, "U-format with non-zero octets 2-4"),
        (bytes.fromhex("07000000"), 9, "U-format carrying a body"),
        (b"ua: ", 45, "S-format with a non-zero first octet pair"),  # 'u' = 0x75
        (bytes.fromhex("01000500"), 4, "S-format with bit 0 of octet 3 set"),
        (bytes.fromhex("01000400"), 8, "S-format carrying a body"),
        (b"tp/0", 116, "I-format with bit 0 of octet 3 set"),  # the TLS ALPN case
        (bytes.fromhex("00000000"), 4, "I-format without an ASDU"),
    ],
)
def test_everything_else_is_refused_with_a_reason(ctrl, length, why):
    kind, defect = hp.check_apci(ctrl, length)
    assert kind is None, why
    assert defect, why


# --- 2. ASDU header --------------------------------------------------------------


def test_cause_and_originator_are_two_fields_not_one_number():
    """`COT=26632` in the store is cause 8 with originator 104, printed as 0x6808."""
    a = hp.parse_asdu(DOUBLE_CMD_ASDU)

    assert a["cot"] == 6
    assert a["originator"] == 0x68
    assert a["common_address"] == 1
    assert a["ioa"] == 0x10
    assert a["defect"] is None


def test_the_negative_and_test_bits_are_split_from_the_cause():
    neg = hp.parse_asdu(bytes.fromhex("64014700ffff00000014"))
    tst = hp.parse_asdu(bytes.fromhex("64018600ffff00000014"))

    assert (neg["cot"], neg["cot_negative"], neg["cot_test"]) == (7, True, False)
    assert (tst["cot"], tst["cot_negative"], tst["cot_test"]) == (6, False, True)


def test_the_variable_structure_qualifier_is_read():
    a = hp.parse_asdu(bytes.fromhex("64010600ffff00000014"))

    assert (a["sq"], a["num_objects"]) == (False, 1)


def test_time_tagged_commands_are_named_and_are_commands():
    a = hp.parse_asdu(DOUBLE_CMD_TA_ASDU)

    assert a["type_id"] == 59
    assert a["type_name"].startswith("C_DC_TA_1")
    assert a["defect"] is None
    assert {58, 59, 60, 61, 62, 63, 64} <= hp.COMMAND_TYPE_IDS


@pytest.mark.parametrize(
    "asdu_hex, why",
    [
        ("2e39086874" + "74702f312e30" * 18, "a command ASDU of the wrong length (TLS ALPN bytes)"),
        ("c8010600010000000000", "an unassigned type identification"),
        ("64010000ffff00000014", "cause of transmission 0"),
        ("64000600ffff00000014", "zero information objects"),
        ("6401", "an ASDU cut inside its header"),
    ],
)
def test_an_implausible_asdu_reports_a_defect(asdu_hex, why):
    assert hp.parse_asdu(bytes.fromhex(asdu_hex))["defect"], why


# --- 3. The stream ----------------------------------------------------------------


@pytest.fixture
def run(monkeypatch):
    """Drive the real connection handler; collect (event, attack_type, severity)."""
    events: list[tuple[dict, str | None, str | None]] = []

    def _log(protocol, peer, data, attack_type=None, severity=None, proto=None, raw=None):
        events.append((data, attack_type, severity))
        return {}

    monkeypatch.setattr(hp, "log_event", _log)

    def _run(stream: bytes):
        decoy = hp.IEC104Honeypot.__new__(hp.IEC104Honeypot)
        decoy.profile = {}
        decoy.port = 2404
        import logging

        decoy.logger = logging.getLogger("test-iec104")
        writer = FakeWriter()
        asyncio.run(decoy.handle_connection(FakeReader(stream), writer, ("203.0.113.9", 4000)))
        return events, writer

    return _run


@pytest.mark.parametrize("stream, guess", [(HTTP, "http"), (TLS, "tls"), (FOX, "fox")])
def test_a_foreign_stream_is_one_event_and_no_frames(run, stream, guess):
    """The whole defect in one assertion: 0x68 inside someone else's protocol is not a start
    byte. One row saying what arrived, flagged not-ICS, instead of a row per `h`."""
    events, _ = run(stream)

    assert len(events) == 1
    data, attack_type, severity = events[0]
    assert data["phase"] == "foreign_on_ics_port"
    assert data["ics"] is False
    assert data["foreign_protocol"] == guess
    assert data["client_bytes"] == len(stream)
    assert (attack_type, severity) == ("SCANNER", "LOW")


def test_a_tls_handshake_is_never_a_double_command(run):
    """25 CRITICAL `ICS_ATTACK` rows on sensor-e, all of them this."""
    events, _ = run(TLS)

    assert all(at != "ICS_ATTACK" for _, at, _ in events)
    assert all(d.get("type_id") is None for d, _, _ in events)


def test_the_decoy_does_not_answer_a_foreign_stream(run):
    _, writer = run(HTTP)

    assert bytes(writer.sent) == b""


def test_text_that_starts_with_h_is_foreign_too(run):
    """`h` then a plausible length then four bytes that pass the two-bit I-format test: the
    APCI check alone lets a quarter of all text through, so the first APDU's ASDU decides."""
    events, _ = run(
        b"html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US\r\n\r\n"
    )

    assert [d["phase"] for d, _, _ in events] == ["foreign_on_ics_port"]


def test_a_real_session_is_recognised_frame_by_frame(run):
    events, _ = run(STARTDT + INTERROGATION + S_ACK)

    assert [d["phase"] for d, _, _ in events] == ["iec104_uframe", "iec104_iframe", "iec104_sframe"]
    assert events[1][0]["type_id"] == 100
    assert events[1][1] == "ICS_RECON"


def test_opening_a_session_is_recon(run):
    """STARTDT act and TESTFR act from an internet source are someone speaking IEC-104 to an
    RTU. 190 such rows from ~87 sources on sensor-e had no verdict while Suricata's ET SCADA
    rules named the same frames."""
    events, _ = run(STARTDT + TESTFR)

    assert [(at, sev) for _, at, sev in events] == [("ICS_RECON", "LOW"), ("ICS_RECON", "LOW")]


def test_an_acknowledgement_is_not_a_verdict(run):
    events, _ = run(STARTDT + S_ACK)

    assert events[1][1] is None


def test_a_time_tagged_command_is_an_attack(run):
    events, _ = run(STARTDT + apdu(bytes.fromhex("00000000") + DOUBLE_CMD_TA_ASDU))

    data, attack_type, severity = events[1]
    assert (attack_type, severity) == ("ICS_ATTACK", "CRITICAL")
    assert data["type_id"] == 59


def test_a_command_before_startdt_is_still_recorded_as_one(run):
    """A real outstation ignores it, but the sender's intent is the event."""
    events, _ = run(apdu(bytes.fromhex("00000000") + DOUBLE_CMD_ASDU))

    data, attack_type, _ = events[0]
    assert attack_type == "ICS_ATTACK"
    assert data["before_startdt"] is True
    assert data["originator"] == 0x68


def test_junk_after_a_valid_session_is_one_desync_event_then_silence(run):
    events, _ = run(STARTDT + b"h-Site: none\r\nSec-Fetch-User: ?1\r\nhttp/1.1 html host\r\n")

    assert [d["phase"] for d, _, _ in events] == ["iec104_uframe", "iec104_desync"]
    assert events[1][0]["frames_before"] == 1


def test_a_malformed_asdu_inside_a_session_earns_no_command_verdict(run):
    bad = apdu(bytes.fromhex("00000000") + bytes.fromhex("2e000600010010000081"))  # zero objects
    events, _ = run(STARTDT + bad)

    data, attack_type, _ = events[1]
    assert data["phase"] == "iec104_iframe"
    assert data["asdu_defect"]
    assert attack_type != "ICS_ATTACK"


def test_an_empty_connection_writes_nothing(run):
    events, _ = run(b"")

    assert events == []
