"""Port 102 must recognise ISO transport before it answers, and S7/MMS before it labels.

Reviewed 2026-11-20, 30 days on three sensors. The dispatcher trusted the length field of
whatever arrived, answered every first packet with a COTP Connection Confirm, and stamped
``s7comm`` / ``ics_enumeration`` on every data TPDU whatever it carried:

    RDP on 102        an RDP client's connection request is a TPKT+CR too. It was given a CC,
                      and its MCS Connect-Initial (``7f 65 ..``) was then stored as S7comm:
                      86+ rows, about 108 ``route=unknown`` rows in all.
    HTTP / TLS        not TPKT at all: the handler waited for a body the length bytes invented
                      and returned without writing a row.
    bare COTP CR      a connect-only scan (the first half of every S7 fingerprint) left no row.

The rule the IEC-104 decoy follows since 2026-11-19, applied here: a stream that is not
TPKT + COTP Connection Request is recorded once as ``foreign_on_ics_port`` (``ics: False``,
``SCANNER``/LOW) and gets no reply; data that is neither S7 nor an ISO session SPDU is not
S7comm evidence; and no input ends a connection without a row.
"""

from __future__ import annotations

import asyncio
import random

import pytest

from honeylens.honeypots.ics import cotp102
from honeylens.honeypots.ics.cotp102 import Cotp102Honeypot
from honeylens.ics import decode_hex
from tests.ics_fakes import FakeReader, FakeWriter
from tests.test_ics_decode_s7comm import CR_BODY, SETUP, SZL, dt, tpkt

PEER = ("203.0.113.9", 40102)
HTTP = b"GET / HTTP/1.1\r\nHost: scanner.example\r\n\r\n"
TLS = bytes.fromhex("160301020001000001fc0303") + b"\x00" * 40
RDP_NEG = bytes.fromhex("030000130ee000000000000100080003000000")
RDP_COOKIE = (
    bytes.fromhex("0300002f2ae00000000000")
    + b"Cookie: mstshash=hello\r\n"
    + bytes.fromhex("0100080003000000")
)
MCS_CONNECT_INITIAL = bytes.fromhex("7f658201940401010401010101ff30190201220201020201000201")


@pytest.fixture
def run(monkeypatch):
    def _run(stream: bytes):
        events: list[dict] = []

        def _log(protocol, peer, data, attack_type=None, severity=None, proto=None, raw=None):
            events.append(
                {"protocol": protocol, "md": data, "verdict": (attack_type, severity), "raw": raw}
            )

        monkeypatch.setattr(cotp102, "log_event", _log)
        writer = FakeWriter(PEER)
        asyncio.run(Cotp102Honeypot().handle_connection(FakeReader(stream), writer, PEER))
        return events, bytes(writer.sent)

    return _run


@pytest.mark.parametrize(
    ("stream", "guess"),
    [
        (HTTP, "http"),
        (TLS, "tls"),
        (RDP_NEG, "rdp"),
        (RDP_COOKIE, "rdp"),
        (b"", "empty"),
        (b"\x03\x00", "tpkt"),
        (b"\x03\x00\xff\xff\x02\xf0\x80", "tpkt"),
        (b"SSH-2.0-Go\r\n", "ssh"),
    ],
)
def test_a_stream_that_is_not_an_iso_connect_is_recorded_once_and_not_answered(run, stream, guess):
    events, sent = run(stream)

    assert sent == b""
    assert len(events) == 1
    md = events[0]["md"]
    assert events[0]["protocol"] == "s7comm"
    assert events[0]["verdict"] == ("SCANNER", "LOW")
    assert md["phase"] == "foreign_on_ics_port"
    assert md["ics"] is False
    assert md["foreign_protocol"] == guess
    assert md["dst_port"] == 102
    assert "frame_hex" not in md
    assert events[0]["raw"] == (stream or None)


def test_an_rdp_client_is_not_given_a_connection_confirm(run):
    events, sent = run(RDP_COOKIE + tpkt(bytes([0x02, 0xF0, 0x80]) + MCS_CONNECT_INITIAL))

    assert sent == b""
    assert [e["md"]["phase"] for e in events] == ["foreign_on_ics_port"]
    assert "mstshash" in events[0]["md"]["preview"]


def test_a_first_tpdu_that_is_not_a_connection_request_is_foreign(run):
    events, sent = run(dt(SETUP))

    assert sent == b""
    assert [e["md"]["phase"] for e in events] == ["foreign_on_ics_port"]
    assert "Connection Request" in events[0]["md"]["defect"]


def test_a_bare_connection_request_leaves_a_row(run):
    events, sent = run(tpkt(CR_BODY))

    assert sent[:2] == b"\x03\x00" and sent[5] == 0xD0
    assert len(events) == 1
    md = events[0]["md"]
    assert md["phase"] == "cotp_connect"
    assert events[0]["verdict"] == ("ics_enumeration", "LOW")
    frame = decode_hex("s7comm", md["frame_hex"])
    assert frame.semantics == "enumerate" and frame.code is None


def test_a_session_that_goes_on_to_s7_keeps_one_row_per_request(run):
    events, _ = run(tpkt(CR_BODY) + dt(SETUP) + dt(SZL))

    assert [e["md"]["phase"] for e in events] == ["cotp102", "cotp102"]
    assert [e["md"]["route"] for e in events] == ["s7", "s7"]


def test_data_that_is_neither_s7_nor_a_session_spdu_is_not_s7comm_evidence(run):
    events, sent = run(tpkt(CR_BODY) + dt(MCS_CONNECT_INITIAL))

    assert sent.count(b"\x03\x00") == 1  # the connection confirm, and nothing after it
    assert len(events) == 1
    md = events[0]["md"]
    assert md["phase"] == "foreign_on_ics_port"
    assert md["ics"] is False
    assert events[0]["verdict"] == ("SCANNER", "LOW")
    assert md["first_bytes_hex"].startswith("7f65")


def test_garbage_after_a_valid_s7_exchange_is_a_desync_and_ends_the_session(run):
    events, _ = run(tpkt(CR_BODY) + dt(SETUP) + dt(b"\xff\xfe\xfd") + dt(SZL))

    assert [e["md"]["phase"] for e in events] == ["cotp102", "ics_desync"]
    assert events[1]["md"]["frames_before"] == 1
    assert events[1]["verdict"] == ("ICS_RECON", "LOW")


def test_a_stream_that_stops_being_tpkt_is_a_desync(run):
    events, _ = run(tpkt(CR_BODY) + dt(SETUP) + HTTP)

    assert [e["md"]["phase"] for e in events] == ["cotp102", "ics_desync"]
    assert events[1]["md"]["foreign_protocol"] == "http"


def test_a_clean_close_after_a_session_adds_no_row(run):
    events, _ = run(tpkt(CR_BODY) + dt(SETUP))

    assert [e["md"]["phase"] for e in events] == ["cotp102"]


def test_no_input_raises_and_every_connection_leaves_a_row(run):
    rng = random.Random(102)
    heads = [b"", b"\x03\x00", tpkt(CR_BODY), tpkt(CR_BODY) + dt(SETUP)[:9], b"\x03\x00\x00\x04"]
    for _ in range(300):
        stream = rng.choice(heads) + rng.randbytes(rng.randrange(0, 40))
        events, _ = run(stream)
        assert events, stream.hex()
        events.clear()


@pytest.mark.parametrize(
    ("head", "defect"),
    [
        (b"\x03\x00\x00\x16", None),
        (b"\x03\x00\x00\x07", None),
        (b"\x02\x00\x00\x16", "TPKT version"),
        (b"\x03\x01\x00\x16", "reserved"),
        (b"\x03\x00\x00\x06", "length"),
        (b"GET ", "TPKT version"),
    ],
)
def test_check_tpkt(head, defect):
    got = cotp102.check_tpkt(head)

    assert (got is None) if defect is None else (defect in got)
