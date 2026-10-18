"""Only a Fox frame is a Fox session.

Reviewed 2026-11-20, 30 days on three sensors: 409 rows of ``honeypot-fox`` begin
``fox a 1 -1 fox hello``. The rest — about 70% — were RDP cookies, SMB negotiates, SIP and
RTSP OPTIONS, JRMI, LDAP, MSSQL, DICOM, iSCSI, TLS handshakes and 74 empty reads, every one
stamped ``ics_enumeration`` with an ``ics_events`` row beside it. Only HTTP was diverted.
The verdict was a substring search over whatever arrived, so a text probe containing ``save``
or ``config`` would have been a write or reconnaissance against a building controller.

A Fox message starts ``fox a ``. Anything else is recorded once as ``foreign_on_ics_port``
(``ics: False``, ``SCANNER``/LOW); the intent keywords are read only inside a Fox frame.
"""

from __future__ import annotations

import asyncio

import pytest

from honeylens.honeypots.ics import fox as fox_mod
from honeylens.honeypots.ics.fox import FoxHoneypot, is_fox_frame
from tests.ics_fakes import FakeReader, FakeWriter

PEER = ("203.0.113.9", 41911)
HELLO = b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n"


@pytest.fixture
def run(monkeypatch):
    def _run(data: bytes):
        events = []

        def _log(protocol, peer, md, attack_type=None, severity=None, proto=None, raw=None):
            events.append({"md": md, "verdict": (attack_type, severity), "raw": raw})

        monkeypatch.setattr(fox_mod, "log_event", _log)
        writer = FakeWriter(PEER)
        asyncio.run(FoxHoneypot().handle_connection(FakeReader(data), writer, PEER))
        assert len(events) == 1
        return events[0], bytes(writer.sent)

    return _run


@pytest.mark.parametrize(
    ("data", "guess"),
    [
        (bytes.fromhex("0300002b26e00000000000") + b"Cookie: mstshash=hello\r\n", "rdp"),
        (b"\x00\x00\x00\x2f\xffSMBr" + b"\x00" * 20, "smb"),
        (b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TCP nm;branch=foo\r\n\r\n", "text"),
        (b"OPTIONS / RTSP/1.0\r\nCSeq: 1\r\n\r\n", "text"),
        (b"JRMI\x00\x02K", "binary"),
        (bytes.fromhex("160301020001000001fc0303") + b"\x00" * 40, "tls"),
        (bytes.fromhex("300c020101600702010304008000"), "binary"),
        (b"", "empty"),
        (b"please save config and set write\r\n", "text"),
    ],
)
def test_bytes_that_are_not_fox_are_foreign_and_never_an_ics_verdict(run, data, guess):
    event, _ = run(data)

    md = event["md"]
    assert md["phase"] == "foreign_on_ics_port"
    assert md["ics"] is False
    assert md["dst_port"] == 1911
    assert md["foreign_protocol"] == guess
    assert md["client_bytes"] == len(data)
    assert event["verdict"] == ("SCANNER", "LOW")
    assert event["raw"] == (data or None)


def test_a_fox_hello_is_a_fox_session(run):
    event, sent = run(HELLO)

    assert event["md"]["phase"] == "fox_session"
    assert "ics" not in event["md"]
    assert event["md"]["client_bytes"] == len(HELLO)
    assert event["verdict"] == ("ics_enumeration", "LOW")
    assert sent.startswith(b"fox a 0 -1 fox hello")


@pytest.mark.parametrize(
    ("frame", "verdict"),
    [
        (b"fox a 2 -1 fox invoke\n{\nord=s:station:|slot:/Drivers\n};;\n", "ics_write_attempt"),
        (b"fox a 2 -1 fox set \n{\nvalue=b:true\n};;\n", "ics_write_attempt"),
        (b"fox a 2 -1 fox file:read\n{\npath=s:/config.bog\n};;\n", "ics_recon_function_code"),
    ],
)
def test_intent_keywords_are_read_inside_a_fox_frame(run, frame, verdict):
    event, _ = run(frame)

    assert event["md"]["phase"] == "fox_session"
    assert event["verdict"][0] == verdict


def test_http_is_still_diverted_under_its_own_phase(run):
    event, _ = run(b"GET / HTTP/1.1\r\nHost: scanner.example:1911\r\n\r\n")

    assert event["md"]["phase"] == "http_on_ics_port"
    assert event["md"]["ics"] is False


def test_is_fox_frame():
    assert is_fox_frame(HELLO)
    assert is_fox_frame(b"fox a 0 -1 fox hello")
    assert not is_fox_frame(b"fox")
    assert not is_fox_frame(b" fox a 1 -1 fox hello")
    assert not is_fox_frame(b"FOX A 1 -1 fox hello")
    assert not is_fox_frame(b"")
