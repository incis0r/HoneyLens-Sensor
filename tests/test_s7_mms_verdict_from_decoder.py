"""On port 102 the verdict comes from the decoder, not from a second table in the decoy.

Reviewed 2026-11-20. ``handle_s7_dt`` knew one write function (0x05) and filed everything
else by a short list, so the request that stops a CPU earned the family's *lowest* verdict:

    PLC Stop 0x29, PI Service 0x28, Request Download 0x1A   ->  "enumeration"  (measured by
                                                                 running the handler)

while ``honeylens.ics.s7comm`` — the table the screen uses — already called them ``control``
and ``write``. MMS decided with a byte search in the first eight bytes after an 0xA1 tag, on a
bare MMS PDU that real clients never send: on the wire the PDU sits inside ISO session and
presentation layers, which only the decoder walks. And a write to a control object
(``…$Oper``, ``…$SBOw``) — the IEC 61850 way to operate a breaker — was any other write.

One table: ``kind_for(decode(protocol, payload))``.
"""

from __future__ import annotations

import asyncio

import pytest

from honeylens.honeypots.honeypots_config import get_profile
from honeylens.honeypots.hp_s7comm import handle_s7_dt
from honeylens.honeypots.ics import cotp102
from honeylens.honeypots.ics.cotp102 import Cotp102Honeypot
from honeylens.honeypots.ics.mms import MmsHandler
from honeylens.ics import decode
from tests.ics_fakes import FakeReader, FakeWriter
from tests.test_ics_decode_mms import (
    IDENTIFY,
    INITIATE,
    READ,
    SESSION_CONNECT,
    WRITE,
    confirmed,
    presentation,
    tlv,
)
from tests.test_ics_decode_mms import dt as mms_dt
from tests.test_ics_decode_s7comm import CR_BODY, READ_VAR, SETUP, SZL, WRITE_VAR, dt, s7_job, tpkt

PEER = ("203.0.113.9", 40102)


def job(function: int) -> bytes:
    return s7_job(bytes([function]) + b"\x00" * 7)


@pytest.mark.parametrize(
    ("payload", "kind"),
    [
        (SETUP, "enumeration"),
        (SZL, "enumeration"),
        (READ_VAR, "recon"),
        (WRITE_VAR, "write"),
        (job(0x1A), "write"),
        (job(0x1B), "write"),
        (job(0x1C), "write"),
        (job(0x28), "command"),
        (job(0x29), "command"),
        (job(0x77), "recon"),  # a job function nobody documents: not an operation
    ],
)
def test_s7_kind_is_what_the_decoder_says(payload, kind):
    _resp, got = handle_s7_dt(payload, get_profile("s7comm"))

    assert got == kind


def test_stopping_the_cpu_is_never_enumeration():
    for function in (0x28, 0x29, 0x1A, 0x1B, 0x1C, 0x05):
        _resp, kind = handle_s7_dt(job(function), get_profile("s7comm"))
        assert kind in ("write", "command"), hex(function)


def test_the_setup_reply_is_unchanged():
    resp, _kind = handle_s7_dt(SETUP, get_profile("s7comm"))

    assert resp is not None and resp[0] == 0x32 and resp[1] == 0x03


def write_to(item: bytes) -> bytes:
    """A confirmed write whose variable specification names ``item`` in domain ``IED1LD0``."""
    name = tlv(0xA1, tlv(0x1A, b"IED1LD0") + tlv(0x1A, item))
    spec = tlv(0xA0, tlv(0x30, tlv(0xA0, name)))
    return confirmed(b"\xa5", spec + tlv(0xA0, tlv(0x83, b"\x01")))


START = confirmed(b"\x9f\x28", b"")  # service 40, start


@pytest.mark.parametrize(
    ("payload", "kind"),
    [
        (SESSION_CONNECT, "enumeration"),
        (presentation(INITIATE), "enumeration"),
        (presentation(IDENTIFY), "enumeration"),
        (presentation(READ), "recon"),
        (presentation(WRITE), "write"),
        (presentation(write_to(b"CSWI1$CO$Pos$Oper")), "command"),
        (presentation(write_to(b"CSWI1$CO$Pos$SBOw")), "command"),
        (presentation(write_to(b"CSWI1$CO$Pos$Cancel")), "command"),
        (presentation(write_to(b"LLN0$SP$SGCB$ActSG")), "write"),
    ],
)
def test_mms_kind_is_what_the_decoder_says(payload, kind):
    handler = MmsHandler(get_profile("mms"))
    handler.handle_mms(payload)

    assert handler.last_kind == kind


def test_operating_a_control_object_is_a_command_in_the_decoder():
    frame = decode("mms", presentation(write_to(b"XCBR1$CO$Pos$Oper")))

    assert frame.semantics == "command"
    assert frame.code == 5
    assert "control object" in frame.sentence


def test_a_read_that_names_a_control_object_orders_nothing():
    name = tlv(0xA1, tlv(0x1A, b"IED1LD0") + tlv(0x1A, b"CSWI1$CO$Pos$Oper"))
    read = confirmed(b"\xa4", tlv(0xA1, tlv(0xA0, tlv(0x30, tlv(0xA0, name)))))

    assert decode("mms", presentation(read)).semantics == "read"


def _session(monkeypatch, stream: bytes) -> list[tuple[str, str, str | None, str | None]]:
    events = []

    def _log(protocol, peer, data, attack_type=None, severity=None, proto=None, raw=None):
        events.append((protocol, data.get("route"), attack_type, severity))

    monkeypatch.setattr(cotp102, "log_event", _log)
    asyncio.run(Cotp102Honeypot().handle_connection(FakeReader(stream), FakeWriter(PEER), PEER))
    return events


def test_the_dispatcher_writes_the_decoders_verdict_for_s7(monkeypatch):
    events = _session(
        monkeypatch, tpkt(CR_BODY) + dt(SETUP) + dt(READ_VAR) + dt(WRITE_VAR) + dt(job(0x29))
    )

    assert events == [
        ("s7comm", "s7", "ics_enumeration", "LOW"),
        ("s7comm", "s7", "ics_recon_function_code", "MEDIUM"),
        ("s7comm", "s7", "ics_write_attempt", "HIGH"),
        ("s7comm", "s7", "ics_command_with_intent", "CRITICAL"),
    ]


def test_the_dispatcher_writes_the_decoders_verdict_for_mms(monkeypatch):
    pdus = [
        SESSION_CONNECT,
        presentation(INITIATE),
        presentation(READ),
        presentation(write_to(b"CSWI1$CO$Pos$Oper")),
        presentation(START),
    ]
    events = _session(monkeypatch, tpkt(CR_BODY) + b"".join(mms_dt(x) for x in pdus))

    assert [e[2] for e in events] == [
        "ics_enumeration",
        "ics_enumeration",
        "ics_recon_function_code",
        "ics_command_with_intent",
        "ics_command_with_intent",
    ]
    assert {e[0] for e in events} == {"mms"}
