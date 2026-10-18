"""The same foreign streams, sent to every industrial decoy.

Each decoy has its own recognition test next to its own protocol. This file is the family
contract, written independently of those: whatever the port claims to be, a TLS handshake, an
HTTP request, an RDP connection request, an SMB negotiate, an SSH banner or noise is recorded
exactly once as ``foreign_on_ics_port`` — not an ICS row, verdict ``SCANNER``/LOW — and the
decoy sends nothing back. And no input, however random, raises or earns ``ICS_ATTACK``.
"""

from __future__ import annotations

import asyncio
import importlib
import random

import pytest

from tests.ics_fakes import FakeReader, FakeWriter

PEER = ("203.0.113.9", 40000)

FOREIGN = {
    "tls": bytes.fromhex("1603010200010001fc0303") + bytes(range(64)),
    "http": b"GET / HTTP/1.1\r\nHost: scanner.example\r\nUser-Agent: x\r\n\r\n",
    "rdp": bytes.fromhex("0300002b26e00000000000") + b"Cookie: mstshash=hello\r\n",
    "smb": b"\x00\x00\x00\x2f\xffSMB\x72" + b"\x00" * 40,
    "ssh": b"SSH-2.0-Go\r\n",
    "noise": bytes.fromhex("9d41c7f2e80b663a5510ffee0123456789abcdef") * 4,
}

# (module, class, attribute of the module that the decoy logs through)
TCP_DECOYS = [
    ("honeylens.honeypots.hp_iec104", "IEC104Honeypot"),
    ("honeylens.honeypots.hp_modbus", "ModbusHoneypot"),
    ("honeylens.honeypots.hp_dnp3", "DNP3Honeypot"),
    ("honeylens.honeypots.hp_fins", "FinsHoneypot"),
    ("honeylens.honeypots.hp_enip", "ENIPHoneypot"),
    ("honeylens.honeypots.hp_opcua", "OpcuaHoneypot"),
    ("honeylens.honeypots.ics.cotp102", "Cotp102Honeypot"),
    ("honeylens.honeypots.ics.fox", "FoxHoneypot"),
]


def _tcp(monkeypatch, module_name: str, class_name: str, stream: bytes):
    module = importlib.import_module(module_name)
    events: list[tuple[dict, str | None, str | None]] = []

    def _log(protocol, peer, data, attack_type=None, severity=None, **_kw):
        events.append((data, attack_type, severity))
        return {}

    monkeypatch.setattr(module, "log_event", _log)
    writer = FakeWriter(PEER)
    asyncio.run(getattr(module, class_name)().handle_connection(FakeReader(stream), writer, PEER))
    return events, bytes(writer.sent)


def _udp(monkeypatch, which: str, datagram: bytes):
    events: list[tuple[dict, str | None, str | None]] = []

    def _log(protocol, peer, data, attack_type=None, severity=None, **_kw):
        events.append((data, attack_type, severity))
        return {}

    class Transport:
        def __init__(self):
            self.sent: list[bytes] = []

        def sendto(self, data, addr=None):
            self.sent.append(data)

    transport = Transport()
    if which == "bacnet":
        from honeylens.honeypots import hp_bacnet as module

        proto = module.BACnetProtocol(module.BACnetHoneypot())
    else:
        from honeylens.honeypots.honeypots_config import get_profile
        from honeylens.honeypots.ics import profinet as module
        from honeylens.honeypots.ics.profinet import ProfinetDatagramProtocol

        proto = ProfinetDatagramProtocol(profile=get_profile("profinet"))
    monkeypatch.setattr(module, "log_event", _log)
    proto.connection_made(transport)
    proto.datagram_received(datagram, PEER)
    return events, transport.sent


@pytest.mark.parametrize(("module_name", "class_name"), TCP_DECOYS)
@pytest.mark.parametrize("kind", [k for k in FOREIGN if k != "http"])
def test_a_tcp_decoy_records_a_foreign_stream_once_and_says_nothing(
    monkeypatch, module_name, class_name, kind
):
    events, sent = _tcp(monkeypatch, module_name, class_name, FOREIGN[kind])

    assert [(d["phase"], d.get("ics"), at, sev) for d, at, sev in events] == [
        ("foreign_on_ics_port", False, "SCANNER", "LOW")
    ], events
    assert events[0][0]["client_bytes"] == len(FOREIGN[kind])
    if class_name != "FoxHoneypot":
        assert sent == b""


@pytest.mark.xfail(strict=True, reason="open defect: the Fox decoy sends its hello on connect")
def test_the_fox_decoy_does_not_speak_before_the_client(monkeypatch):
    # A Niagara station waits for the client's hello. Ours hands its banner to every TCP
    # connect, so a foreign stream is recorded correctly and still gets a Fox reply.
    _, sent = _tcp(monkeypatch, "honeylens.honeypots.ics.fox", "FoxHoneypot", FOREIGN["tls"])

    assert sent == b""


@pytest.mark.parametrize(
    ("module_name", "class_name"), [d for d in TCP_DECOYS if d[1] != "FoxHoneypot"]
)
def test_http_on_an_industrial_port_is_foreign(monkeypatch, module_name, class_name):
    # Fox diverts HTTP to its own web handler (tests/test_fox_http_is_not_ics.py); every
    # other decoy treats it like any foreign stream.
    events, sent = _tcp(monkeypatch, module_name, class_name, FOREIGN["http"])

    assert [(d["phase"], d.get("ics"), at) for d, at, _ in events] == [
        ("foreign_on_ics_port", False, "SCANNER")
    ], events
    assert events[0][0]["foreign_protocol"] == "http"
    assert sent == b""


@pytest.mark.parametrize("which", ["bacnet", "profinet"])
@pytest.mark.parametrize("kind", sorted(FOREIGN))
def test_a_udp_decoy_never_answers_a_foreign_datagram(monkeypatch, which, kind):
    events, sent = _udp(monkeypatch, which, FOREIGN[kind])

    assert sent == [], "a reply to an unrecognised datagram is a reflector"
    assert [(d["phase"], d.get("ics"), at) for d, at, _ in events] == [
        ("foreign_on_ics_port", False, "SCANNER")
    ], events


@pytest.mark.parametrize(("module_name", "class_name"), TCP_DECOYS)
def test_random_streams_never_raise_and_never_earn_an_attack(monkeypatch, module_name, class_name):
    rng = random.Random(20261120)
    for _ in range(300):
        stream = rng.randbytes(rng.randrange(0, 96))
        events, _ = _tcp(monkeypatch, module_name, class_name, stream)
        assert all(
            at not in ("ICS_ATTACK", "ics_write_attempt", "ics_command_with_intent")
            for _, at, _ in events
        ), (stream.hex(), events)


@pytest.mark.parametrize("which", ["bacnet", "profinet"])
def test_random_datagrams_never_raise_and_never_earn_an_attack(monkeypatch, which):
    rng = random.Random(20261120)
    for _ in range(300):
        datagram = rng.randbytes(rng.randrange(0, 96))
        events, _ = _udp(monkeypatch, which, datagram)
        assert all(
            at not in ("ICS_ATTACK", "ics_write_attempt", "ics_command_with_intent")
            for _, at, _ in events
        ), (datagram.hex(), events)
