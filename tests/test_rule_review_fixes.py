"""Fixes for the defects listed in the August rule review, section 1.

Each test states the behaviour that was wrong and the behaviour that replaces it. The
production evidence behind the ordering is in that document's appendix: of the seven
rules named, five had never fired at all, and the two that had produced only false
positives — one of them on our own Kubernetes decoy's traffic.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row


def _rules(payload, protocol="HTTP", **meta):
    md = {"dst_port": 443}
    md.update(meta)
    return {h[1] for h in classify_event_row(payload=payload, protocol=protocol, metadata=md)}


# ---------------------------------------------------------------- 1.5 aws_secret_key
#
# The rule matched any 40 characters between quotes with no key context at all. Its one
# production hit was a kube-apiserver response whose 40-hex resourceVersion looked like
# a secret. It is the only rule in the review not covered by the binary-protocol gate,
# which is why it is fixed first.


@pytest.mark.parametrize(
    "payload,what",
    [
        ('"' + "a" * 40 + '"', "40 identical characters"),
        ('"da39a3ee5e6b4b0d3255bfef95601890afd80709"', "a SHA-1 digest"),
        (
            '{"resourceVersion":"9e644106593f3f4aa98f8a84b23db5fa378900bd"}',
            "the actual production false positive",
        ),
        ('{"sessionId":"' + "Zk9" * 13 + 'x"}', "a 40-char session id"),
    ],
)
def test_aws_secret_key_needs_key_context(payload, what):
    assert "aws_secret_key" not in _rules(payload), what


@pytest.mark.parametrize(
    "payload",
    [
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        '"aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        "SecretAccessKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ],
)
def test_aws_secret_key_still_detects_a_real_one(payload):
    assert "aws_secret_key" in _rules(payload)


# ------------------------------------------- 1.3 claude_http_headers_to_mqtt_port
#
# Alternation bound looser than intended: `A|B` split the pattern so that
# `image/(webp|avif|apng)` was a standalone branch matching on its own. Separately, the
# rule's four production hits were all on port 6379 — an HTTP scanner reaching the
# Redis decoy, reported as MQTT_ATTACK.


def test_image_type_alone_without_a_header_is_not_an_mqtt_attack():
    """The bug was that `image/(webp|avif|apng)` formed its own branch and matched with
    no header present at all. A payload that really does carry `Accept:` is a genuine
    match and is covered by the test below."""
    assert "mqtt_http_headers_on_mqtt_port" not in _rules(
        "some blob mentioning image/webp in passing", protocol="MQTT", dst_port=1883
    )


def test_http_headers_on_an_mqtt_port_still_match():
    assert "mqtt_http_headers_on_mqtt_port" in _rules(
        "Accept: text/html,application/xml;q=0.9", protocol="MQTT", dst_port=1883
    )


def test_the_rule_does_not_fire_on_the_redis_port():
    """Its four production hits were all 6379. An MQTT rule has no business there."""
    assert "mqtt_http_headers_on_mqtt_port" not in _rules(
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9",
        protocol="TCP",
        dst_port=6379,
    )


# ------------------------------------------------------- 1.1 Suricata syntax leak
#
# Two rules carried IDS rule syntax instead of a regex, so Python searched for the
# literal text "payload =~ /.../". Neither has ever fired, on any sensor, which is what
# a rule that cannot match looks like in the data.


def test_no_rule_still_carries_ids_syntax():
    from honeylens.classification.text_rules import _RULES

    bad = [n for _a, n, rx in _RULES if "payload =~" in rx.pattern]
    assert not bad, f"IDS rule syntax still present in: {bad}"


def test_mqtt_command_injection_matches_its_intended_shape():
    """Superseded 2026-08-27 — and worth keeping as a record of how it went wrong.

    This test used to assert that `cmd 1234567890 end` matched, which it did:
    the August repair of the IDS-syntax rule left the pattern as `\\d{10}`, any ten
    consecutive digits. The test checked only that the rule fired on the shape it
    was written for, never that it stayed quiet on anything else — so it pinned the
    defect in place instead of catching it. In production the rule went on to tag
    SIP INVITEs, PostgreSQL password messages and Unix timestamps as MQTT_ATTACK.

    A digit run is now explicitly NOT a match; the full behaviour is covered in
    tests/test_mqtt_smtp_scoping.py.
    """
    assert "MQTT_Command_Injection_Detection" not in _rules(
        "cmd 1234567890 end", protocol="MQTT", dst_port=1883
    )
    assert "MQTT_Command_Injection_Detection" in _rules(
        "cmd `id` end", protocol="MQTT", dst_port=1883
    )


def test_scanner_payload_rule_matches_its_hex_string():
    hexstr = (
        "636363303030303030303030303030303030303030303030"
        "303030303030303036613065626536343030303030303030"
    )
    assert "Suspicious_TCP_traffic_with_unusual_payload" in _rules(
        hexstr, protocol="TCP", dst_port=4444
    )


# ---------------------------------------------------------- 1.2 Modbus_Scan_Detection
#
# `^[0-9A-Fa-f]{16}$` matches any bare 16-hex string. The binary-protocol gate keeps it
# off HTTP traffic, so the "half an MD5 in a cookie" case does not occur — but on an ICS
# port as raw traffic it still fires on anything hex-shaped.


@pytest.mark.parametrize(
    "payload,what",
    [
        ("a3f5c9d2e1b4778f", "an arbitrary 16-hex string"),
        ("0123456789abcdef", "sequential hex"),
    ],
)
def test_bare_hex_is_not_a_modbus_scan(payload, what):
    assert "Modbus_Scan_Detection" not in _rules(payload, protocol="TCP", dst_port=502), what


def test_modbus_scan_still_matches_a_real_mbap_header():
    """MBAP: transaction id, protocol id 0000, length, unit id, then a function code."""
    assert "Modbus_Scan_Detection" in _rules("0001000000060a2b0e0100", protocol="TCP", dst_port=502)


def test_fc43_rule_is_anchored_to_the_mbap_header():
    """`^.{8}002b0e01` accepted any eight leading characters. The protocol identifier
    must be 0000 for this to be Modbus at all."""
    assert "claude_modbus_fc43_device_enumeration" not in _rules(
        "ZZZZZZZZ002b0e01", protocol="TCP", dst_port=502
    )
    assert "claude_modbus_fc43_device_enumeration" in _rules(
        "00010000002b0e01", protocol="TCP", dst_port=502
    )


# --------------------------------------------------------------- 1.4 taxonomy
#
# A Modbus/MongoDB rule was filed under SQLI.


def test_modbus_mongodb_rule_is_not_filed_as_sqli():
    from honeylens.classification.text_rules import _RULES

    for atype, name, _rx in _RULES:
        if name == "claude_modbus_illegal_function_code_with_mongodb_injection":
            assert atype != "SQLI", "still SQLI; MongoDB is not SQL and this is ICS traffic"
            assert atype in ("NOSQLI", "ICS_ATTACK"), atype
            break
    else:
        pytest.fail("rule disappeared entirely")


def test_its_severity_is_registered():
    from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY
    from honeylens.classification.text_rules import _RULES

    atype = next(
        a for a, n, _ in _RULES if n == "claude_modbus_illegal_function_code_with_mongodb_injection"
    )
    assert atype in ATTACK_TYPE_SEVERITY, (
        f"{atype} has no entry in ATTACK_TYPE_SEVERITY, so it scores as the default"
    )
