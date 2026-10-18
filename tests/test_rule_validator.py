"""AI rule-generation guardrails — reject fantasy/over-broad rules, keep good ones."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeylens.analysis.rule_validator import validate_rule

# --- the actual rules from the 2026-07-23 false-ICS incident must be rejected ---


def test_reject_fc90_x5a_matches_mozilla():
    ok, reason = validate_rule(
        "claude_modbus_fc90_illegal_function_code", "AI_DETECTED", r"FC=90|\x5a"
    )
    assert not ok
    # The rejection is the contract; which guardrail catches it first is not.
    # This rule now trips the single-character check before the benign corpus —
    # \x5a is 'Z' and the rules compile case-insensitively, so the alternation is
    # satisfied by the one-character string 'z'. That is a strictly sharper
    # statement of the same defect, so the assertion accepts either wording.
    assert any(k in reason for k in ("benign", "\\x5a", "character sample")), reason


def test_reject_trailing_pipe_catchall():
    ok, reason = validate_rule(
        "claude_ics_modbus_nonstandard_fc90_broadcast",
        "AI_DETECTED",
        r"(?i)FC\s*=\s*90|\bfc[_\s:]?0x5[aA]\b|function.?code[^\d]*90|",
    )
    assert not ok
    assert "empty" in reason


def test_reject_bare_x5a_binary_rule():
    ok, _reason = validate_rule("claude_modbus_probe", "MODBUS", r"\x5a")
    assert not ok


def test_reject_http_headers_to_mqtt_port():
    # PROD id 34: matched HTTP headers, mislabelled them as an MQTT attack
    ok, reason = validate_rule(
        "claude_http_headers_to_mqtt_port",
        "AI_DETECTED",
        r"(?i)(accept:|user-agent:|host:|content-type:)",
    )
    assert not ok
    assert "benign" in reason


def test_reject_wildcard_only():
    for pat in [r".*", r".+", r".{0,}", r"(?:.*)"]:
        ok, _reason = validate_rule("x", "AI_DETECTED", pat)
        assert not ok, f"{pat} should be rejected"


def test_reject_single_char_and_optional():
    assert not validate_rule("x", "AI_DETECTED", "z")[0]  # too short
    assert not validate_rule("x", "AI_DETECTED", "x?")[0]  # matches empty


def test_reject_uncompilable():
    ok, reason = validate_rule("x", "AI_DETECTED", r"(unclosed[")
    assert not ok
    assert "compile" in reason


# --- legitimate, protocol-grounded rules must pass ---


def test_accept_sqli_union_select():
    ok, reason = validate_rule("sqli_union_select", "SQLI", r"union\s+select\s+")
    assert ok, reason


def test_accept_lfi_traversal():
    ok, reason = validate_rule("lfi_etc_passwd", "LFI", r"\.\./\.\./.*etc/passwd")
    assert ok, reason


def test_accept_real_modbus_mei_hex():
    # Modbus Read Device ID (MEI 0x2b/0x0e) — real wire signature, hex text
    ok, reason = validate_rule(
        "modbus_read_device_id", "MODBUS", r"^[0-9a-f]{4}0000[0-9a-f]{4}002b0e01"
    )
    assert ok, reason


def test_accept_s7comm_cotp_hex():
    ok, reason = validate_rule(
        "s7comm_cotp_connection", "AI_DETECTED", r"0300[0-9a-fA-F]{4}0e[eE][0-9a-fA-F]{2}0000000000"
    )
    assert ok, reason


# --- 2026-08-15: degenerate patterns found live on the edge host -----------------------


def test_reject_optional_alternation_that_hides_a_bare_word():
    """`claude_redis_info_enumeration`, live on the edge host for weeks.

    The trailing alternation is optional, so the rule reduces to "the word INFO
    anywhere" — while the long list of Redis subcommands made its literal core
    look highly specific. It matched the bytes of SSH key exchange and produced
    11,610 events across 460 sources in 30 days, 11,303 of them on port 22, each
    one labelled Redis reconnaissance.
    """
    ok, reason = validate_rule(
        "claude_redis_info_enumeration",
        "SCANNER",
        r"(?i)\bINFO\b\s*(all|server|clients|memory|stats|replication|cpu"
        r"|commandstats|cluster|keyspace|modules|errorstats)?",
    )
    assert not ok
    assert "degenerate" in reason


def test_reject_single_character_class():
    """`claude_ethernet_ip_minimal_payload_scan` = `^[a-z]$` — any one lowercase
    letter. 1,246 events across 728 sources before it was disabled."""
    ok, _reason = validate_rule(
        "claude_ethernet_ip_minimal_payload_scan", "AI_DETECTED", r"^[a-z]$"
    )
    assert not ok


def test_accept_the_redis_rule_that_is_actually_correct():
    """The counter-example, and the reason the check is a ratio rather than an
    absolute length: this one names the RESP framing of a real INFO command and
    fired 386 times on port 6379. Rejecting it alongside its degenerate namesake
    would have cost real Redis detection."""
    ok, reason = validate_rule(
        "claude_redis_info_reconnaissance_probe", "AI_DETECTED", r"\*1\s*\$4\s*INFO"
    )
    assert ok, reason


def test_accept_binary_signature_with_no_literal_text():
    """A Telnet IAC probe carries no literal text at all. Scoring specificity on
    literal characters alone put every binary/ICS signature at zero — which would
    have rejected the detections this platform exists for."""
    ok, reason = validate_rule("telnet_iac_fuzzing", "TELNET", r"\xFF[\xFE\xFF]{2,}")
    assert ok, reason


def test_accept_structurally_anchored_rule_without_many_literals():
    """`^EHLO\\s+(?:\\d{1,3}\\.){3}\\d{1,3}\\s*$` gets its precision from anchors
    and structure, not vocabulary. An absolute-length rule would reject it."""
    ok, reason = validate_rule(
        "smtp_ehlo_ip_literal", "SCANNER", r"^EHLO\s+(?:\d{1,3}\.){3}\d{1,3}\s*$"
    )
    assert ok, reason


def test_accept_repetition_counts_toward_specificity():
    ok, reason = validate_rule("mqtt_repeated_disconnect", "MQTT", r"(?:e000){2,}")
    assert ok, reason
