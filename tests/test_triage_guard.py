#!/usr/bin/env python3
"""Tests for analysis/triage_guard.py — the deterministic 0-day FP guard."""

import json

import pytest

from honeylens.analysis.triage_guard import (
    NOVELTY_CAP,
    apply_triage_guard,
    is_benign_protocol_event,
)


def _ehlo(host="sh-ams-nl-gp5-wk102.internet-census.org"):
    return {"protocol": "SMTP", "dst_port": 25, "payload": f"EHLO {host}"}


def _auth_login(user_b64="bmF0ZQ=="):
    return {
        "protocol": "SMTP",
        "dst_port": 25,
        "payload": json.dumps(
            {
                "phase": "auth_login_creds",
                "raw": "AUTH LOGIN",
                "username_b64": user_b64,
                "username": "nate",
            }
        ),
    }


# --- benign detection ------------------------------------------------------


def test_ehlo_greeting_is_benign():
    ok, reason = is_benign_protocol_event(_ehlo())
    assert ok is True
    assert "SMTP" in reason


def test_auth_login_capture_is_benign():
    ok, reason = is_benign_protocol_event(_auth_login())
    assert ok is True
    assert "auth_login_creds" in reason


def test_benign_by_port_when_protocol_missing():
    ev = {"dst_port": 587, "payload": "HELO mail.example.com"}
    ok, _ = is_benign_protocol_event(ev)
    assert ok is True


def test_multiline_smtp_handshake_is_benign():
    ev = {
        "protocol": "SMTP",
        "dst_port": 25,
        "payload": "EHLO x\r\nAUTH LOGIN\r\ndXNlcg==\r\ncGFzcw==\r\nQUIT",
    }
    ok, _ = is_benign_protocol_event(ev)
    assert ok is True


# --- things that must NOT be suppressed (real-exploit shapes) --------------


def test_non_smtp_is_not_benign():
    ev = {"protocol": "HTTP", "dst_port": 80, "payload": "EHLO x"}
    ok, _ = is_benign_protocol_event(ev)
    assert ok is False


def test_binary_payload_not_benign():
    ev = {"protocol": "SMTP", "dst_port": 25, "payload": "EHLO \x00\x90\x90\x90shellcode"}
    ok, _ = is_benign_protocol_event(ev)
    assert ok is False


def test_oversized_smtp_arg_not_benign():
    ev = {"protocol": "SMTP", "dst_port": 25, "payload": "MAIL FROM:<" + "A" * 900 + ">"}
    ok, _ = is_benign_protocol_event(ev)
    assert ok is False


def test_unknown_smtp_phase_not_benign():
    ev = {
        "protocol": "SMTP",
        "dst_port": 25,
        "payload": json.dumps({"phase": "exploit_attempt", "raw": "..."}),
    }
    ok, _ = is_benign_protocol_event(ev)
    assert ok is False


def test_non_smtp_verb_line_not_benign():
    ev = {"protocol": "SMTP", "dst_port": 25, "payload": "EHLO x\r\nGET /etc/passwd HTTP/1.0"}
    ok, _ = is_benign_protocol_event(ev)
    assert ok is False


# --- apply_triage_guard downgrade ------------------------------------------


def test_guard_caps_novelty_and_downgrades_class():
    ev = _auth_login()
    result = {
        "classification": "SUSPICIOUS",
        "novelty_score": 8,
        "reasoning": "credential capture over SMTP is unusual",
    }
    out = apply_triage_guard(ev, result)
    assert out["novelty_score"] == NOVELTY_CAP
    assert out["classification"] == "NOISE"
    assert out["guarded"] is True
    assert out["reasoning"].startswith("[guard:")


def test_guard_downgrades_ehlo_scanner():
    ev = _ehlo()
    result = {"classification": "SUSPICIOUS", "novelty_score": 6, "reasoning": "x"}
    out = apply_triage_guard(ev, result)
    assert out["novelty_score"] == NOVELTY_CAP
    assert out["classification"] == "NOISE"


def test_guard_noop_on_real_exploit():
    ev = {"protocol": "SMTP", "dst_port": 25, "payload": "MAIL FROM:<" + "A" * 900 + ">"}
    result = {"classification": "CRITICAL", "novelty_score": 9, "reasoning": "overflow"}
    out = apply_triage_guard(ev, result)
    assert out["novelty_score"] == 9
    assert out["classification"] == "CRITICAL"
    assert "guarded" not in out


def test_guard_noop_on_non_smtp():
    ev = {"protocol": "HTTP", "dst_port": 8080, "payload": "GET / HTTP/1.1"}
    result = {"classification": "SUSPICIOUS", "novelty_score": 7, "reasoning": "y"}
    out = apply_triage_guard(ev, result)
    assert out["novelty_score"] == 7
    assert out["classification"] == "SUSPICIOUS"


def test_guard_preserves_already_low_noise():
    ev = _ehlo()
    result = {"classification": "NOISE", "novelty_score": 1, "reasoning": "z"}
    out = apply_triage_guard(ev, result)
    assert out["novelty_score"] == 1
    assert out["classification"] == "NOISE"
    assert "guarded" not in out  # nothing changed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
