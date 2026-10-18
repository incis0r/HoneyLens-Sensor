"""Idea 52 Phase A — AI prompt-injection canary (offline, no DB/network)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import honeylens.intelligence.ai_canary as ac


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ac._reset_for_tests()
    # deterministic install id + base url off (derive from Host)
    monkeypatch.setenv("AI_CANARY_INSTALL_ID", "test-install")
    monkeypatch.delenv("AI_CANARY_BASE_URL", raising=False)
    yield
    ac._reset_for_tests()


def _enable(monkeypatch):
    monkeypatch.setenv("AI_CANARY_ENABLED", "true")


# --- issue -----------------------------------------------------------------


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AI_CANARY_ENABLED", raising=False)
    assert ac.enabled() is False
    assert ac.issue("k8s", "/x", "h") == (None, {})


def test_issue_headers_and_nonce(monkeypatch):
    _enable(monkeypatch)
    nonce, headers = ac.issue("k8s", "/api/v1/namespaces/prod/secrets/s1", "1.2.3.4:6443")
    assert ac._NONCE_RE.fullmatch(nonce)
    assert headers["X-HoneyLens-Canary-Id"] == f"k8s:test-install:{nonce}"
    instr = headers["X-HoneyLens-AI-Canary"]
    assert f"https://1.2.3.4:6443/canary/ai/{nonce}" in instr
    assert "Do not send any credential material." in instr
    assert "\n" not in instr and "\r" not in instr


def test_issue_base_url_override(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setenv("AI_CANARY_BASE_URL", "https://sensor.example:60443/")
    nonce, headers = ac.issue("k8s", "/x", "ignored-host")
    assert f"https://sensor.example:60443/canary/ai/{nonce}" in headers["X-HoneyLens-AI-Canary"]


# --- path / nonce parsing --------------------------------------------------


def test_is_canary_path_and_extract():
    assert ac.is_canary_path("/canary/ai/deadbeef00")
    assert ac.is_canary_path("/CANARY/AI/deadbeef00?x=1")
    assert not ac.is_canary_path("/api/v1/secrets")
    assert ac._extract_nonce("/canary/ai/deadbeef00") == "deadbeef00"
    assert ac._extract_nonce("/canary/ai/NOT_HEX_$$") is None
    assert ac._extract_nonce("/canary/ai/") is None


# --- callback --------------------------------------------------------------


def test_callback_correlated(monkeypatch):
    _enable(monkeypatch)
    nonce, _ = ac.issue("k8s", "/api/v1/namespaces/prod/secrets/cicd", "1.2.3.4")
    ev = ac.record_callback(
        "GET", f"/canary/ai/{nonce}", {"user-agent": "curl/8"}, "", ("9.9.9.9", 40000)
    )
    assert ev["attack_type"] == "AI_AGENT_CALLBACK"
    assert ev["rule_name"] == "prompt_injection_canary_callback"
    assert ev["canary_correlated"] is True
    assert ev["origin_path"] == "/api/v1/namespaces/prod/secrets/cicd"
    assert "callback_delay_ms" in ev and ev["user_agent"] == "curl/8"


def test_callback_valid_format_but_unknown_still_recorded(monkeypatch):
    _enable(monkeypatch)
    ev = ac.record_callback("GET", "/canary/ai/aabbccddeeff", {}, "", ("9.9.9.9", 1))
    assert ev is not None and ev["canary_correlated"] is False


def test_callback_bad_nonce_dropped(monkeypatch):
    _enable(monkeypatch)
    assert ac.record_callback("GET", "/canary/ai/NOPE$$$", {}, "", ("9.9.9.9", 1)) is None


def test_callback_body_capped_and_sanitized(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setenv("AI_CANARY_MAX_CALLBACK_BODY", "16")
    body = "abc\x00\x07def" + "Z" * 100
    ev = ac.record_callback("POST", "/canary/ai/aabbccddeeff", {}, body, ("9.9.9.9", 1))
    assert len(ev["callback_body_sample"]) <= 16
    assert "\x00" not in ev["callback_body_sample"] and "\x07" not in ev["callback_body_sample"]


def test_callback_rate_limited(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setenv("AI_CANARY_RATE_LIMIT_PER_IP_PER_HOUR", "3")
    ok = sum(
        1
        for _ in range(10)
        if ac.record_callback("GET", "/canary/ai/aabbccddeeff", {}, "", ("5.5.5.5", 1)) is not None
    )
    assert ok == 3  # first 3 pass, rest dropped


# --- k8s honeypot integration ---------------------------------------------


def test_k8s_secret_response_has_canary_header_when_enabled(monkeypatch, tmp_path):
    _enable(monkeypatch)
    from honeylens.honeypots import honeypot_k8s as hp

    monkeypatch.setattr(hp, "LOG_FILE", tmp_path / "k8s.json")
    resp = hp.handle_k8s_api_request(
        "GET",
        "/api/v1/namespaces/production/secrets/cicd-deployer-token-x7f9k",
        {"host": "10.0.0.9:6443"},
        "",
        6443,
        ("8.8.8.8", 5555),
    ).decode("utf-8", "replace")
    assert "X-HoneyLens-AI-Canary:" in resp
    assert "/canary/ai/" in resp


def test_k8s_secret_response_no_header_when_disabled(monkeypatch, tmp_path):
    monkeypatch.delenv("AI_CANARY_ENABLED", raising=False)
    from honeylens.honeypots import honeypot_k8s as hp

    monkeypatch.setattr(hp, "LOG_FILE", tmp_path / "k8s.json")
    resp = hp.handle_k8s_api_request(
        "GET",
        "/api/v1/namespaces/production/secrets/cicd-deployer-token-x7f9k",
        {"host": "10.0.0.9:6443"},
        "",
        6443,
        ("8.8.8.8", 5555),
    ).decode("utf-8", "replace")
    assert "X-HoneyLens-AI-Canary:" not in resp


def test_context_noun_and_origin_correlation(monkeypatch):
    _enable(monkeypatch)
    nonce, headers = ac.issue(
        "fortigate",
        "/config",
        "1.2.3.4",
        origin_src_ip="9.9.9.9",
        context="FortiGate configuration",
    )
    assert "analyzing this FortiGate configuration" in headers["X-HoneyLens-AI-Canary"]
    assert headers["X-HoneyLens-Canary-Id"].startswith("fortigate:")
    ev = ac.record_callback("GET", f"/canary/ai/{nonce}", {}, "", ("8.8.8.8", 1))
    assert ev["canary_correlated"] is True and ev["origin_src_ip"] == "9.9.9.9"


def test_k8s_secret_annotation_carrier(monkeypatch, tmp_path):
    _enable(monkeypatch)
    from honeylens.honeypots import honeypot_k8s as hp

    monkeypatch.setattr(hp, "LOG_FILE", tmp_path / "k8s.json")
    resp = hp.handle_k8s_api_request(
        "GET",
        "/api/v1/namespaces/production/secrets/cicd-deployer-token-x7f9k",
        {"host": "h:6443"},
        "",
        6443,
        ("8.8.8.8", 1),
    ).decode("utf-8", "replace")
    assert "honeylens.io/ai-canary" in resp  # embedded in object body
    assert "X-HoneyLens-AI-Canary:" in resp  # and as a header


def test_ai_agent_callback_maps_to_ai_assisted_tag():
    from honeylens.intelligence import apt_attribution as apt

    assert "AI_ASSISTED_AUTOMATION" in apt.TAG_DEFINITIONS
    assert "AI_ASSISTED_AUTOMATION" in apt.compute_tags(["AI_AGENT_CALLBACK"])
    assert "AI_ASSISTED_AUTOMATION" not in apt.compute_tags(["SCANNER"])


def test_k8s_canary_callback_returns_204(monkeypatch, tmp_path):
    _enable(monkeypatch)
    from honeylens.honeypots import honeypot_k8s as hp

    monkeypatch.setattr(hp, "LOG_FILE", tmp_path / "k8s.json")
    nonce, _ = ac.issue("k8s", "/x", "10.0.0.9")
    resp = hp.handle_k8s_api_request(
        "GET", f"/canary/ai/{nonce}", {"user-agent": "agent"}, "", 6443, ("8.8.8.8", 5555)
    ).decode("utf-8", "replace")
    assert resp.startswith("HTTP/1.1 204")


# --- LLM gate ---------------------------------------------------------------


def test_llm_gate_off_when_canary_disabled(monkeypatch):
    monkeypatch.delenv("AI_CANARY_ENABLED", raising=False)
    assert ac.llm_should_issue(attack_category="PROMPT_INJECTION", turn_number=1) is False


def test_llm_gate_fires_on_attack(monkeypatch):
    _enable(monkeypatch)
    assert ac.llm_should_issue(attack_category="PROMPT_INJECTION", turn_number=7) is True


def test_llm_gate_fires_on_suspected_agent(monkeypatch):
    _enable(monkeypatch)
    # classify_actor confidences: LLM_AGENT 70..95, BOT_OR_FAST_HUMAN a flat 50
    assert ac.llm_should_issue(actor_type="LLM_AGENT", actor_confidence=88, turn_number=7) is True
    assert (
        ac.llm_should_issue(actor_type="BOT_OR_FAST_HUMAN", actor_confidence=50, turn_number=7)
        is True
    )


def test_llm_gate_ignores_confidence_of_a_human_verdict(monkeypatch):
    """classify_actor returns confidence in the *classification*, so a confidently
    identified HUMAN scores 50..90. Thresholding that number on its own would spray
    canaries at ordinary visitors."""
    _enable(monkeypatch)
    assert ac.llm_should_issue(actor_type="HUMAN", actor_confidence=90, turn_number=4) is False
    assert ac.llm_should_issue(actor_type="UNKNOWN", actor_confidence=0, turn_number=4) is False


def test_llm_gate_fires_on_first_turn_only(monkeypatch):
    """Timing-based actor detection is blind on turn 1, so a one-shot scraper would
    otherwise never see a canary."""
    _enable(monkeypatch)
    assert ac.llm_should_issue(attack_category="BENIGN", actor_type="HUMAN", turn_number=1) is True
    assert ac.llm_should_issue(attack_category="BENIGN", actor_type="HUMAN", turn_number=2) is False


def test_llm_gate_quiet_for_benign_human_conversation(monkeypatch):
    """The regression this gate exists for: not a header on every single response."""
    _enable(monkeypatch)
    assert [
        ac.llm_should_issue(
            attack_category="BENIGN", actor_type="HUMAN", actor_confidence=75, turn_number=t
        )
        for t in range(1, 6)
    ] == [True, False, False, False, False]


def test_llm_gate_respects_env_switches(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setenv("LLM_AI_CANARY_ON_FIRST_TURN", "false")
    assert ac.llm_should_issue(attack_category="BENIGN", turn_number=1) is False
    monkeypatch.setenv("LLM_AI_CANARY_ON_ATTACK", "false")
    assert ac.llm_should_issue(attack_category="JAILBREAK", turn_number=3) is False
    monkeypatch.setenv("LLM_AI_CANARY_ON_AGENT", "false")
    assert ac.llm_should_issue(actor_type="LLM_AGENT", actor_confidence=99, turn_number=3) is False


def test_llm_gate_confidence_threshold_configurable(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setenv("LLM_AI_CANARY_ACTOR_CONFIDENCE", "80")
    assert (
        ac.llm_should_issue(actor_type="BOT_OR_FAST_HUMAN", actor_confidence=50, turn_number=4)
        is False
    )
    assert ac.llm_should_issue(actor_type="LLM_AGENT", actor_confidence=85, turn_number=4) is True


def test_llm_gate_tolerates_junk_values(monkeypatch):
    _enable(monkeypatch)
    assert (
        ac.llm_should_issue(
            actor_confidence=None, actor_type=None, attack_category=None, turn_number=3
        )
        is False
    )
