"""OpenAI/Ollama-shaped bait on the ordinary HTTP honeypot ports.

Scanners hunting exposed AI endpoints probe by path on whatever port answers — the
sensors recorded /v1/models, /v1/chat/completions and /api/generate arriving on :80,
:8080 and :30000 — while the LLM honeypot listens on a dedicated :3080 nobody asks for.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import honeylens.intelligence.ai_canary as ac
from honeylens.honeypots import ai_endpoints as ae


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ac._reset_for_tests()
    monkeypatch.setenv("AI_CANARY_INSTALL_ID", "test-install")
    monkeypatch.delenv("AI_CANARY_BASE_URL", raising=False)
    yield
    ac._reset_for_tests()


# --- path matching ---------------------------------------------------------


def test_recognises_the_paths_actually_seen_in_the_wild():
    for p in ("/v1/models", "/v1/chat/completions", "/api/generate", "/api/tags"):
        assert ae.is_ai_endpoint(p), p


def test_query_string_and_trailing_slash_still_match():
    assert ae.is_ai_endpoint("/v1/models?verbose=1")
    assert ae.is_ai_endpoint("/v1/models/")
    assert ae.is_ai_endpoint("/V1/Models")


def test_unrelated_paths_are_left_alone():
    """A prefix match would hijack any app that happens to expose /v1/…"""
    for p in ("/", "/v1/users", "/api/v1/namespaces/default/pods", "/apiservice", ""):
        assert not ae.is_ai_endpoint(p), p
    assert ae.handle("GET", "/v1/users") is None


# --- responses -------------------------------------------------------------


def test_models_list_is_openai_shaped_and_matches_the_llm_honeypot_identity():
    status, payload, _h, _e = ae.handle("GET", "/v1/models")
    assert status == 200 and payload["object"] == "list"
    assert payload["data"][0]["id"] == ae.MODEL_NAME == "nexova-assistant-v2"


def test_get_on_a_post_only_route_answers_like_openai():
    """The right error is itself the signal that the endpoint is real."""
    status, payload, _h, _e = ae.handle("GET", "/v1/chat/completions")
    assert status == 405
    assert payload["error"]["type"] == "invalid_request_error"


def test_post_chat_returns_a_completion_echoing_the_requested_model():
    body = json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}).encode()
    status, payload, _h, _e = ae.handle("POST", "/v1/chat/completions", body=body)
    assert status == 200 and payload["model"] == "gpt-4o"
    assert payload["choices"][0]["message"]["role"] == "assistant"


def test_ollama_paths_answer_in_ollama_shape():
    _s, tags, _h, _e = ae.handle("GET", "/api/tags")
    assert tags["models"][0]["name"].startswith(ae.MODEL_NAME)
    _s, gen, _h, ev = ae.handle("POST", "/api/generate", body=b'{"model":"llama3"}')
    assert gen["done"] is True and gen["model"] == "llama3"
    assert ev["flavour"] == "ollama"


def test_malformed_body_does_not_break_the_response():
    status, payload, _h, _e = ae.handle("POST", "/v1/chat/completions", body=b"{not json")
    assert status == 200 and payload["model"] == ae.MODEL_NAME


# --- canary + event --------------------------------------------------------


def test_probe_carries_a_canary_when_enabled(monkeypatch):
    """A scanner piping the reply into a model is exactly the actor Idea 52 hunts."""
    monkeypatch.setenv("AI_CANARY_ENABLED", "true")
    _s, _p, headers, event = ae.handle("GET", "/v1/models", host="h:8080", src_ip="8.8.8.8")
    assert ac.header_name() in headers
    assert "/canary/ai/" in headers[ac.header_name()]
    assert event["canary_nonce"]


def test_no_canary_when_disabled(monkeypatch):
    monkeypatch.delenv("AI_CANARY_ENABLED", raising=False)
    _s, _p, headers, event = ae.handle("GET", "/v1/models")
    assert headers == {} and event["canary_nonce"] is None


def test_carrier_has_its_own_switch(monkeypatch):
    monkeypatch.setenv("AI_CANARY_ENABLED", "true")
    monkeypatch.setenv("AI_CANARY_ON_AI_ENDPOINT_BAIT", "false")
    _s, _p, headers, _e = ae.handle("GET", "/v1/models")
    assert headers == {}


def test_event_is_classified_as_a_probe_not_an_attack():
    _s, _p, _h, event = ae.handle("GET", "/v1/models")
    assert event["attack_type"] == "AI_ENDPOINT_PROBE" == ae.ATTACK_TYPE
    assert event["rule_name"] == "ai_endpoint_v1_models"
    from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY

    assert ATTACK_TYPE_SEVERITY["AI_ENDPOINT_PROBE"] == "medium"


# --- honeypot integration --------------------------------------------------


def test_k8s_honeypot_serves_the_bait(monkeypatch, tmp_path):
    """A sensor saw /v1/chat/completions probes land on this honeypot's port 30000."""
    from honeylens.honeypots import honeypot_k8s as hp

    monkeypatch.setattr(hp, "LOG_FILE", tmp_path / "k8s.json")
    resp = hp.handle_k8s_api_request(
        "GET", "/v1/models", {"host": "h:8080"}, "", 8080, ("8.8.8.8", 1)
    ).decode("utf-8", "replace")
    assert resp.startswith("HTTP/1.1 200")
    assert ae.MODEL_NAME in resp


def test_k8s_kubernetes_paths_are_unaffected(monkeypatch, tmp_path):
    from honeylens.honeypots import honeypot_k8s as hp

    monkeypatch.setattr(hp, "LOG_FILE", tmp_path / "k8s.json")
    resp = hp.handle_k8s_api_request("GET", "/version", {}, "", 8080, ("8.8.8.8", 1)).decode(
        "utf-8", "replace"
    )
    assert "gitVersion" in resp or "major" in resp
