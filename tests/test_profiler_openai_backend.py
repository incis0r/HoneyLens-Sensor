"""The attacker-profiler hunting-AI gains an `openai` provider (client LiteLLM proxy).

Previously it supported only `ollama` (local) and `nous` (hard-coded nousresearch.com URL), so a
sensor with neither — e.g. PROD, which uses the client's OpenAI-compatible LiteLLM — logged
`ClientConnectorError` and produced no hunting AI. These pin the new branch: config wiring, the
missing-config guard, and a successful OpenAI-compatible round-trip.
"""

from __future__ import annotations

import asyncio
import json
from typing import ClassVar

from honeylens.analysis import attacker_profiler as ap


def test_profiler_config_exposes_openai_keys():
    from honeylens.config import ATTACKER_PROFILING

    for k in ("openai_base_url", "openai_api_key", "openai_model"):
        assert k in ATTACKER_PROFILING


def test_openai_provider_missing_config_returns_default(monkeypatch):
    monkeypatch.setitem(ap.ATTACKER_PROFILING, "ai_provider", "openai")
    monkeypatch.setitem(ap.ATTACKER_PROFILING, "openai_base_url", "")
    monkeypatch.setitem(ap.ATTACKER_PROFILING, "openai_api_key", "")
    res = asyncio.run(ap.ai_analyze_profile("203.0.113.5", {"attack_types": ["RCE"]}))
    assert res.get("available") is not True  # fell back to the safe default, no crash


class _FakeResp:
    status = 200

    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    captured: ClassVar[dict] = {}

    def __init__(self, *a, **k):
        pass

    def post(self, url, json=None, headers=None):
        _FakeSession.captured = {"url": url, "json": json, "headers": headers}
        content = json_dumps_ai()
        return _FakeResp({"choices": [{"message": {"content": content}}], "usage": {"x": 1}})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def json_dumps_ai():
    return json.dumps(
        {
            "intent": "EXPLOIT",
            "threat_level": "HIGH",
            "summary": "forged-token RCE attempt",
            "recommendations": "block",
        }
    )


def test_openai_provider_roundtrip(monkeypatch):
    monkeypatch.setitem(ap.ATTACKER_PROFILING, "ai_provider", "openai")
    monkeypatch.setitem(ap.ATTACKER_PROFILING, "openai_base_url", "https://llm.example/v1")
    monkeypatch.setitem(ap.ATTACKER_PROFILING, "openai_api_key", "sk-test")
    monkeypatch.setitem(ap.ATTACKER_PROFILING, "openai_model", "qwen-coder")
    monkeypatch.setattr(ap.aiohttp, "ClientSession", _FakeSession)

    res = asyncio.run(ap.ai_analyze_profile("203.0.113.9", {"attack_types": ["RCE"]}))
    assert res["available"] is True
    assert res["intent"] == "EXPLOIT" and res["threat_level"] == "HIGH"
    assert res["provider"] == "openai"
    # posted to the OpenAI-compatible chat/completions endpoint with the bearer key
    assert _FakeSession.captured["url"] == "https://llm.example/v1/chat/completions"
    assert _FakeSession.captured["headers"]["Authorization"] == "Bearer sk-test"
    assert _FakeSession.captured["json"]["model"] == "qwen-coder"
