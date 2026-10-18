"""Provider failures must never masquerade as negative threat intelligence."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from honeylens.intelligence.osint_providers import FeodoProvider, ThreatFoxProvider


def session_with(payload, http_error=False):
    response = MagicMock()
    response.json = AsyncMock(return_value=payload)
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=False)
    if http_error:
        response.raise_for_status.side_effect = RuntimeError("HTTP 401")
    session = MagicMock()
    session.get.return_value = response
    session.post.return_value = response
    return session


@pytest.fixture(autouse=True)
def reset_feed(monkeypatch):
    monkeypatch.setattr(FeodoProvider, "_cache", None)
    monkeypatch.setattr(FeodoProvider, "_cache_ts", 0.0)


@pytest.mark.parametrize("payload,http_error", [([], True), ({"error": "unavailable"}, False)])
def test_feodo_failure_is_not_a_negative_result(payload, http_error):
    result = asyncio.run(FeodoProvider().safe_lookup("8.8.8.8", session_with(payload, http_error)))
    assert result["status"] == "error"
    assert "found" not in result
    assert FeodoProvider._cache is None


def test_feodo_failed_refresh_does_not_trust_stale_cache():
    FeodoProvider._cache = {"8.8.8.8": {"malware": "old"}}
    result = asyncio.run(FeodoProvider().safe_lookup("8.8.8.8", session_with([], True)))
    assert result["status"] == "error"
    assert "is_botnet_c2" not in result


def test_feodo_caches_valid_feed_and_preserves_port_and_c2_status():
    session = session_with([{"ip_address": "8.8.8.8", "port": 443, "status": "offline"}])
    provider = FeodoProvider()
    result = asyncio.run(provider.safe_lookup("8.8.8.8", session))
    assert result["status"] == "ok"
    assert result["found"] is True
    assert result["c2_port"] == 443
    assert result["c2_status"] == "offline"
    result = asyncio.run(provider.safe_lookup("1.1.1.1", session))
    assert result["found"] is False
    assert session.get.call_count == 1
    assert session.get.call_args.args[0].endswith("/ipblocklist.json")


def test_threatfox_requires_auth_key():
    session = session_with({})
    result = asyncio.run(ThreatFoxProvider().safe_lookup("8.8.8.8", session))
    assert result["status"] == "disabled"
    session.post.assert_not_called()


@pytest.mark.parametrize(
    "payload,http_error", [({"query_status": "auth_required"}, False), ({}, True)]
)
def test_threatfox_auth_failure_is_not_no_result(payload, http_error):
    session = session_with(payload, http_error)
    result = asyncio.run(ThreatFoxProvider("test-key").safe_lookup("8.8.8.8", session))
    assert result["status"] == "error"
    assert "found" not in result
    assert session.post.call_args.kwargs["headers"] == {"Auth-Key": "test-key"}


def test_threatfox_no_result_is_a_valid_negative():
    result = asyncio.run(
        ThreatFoxProvider("test-key").safe_lookup(
            "8.8.8.8", session_with({"query_status": "no_result"})
        )
    )
    assert result["status"] == "ok"
    assert result["found"] is False
