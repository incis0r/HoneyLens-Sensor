"""Regressions for the hunting queue, config contract and AI backend selection."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from honeylens.analysis import attacker_profiler as profiler
from honeylens.config import ATTACKER_PROFILING, OLLAMA_DEEP_MODEL, OLLAMA_URL
from honeylens.routes import hunting


def request(body, admin=True):
    return SimpleNamespace(state=SimpleNamespace(is_admin=admin), json=AsyncMock(return_value=body))


def test_bulk_hunt_enqueues_new_ip_instead_of_only_updating_profile(monkeypatch):
    conn = MagicMock()
    monkeypatch.setattr(hunting, "db", lambda: conn)
    monkeypatch.setattr(hunting, "is_known_scanner", lambda **kw: False)
    monkeypatch.setattr(hunting, "is_whitelisted", lambda ip: False)
    result = asyncio.run(hunting.attacker_hunting_bulk_hunt(request({"ips": ["203.0.113.12"]})))
    sql = [
        call.args[0]
        for call in conn.cursor.return_value.__enter__.return_value.execute.call_args_list
    ]
    assert any("INSERT INTO attacker_hunt_queue" in statement for statement in sql)
    assert not any("updated_at = NOW()" in statement for statement in sql)
    assert result["queued"] == 1
    conn.commit.assert_called_once()
    conn.close.assert_called_once()


@pytest.mark.parametrize(
    "body", [[], {"ips": "1.1.1.1"}, {"ips": ["invalid"]}, {"ips": ["1.1.1.1"] * 51}]
)
def test_bulk_rejects_invalid_requests_before_database(body, monkeypatch):
    db = MagicMock()
    monkeypatch.setattr(hunting, "db", db)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(hunting.attacker_hunting_bulk_hunt(request(body)))
    assert exc.value.status_code == 400
    db.assert_not_called()


def test_queue_drains_when_automatic_discovery_is_disabled(monkeypatch):
    conn = MagicMock()
    monkeypatch.setattr(profiler.hunt_queue, "pending", lambda c, n: [("203.0.113.12", "version1")])
    done = MagicMock()
    monkeypatch.setattr(profiler.hunt_queue, "complete", done)
    monkeypatch.setattr(profiler, "fetch_ip_info", lambda c, ip: {"total_events": 2})
    analyze = AsyncMock(return_value={"ai_threat_level": "HIGH"})
    monkeypatch.setattr(profiler, "profile_ip", analyze)
    discovery = MagicMock(side_effect=AssertionError("automatic discovery is disabled"))
    monkeypatch.setattr(profiler, "find_qualifying_ips", discovery)
    assert asyncio.run(profiler.daemon_cycle(conn, [], {"auto_profile": False})) == 1
    analyze.assert_awaited_once()
    done.assert_called_once_with(conn, "203.0.113.12", "version1")


def test_failed_queue_item_is_retained_for_retry(monkeypatch):
    conn = MagicMock()
    monkeypatch.setattr(profiler.hunt_queue, "pending", lambda c, n: [("203.0.113.12", "version1")])
    monkeypatch.setattr(profiler, "fetch_ip_info", lambda c, ip: {})
    monkeypatch.setattr(
        profiler, "profile_ip", AsyncMock(side_effect=RuntimeError("database unavailable"))
    )
    failed, complete = MagicMock(), MagicMock()
    monkeypatch.setattr(profiler.hunt_queue, "failed", failed)
    monkeypatch.setattr(profiler.hunt_queue, "complete", complete)
    assert asyncio.run(profiler.daemon_cycle(conn, [], {"auto_profile": False})) == 0
    failed.assert_called_once()
    complete.assert_not_called()
    conn.rollback.assert_called_once()


def test_configured_batch_and_attack_threshold_reach_discovery(monkeypatch):
    monkeypatch.setattr(profiler.hunt_queue, "pending", lambda c, n: [])
    discover = MagicMock(return_value=[])
    monkeypatch.setattr(profiler, "find_qualifying_ips", discover)
    conn = MagicMock()
    config = {
        **ATTACKER_PROFILING,
        "min_connections": 7,
        "min_attack_patterns": 4,
        "max_profiles_per_cycle": 2,
        "reprofile_interval_sec": 600,
    }
    asyncio.run(profiler.daemon_cycle(conn, [], config))
    discover.assert_called_once_with(conn, 7, 4, 2, 600)
    assert ATTACKER_PROFILING["ollama_url"] == OLLAMA_URL
    assert ATTACKER_PROFILING["ollama_model"] == OLLAMA_DEEP_MODEL
    assert ATTACKER_PROFILING["daemon_interval_sec"] > 0


def test_ai_uses_configured_backend_and_model(monkeypatch):
    config = {
        **profiler.ATTACKER_PROFILING,
        "ollama_url": "http://ai.test:11434",
        "ollama_model": "test-model",
    }
    monkeypatch.setattr(profiler, "ATTACKER_PROFILING", config)
    response = MagicMock(status=200)
    response.json = AsyncMock(
        return_value={"response": '{"intent":"RECON","threat_level":"LOW","summary":"scanning"}'}
    )
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=response)
    session = MagicMock()
    session.post.return_value = context
    session_context = MagicMock()
    session_context.__aenter__ = AsyncMock(return_value=session)
    monkeypatch.setattr(profiler.aiohttp, "ClientSession", lambda **kw: session_context)
    result = asyncio.run(profiler.ai_analyze_profile("203.0.113.12", {}))
    assert result["threat_level"] == "LOW"
    assert session.post.call_args.args[0] == "http://ai.test:11434/api/generate"
    assert session.post.call_args.kwargs["json"]["model"] == "test-model"


@pytest.mark.parametrize(
    "status,body,available",
    [
        (
            200,
            {
                "choices": [
                    {
                        "message": {
                            "content": '{"intent":"RECON","threat_level":"LOW","summary":"probe"}'
                        }
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
            True,
        ),
        (429, {}, False),
        (
            200,
            {
                "choices": [
                    {
                        "message": {
                            "content": '{"intent":"RECON","threat_level":"banana","summary":"probe"}'
                        }
                    }
                ]
            },
            False,
        ),
        (200, {"choices": []}, False),
    ],
)
def test_nous_json_validation_token_limit_and_failures(monkeypatch, status, body, available):
    config = {
        **profiler.ATTACKER_PROFILING,
        "ai_provider": "nous",
        "nous_api_key": "test-token",
        "nous_model": "qwen/qwen3-30b-a3b-instruct-2507",
        "ai_max_tokens": 512,
    }
    monkeypatch.setattr(profiler, "ATTACKER_PROFILING", config)
    response = MagicMock(status=status)
    response.json = AsyncMock(return_value=body)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=response)
    session = MagicMock()
    session.post.return_value = context
    session_context = MagicMock()
    session_context.__aenter__ = AsyncMock(return_value=session)
    monkeypatch.setattr(profiler.aiohttp, "ClientSession", lambda **kw: session_context)
    result = asyncio.run(profiler.ai_analyze_profile("203.0.113.12", {}))
    assert result["available"] is available
    call = session.post.call_args
    assert call.args[0] == "https://inference-api.nousresearch.com/v1/chat/completions"
    assert call.kwargs["json"]["max_tokens"] == 512
    assert call.kwargs["headers"]["Authorization"] == "Bearer test-token"
    if available:
        assert result["usage"]["prompt_tokens"] == 100
    else:
        assert result["threat_level"] == "UNKNOWN"


# --- _attacker_hunting_tables_exist: transient error must not masquerade as a missing table ---


def _fake_conn(execute=None):
    cur = MagicMock()
    if execute is not None:
        cur.execute.side_effect = execute
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn, cur


def test_table_gate_true_when_present(monkeypatch):
    conn, cur = _fake_conn()
    cur.fetchone.return_value = (True,)
    monkeypatch.setattr(hunting, "db", lambda: conn)
    assert hunting._attacker_hunting_tables_exist() is True
    conn.close.assert_called_once()  # connection always released


def test_table_gate_false_when_absent(monkeypatch):
    conn, cur = _fake_conn()
    cur.fetchone.return_value = (False,)  # to_regclass IS NOT NULL -> False
    monkeypatch.setattr(hunting, "db", lambda: conn)
    assert hunting._attacker_hunting_tables_exist() is False
    conn.close.assert_called_once()


def test_table_gate_reraises_transient_error_not_false(monkeypatch):
    # A dead/poisoned pooled connection (or pool exhaustion) must NOT be reported as a missing
    # table — it propagates so the endpoint answers an honest 500, not a false 503. (bugfix)
    conn, _cur = _fake_conn(execute=RuntimeError("connection pool exhausted"))
    monkeypatch.setattr(hunting, "db", lambda: conn)
    with pytest.raises(RuntimeError):
        hunting._attacker_hunting_tables_exist()
    conn.close.assert_called_once()  # still released on the error path (no leak)
