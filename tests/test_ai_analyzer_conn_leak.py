"""Regression: ai_analyzer must RETURN its pooled connection even when the DB op raises.

The daemon's borrow sites used ``conn = get_db() … conn.close()`` with no try/finally, so an
exception between borrow and close (a DB hiccup, or an LLM-backend error while a connection was
held) leaked the lease; after ~maxconn leaks the per-process pool was exhausted and every cycle
failed ``connection pool exhausted``. These pin that a raise no longer leaks.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from honeylens.analysis import ai_analyzer


def _boom_conn():
    """A fake pooled lease whose cursor.execute always raises; .close() is tracked."""
    cur = MagicMock()
    cur.execute.side_effect = RuntimeError("db boom")
    conn = MagicMock()
    conn.cursor.return_value = cur
    return conn


def test_db_conn_returns_lease_on_exception(monkeypatch):
    conn = MagicMock()
    monkeypatch.setattr(ai_analyzer, "legacy_get_db", lambda: conn)
    with pytest.raises(RuntimeError), ai_analyzer._db_conn() as c:
        assert c is conn
        raise RuntimeError("inside")
    conn.close.assert_called_once()  # returned to the pool despite the raise


def test_db_conn_returns_lease_on_success(monkeypatch):
    conn = MagicMock()
    monkeypatch.setattr(ai_analyzer, "legacy_get_db", lambda: conn)
    with ai_analyzer._db_conn() as c:
        assert c is conn
    conn.close.assert_called_once()


def test_store_triage_result_no_leak_on_db_error(monkeypatch):
    conn = _boom_conn()
    monkeypatch.setattr(ai_analyzer, "legacy_get_db", lambda: conn)
    with pytest.raises(RuntimeError):
        ai_analyzer.store_triage_result("evt1", "model", {"classification": "NOISE"}, 5)
    conn.close.assert_called_once()  # lease returned even though the INSERT raised


def test_store_deep_result_no_leak_on_db_error(monkeypatch):
    conn = _boom_conn()
    monkeypatch.setattr(ai_analyzer, "legacy_get_db", lambda: conn)
    with pytest.raises(RuntimeError):
        ai_analyzer.store_deep_result("evt1", "model", {})
    conn.close.assert_called_once()


def test_fetch_unanalysed_events_no_leak_on_db_error(monkeypatch):
    conn = _boom_conn()
    monkeypatch.setattr(ai_analyzer, "legacy_get_db", lambda: conn)
    with pytest.raises(RuntimeError):
        ai_analyzer.fetch_unanalysed_events(limit=5)
    conn.close.assert_called_once()
