"""A route handler must not be able to leak a database connection.

`db()` returns a NEW psycopg2 connection (`legacy_get_db`), and 98 route handlers
take one without a try/finally. On the happy path CPython's refcounting closes it
when the handler returns. On the error path it does not: the traceback holds the
frame, the frame holds the connection, and it stays open in
`idle in transaction (aborted)` for as long as the exception is referenced.

Observed on sensor-a 2026-08-27. One failing query — `SELECT COUNT(*) FROM mitm_events`
against a table missing the `baseline` column on that fresh install — leaked one
connection per dashboard poll. Eleven accumulated over six hours, the API ran out
of usable connections, and `/ics/stats`, `/ai/stats` and even `/` timed out.
Terminating them restored a 30-second timeout to 0.011 s. A ten-day-old aborted
connection had been sitting on another host for the same reason.

The fix is a per-request scope, so the leak is impossible regardless of what a
handler does. These tests pin that, and pin the two properties that make it work:
the scope must survive a handler raising, and the middleware must be raw ASGI.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from honeylens.routes import _helpers as h

_API_PY = Path(__file__).resolve().parents[1] / "src" / "honeylens" / "api.py"


class _FakeConn:
    """Just enough psycopg2 connection surface for the scope to act on."""

    def __init__(self, closed=False, rollback_raises=False):
        self.closed = closed
        self.rolled_back = False
        self._rollback_raises = rollback_raises

    def rollback(self):
        if self._rollback_raises:
            raise RuntimeError("connection is unusable")
        self.rolled_back = True

    def close(self):
        self.closed = True


@pytest.fixture
def scope():
    token = h.begin_request_conn_scope()
    yield
    h.close_request_conns(token)


# ------------------------------------------------------------------ the mechanism


def test_a_connection_taken_in_scope_is_closed_at_the_end(monkeypatch):
    conn = _FakeConn()
    monkeypatch.setattr(h, "legacy_get_db", lambda: conn)
    token = h.begin_request_conn_scope()
    h.db()
    assert conn.closed is False
    leaked = h.close_request_conns(token)
    assert conn.closed is True
    assert leaked == 1, "an unclosed connection should be reported, not silently swept"


def test_it_is_rolled_back_before_closing(monkeypatch):
    """An aborted transaction that is closed without a rollback can leave the
    server holding locks until it notices the disconnect."""
    conn = _FakeConn()
    monkeypatch.setattr(h, "legacy_get_db", lambda: conn)
    token = h.begin_request_conn_scope()
    h.db()
    h.close_request_conns(token)
    assert conn.rolled_back is True


def test_a_connection_the_handler_already_closed_is_not_counted(monkeypatch):
    """A well-behaved handler must not be reported as leaking."""
    conn = _FakeConn()
    monkeypatch.setattr(h, "legacy_get_db", lambda: conn)
    token = h.begin_request_conn_scope()
    h.db()
    conn.close()
    assert h.close_request_conns(token) == 0


def test_every_connection_is_closed_even_when_one_misbehaves(monkeypatch):
    """Cleanup runs in the response path — one bad connection must not abort it."""
    bad, good = _FakeConn(rollback_raises=True), _FakeConn()
    seq = iter([bad, good])
    monkeypatch.setattr(h, "legacy_get_db", lambda: next(seq))
    token = h.begin_request_conn_scope()
    h.db()
    h.db()
    h.close_request_conns(token)
    assert bad.closed is True and good.closed is True


def test_the_scope_survives_the_handler_raising(monkeypatch):
    """The whole point: the error path is the one that leaked."""
    conn = _FakeConn()
    monkeypatch.setattr(h, "legacy_get_db", lambda: conn)
    token = h.begin_request_conn_scope()
    try:
        h.db()
        raise ValueError("boom, exactly like the missing-column query")
    except ValueError:
        pass
    finally:
        h.close_request_conns(token)
    assert conn.closed is True


def test_outside_a_request_db_still_works(monkeypatch):
    """Cron jobs and background tasks call db() with no scope open."""
    conn = _FakeConn()
    monkeypatch.setattr(h, "legacy_get_db", lambda: conn)
    assert h.db() is conn
    assert conn.closed is False, "no scope means the caller still owns it"


def test_scopes_do_not_leak_between_requests(monkeypatch):
    a, b = _FakeConn(), _FakeConn()
    seq = iter([a, b])
    monkeypatch.setattr(h, "legacy_get_db", lambda: next(seq))
    t1 = h.begin_request_conn_scope()
    h.db()
    h.close_request_conns(t1)
    t2 = h.begin_request_conn_scope()
    h.db()
    h.close_request_conns(t2)
    assert a.closed and b.closed


# --------------------------------------------------------------- the middleware


def test_the_middleware_is_raw_asgi_not_basehttpmiddleware():
    """BaseHTTPMiddleware runs the downstream app in a separate anyio task, and a
    ContextVar set in its dispatch() is not reliably visible there. A raw ASGI
    middleware runs in the same task, so the scope reaches the handler."""
    import ast

    tree = ast.parse(open(_API_PY).read())
    cls = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name == "DbConnScopeMiddleware"
    )
    bases = [ast.unparse(b) if hasattr(ast, "unparse") else getattr(b, "id", "") for b in cls.bases]
    assert "BaseHTTPMiddleware" not in bases, (
        f"DbConnScopeMiddleware must not inherit BaseHTTPMiddleware (got {bases})"
    )
    calls = [n.name for n in cls.body if isinstance(n, ast.AsyncFunctionDef)]
    assert "__call__" in calls, "a raw ASGI middleware needs async __call__"


def test_the_scope_is_closed_in_a_finally():
    src = open(_API_PY).read()
    i = src.index("class DbConnScopeMiddleware")
    body = src[i : i + 1600]
    assert "finally:" in body
    assert body.index("finally:") < body.index("close_request_conns")


def test_non_http_scopes_pass_straight_through():
    """Lifespan and websocket scopes have no request to bound."""
    src = open(_API_PY).read()
    i = src.index("class DbConnScopeMiddleware")
    assert 'scope.get("type") != "http"' in src[i : i + 1600]


def test_the_scope_wraps_authentication_too():
    """add_middleware puts the last-added outermost, so registering the scope after
    AuthMiddleware means a connection taken during auth is covered as well."""
    src = open(_API_PY).read()
    assert src.index("app.add_middleware(AuthMiddleware)") < src.index(
        "app.add_middleware(DbConnScopeMiddleware)"
    )
