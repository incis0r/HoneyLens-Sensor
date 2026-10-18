"""Pooling must preserve legacy close() and isolate successive checkouts."""

from unittest.mock import MagicMock

import psycopg2
import psycopg2.extras
import pytest

from honeylens import database as db


@pytest.fixture
def pool(monkeypatch):
    raw = MagicMock()
    raw.closed = False
    pool = MagicMock()
    pool.getconn.return_value = raw
    monkeypatch.setattr(db, "get_pool", lambda: pool)
    return pool


def test_legacy_close_returns_connection_and_cleans_session(pool):
    conn = db.legacy_get_db()
    raw = pool.getconn.return_value
    raw.reset_mock()  # ignore the borrow-time liveness check; assert only the close path
    conn.close()
    raw.rollback.assert_called_once()
    raw.cursor.return_value.__enter__.return_value.execute.assert_called_once_with("DISCARD ALL")
    pool.putconn.assert_called_once_with(raw, close=False)
    assert conn.closed
    assert raw.autocommit is False


def test_release_clears_a_cursor_factory_set_by_the_borrower(pool):
    """A borrower's ``cursor_factory`` must not follow the connection back into the pool.

    ``DISCARD ALL`` resets server-side state only; ``cursor_factory`` is an attribute of the
    client-side connection object and survives both it and ``putconn``. Four callers set
    ``conn.cursor_factory = RealDictCursor`` on a pooled connection, so once any of them had
    run, the next borrower's ordinary ``cur.fetchone()[0]`` received a ``RealDictRow`` and
    raised ``KeyError: 0``. With ~107 such call sites the failure hit most of the app, and it
    was intermittent — it depended on which connection you drew, so one request 500'd while the
    next succeeded.
    """
    conn = db.legacy_get_db()
    raw = pool.getconn.return_value
    raw.cursor_factory = psycopg2.extras.RealDictCursor  # what the four callers do
    conn.close()
    assert raw.cursor_factory is None, "cursor_factory leaked back into the pool"


def test_borrow_validates_and_discards_a_dead_connection(monkeypatch):
    # First getconn hands out a dead connection (its liveness query raises), second a live one.
    dead = MagicMock()
    dead.closed = False
    dead.cursor.return_value.__enter__.return_value.execute.side_effect = psycopg2.OperationalError(
        "server closed"
    )
    live = MagicMock()
    live.closed = False
    pool = MagicMock()
    pool.getconn.side_effect = [dead, live]
    monkeypatch.setattr(db, "get_pool", lambda: pool)

    conn = db.get_db()
    # The dead one is dropped from the pool, the live one is leased.
    pool.putconn.assert_called_once_with(dead, close=True)
    assert conn._conn is live


def test_old_lease_cannot_return_a_new_checkout(pool):
    first = db.get_db()
    first.close()
    second = db.get_db()
    first.close()
    assert not second.closed
    assert pool.putconn.call_count == 1
    with pytest.raises(psycopg2.InterfaceError):
        first.cursor()
    db.return_db(second)
    assert pool.putconn.call_count == 2


def test_closed_raw_connection_is_removed_from_pool(pool):
    conn = db.get_db()
    pool.getconn.return_value.closed = True
    db.return_db(conn)
    pool.putconn.assert_called_once_with(pool.getconn.return_value, close=True)


def test_reset_failure_discards_connection(pool):
    conn = db.get_db()
    pool.getconn.return_value.rollback.side_effect = psycopg2.OperationalError("lost")
    conn.close()
    pool.putconn.assert_called_once_with(pool.getconn.return_value, close=True)


def test_pool_shutdown_closes_raw_connection(pool):
    conn = db.get_db()
    pool.putconn.side_effect = psycopg2.pool.PoolError("closed")
    conn.close()
    pool.getconn.return_value.close.assert_called_once()


def test_return_none_is_safe():
    db.return_db(None)


def test_transaction_context_delegates_without_releasing(pool):
    conn = db.get_db()
    with conn as entered:
        assert entered is conn
        conn.autocommit = True
    pool.getconn.return_value.__exit__.assert_called_once()
    assert not conn.closed
    conn.close()
