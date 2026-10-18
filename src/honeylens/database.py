"""Database access: per-process connection pool, detected-schema cache, context-managed cursor.

Replaces the ``psycopg2.connect()``-per-call pattern duplicated in 0.9 across the api, the
AI analyser and three ingests.

Usage::

    from honeylens.database import db_cursor, get_db, return_db, detect_schema

    with db_cursor() as cur:                       # commit on exit, rollback on exception
        cur.execute("SELECT count(*) FROM sensor_events")
        count = cur.fetchone()[0]

    conn = get_db()                                # long-lived connections (daemon loops)
    try:
        ...
    finally:
        return_db(conn)

    schema = detect_schema()                       # once per process
    if schema["has_attack_types"]:
        ...
"""

import logging
import threading
from typing import Any, Literal, cast

import psycopg2
import psycopg2.extensions
import psycopg2.extras
import psycopg2.pool

logger = logging.getLogger("honeylens.database")

_pool: psycopg2.pool.ThreadedConnectionPool | None = None
_pool_lock = threading.Lock()


def _get_db_config() -> dict[str, Any]:
    """Deferred import: ``config`` imports ``env`` and ``version``, which must not depend on the DB."""
    from honeylens.config import DB_CONFIG

    return DB_CONFIG


def init_pool(minconn: int = 2, maxconn: int = 20) -> psycopg2.pool.ThreadedConnectionPool:
    """Initialise the global pool. Thread-safe, idempotent."""
    global _pool
    with _pool_lock:
        if _pool is None:
            cfg = _get_db_config()
            _pool = psycopg2.pool.ThreadedConnectionPool(minconn=minconn, maxconn=maxconn, **cfg)
            logger.info(
                "Database pool initialised (min=%d, max=%d, db=%s)",
                minconn,
                maxconn,
                cfg.get("dbname", "?"),
            )
        return _pool


def get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    return _pool if _pool is not None else init_pool()


def _is_alive(conn: psycopg2.extensions.connection) -> bool:
    """Is a pooled connection still usable? A connection can be closed server-side while idle
    in the pool (DB restart, idle timeout, network blip) without psycopg2 noticing, so test it
    before handing it out — otherwise the borrower's first query fails and callers that wrap DB
    errors mis-report it (e.g. "attacker_profiles table not found")."""
    if conn.closed:
        return False
    try:
        conn.rollback()  # clear any aborted-transaction state left on the pooled connection
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        conn.rollback()  # do not leave it idle-in-transaction
        return True
    except psycopg2.Error:
        return False


def _borrow_valid(pool: psycopg2.pool.ThreadedConnectionPool) -> psycopg2.extensions.connection:
    """getconn() a connection that is actually alive, discarding dead ones (bounded)."""
    conn = pool.getconn()
    for _ in range(3):
        if _is_alive(conn):
            return conn
        try:
            pool.putconn(conn, close=True)  # drop the dead one from the pool
        except (psycopg2.Error, KeyError):
            pass
        conn = pool.getconn()
    return conn  # last resort: hand it back and let the real query surface the error


class _ConnectionLease:
    """One checkout of a raw connection; close returns it exactly once.

    Lease state belongs to this checkout, never to the reusable psycopg2 object.
    This also keeps legacy callers using close() compatible with pooling.
    """

    def __init__(self, pool: psycopg2.pool.ThreadedConnectionPool) -> None:
        object.__setattr__(self, "_pool", pool)
        object.__setattr__(self, "_conn", _borrow_valid(pool))
        object.__setattr__(self, "_released", False)
        object.__setattr__(self, "_lock", threading.Lock())

    @property
    def closed(self) -> bool:
        return self._released or bool(self._conn.closed)

    def __getattr__(self, name: str) -> Any:
        if self._released:
            raise psycopg2.InterfaceError("connection lease already closed")
        return getattr(self._conn, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if self._released:
            raise psycopg2.InterfaceError("connection lease already closed")
        setattr(self._conn, name, value)

    def __enter__(self) -> "_ConnectionLease":
        if self.closed:
            raise psycopg2.InterfaceError("connection lease already closed")
        self._conn.__enter__()
        return self

    def __exit__(self, *args: Any) -> Any:
        if self._released:
            raise psycopg2.InterfaceError("connection lease already closed")
        return self._conn.__exit__(*args)

    def close(self) -> None:
        with self._lock:
            if self._released:
                return
            object.__setattr__(self, "_released", True)
            conn = self._conn
            discard = bool(conn.closed)
            if not discard:
                try:
                    conn.rollback()
                    # Match a fresh legacy connection: release advisory locks,
                    # temporary objects and session settings before reuse.
                    conn.autocommit = True
                    with conn.cursor() as cur:
                        cur.execute("DISCARD ALL")
                    conn.autocommit = False
                    # DISCARD ALL resets SERVER-side state. `cursor_factory` lives on the
                    # client-side connection object, so it survives both DISCARD ALL and the
                    # return to the pool — and then every later borrower of this connection
                    # silently gets that factory. Four callers set
                    # `conn.cursor_factory = RealDictCursor` on a POOLED connection
                    # (blog_publisher, blog_diag, hunt_cleanup, hunt_rebuild); once any of them
                    # ran, unrelated code doing the normal `cur.fetchone()[0]` got a
                    # RealDictRow and died with `KeyError: 0`. There are ~107 such call sites,
                    # so the blast radius was most of the app, intermittent and dependent on
                    # which connection you happened to draw: the same endpoint returned 500 and
                    # then 200 OK minutes later. Observed 2026-10-18 on the hunting dashboard,
                    # /events and the attack knowledge base. None is psycopg2's default, i.e.
                    # the plain tuple cursor.
                    conn.cursor_factory = None
                except psycopg2.Error as exc:
                    logger.debug("connection reset failed: %s", exc)
                    discard = True
            try:
                self._pool.putconn(conn, close=discard)
            except (psycopg2.Error, AttributeError) as exc:
                logger.debug("putconn failed (%s) — closing connection directly", exc)
                conn.close()


def get_db() -> psycopg2.extensions.connection:
    """A pooled connection lease; close() or return_db() releases the checkout."""
    return cast(psycopg2.extensions.connection, _ConnectionLease(get_pool()))


def return_db(conn: psycopg2.extensions.connection | None) -> None:
    """Release a lease; tolerate an already closed or external legacy connection."""
    if conn is not None:
        conn.close()


def close_pool() -> None:
    """Close every pooled connection. Called on process shutdown."""
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.closeall()
            _pool = None
            logger.info("Database pool closed")


class db_cursor:
    """Pooled cursor: commit on clean exit, rollback on exception, always returned to the pool.

    ``dict_cursor=True`` gives a ``RealDictCursor``; ``autocommit=True`` switches the
    connection for the duration of the context and restores the previous mode before
    returning it to the pool.
    """

    def __init__(self, dict_cursor: bool = False, autocommit: bool = False) -> None:
        self._conn: psycopg2.extensions.connection | None = None
        self._dict_cursor = dict_cursor
        self._autocommit = autocommit

    def __enter__(self) -> psycopg2.extensions.cursor:
        self._conn = get_db()
        if self._autocommit:
            self._conn.autocommit = True
        if self._dict_cursor:
            return self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return self._conn.cursor()

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> Literal[False]:
        conn = self._conn
        if conn is None:
            return False
        try:
            if exc_type is not None:
                conn.rollback()
            elif not self._autocommit:
                conn.commit()
        except psycopg2.Error as exc:
            # The connection may have died mid-way; the original exception (if any) will
            # propagate out of the with block anyway, and this is only transaction cleanup.
            logger.debug("commit/rollback on exit failed: %s", exc)
        finally:
            if self._autocommit:
                try:
                    conn.autocommit = False
                except psycopg2.Error as exc:
                    logger.debug("autocommit reset failed: %s", exc)
            return_db(conn)
            self._conn = None
        return False


_SCHEMA_KEYS = (
    "has_attack_types",
    "has_attack_patterns",
    "has_ics_events",
    "has_ja4_fingerprints",
    "has_ja4_database",
    "has_ai_analysis",
    "has_attacker_profiles",
    "has_user_sessions",
    "has_credential_vault",
)
_schema_cache: dict[str, bool] = {}
_schema_lock = threading.Lock()


def detect_schema() -> dict[str, bool]:
    """Detect optional columns and tables once, remember for the lifetime of the process.

    On a database error returns everything ``False`` and does **not** cache — the next
    call tries again.
    """
    with _schema_lock:
        if _schema_cache:
            return dict(_schema_cache)

    try:
        with db_cursor() as cur:
            cur.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'sensor_events'"
            )
            se_cols = {row[0] for row in cur.fetchall()}
            cur.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            )
            tables = {row[0] for row in cur.fetchall()}
    except psycopg2.Error as exc:
        logger.warning("Schema detection failed: %s", exc)
        return dict.fromkeys(_SCHEMA_KEYS, False)

    result = {
        "has_attack_types": "attack_types" in se_cols,
        "has_attack_patterns": "attack_patterns" in tables,
        "has_ics_events": "ics_events" in tables,
        "has_ja4_fingerprints": "ja4_fingerprints" in tables,
        "has_ja4_database": "ja4_database" in tables,
        "has_ai_analysis": "ai_analysis" in tables,
        "has_attacker_profiles": "attacker_profiles" in tables,
        "has_user_sessions": "user_sessions" in tables,
        "has_credential_vault": "credential_vault" in tables,
    }
    with _schema_lock:
        _schema_cache.update(result)
    logger.info("Schema detected: %s", ", ".join(k for k, v in result.items() if v))
    return result


def reset_schema_cache() -> None:
    """Clear the schema cache, e.g. after migrations."""
    with _schema_lock:
        _schema_cache.clear()


def legacy_get_db() -> psycopg2.extensions.connection:
    """Return a pooled connection from the process-wide ThreadedConnectionPool.

    In 0.9 and early 1.0, this spawned an unpooled ``psycopg2.connect()`` call on every invocation.
    Now it uses the process-wide pool for high performance, scalability, and connection reuse.
    """
    return get_db()
