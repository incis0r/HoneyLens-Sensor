"""Coverage for honeylens.auth.session_manager — opaque-token sessions (todo C5).

Tokens are 512-bit random, stored as SHA-256; the DB is mocked (_get_db), so these pin the
token hashing, the create/validate/revoke lifecycle (valid, expired, idle, deactivated,
too-short), the concurrent-session cap, and the in-memory login rate limit.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from honeylens.auth import session_manager as sm


class _Cur:
    def __init__(self, fetchone=None, fetchall=None, rowcount=0):
        self._fetchone = fetchone
        self._fetchall = fetchall if fetchall is not None else []
        self.rowcount = rowcount
        self.calls: list = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchone(self):
        return self._fetchone

    def fetchall(self):
        return self._fetchall

    def close(self):
        pass


class _Conn:
    def __init__(self, cur):
        self._cur = cur
        self.committed = 0
        self.rolled = 0
        self.closed = False

    def cursor(self, cursor_factory=None):
        return self._cur

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled += 1

    def close(self):
        self.closed = True


def _patch_db(monkeypatch, cur):
    conn = _Conn(cur)
    monkeypatch.setattr(sm, "_get_db", lambda: conn)
    return conn


# --- pure -------------------------------------------------------------------------------


def test_hash_token_is_sha256_hex():
    h = sm._hash_token("abc")
    assert len(h) == 64 and h == sm._hash_token("abc") and h != sm._hash_token("abd")


def test_utcnow_is_tz_aware():
    assert sm._utcnow().tzinfo is not None


# --- create_session ---------------------------------------------------------------------


def test_create_session_returns_random_token_and_stores_its_hash(monkeypatch):
    cur = _Cur(fetchall=[])  # no existing sessions -> no eviction
    conn = _patch_db(monkeypatch, cur)
    token = sm.create_session(user_id=7, ip="192.0.2.5", user_agent="UA")
    assert len(token) == sm.TOKEN_BYTES * 2  # hex of 64 random bytes
    inserts = [c for c in cur.calls if "INSERT INTO user_sessions" in c[0]]
    assert inserts and inserts[0][1][0] == sm._hash_token(token)  # DB stores the hash, not raw
    assert conn.committed >= 1


# --- validate_session -------------------------------------------------------------------


def _row(**over):
    base = {
        "session_row_id": 11,
        "user_id": 7,
        "expires_at": datetime.now(UTC) + timedelta(hours=1),
        "last_active_at": datetime.now(UTC),
        "is_persistent": False,
        "revoked": False,
        "username": "alice",
        "name": "Alice",
        "lastname": "A",
        "email": "a@x",
        "role": "admin",
        "is_active": True,
    }
    base.update(over)
    return base


def test_validate_rejects_short_or_empty_token():
    assert sm.validate_session("") is None
    assert sm.validate_session("tooshort") is None  # < 32 chars, never hits the DB


def test_validate_valid_session_returns_user_and_slides_window(monkeypatch):
    cur = _Cur(fetchone=_row())
    _patch_db(monkeypatch, cur)
    user = sm.validate_session("x" * 40)
    assert user["id"] == 7 and user["username"] == "alice"
    assert user["is_admin"] is True and user["auth_method"] == "session"
    assert any("UPDATE user_sessions SET last_active_at" in c[0] for c in cur.calls)


def test_validate_missing_row_is_none(monkeypatch):
    _patch_db(monkeypatch, _Cur(fetchone=None))
    assert sm.validate_session("x" * 40) is None


def test_validate_expired_session_autorevokes(monkeypatch):
    cur = _Cur(fetchone=_row(expires_at=datetime.now(UTC) - timedelta(hours=1)))
    _patch_db(monkeypatch, cur)
    assert sm.validate_session("x" * 40) is None
    assert any("revoked_reason = 'expired'" in c[0] for c in cur.calls)


def test_validate_idle_timeout_revokes(monkeypatch):
    cur = _Cur(fetchone=_row(last_active_at=datetime.now(UTC) - timedelta(days=30)))
    _patch_db(monkeypatch, cur)
    assert sm.validate_session("x" * 40) is None
    assert any("revoked_reason = 'idle_timeout'" in c[0] for c in cur.calls)


def test_validate_deactivated_user_revokes(monkeypatch):
    cur = _Cur(fetchone=_row(is_active=False))
    _patch_db(monkeypatch, cur)
    assert sm.validate_session("x" * 40) is None
    assert any("revoked_reason = 'user_deactivated'" in c[0] for c in cur.calls)


# --- revoke -----------------------------------------------------------------------------


def test_revoke_session(monkeypatch):
    assert sm.revoke_session("") is False  # no token, no DB
    cur = _Cur(rowcount=1)
    _patch_db(monkeypatch, cur)
    assert sm.revoke_session("x" * 40, reason="logout") is True
    cur2 = _Cur(rowcount=0)
    _patch_db(monkeypatch, cur2)
    assert sm.revoke_session("x" * 40) is False  # nothing matched


# --- concurrent-session limit -----------------------------------------------------------


def test_enforce_session_limit_revokes_oldest_over_cap():
    over = sm.MAX_SESSIONS_PER_USER + 2
    cur = _Cur(fetchall=[(i,) for i in range(over)])  # id tuples, oldest first
    sm._enforce_session_limit(cur, user_id=7)
    revokes = [c for c in cur.calls if "revoked_reason = 'session_limit'" in c[0]]
    # excess = over - MAX + 1
    assert len(revokes) == over - sm.MAX_SESSIONS_PER_USER + 1
    assert revokes[0][1][1] == 0  # the oldest id was revoked first


# --- login rate limit (in-memory) -------------------------------------------------------


def test_login_rate_limit(monkeypatch):
    monkeypatch.setattr(sm, "_login_attempts", {})
    ip = "192.0.2.50"
    assert sm.check_login_rate_limit(ip) is False  # clean
    for _ in range(sm.LOGIN_RATE_LIMIT):
        sm.record_login_attempt(ip)
    assert sm.check_login_rate_limit(ip) is True  # hit the cap


def test_login_rate_limit_prunes_old_attempts(monkeypatch):
    ip = "192.0.2.51"
    old = datetime.now(UTC) - timedelta(seconds=sm.LOGIN_RATE_WINDOW_SEC + 10)
    monkeypatch.setattr(sm, "_login_attempts", {ip: [old] * (sm.LOGIN_RATE_LIMIT + 3)})
    assert sm.check_login_rate_limit(ip) is False  # all stale -> pruned -> not limited


# --- the remaining CRUD / housekeeping --------------------------------------------------


def test_revoke_all_user_sessions_returns_count(monkeypatch):
    cur = _Cur(rowcount=3)
    _patch_db(monkeypatch, cur)
    assert sm.revoke_all_user_sessions(7, reason="password_change") == 3


def test_revoke_session_by_id(monkeypatch):
    _patch_db(monkeypatch, _Cur(rowcount=1))
    assert sm.revoke_session_by_id(11) is True
    _patch_db(monkeypatch, _Cur(rowcount=0))
    assert sm.revoke_session_by_id(99) is False


def test_get_active_sessions_maps_rows(monkeypatch):
    rows = [{"id": 1, "user_id": 7, "ip_address": "192.0.2.5"}]
    _patch_db(monkeypatch, _Cur(fetchall=rows))
    out = sm.get_active_sessions(7)
    assert out == rows and out is not rows  # dict-copied


def test_get_all_active_sessions_maps_rows(monkeypatch):
    rows = [{"id": 1, "user_id": 7, "username": "alice", "role": "admin"}]
    _patch_db(monkeypatch, _Cur(fetchall=rows))
    assert sm.get_all_active_sessions() == rows


def test_cleanup_expired_counts(monkeypatch):
    _patch_db(monkeypatch, _Cur(rowcount=4))
    assert sm.cleanup_expired() == {"auto_revoked": 4, "deleted": 4}


class _BoomCur(_Cur):
    def execute(self, sql, params=None):
        raise RuntimeError("exec failed")


def test_crud_swallows_cursor_errors(monkeypatch):
    # The try/except wraps the cursor work (not _get_db), so an execute failure is the realistic
    # fault: each function returns its safe default instead of raising.
    _patch_db(monkeypatch, _BoomCur())
    assert sm.revoke_all_user_sessions(1) == 0
    _patch_db(monkeypatch, _BoomCur())
    assert sm.get_active_sessions(1) == []
    _patch_db(monkeypatch, _BoomCur())
    assert sm.get_all_active_sessions() == []
    _patch_db(monkeypatch, _BoomCur())
    assert sm.revoke_session_by_id(1) is False
    _patch_db(monkeypatch, _BoomCur())
    assert sm.cleanup_expired() == {"auto_revoked": 0, "deleted": 0}
