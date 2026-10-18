"""Coverage for honeylens.auth.user_manager — validators, the User model, and the
authenticate/change-password core (todo C5).

The DB and the helper modules (verify_password, lockout counters, LDAP, sessions) are
mocked, so these pin the input validation and the security-critical decision logic without a
database.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from honeylens.auth import user_manager as um

# --- validators -------------------------------------------------------------------------


def test_sanitize_html_escapes():
    assert um.sanitize_html('<a href="x">') == "&lt;a href=&quot;x&quot;&gt;"
    assert um.sanitize_html(None) == ""


@pytest.mark.parametrize(
    "name,ok",
    [
        ("", True),  # empty allowed
        ("Jean-Luc", True),  # letters, space, hyphen
        ("x" * 129, False),  # too long
        ("<script>", False),  # dangerous
        ("a&b", False),
        # NOTE: an apostrophe is rejected by the dangerous-patterns list even though the final
        # charset pattern permits it — pinning the current (stricter) behaviour, not the docstring.
        ("O'Brien", False),
        ("Ælfric 123", False),  # digits/charset not allowed by pattern
    ],
)
def test_validate_name(name, ok):
    assert um.validate_name(name)[0] is ok


@pytest.mark.parametrize(
    "username,ok",
    [("alice", True), ("ab", False), ("x" * 65, False), ("bad-name", False), ("", False)],
)
def test_validate_username(username, ok):
    assert um.validate_username(username)[0] is ok


@pytest.mark.parametrize(
    "email,ok",
    [("a@b.com", True), ("", False), ("nope", False), ("a@" + "x" * 256 + ".com", False)],
)
def test_validate_email(email, ok):
    assert um.validate_email(email)[0] is ok


# --- User model -------------------------------------------------------------------------


def _make_user(**over):
    base = dict(
        id=1,
        username="alice",
        name="Alice",
        lastname="Example",
        email="a@x",
        password_hash="h",
        salt="s",
        role=um.UserRole.ADMIN,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        last_login=None,
        is_active=True,
        failed_attempts=0,
        locked_until=None,
    )
    base.update(over)
    return um.User(**base)


def test_user_properties():
    u = _make_user()
    assert u.is_admin is True and u.full_name == "Alice Example"
    assert u.is_locked is False  # no locked_until
    assert _make_user(locked_until=datetime.now(UTC) + timedelta(minutes=5)).is_locked is True
    assert _make_user(locked_until=datetime.now(UTC) - timedelta(minutes=5)).is_locked is False
    # naive timestamp is treated as UTC, not crash
    assert _make_user(locked_until=datetime.now() + timedelta(minutes=5)).is_locked is True


def test_user_to_dict_and_from_row():
    u = _make_user()
    d = u.to_dict()
    assert d["role"] == "admin" and "password_hash" not in d
    assert u.to_dict(include_sensitive=True)["failed_attempts"] == 0
    row = {
        "id": 2,
        "username": "bob",
        "name": None,
        "lastname": None,
        "email": "b@x",
        "password_hash": "h",
        "salt": "s",
        "role": "user",
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
        "is_active": True,
    }
    u2 = um.User.from_row(row)
    assert u2.role is um.UserRole.USER and u2.name == "" and u2.failed_attempts == 0


# --- authenticate_user ------------------------------------------------------------------


def _wire_auth(monkeypatch, *, user, verify, ldap_on=False):
    monkeypatch.setattr(um, "get_user_by_username", lambda n: user)
    monkeypatch.setattr(um, "verify_password", lambda pw, h, s: verify)
    monkeypatch.setattr(um, "record_failed_login", lambda uid: rec.append(uid))
    monkeypatch.setattr(um, "clear_failed_attempts", lambda uid: cleared.append(uid))
    monkeypatch.setattr(um, "ldap_enabled", lambda: ldap_on)


rec: list = []
cleared: list = []


def test_authenticate_local_success(monkeypatch):
    rec.clear()
    cleared.clear()
    u = _make_user()
    _wire_auth(monkeypatch, user=u, verify=True)
    assert um.authenticate_user("alice", "pw") is u
    assert cleared == [1] and rec == []  # cleared failures, recorded none


def test_authenticate_wrong_password_records_failure(monkeypatch):
    rec.clear()
    _wire_auth(monkeypatch, user=_make_user(), verify=False)
    assert um.authenticate_user("alice", "bad") is None
    assert rec == [1]


def test_authenticate_unknown_user(monkeypatch):
    _wire_auth(monkeypatch, user=None, verify=True)
    assert um.authenticate_user("ghost", "pw") is None


def test_authenticate_inactive_and_locked(monkeypatch):
    _wire_auth(monkeypatch, user=_make_user(is_active=False), verify=True)
    assert um.authenticate_user("alice", "pw") is None
    _wire_auth(
        monkeypatch,
        user=_make_user(locked_until=datetime.now(UTC) + timedelta(minutes=10)),
        verify=True,
    )
    assert um.authenticate_user("alice", "pw") is None


def test_authenticate_ldap_path(monkeypatch):
    mirrored = _make_user(username="aduser")
    monkeypatch.setattr(um, "ldap_enabled", lambda: True)
    monkeypatch.setattr(um, "ldap_authenticate", lambda u, p: {"email": "a@x", "role": "admin"})
    monkeypatch.setattr(um, "_mirror_ldap_user", lambda info: mirrored)
    assert um.authenticate_user("a@x", "pw") is mirrored
    monkeypatch.setattr(um, "ldap_authenticate", lambda u, p: None)  # AD rejected
    assert um.authenticate_user("a@x", "pw") is None


# --- change_password --------------------------------------------------------------------


class _Cur:
    def execute(self, sql, params=None):
        pass


class _Conn:
    def cursor(self):
        return _Cur()

    def commit(self):
        pass

    def close(self):
        pass


def _wire_change(monkeypatch, *, user, verify_fn, revoked):
    monkeypatch.setattr(um, "get_user_by_id", lambda uid: user)
    monkeypatch.setattr(um, "verify_password", verify_fn)
    monkeypatch.setattr(um, "get_db", lambda: _Conn())
    import honeylens.auth.session_manager as smod

    monkeypatch.setattr(smod, "revoke_all_user_sessions", lambda uid, reason: revoked.append(uid))


def test_change_password_success_revokes_sessions(monkeypatch):
    revoked: list = []
    # current password verifies True, the new one verifies False (so "must differ" passes)
    _wire_change(
        monkeypatch,
        user=_make_user(),
        verify_fn=lambda pw, h, s: pw == "OldPassw0rd!xx",
        revoked=revoked,
    )
    ok, err = um.change_password(1, "OldPassw0rd!xx", "BrandN3w-Pass!q")
    assert ok is True and err is None
    assert revoked == [1]  # all sessions killed on password change


def test_change_password_rejections(monkeypatch):
    revoked: list = []
    # user not found
    _wire_change(monkeypatch, user=None, verify_fn=lambda *a: True, revoked=revoked)
    assert um.change_password(1, "x", "y")[0] is False
    # wrong current password
    _wire_change(monkeypatch, user=_make_user(), verify_fn=lambda *a: False, revoked=revoked)
    assert um.change_password(1, "wrong", "BrandN3w-Pass!q") == (
        False,
        "Current password is incorrect",
    )
    # new password fails strength validation (always verifies current True)
    _wire_change(monkeypatch, user=_make_user(), verify_fn=lambda *a: True, revoked=revoked)
    ok, err = um.change_password(1, "cur", "weak")
    assert ok is False and err and "at least" in err
    # new password identical to current (verify_password returns True for both)
    _wire_change(monkeypatch, user=_make_user(), verify_fn=lambda *a: True, revoked=revoked)
    ok, err = um.change_password(1, "Str0ng-Current!x", "Str0ng-Current!x")
    assert ok is False and "different" in err


# --- create_user / get_user_by_* (DB mocked) -------------------------------------------


class _SeqCur:
    """Cursor whose fetchone() yields a preset sequence (existing-check, then RETURNING row);
    fetchall() returns a fixed list."""

    def __init__(self, fetchones, fetchall=None):
        self._fo = list(fetchones)
        self._fa = fetchall if fetchall is not None else []

    def execute(self, sql, params=None):
        pass

    def fetchone(self):
        return self._fo.pop(0) if self._fo else None

    def fetchall(self):
        return self._fa


class _SeqConn:
    def __init__(self, fetchones, fetchall=None):
        self._cur = _SeqCur(fetchones, fetchall)

    def cursor(self, cursor_factory=None):
        return self._cur

    def commit(self):
        pass

    def close(self):
        pass


def _row(**over):
    base = {
        "id": 5,
        "username": "newbie",
        "name": "New",
        "lastname": "Bie",
        "email": "new@x",
        "password_hash": "h",
        "salt": "s",
        "role": "user",
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
        "is_active": True,
    }
    base.update(over)
    return base


def test_create_user_validation_rejections(monkeypatch):
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([]))  # never reached for these
    assert (
        um.create_user("u", "e@x", "pw", role="root")[1]
        == "Invalid role. Must be 'admin' or 'user'"
    )
    assert um.create_user("u", "e@x", "weak")[0] is None  # weak password
    assert um.create_user("ab", "e@x", "BrandN3w-Pass!q")[0] is None  # username too short
    assert um.create_user("alice", "bad-email", "BrandN3w-Pass!q")[0] is None


def test_create_user_duplicate(monkeypatch):
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([{"id": 1}]))  # existing row -> duplicate
    user, err = um.create_user("alice", "alice@example.com", "BrandN3w-Pass!q")
    assert user is None and "already exists" in err


def test_create_user_success(monkeypatch):
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([None, _row()]))  # no dup, then RETURNING
    user, err = um.create_user("newbie", "new@example.com", "BrandN3w-Pass!q", role="user")
    assert (
        err is None and user.id == 5 and user.username == "newbie" and user.role is um.UserRole.USER
    )


def test_get_user_by_username_and_id(monkeypatch):
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([_row(username="alice")]))
    assert um.get_user_by_username("alice").username == "alice"
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([None]))
    assert um.get_user_by_username("ghost") is None
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([_row(id=9)]))
    assert um.get_user_by_id(9).id == 9


def test_get_user_by_email(monkeypatch):
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([_row(email="a@x.com")]))
    assert um.get_user_by_email("a@x.com").email == "a@x.com"


def test_list_users(monkeypatch):
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([], fetchall=[_row(), _row(id=6)]))
    out = um.list_users(include_inactive=True)
    assert [u.id for u in out] == [5, 6]
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([], fetchall=[]))
    assert um.list_users() == []


# --- update_user / delete_user / reset_password -----------------------------------------


def test_update_user_validation_and_no_fields(monkeypatch):
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([]))
    assert um.update_user(1, role="root")[1] == "Invalid role. Must be 'admin' or 'user'"
    assert um.update_user(1, email="bad")[0] is None
    assert um.update_user(1)[1] == "No fields to update"


def test_update_user_email_in_use_then_success(monkeypatch):
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([{"id": 2}]))  # email-uniqueness hit
    assert um.update_user(1, email="dupe@example.com")[1] == "Email already in use"
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([_row(name="Renamed")]))  # RETURNING
    user, err = um.update_user(1, name="Renamed")
    assert err is None and user.id == 5
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([None]))  # RETURNING empty -> not found
    assert um.update_user(999, name="x")[1] == "User not found"


def test_delete_user(monkeypatch):
    assert um.delete_user(3, deleted_by=3) == (False, "Cannot delete your own account")
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([None]))  # username lookup empty
    assert um.delete_user(3)[0] is False  # not found
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([("victim",)]))
    assert um.delete_user(3) == (True, None)


def _patch_revoke(monkeypatch):
    import honeylens.auth.session_manager as smod

    monkeypatch.setattr(smod, "revoke_all_user_sessions", lambda uid, reason: 0)


def test_reset_password(monkeypatch):
    _patch_revoke(monkeypatch)
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([("alice",)]))  # RETURNING username
    pw, err = um.reset_password(1)  # generated
    assert err is None and len(pw) == 16
    # a provided weak password is rejected before any DB work
    assert um.reset_password(1, new_password="weak")[0] is None
    # user not found
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([None]))
    assert um.reset_password(1, new_password="BrandN3w-Pass!q")[1] == "User not found"


# --- _mirror_ldap_user + get_audit_log --------------------------------------------------


def test_mirror_ldap_user_existing_and_new(monkeypatch):
    existing = _make_user(id=3, role=um.UserRole.USER, email="a@x")
    monkeypatch.setattr(um, "get_user_by_email", lambda e: existing)
    seen = {}
    monkeypatch.setattr(um, "update_user", lambda uid, role: seen.update(role=role))
    monkeypatch.setattr(um, "clear_failed_attempts", lambda uid: None)
    monkeypatch.setattr(um, "get_user_by_id", lambda uid: existing)
    out = um._mirror_ldap_user({"email": "a@x", "role": "admin"})  # role changed user->admin
    assert out is existing and seen["role"] == "admin"
    # inactive local account -> refuse AD login
    monkeypatch.setattr(um, "get_user_by_email", lambda e: _make_user(is_active=False))
    assert um._mirror_ldap_user({"email": "a@x", "role": "admin"}) is None
    # brand-new user -> create_user
    monkeypatch.setattr(um, "get_user_by_email", lambda e: None)
    created = _make_user(id=9, username="aduser")
    monkeypatch.setattr(um, "create_user", lambda **kw: (created, None))
    assert um._mirror_ldap_user({"email": "new@x", "role": "user", "username": "aduser"}) is created


def test_get_audit_log(monkeypatch):
    rows = [{"id": 1, "action": "reset_password", "admin_username": "root"}]
    monkeypatch.setattr(um, "get_db", lambda: _SeqConn([], fetchall=rows))
    assert um.get_audit_log(limit=10, admin_user_id=1, action="reset_password") == rows
