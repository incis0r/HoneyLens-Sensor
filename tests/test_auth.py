"""Coverage for honeylens.auth.auth — password hashing (Argon2id + PBKDF2 fallback),
strength validation, and the account-lockout counters (todo C5).

The crypto and validation are pure; the three lockout/audit helpers touch the database, so
db_cursor is mocked — no real database.
"""

from __future__ import annotations

import contextlib

import pytest

from honeylens.auth import auth

# --- salt + hashing --------------------------------------------------------------------


def test_generate_salt_is_unique_256_bit_hex():
    a, b = auth.generate_salt(), auth.generate_salt()
    assert a != b
    assert len(a) == 64 and all(c in "0123456789abcdef" for c in a)


def test_hash_and_verify_roundtrip_argon2():
    h, salt = auth.hash_password("Correct-Horse-9!")
    assert salt and h.startswith("$argon2id$")  # argon2 is installed in the venv
    assert auth.verify_password("Correct-Horse-9!", h, salt) is True
    assert auth.verify_password("wrong", h, salt) is False
    assert auth.verify_password("Correct-Horse-9!", h, "different-salt") is False


def test_hash_uses_given_salt_and_is_randomised():
    salt = auth.generate_salt()
    h1, s1 = auth.hash_password("pw", salt=salt)
    h2, s2 = auth.hash_password("pw", salt=salt)
    assert s1 == s2 == salt
    assert h1 != h2  # argon2 embeds a random internal salt, so hashes differ


def test_verify_rejects_garbage_hash():
    assert auth.verify_password("x", "not-a-real-hash", "salt") is False


def test_pbkdf2_fallback_roundtrip(monkeypatch):
    monkeypatch.setattr(auth, "_HAS_ARGON2", False)
    h, salt = auth.hash_password("Correct-Horse-9!")
    assert len(h) == 64  # sha256 hex digest
    assert auth.verify_password("Correct-Horse-9!", h, salt) is True
    assert auth.verify_password("nope", h, salt) is False


def test_needs_rehash():
    h, _ = auth.hash_password("pw")
    assert auth.needs_rehash(h) is False  # fresh hash at current params
    assert auth.needs_rehash("garbage") is False  # bad input -> False, not raise


# --- password validation ---------------------------------------------------------------


def test_validate_password_accepts_a_strong_password():
    assert auth.validate_password("Tr0ub4dour&3xplore") == (True, None)


@pytest.mark.parametrize(
    "pw,needle",
    [
        ("Ab1!", "at least"),  # too short
        ("alllowercase1!x", "uppercase"),
        ("ALLUPPERCASE1!X", "lowercase"),
        ("NoDigitsHere!!xx", "digit"),
        ("NoSpecialChar1xx", "special"),
        ("Passsss1!wordxxx", "weak"),  # 4+ repeated chars
        ("Password123!xxxx", "weak"),  # sequential digits 123
        ("Passwordabc1!xxx", "weak"),  # sequential letters abc
    ],
)
def test_validate_password_rejects_weak(pw, needle):
    ok, msg = auth.validate_password(pw)
    assert ok is False and needle in msg


def test_generated_password_meets_the_shape():
    pw = auth.generate_secure_password(20)
    assert len(pw) == 20
    assert any(c.islower() for c in pw)
    assert any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw)
    assert any(c in "!@#$%^&*()-_=+" for c in pw)


# --- lockout / audit (DB mocked) --------------------------------------------------------


class _Cur:
    def __init__(self, fetchone=None):
        self._fetchone = fetchone
        self.calls: list = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchone(self):
        return self._fetchone


def _patch_cursor(monkeypatch, cur):
    @contextlib.contextmanager
    def _ctx():
        yield cur

    monkeypatch.setattr(auth, "db_cursor", _ctx)


def test_record_failed_login_passes_lockout_params(monkeypatch, caplog):
    cur = _Cur(fetchone=(auth.MAX_FAILED_ATTEMPTS,))  # threshold reached -> locks
    _patch_cursor(monkeypatch, cur)
    with caplog.at_level("WARNING"):
        auth.record_failed_login(42)
    _sql, params = cur.calls[0]
    assert params == (auth.MAX_FAILED_ATTEMPTS, auth.LOCKOUT_DURATION_MINUTES, 42)
    assert "locked" in caplog.text.lower()


def test_record_failed_login_swallows_db_errors(monkeypatch):
    def _boom():
        raise RuntimeError("db down")

    monkeypatch.setattr(auth, "db_cursor", _boom)
    auth.record_failed_login(1)  # must not raise


def test_clear_failed_attempts(monkeypatch):
    cur = _Cur()
    _patch_cursor(monkeypatch, cur)
    auth.clear_failed_attempts(7)
    assert cur.calls and cur.calls[0][1] == (7,)


def test_log_admin_action_serialises_details(monkeypatch):
    cur = _Cur()
    _patch_cursor(monkeypatch, cur)
    auth.log_admin_action(
        1, "reset_password", target_user_id=2, details={"k": "v"}, ip_address="192.0.2.9"
    )
    _sql, params = cur.calls[0]
    assert params[0] == 1 and params[1] == "reset_password" and params[2] == 2
    assert params[3] == '{"k": "v"}' and params[4] == "192.0.2.9"
