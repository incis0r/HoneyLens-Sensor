"""Coverage for honeylens.auth.admin_routes — the admin authz dependencies and the
user-management endpoints (todo C5).

FastAPI endpoints are plain async functions, so they're called directly with a fake Request
and an explicit admin user (bypassing Depends); the user_manager layer is mocked. Focus is
the security-relevant authorization (get_current_user / require_admin) and the endpoint
error->HTTP mapping, not the HTML panel.
"""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from honeylens.auth import admin_routes as ar
from honeylens.auth.user_manager import User, UserRole


def _user(role=UserRole.ADMIN, is_active=True, locked_until=None, uid=1):
    return User(
        id=uid,
        username="admin",
        name="A",
        lastname="D",
        email="a@x",
        password_hash="h",
        salt="s",
        role=role,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        last_login=None,
        is_active=is_active,
        failed_attempts=0,
        locked_until=locked_until,
    )


def _req(*, user=None, is_admin=None, auth=None, client_host="192.0.2.1"):
    state = SimpleNamespace()
    if user is not None:
        state.user = user
    if is_admin is not None:
        state.is_admin = is_admin
    return SimpleNamespace(
        state=state,
        headers={"Authorization": auth} if auth else {},
        client=SimpleNamespace(host=client_host) if client_host else None,
    )


def _run(coro):
    return asyncio.run(coro)


# --- get_current_user -------------------------------------------------------------------


def test_get_current_user_from_state():
    u = _user()
    assert _run(ar.get_current_user(_req(user=u))) is u


def test_get_current_user_state_inactive_or_locked():
    with pytest.raises(HTTPException) as e1:
        _run(ar.get_current_user(_req(user=_user(is_active=False))))
    assert e1.value.status_code == 403
    locked = _user(locked_until=datetime(2999, 1, 1, tzinfo=UTC))
    with pytest.raises(HTTPException) as e2:
        _run(ar.get_current_user(_req(user=locked)))
    assert e2.value.status_code == 403


def test_get_current_user_no_auth_is_401():
    with pytest.raises(HTTPException) as e:
        _run(ar.get_current_user(_req()))
    assert e.value.status_code == 401


def test_get_current_user_basic_auth(monkeypatch):
    u = _user()
    monkeypatch.setattr(ar, "authenticate_user", lambda un, pw: u)
    tok = base64.b64encode(b"admin:pw").decode()
    assert _run(ar.get_current_user(_req(auth=f"Basic {tok}"))) is u
    # bad credentials
    monkeypatch.setattr(ar, "authenticate_user", lambda un, pw: None)
    with pytest.raises(HTTPException) as e:
        _run(ar.get_current_user(_req(auth=f"Basic {tok}")))
    assert e.value.status_code == 401
    # malformed base64
    with pytest.raises(HTTPException) as e2:
        _run(ar.get_current_user(_req(auth="Basic !!!notb64")))
    assert e2.value.status_code == 401


# --- require_admin ----------------------------------------------------------------------


def test_require_admin_legacy_paths():
    u = _user()
    assert _run(ar.require_admin(_req(user=u, is_admin=True))) is u  # admin via state
    with pytest.raises(HTTPException) as e:
        _run(ar.require_admin(_req(user=_user(role=UserRole.USER), is_admin=True)))
    assert e.value.status_code == 403
    assert _run(ar.require_admin(_req(is_admin=True))) is None  # legacy config auth, no user


def test_require_admin_db_path():
    assert _run(ar.require_admin(_req(user=_user()))).is_admin is True
    with pytest.raises(HTTPException) as e:
        _run(ar.require_admin(_req(user=_user(role=UserRole.USER))))
    assert e.value.status_code == 403


# --- user-management endpoints ----------------------------------------------------------


def test_create_new_user_success_and_error(monkeypatch):
    u = _user(uid=5)
    monkeypatch.setattr(ar, "create_user", lambda **kw: (u, None))
    data = ar.CreateUserRequest(username="newbie", email="n@x.com", password="BrandN3w-Pass!q")
    out = _run(ar.create_new_user(request=_req(), data=data, admin=_user()))
    assert out["message"] == "User created successfully" and out["user"]["id"] == 5
    monkeypatch.setattr(ar, "create_user", lambda **kw: (None, "Username or email already exists"))
    with pytest.raises(HTTPException) as e:
        _run(ar.create_new_user(request=_req(), data=data, admin=_user()))
    assert e.value.status_code == 400 and "already exists" in e.value.detail


def test_get_user_endpoint(monkeypatch):
    monkeypatch.setattr(ar, "get_user_by_id", lambda uid: _user(uid=uid))
    assert _run(ar.get_user(7, admin=_user()))["user"]["id"] == 7
    monkeypatch.setattr(ar, "get_user_by_id", lambda uid: None)
    with pytest.raises(HTTPException) as e:
        _run(ar.get_user(7, admin=_user()))
    assert e.value.status_code == 404


def test_update_and_delete_and_reset(monkeypatch):
    monkeypatch.setattr(ar, "update_user", lambda **kw: (_user(uid=3), None))
    out = _run(
        ar.update_user_endpoint(
            3, request=_req(), data=ar.UpdateUserRequest(name="X"), admin=_user()
        )
    )
    assert out["message"] == "User updated successfully"
    monkeypatch.setattr(ar, "update_user", lambda **kw: (None, "Email already in use"))
    with pytest.raises(HTTPException) as e:
        _run(
            ar.update_user_endpoint(
                3, request=_req(), data=ar.UpdateUserRequest(email="d@x.com"), admin=_user()
            )
        )
    assert e.value.status_code == 400

    monkeypatch.setattr(ar, "delete_user", lambda **kw: (True, None))
    assert _run(ar.delete_user_endpoint(3, request=_req(), admin=_user()))["message"]
    monkeypatch.setattr(ar, "delete_user", lambda **kw: (False, "Cannot delete your own account"))
    with pytest.raises(HTTPException) as e2:
        _run(ar.delete_user_endpoint(3, request=_req(), admin=_user()))
    assert e2.value.status_code == 400

    monkeypatch.setattr(ar, "reset_password", lambda **kw: ("Gen3rated-Pass!x", None))
    assert _run(ar.reset_user_password(3, request=_req(), admin=_user()))["new_password"]
    monkeypatch.setattr(ar, "reset_password", lambda **kw: (None, "User not found"))
    with pytest.raises(HTTPException) as e3:
        _run(ar.reset_user_password(3, request=_req(), admin=_user()))
    assert e3.value.status_code == 400


def test_list_and_audit_endpoints(monkeypatch):
    monkeypatch.setattr(
        ar, "list_users", lambda include_inactive=False: [_user(uid=1), _user(uid=2)]
    )
    assert len(_run(ar.list_all_users(user=_user()))["users"]) == 2
    monkeypatch.setattr(ar, "get_audit_log", lambda limit=100: [{"id": 1, "action": "x"}])
    assert _run(ar.get_audit_log_endpoint(limit=5, admin=_user()))["entries"] == [
        {"id": 1, "action": "x"}
    ]
