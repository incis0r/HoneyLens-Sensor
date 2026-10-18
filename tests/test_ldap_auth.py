"""Coverage for honeylens.auth.ldap_auth — the optional LDAP/AD backend (todo C5).

ldap3 is installed in the venv but we never touch a directory: _server and Connection are
mocked, so these tests pin the pure logic (enable gate, RFC-4515 escaping, group->role
mapping) and the full ldap_authenticate flow (service bind -> search -> role -> password
bind) for success and every denial path. ldap_authenticate must never raise.
"""

from __future__ import annotations

from honeylens.auth import ldap_auth as la

# --- pure helpers ----------------------------------------------------------------------


def test_ldap_enabled_gate(monkeypatch):
    monkeypatch.delenv("LDAP_ENABLED", raising=False)
    assert la.ldap_enabled() is False
    monkeypatch.setenv("LDAP_ENABLED", "true")
    assert la.ldap_enabled() is True
    monkeypatch.setenv("LDAP_ENABLED", "off")
    assert la.ldap_enabled() is False


def test_escape_filter_rfc4515():
    assert la._escape_filter("a*b(c)d\\e") == "a\\2ab\\28c\\29d\\5ce"
    assert la._escape_filter("plain") == "plain"


def test_role_for_groups(monkeypatch):
    monkeypatch.setenv("LDAP_GROUP_ADMIN", "CN=admins,DC=x")
    monkeypatch.setenv("LDAP_GROUP_VIEWER", "CN=viewers,DC=x")
    monkeypatch.delenv("LDAP_DEFAULT_ROLE", raising=False)
    assert la._role_for_groups(["CN=admins,DC=x"]) == "admin"
    assert la._role_for_groups(["cn=viewers,dc=x"]) == "user"  # case-insensitive
    assert la._role_for_groups(["CN=other,DC=x"]) is None  # no mapped group -> deny
    monkeypatch.setenv("LDAP_DEFAULT_ROLE", "user")
    assert la._role_for_groups(["CN=other,DC=x"]) == "user"  # default applies


# --- ldap_authenticate: mocked directory ------------------------------------------------


class _A:
    def __init__(self, value):
        self.value = value


class _MemberOf:
    def __init__(self, values):
        self.values = values


class _Entry:
    def __init__(self, dn, member_of, attrs):
        self.entry_dn = dn
        self.memberOf = _MemberOf(member_of)
        self._has_mo = bool(member_of)
        for k, v in attrs.items():
            setattr(self, k, _A(v))

    def __contains__(self, key):
        return key == "memberOf" and self._has_mo


class _SvcConn:
    def __init__(self, entries):
        self.entries = entries

    def search(self, *a, **k):
        return True

    def unbind(self):
        pass


class _UserConn:
    def unbind(self):
        pass


_USER_DN = "CN=alice,DC=x"
_ENTRY = _Entry(
    _USER_DN,
    ["CN=admins,DC=x"],
    {
        "sAMAccountName": "alice",
        "userPrincipalName": "alice@example.com",
        "mail": "alice@example.com",
        "givenName": "Alice",
        "sn": "Example",
    },
)


def _wire(monkeypatch, *, entries, correct_pw):
    for k, v in {
        "LDAP_ENABLED": "true",
        "LDAP_BASE_DN": "DC=x",
        "LDAP_BIND_DN": "CN=svc,DC=x",
        "LDAP_BIND_PASSWORD": "svcpw",
        "LDAP_GROUP_ADMIN": "CN=admins,DC=x",
    }.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(la, "_server", lambda: object())

    def _conn(server, user=None, password=None, auto_bind=False, receive_timeout=None):
        if user == "CN=svc,DC=x":
            return _SvcConn(entries)
        if user == _USER_DN and password == correct_pw:
            return _UserConn()
        raise la.LDAPException("bad bind")

    monkeypatch.setattr(la, "Connection", _conn)


def test_authenticate_success_maps_admin(monkeypatch):
    _wire(monkeypatch, entries=[_ENTRY], correct_pw="s3cret")
    out = la.ldap_authenticate("alice@example.com", "s3cret")
    assert out == {
        "username": "alice",
        "email": "alice@example.com",
        "name": "Alice",
        "lastname": "Example",
        "role": "admin",
    }


def test_authenticate_bad_password_denied(monkeypatch):
    _wire(monkeypatch, entries=[_ENTRY], correct_pw="s3cret")
    assert la.ldap_authenticate("alice@example.com", "WRONG") is None


def test_authenticate_user_not_found(monkeypatch):
    _wire(monkeypatch, entries=[], correct_pw="s3cret")
    assert la.ldap_authenticate("ghost@example.com", "s3cret") is None


def test_authenticate_no_mapped_group_denied(monkeypatch):
    entry = _Entry(_USER_DN, ["CN=nobody,DC=x"], {"userPrincipalName": "alice@example.com"})
    _wire(monkeypatch, entries=[entry], correct_pw="s3cret")
    assert la.ldap_authenticate("alice@example.com", "s3cret") is None


def test_authenticate_disabled_or_empty_is_none(monkeypatch):
    monkeypatch.delenv("LDAP_ENABLED", raising=False)
    assert la.ldap_authenticate("a@b", "pw") is None  # disabled
    _wire(monkeypatch, entries=[_ENTRY], correct_pw="s3cret")
    assert la.ldap_authenticate("", "pw") is None  # empty login
    assert la.ldap_authenticate("a@b", "") is None  # empty password


def test_authenticate_never_raises_on_ldap_error(monkeypatch):
    _wire(monkeypatch, entries=[_ENTRY], correct_pw="s3cret")

    def _boom(*a, **k):
        raise la.LDAPException("service bind failed")

    monkeypatch.setattr(la, "Connection", _boom)
    assert la.ldap_authenticate("alice@example.com", "s3cret") is None


def test_authenticate_swallows_unexpected_error(monkeypatch):
    _wire(monkeypatch, entries=[_ENTRY], correct_pw="s3cret")
    monkeypatch.setattr(la, "_server", lambda: (_ for _ in ()).throw(ValueError("boom")))
    assert la.ldap_authenticate("alice@example.com", "s3cret") is None  # non-LDAP error -> None


# --- _server construction (TLS policy) --------------------------------------------------


def test_server_insecure_tls_warns(monkeypatch, caplog):
    monkeypatch.setenv("LDAP_SERVER", "ldaps://dc.example:636")
    monkeypatch.setenv("LDAP_ALLOW_INSECURE_TLS", "true")
    la._warned_no_ca = False
    with caplog.at_level("ERROR"):
        srv = la._server()
    assert srv is not None and "not validated" in caplog.text.lower()


def test_server_plain_ldap_builds_without_tls(monkeypatch):
    monkeypatch.setenv("LDAP_SERVER", "ldap://dc.example:389")
    assert la._server() is not None


# --- settings must come from the .env file, not only os.environ -------------------------
# Regression for a lockout on a live sensor: _env used os.environ.get directly, so every
# LDAP_* value placed in the sensor's .env - which is where the module docstring and the
# deployment both put them - was invisible. ldap_enabled() returned False with no error
# anywhere, AD logins silently fell through to the empty local users table, and the WebUI
# rejected every credential.


def test_env_values_are_read_from_the_env_file(tmp_path, monkeypatch):
    from honeylens import env as hl_env

    env_file = tmp_path / ".env"
    env_file.write_text(
        "LDAP_ENABLED=true\nLDAP_SERVER=ldaps://dc.example:636\nLDAP_BASE_DN=DC=example,DC=com\n"
    )
    env_file.chmod(0o600)

    # Nothing in the process environment - the file is the only source.
    for key in ("LDAP_ENABLED", "LDAP_SERVER", "LDAP_BASE_DN"):
        monkeypatch.delenv(key, raising=False)

    try:
        hl_env.reload([env_file])
        assert la._env("LDAP_ENABLED") == "true"
        assert la._env("LDAP_SERVER") == "ldaps://dc.example:636"
        assert la._env("LDAP_BASE_DN") == "DC=example,DC=com"
        assert la.ldap_enabled() is True
    finally:
        hl_env.reload()


def test_os_environ_still_works_and_env_file_wins(tmp_path, monkeypatch):
    from honeylens import env as hl_env

    env_file = tmp_path / ".env"
    env_file.write_text("LDAP_SERVER=ldaps://from-file:636\n")
    env_file.chmod(0o600)

    try:
        # os.environ alone is still honoured, for hosts that set it in the unit file.
        hl_env.reload([tmp_path / "absent.env"])
        monkeypatch.setenv("LDAP_SERVER", "ldaps://from-environ:636")
        assert la._env("LDAP_SERVER") == "ldaps://from-environ:636"

        # When both carry the key, the .env file is the more specific source and wins.
        hl_env.reload([env_file])
        assert la._env("LDAP_SERVER") == "ldaps://from-file:636"
    finally:
        hl_env.reload()


def test_env_missing_key_returns_default():
    assert la._env("LDAP_NOT_SET_ANYWHERE") == ""
    assert la._env("LDAP_NOT_SET_ANYWHERE", "fallback") == "fallback"
