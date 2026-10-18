"""
auth/ldap_auth.py — optional LDAP / Active Directory authentication backend.

Config-gated (LDAP_ENABLED). When enabled, a user who logs in with an email /
UPN (username containing '@') is authenticated against AD over LDAPS and then
mirrored into the local `users` table with a role derived from AD group
membership — so the session layer (keyed on a local user_id) works unchanged.
Local (non-'@') accounts are never touched: the break-glass admin always works,
even if AD is unreachable.

Auth model is the conventional two-bind pattern: a read-only service bind
(`svc-ldap`) finds the user by `userPrincipalName`, then the user's own DN is
bound with the submitted password to verify it, and `memberOf` maps to a role
(admin group -> admin, viewer group -> user). LDAPS certificates are always
validated (LDAP_CA_CERT or the system trust store) unless LDAP_ALLOW_INSECURE_TLS=true.

Requires: ldap3 (pure-Python, no C build). The import is guarded — if ldap3 is
missing or LDAP_ENABLED is off, ldap_enabled() is False and behaviour is
identical to before.

Config (env / .env):
  LDAP_ENABLED=true
  LDAP_SERVER=ldaps://192.0.2.60:636
  LDAP_BASE_DN=DC=example,DC=com
  LDAP_BIND_DN=CN=svc-ldap,CN=Users,DC=example,DC=com
  LDAP_BIND_PASSWORD=...            # from the offline creds store, never in repo
  LDAP_USER_FILTER=(userPrincipalName=%s)
  LDAP_GROUP_ADMIN=CN=app-admins,CN=Users,DC=example,DC=com
  LDAP_GROUP_VIEWER=CN=app-viewers,CN=Users,DC=example,DC=com
  LDAP_CA_CERT=/opt/honeylens/certs/ad-dc-ca.pem   # omit to validate against the system trust store
  LDAP_ALLOW_INSECURE_TLS=false      # true disables LDAPS certificate validation (lab only)
  LDAP_DEFAULT_ROLE=                # optional: role for authenticated users in no mapped group
"""

from __future__ import annotations

import logging

from honeylens.env import env as _cfg_env

logger = logging.getLogger("auth.ldap")

try:
    import ssl

    from ldap3 import ALL, SUBTREE, Connection, Server, Tls
    from ldap3.core.exceptions import LDAPException
    from ldap3.utils.conv import escape_filter_chars

    _HAS_LDAP3 = True
except ImportError:
    _HAS_LDAP3 = False

    def escape_filter_chars(s: str) -> str:
        """Stand-in for the ldap3 escaper when ldap3 is absent.

        Nothing in this module reaches a filter without ldap3 — ``ldap_enabled()`` is False
        without it and ``ldap_authenticate`` returns early — but ``_escape_filter`` is
        importable on its own, and a sanitiser that raises NameError is a worse failure than
        one that escapes. Same RFC 4515 set, same backslash-hex form.
        """
        return "".join(f"\\{ord(c):02x}" if c in "\\*()\x00" else c for c in s)


def _env(name: str, default: str = "") -> str:
    """Read a setting through the project's own loader, NOT straight from ``os.environ``.

    This used to be ``os.environ.get``, which silently bypassed the ``.env`` file: deployments
    put ``LDAP_*`` in the sensor's ``.env`` (that is what the module docstring above tells them
    to do) and the whole block came back empty, so ``ldap_enabled()`` was False and AD logins
    fell through to the local ``users`` table. ``honeylens.env.env`` checks the ``.env`` file
    first and ``os.environ`` second, so both placements now work.
    """
    val = _cfg_env(name, default)
    return "" if val is None else str(val)


def ldap_enabled() -> bool:
    """True only if ldap3 is installed AND LDAP_ENABLED is truthy."""
    return _HAS_LDAP3 and _env("LDAP_ENABLED").strip().lower() in ("1", "true", "yes", "on")


def _escape_filter(s: str) -> str:
    """RFC 4515 LDAP filter escaping of a user-supplied value.

    Delegates to ldap3's own escaper rather than hand-rolling the character loop. The
    hand-rolled version was correct — byte-identical to this on every case tried,
    injection attempts included — but a security primitive written out by hand is one
    static analysis cannot recognise, and CodeQL reported the search below as a Critical
    LDAP injection because of it. Using the library's function makes the sanitiser
    visible to the analyser as well as to the reader, and leaves one less piece of
    security-relevant string handling for us to maintain.
    """
    return escape_filter_chars(s)


_warned_no_ca = False


def _server() -> Server:
    global _warned_no_ca
    uri = _env("LDAP_SERVER", "ldaps://127.0.0.1:636")
    use_ssl = uri.lower().startswith("ldaps")
    tls = None
    if use_ssl:
        # 0.9: a missing LDAP_CA_CERT disabled certificate validation (CERT_NONE) with a warning —
        # the user's password went to any server impersonating the DC. Now a missing custom CA
        # means "system trust store" (ldap3 calls load_default_certs), and disabling validation
        # requires an explicit LDAP_ALLOW_INSECURE_TLS=true.
        ca = _env("LDAP_CA_CERT")
        insecure = _env("LDAP_ALLOW_INSECURE_TLS").strip().lower() in ("1", "true", "yes")
        validate = ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED
        tls = Tls(ca_certs_file=(ca or None), validate=validate)
        if insecure and not _warned_no_ca:
            logger.error("LDAP_ALLOW_INSECURE_TLS=true — LDAPS certificate is NOT validated")
            _warned_no_ca = True
    return Server(uri, use_ssl=use_ssl, tls=tls, get_info=ALL, connect_timeout=8)


def _role_for_groups(member_of: list) -> str | None:
    """Map AD group DNs to a local role ('admin'|'user'), else None (deny)."""
    groups = {g.lower() for g in member_of}
    admin_grp = _env("LDAP_GROUP_ADMIN").strip().lower()
    viewer_grp = _env("LDAP_GROUP_VIEWER").strip().lower()
    if admin_grp and admin_grp in groups:
        return "admin"
    if viewer_grp and viewer_grp in groups:
        return "user"  # viewer -> the non-admin 'user' role
    default = _env("LDAP_DEFAULT_ROLE").strip().lower()
    return default if default in ("admin", "user") else None


def _val(entry, attr: str) -> str:
    try:
        v = getattr(entry, attr)
        return str(v.value) if v and v.value else ""
    except Exception:
        return ""


def ldap_authenticate(login: str, password: str) -> dict | None:
    """Authenticate `login`/`password` against AD.

    Returns {username, email, name, lastname, role} on success, else None.
    Never raises.
    """
    if not ldap_enabled() or not login or not password:
        return None
    base_dn = _env("LDAP_BASE_DN")
    bind_dn = _env("LDAP_BIND_DN")
    bind_pw = _env("LDAP_BIND_PASSWORD")
    user_filter = _env("LDAP_USER_FILTER", "(userPrincipalName=%s)")
    try:
        srv = _server()
        # 1. read-only service bind to locate the user
        svc = Connection(srv, user=bind_dn, password=bind_pw, auto_bind=True, receive_timeout=8)
        flt = user_filter.replace("%s", _escape_filter(login))
        svc.search(
            base_dn,
            flt,
            search_scope=SUBTREE,
            attributes=[
                "distinguishedName",
                "userPrincipalName",
                "mail",
                "sAMAccountName",
                "givenName",
                "sn",
                "memberOf",
            ],
        )
        if not svc.entries:
            logger.info("LDAP: no user matched %s", login)
            svc.unbind()
            return None
        entry = svc.entries[0]
        user_dn = entry.entry_dn
        try:
            member_of = [str(g) for g in entry.memberOf.values] if "memberOf" in entry else []
        except Exception:
            member_of = []
        role = _role_for_groups(member_of)
        svc.unbind()
        if role is None:
            logger.warning("LDAP: %s is in no mapped group — denied", login)
            return None
        # 2. verify the password by binding as the user
        try:
            uc = Connection(srv, user=user_dn, password=password, auto_bind=True, receive_timeout=8)
            uc.unbind()
        except LDAPException:
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure  # the message contains the word "password", not an actual password
            logger.warning("LDAP: authentication failed (bad password) for %s", login)
            return None
        email = (_val(entry, "userPrincipalName") or _val(entry, "mail") or login).lower()
        return {
            "username": _val(entry, "sAMAccountName") or email.split("@")[0],
            "email": email,
            "name": _val(entry, "givenName"),
            "lastname": _val(entry, "sn"),
            "role": role,
        }
    except LDAPException as e:
        logger.error("LDAP error authenticating %s: %s", login, e)
        return None
    except Exception as e:  # never let auth crash the login path
        logger.error("LDAP unexpected error for %s: %s", login, e)
        return None
