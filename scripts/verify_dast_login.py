"""Verify that the DAST scanner accounts can still log in over HTTP.

Checks the path a scanner actually uses — ``POST /login`` on the sensor WebUI — rather than the
authentication function underneath it, so a session-layer regression shows up too.

Reads ``user/pw`` lines on **stdin**, never argv, so the passwords stay out of the process list
and out of shell history. It prints only the username and the observed result, which makes a run
safe to paste into a ticket. Run it on the sensor itself, against the loopback listener:

    scp scripts/verify_dast_login.py <host>:/tmp/vdl.py
    ssh <host> 'cd ~/sensor-1.0 && \
      HONEYLENS_ENV_FILE=~/honeylens-state/.env .venv/bin/python /tmp/vdl.py; rm -f /tmp/vdl.py' \
      < <creds-file>

A successful login answers ``303`` with ``Location: /`` and sets the session cookie; a failure
answers ``401`` with the login page re-rendered. The redirect is deliberately NOT followed, since
following it would exchange the useful status code for a ``200`` on the dashboard.

Mind the login rate limit — 5 attempts per 60 s per client IP, after which the endpoint answers
``429``. A couple of accounts is fine; do not loop this.
"""

from __future__ import annotations

import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

LOGIN_URL = "https://127.0.0.1:60443/login"
TIMEOUT_SEC = 15


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep the 303 instead of following it to the dashboard."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def _post_login(username: str, password: str, ctx: ssl.SSLContext) -> tuple[int, object]:
    body = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(LOGIN_URL, data=body, method="POST")  # fixed https URL
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        resp = opener.open(req, timeout=TIMEOUT_SEC)
        return resp.status, resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.headers


def _tls_context() -> ssl.SSLContext:
    """Verify against the sensor's OWN certificate rather than switching verification off.

    The listener is self-signed, so the system trust store cannot validate it — but the cert is
    right there on disk, and pinning it still catches the case where something other than our
    own API answers on the port. Hostname checking stays off because the cert is issued for the
    sensor's name, not for ``127.0.0.1``.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    try:
        from honeylens.config import TLS_CERT_FILE

        ctx.load_verify_locations(cafile=str(TLS_CERT_FILE))
        ctx.verify_mode = ssl.CERT_REQUIRED
    except Exception as e:  # cert unreadable: say so, do not silently downgrade
        print(
            f"warning: cannot pin the sensor certificate ({type(e).__name__}: {e}); "
            "continuing unverified over loopback only",
            file=sys.stderr,
        )
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def main() -> int:
    ctx = _tls_context()

    seen = failures = 0
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#") or "/" not in line:
            continue
        seen += 1
        username, _, password = line.partition("/")
        try:
            code, headers = _post_login(username, password, ctx)
        except Exception as e:  # report and keep going to the next account
            print(f"{username}: ERROR {type(e).__name__}: {e}")
            failures += 1
            continue

        location = headers.get("location", "") or "-"  # type: ignore[union-attr]
        cookie = (headers.get("set-cookie", "") or "").lower()  # type: ignore[union-attr]
        # Cookie name comes from config (`sensor_sid` by default), so look for the attributes
        # the login path always sets rather than hardcoding the name.
        has_cookie = "httponly" in cookie and "secure" in cookie
        ok = code in (302, 303) and location == "/"
        if not ok:
            failures += 1
        hint = " (rate-limited)" if code == 429 else ""
        print(
            f"{username}: http={code} location={location} "
            f"session_cookie={'yes' if has_cookie else 'no'} "
            f"-> {'LOGIN OK' if ok else 'NOT A LOGIN'}{hint}"
        )

    if seen == 0:
        print("no `user/pw` lines on stdin - did you forget to redirect the creds file?")
        return 2
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
