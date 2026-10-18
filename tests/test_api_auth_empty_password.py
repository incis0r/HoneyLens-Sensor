"""The legacy API credentials must not authenticate anyone when unconfigured.

`config.API_AUTH_PASSWORD` defaults to the empty string. Both the auth middleware and
the login-form handler compared the submitted password against it with
`secrets.compare_digest`, which returns True when both sides are empty. A request
carrying HTTP Basic `sensor:` (username `sensor`, empty password) therefore satisfied
the check and was granted `is_admin = True`.

That is a full unauthenticated read of the event store, and on a sensor with 60443
open in the firewall it is reachable from the internet. Confirmed exploitable against
two live sensors on 2026-08-26 before the guard below was added.

The fix is one condition — the fallback only applies when a password is actually
configured — so these tests exist to keep it from being refactored away.
"""

import os
import re
from pathlib import Path

API_PY = Path(__file__).resolve().parents[1] / "src" / "honeylens" / "api.py"


def _fallback_blocks():
    """Return the source of every legacy-credential fallback in api.py."""
    src = API_PY.read_text()
    return re.findall(
        r"if not authenticated[^\n]*:\n(?:[^\n]*\n){0,4}?[^\n]*"
        r"compare_digest\(username, API_AUTH_USERNAME\)",
        src,
    )


def test_both_fallback_sites_exist():
    """One in the middleware, one in the login-form handler. If a future refactor
    collapses them, this count changes and the guard tests below need revisiting."""
    assert len(_fallback_blocks()) == 2, _fallback_blocks()


def test_every_fallback_requires_a_configured_password():
    for block in _fallback_blocks():
        assert "and API_AUTH_PASSWORD" in block.split("\n")[0], (
            "legacy credential fallback is not guarded on a configured password:\n" + block
        )


def test_config_default_is_still_empty():
    """The guard matters precisely because the default is empty. If someone gives
    API_AUTH_PASSWORD a real default, that is a shipped credential and worse."""
    from honeylens import config

    assert config.API_AUTH_PASSWORD == os.environ.get("API_AUTH_PASSWORD", ""), (
        "API_AUTH_PASSWORD should come from the environment with an empty default"
    )


def test_empty_password_cannot_match_a_configured_one():
    """The property the guard protects, stated directly."""
    import secrets

    configured = ""  # unset, as shipped
    assert secrets.compare_digest("", configured) is True, (
        "compare_digest('', '') is True — this is why the guard is needed, not a bug "
        "in compare_digest"
    )
    # With the guard, an empty configured password disables the branch entirely.
    assert not (configured and secrets.compare_digest("", configured))
