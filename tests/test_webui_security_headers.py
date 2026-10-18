"""The WebUI's own security headers, and the one thing about them that rots.

A test that merely asserts "the CSP header is a string" would pass forever and catch
nothing. The test worth having is the last one here: it reads the WebUI source, collects
the origins the pages actually load subresources from, and fails if any of them is
missing from the policy. That is the realistic failure — somebody adds a charting library
from a new CDN, the page silently stops rendering in a browser that enforces CSP, and the
header is the last place anyone looks.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

WEBUI = Path(__file__).resolve().parent.parent / "src" / "honeylens" / "webui"


class _Resp:
    def __init__(self):
        self.headers: dict[str, str] = {}


@pytest.fixture
def headers() -> dict[str, str]:
    from honeylens.api import AuthMiddleware

    resp = _Resp()
    AuthMiddleware._add_security_headers(resp)
    return resp.headers


def _directive(csp: str, name: str) -> str:
    for part in csp.split(";"):
        part = part.strip()
        if part.split(" ")[0] == name:
            return part
    return ""


def test_csp_is_set_and_locks_down_the_cheap_wins(headers):
    csp = headers.get("Content-Security-Policy", "")
    assert csp, "no CSP at all was the ZAP finding"
    # These four cost nothing to enforce and are the part that works despite 'unsafe-inline'.
    assert _directive(csp, "object-src") == "object-src 'none'"
    assert _directive(csp, "base-uri") == "base-uri 'self'"
    assert _directive(csp, "form-action") == "form-action 'self'"
    assert _directive(csp, "frame-ancestors") == "frame-ancestors 'none'"


def test_cross_origin_isolation_headers(headers):
    assert headers.get("Cross-Origin-Opener-Policy") == "same-origin"
    assert headers.get("Cross-Origin-Resource-Policy") == "same-origin"


def test_coep_is_not_set_because_it_would_break_the_hunting_map(headers):
    """ZAP asks for require-corp. Leaflet and the basemap tiles do not send CORP, so
    enforcing it would blank the map. Keep this explicit so nobody "fixes" the finding."""
    assert "Cross-Origin-Embedder-Policy" not in headers


def test_script_src_still_needs_unsafe_inline():
    """Guards the claim the policy's comment makes, so the comment cannot quietly go stale.

    When this fails, the inline handlers are gone and the nonce path is finally available —
    at which point drop 'unsafe-inline' and wire generate_csp_nonce() through html_page.
    """
    inline_handlers = sum(
        len(re.findall(r"\son(?:click|change|submit|input|load)=", p.read_text()))
        for p in WEBUI.glob("*.py")
    )
    assert inline_handlers > 0, "inline handlers are gone — time to switch to a nonce CSP"


def _deny(accept: str):
    """Run the auth middleware for an unauthenticated request to a protected path."""
    from honeylens.api import AuthMiddleware

    middleware = AuthMiddleware(app=None)
    request = SimpleNamespace(
        url=SimpleNamespace(path="/stats"),
        headers={"Accept": accept} if accept else {},
        cookies={},
        state=SimpleNamespace(),
    )

    async def call_next(_request):
        raise AssertionError("an unauthenticated request must not reach the application")

    return asyncio.run(middleware.dispatch(request, call_next))


@pytest.mark.parametrize(
    ("accept", "status"),
    [("text/html", 303), ("application/json", 401)],
)
def test_the_denial_responses_carry_the_headers_too(accept, status):
    """The responses an unauthenticated client sees used to be the only bare ones.

    Both of these returned without passing through _add_security_headers, so the redirect
    to the login page and the Basic challenge had no HSTS, no X-Frame-Options and no CSP —
    which is precisely what a scanner without credentials is handed first.
    """
    response = _deny(accept)
    assert response.status_code == status
    for header in (
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
    ):
        assert header in response.headers, f"{status} response is missing {header}"


def _subresource_origins() -> set[str]:
    """Origins the served pages fetch subresources from, read out of the WebUI source."""
    patterns = (
        r"""<script src=["'](https://[^/"']+)""",
        r"""<link[^>]+href=["'](https://[^/"']+)""",
        r"""L\.tileLayer\(['"](https://[^/'"]+)""",
        r"""fetch\(['"](https://[^/'"]+)""",
    )
    found: set[str] = set()
    for path in WEBUI.glob("*.py"):
        text = path.read_text()
        for pat in patterns:
            found.update(re.findall(pat, text))
    return found


def test_every_origin_the_pages_load_is_allowed_by_the_policy(headers):
    csp = headers.get("Content-Security-Policy", "")
    origins = _subresource_origins()
    assert origins, "the extractor matched nothing — it has drifted from the markup"
    missing = sorted(o for o in origins if o not in csp)
    assert not missing, (
        "these origins are loaded by the dashboards but absent from the CSP, so an "
        f"enforcing browser will drop them: {', '.join(missing)}"
    )
