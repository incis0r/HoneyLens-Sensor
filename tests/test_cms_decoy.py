"""`hp_cms` — the CMS decoy, WordPress profile.

These pin the properties that make the decoy worth running rather than the HTML it serves.

The baits are the four that measured real traffic on the fleet (`?rest_route=` 807 requests
from 43 sources, `/wp-json/batch/v1` 238/9, `/wp-content/debug.log` 34/25,
`/wp-content/upgrade/` 25/6). The design this implements also specified surfaces that measured
**zero** requests in the same window -- `really-simple-ssl`, `bricks/v1/render_element`,
`wp-automatic/inc/csv.php`, and the Bitrix, Drupal and Joomla endpoints -- and those are
deliberately absent, so a test that expected them would be asserting the wrong thing.
"""

from __future__ import annotations

import json

import pytest
from aiohttp.test_utils import make_mocked_request

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.honeypots import honeypot_cms as cms


@pytest.fixture
def decoy() -> cms.CmsDecoy:
    return cms.CmsDecoy()


def answer(
    decoy: cms.CmsDecoy, method: str, path: str, query: str = "", body: bytes = b""
) -> cms.Answer:
    return decoy.answer(cms.WORDPRESS, method, path, query, body)


class TestTheNegativeAnswerIsHonest:
    """Every scanner worth deceiving takes a soft-404 baseline first -- a request for a path
    that cannot exist -- and discards a host that answers 200 to everything as a false
    positive. The baits are only ever reached because this answer is a real 404."""

    @pytest.mark.parametrize(
        "path",
        [
            "/zzz-nie-istnieje-9f3k7q.txt",
            "/__fp_test_4291__.html",
            "/bitrix/services/main/ajax.php",
            "/jsonapi",
            "/administrator/index.php",
        ],
    )
    def test_an_unknown_path_is_a_real_404(self, decoy: cms.CmsDecoy, path: str) -> None:
        a = answer(decoy, "GET", path)
        assert a.status == 404
        assert "Nothing here" in a.body

    def test_the_404_is_wordpress_own_document(self, decoy: cms.CmsDecoy) -> None:
        a = answer(decoy, "GET", "/nope-9f3k7q")
        assert "error404" in a.body and "wp-block-search" in a.body


class TestTheFourBaits:
    def test_rest_batch_answers_instead_of_refusing(self, decoy: cms.CmsDecoy) -> None:
        """A patched install replies `rest_batch_not_allowed`; this one replies 207, because
        the value is the multi-step payload the caller only sends once the endpoint looks
        willing."""
        a = answer(decoy, "POST", "/wp-json/batch/v1", body=b'{"requests":[]}')
        assert a.status == 207
        assert a.bait == "wp_rest_batch"
        assert json.loads(a.body)["responses"][0]["status"] == 200
        assert "rest_batch_not_allowed" not in a.body

    def test_both_spellings_of_the_batch_route_answer_the_same(self, decoy: cms.CmsDecoy) -> None:
        """`?rest_route=` is the same API on an install without pretty permalinks and it
        measured more traffic than the pretty form, so answering one and not the other would
        make the decoy contradict itself within a single scan."""
        pretty = answer(decoy, "POST", "/wp-json/batch/v1", body=b"x=1")
        query = answer(decoy, "POST", "/", "rest_route=/batch/v1", body=b"x=1")
        assert pretty.status == query.status == 207
        assert pretty.bait == query.bait == "wp_rest_batch"
        assert json.loads(pretty.body) == json.loads(query.body)

    def test_a_get_of_the_batch_route_is_not_the_vulnerable_answer(
        self, decoy: cms.CmsDecoy
    ) -> None:
        """404 with `rest_no_route`, which is what the WordPress REST server answers to a
        method mismatch. It used to be 405 -- a shape no WordPress install produces, so it
        identified the decoy to anything that checked."""
        a = answer(decoy, "GET", "/wp-json/batch/v1")
        assert a.status == 404
        assert a.bait == "wp_rest_batch_probe"
        body = json.loads(a.body)
        assert body["code"] == "rest_no_route"
        assert body["message"] == "No route was found matching the URL and request method."

    def test_the_debug_log_leaks_a_session_cookie(self, decoy: cms.CmsDecoy) -> None:
        a = answer(decoy, "GET", "/wp-content/debug.log")
        assert a.status == 200
        assert a.bait == "wp_debug_log"
        assert "wordpress_logged_in_" in a.body
        assert "litespeed" in a.body.lower()  # the plugin the flaw belongs to

    def test_the_upgrade_window_is_listable(self, decoy: cms.CmsDecoy) -> None:
        a = answer(decoy, "GET", "/wp-content/upgrade/")
        assert a.status == 200
        assert a.bait == "wp_upgrade_window"
        assert "Index of /wp-content/upgrade" in a.body

    def test_rest_users_lists_accounts(self, decoy: cms.CmsDecoy) -> None:
        """How a password-spray run gets its user list."""
        for a in (
            answer(decoy, "GET", "/wp-json/wp/v2/users"),
            answer(decoy, "GET", "/", "rest_route=/wp/v2/users"),
        ):
            assert a.status == 200
            assert [u["slug"] for u in json.loads(a.body)] == ["admin", "editor"]


class TestItKeepsItsStoryStraight:
    def test_the_staging_directory_follows_the_advertised_version(self) -> None:
        """The design advertised 6.9.4 while serving a staging directory for 7.1.3 -- a site
        cannot be both. Deriving it means the two cannot disagree."""
        assert cms.next_version("6.9.4") == "6.9.5"
        assert cms.next_version("7.1.3") == "7.1.4"
        assert f"wordpress-{cms.next_version(cms.WP_VERSION)}-working" in cms._upgrade_listing()

    def test_a_version_it_cannot_parse_is_left_alone(self) -> None:
        assert cms.next_version("trunk") == "trunk"
        assert cms.next_version("") == ""

    def test_the_version_it_claims_is_the_one_it_serves(self, decoy: cms.CmsDecoy) -> None:
        index = answer(decoy, "GET", "/")
        readme = answer(decoy, "GET", "/readme.html")
        assert cms.WP_VERSION in index.body
        assert cms.WP_VERSION in readme.body


class TestTheHoneytokenIsWorthless:
    def test_it_is_derived_and_stable(self) -> None:
        """Stable so a later attempt to use it elsewhere is attributable."""
        assert cms.honeytoken("wp-debug-log") == cms.honeytoken("wp-debug-log")
        assert cms.honeytoken("a") != cms.honeytoken("b")
        assert len(cms.honeytoken("wp-debug-log")) == 32

    def test_it_differs_per_deployment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cms, "_HONEYTOKEN_SALT", "sensor-one")
        one = cms.honeytoken("wp-debug-log")
        monkeypatch.setattr(cms, "_HONEYTOKEN_SALT", "sensor-two")
        assert cms.honeytoken("wp-debug-log") != one

    def test_the_leaked_cookie_is_the_derived_token_and_nothing_else(
        self, decoy: cms.CmsDecoy
    ) -> None:
        """The only secret the decoy hands out is the derived token.

        The earlier version of this grepped the module source for four arbitrary strings,
        which `admin:P@ssw0rd` would have passed. This takes the one response that leaks a
        secret and checks the secret in it is the derived one."""
        body = answer(decoy, "GET", "/wp-content/debug.log").body
        token = cms.honeytoken("wp-debug-log")
        assert token in body
        # the cookie value carries the token and the derived COOKIEHASH, nothing else
        cookie = next(line for line in body.splitlines() if "wordpress_logged_in_" in line)
        secret = cookie.split("wordpress_logged_in_", 1)[1]
        assert secret.startswith(cms._cookiehash())
        assert token in secret

    def test_the_cookie_hash_is_the_length_wordpress_uses(self) -> None:
        """COOKIEHASH is md5 of the site URL: 32 hex characters. It was 16, which is a length
        no WordPress install produces."""
        assert len(cms._cookiehash()) == 32
        assert all(c in "0123456789abcdef" for c in cms._cookiehash())


class TestPersonas:
    def test_one_profile_is_enabled(self) -> None:
        assert set(cms.available_personas()) == {"wordpress"}

    def test_a_request_aimed_at_nothing_in_particular_gets_the_default(self) -> None:
        assert cms.resolve_persona("/robots.txt").name == cms.DEFAULT_PERSONA
        assert cms.resolve_persona("/").name == cms.DEFAULT_PERSONA

    def test_a_wordpress_shaped_request_resolves_to_wordpress(self) -> None:
        for path in (
            "/wp-login.php",
            "/wp-json/wp/v2/users",
            "/?rest_route=/wp/v2/pages",
            "/xmlrpc.php",
        ):
            assert cms.resolve_persona(path).name == "wordpress"

    def test_the_registry_falls_back_rather_than_serving_nothing(self) -> None:
        """An empty or misconfigured `CMS_ENABLED_PERSONAS` must not leave the decoy with no
        identity to answer as."""
        assert cms.available_personas() != {}


class TestTheEventIsUsable:
    """A capture nothing can read is not a capture. The classifier's metadata sweep reads
    `path`, `headers`, `body` and `body_sample`; a decoy that put the path only in its own
    summary line would hand every POST to the rules with no path at all."""

    def _capture(self, decoy: cms.CmsDecoy, method: str, path: str, query: str = "") -> dict:
        """Run one request through the real handler and return what it would have emitted."""
        import asyncio

        captured: dict = {}
        decoy._emit = lambda **kw: captured.update(kw)  # type: ignore[method-assign]
        request = make_mocked_request(
            method, path + (f"?{query}" if query else ""), headers={"User-Agent": "curl/8"}
        )
        asyncio.run(decoy.handle(request))
        return captured

    def _event(self, decoy: cms.CmsDecoy, method: str, path: str, query: str = "") -> dict:
        return self._capture(decoy, method, path, query)["event"]

    def test_it_carries_what_the_classifier_reads(self, decoy: cms.CmsDecoy) -> None:
        event = self._event(decoy, "GET", "/wp-content/debug.log")
        for key in ("path", "method", "headers", "honeypot", "cms_persona", "body_len"):
            assert key in event, key
        assert event["path"] == "/wp-content/debug.log"
        assert event["honeypot"] == "cms"

    def test_it_names_the_bait_it_answered(self, decoy: cms.CmsDecoy) -> None:
        assert self._event(decoy, "GET", "/wp-content/upgrade/")["cms_bait"] == "wp_upgrade_window"

    @pytest.mark.parametrize(
        ("path", "query", "verdict"),
        [
            ("/wp-content/debug.log", "", "WORDPRESS_CRED"),
            ("/wp-content/upgrade/", "", "WORDPRESS_RECON"),
            ("/wp-json/batch/v1", "", "WORDPRESS_RECON"),
            ("/", "rest_route=/batch/v1", "WORDPRESS_RECON"),
            ("/wp-json/wp/v2/users", "", "WORDPRESS_RECON"),
        ],
    )
    def test_every_bait_produces_a_labelled_event(
        self, decoy: cms.CmsDecoy, path: str, query: str, verdict: str
    ) -> None:
        """Measured before the rules were added: the debug.log, upgrade-window and
        query-form batch baits came back labelled `SCANNER` and nothing else -- a bait whose
        capture says only "someone scanned us" is a bait that tells you nothing."""
        # The decoy's own payload and metadata, not a reconstruction of them: the point is
        # that what it writes is what the rules can read.
        captured = self._capture(decoy, "GET", path, query)
        hits = classify_event_row(captured["payload"], "http", captured["event"])
        assert verdict in {a for a, _n, _s in hits}, (
            f"{path} got {sorted({a for a, _n, _s in hits})}"
        )


class TestItIsNotAWeaponPointedOutward:
    """The upgrade-window bait reflected the requested directory name into its HTML listing.
    An internet-facing decoy that echoes a path segment is usable as a reflected-XSS gadget
    against a third party -- a phishing lure served from our own address -- and "it is only a
    honeypot" does not change who gets hit. A real staging directory has one shape, so only
    that shape is reflected and anything else falls back to the derived name, which keeps the
    listing realistic at the same time.
    """

    @pytest.mark.parametrize(
        "segment",
        [
            "wordpress-<script>alert(1)</script>-working",
            'wordpress-" onload="alert(1)-working',
            "../../etc/passwd",
            "wordpress-6.9.5-working'><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ],
    )
    def test_a_hostile_directory_name_is_not_reflected(
        self, decoy: cms.CmsDecoy, segment: str
    ) -> None:
        a = answer(decoy, "GET", f"/wp-content/upgrade/{segment}/")
        # Either it never reached the bait (a path with a traversal or an extra slash falls
        # through to the 404) or it did and the name was replaced. What must hold in both
        # cases is that nothing the caller sent comes back.
        assert a.status in (200, 404)
        for marker in ("<script", "onerror=", "onload=", "<svg", "../", "alert(1)"):
            assert marker not in a.body, f"{marker!r} reached the response"
        if a.status == 200:
            assert f"wordpress-{cms.next_version(cms.WP_VERSION)}-working" in a.body

    def test_a_real_staging_name_is_still_reflected(self, decoy: cms.CmsDecoy) -> None:
        """The bait still has to look like the directory the caller asked about."""
        a = answer(decoy, "GET", "/wp-content/upgrade/wordpress-7.1.4-working/")
        assert "wordpress-7.1.4-working" in a.body

    @pytest.mark.parametrize(
        "path",
        [
            "/<script>alert(1)</script>",
            "/wp-login.php",
            "/wp-json/wp/v2/users",
            "/wp-content/debug.log",
            "/readme.html",
            "/robots.txt",
            "/",
        ],
    )
    def test_no_response_body_echoes_the_request(self, decoy: cms.CmsDecoy, path: str) -> None:
        """Asserted over every response builder, by sending a marker and looking for it.

        The earlier version of this test read `_upgrade_listing`'s source for the strings
        `html.escape` and `_STAGING_NAME.match`, which says nothing about the other builders
        and would still have passed if the 404 had started echoing `request.path`. Checking
        the prose about the code instead of the code is a mistake this file made twice."""
        marker = "zzmarker9f3k7q"
        a = answer(
            decoy,
            "GET",
            path.replace("alert(1)", marker),
            f"q={marker}",
            b"body=" + marker.encode(),
        )
        assert marker not in a.body, f"{path} echoed the request into its response"


class TestItCapturesWholeBodies:
    """The stage-two payload is the reason this decoy exists.

    `request.content.read(n)` returns whatever is already buffered as soon as any data is
    present, so a body split across TCP writes was truncated to its first chunk -- and the
    event said `body_truncated=False`, claiming to be complete. Measured before the fix:
    20,000 bytes sent in two writes 400 ms apart recorded `body_len=1000`. The old tests all
    used `make_mocked_request` with an empty payload, so none of them could see it.
    """

    def test_a_body_split_across_writes_arrives_whole(self) -> None:
        import asyncio
        import socket
        import threading

        captured: list[dict] = []

        async def serve() -> tuple[object, int]:
            decoy = cms.CmsDecoy()
            decoy._emit = lambda **kw: captured.append(kw)  # type: ignore[method-assign]
            runner = __import__("aiohttp").web.AppRunner(cms.build_app(decoy), access_log=None)
            await runner.setup()
            site = __import__("aiohttp").web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = runner.addresses[0][1]
            return runner, port

        async def main() -> None:
            runner, port = await serve()
            try:
                await asyncio.get_running_loop().run_in_executor(None, _post_split, port)
                for _ in range(50):
                    if captured:
                        break
                    await asyncio.sleep(0.05)
            finally:
                await runner.cleanup()

        def _post_split(port: int) -> None:
            first, second = b"A" * 1000, b"B" * 19000
            total = len(first) + len(second)
            with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
                sock.sendall(
                    (
                        "POST /wp-json/batch/v1 HTTP/1.1\r\nHost: x\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {total}\r\nConnection: close\r\n\r\n"
                    ).encode()
                    + first
                )
                threading.Event().wait(0.3)  # the rest arrives in a later TCP read
                sock.sendall(second)
                sock.shutdown(socket.SHUT_WR)
                while sock.recv(65536):
                    pass

        asyncio.run(main())
        assert captured, "the handler never emitted an event"
        event = captured[0]["event"]
        assert event["body_len"] == 20000, f"body truncated to {event['body_len']}"
        assert event["cms_bait"] == "wp_rest_batch"

    def test_a_stage_two_surface_gets_the_larger_budget(self) -> None:
        """64 KB is the fleet default for an ordinary request; the surfaces a payload is
        delivered to get more. A flat 512 KB for everything let the attacker choose our disk
        cost."""
        assert cms.capture_budget("wp_rest_batch") == cms.RAW_CAPTURE_BYTES_STAGE2
        assert cms.capture_budget("wp_login_post") == cms.RAW_CAPTURE_BYTES_STAGE2
        assert cms.capture_budget("wp_robots") == cms.RAW_CAPTURE_BYTES
        assert cms.capture_budget(None) == cms.RAW_CAPTURE_BYTES
        assert cms.RAW_CAPTURE_BYTES < cms.RAW_CAPTURE_BYTES_STAGE2


class TestItLooksLikeApacheAndPhp:
    """Each of these was a tell measured against the running decoy."""

    def test_the_referenced_assets_exist(self, decoy: cms.CmsDecoy) -> None:
        """The index page names a stylesheet and a script. Both used to 404, so a scanner
        that fetched what it had just been told about concluded this was not WordPress."""
        index = answer(decoy, "GET", "/").body
        for href in (
            f"/wp-content/themes/{cms.WP_THEME}/style.css",
            "/wp-includes/js/wp-embed.min.js",
        ):
            assert href in index
            assert answer(decoy, "GET", href).status == 200

    def test_wp_admin_redirects_to_the_login_form(self, decoy: cms.CmsDecoy) -> None:
        """A real install 302s an unauthenticated `/wp-admin/`; it used to 404 here, and the
        redirect target is how a bot finds the form."""
        a = answer(decoy, "GET", "/wp-admin/")
        assert a.status == 302
        assert a.headers["Location"].startswith("/wp-login.php?redirect_to=")

    def test_robots_and_feed_are_served(self, decoy: cms.CmsDecoy) -> None:
        assert "Disallow: /wp-admin/" in answer(decoy, "GET", "/robots.txt").body
        assert "<rss" in answer(decoy, "GET", "/feed/").body

    def test_php_header_only_on_php_responses(self, decoy: cms.CmsDecoy) -> None:
        """Apache never adds `X-Powered-By` to a mod_autoindex listing or a static file."""
        assert answer(decoy, "GET", "/wp-login.php").php is True
        for static in ("/wp-content/upgrade/", "/wp-content/debug.log", "/robots.txt"):
            assert answer(decoy, "GET", static).php is False, static

    def test_the_autoindex_carries_apache_footer(self, decoy: cms.CmsDecoy) -> None:
        body = answer(decoy, "GET", "/wp-content/upgrade/").body
        assert "<address>" in body and cms.SERVER_HEADER in body

    def test_a_path_inside_the_staging_tree_is_not_the_parent_listing(
        self, decoy: cms.CmsDecoy
    ) -> None:
        """The CVE-2026-119977 chain asks for files inside the staging tree. Every one of them
        used to get the index of the parent directory, which is the wrong document."""
        staging = f"/wp-content/upgrade/wordpress-{cms.next_version(cms.WP_VERSION)}-working"
        listing = answer(decoy, "GET", staging + "/")
        assert listing.status == 200
        assert "Index of /wp-content/upgrade/wordpress-" in listing.body
        inside = answer(decoy, "GET", staging + "/wordpress/wp-admin/setup-config.php")
        assert inside.status == 404
        assert "Index of" not in inside.body

    def test_the_charset_is_spelled_the_way_php_spells_it(self, decoy: cms.CmsDecoy) -> None:
        assert answer(decoy, "GET", "/").content_type.endswith("charset=UTF-8")


class TestTheBannerIsMaskedBeforeTheAppRuns:
    def test_aiohttp_default_server_banner_is_replaced(self) -> None:
        """aiohttp answers an oversized request line or a TLS handshake on the plaintext port
        itself, before any handler runs, and those responses used to carry
        `Server: Python/3.12 aiohttp/x` and produce no event at all."""
        from aiohttp import web_response

        before = web_response.SERVER_SOFTWARE
        try:
            cms._mask_server_banner()
            assert web_response.SERVER_SOFTWARE == cms.SERVER_HEADER
            assert "aiohttp" not in web_response.SERVER_SOFTWARE
            assert "Python" not in web_response.SERVER_SOFTWARE
        finally:
            web_response.SERVER_SOFTWARE = before


class TestTheSenderIsRecordedAsTheySpokeIt:
    def test_header_casing_is_preserved(self) -> None:
        """The parser-normalised multidict turned a client's `content-type:` into
        `Content-Type`. The casing is a fingerprint the hunts read out of
        `metadata->>'headers'`, and this decoy was erasing it for every header aiohttp knows."""
        import asyncio

        captured: list[dict] = []
        decoy = cms.CmsDecoy()
        decoy._emit = lambda **kw: captured.append(kw)  # type: ignore[method-assign]
        request = make_mocked_request(
            "GET", "/", headers={"content-type": "text/plain", "X-Odd-Case": "1"}
        )
        asyncio.run(decoy.handle(request))
        recorded = captured[0]["event"]["headers"]
        assert "content-type" in recorded, sorted(recorded)
        assert "Content-Type" not in recorded


class TestTheHoneytokenIsStableWhereItRuns:
    def test_the_sensor_hostname_is_preferred_over_the_container_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """In a container the node name IS the container id, and the quadlet runs
        `--replace --rm` with `Restart=always`, so deriving from it produced a new token on
        every restart -- the opposite of the stability the function promises."""
        monkeypatch.setattr(cms, "_HONEYTOKEN_SALT", "")
        monkeypatch.setenv("SENSOR_HOSTNAME", "sensor-a")
        from_host = cms.honeytoken("wp-debug-log")
        monkeypatch.setenv("SENSOR_HOSTNAME", "sensor-b")
        assert cms.honeytoken("wp-debug-log") != from_host
        # and it does not fall through to the node name while SENSOR_HOSTNAME is set
        monkeypatch.setenv("SENSOR_HOSTNAME", "sensor-a")
        assert cms.honeytoken("wp-debug-log") == from_host


class TestTheBaitsHistoryCanBeBackfilled:
    """The three rules that ship with this decoy also match history, so they need the same
    additive pass the CONNECT rules got -- otherwise marking the rule fingerprint as applied
    would be a false claim, and the alternative is the nightly authoritative reprocess that
    exists for *tightened* rules and is wrong for added ones."""

    def test_a_profile_exists_for_them(self) -> None:
        from honeylens.tools.backfill_rule_profile import PROFILES

        profile = PROFILES["wordpress-baits"]
        assert profile.rules == {
            "wordpress_debug_log_probe",
            "wordpress_upgrade_window_probe",
            "wordpress_rest_batch",
        }

    def test_every_rule_in_the_profile_exists_in_the_registry(self) -> None:
        """A profile naming a rule that is not registered would report zero for ever and look
        like a clean pass."""
        from honeylens.classification import text_rules
        from honeylens.tools.backfill_rule_profile import PROFILES

        registered = {name for _a, name, _rx in text_rules._RULES}
        for profile in PROFILES.values():
            assert profile.rules <= registered, profile.rules - registered

    def test_it_adds_both_verdicts_and_keeps_what_was_there(self) -> None:
        """The three rules carry two different verdicts, and a row may already hold others
        from rules that predate them. The pass adds what is missing and removes nothing."""
        from unittest.mock import MagicMock, patch

        from honeylens.tools import backfill_rule_profile as tool

        row = (
            "evt_1",
            "GET /wp-content/debug.log",
            "http",
            {"path": "/wp-content/debug.log", "method": "GET"},
            "SCANNER",  # already labelled by a rule that predates these
        )
        cur = MagicMock()
        cur.fetchall.return_value = [row]
        cur.rowcount = 1
        ctx = MagicMock()
        ctx.__enter__.return_value = cur
        with patch.object(tool, "db_cursor", return_value=ctx):
            counts = tool.backfill(tool.PROFILES["wordpress-baits"], since_days=1, apply=True)
        assert counts["matched"] == 1
        statements = [c.args[0] for c in cur.execute.call_args_list]
        params = [c.args[1] for c in cur.execute.call_args_list if len(c.args) > 1]
        assert any("INSERT INTO attack_patterns" in s for s in statements)
        assert any("UPDATE sensor_events" in s for s in statements)
        # the verdict the new rule carries is appended; SCANNER is never touched
        appended = {p[0] for p in params if isinstance(p, tuple) and p and p[0].isupper()}
        assert "WORDPRESS_CRED" in appended
        assert "SCANNER" not in appended

    def test_it_counts_a_row_that_already_has_the_verdict_as_done(self) -> None:
        from unittest.mock import MagicMock, patch

        from honeylens.tools import backfill_rule_profile as tool

        row = (
            "evt_1",
            "GET /wp-content/debug.log",
            "http",
            {"path": "/wp-content/debug.log"},
            "SCANNER,WORDPRESS_CRED",
        )
        cur = MagicMock()
        cur.fetchall.return_value = [row]
        cur.rowcount = 0
        ctx = MagicMock()
        ctx.__enter__.return_value = cur
        with patch.object(tool, "db_cursor", return_value=ctx):
            counts = tool.backfill(tool.PROFILES["wordpress-baits"], since_days=1, apply=False)
        assert counts["already_tagged"] == 1
