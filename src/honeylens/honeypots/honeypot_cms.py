"""honeypot_cms — a CMS decoy, with the WordPress profile enabled.

Why it exists, and why it is one profile and not four. The design this implements proposed a
four-persona chameleon (WordPress, 1C-Bitrix, Drupal, Joomla), arguing that WordPress traffic
was 35-58% of the unlabelled HTTP events on the fleet. Measured 2026-11-08 on the public
sensor, 30 days, external traffic only, 186,082 HTTP events carrying a path:

    family      events   sources   unlabelled
    WordPress   13,756      310     1,032  (8% of the family)
    Drupal          67       42        48
    Joomla          67       25         5
    1C-Bitrix       14        1        14

WordPress is 1.1% of the unlabelled events, not 35-58%, because `classification/rules/cms.py`
already labels 92% of that traffic. Bitrix -- eight CVEs and a full persona in the design --
is fourteen requests from one source in a month, and zero on the second sensor checked. So the
registry is built for several personas and ships with one; the rest arrive when telemetry
does, not before.

The baits are the four that measured real traffic, and nothing else:

    ?rest_route=                807 requests / 43 sources
    /wp-json/batch/v1           238 / 9
    /wp-content/debug.log        34 / 25
    /wp-content/upgrade/         25 / 6

Of the design's other Stage-1 surfaces, `really-simple-ssl`, `bricks/v1/render_element`,
`wp-automatic/inc/csv.php` and the Drupal/Joomla/Bitrix endpoints measured **zero** requests in
the window. A bait nobody probes is a response nobody reads.

Three things this decoy is careful about:

**A genuine 404 for anything it does not bait.** Every scanner worth deceiving starts with a
soft-404 baseline -- a request for a path that cannot exist -- and discards any host that
answers 200 to everything. The illusion only works if the negative answer is honest, so
unknown paths get WordPress's own 404 document and status.

**The client address comes from `http_client_ip_with_origin`, and an event says when it was
not the peer's.** Measured 2026-11-06 on one sensor: 10,650 rows stored the edge's own address
while the real client sat in `X-Real-IP`, and `source_class` read `internal` for all of them --
external attacks filtered out of the dashboards by our own proxy. When the second persona
lands and the persona cache becomes necessary, **it must key on this resolved address and must
not be sticky at all when the origin is `ORIGIN_EDGE_UNRESOLVED`**: behind a proxy, `src_ip` is
one value for every attacker, so a cache keyed on it would collapse them into one persona and
would hand one actor the state built by another. There is no cache yet because with a single
persona there is nothing to keep consistent across requests.

**The honeytoken is derived, never real.** The `debug.log` bait leaks a `wordpress_logged_in_*`
cookie, which is the point of CVE-2024-44000. It is an HMAC of a per-deployment salt, so it is
stable for correlation, unique per sensor, and worthless as a credential anywhere.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import html
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from aiohttp import web

from honeylens.honeypots import deception_waf, proxy_protocol, sink
from honeylens.honeypots.body_capture import capture as capture_body
from honeylens.honeypots.netscaler_eventlog import EventLog

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("cms-honeypot")

# --- configuration ----------------------------------------------------------------------
#
# 20080, bound 1:1. No port block and no translation: the port on the edge, the port the
# decoy binds and the port recorded in the event are the same number, which is what makes a
# capture traceable back to a firewall rule without a mapping table.
DEFAULT_PORT = int(os.environ.get("CMS_PORT", "20080"))
DEFAULT_HOST = os.environ.get("CMS_BIND", "0.0.0.0")

ENABLED_PERSONAS = tuple(
    p.strip().lower()
    for p in os.environ.get("CMS_ENABLED_PERSONAS", "wordpress").split(",")
    if p.strip()
)
DEFAULT_PERSONA = os.environ.get("CMS_DEFAULT_PERSONA", "wordpress").strip().lower()

MAX_BODY = int(os.environ.get("CMS_CLIENT_MAX_SIZE", str(8 * 1024 * 1024)))
# The fleet default for an ordinary request, raised only for the surfaces a multi-step payload
# is delivered to. A flat 512 KB for everything let the attacker choose our disk cost: one 8 MB
# POST became roughly 1.5 MB of event line (hex plus body sample) whatever it carried.
RAW_CAPTURE_BYTES = int(
    os.environ.get(
        "CMS_RAW_CAPTURE_BYTES", os.environ.get("HONEYPOT_RAW_CAPTURE_BYTES", str(64 * 1024))
    )
)
RAW_CAPTURE_BYTES_STAGE2 = int(os.environ.get("CMS_RAW_CAPTURE_BYTES_STAGE2", str(512 * 1024)))

# Baits a payload is delivered TO, as opposed to probed for.
_STAGE2_BAITS = frozenset({"wp_rest_batch", "wp_login_post", "wp_xmlrpc"})


def capture_budget(bait: str | None) -> int:
    """Bytes of body and raw request to keep for a request that hit `bait`."""
    return RAW_CAPTURE_BYTES_STAGE2 if bait in _STAGE2_BAITS else RAW_CAPTURE_BYTES


# 6.9.4: in range for the batch/REST chain, which is the bait with the most measured traffic.
# The upgrade-window bait derives its staging directory from this value rather than naming a
# fixed release, so the two cannot contradict each other -- a site claiming 6.9.4 while
# advertising a staging directory for 7.1.3 is a tell, and the design had exactly that.
WP_VERSION = os.environ.get("CMS_WP_VERSION", "6.9.4").strip()
WP_THEME = os.environ.get("CMS_WP_THEME", "twentytwentyfour").strip()
SERVER_HEADER = os.environ.get("CMS_SERVER_HEADER", "Apache/2.4.58 (Debian)").strip()
PHP_VERSION = os.environ.get("CMS_PHP_VERSION", "8.2.18").strip()

_HONEYTOKEN_SALT = os.environ.get("CMS_HONEYTOKEN_SALT", "").strip()

# What the site calls itself in the places a real install would: Apache's autoindex footer and
# WordPress's COOKIEHASH. Configurable, because a fleet-wide constant is itself a fingerprint.
_SITE_HOST = os.environ.get("CMS_SITE_HOST", "localhost").strip()


def next_version(version: str) -> str:
    """`6.9.4` -> `6.9.5`: the release a site on `version` would be staging an upgrade to.

    Keeps the upgrade-window bait coherent with the advertised version instead of naming a
    release the claimed install could not be upgrading to.
    """
    parts = version.split(".")
    if not parts or not parts[-1].isdigit():
        return version
    return ".".join([*parts[:-1], str(int(parts[-1]) + 1)])


def honeytoken(kind: str) -> str:
    """A stable, per-deployment, worthless secret.

    Derived so the same sensor always leaks the same value -- which is what makes a later
    attempt to use it elsewhere attributable -- while never being a credential that opens
    anything. With no salt configured it is still derived, from the hostname, rather than
    falling back to something hard-coded and fleet-wide.
    """
    # `SENSOR_HOSTNAME` before the node name: in a container the node name IS the container
    # id, and the quadlet runs `podman run --replace --rm` with `Restart=always`, so every
    # restart produced a different id and therefore a different token -- the opposite of the
    # stability this function promises. `SENSOR_HOSTNAME` is already injected into the unit.
    salt = (
        _HONEYTOKEN_SALT
        or os.environ.get("SENSOR_HOSTNAME", "").strip()
        or f"cms-decoy@{os.uname().nodename}"
    )
    return hmac.new(salt.encode(), kind.encode(), hashlib.sha256).hexdigest()[:32]


# --- personas ---------------------------------------------------------------------------


@dataclass
class Persona:
    """One CMS identity: how it names itself and how it says no.

    `claims` are the path fragments that identify a request as aimed at this CMS. They are
    what a persona cache would key a client on once more than one persona is enabled.
    """

    name: str
    server: str
    powered_by: str
    generator: str
    claims: tuple[str, ...]
    not_found: str
    cookie_name: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)


_WP_404 = """<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Page not found &#8211; Blog</title>
<meta name='robots' content='max-image-preview:large' />
</head>
<body class="error404 wp-embed-responsive">
<main id="wp--skip-link--target">
<header class="page-header"><h1 class="page-title">Nothing here</h1></header>
<div class="page-content"><p>It looks like nothing was found at this location. Maybe try a search?</p>
<form role="search" method="get" class="wp-block-search" action="/">
<input class="wp-block-search__input" type="search" name="s" required />
</form></div>
</main>
</body>
</html>
"""

WORDPRESS = Persona(
    name="wordpress",
    server=SERVER_HEADER,
    powered_by=f"PHP/{PHP_VERSION}",
    generator=f"WordPress {WP_VERSION}",
    claims=("/wp-", "/xmlrpc.php", "rest_route=", "/wp-json"),
    not_found=_WP_404,
    cookie_name="wordpress_test_cookie",
)

PERSONAS: dict[str, Persona] = {WORDPRESS.name: WORDPRESS}


def available_personas() -> dict[str, Persona]:
    """The personas this deployment serves: the registry filtered by `CMS_ENABLED_PERSONAS`."""
    enabled = {n: p for n, p in PERSONAS.items() if n in ENABLED_PERSONAS}
    return enabled or {WORDPRESS.name: WORDPRESS}


def resolve_persona(path_qs: str, personas: dict[str, Persona] | None = None) -> Persona:
    """Which CMS this request is aimed at, falling back to the configured default.

    With one persona enabled every request resolves to it; the function exists so that
    enabling a second one is a registry entry and not a rewrite of the request path.
    """
    pool = personas if personas is not None else available_personas()
    lowered = path_qs.lower()
    for persona in pool.values():
        if any(claim in lowered for claim in persona.claims):
            return persona
    return pool.get(DEFAULT_PERSONA) or next(iter(pool.values()))


# --- the four baits ---------------------------------------------------------------------
#
# Each is "what the scanner probes" -> "the answer that makes it continue to stage two". The
# value of a decoy here is not the response, it is the exploit the response provokes: a probe
# answered with a plausible 403 or 200 is followed by the payload, which is the artefact worth
# capturing.

_REST_PAGES = [
    {
        "id": 2,
        "date": "2026-02-11T09:14:22",
        "slug": "sample-page",
        "status": "publish",
        "type": "page",
        "link": "/sample-page/",
        "title": {"rendered": "Sample Page"},
        "template": "",
    }
]

_REST_USERS = [
    {"id": 1, "name": "admin", "url": "", "slug": "admin", "description": ""},
    {"id": 4, "name": "editor", "url": "", "slug": "editor", "description": ""},
]


def _batch_response() -> dict[str, Any]:
    """`207 Multi-Status`, i.e. the batch endpoint answering instead of refusing.

    An unpatched install does not reply `rest_batch_not_allowed`, so neither do we. What this
    buys is the next request: the multi-step payload the caller only sends once the endpoint
    looks willing.
    """
    return {
        "responses": [
            {
                "body": {"id": 99, "title": {"rendered": "Sample Page"}, "status": "publish"},
                "status": 200,
                "headers": {"Allow": "GET, POST, PUT, PATCH, DELETE"},
            }
        ],
        "failed": None,
    }


def _cookiehash() -> str:
    """WordPress's COOKIEHASH: md5 of the site URL, so 32 hex characters, not 16."""
    return hashlib.md5(f"http://{_SITE_HOST}/".encode(), usedforsecurity=False).hexdigest()


def _debug_log(token: str) -> str:
    """A believable `wp-content/debug.log` tail whose last line leaks a session cookie.

    CVE-2024-44000: the plugin wrote the `Set-Cookie` header of a login response into the
    debug log, and the log was web-readable. The leak is the bait; the honeytoken is derived
    (see `honeytoken`) so using it anywhere is attributable and opens nothing.
    """
    now = datetime.now(UTC)
    lines = []
    for minutes, text in (
        (
            41,
            "PHP Notice:  Function wp_enqueue_script was called incorrectly. in /var/www/html/wp-includes/functions.php on line 6031",
        ),
        (
            33,
            'PHP Warning:  Undefined array key "HTTP_X_FORWARDED_PROTO" in /var/www/html/wp-content/plugins/litespeed-cache/src/router.cls.php on line 218',
        ),
        (12, "LiteSpeed_Cache_Purge: purge_all requested by cron"),
        (
            4,
            f"Cookies: wordpress_logged_in_{_cookiehash()}=admin%7C{int(time.time()) + 1209600}%7C{token}%7C{token[:12]}",
        ),
    ):
        stamp = (now - timedelta(minutes=minutes)).strftime("%d-%b-%Y %H:%M:%S UTC")
        lines.append(f"[{stamp}] {text}")
    return "\n".join(lines) + "\n"


# A real staging directory has one shape. Anything else is not a directory name a WordPress
# upgrade would have produced, so it is not reflected -- which keeps the listing realistic and
# keeps this decoy from being usable as a reflected-XSS gadget against a third party. An
# internet-facing decoy that echoes a path segment into HTML is a weapon pointed outward, and
# "it is only a honeypot" does not change who gets hit.
_STAGING_NAME = re.compile(r"^wordpress-[0-9]+(?:\.[0-9]+)*-working$")


def _upgrade_listing(staging: str | None = None) -> str:
    """An Apache index for `wp-content/upgrade/`, the window CVE-2026-119977 lives in.

    The flaw is that the staging tree is predictable and web-reachable while a core upgrade
    runs, so the bait is the listing existing at all. `staging` names the release the claimed
    version would be upgrading to, derived rather than fixed, and a requested name is used
    only when it has the shape a real staging directory has.
    """
    derived = f"wordpress-{next_version(WP_VERSION)}-working"
    target = staging if staging and _STAGING_NAME.match(staging) else derived
    target = html.escape(target, quote=True)
    stamp = datetime.now(UTC).strftime("%d-%b-%Y %H:%M")
    return (
        '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
        "<html>\n <head>\n  <title>Index of /wp-content/upgrade</title>\n </head>\n"
        " <body>\n<h1>Index of /wp-content/upgrade</h1>\n"
        '<pre><a href="?C=N;O=D">Name</a>                    '
        '<a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>\n<hr>'
        '<a href="/wp-content/">Parent Directory</a>                             -\n'
        f'<a href="{target}/">{target}/</a>   {stamp}       -\n'
        "<hr></pre>\n"
        f"<address>{SERVER_HEADER} Server at {_SITE_HOST} Port {DEFAULT_PORT}</address>\n"
        "</body></html>\n"
    )


def _staging_listing(name: str) -> str:
    """The index *of* the staging directory, listing what a core upgrade puts there."""
    safe = html.escape(
        name if _STAGING_NAME.match(name) else f"wordpress-{next_version(WP_VERSION)}-working",
        quote=True,
    )
    stamp = datetime.now(UTC).strftime("%d-%b-%Y %H:%M")
    return (
        '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
        f"<html>\n <head>\n  <title>Index of /wp-content/upgrade/{safe}</title>\n </head>\n"
        f" <body>\n<h1>Index of /wp-content/upgrade/{safe}</h1>\n"
        '<pre><a href="?C=N;O=D">Name</a>                    '
        '<a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>\n<hr>'
        '<a href="/wp-content/upgrade/">Parent Directory</a>                          -\n'
        f'<a href="wordpress/">wordpress/</a>              {stamp}       -\n'
        "<hr></pre>\n"
        f"<address>{SERVER_HEADER} Server at {_SITE_HOST} Port {DEFAULT_PORT}</address>\n"
        "</body></html>\n"
    )


_LOGIN_FORM = """<!DOCTYPE html>
<html lang="en-US">
<head><meta charset="UTF-8" /><title>Log In &lsaquo; Blog &#8212; WordPress</title></head>
<body class="login js login-action-login wp-core-ui">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" /></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" /></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In" /></p>
</form>
</div>
</body>
</html>
"""


def _index_html() -> str:
    return (
        '<!DOCTYPE html>\n<html lang="en-US">\n<head>\n<meta charset="UTF-8" />\n'
        f'<meta name="generator" content="WordPress {WP_VERSION}" />\n'
        "<title>Blog &#8211; Just another WordPress site</title>\n"
        f'<link rel="stylesheet" href="/wp-content/themes/{WP_THEME}/style.css" />\n'
        '<link rel="https://api.w.org/" href="/wp-json/" />\n'
        '</head>\n<body class="home blog wp-embed-responsive">\n'
        "<main><h1>Blog</h1><p>Welcome to WordPress. This is your first post.</p></main>\n"
        f'<script src="/wp-includes/js/wp-embed.min.js?ver={WP_VERSION}"></script>\n'
        "</body>\n</html>\n"
    )


def _readme_html() -> str:
    return (
        "<!DOCTYPE html>\n<html><head><title>WordPress &rsaquo; ReadMe</title></head>\n"
        f'<body><h1 id="logo">WordPress</h1><p style="text-align:center">Version {WP_VERSION}</p>\n'
        "<h2>Installation</h2><p>Famous 5-minute install</p></body></html>\n"
    )


# --- the decoy --------------------------------------------------------------------------


@dataclass
class Answer:
    """What a bait answers with, and under which name the event records it."""

    status: int
    body: str
    content_type: str = "text/html; charset=UTF-8"
    bait: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    # Was this served by PHP? Apache adds `X-Powered-By` only then -- never to a mod_autoindex
    # listing or a static file, and sending it on those was a tell.
    php: bool = True


class CmsDecoy:
    """One listener, every path. The catch-all is deliberate.

    Routing each bait and letting aiohttp answer the rest would mean the 404 -- the answer a
    scanner uses to decide whether this host is worth attacking -- came from the framework and
    was never recorded. Here every request is seen, recorded and answered by the persona.
    """

    def __init__(self) -> None:
        self._personas = available_personas()
        # Set by `run_server`. The write has to leave the event loop: `sink.write_record`
        # takes an exclusive flock on the event file, and the ingest holds that same lock
        # while shifting the unconsumed tail in 64 KB chunks -- hundreds of MB under a heavy
        # scan. Writing inline stalled every in-flight request for the duration. Same bounded
        # off-loop queue the SharePoint and NetScaler decoys use, for the same reason.
        self._eventlog: EventLog | None = None
        logger.info(
            "personas enabled: %s (default %s), WordPress %s on :%d",
            ",".join(sorted(self._personas)),
            DEFAULT_PERSONA,
            WP_VERSION,
            DEFAULT_PORT,
        )

    # -- provenance ----------------------------------------------------------------------

    def _client_ip_with_origin(self, request: web.Request) -> tuple[str, int, str]:
        """`(src_ip, src_port, origin)` — the address, and how it was learned.

        `X-Real-IP` is honoured only from a configured proxy, never from a direct client: the
        header is sender-controlled, and trusting it from anyone lets an attacker choose the
        address we record about them.
        """
        peer = request.transport.get_extra_info("peername") if request.transport else None
        src_ip = request.remote or (peer[0] if peer else "0.0.0.0")
        origin = proxy_protocol.ORIGIN_PEER
        if peer:
            src_ip, origin = proxy_protocol.http_client_ip_with_origin(
                peer[0],
                src_ip,
                request.headers.get("X-Real-IP", "").strip(),
                os.environ.get("HONEYLENS_HTTP_PROXY", "").strip(),
            )
        src_port = peer[1] if peer and len(peer) > 1 else 0
        return src_ip, src_port, origin

    # -- baits ---------------------------------------------------------------------------

    def answer(self, persona: Persona, method: str, path: str, query: str, body: bytes) -> Answer:
        """The persona's response to one request, and the bait it counts as."""
        if persona.name != "wordpress":  # pragma: no cover - no second persona is enabled yet
            return Answer(404, persona.not_found)
        return self._wordpress(method, path, query, body)

    def _wordpress(self, method: str, path: str, query: str, body: bytes) -> Answer:
        low = path.lower().rstrip("/") or "/"
        q = query.lower()
        route = ""
        if "rest_route=" in q:
            route = q.split("rest_route=", 1)[1].split("&", 1)[0]

        # Bait 1 + 2: the REST API, reached either way round. `?rest_route=` is the same API on
        # an install without pretty permalinks, and it measured more traffic than the pretty
        # form, so both spellings have to answer identically or the decoy contradicts itself.
        if low == "/wp-json/batch/v1" or route.startswith("/batch/v1"):
            if method in ("POST", "PUT", "PATCH"):
                return Answer(
                    207,
                    json.dumps(_batch_response()),
                    "application/json; charset=UTF-8",
                    bait="wp_rest_batch",
                )
            # 404, not 405: the WordPress REST server answers a method mismatch with
            # `rest_no_route` and this exact message. 405 is a shape no WordPress install
            # produces, so it identified the decoy to anything that checks.
            return Answer(
                404,
                json.dumps(
                    {
                        "code": "rest_no_route",
                        "message": "No route was found matching the URL and request method.",
                        "data": {"status": 404},
                    }
                ),
                "application/json; charset=UTF-8",
                bait="wp_rest_batch_probe",
            )

        if low.startswith("/wp-json") or route:
            target = route or low[len("/wp-json") :]
            if "/wp/v2/users" in target:
                return Answer(
                    200,
                    json.dumps(_REST_USERS),
                    "application/json; charset=UTF-8",
                    bait="wp_rest_users",
                )
            if "/wp/v2/pages" in target or "/wp/v2/posts" in target:
                return Answer(
                    200,
                    json.dumps(_REST_PAGES),
                    "application/json; charset=UTF-8",
                    bait="wp_rest_content",
                )
            if target in ("", "/"):
                return Answer(
                    200,
                    json.dumps(
                        {
                            "name": "Blog",
                            "description": "Just another WordPress site",
                            "namespaces": ["wp/v2", "batch/v1"],
                        }
                    ),
                    "application/json; charset=UTF-8",
                    bait="wp_rest_index",
                )
            return Answer(
                404,
                json.dumps(
                    {
                        "code": "rest_no_route",
                        "message": "No route was found matching the URL and request method.",
                        "data": {"status": 404},
                    }
                ),
                "application/json; charset=UTF-8",
                bait="wp_rest_unknown",
            )

        # Bait 3: the debug log, readable, with a session cookie in its tail.
        if low == "/wp-content/debug.log":
            return Answer(
                200,
                _debug_log(honeytoken("wp-debug-log")),
                "text/plain; charset=UTF-8",
                bait="wp_debug_log",
                php=False,
            )

        # Bait 4: the core-upgrade staging window, listable.
        if low == "/wp-content/upgrade":
            return Answer(200, _upgrade_listing(), bait="wp_upgrade_window", php=False)
        if low.startswith("/wp-content/upgrade/wordpress-"):
            segments = low[len("/wp-content/upgrade/") :].split("/")
            if len(segments) == 1:
                return Answer(
                    200, _staging_listing(segments[0]), bait="wp_upgrade_staging", php=False
                )
            # A path INSIDE the staging tree. The CVE-2026-119977 chain asks for files there,
            # and answering every one of them with the listing of the parent directory was
            # the wrong document for the request.
            return Answer(404, _WP_404)

        # The static files a real install serves, and the two the index page references.
        # They mattered: a scanner that fetches the stylesheet it was just told about, or
        # follows `/wp-admin/`, and gets a 404 concludes this is not WordPress and leaves.
        if low == f"/wp-content/themes/{WP_THEME}/style.css":
            return Answer(
                200,
                "/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.0\n*/\n:root{--wp--preset--color--base:#fff}\n",
                "text/css; charset=UTF-8",
                bait="wp_theme_asset",
                php=False,
            )
        if low == "/wp-includes/js/wp-embed.min.js":
            return Answer(
                200,
                '/*! This file is auto-generated */\n!function(c,d){"use strict";}(window,document);\n',
                "application/javascript; charset=UTF-8",
                bait="wp_core_asset",
                php=False,
            )
        if low == "/robots.txt":
            return Answer(
                200,
                "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n\n"
                f"Sitemap: http://{_SITE_HOST}/wp-sitemap.xml\n",
                "text/plain; charset=UTF-8",
                bait="wp_robots",
                php=False,
            )
        if low == "/feed":
            return Answer(
                200,
                '<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel>'
                "<title>Blog</title><link>/</link>"
                f"<generator>https://wordpress.org/?v={WP_VERSION}</generator>"
                "</channel></rss>\n",
                "application/rss+xml; charset=UTF-8",
                bait="wp_feed",
            )
        # A real install redirects an unauthenticated `/wp-admin/` to the login form rather
        # than 404-ing it, and the redirect target is how a bot finds the form.
        if low == "/wp-admin" or low.startswith("/wp-admin/"):
            return Answer(
                302,
                "",
                "text/html; charset=UTF-8",
                bait="wp_admin_probe",
                headers={"Location": f"/wp-login.php?redirect_to={low}%2F&reauth=1"},
            )

        # Enough of a site to pass a version check, which every multi-step exploit does first.
        if low == "/":
            return Answer(200, _index_html(), bait="wp_index")
        if low == "/readme.html":
            return Answer(200, _readme_html(), bait="wp_readme")
        if low == "/wp-login.php":
            if method == "POST":
                # Credentials posted. Answered as a failed login, because a decoy that accepts
                # them stops the sequence; a decoy that rejects them gets the next attempt.
                return Answer(
                    200,
                    _LOGIN_FORM.replace(
                        '<form name="loginform"',
                        '<div id="login_error"><strong>Error:</strong> The password you entered is incorrect.</div>\n<form name="loginform"',
                    ),
                    bait="wp_login_post",
                )
            # A real install sets this on the form, and `Persona.cookie_name` existed
            # without ever being used -- a login page that sets no cookie is a tell.
            return Answer(
                200,
                _LOGIN_FORM,
                bait="wp_login_form",
                headers={"Set-Cookie": "wordpress_test_cookie=WP%20Cookie%20check; path=/"},
            )
        if low == "/xmlrpc.php":
            if method != "POST":
                return Answer(
                    405,
                    "XML-RPC server accepts POST requests only.",
                    "text/plain; charset=UTF-8",
                    headers={"Allow": "POST"},
                    bait="wp_xmlrpc_probe",
                )
            return Answer(
                200,
                '<?xml version="1.0" encoding="UTF-8"?>\n<methodResponse><params><param><value>'
                "<array><data><value><string>Incorrect username or password.</string></value></data></array>"
                "</value></param></params></methodResponse>\n",
                "text/xml; charset=UTF-8",
                bait="wp_xmlrpc",
            )

        # Everything else: WordPress's own 404. The soft-404 baseline every serious scanner
        # takes is the reason this is a real 404 and not a 200 -- a host that answers 200 to a
        # path that cannot exist is discarded before any bait is ever probed.
        return Answer(404, _WP_404)

    # -- request path --------------------------------------------------------------------

    async def handle(self, request: web.Request) -> web.Response:
        src_ip, src_port, client_ip_from = self._client_ip_with_origin(request)
        try:
            # `request.read()`, not `request.content.read(n)`. The latter returns whatever is
            # already buffered as soon as any data is present, so a body split across TCP
            # writes was truncated to its first chunk -- measured: 20,000 bytes sent in two
            # writes 400 ms apart recorded `body_len=1000` with `body_truncated=False`, so the
            # stage-two payload this decoy exists to capture was dropped AND the event claimed
            # to be complete. aiohttp still bounds it by `client_max_size` (MAX_BODY).
            body = await request.read()
            read_error = None
        except Exception as exc:
            body, read_error = b"", type(exc).__name__

        persona = resolve_persona(request.path_qs, self._personas)
        try:
            answer = self.answer(persona, request.method, request.path, request.query_string, body)
            answer_error = None
        except Exception as exc:  # pragma: no cover - no bait raises today
            # The capture comes first. A bait that throws must cost us the response, never the
            # record of what was sent -- that record is the only artefact of the request.
            logger.warning("bait raised (%s): %s", type(exc).__name__, exc)
            answer = Answer(500, _WP_404)
            answer_error = type(exc).__name__
        budget = capture_budget(answer.bait)

        # `raw_headers`, not `headers.items()`: the latter is the parser-normalised multidict,
        # so a client sending `content-type:` was recorded as `Content-Type`. The sender's
        # casing is a fingerprint the hunts read straight out of `metadata->>'headers'`.
        headers_ordered = [
            (k.decode("latin-1", "replace"), v.decode("latin-1", "replace"))
            for k, v in request.raw_headers
        ]
        headers = dict(headers_ordered)
        local_port = (
            request.transport.get_extra_info("sockname")[1] if request.transport else DEFAULT_PORT
        )

        event: dict[str, Any] = {
            "honeypot": "cms",
            "cms_persona": persona.name,
            "method": request.method,
            "path": request.path,
            "query": request.query_string,
            "http_version": f"{request.version.major}.{request.version.minor}",
            "status": answer.status,
            "headers_ordered": headers_ordered,
            "headers": headers,
            **capture_body(body, request.path, headers.get("Content-Type", ""), max_capture=budget),
        }
        if answer.bait:
            event["cms_bait"] = answer.bait
        # Only when the address is not the peer's. A row carrying this key is never classified
        # as ours -- see intelligence/source_class.classify_source.
        if client_ip_from != proxy_protocol.ORIGIN_PEER:
            event["client_ip_from"] = client_ip_from
        if read_error:
            event["read_error"] = read_error
        if answer_error:
            event["answer_error"] = answer_error

        head = f"{request.method} {request.path_qs} HTTP/{event['http_version']}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in headers_ordered) + "\r\n"
        raw = head.encode("latin-1", "replace") + body
        payload = (
            body[:2000].decode("utf-8", "replace")
            if body
            else f"{request.method} {request.path_qs}"
        )

        self._emit(
            event=event,
            payload=payload,
            raw=raw,
            peer=(src_ip, src_port),
            dst_port=local_port,
            budget=budget,
        )
        logger.info(
            "[%s] %s %s %s -> %d%s",
            persona.name,
            src_ip,
            request.method,
            request.path_qs[:120],
            answer.status,
            f" bait={answer.bait}" if answer.bait else "",
        )

        # `body=` with an explicit Content-Type, not `text=`+`content_type=`: the latter has
        # aiohttp append `charset=utf-8` lowercase, where PHP and Apache emit `charset=UTF-8`.
        resp = web.Response(
            status=answer.status,
            body=answer.body.encode("utf-8"),
            headers={"Content-Type": answer.content_type},
        )
        resp.headers["Server"] = persona.server
        if answer.php:
            resp.headers["X-Powered-By"] = persona.powered_by
        for k, v in {**persona.extra_headers, **answer.headers}.items():
            resp.headers[k] = v
        return resp

    def _emit(
        self, *, event: dict, payload: str, raw: bytes, peer: tuple, dst_port: int, budget: int
    ) -> None:
        """Hand the event to the off-loop queue, or write it inline when running standalone."""
        try:
            record = sink.build_record(
                source="cms",
                honeypot="cms",
                protocol="http",
                peer=peer,
                event=event,
                payload=payload,
                dst_port=dst_port,
                raw=raw,
                raw_capture_bytes=budget,
            )
        except Exception as exc:  # pragma: no cover - a decoy must not die building a record
            logger.warning("could not build the record (%s): %s", type(exc).__name__, exc)
            return
        if self._eventlog is not None:
            if not self._eventlog.submit(record):
                logger.warning("event queue full, dropped %s", event.get("path"))
            return
        try:
            if not sink.write_record(record):
                logger.warning("sink refused the record for %s", event.get("path"))
        except Exception as exc:  # pragma: no cover - a decoy must not die on a write failure
            logger.warning("sink write failed (%s): %s", type(exc).__name__, exc)


def _mask_server_banner() -> None:
    """Make aiohttp's default ``Server`` the Apache banner everywhere.

    Including the 400/413/431 responses aiohttp generates *before* the app runs, which the
    per-response path cannot reach. Measured without this: a request line over 8190 bytes, and
    a TLS ClientHello sent to the plaintext port, both answered
    `Server: Python/3.12 aiohttp/3.14.5` and produced no event at all -- the one response that
    says "decoy", handed out for a routine scanner input.
    """
    try:
        from aiohttp import web_response

        web_response.SERVER_SOFTWARE = SERVER_HEADER
    except Exception as exc:  # pragma: no cover
        logger.debug("could not mask the aiohttp banner: %s", exc)


def build_app(decoy: CmsDecoy | None = None) -> web.Application:
    app = web.Application(client_max_size=MAX_BODY)
    app["decoy"] = decoy or CmsDecoy()
    app.on_response_prepare.append(deception_waf.on_response_prepare)
    app.router.add_route("*", "/{tail:.*}", app["decoy"].handle)
    return app


async def run_server(host: str, port: int) -> None:
    _mask_server_banner()
    decoy = CmsDecoy()
    decoy._eventlog = EventLog(sink=sink, log_file="")
    await decoy._eventlog.start()
    runner = web.AppRunner(build_app(decoy), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logger.info("hp-cms listening on %s:%d", host, port)
    await asyncio.Event().wait()  # serve until the unit stops us


def main() -> int:
    parser = argparse.ArgumentParser(description="CMS decoy (WordPress profile)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    try:
        asyncio.run(run_server(args.host, args.port))
    except KeyboardInterrupt:
        logger.info("shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
