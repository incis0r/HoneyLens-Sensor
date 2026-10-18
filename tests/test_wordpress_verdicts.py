"""WordPress gets verdicts of its own, graded by what the request actually does.

B7, the other half of the section 5.5 finding. **There was no WordPress verdict in the
committed registry.** `rules/scanners.py:138` lists `wp-admin|wp-login|wp-config|xmlrpc.php`
inside the generic `scan_vuln_paths` SCANNER pattern and does not mention `wp-json` or
`wp-content` at all, so measured through the PAN-OS captive ingest before this change:

    /wp-json/wp/v2/posts?per_page=1         -> nothing
    /wp-content/plugins/revslider/tout.php  -> nothing
    /wp-login.php                           -> SCANNER / scan_vuln_paths
    /xmlrpc.php                             -> SCANNER / scan_vuln_paths
    /wp-admin/                              -> SCANNER / scan_vuln_paths

A lowercase `wordpress_scan` rule does exist, but only on `sensor-a` (3,621 rows) and `prod`
(17), as a custom rule that was never committed — so `sensor-b`, `sensor-c`, `sensor-e` and `sensor-f`
have nothing at all.

Measured unlabelled WordPress-shaped requests: `sensor-b` 3,690 of 6,305 (58%), `sensor-a` 4,739 of
13,513 (35%), `sensor-c` 917 of 2,159 (42%), `sensor-e` 56 of 117 (48%).

The grading this file pins: posting credentials outranks asking which plugins are installed,
and `xmlrpc.php` with `system.multicall` outranks a single login attempt because one request
carries hundreds of them. A bare `/wp-admin` GET is enumeration, not an exploit — the same
discipline as `k8s_proxy_port_probe` and `appliance_port_probe`.

They live in `rules/cms.py` rather than `scanners.py` or `web_injection.py`: this is neither a
scanner fingerprint nor an injection, it is a product, and the package is organised by subject
(`appliance.py`, `cloud_container.py`, `database.py`, `ics.py`, `wago.py`). The measurement
also saw Magento, Lotus Domino and JBoss arriving on the same decoys, and they belong in the
same file when their turn comes.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.mitre_mapping import get_mitre_mapping
from honeylens.classification.scoring import RULE_SEVERITY_OVERRIDE, get_severity

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

ENUM = "wordpress_content_enum"
PLUGIN = "wordpress_plugin_probe"
LOGIN = "wordpress_login_attempt"
MULTICALL = "wordpress_xmlrpc_multicall"
CONFIG = "wordpress_config_exposure"


def _hits(path, method="GET", body=""):
    payload = f"{method} {path} HTTP/1.1\r\nHost: blog\r\n\r\n{body}"
    return classify_event_row(
        payload=payload, protocol="http", metadata={"dst_port": 80, "path": path, "method": method}
    )


def _rules(path, **kw):
    return {h[1] for h in _hits(path, **kw)}


def _worst(path, **kw):
    hits = _hits(path, **kw)
    assert hits, path
    return max(_RANK[get_severity(h[0], h[1])] for h in hits)


# ---------------------------------------------------------------------------
# Enumeration: the half that had no verdict at all
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/wp-json/wp/v2/posts?per_page=1",
        "/wp-json/wp/v2/users",
        "/wp-json/",
        "/?rest_route=/wp/v2/users",
    ],
)
def test_the_rest_api_is_content_enumeration(path):
    """`wp-json` appeared in no committed rule. `/wp-json/wp/v2/users` is how an actor lists
    author accounts before trying passwords against them."""
    assert ENUM in _rules(path)


@pytest.mark.parametrize(
    "path",
    [
        "/wp-content/plugins/revslider/tout.php",
        "/wp-content/plugins/wp-file-manager/readme.txt",
        "/wp-content/themes/twentytwenty/style.css",
        "/wp-content/uploads/2026/01/shell.php",
    ],
)
def test_plugin_and_theme_paths_are_a_probe(path):
    """`wp-content` appeared in no committed rule either. Reading a plugin's readme.txt is how
    its version — and so its known CVEs — gets established."""
    assert PLUGIN in _rules(path)


def test_a_bare_admin_get_is_enumeration_not_an_exploit():
    types = {h[0] for h in _hits("/wp-admin/")}

    assert "WORDPRESS_RECON" in types
    assert _worst("/wp-admin/") <= _RANK["medium"]


# ---------------------------------------------------------------------------
# Credential abuse, which outranks it
# ---------------------------------------------------------------------------


def test_a_login_post_is_credential_abuse():
    rules = _rules("/wp-login.php", method="POST", body="log=admin&pwd=hunter2&wp-submit=Log+In")

    assert LOGIN in rules


def test_xmlrpc_multicall_is_named_for_what_it_amplifies():
    """One request carrying hundreds of `wp.getUsersBlogs` calls is the standard way to brute
    force WordPress without hundreds of requests."""
    body = (
        "<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName>"
        "<params><param><value><array><data><value><struct>"
        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "</struct></value></data></array></value></param></params></methodCall>"
    )

    assert MULTICALL in _rules("/xmlrpc.php", method="POST", body=body)


def test_posting_credentials_outranks_asking_what_is_installed():
    login = _worst("/wp-login.php", method="POST", body="log=admin&pwd=x&wp-submit=Log+In")
    enumeration = _worst("/wp-json/wp/v2/users")

    assert login > enumeration, (login, enumeration)


def test_a_multicall_outranks_a_single_login():
    body = "<methodCall><methodName>system.multicall</methodName></methodCall>"
    multicall = _worst("/xmlrpc.php", method="POST", body=body)
    login = _worst("/wp-login.php", method="POST", body="log=admin&pwd=x&wp-submit=Log+In")

    assert multicall > login, (multicall, login)


def test_reaching_wp_config_is_the_worst_of_them():
    """`wp-config.php` holds the database credentials and the auth salts in cleartext."""
    assert CONFIG in _rules("/wp-config.php.bak")
    assert _worst("/wp-config.php.bak") >= _RANK["high"]


# ---------------------------------------------------------------------------
# It does not over-reach
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/secrets",
        "/php/uid.php",
        "/v3/kv/range",
        "/wordpress-is-mentioned-in-this-path-only",
        "/content/plugins/x.php",
        "/json/wp/v2/posts",
    ],
)
def test_nothing_that_is_not_wordpress_gets_a_wordpress_verdict(path):
    rules = _rules(path)

    assert not any(r.startswith("wordpress_") for r in rules), (path, rules)


def test_a_get_to_wp_login_is_not_a_credential_attempt():
    """Fetching the login form is enumeration. Measured: most `/wp-login.php` rows are GETs."""
    rules = _rules("/wp-login.php")

    assert LOGIN not in rules
    assert any(r.startswith("wordpress_") for r in rules), rules


# ---------------------------------------------------------------------------
# Scored and mapped
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule", [ENUM, PLUGIN, LOGIN, MULTICALL, CONFIG])
def test_every_new_rule_is_scored_and_mapped(rule):
    assert rule in RULE_SEVERITY_OVERRIDE, rule
    for attack_type in ("WORDPRESS_RECON", "WORDPRESS_CRED"):
        assert get_mitre_mapping(attack_type), attack_type


def test_the_new_attack_types_have_severities():
    from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY

    for attack_type in ("WORDPRESS_RECON", "WORDPRESS_CRED"):
        assert attack_type in ATTACK_TYPE_SEVERITY, attack_type
