"""Content-management systems, starting with WordPress.

A new subject file rather than additions to `scanners.py` or `web_injection.py`: this is
neither a scanner fingerprint nor an injection, it is a product, and the package is organised
by subject — `appliance.py`, `cloud_container.py`, `database.py`, `ics.py`, `wago.py`. The
2026-11-04 measurement also saw Magento (`/index.php/catalogsearch/…`), Lotus Domino
(`/names.nsf/People`) and JBoss (`/invoker/JMXInvokerServlet`) arriving on the same decoys;
they belong here when their turn comes.

Why these rules exist at all: before them there was **no WordPress verdict in the committed
registry**. `scanners.py` lists `wp-admin|wp-login|wp-config|xmlrpc.php` inside the generic
`scan_vuln_paths` SCANNER pattern and does not mention `wp-json` or `wp-content`, so the REST
API and every plugin path got nothing. A lowercase `wordpress_scan` rule existed on `sensor-a`
(3,621 rows) and `prod` (17) as an uncommitted custom rule, which left `sensor-b`, `sensor-c`,
`sensor-e` and `sensor-f` with nothing.

Measured unlabelled WordPress-shaped requests: `sensor-b` 3,690 of 6,305 (58%), `sensor-a` 4,739 of
13,513 (35%), `sensor-c` 917 of 2,159 (42%), `sensor-e` 56 of 117 (48%).

Two verdicts, so the dashboard can tell apart the two things actors actually do here:
`WORDPRESS_RECON` for finding out what is installed and who the authors are, and
`WORDPRESS_CRED` for going after the credentials. The ordering is pinned in
`tests/test_wordpress_verdicts.py`, not left to a default.
"""

from __future__ import annotations

import re


def register(add):
    # --- Enumeration -------------------------------------------------------------------
    #
    # The REST API is the half that had no rule at all. `/wp-json/wp/v2/users` lists author
    # accounts, which is how a password-spray run gets its user list; `?rest_route=` is the
    # same API for installs without pretty permalinks.
    add(
        "WORDPRESS_RECON",
        "wordpress_content_enum",
        r"(/wp-json(/|\b)|[?&]rest_route=/wp/)",
        re.IGNORECASE,
    )

    # `wp-content` likewise appeared nowhere. Reading a plugin's readme.txt establishes its
    # version and therefore its known CVEs, and `/wp-content/uploads/.../*.php` is where a
    # dropped webshell lands.
    add(
        "WORDPRESS_RECON",
        "wordpress_plugin_probe",
        r"/wp-content/(plugins|themes|uploads)/",
        re.IGNORECASE,
    )

    # A GET of the admin surface or the login form is enumeration. It stays below the
    # credential rules below — the same discipline as `k8s_proxy_port_probe` and
    # `appliance_port_probe`, where asking is not the same as doing.
    add(
        "WORDPRESS_RECON",
        "wordpress_admin_probe",
        r"/(wp-admin|wp-login\.php|wp-includes/|wp-cron\.php|readme\.html)",
        re.IGNORECASE,
    )

    # --- Credentials and secrets -------------------------------------------------------
    #
    # A POSTed login form, matched on the body's own field names rather than on the path, so
    # a GET of the same URL does not read as an attempt.
    add(
        "WORDPRESS_CRED",
        "wordpress_login_attempt",
        r"\blog=[^&\s]*&?.*\bpwd=|\bpwd=[^&\s]*&?.*\blog=|\bwp-submit=",
        re.IGNORECASE,
    )

    # One request carrying hundreds of `wp.getUsersBlogs` calls is the standard way to brute
    # force WordPress without sending hundreds of requests, which is why it outranks a single
    # login attempt.
    add(
        "WORDPRESS_CRED",
        "wordpress_xmlrpc_multicall",
        r"system\.multicall|wp\.getUsersBlogs|metaWeblog\.getUsersBlogs",
        re.IGNORECASE,
    )

    # The debug log, when a plugin wrote a `Set-Cookie` into it and the file stayed
    # web-readable — CVE-2024-44000. What comes back is a live `wordpress_logged_in_*`
    # cookie, so this sits above a login attempt and below `wp-config.php`, which also hands
    # over the database. Measured 2026-11-08 on the public sensor: 34 requests from 25
    # sources in 30 days, every one of them labelled `SCANNER` and nothing else. Not covered
    # by `wordpress_plugin_probe`, which only matches the plugins/themes/uploads subtrees.
    add(
        "WORDPRESS_CRED",
        "wordpress_debug_log_probe",
        r"/wp-content/(debug|error)\.log\b",
        re.IGNORECASE,
    )

    # --- Specific CVE preconditions ----------------------------------------------------
    #
    # Two surfaces that are not generic enumeration: each is the precondition check for one
    # named core flaw, which is why they outrank `wordpress_content_enum` without claiming
    # the exploit itself. A GET establishes whether the door exists; the payload that walks
    # through it is a separate request and gets its own verdict from the injection rules.

    # `/wp-content/upgrade/` is web-reachable only while a core upgrade is staged, which is
    # the window CVE-2026-119977 (CISA KEV 2026-11-03) lives in. 25 requests from 6 sources.
    add(
        "WORDPRESS_RECON",
        "wordpress_upgrade_window_probe",
        r"/wp-content/upgrade(/|\b)",
        re.IGNORECASE,
    )

    # The REST batch endpoint, the entry to the CVE-2026-63030 chain (CISA KEV 2026-07-21;
    # six rows of it in our own 30-day window). 238 requests from 9 sources. Both spellings,
    # because `wordpress_content_enum` only accepts `rest_route=/wp/` and the batch route is
    # `rest_route=/batch/` — measured: the pretty form was labelled and the query form was
    # not, for the same request against the same API.
    add(
        "WORDPRESS_RECON",
        "wordpress_rest_batch",
        # `(?:^|[?&])` and not `[?&]`: the classifier scans `metadata["query"]` as its own
        # target, where the value arrives as a bare `rest_route=...` with no separator in
        # front of it. Anchoring on either makes the rule fire whether it sees the full
        # request line or just the query. (`wordpress_content_enum` above still has the
        # narrow form and therefore the same blind spot on that one target.)
        r"(/wp-json/batch/v\d|(?:^|[?&])rest_route=/batch/)",
        re.IGNORECASE,
    )

    # `wp-config.php` holds the database credentials and the auth salts in cleartext, so a
    # reachable copy of it is the end of the engagement rather than a step in it. The live
    # file is executed, never served, so what is hunted are the backup spellings.
    add(
        "WORDPRESS_CRED",
        "wordpress_config_exposure",
        r"/wp-config\.php[-._~]|/wp-config\.php\.(bak|old|orig|save|swp|txt|zip|gz)|"
        r"/wp-config\.(bak|old|orig|save|txt)",
        re.IGNORECASE,
    )
