"""CVE-2024-4577 must be named, and must not be claimed by a length-based heuristic.

A real capture on a sensor was reported as CVE-2026-42533 —
the NGINX script-engine overflow, which has no public PoC and whose matcher is
explicitly length-based — because the request's base64 body was 1149 bytes. The
request was a textbook PHP-CGI argument injection whose own payload ends
`echo(md5("Hello CVE-2024-4577"))`.

Two properties are pinned here:
  1. the attack gets its own, correct name;
  2. the heuristic 42533 matcher yields to it rather than mislabelling it.

CVE-2024-4577 verified against NVD on 2026-08-27: published 2024-06-09, status
Analyzed, PHP 8.1.<29 / 8.2.<20 / 8.3.<8 on Windows with Apache + PHP-CGI.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row

# the request as it actually arrived
PATH = "/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
BODY = (
    '<?php shell_exec(base64_decode("'
    + "Y2QgL3RtcCB8fCBjZCAvdmFyL3RtcA==" * 30
    + '")); echo(md5("Hello CVE-2024-4577")); ?>'
)


def _rules(payload, port=8443):
    return {
        h[1]
        for h in classify_event_row(payload=payload, protocol="HTTP", metadata={"dst_port": port})
    }


def test_the_real_capture_is_named_correctly():
    hits = _rules(f"POST {PATH} HTTP/1.1\r\n\r\n{BODY}")
    assert "php_cgi_argument_injection_cve_2024_4577" in hits


def test_the_soft_hyphen_switch_is_enough_on_its_own():
    """The query string alone identifies the exploit — no body required."""
    assert "php_cgi_argument_injection_cve_2024_4577" in _rules(f"GET {PATH} HTTP/1.1")


@pytest.mark.parametrize("raw", ["%ad", "%AD", "\xad"])
def test_both_encodings_of_the_soft_hyphen(raw):
    assert "php_cgi_argument_injection_cve_2024_4577" in _rules(
        f"GET /x?{raw}d+allow_url_include%3d1 HTTP/1.1"
    )


def test_the_directive_pair_is_caught_however_it_was_smuggled():
    assert "php_cgi_include_prepend_pair" in _rules(
        "POST /x HTTP/1.1\r\n\r\nallow_url_include=1&auto_prepend_file=php://input"
    )


@pytest.mark.parametrize(
    "payload,what",
    [
        ("GET /info.php HTTP/1.1", "an ordinary request"),
        (
            "POST /cfg HTTP/1.1\r\n\r\nauto_prepend_file = /var/www/prepend.php",
            "a legitimate php.ini value — auto_prepend_file alone is not an attack",
        ),
        (
            "POST /upload HTTP/1.1\r\n\r\n" + "A" * 4000,
            "a long body with no fingerprint — the defect being fixed",
        ),
    ],
)
def test_no_false_positives(payload, what):
    hits = _rules(payload)
    assert not {h for h in hits if "4577" in h or "include_prepend" in h}, what


def test_it_scores_critical():
    from honeylens.classification.scoring import get_severity

    assert get_severity("RCE", "php_cgi_argument_injection_cve_2024_4577") == "critical"


# ------------------------------------------------------- the NGINX signature guard


def test_42533_yields_to_a_php_cgi_argument_injection():
    """The heuristic must not claim a request that identifies itself as another CVE."""
    from honeylens.honeypots.nginx import signatures as sig

    m = sig._match_42533("POST", PATH.encode(), {}, BODY.encode(), b"HTTP/1.1")
    assert m is None, "42533 still claims a CVE-2024-4577 request"


def test_42533_still_fires_on_its_own_shape():
    """The guard must not disarm the signature for traffic it is actually for."""
    from honeylens.honeypots.nginx import signatures as sig

    m = sig._match_42533("POST", b"/x", {}, b"A" * 1200, b"HTTP/1.1")
    assert m is not None and any("cve_2026_42533_overflow" in i for i in m.indicators)


def test_the_42533_matcher_is_still_honest_about_being_heuristic():
    """If this ever becomes a confident signature the guard should be revisited."""
    from honeylens.honeypots.nginx import signatures as sig

    m = sig._match_42533("POST", b"/x", {}, b"A" * 1200, b"HTTP/1.1")
    assert m.confidence == "low"
