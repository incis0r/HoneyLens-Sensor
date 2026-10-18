"""Answering a web-shell hunt without doing it under someone else's name.

The bait exists to learn what a scanner sends *after* it believes it found a
shell. The constraint is that a recycled address can inherit a stranger's DNS, so
some of that traffic arrives carrying their hostname - and answering "200, the
shell is here" under their name would manufacture evidence that their site is
compromised.

These tests pin that the refusal wins over the bait, that the bait stays off
unless switched on, and that the path list stays narrow enough not to change what
the honeypot measures.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from honeylens.honeypots import shell_bait as sb


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("HP_HTTP_SHELL_BAIT", "HP_HTTP_FOREIGN_HOSTS", "HP_HTTP_SHELL_BAIT_EXTRA"):
        monkeypatch.delenv(k, raising=False)
    yield


def _on(monkeypatch):
    monkeypatch.setenv("HP_HTTP_SHELL_BAIT", "true")


def _foreign(monkeypatch, doms="sfos.example"):
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", doms)


# ------------------------------------------------- refusing a foreign hostname


def test_a_foreign_host_is_refused_not_baited(monkeypatch):
    """The whole point. Even a shell probe gets 421 under someone else's name."""
    _on(monkeypatch)
    _foreign(monkeypatch)
    assert sb.decide("/this_is_a_new_hello_world.php", "sfos.example") == "misdirected"


def test_subdomains_of_a_foreign_host_are_refused_too(monkeypatch):
    _on(monkeypatch)
    _foreign(monkeypatch)
    for h in ("www.sfos.example", "assets.sfos.example", "ns2.sfos.example"):
        assert sb.decide("/1.php", h) == "misdirected", h


def test_the_port_and_a_trailing_dot_do_not_defeat_the_check(monkeypatch):
    """Resolvers send a trailing dot and clients append the port; both were seen."""
    _on(monkeypatch)
    _foreign(monkeypatch)
    assert sb.decide("/1.php", "sfos.example:80") == "misdirected"
    assert sb.decide("/1.php", "sfos.example.") == "misdirected"


def test_a_lookalike_domain_is_not_treated_as_foreign(monkeypatch):
    """Suffix matching must not catch notsfos.example."""
    _on(monkeypatch)
    _foreign(monkeypatch)
    assert sb.decide("/1.php", "notsfos.example") == "bait"


def test_a_foreign_host_is_refused_even_for_an_ordinary_page(monkeypatch):
    """Refusal is not part of the deception - it applies with the bait switched off."""
    _foreign(monkeypatch)
    assert sb.bait_enabled() is False
    assert sb.decide("/", "www.sfos.example") == "misdirected"


def test_no_foreign_list_means_nothing_is_refused(monkeypatch):
    _on(monkeypatch)
    assert sb.decide("/", "anything.example") is None


# ------------------------------------------------------------ the bait itself


def test_bait_is_off_unless_switched_on(monkeypatch):
    assert sb.decide("/this_is_a_new_hello_world.php", "1.2.3.4") is None


def test_a_known_shell_name_is_baited(monkeypatch):
    _on(monkeypatch)
    for p in (
        "/this_is_a_new_hello_world.php",
        "/4PJcpMFsD8B.php",
        "/ops.php",
        "/wp-content/plugins/hellopress/wp_filemanager.php",
    ):
        assert sb.decide(p, "198.51.100.7") == "bait", p


def test_a_query_string_does_not_hide_the_name(monkeypatch):
    _on(monkeypatch)
    assert sb.decide("/1.php?pass=x", "1.2.3.4") == "bait"


def test_ordinary_traffic_is_left_alone(monkeypatch):
    """A broad match would have the honeypot answering 200 to much of what scans
    it, changing what the sensor measures."""
    _on(monkeypatch)
    for p in (
        "/",
        "/index.php",
        "/wp-login.php",
        "/favicon.ico",
        "/robots.txt",
        "/index.html",
        "/api/v1/status",
        "/wp-content/plugins/foo/readme.php",
    ):
        assert sb.decide(p, "1.2.3.4") is None, p


def test_the_list_can_be_extended_without_a_code_change(monkeypatch):
    _on(monkeypatch)
    assert sb.decide("/zzz-new-shell.php", "1.2.3.4") is None
    monkeypatch.setenv("HP_HTTP_SHELL_BAIT_EXTRA", "zzz-new-shell.php")
    assert sb.decide("/zzz-new-shell.php", "1.2.3.4") == "bait"


# ---------------------------------------------------------------- the response


def test_the_bait_reply_is_an_empty_200():
    r = sb.build("bait", "Apache/2.4.66 (Ubuntu)").decode()
    assert r.startswith("HTTP/1.1 200 OK")
    assert "Content-Length: 0" in r
    assert r.endswith("\r\n\r\n"), "an empty body gives nothing to fingerprint"


def test_the_refusal_is_421_with_no_content():
    r = sb.build("misdirected", "Apache/2.4.66 (Ubuntu)").decode()
    assert r.startswith("HTTP/1.1 421 Misdirected Request")
    assert "Content-Length: 0" in r


def test_the_server_header_still_matches_the_decoy_identity():
    """A reply that drops the header the rest of the honeypot sends would mark
    these two paths as special."""
    for mode in ("bait", "misdirected"):
        assert "Server: Apache/2.4.66 (Ubuntu)" in sb.build(mode, "Apache/2.4.66 (Ubuntu)").decode()


# ------------------------------------------------------------- wiring into http


def test_the_handler_records_which_reply_it_served():
    """Without this the follow-up POST cannot be tied to the bait that caused it."""
    src = open(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "src",
            "honeylens",
            "honeypots",
            "hp_http.py",
        )
    ).read()
    assert "shell_bait.decide(" in src
    assert 'event["response_mode"] = mode' in src
    assert src.index("shell_bait.decide(") < src.index("log_event("), (
        "the decision must be made before the event is logged"
    )


# ---------------------------------------------------------------------------
# Host claims: the union, and the one table of spellings
#
# This guard shipped a bypass in four consecutive review rounds, every time
# because a reader reasoned about one or two spellings of a host claim and a
# legal third existed. `host_claims` is the answer to that — every spelling in
# one place, and `decide` refusing if ANY of them is foreign. This is the matrix
# that pins it; a sixth spelling adds a row here.
# ---------------------------------------------------------------------------

FOREIGN = "victim.example"
OURS = "decoy.invalid"


def _claims_foreign(monkeypatch):
    monkeypatch.setenv("HP_HTTP_FOREIGN_HOSTS", FOREIGN)


@pytest.mark.parametrize(
    ("label", "kwargs"),
    [
        # 1. the HTTP/1.1 Host header
        ("host header", {"host_header": FOREIGN}),
        # 2. an authority inside the HTTP/1.1 request-target
        ("absolute-form target", {"target": f"http://{FOREIGN}/x"}),
        ("authority-form target", {"target": f"{FOREIGN}:80"}),
        ("network-path target", {"target": f"//{FOREIGN}/x"}),
        # 3. the HTTP/2 :authority pseudo-header
        ("h2 :authority", {"authority": FOREIGN}),
        # 4. a host header on an HTTP/2 stream
        ("h2 host header", {"host_header": FOREIGN}),
        # 5. an authority inside an absolute HTTP/2 :path
        ("h2 absolute :path", {"target": f"http://{FOREIGN}/"}),
        # ... and `Host` sent more than once counts in every position, not just last.
        ("duplicate Host, foreign first", {"host_header": [FOREIGN, OURS]}),
        ("duplicate Host, foreign last", {"host_header": [OURS, FOREIGN]}),
        ("duplicate Host, foreign middle", {"host_header": [OURS, FOREIGN, "also.ours"]}),
        # ... and every spelling still counts when another claim is our own. This is the
        # whole point of a union: the regression it replaced let a target authority
        # REPLACE a foreign Host, so one extra slash un-refused the request.
        ("foreign target, our host", {"target": f"http://{FOREIGN}/", "host_header": OURS}),
        ("foreign host, our target", {"target": f"http://{OURS}/", "host_header": FOREIGN}),
        ("foreign host, pseudo target", {"target": "//images.php", "host_header": FOREIGN}),
        ("foreign host, bare target", {"target": "foo", "host_header": FOREIGN}),
        ("foreign host, mangled target", {"target": "HTTP/1.1", "host_header": FOREIGN}),
        ("foreign authority, our host", {"authority": FOREIGN, "host_header": OURS}),
        ("our authority, foreign host", {"authority": OURS, "host_header": FOREIGN}),
        ("our authority, foreign :path", {"authority": OURS, "target": f"http://{FOREIGN}/"}),
    ],
)
def test_any_foreign_claim_misdirects(monkeypatch, label, kwargs):
    _claims_foreign(monkeypatch)
    claims = sb.host_claims(**kwargs)
    assert sb.foreign_claim(claims) is not None, label
    assert sb.decide("/1.php", claims) == "misdirected", label


@pytest.mark.parametrize(
    ("label", "kwargs"),
    [
        ("our host only", {"host_header": OURS}),
        ("our absolute target", {"target": f"http://{OURS}/x", "host_header": OURS}),
        ("our network-path target", {"target": f"//{OURS}/x", "host_header": OURS}),
        ("our authority", {"authority": OURS}),
        ("origin-form target carries no claim", {"target": "/images.php", "host_header": OURS}),
        ("asterisk-form carries no claim", {"target": "*", "host_header": OURS}),
        ("nothing claimed at all", {}),
        ("every Host value ours", {"host_header": [OURS, "also.ours"]}),
        ("an empty host list", {"host_header": []}),
    ],
)
def test_our_own_name_is_still_answered(monkeypatch, label, kwargs):
    # The guard must refuse the right requests, not merely more of them: a union that
    # refuses everything would pass every test above and be useless.
    _claims_foreign(monkeypatch)
    claims = sb.host_claims(**kwargs)
    assert sb.foreign_claim(claims) is None, label
    assert sb.decide("/", claims) is None, label


def test_the_foreign_claim_is_the_one_reported(monkeypatch):
    # The caller records it as the row's host; reporting a non-foreign claim instead would
    # leave the refused name out of the event entirely.
    _claims_foreign(monkeypatch)
    claims = sb.host_claims(target=f"http://{OURS}/", host_header=FOREIGN)
    assert sb.foreign_claim(claims) == FOREIGN


def test_a_single_host_string_still_works(monkeypatch):
    # `decide` is called with one host from tests and with a claim list from the decoy;
    # both mean "the host(s) this request claims". A bare string must not be read as an
    # iterable of characters, which is the way this signature goes wrong.
    _claims_foreign(monkeypatch)
    assert sb.decide("/", FOREIGN) == "misdirected"
    assert sb.decide("/", OURS) is None
    assert sb.decide("/", []) is None
    assert sb.decide("/", None) is None


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("/images.php", None),  # origin-form: no authority
        ("*", None),  # asterisk-form: no authority
        (None, None),
        ("", None),
        ("http://h/x?y", "h"),  # absolute-form
        ("https://h:8443/x", "h:8443"),
        ("//h/x", "h"),  # network-path reference
        ("//h", "h"),
        ("h:80", "h:80"),  # authority-form
        ("http://h", "h"),
        ("http://h?q", "h"),
        ("http://h#f", "h"),
        ("//", None),  # nothing after the slashes
    ],
)
def test_target_authority_shapes(target, expected):
    assert sb.target_authority(target) == expected


def test_a_bare_string_host_is_not_read_as_characters(monkeypatch):
    # `host_header` takes one value or all of them, the same shape as `decide`'s argument
    # and for the same reason: `list("victim.example")` is fifteen one-character claims,
    # none of which is a host.
    _claims_foreign(monkeypatch)
    assert sb.host_claims(host_header=FOREIGN) == [FOREIGN]
    assert sb.decide("/", sb.host_claims(host_header=FOREIGN)) == "misdirected"
