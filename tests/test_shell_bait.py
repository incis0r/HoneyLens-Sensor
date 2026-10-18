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
