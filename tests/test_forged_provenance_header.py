"""A header cannot make an attacker's traffic look like ours.

Phase C turns provenance into a stored column that every dashboard filters on
(`source_class IS NULL` means "a real actor"). That makes the source address load-bearing in a
way it was not before: whoever controls the address we record controls whether their traffic is
visible.

Two decoys were reading a forwarded header with **no check on who sent it**:

* `honeypots/honeypot.py` — the Flask decoy took `X-Real-IP`, then `X-Forwarded-For`, then the
  socket peer, in that order;
* `honeypots/honeypot_llm.py` — `_get_client_ip` took the first element of `X-Forwarded-For`
  whenever it was present.

`honeypot_netscaler` and `honeypot_sharepoint` have always required the TCP peer to be the
configured edge (`HONEYLENS_HTTP_PROXY`) before believing the header, because nginx terminates
port 80 as HTTP and cannot attach a PROXY preamble there. That check is now in
`proxy_protocol.http_client_ip`, shared by all four.

A forged address was already a defect — it pollutes the actor analysis, the IOC sheets and every
hunt — but with `source_class` it becomes an attacker switching off their own visibility with one
header, which is why the fix lands with this phase. Addresses here are RFC 5737 documentation
ranges; the edge's own address is configuration, never a literal in a committed file.
"""

from __future__ import annotations

import pytest

from honeylens.honeypots import proxy_protocol
from honeylens.intelligence import source_class as sc

EDGE = "192.0.2.10"  # stands in for the deployment's nginx front
ATTACKER = "198.51.100.77"
OUR_OWN = "192.0.2.50"  # inside the configured own-infra range below
REAL_CLIENT = "203.0.113.5"


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    monkeypatch.setattr(sc, "_OWN_INFRA", sc._compile(("192.0.2.0/24",)))
    monkeypatch.setattr(sc, "_VALIDATION", sc._compile(()))
    yield


# ---------------------------------------------------------------------------
# The shared resolver
# ---------------------------------------------------------------------------


def test_a_header_from_an_untrusted_peer_is_ignored():
    """The attacker connects directly and claims to be one of our own hosts."""
    resolved = proxy_protocol.http_client_ip(ATTACKER, ATTACKER, OUR_OWN, EDGE)

    assert resolved == ATTACKER


def test_a_header_from_the_configured_edge_is_believed():
    """Which is the whole reason the header exists: nginx terminates :80 as HTTP and cannot
    attach a PROXY preamble, so without this the real client is invisible."""
    resolved = proxy_protocol.http_client_ip(EDGE, EDGE, REAL_CLIENT, EDGE)

    assert resolved == REAL_CLIENT


def test_with_no_edge_configured_no_header_is_believed():
    """A sensor with no front in front of it must not accept a claim from anybody."""
    assert proxy_protocol.http_client_ip(ATTACKER, ATTACKER, OUR_OWN, "") == ATTACKER


def test_an_unparseable_claim_from_the_edge_falls_back_to_the_peer():
    assert proxy_protocol.http_client_ip(EDGE, EDGE, "not-an-address", EDGE) == EDGE


def test_a_cidr_of_trusted_edges_works():
    """A deployment can have more than one front."""
    assert proxy_protocol.http_client_ip(EDGE, EDGE, REAL_CLIENT, "192.0.2.0/24") == REAL_CLIENT
    assert proxy_protocol.http_client_ip(ATTACKER, ATTACKER, REAL_CLIENT, "192.0.2.0/24") == (
        ATTACKER
    )


# ---------------------------------------------------------------------------
# Which header the edge is actually responsible for
# ---------------------------------------------------------------------------


def test_the_real_ip_header_wins_because_the_edge_overwrites_it():
    """nginx sets `X-Real-IP $remote_addr` — it overwrites, so the value is what the edge saw
    and nothing the client chose."""
    assert proxy_protocol.forwarded_client_claim(REAL_CLIENT, "") == REAL_CLIENT


def test_the_forwarded_for_list_is_read_from_the_right():
    """nginx appends with `$proxy_add_x_forwarded_for`, so a client that sends
    `X-Forwarded-For: 192.0.2.50` arrives as `192.0.2.50, <real client>`. The FIRST element is
    the client's own invention even when the peer is the trusted edge; the LAST is what the
    edge appended. Taking the leftmost would have handed the header straight back to the
    sender — the hole this helper exists to close."""
    claim = proxy_protocol.forwarded_client_claim("", f"{OUR_OWN}, {REAL_CLIENT}")

    assert claim == REAL_CLIENT


def test_a_forged_chain_through_the_trusted_edge_still_resolves_to_the_real_client():
    """End to end: the attacker prepends one of our addresses, nginx appends theirs, the peer
    IS the trusted edge — and the event is still recorded against them."""
    xff = f"{OUR_OWN}, {ATTACKER}"
    claim = proxy_protocol.forwarded_client_claim("", xff)
    resolved = proxy_protocol.http_client_ip(EDGE, EDGE, claim, EDGE)

    assert resolved == ATTACKER
    assert sc.classify_source(resolved) is None


def test_an_empty_pair_of_headers_claims_nothing():
    assert proxy_protocol.forwarded_client_claim("", "") == ""
    assert proxy_protocol.forwarded_client_claim("  ", " , ") == ""


# ---------------------------------------------------------------------------
# What it means for the stored class
# ---------------------------------------------------------------------------


def test_the_forged_claim_does_not_become_our_own_traffic():
    """The point of the whole file: had the header been believed, this event would have been
    stored `own_infra` and filtered out of every dashboard."""
    resolved = proxy_protocol.http_client_ip(ATTACKER, ATTACKER, OUR_OWN, EDGE)

    assert sc.classify_source(resolved) is None, "a real actor must stay a real actor"
    assert sc.classify_source(OUR_OWN) == sc.OWN_INFRA, "the claimed address really is ours"


def test_a_genuine_proxied_client_is_still_classified_on_its_own_address():
    resolved = proxy_protocol.http_client_ip(EDGE, EDGE, REAL_CLIENT, EDGE)

    assert sc.classify_source(resolved) is None


# ---------------------------------------------------------------------------
# Every decoy that reads such a header goes through the resolver
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("module", "function"),
    [
        ("honeylens.honeypots.honeypot", "_flask_client_ip"),
        ("honeylens.honeypots.honeypot_llm", "_get_client_ip"),
        ("honeylens.honeypots.honeypot_netscaler", "_http_client_ip"),
        ("honeylens.honeypots.honeypot_sharepoint", "_http_client_ip"),
    ],
)
def test_the_decoys_resolve_through_the_shared_helper(module, function):
    """Four decoys, one check. A fifth that reads the header itself is the thing this test is
    here to make visible."""
    import importlib
    import inspect

    src = inspect.getsource(getattr(importlib.import_module(module), function))

    assert "http_client_ip" in src


def test_no_decoy_reads_a_forwarded_header_straight_into_a_client_address():
    """The pattern that was wrong, written out so it cannot come back: taking the header as the
    address with no peer check. Detection logic may still read the header — `honeypot_fortigate`
    looks for `127.0.0.1` in it as a CVE-2022-40684 tell — so this looks for the assignment
    shape, not for the header name."""
    import pathlib

    bad = 0
    offenders = []
    decoys = pathlib.Path(proxy_protocol.__file__).parent
    for path in sorted(decoys.glob("*.py")):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.startswith(("client_ip", "src_ip", "return")):
                continue
            if 'headers.get("X-Real-IP")' in stripped or 'headers.get("X-Forwarded-For")' in (
                stripped
            ):
                bad += 1
                offenders.append(f"{path.name}: {stripped[:80]}")

    assert bad == 0, offenders
