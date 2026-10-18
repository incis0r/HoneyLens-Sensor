"""An address we did not learn from the TCP peer cannot make a row disappear.

`test_forged_provenance_header.py` closed the first half: a header is believed only when the TCP
peer is the configured edge. Trusting the peer decides *which* address to record; it does not
establish that the value is the edge's rather than the client's. That depends on the edge's
configuration, which the decoy cannot see — and our own nginx guide did not set
`proxy_set_header X-Real-IP $remote_addr` on the port-80 path until 2026-11-07, while nginx
passes an unknown header through unchanged. A deployment following the guide forwarded whatever
the client sent, and the decoy believed it.

With `source_class` that is an attacker choosing their own provenance: claim a private address,
get `internal`, and nine dashboard queries filter the row out. It is stored at ingest, so fixing
the edge later recovers nothing — `backfill_source_class` would re-derive from the same
unestablished address.

**The mirror image is the one that actually bit, and it was already live.** Measured 2026-11-06
on `sensor-c`: 10,650 SharePoint rows between 2026-10-10 and 2026-10-30 stored the edge's own
the edge's own address while carrying the real client in `X-Real-IP`, and every one of them read
`internal`. Real external attacks, hidden from the dashboards by our own proxy's address.

Both directions have the same remedy, and it is the rule migration 0013 already states for an
unparseable address: NULL — "a real actor" — is the safe answer, because it is the visible one.
Addresses here are RFC 5737 documentation ranges.
"""

from __future__ import annotations

import inspect

import pytest

from honeylens.honeypots import proxy_protocol as pp
from honeylens.intelligence import source_class as sc

EDGE = "192.0.2.10"  # the deployment's proxy; private in the real thing, documentation here
ATTACKER = "198.51.100.77"
OUR_OWN = "192.0.2.50"
REAL_CLIENT = "203.0.113.5"


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    monkeypatch.setattr(sc, "_OWN_INFRA", sc._compile(("192.0.2.0/24",)))
    monkeypatch.setattr(sc, "_VALIDATION", sc._compile(()))
    yield


# ---------------------------------------------------------------------------
# Where the address came from
# ---------------------------------------------------------------------------


def test_a_direct_client_is_the_peer():
    assert pp.http_client_ip_with_origin(ATTACKER, ATTACKER, "", "") == (
        ATTACKER,
        pp.ORIGIN_PEER,
    )


def test_a_header_from_an_untrusted_peer_leaves_the_origin_the_peer():
    """The claim is discarded, so there is nothing unestablished about the address we keep."""
    assert pp.http_client_ip_with_origin(ATTACKER, ATTACKER, OUR_OWN, EDGE) == (
        ATTACKER,
        pp.ORIGIN_PEER,
    )


def test_a_header_from_the_edge_is_marked_as_coming_from_the_edge():
    assert pp.http_client_ip_with_origin(EDGE, EDGE, REAL_CLIENT, EDGE) == (
        REAL_CLIENT,
        pp.ORIGIN_EDGE_HEADER,
    )


def test_the_edge_with_no_header_is_marked_unresolved():
    """What sensor-c did for twenty days: the address we hold is the proxy's own."""
    assert pp.http_client_ip_with_origin(EDGE, EDGE, "", EDGE) == (
        EDGE,
        pp.ORIGIN_EDGE_UNRESOLVED,
    )


def test_an_unusable_header_from_the_edge_is_unresolved_not_peer():
    """The header was there and could not be used, so the address is still the edge's."""
    assert pp.http_client_ip_with_origin(EDGE, EDGE, "not-an-address", EDGE) == (
        EDGE,
        pp.ORIGIN_EDGE_UNRESOLVED,
    )


def test_the_old_signature_still_answers_with_the_address_alone():
    """Four decoys call it; the refactor must not change what they get."""
    assert pp.http_client_ip(EDGE, EDGE, REAL_CLIENT, EDGE) == REAL_CLIENT
    assert pp.http_client_ip(ATTACKER, ATTACKER, OUR_OWN, EDGE) == ATTACKER


# ---------------------------------------------------------------------------
# What provenance does with it
# ---------------------------------------------------------------------------


def test_an_address_from_the_edge_is_never_classified_as_ours():
    """The forgery: the attacker sends `X-Real-IP: <one of our hosts>` through the edge."""
    assert sc.classify_source(OUR_OWN) == sc.OWN_INFRA
    assert sc.classify_source(OUR_OWN, address_learned_from_edge=True) is None


def test_the_edges_own_address_does_not_hide_the_interaction():
    """The sensor-c shape: the stored address is the proxy's, which is ours — but the event is
    somebody else's request."""
    assert sc.classify_source(EDGE) == sc.OWN_INFRA
    assert sc.classify_source(EDGE, address_learned_from_edge=True) is None


def test_a_real_client_through_the_edge_is_an_actor_either_way():
    assert sc.classify_source(REAL_CLIENT) is None
    assert sc.classify_source(REAL_CLIENT, address_learned_from_edge=True) is None


def test_the_peer_path_is_unchanged():
    """The flag is opt-in: every caller that did establish the address keeps its answer."""
    assert sc.classify_source(OUR_OWN, address_learned_from_edge=False) == sc.OWN_INFRA
    assert sc.classify_source("10.9.9.9") == sc.INTERNAL


# ---------------------------------------------------------------------------
# The wiring, because a rule nobody passes is not a rule
# ---------------------------------------------------------------------------


def test_the_two_edge_facing_decoys_record_the_origin():
    """Both build a structured event that becomes `metadata`, so the marker travels with the
    row to whoever classifies it."""
    from honeylens.honeypots import honeypot_netscaler, honeypot_sharepoint

    for module in (honeypot_netscaler, honeypot_sharepoint):
        src = inspect.getsource(module)
        assert "http_client_ip_with_origin" in src, module.__name__
        assert 'event["client_ip_from"] = client_ip_from' in src, module.__name__


def test_the_ingest_passes_the_marker_to_the_classifier():
    from honeylens.ingest import honeypot as ingest

    src = inspect.getsource(ingest)
    assert 'address_learned_from_edge=bool((rec["metadata"] or {}).get("client_ip_from"))' in (
        src.replace("'", '"')
    )


def test_the_backfill_refuses_to_re_derive_an_unestablished_address():
    """Recomputing from the stored address is exactly what cannot recover these rows."""
    from honeylens.tools import backfill_source_class as bf

    assert "metadata ? 'client_ip_from'" in bf._CASE_SQL
    # and it comes first, before any address test can answer
    assert bf._CASE_SQL.index("client_ip_from") < bf._CASE_SQL.index("own")


def test_the_nginx_guide_sets_the_header_it_tells_the_decoy_to_trust():
    """The cheapest half of the fix, and the one that makes forgery impossible rather than
    merely visible."""
    from pathlib import Path

    guide = Path(__file__).resolve().parents[1] / "docs" / "deploy-behind-nginx.md"
    text = guide.read_text(encoding="utf-8")

    assert "proxy_set_header X-Real-IP  $remote_addr;" in text
