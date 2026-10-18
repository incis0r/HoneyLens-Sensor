"""Whose traffic was this, stored as a fact rather than guessed at report time.

Phase C, Task C1. Open item 4 of the 4 Oct-4 Nov fleet review: **2,139,975 rows — 12.8% of
everything recorded — are ours**, and they are the single root cause behind the window's three
most distorted verdicts (`ANOMALY` 99.7% own, `SURICATA_ALERT` 97.9%, `SCANNER` 83.1%). The
operator chose to keep those rows and mark them, so provenance becomes a column.

**A varchar, not a boolean.** The review's standing discipline is to report two columns — what
arrived, and what arrived from somewhere that is not an actor — and "why it is ours" is exactly
what a boolean throws away. An operator's validation run and a sensor's own monitoring traffic
need separating when one of them turns out to be louder than expected.

**`None` is the load-bearing value.** It means "a real actor", so it is the value every reader
filters on and the value an unparseable or missing address has to produce. A classifier that
guesses "ours" when it cannot tell would hide actors, which is the expensive direction of the
error; a classifier that guesses "actor" merely leaves a row in a dashboard.

**`internal` is an explicit list of networks, not `ipaddress.is_private`.** Python counts
`100.64.0.0/10` as private, and CGNAT is where a great many real actors live — `prod` itself
sits behind a client NAT. Using the property would have classified those senders as ours.

No addresses of ours appear in this file or in `config.py`: the lists are configuration, empty by
default, set per deployment. These tests use the documentation ranges from RFC 5737.
"""

from __future__ import annotations

import pytest

from honeylens.intelligence import source_class as sc

# RFC 5737 documentation ranges, standing in for the real configuration.
OWN_INFRA_CIDR = "192.0.2.0/24"
OWN_INFRA_HOST = "198.51.100.7"
VALIDATION_HOST = "203.0.113.9"
VALIDATION_HOST_2 = "203.0.113.200"


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    """Configure the module the way a deployment's `.env` would, then put it back."""
    monkeypatch.setattr(
        sc,
        "_OWN_INFRA",
        sc._compile((OWN_INFRA_CIDR, OWN_INFRA_HOST)),
        raising=True,
    )
    monkeypatch.setattr(
        sc,
        "_VALIDATION",
        sc._compile((VALIDATION_HOST, VALIDATION_HOST_2)),
        raising=True,
    )
    yield


# ---------------------------------------------------------------------------
# The configured classes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ip", [OWN_INFRA_HOST, "192.0.2.1", "192.0.2.254"])
def test_a_configured_own_infra_address_classifies(ip):
    assert sc.classify_source(ip) == sc.OWN_INFRA


@pytest.mark.parametrize("ip", [VALIDATION_HOST, VALIDATION_HOST_2])
def test_a_configured_validation_address_classifies(ip):
    """The validation sources are EXTERNAL addresses — an operator testing the sensor from
    their own connection — so they arrive as a `/32` each and never as a subnet."""
    assert sc.classify_source(ip) == sc.VALIDATION


@pytest.mark.parametrize("ip", ["203.0.113.8", "203.0.113.10", "198.51.100.6", "198.51.100.8"])
def test_the_addresses_either_side_of_a_configured_host_are_actors(ip):
    """A bare address becomes a `/32`, so the neighbour is not swept up with it. Getting this
    wrong would silently hide whoever happens to sit next to an operator's address."""
    assert sc.classify_source(ip) is None


def test_own_infra_outranks_validation():
    """One address can be both — a sensor of ours that the operator also validates from. It is
    our infrastructure first; that is the more specific true statement about it."""
    both = "192.0.2.50"
    sc._VALIDATION = sc._compile((both,))

    assert sc.classify_source(both) == sc.OWN_INFRA


# ---------------------------------------------------------------------------
# internal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "10.9.9.9",
        "10.0.0.1",
        "172.20.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "::1",
        "fe80::1",
        "fd00::1",
    ],
)
def test_private_loopback_and_link_local_are_internal(ip):
    """These need no configuration: they cannot be a real actor reaching us over the
    internet, on any deployment."""
    assert sc.classify_source(ip) == sc.INTERNAL


@pytest.mark.parametrize("ip", ["100.64.0.1", "100.127.255.254"])
def test_carrier_grade_nat_is_not_internal(ip):
    """`ipaddress.is_private` says these are private. They are not ours: CGNAT is where a great
    many real senders live, and `prod` itself sits behind a client NAT. Classifying them as
    internal would have hidden actors, which is the expensive direction of this error."""
    assert sc.classify_source(ip) is None


@pytest.mark.parametrize("ip", ["0.0.0.0", "255.255.255.255", "224.0.0.1"])
def test_the_other_reserved_ranges_are_not_claimed_as_ours(ip):
    """They are not actors either, but they are not OUR traffic, and this column answers only
    the second question. Saying `None` leaves them visible rather than quietly ours."""
    assert sc.classify_source(ip) is None


# ---------------------------------------------------------------------------
# What a missing or broken address does
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ip", [None, "", "   ", "not-an-address", "1.2.3", "1.2.3.4.5", "::ffff:"])
def test_an_unusable_address_is_never_silently_ours(ip):
    """`None` means "a real actor", so an address we cannot parse stays visible. The opposite
    default would hide traffic on the strength of a parse failure."""
    assert sc.classify_source(ip) is None


def test_an_address_with_a_prefix_or_whitespace_still_classifies():
    """`src_ip::text` on an `inet` column carries a `/32`, which is the trap recorded in
    `event-store-query-traps` — a backfill reading that column must not fall through to
    `None` for every row."""
    assert sc.classify_source(" 192.0.2.1/32 ") == sc.OWN_INFRA
    assert sc.classify_source("10.9.9.9/32") == sc.INTERNAL


def test_an_ordinary_external_address_is_an_actor():
    assert sc.classify_source("91.92.40.12") is None


# ---------------------------------------------------------------------------
# An empty configuration
# ---------------------------------------------------------------------------


def test_with_no_configuration_only_internal_is_claimed():
    """A fresh install must not claim anything it was not told about. `internal` still holds,
    because it is true everywhere."""
    sc._OWN_INFRA = ()
    sc._VALIDATION = ()

    assert sc.classify_source(OWN_INFRA_HOST) is None
    assert sc.classify_source(VALIDATION_HOST) is None
    assert sc.classify_source("192.0.2.1") is None
    assert sc.classify_source("10.0.0.1") == sc.INTERNAL


def test_the_defaults_ship_empty():
    """No address of ours belongs in a committed file; the lists come from the deployment's
    environment. Checked here because the alternative is a leak that nothing else catches."""
    from honeylens import config

    assert config.SOURCE_CLASS_OWN_INFRA == ()
    assert config.SOURCE_CLASS_VALIDATION == ()


# ---------------------------------------------------------------------------
# It runs on the ingest hot path
# ---------------------------------------------------------------------------


def test_the_networks_are_compiled_once():
    """No per-call parsing: the lists are `ip_network` objects built at import. At 12.8% of
    16.7 million rows this is called a lot."""
    import ipaddress

    assert all(isinstance(n, ipaddress.IPv4Network | ipaddress.IPv6Network) for n in sc._OWN_INFRA)
    assert all(
        isinstance(n, ipaddress.IPv4Network | ipaddress.IPv6Network) for n in sc._INTERNAL_NETS
    )


def test_a_mixed_family_configuration_does_not_raise():
    """An IPv4 address against an IPv6 network raises from `in` if compared carelessly, and an
    ingest that raises on a classification loses the event."""
    sc._OWN_INFRA = sc._compile(("2001:db8::/32", OWN_INFRA_CIDR))

    assert sc.classify_source("192.0.2.1") == sc.OWN_INFRA
    assert sc.classify_source("2001:db8::1") == sc.OWN_INFRA
    assert sc.classify_source("91.92.40.12") is None


def test_the_class_values_are_short_enough_for_the_column():
    """Migration 0013 declares `VARCHAR(16)`."""
    for value in (sc.OWN_INFRA, sc.VALIDATION, sc.INTERNAL):
        assert len(value) <= 16
