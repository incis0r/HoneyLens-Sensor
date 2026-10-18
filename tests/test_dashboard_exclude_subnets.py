"""DASHBOARD_EXCLUDE_SUBNETS — the display-time subnet filter for dashboards/API views.

Regression for a finding on a live sensor: the exclusion was a
hardcoded `_LOCAL_SUBNET = "192.168.0.0/24"` duplicated across three route modules, so a
sensor standing in another range filtered the development range instead of its own and showed
every internal management and monitoring source on the dashboards. The MITRE technique
drill-down had no exclusion at all.

These assert the parser's contract, not the SQL: the predicate itself needs a database.
"""

from __future__ import annotations

from honeylens.config import parse_cidrs


def test_parses_a_single_cidr():
    assert parse_cidrs("198.51.100.0/24") == ("198.51.100.0/24",)


def test_parses_several_and_trims_whitespace():
    # A sensor can sit in more than one internal range; that is why this is a list.
    assert parse_cidrs(" 10.0.0.0/8 , 198.51.100.0/24,192.168.0.0/24 ") == (
        "10.0.0.0/8",
        "198.51.100.0/24",
        "192.168.0.0/24",
    )


def test_empty_means_exclude_nothing():
    # Honoured as "filter nothing": no array element can match, so NOT keeps every row.
    assert parse_cidrs("") == ()
    assert parse_cidrs("   ") == ()
    assert parse_cidrs(",,") == ()


def test_bare_address_becomes_a_host_network():
    # A single host is a legitimate thing to hide (the sensor's own address).
    assert parse_cidrs("198.51.100.167") == ("198.51.100.167/32",)
    assert parse_cidrs("2001:db8::1") == ("2001:db8::1/128",)


def test_host_bits_are_normalised_not_rejected():
    # strict=False: an operator writing the gateway address with a prefix still gets the
    # network they meant, rather than a silently dropped entry.
    assert parse_cidrs("198.51.100.167/24") == ("198.51.100.0/24",)


def test_ipv6_cidr_survives():
    assert parse_cidrs("2001:db8::/32") == ("2001:db8::/32",)


def test_malformed_entries_are_dropped_and_do_not_poison_the_rest():
    # These reach SQL as inet literals; a bad one would fail the query and blank the panel,
    # so dropping it is deliberate. The valid neighbours must survive.
    assert parse_cidrs("not-a-subnet,198.51.100.0/24") == ("198.51.100.0/24",)
    assert parse_cidrs("198.51.100.0/33") == ()
    assert parse_cidrs("999.1.1.1/24,10.0.0.0/8") == ("10.0.0.0/8",)


def test_default_is_the_previous_hardcoded_value():
    # Behaviour must not change for a sensor that sets nothing - our own hosts relied on
    # 192.168.0.0/24 being filtered before this was configurable.
    from honeylens import config

    assert config.parse_cidrs(config.env("DASHBOARD_EXCLUDE_SUBNETS", "192.168.0.0/24")), (
        "the default must never resolve to an empty tuple"
    )


def test_helpers_exposes_the_parsed_list_for_sql_params():
    # Route modules pass this straight into psycopg2 as an inet[] parameter, so it has to be
    # a plain list of strings, not a tuple or a set.
    from honeylens.routes._helpers import EXCLUDED_SUBNETS

    assert isinstance(EXCLUDED_SUBNETS, list)
    assert all(isinstance(x, str) for x in EXCLUDED_SUBNETS)
