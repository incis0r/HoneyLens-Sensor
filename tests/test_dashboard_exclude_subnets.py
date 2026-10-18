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


# ─── EXTERNAL_ONLY — the stored-provenance filter (Phase C, Task C4) ──────────
#
# The subnet filter above answers "is this one of MY internal ranges?", which is a
# per-deployment fact and stays. It cannot answer "was this us?", because our own traffic
# arrives from public addresses too — our fronts, our jump hosts, the operator's own
# connection — and a CIDR list evaluated at report time changes under the data. 12.8% of the
# store is mislabelled because that is the only question the dashboards could ask.
#
# These assert the predicate text and the fallback, not the SQL: running it needs a database.


def test_the_predicate_is_the_column_is_null():
    """NULL means external. It is the whole contract and the thing a reader gets backwards."""
    from honeylens.routes._helpers import EXTERNAL_ONLY

    assert EXTERNAL_ONLY == "source_class IS NULL"


def test_the_predicate_can_be_qualified_with_a_table_alias(monkeypatch):
    """`routes/classifier.py` joins and writes `se.src_ip`, so an unqualified column name
    would be ambiguous there. The column is forced present here: these tests run without a
    database, where the probe correctly finds nothing."""
    from honeylens.routes import _helpers

    monkeypatch.setattr(_helpers, "_source_class_column_present", lambda: True)

    assert _helpers.external_only() == "source_class IS NULL"
    assert _helpers.external_only("se") == "se.source_class IS NULL"


def test_the_predicate_takes_no_query_parameter(monkeypatch):
    """Unlike the subnet filter, this adds no `%s` — so a call site that forgets to extend its
    parameter list is not a possible mistake here."""
    from honeylens.routes import _helpers

    monkeypatch.setattr(_helpers, "_source_class_column_present", lambda: True)

    assert "%s" not in _helpers.external_only()
    assert "%s" not in _helpers.external_only("se")


def test_without_the_column_the_predicate_is_a_no_op(monkeypatch):
    """A host that has not run migration 0013 has no such column, and a query naming it fails
    outright — which would blank every panel that filters. The predicate degrades to TRUE
    instead, so an un-migrated sensor keeps its dashboards and simply shows own traffic, which
    is exactly what it showed before Phase C."""
    from honeylens.routes import _helpers

    monkeypatch.setattr(_helpers, "_source_class_column_present", lambda: False)

    assert _helpers.external_only() == "TRUE"
    assert _helpers.external_only("se") == "TRUE"


def test_every_subnet_filtered_query_also_filters_provenance():
    """The nine queries that carry the subnet predicate are exactly the ones that mean "show
    me what arrived from outside", so each has to carry both. The plan said twelve call sites;
    the tree has nine, and counting them here is how the tenth gets caught."""
    import pathlib
    import re

    src = pathlib.Path(_helpers_dir())
    subnet = re.compile(r"NOT \((?:\w+\.)?src_ip <<= ANY\(%s::inet\[\]\)\)")
    total = 0
    for path in sorted(src.rglob("*.py")):
        if path.name == "_helpers.py":
            continue
        text = path.read_text(encoding="utf-8")
        hits = subnet.findall(text)
        if not hits:
            continue
        total += len(hits)
        assert text.count("external_only(") >= len(hits), (
            f"{path.name}: {len(hits)} subnet filters, {text.count('external_only(')} "
            "provenance filters"
        )
    assert total == 9, f"expected 9 subnet-filtered queries, found {total}"


def _helpers_dir() -> str:
    from honeylens.routes import _helpers

    return str(pathlib.Path(_helpers.__file__).parent)


import pathlib  # noqa: E402  — used by the helper above
