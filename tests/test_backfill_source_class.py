"""The backfill's SQL says the same thing `classify_source` says.

Phase C, Task C5. The pass that makes `source_class` true about the 16.7 million rows already
stored. It classifies in SQL because Postgres does `inet` containment natively and a Python loop
over that many rows would take hours — but writing the predicate twice is how two predicates
drift apart, so these tests pin the three things that would let them.

No database: the SQL text and its bound parameters are the contract, and the arrays have to come
from `intelligence.source_class` rather than from a copy of the list.
"""

from __future__ import annotations

import pytest

from honeylens.intelligence import source_class as sc
from honeylens.tools import backfill_source_class as bf


@pytest.fixture(autouse=True)
def _configured(monkeypatch):
    monkeypatch.setattr(sc, "_OWN_INFRA", sc._compile(("192.0.2.0/24",)))
    monkeypatch.setattr(sc, "_VALIDATION", sc._compile(("203.0.113.9",)))
    yield


def test_the_networks_come_from_the_classifier_not_from_a_copy():
    """If someone edits one list, this tool has to follow. That is the whole reason the arrays
    are derived rather than written out."""
    params = bf._params()

    assert params["own"] == ["192.0.2.0/24"]
    assert params["validation"] == ["203.0.113.9/32"]
    assert params["internal"] == [str(n) for n in sc._INTERNAL_NETS]


def test_the_class_names_come_from_the_classifier_too():
    params = bf._params()

    assert params["own_class"] == sc.OWN_INFRA
    assert params["validation_class"] == sc.VALIDATION
    assert params["internal_class"] == sc.INTERNAL


def test_carrier_grade_nat_is_not_in_the_internal_array():
    """The one case where `ipaddress.is_private` and this project disagree: `100.64.0.0/10` is
    where a great many real senders live, `prod` itself sits behind a client NAT, and claiming
    it as ours would hide actors. If the SQL ever grew its own list, this is what it would get
    wrong."""
    assert not any(n.startswith("100.64") for n in bf._params()["internal"])


def test_the_case_expression_has_the_same_precedence_as_the_function():
    """own_infra, then validation, then internal, then NULL. An address can be in two lists --
    a sensor of ours the operator also validates from -- and the order decides which one wins,
    so the SQL and the function must agree on it."""
    case = bf._CASE_SQL

    own = case.index("%(own)s")
    validation = case.index("%(validation)s")
    internal = case.index("%(internal)s")

    assert own < validation < internal
    assert case.rstrip().rstrip("END").rstrip().endswith("ELSE NULL")


def test_the_case_expression_binds_every_value_as_a_parameter():
    """No address and no class name is interpolated into the SQL text. The networks reach
    Postgres as `inet` literals, where a bad one fails the whole statement, and the class names
    reach it as text — both as bound parameters. (The parameter NAMES contain the words, which
    is why this checks for the values' own shapes rather than for substrings.)"""
    for address in ("192.0.2", "203.0.113", "10.0.0.0/8", "127.0.0.0/8"):
        assert address not in bf._CASE_SQL
    for name in ("own_class", "validation_class", "internal_class"):
        assert f"%({name})s" in bf._CASE_SQL
    assert f"'{sc.OWN_INFRA}'" not in bf._CASE_SQL


def test_null_means_external_in_the_report():
    """`report()` renames NULL to "external" for the operator, because a report line reading
    `None: 14,560,000` invites the reader to guess."""
    import inspect

    src = inspect.getsource(bf.report)

    assert '"external"' in src


def test_the_report_never_groups_by_address():
    """One of the validation sources is the operator's own connection, and that address does
    not belong in a report. Grouping by class is the whole output."""
    import inspect

    src = inspect.getsource(bf.report)

    assert "src_ip" not in src.split("GROUP BY")[1] if "GROUP BY" in src else True
    assert "GROUP BY 1" in src


def test_the_write_only_touches_rows_whose_class_would_change():
    """Which is what makes a second run a no-op and an interrupted run safe to repeat."""
    import inspect

    src = inspect.getsource(bf.apply_batches)

    assert "IS DISTINCT FROM" in src
    assert "LIMIT %(batch)s" in src
    assert "conn.commit()" in src


def test_the_write_is_batched_and_committed_per_batch():
    """2.1 million rows in one transaction is a long lock and a long rollback. Per batch, an
    interruption leaves every finished batch correct."""
    import inspect

    src = inspect.getsource(bf.apply_batches)
    update = src.index("UPDATE sensor_events")
    commit = src.index("conn.commit()")

    assert update < commit, "the commit must follow the update inside the loop"


def test_a_dry_run_is_the_default():
    """A tool that writes 2.1 million rows when invoked with no arguments is a tool that gets
    invoked by accident."""
    import inspect

    src = inspect.getsource(bf.main)

    assert "if args.apply and not args.dry_run:" in src
    assert '"--apply", action="store_true"' in src


def test_an_empty_configuration_is_called_out_rather_than_reported_as_zero():
    """With both lists empty the tool is correct and useless: only `internal` is claimed. A
    clean-looking zero would be read as "we have no own traffic", which is the belief this
    whole phase exists to correct."""
    import inspect

    src = inspect.getsource(bf.main)

    assert "both empty" in src
