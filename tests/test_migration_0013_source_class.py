"""Migration 0013 — the source_class column (SQL text only, no database).

Phase C, Task C2. The column stores whose traffic an event was, decided at ingest. The things
worth pinning here are the ones that cannot be seen from the column name:

* it is **additive** — a nullable column with no default, so a 16.7-million-row table is not
  rewritten and no stored row is touched;
* it **deletes and rewrites nothing**, which is the standing contract for `migrate.apply()`;
* it is **guarded** by `to_regclass`, as 0010 and 0011 are;
* and `VARCHAR(16)` has to hold every value `source_class.classify_source` can return, which is
  checked against that module rather than against a copy of the list.
"""

from __future__ import annotations

import pytest

from honeylens.db import migrate


def read_migration(version: str) -> str:
    for v, path in migrate.discover_migrations():
        if v == version:
            return path.read_text(encoding="utf-8")
    raise AssertionError(f"migration {version} not found")


@pytest.fixture
def sql() -> str:
    return read_migration("0013")


def test_the_migration_is_discoverable_and_in_order() -> None:
    versions = [v for v, _ in migrate.discover_migrations()]

    assert "0013" in versions
    assert versions == sorted(versions)


def test_it_adds_a_nullable_column_with_no_default(sql: str) -> None:
    """A default would rewrite the table. `sensor_events` is 16.7 million rows on the busiest
    sensor, and a rewrite is an outage, not a migration."""
    stmts = migrate.split_statements(sql)
    add = next(s for s in stmts if "ADD COLUMN" in s.upper())

    assert "ADD COLUMN IF NOT EXISTS SOURCE_CLASS VARCHAR(16)" in add.upper()
    assert "DEFAULT" not in add.upper()
    assert "NOT NULL" not in add.upper()


def test_it_is_guarded_by_to_regclass(sql: str) -> None:
    """As 0010 and 0011 are. A migration that assumes a table is how a runner starts failing on
    the one host whose profile differs."""
    stmts = migrate.split_statements(sql)
    add = next(s for s in stmts if "ADD COLUMN" in s.upper())

    assert "to_regclass" in add
    assert "public.sensor_events" in add


@pytest.mark.parametrize("verb", ["DELETE", "TRUNCATE", "UPDATE", "DROP"])
def test_it_touches_no_stored_row(sql: str, verb: str) -> None:
    """Existing rows stay NULL until Task C5 backfills them, deliberately: a migration that
    writes 2.1 million rows holds a lock for the duration and cannot be reported on per
    sensor."""
    executable = " ".join(migrate.split_statements(sql)).upper()

    assert verb not in executable


def test_the_index_is_partial_on_the_readers_predicate(sql: str) -> None:
    """`source_class IS NULL` is what every reader filters on, so the index covers exactly the
    external rows and costs nothing on the 12.8% that are ours."""
    stmts = migrate.split_statements(sql)
    index = next(s for s in stmts if "CREATE INDEX" in s.upper())

    assert "IF NOT EXISTS" in index.upper()
    assert "WHERE SOURCE_CLASS IS NULL" in index.upper()
    assert "TIMESTAMP DESC" in index.upper(), "these queries always carry a time range"


def test_the_column_is_wide_enough_for_every_class_the_code_can_write() -> None:
    """Checked against the module, not against a copy of the list: a fifth class added there
    with a longer name would otherwise fail at INSERT time on a live sensor."""
    from honeylens.intelligence import source_class

    classes = (source_class.OWN_INFRA, source_class.VALIDATION, source_class.INTERNAL)

    assert all(len(c) <= 16 for c in classes), classes


def test_the_header_says_what_null_means(sql: str) -> None:
    """The one fact a reader of this schema cannot guess, and the one that inverts every query
    if they guess wrong."""
    header = sql[: sql.index("DO $$")].lower()

    assert "null means external" in header
    assert "c5" in header, "say that stored rows stay NULL until the backfill"
