"""Migration 0010 -- the foreign key from ics_events to sensor_events (SQL text only, no database)."""

from __future__ import annotations

import pytest

from honeylens.db import migrate


def read_migration(version: str) -> str:
    for v, path in migrate.discover_migrations():
        if v == version:
            return path.read_text(encoding="utf-8")
    raise AssertionError(f"migration {version} not found")


def test_the_migration_is_discoverable_and_last() -> None:
    versions = [v for v, _ in migrate.discover_migrations()]
    assert "0010" in versions and versions == sorted(versions)


def executable(sql: str) -> str:
    """The text the runner actually executes: comments are dropped by split_statements."""
    return migrate.split_statements(sql)[0]


def assert_key_guarded(stmt: str) -> None:
    assert "to_regclass" in stmt, "skip hosts without the table, as 0007 does"
    assert "pg_constraint" in stmt, "skip when the key already exists"


def test_the_key_is_not_valid_so_the_migration_deletes_nothing() -> None:
    """sensor-b has 108 rows whose event has left the live table -- FK violations for this key,
    even though the events survive in an archive partition -- and migrate.apply() may not delete
    or rewrite data, so a validating ADD CONSTRAINT is not an option."""
    stmt = executable(read_migration("0010")).upper()
    assert "NOT VALID" in stmt
    assert "ON DELETE CASCADE" in stmt
    assert "ICS_EVENTS_EVENT_ID_FKEY" in stmt
    for verb in ("DELETE", "TRUNCATE", "UPDATE"):
        # ON DELETE CASCADE is the one legitimate mention of DELETE.
        assert verb not in stmt.replace("ON DELETE CASCADE", ""), verb


def test_it_is_guarded_and_idempotent() -> None:
    assert_key_guarded(executable(read_migration("0010")))


def test_the_guard_assertion_is_not_vacuous() -> None:
    """Without the guard lines in the executable text, the assertion must fail."""
    stmt = executable(read_migration("0010"))
    stripped = "\n".join(
        line
        for line in stmt.splitlines()
        if "to_regclass" not in line and "pg_constraint" not in line
    )
    with pytest.raises(AssertionError):
        assert_key_guarded(stripped)


def assert_delete_rule_guarded(stmt: str) -> None:
    assert "confdeltype" in stmt, "the guard must test the delete rule, not mere existence"
    assert "DROP CONSTRAINT" in stmt.upper(), "a key with the wrong rule is converted"


def test_a_key_with_the_wrong_delete_rule_is_converted_not_skipped() -> None:
    """The first version of 0010 returned early on *any* foreign key from ics_events to
    sensor_events, so on a host carrying a hand-made NO ACTION key it was a silent no-op
    and db_archive then failed exactly as 0007's header records, with the partition drop
    still succeeding and the unit still exiting 0. 0007 adds `confdeltype <> 'c'` for
    precisely this reason, and the base schema declares no key here, so any key present
    on a sensor got there by hand."""
    assert_delete_rule_guarded(executable(read_migration("0010")))


def test_the_delete_rule_assertion_is_not_vacuous() -> None:
    """Without the conversion lines in the executable text, the assertion must fail."""
    stmt = executable(read_migration("0010"))
    stripped = "\n".join(
        line
        for line in stmt.splitlines()
        if "confdeltype" not in line and "DROP CONSTRAINT" not in line.upper()
    )
    with pytest.raises(AssertionError):
        assert_delete_rule_guarded(stripped)


def test_the_name_of_the_key_it_drops_is_read_from_the_catalogue() -> None:
    """A key created by hand is called whatever that hand chose; assuming
    `ics_events_event_id_fkey` would leave a differently-named NO ACTION key in place."""
    stmt = executable(read_migration("0010"))
    assert "conname" in stmt, "the name comes out of pg_constraint"
    assert "DROP CONSTRAINT %I" in stmt, "and is interpolated, not hardcoded"


def test_a_correct_key_is_still_left_alone() -> None:
    """Idempotency: a host already cascading must come out of a re-run untouched."""
    stmt = executable(read_migration("0010"))
    assert "confdeltype = 'c'" in stmt, "the early return tests for the correct rule"


def test_it_parses_into_statements_the_runner_can_execute() -> None:
    stmts = migrate.split_statements(read_migration("0010"))
    assert len(stmts) >= 1 and stmts[0].strip()
