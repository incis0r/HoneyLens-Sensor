"""honeylens.db.migrate — runner for numbered migrations; the part that needs no database."""

from __future__ import annotations

from pathlib import Path

from honeylens.db import migrate


def test_discover_migrations_orders_by_version_and_ignores_others(tmp_path: Path) -> None:
    for name in ("0002_b.sql", "0001_a.sql", "0010_j.sql", "notes.sql", "0003.sql", "0004_x.txt"):
        (tmp_path / name).write_text("SELECT 1;")
    found = migrate.discover_migrations(tmp_path)
    assert [v for v, _ in found] == ["0001", "0002", "0010"]
    assert all(isinstance(p, Path) for _, p in found)


def test_packaged_migrations_are_discoverable() -> None:
    versions = [v for v, _ in migrate.discover_migrations()]
    assert versions[:1] == ["0001"]
    assert versions == sorted(versions)


def test_split_statements_handles_semicolons_comments_and_dollar_blocks() -> None:
    blob = """
    -- comment
    CREATE TABLE IF NOT EXISTS a (x int);

    DO $$
    BEGIN
        ALTER TABLE a ADD COLUMN y int;
    END $$;
    CREATE INDEX IF NOT EXISTS i ON a (x)
    """
    stmts = migrate.split_statements(blob)
    assert len(stmts) == 3
    assert stmts[0].startswith("CREATE TABLE")
    assert "$$" in stmts[1] and stmts[1].rstrip().endswith("$$;")
    assert stmts[2].startswith("CREATE INDEX")


def test_split_statements_single_line_dollar_block() -> None:
    assert migrate.split_statements("DO $$ BEGIN NULL; END $$;\nSELECT 1;") == [
        "DO $$ BEGIN NULL; END $$;",
        "SELECT 1;",
    ]


def test_normalize_ddl() -> None:
    assert migrate.normalize_ddl("  CREATE   TABLE\n  a (x int) ; ") == "CREATE TABLE a (x int)"


def test_execute_tolerant_retries_once_and_tolerates_already_exists() -> None:
    import psycopg2

    class Cur:
        def __init__(self):
            self.seen = []

        def execute(self, stmt):
            self.seen.append(stmt)
            if stmt == "A":
                raise psycopg2.Error("relation already exists")
            if stmt == "B" and self.seen.count("B") == 1:
                raise psycopg2.Error("missing dependency")
            if stmt == "C":
                raise psycopg2.Error("never works")

    cur = Cur()
    pending = migrate._execute_tolerant(cur, ["A", "B", "C", ""])
    assert pending == ["C"]
    assert cur.seen == ["A", "B", "C", "B", "C"]


def test_cli_list_needs_no_database(capsys) -> None:
    assert migrate.main(["--list"]) == 0
    out = capsys.readouterr().out
    assert "0001" in out and "base_schema" in out
