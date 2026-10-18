"""Retention must clean up the analyses it orphans.

`ai_analysis` and `claude_analysis_log` each describe exactly one `sensor_event`.
Dropping an archive partition removes those events — and left the rows describing
them behind, pointing at evidence nobody could look at any more. Nothing ever
removed them, because retention covered `sensor_events` alone.

Measured in production, before this existed:

    ai_analysis          1,324,162 orphaned of 2,105,638  (63%)
    claude_analysis_log  1,394,329 orphaned of 2,255,294  (62%)

together holding 4.4 GB. The manual cleanup took the database from 27 GB to 22 GB.

These tests use a fake connection: the logic being pinned is which tables are
consulted and in what order the steps run, neither of which needs a real database.
"""

from __future__ import annotations

import inspect

from honeylens.tools import db_archive as da


def _render(q):
    """Flatten a psycopg2 Composed/SQL/Identifier tree to text.

    `as_string()` needs a live connection, which is exactly what these tests avoid,
    so walk the structure instead. Identifiers come back quoted, matching the SQL
    that would be sent.
    """
    from psycopg2 import sql as _sql

    if isinstance(q, _sql.Composed):
        return "".join(_render(x) for x in q.seq)
    if isinstance(q, _sql.Identifier):
        return '"' + '"."'.join(q.strings) + '"'
    if isinstance(q, _sql.SQL):
        return q.string
    return str(q)


class _FakeCursor:
    """Records the SQL it is given and answers counts from a script."""

    def __init__(self, archive_tables, counts, regclass=lambda t: t):
        self._archives = archive_tables
        self._counts = dict(counts)
        self._regclass = regclass
        self.executed = []
        self._last = None
        self.rowcount = 0

    def execute(self, query, params=None):
        text = _render(query)
        self.executed.append(text)
        if "information_schema.tables" in text:
            self._last = [(t,) for t in self._archives]
        elif "to_regclass" in text:
            self._last = [(self._regclass(params[0]),)]
        elif text.strip().upper().startswith("SELECT COUNT(*)"):
            tbl = next((t for t in da.ANALYSIS_TABLES if f'"{t}"' in text), None)
            self._last = [(self._counts.get(tbl, 0),)]
        elif text.strip().upper().startswith("DELETE"):
            tbl = next((t for t in da.ANALYSIS_TABLES if f'"{t}"' in text), None)
            left = self._counts.get(tbl, 0)
            take = min(left, da.ORPHAN_BATCH)
            self._counts[tbl] = left - take
            self.rowcount = take
            self._last = []
        else:
            self._last = []

    def fetchone(self):
        return self._last[0] if self._last else None

    def fetchall(self):
        return self._last or []


class _FakeConn:
    def __init__(self, archive_tables=(), counts=(), regclass=lambda t: t):
        self._cur = _FakeCursor(list(archive_tables), dict(counts), regclass)
        self.commits = 0

    def cursor(self):
        return self._cur

    def commit(self):
        self.commits += 1


# ------------------------------------------------------------------ which tables


def test_the_two_analysis_tables_are_the_ones_covered():
    assert da.ANALYSIS_TABLES == ("ai_analysis", "claude_analysis_log")


def test_a_missing_table_is_skipped_not_an_error():
    """Not every sensor runs the Claude path; an absent table must not break retention."""
    conn = _FakeConn(
        archive_tables=["archive_events_2026_06"],
        counts={"ai_analysis": 5},
        regclass=lambda t: None if t == "claude_analysis_log" else t,
    )
    out = da.delete_orphaned_analyses(conn)
    assert "claude_analysis_log" not in out
    assert out["ai_analysis"] == 5


# ------------------------------------------------------- the surviving partitions


def test_the_exists_clause_consults_every_surviving_partition():
    """A row is only an orphan when its event is in neither the live table nor any
    archive still on disk. Consulting only sensor_events would delete analyses whose
    evidence is still available."""
    conn = _FakeConn(archive_tables=["archive_events_2026_06", "archive_events_2026_07"])
    clause = _render(da._event_exists_clause(conn))
    assert "sensor_events" in clause
    assert "archive_events_2026_06" in clause
    assert "archive_events_2026_07" in clause
    assert clause.count("UNION ALL") == 2


def test_with_no_archives_only_the_live_table_is_consulted():
    conn = _FakeConn(archive_tables=[])
    clause = _render(da._event_exists_clause(conn))
    assert "sensor_events" in clause
    assert "UNION ALL" not in clause


# --------------------------------------------------------------------- behaviour


def test_dry_run_counts_but_deletes_nothing():
    conn = _FakeConn(counts={"ai_analysis": 1200, "claude_analysis_log": 900})
    out = da.delete_orphaned_analyses(conn, dry_run=True)
    assert out == {"ai_analysis": 1200, "claude_analysis_log": 900}
    assert not any(s.strip().upper().startswith("DELETE") for s in conn._cur.executed)


def test_deletion_is_batched_and_commits_between_batches():
    """One transaction over 1.3M rows would hold locks against ingest for minutes."""
    n = da.ORPHAN_BATCH * 3 + 7
    conn = _FakeConn(counts={"ai_analysis": n, "claude_analysis_log": 0})
    out = da.delete_orphaned_analyses(conn)
    assert out["ai_analysis"] == n
    deletes = [s for s in conn._cur.executed if s.strip().upper().startswith("DELETE")]
    assert len(deletes) == 5, (
        "expected 4 full/partial batches plus the empty one that ends the loop"
    )
    assert conn.commits >= 4


def test_nothing_to_do_is_reported_as_zero_not_skipped():
    conn = _FakeConn(counts={"ai_analysis": 0, "claude_analysis_log": 0})
    assert da.delete_orphaned_analyses(conn) == {"ai_analysis": 0, "claude_analysis_log": 0}


# --------------------------------------------------------------------- ordering


def test_cleanup_runs_after_the_partition_drop_not_before():
    """Dropping a partition is what creates the orphans. Running the cleanup first
    would find nothing and leave a month's worth behind until the next night."""
    src = inspect.getsource(da.main)
    drop = src.index("drop_old_partitions(")
    orphan = src.index("delete_orphaned_analyses(")
    assert drop < orphan, "orphan cleanup must follow drop_old_partitions"


def test_the_cleanup_is_tied_to_retention_being_enabled():
    """No --retention-days means no partitions are dropped, so nothing is orphaned."""
    src = inspect.getsource(da.main)
    guard = src.index("if args.retention_days is not None:")
    assert guard < src.index("delete_orphaned_analyses(")


def test_there_is_an_opt_out():
    src = inspect.getsource(da.main)
    assert "--no-orphan-cleanup" in src
    assert "args.no_orphan_cleanup" in src
