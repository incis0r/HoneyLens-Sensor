"""A night whose trim fails must not make the archive bigger the next night.

Measured on `prod`, 2026-11-14. The copy is `INSERT INTO archive_events_2026_10 SELECT
... FROM sensor_events WHERE <range>`, the archive's only index on `event_id` is not
unique, and there is no `ON CONFLICT`. So while the trim was failing (see
`test_archive_delete_survives_statement_timeout.py`) every night re-copied rows that were
already there:

    archive_events_2026_10   3 327 324 rows   but   2 341 920 distinct event_id
                             -> 985 404 duplicate rows, 2 186 MB of table
    archived_at per day      11-07: 3 510   ...   11-12: 662 810   11-13: 985 404
                             11-14: 1 558 088 -- growing, because the window slides
                             forward while nothing is ever removed

and the next run would have added 1 308 088 more: of the 1 409 120 rows then due for
archiving, that many were already in the archive. 93% of the copy was pure duplication.

Two properties are needed, and the second is the one that bites:

1. The copy skips rows the archive already holds, so a repeated run is a no-op.
2. The trim still runs when the copy copied nothing. This is exactly `prod`'s state --
   every row due is already archived -- and the old gate was `if cleanup and archived > 0`,
   so making the copy idempotent without moving that gate would have left the live table
   untrimmed forever while every night reported success. The archive is the reason to
   delete; this run's insert count is not.

Because the trim no longer takes the copy's row count as its evidence, it asks the
database directly: no row in the range may be missing from the archive. That check is the
guard on a 1.4 M-row delete, so it is tested in both directions.

Paging goes with the predicate. `LIMIT ... OFFSET n` over a result set that shrinks as you
insert into it skips rows: batch 1's rows stop matching, so the window at OFFSET 10000
starts past rows never copied. The copy pages the way the trim does -- always the first
`BATCH_SIZE` rows that still match -- and stops when a pass copies nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime

from psycopg2 import sql

from honeylens.tools import db_archive

COMMIT = "<commit>"


def statement_text(q) -> str:
    """The text of a plain statement or of a `psycopg2.sql` composable.

    The copy is built with composables, so a fake that only records `str` statements --
    as the timeout test's fake does, because it is about the plain DELETE -- cannot see
    the copy at all.
    """
    if isinstance(q, str):
        return " ".join(q.split())
    parts = []
    for part in q.seq:
        if isinstance(part, sql.SQL):
            parts.append(part.string)
        elif isinstance(part, sql.Identifier):
            parts.append(".".join(part.strings))
        else:  # pragma: no cover - the archive builds nothing else
            parts.append(str(part))
    return " ".join("".join(parts).split())


def kind_of(text: str) -> str:
    if "statement_timeout" in text:
        return "timeout"
    if text.startswith("INSERT INTO"):
        return "copy"
    if text.startswith("DELETE FROM sensor_events"):
        return "delete"
    if "NOT EXISTS" in text and "FROM sensor_events" in text and "count(*)" in text.lower():
        return "verify"
    if "COUNT(*) FROM SENSOR_EVENTS" in text.upper():
        return "count"
    return "other"


class FakeCursor:
    def __init__(self, log, *, count, copy_rowcounts, delete_rowcounts, unarchived):
        self._log = log
        self._count = count
        self._copy = list(copy_rowcounts)
        self._delete = list(delete_rowcounts)
        self._unarchived = unarchived
        self._last = "other"
        self.params: list[tuple] = []

    def execute(self, q, params=None):
        text = statement_text(q)
        self._log.append(text)
        self._last = kind_of(text)
        if self._last in ("copy", "delete"):
            self.params.append((self._last, params))

    def fetchone(self):
        if self._last == "verify":
            return (self._unarchived,)
        return (self._count,)

    @property
    def rowcount(self):
        if self._last == "copy":
            return self._copy.pop(0) if self._copy else 0
        if self._last == "delete":
            return self._delete.pop(0) if self._delete else 0
        return 0

    def close(self):
        pass


class FakeConn:
    def __init__(
        self,
        *,
        count=25_000,
        copy_rowcounts=(10_000, 10_000, 5_000, 0),
        delete_rowcounts=(10_000, 10_000, 5_000, 0),
        unarchived=0,
    ):
        self.log: list[str] = []
        self.cur = FakeCursor(
            self.log,
            count=count,
            copy_rowcounts=copy_rowcounts,
            delete_rowcounts=delete_rowcounts,
            unarchived=unarchived,
        )

    def cursor(self, *a, **kw):
        return self.cur

    def commit(self):
        self.log.append(COMMIT)

    def rollback(self):
        pass


def run(conn, **kw) -> list[str]:
    kw.setdefault("dry_run", False)
    kw.setdefault("cleanup", True)
    db_archive.archive_month(conn, 2026, 10, **kw)
    return conn.log


def of_kind(log: list[str], kind: str) -> list[str]:
    return [s for s in log if s != COMMIT and kind_of(s) == kind]


# ---------------------------------------------------------------------------
# 1. The copy does not re-copy
# ---------------------------------------------------------------------------


def test_the_copy_skips_rows_the_archive_already_holds():
    copies = of_kind(run(FakeConn()), "copy")
    assert copies, "no copy statement was issued, so nothing is pinned"
    for stmt in copies:
        assert "NOT EXISTS" in stmt, (
            "the copy re-inserts rows already archived; prod accumulated 985 404 of them"
        )
        assert "archive_events_2026_10" in stmt


def test_the_skip_predicate_matches_on_event_id():
    """Not on the timestamp range: the range is what was already copied once."""
    stmt = of_kind(run(FakeConn()), "copy")[0]
    tail = stmt[stmt.index("NOT EXISTS") :]
    assert "event_id" in tail, f"the skip is not keyed on event_id: {tail[:120]}"


def test_the_copy_does_not_page_by_offset():
    """`OFFSET n` over a set that shrinks as you insert into it skips rows."""
    conn = FakeConn()
    run(conn)
    for stmt in of_kind(conn.log, "copy"):
        assert "OFFSET" not in stmt.upper(), (
            "offset paging plus a skip predicate walks past rows never copied"
        )
    for kind, params in conn.cur.params:
        if kind == "copy":
            assert params[-1] == db_archive.BATCH_SIZE, (
                f"the copy still carries an offset parameter: {params!r}"
            )


def test_the_copy_stops_when_a_pass_copies_nothing():
    conn = FakeConn(count=10**9, copy_rowcounts=(10_000, 0))
    assert len(of_kind(run(conn), "copy")) == 2, (
        "the copy must stop on an empty pass, not on a row count it can no longer reach"
    )


def test_a_fully_redundant_copy_issues_exactly_one_pass():
    """prod's state: everything due is already in the archive."""
    conn = FakeConn(copy_rowcounts=(0,))
    assert len(of_kind(run(conn), "copy")) == 1


# ---------------------------------------------------------------------------
# 2. The trim's evidence is the archive, not this run's insert count
# ---------------------------------------------------------------------------


def test_the_trim_runs_when_the_copy_copied_nothing():
    """The regression that would have left prod broken while reporting success."""
    conn = FakeConn(copy_rowcounts=(0,))
    assert of_kind(run(conn), "delete"), (
        "every row due was already archived, so nothing was copied and nothing was trimmed"
    )


def test_the_trim_asks_the_database_whether_the_range_is_archived():
    assert of_kind(run(FakeConn(copy_rowcounts=(0,))), "verify"), (
        "the trim deletes 1.4 M rows on no evidence that they were copied"
    )


def test_the_trim_is_refused_when_a_row_in_range_is_not_archived():
    conn = FakeConn(copy_rowcounts=(0,), unarchived=1)
    assert not of_kind(run(conn), "delete"), (
        "rows would be deleted from the live table with no copy in the archive"
    )


def test_the_check_runs_before_the_first_delete():
    log = run(FakeConn())
    kinds = [kind_of(s) for s in log if s != COMMIT]
    assert "verify" in kinds and "delete" in kinds
    assert kinds.index("verify") < kinds.index("delete")


# ---------------------------------------------------------------------------
# 3. Unchanged behaviour, asserted because this branch is being edited
# ---------------------------------------------------------------------------


def test_a_dry_run_neither_copies_nor_deletes():
    conn = FakeConn()
    db_archive.archive_month(
        conn, 2026, 10, dry_run=True, cleanup=True, not_after=datetime(2026, 11, 14, tzinfo=UTC)
    )
    assert not of_kind(conn.log, "copy") and not of_kind(conn.log, "delete")


def test_cleanup_disabled_still_copies_but_never_deletes():
    conn = FakeConn()
    run(conn, cleanup=False)
    assert of_kind(conn.log, "copy")
    assert not of_kind(conn.log, "delete")


def test_an_empty_month_does_no_work_at_all():
    conn = FakeConn(count=0)
    assert db_archive.archive_month(conn, 2026, 10, dry_run=False, cleanup=True) == 0
    assert not of_kind(conn.log, "copy") and not of_kind(conn.log, "delete")
