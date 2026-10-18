"""The trim must be allowed to finish, or the archive copy is made and never collected.

Measured on `prod`, 2026-11-14 03:31:35 → 03:40:07, exit 1, every night:

    Found 1558088 events to archive for 2026-10
    Archived 1558088/1558088 events for 2026-10
    Deleting archived events from sensor_events...
    Deleted 250000 events from main table
    [ERROR] Error archiving 2026-10: canceling statement due to statement timeout
    CONTEXT: SQL statement "DELETE FROM ONLY "public"."attack_patterns" WHERE $1 = "event_id""
      the live table is NOT being trimmed

The copy commits per batch and the trim does not finish, so the result is the worst of
both: `archive_events_2026_10` held 3 327 324 rows (2 186 MB) while `sensor_events` still
held 4 075 730 October rows, and the oldest live row was 2026-10-13 against a 30-day floor
that should have started at 10-15.

Nothing here is pathological. `attack_patterns` holds 4 109 524 rows against
`sensor_events`' 4 126 539 — row parity, because whoever writes a verdict writes both — and
the foreign key is ``ON DELETE CASCADE``, so each of the 10 000 parents in a batch fires a
child delete. The column is indexed, so this is not a missing index; it is 10 000 cascades
in one statement against a 30-second ``statement_timeout``.

`db_archive.py` already knows this. `get_months_to_archive` lifts the timeout for its read,
with a comment describing the same self-reinforcing failure — "nightly archive never ran,
so the table grew, so the next night's query took even longer". The delete loop never got
the same treatment.

**And the trap in fixing it:** ``SET LOCAL`` is scoped to the transaction, and the delete
loop commits after every batch. One ``SET LOCAL`` before the loop would be lifted for the
first batch and gone for the rest, which looks like a working fix on a small table and
fails exactly where this one failed. These tests pin per-batch renewal, not just presence.
"""

from __future__ import annotations

from datetime import UTC, datetime

from honeylens.tools import db_archive

COMMIT = "<commit>"


def _kind(q) -> str:
    """Which statement this is, for a fake that has to answer them differently."""
    if isinstance(q, str):
        text = " ".join(q.split())
        if "DELETE FROM sensor_events" in text:
            return "delete"
        if "statement_timeout" in text:
            return "timeout"
        return "other"
    # `psycopg2.sql` composables: the archive copy, the table DDL, and the check that
    # every row in range is in the archive before anything is deleted.
    head = " ".join(q.seq[0].string.split())
    if head.startswith("INSERT INTO"):
        return "copy"
    if head.startswith("SELECT count(*)"):
        return "archived_check"
    return "other"


class RecordingCursor:
    """Records the statement text in order, with the commits marked.

    Only plain-string statements are recorded: the archive copy, the table DDL and the
    archived-ness check are built with `psycopg2.sql` composables, and this test is about
    the two plain statements that matter — the DELETE and whatever lifts the timeout
    before it. The composables still have to be *answered*, so they are classified.
    """

    def __init__(
        self,
        log: list[str],
        count: int,
        delete_rowcounts: list[int],
        copy_rowcounts: list[int],
    ):
        self._log = log
        self._count = count
        self._deletes = list(delete_rowcounts)
        self._copies = list(copy_rowcounts)
        self._last = "other"

    def execute(self, q, params=None):
        if isinstance(q, str):
            self._log.append(" ".join(q.split()))
        self._last = _kind(q)

    def fetchone(self):
        # Nothing in range is missing from the archive, so the trim is allowed to run;
        # `test_archive_copy_is_idempotent.py` pins the refusal when it is not.
        if self._last == "archived_check":
            return (0,)
        return (self._count,)

    @property
    def rowcount(self):
        if self._last == "delete":
            return self._deletes.pop(0) if self._deletes else 0
        if self._last == "copy":
            return self._copies.pop(0) if self._copies else 0
        return db_archive.BATCH_SIZE

    def close(self):
        pass


class RecordingConn:
    def __init__(
        self,
        count=25_000,
        delete_rowcounts=(10_000, 10_000, 5_000, 0),
        copy_rowcounts=(10_000, 10_000, 5_000, 0),
    ):
        self.log: list[str] = []
        self.cur = RecordingCursor(self.log, count, list(delete_rowcounts), list(copy_rowcounts))

    def cursor(self, *a, **kw):
        return self.cur

    def commit(self):
        self.log.append(COMMIT)

    def rollback(self):
        pass


def _run_one_month() -> list[str]:
    conn = RecordingConn()
    db_archive.archive_month(conn, 2026, 10, dry_run=False, cleanup=True)
    return conn.log


def _lifts_timeout(stmt: str) -> bool:
    return "statement_timeout" in stmt


def _is_delete(stmt: str) -> bool:
    return "DELETE FROM sensor_events" in stmt


def _transactions(log: list[str]) -> list[list[str]]:
    """The log split at commits: one list of statements per transaction."""
    out: list[list[str]] = [[]]
    for stmt in log:
        if stmt == COMMIT:
            out.append([])
        else:
            out[-1].append(stmt)
    return out


def test_the_trim_runs_at_all():
    """Guards the fixture itself: a test about the DELETE needs the DELETE to happen."""
    log = _run_one_month()
    assert [s for s in log if _is_delete(s)], "no delete was issued, so nothing is pinned"


def test_every_delete_batch_is_exempt_from_the_statement_timeout():
    """A 10 000-row cascade cannot be assumed to fit in 30 seconds."""
    for statements in _transactions(_run_one_month()):
        deletes = [i for i, s in enumerate(statements) if _is_delete(s)]
        if not deletes:
            continue
        lifted = [i for i, s in enumerate(statements) if _lifts_timeout(s)]
        assert lifted, "a delete batch ran under the session statement_timeout"
        assert min(lifted) < min(deletes), (
            "the timeout was lifted after the delete it was meant to protect"
        )


def test_the_exemption_is_renewed_for_every_batch():
    """The trap: `SET LOCAL` dies at the commit that ends each batch.

    On a table small enough for one batch, a single lift before the loop passes the test
    above and still fails in production. Counting is what catches it.
    """
    log = _run_one_month()
    deletes = len([s for s in log if _is_delete(s)])
    lifts = len([s for s in log if _lifts_timeout(s)])
    assert deletes >= 2, "the fixture must span more than one batch for this to mean anything"
    assert lifts >= deletes, f"{lifts} timeout lifts for {deletes} delete batches"


def test_the_exemption_is_transaction_scoped_not_session_wide():
    """This connection is handed back to a pool. A session-wide `SET statement_timeout`
    would silently remove the guard from every later query that borrows it.
    """
    lifts = [s for s in _run_one_month() if _lifts_timeout(s)]
    assert lifts, "nothing lifts the timeout"
    for stmt in lifts:
        assert stmt.upper().startswith("SET LOCAL "), f"not transaction-scoped: {stmt!r}"


def test_a_dry_run_still_deletes_nothing():
    """Unchanged behaviour, asserted because the delete branch is being edited."""
    conn = RecordingConn()
    db_archive.archive_month(
        conn, 2026, 10, dry_run=True, cleanup=True, not_after=datetime(2026, 11, 14, tzinfo=UTC)
    )
    assert not [s for s in conn.log if _is_delete(s)]


def test_cleanup_disabled_still_skips_the_trim():
    conn = RecordingConn()
    db_archive.archive_month(conn, 2026, 10, dry_run=False, cleanup=False)
    assert not [s for s in conn.log if _is_delete(s)]
