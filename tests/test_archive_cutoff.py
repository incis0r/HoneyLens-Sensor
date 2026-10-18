"""Retention must honour `--days`, not "whole months only".

`archive_month` moved a calendar month at a time, so `archive_events` had to stop before
the month containing the cutoff — otherwise it would have moved data newer than the
retention window. The consequence was that every row in that month stayed in the live
table however old it was: on the 11th, with `--days 30`, the whole of the previous month.
On one sensor that was 476,605 rows and roughly 4.7 GB waiting for the month to close,
while the unit reported success every night.

The fix is a `not_after` bound so the final month can be archived up to the cutoff
timestamp rather than skipped. These tests pin the boundary, because getting it wrong in
the other direction would delete data that is still inside the retention window.
"""

from __future__ import annotations

from datetime import UTC, datetime

from honeylens.tools import db_archive


class FakeCursor:
    """Records the date range each statement was given."""

    def __init__(self, count):
        self._count = count
        self.ranges = []

    def execute(self, q, params=None):
        if params and len(params) >= 2 and isinstance(params[0], datetime):
            self.ranges.append((params[0], params[1]))

    def fetchone(self):
        return (self._count,)


class FakeConn:
    def __init__(self, count=5):
        self.cur = FakeCursor(count)

    def cursor(self):
        return self.cur

    def commit(self):
        pass


def test_a_whole_past_month_is_unbounded(monkeypatch):
    """A month entirely behind the cutoff is moved in full, as before."""
    conn = FakeConn()
    db_archive.archive_month(
        conn, 2026, 7, dry_run=True, not_after=datetime(2026, 9, 11, tzinfo=UTC)
    )
    start, end = conn.cur.ranges[0]
    assert (start, end) == (datetime(2026, 7, 1, tzinfo=UTC), datetime(2026, 8, 1, tzinfo=UTC))


def test_the_cutoff_month_is_clamped_to_the_cutoff(monkeypatch):
    """The case that was being skipped entirely."""
    conn = FakeConn()
    cutoff = datetime(2026, 8, 12, 13, 30, tzinfo=UTC)
    db_archive.archive_month(conn, 2026, 8, dry_run=True, not_after=cutoff)
    start, end = conn.cur.ranges[0]
    assert start == datetime(2026, 8, 1, tzinfo=UTC)
    assert end == cutoff, "must stop at the cutoff, not at the end of the month"


def test_nothing_newer_than_the_cutoff_is_ever_touched():
    """The direction that would lose data still inside the retention window."""
    conn = FakeConn()
    cutoff = datetime(2026, 9, 1, tzinfo=UTC)
    db_archive.archive_month(conn, 2026, 9, dry_run=True, not_after=cutoff)
    assert conn.cur.ranges == [], "a month starting at or after the cutoff must be skipped"


def test_a_tz_aware_cutoff_does_not_raise():
    """get_months_to_archive derives its cutoff from a tz-aware column; archive_month
    builds naive month bounds. Mixing them raises TypeError on comparison."""

    conn = FakeConn()
    cutoff = datetime(2026, 8, 12, tzinfo=UTC)
    db_archive.archive_month(conn, 2026, 8, dry_run=True, not_after=cutoff)
    _start, end = conn.cur.ranges[0]
    assert end == datetime(2026, 8, 12, tzinfo=UTC)


def test_without_a_bound_behaviour_is_unchanged():
    conn = FakeConn()
    db_archive.archive_month(conn, 2026, 7, dry_run=True)
    assert conn.cur.ranges[0] == (
        datetime(2026, 7, 1, tzinfo=UTC),
        datetime(2026, 8, 1, tzinfo=UTC),
    )


# --- month enumeration -----------------------------------------------------------


class MonthConn:
    def __init__(self, min_ts):
        self._min = min_ts

    def cursor(self):
        return self

    def execute(self, *a, **k):
        pass

    def fetchone(self):
        return (self._min,)


def test_the_cutoff_month_is_now_enumerated():
    """`<` here is what excluded it. With `<=` the month is listed and clamped later."""
    conn = MonthConn(datetime(2026, 6, 15, tzinfo=UTC))
    months = db_archive.get_months_to_archive(conn, days=30)
    ym = [(y, m) for y, m, _ in months]
    assert (2026, 6) in ym and (2026, 7) in ym
    now = datetime.now()
    from datetime import timedelta

    cutoff = now - timedelta(days=30)
    assert (cutoff.year, cutoff.month) in ym, (
        "the month containing the cutoff must be enumerated, not skipped"
    )


def test_a_recent_only_table_yields_nothing():
    from datetime import timedelta

    conn = MonthConn(datetime.now() - timedelta(days=3))
    assert db_archive.get_months_to_archive(conn, days=30) == []
