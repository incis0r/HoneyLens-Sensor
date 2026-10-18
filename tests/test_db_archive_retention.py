"""Partition-retention logic for tools.db_archive — drop monthly archive
partitions whose entire month is older than the retention window."""

from datetime import date

from honeylens.tools.db_archive import _partition_is_expired

TODAY = date(2026, 6, 23)  # cutoff at 60 days = 2026-04-24


def test_old_month_is_expired():
    # March ends 2026-03-31, well before the 60-day cutoff (2026-04-24)
    assert _partition_is_expired("archive_events_2026_03", 60, TODAY) is True


def test_straddling_month_is_kept():
    # April ends 2026-04-30, which is >= cutoff -> has within-window data -> keep
    assert _partition_is_expired("archive_events_2026_04", 60, TODAY) is False


def test_recent_month_is_kept():
    assert _partition_is_expired("archive_events_2026_05", 60, TODAY) is False


def test_december_rollover():
    # Dec ends 2025-12-31; from 2026-03-15 the 60-day cutoff is 2026-01-14 -> expired
    assert _partition_is_expired("archive_events_2025_12", 60, date(2026, 3, 15)) is True
    # exact boundary (cutoff == month_end) is kept, not dropped
    assert _partition_is_expired("archive_events_2025_12", 60, date(2026, 3, 1)) is False


def test_malformed_name_is_not_expired():
    assert _partition_is_expired("archive_events_garbage", 60, TODAY) is False
    assert _partition_is_expired("archive_events_2026", 60, TODAY) is False


def test_zero_retention_expires_everything_past():
    # retention 0 -> any month ending before today is expired
    assert _partition_is_expired("archive_events_2026_05", 0, TODAY) is True
    # current month not yet ended -> not expired
    assert _partition_is_expired("archive_events_2026_06", 0, TODAY) is False
