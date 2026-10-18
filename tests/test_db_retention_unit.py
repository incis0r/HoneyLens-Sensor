"""The retention unit must actually enforce retention.

`honeylens-db-archive` has two halves. Without `--days` it moves nothing; without
`--retention-days` it moves rows into `archive_events_YYYY_MM` and **stops there** — the
data leaves the live table, the database keeps growing, and `df` tells the same story it
did before. That half-measure is exactly what a unit file silently degrades into when
someone trims the command line, so the contract is asserted here rather than left to a
reading of the unit.

The rest of this file guards the two properties that make the timer trustworthy on a host
that is not always up: it fires even if the machine was off at 03:30, and it does not run
while the nightly reclassification is still rewriting rows.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

UNIT_DIR = Path(__file__).resolve().parent.parent / "containers" / "systemd"
SERVICE = UNIT_DIR / "honeylens-db-retention.service"
TIMER = UNIT_DIR / "honeylens-db-retention.timer"


@pytest.fixture(scope="module")
def service_text() -> str:
    assert SERVICE.is_file(), f"{SERVICE.name} is missing"
    return SERVICE.read_text()


@pytest.fixture(scope="module")
def timer_text() -> str:
    assert TIMER.is_file(), f"{TIMER.name} is missing"
    return TIMER.read_text()


def _exec_start(text: str) -> str:
    lines = [ln for ln in text.splitlines() if ln.startswith("ExecStart=")]
    assert len(lines) == 1, f"expected exactly one ExecStart, found {len(lines)}"
    return lines[0]


def test_it_runs_the_archive_entry_point(service_text: str):
    assert "/.venv/bin/honeylens-db-archive" in _exec_start(service_text)


def test_it_passes_retention_days_so_disk_is_actually_freed(service_text: str):
    """The whole point. Archiving alone moves rows between tables in one database."""
    exec_start = _exec_start(service_text)
    assert "--retention-days" in exec_start, (
        "the unit archives but never drops expired partitions, so the database still "
        "grows without bound — pass --retention-days"
    )


@pytest.mark.parametrize("flag", ["--days", "--retention-days"])
def test_both_windows_are_thirty_days(service_text: str, flag: str):
    match = re.search(rf"{re.escape(flag)}\s+(\d+)", _exec_start(service_text))
    assert match, f"{flag} has no value"
    assert match.group(1) == "30", f"{flag} is {match.group(1)}, expected 30"


def test_it_does_not_quietly_skip_the_delete(service_text: str):
    """`--no-cleanup` leaves every archived row in the live table as well."""
    assert "--no-cleanup" not in service_text


def test_the_timer_survives_a_host_that_was_off(timer_text: str):
    assert "Persistent=true" in timer_text, (
        "without Persistent=true a sensor that is down at 03:30 skips retention entirely "
        "until the next night, and the skips are invisible"
    )


def test_retention_runs_after_the_nightly_backfill(timer_text: str):
    """auto-backfill runs at 01:00 and rewrites classifications on old rows."""
    match = re.search(r"OnCalendar=\*-\*-\* (\d{2}):(\d{2}):\d{2}", timer_text)
    assert match, "the timer has no daily OnCalendar"
    hour, minute = int(match.group(1)), int(match.group(2))
    assert (hour, minute) > (1, 0), (
        f"retention fires at {hour:02d}:{minute:02d}, at or before the 01:00 backfill — "
        "it would move rows the backfill is still rewriting"
    )


def test_the_unit_documents_the_monthly_granularity(service_text: str):
    """Partitions are monthly, so "30 days" is really 30-61. An operator reading the
    unit to answer "how long do we keep evidence" must not be told 30 flat."""
    assert "61" in service_text, (
        "the unit does not say that monthly partitions make the real window 30-61 days"
    )
