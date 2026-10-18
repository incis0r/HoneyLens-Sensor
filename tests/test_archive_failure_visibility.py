"""A month that fails to archive must not look like a successful run.

Found in production. Every month failed on a foreign key —
attack_patterns/ja4_fingerprints/threat_scores referenced sensor_events with the
default ON DELETE NO ACTION, so deleting archived rows from the live table was
refused. The run printed "Total archived: 0 events", the partition-drop step ran
anyway and succeeded, and systemd recorded the unit as successful.

The result was the worst of both: 7,873,995 rows older than 60 days sat in
sensor_events (April 2.68M, May 2.55M, June 2.61M) while the archive partitions
for those same months were being dropped. Nothing in the unit status said so.

migrations/0007_event_fk_cascade.sql removes the cause; these tests pin the
symptom, so a future cause cannot hide the same way.
"""

from __future__ import annotations

import inspect
import pathlib

from honeylens.tools import db_archive as da


def _main_src():
    return inspect.getsource(da.main)


def test_a_failed_month_is_recorded_as_negative_not_dropped():
    """archive_events signals failure per month with -1; main must look at it."""
    src = inspect.getsource(da.archive_events)
    assert "results[key] = -1" in src
    assert "failed_months" in _main_src(), "main ignores the failure signal"


def test_failures_are_printed_separately_from_the_total():
    """'Total archived: 0 events' on its own reads as 'nothing to do'."""
    src = _main_src()
    assert "ARCHIVE FAILURES" in src
    assert src.index("Total archived") < src.index("ARCHIVE FAILURES"), (
        "the failure block belongs after the total it contradicts"
    )


def test_the_run_exits_non_zero_so_systemd_shows_it_red():
    src = _main_src()
    assert "if failed_months:" in src and "return 1" in src


def test_the_exit_code_reaches_the_process():
    """`main()` returning 1 is useless if __main__ throws it away."""
    tail = pathlib.Path(da.__file__).read_text()
    i = tail.rindex('if __name__ == "__main__":')
    assert "SystemExit" in tail[i:], "main()'s return value is discarded"


def test_partition_drop_still_runs_after_a_failure():
    """Retention must not stop dead: dropping expired partitions is still correct
    and the operator needs the disk back either way. The failure is reported, not
    used to skip the rest."""
    src = _main_src()
    assert src.index("ARCHIVE FAILURES") < src.index("drop_old_partitions("), (
        "the failure report must not short-circuit partition retention"
    )


def test_migration_0007_exists_and_is_idempotent():
    p = (
        pathlib.Path(__file__).resolve().parents[1]
        / "src"
        / "honeylens"
        / "db"
        / "migrations"
        / "0007_event_fk_cascade.sql"
    )
    assert p.exists()
    sql = p.read_text()
    assert "ON DELETE CASCADE" in sql
    assert "confdeltype <> 'c'" in sql, "must skip constraints already converted"
    assert "to_regclass" in sql, "must tolerate a table the profile does not have"


def test_migration_0007_covers_the_three_child_tables():
    p = (
        pathlib.Path(__file__).resolve().parents[1]
        / "src"
        / "honeylens"
        / "db"
        / "migrations"
        / "0007_event_fk_cascade.sql"
    )
    sql = p.read_text()
    for t in ("attack_patterns", "ja4_fingerprints", "threat_scores"):
        assert t in sql, f"{t} references sensor_events and blocks archiving"
