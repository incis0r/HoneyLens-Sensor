"""The orphan sweep covers every per-event table, and says so where a reader will look.

The 4.4 GB precedent in `delete_orphaned_analyses`'s docstring added two tables to a
list and left the next table unprotected. `ics_events` was that next table, swept from
2026-10-25. `llm_honeypot_events` followed on 2026-10-25 (61 of sensor-d's 62 rows dangling).

`mitm_events` was added in the same edit and then removed, which is the case these tests
exist to prevent repeating. It has the same shape -- event_id VARCHAR(64) UNIQUE NOT
NULL, no foreign key, 4280 of 4280 rows on prod with no matching sensor_event -- but
mitm_detector.py mints that id itself, so there is no referent and 100% is correct
forever. Sweeping it would delete 209 live network observations a day, nightly, in
silence. Membership here is about having a referent, not about sharing a column name.

These tests pin that, plus the thing that kept going wrong: the tuple's contents
documented with measured numbers rather than asserted. They deliberately do NOT pin a
specific count -- an assertion on the digits is what made the earlier version of this
file need editing every time a number was re-measured.
"""

from __future__ import annotations

import inspect
import re

from honeylens.tools import db_archive

# Tables whose event_id REFERENCES a sensor_event, so a missing event makes the row
# dangling. mitm_events is deliberately not here: it mints its own id.
PER_EVENT_TABLES = (
    "ai_analysis",
    "claude_analysis_log",
    "ics_events",
    "llm_honeypot_events",
)


def test_every_per_event_table_is_swept():
    for t in PER_EVENT_TABLES:
        assert t in db_archive.ORPHAN_TABLES, f"{t} would dangle with nothing to remove it"


def test_the_analysis_tables_are_still_swept():
    """ANALYSIS_TABLES must stay inside ORPHAN_TABLES however the tuple is rebuilt."""
    for t in db_archive.ANALYSIS_TABLES:
        assert t in db_archive.ORPHAN_TABLES


def test_each_swept_table_is_documented_with_a_measured_number():
    """A sweep list that is silently incomplete is how ics_events was missed, and a list
    documented with hand-waving is how it stayed missed. Every table the nightly timer
    deletes from must be named in the docstring on a line that carries a figure."""
    doc = db_archive.delete_orphaned_analyses.__doc__ or ""
    for t in db_archive.ORPHAN_TABLES:
        lines = [ln for ln in doc.splitlines() if t in ln]
        assert lines, f"{t} is swept but not named in the docstring"
        assert any(re.search(r"\d", ln) for ln in lines), (
            f"{t} is named but with no measured figure beside it"
        )


def test_a_table_that_mints_its_own_event_id_is_not_swept():
    """The one that nearly went wrong. mitm_events shares the column name and reads as
    100% orphaned, but mitm_detector.py generates the id, so nothing is dangling and the
    nightly timer would delete 209 live observations a day."""
    assert "mitm_events" not in db_archive.ORPHAN_TABLES


def test_the_reason_mitm_events_is_excluded_is_written_down():
    """Removing it from the tuple without saying why invites the next reader to add it
    back -- the exact failure the 4.4 GB precedent records for the opposite direction."""
    doc = db_archive.delete_orphaned_analyses.__doc__ or ""
    assert "mitm_events is NOT here" in doc
    assert "mitm_detector" in doc, "the docstring must name the writer that mints the id"
    assert "referent" in doc, "the rule is about having a referent, not a column name"


def test_the_sweep_counts_archived_events_as_existing():
    """An event in archive_events_* is not gone, so its derivations are not orphans.
    The clause is composed from the partitions that exist now, via get_archive_tables,
    so that call is what pins the property -- the table names never appear literally."""
    assert "get_archive_tables" in inspect.getsource(db_archive._event_exists_clause)
