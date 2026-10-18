"""A hand-run authoritative pass has to record which rules it ran.

`auto_backfill` decides whether to reprocess by comparing today's rule fingerprint against the
one stored in `classification_state`. Until 2026-11-05 only `auto_backfill` wrote that row, so
the Phase Z pass -- run by hand, deliberately, on all six sensors -- left every one of them
still reporting `would_reprocess`. Re-arming the timers would have reprocessed 7.7M events on
`sensor-a` a second time for no change in the result.

The tests below pin the part that is easy to get wrong: a pass that covered only part of the
store must NOT stamp, because a false stamp suppresses the reprocess that store still needs.
"""

from __future__ import annotations

import pytest

from honeylens.tools.backfill_attacks import BackfillConfig, record_fingerprint_if_authoritative


@pytest.fixture
def recorded(monkeypatch):
    """Capture what would be written, without a database."""
    written: list[str] = []

    class _Conn:
        def close(self):
            pass

    monkeypatch.setattr("honeylens.database.legacy_get_db", lambda: _Conn())
    monkeypatch.setattr("honeylens.tools.auto_backfill._ensure_state_table", lambda conn: None)
    monkeypatch.setattr("honeylens.tools.auto_backfill._store", lambda conn, fp: written.append(fp))
    return written


def test_a_full_authoritative_pass_records_the_fingerprint(recorded):
    assert record_fingerprint_if_authoritative(BackfillConfig(replace_patterns=True)) is True
    assert len(recorded) == 1


def test_the_recorded_value_is_the_one_auto_backfill_compares_against(recorded):
    """A fingerprint computed any other way would make the timer reprocess forever."""
    from honeylens.tools.auto_backfill import rules_fingerprint

    record_fingerprint_if_authoritative(BackfillConfig(replace_patterns=True))

    assert recorded == [rules_fingerprint()]


def test_a_dry_run_records_nothing(recorded):
    """It wrote no patterns, so the store has not been reprocessed."""
    config = BackfillConfig(replace_patterns=True, dry_run=True)

    assert record_fingerprint_if_authoritative(config) is False
    assert recorded == []


def test_a_limited_pass_records_nothing(recorded):
    """`--limit` covers part of the store. Stamping would suppress the rest of the work."""
    config = BackfillConfig(replace_patterns=True, limit=1000)

    assert record_fingerprint_if_authoritative(config) is False
    assert recorded == []


def test_a_pass_that_is_not_authoritative_records_nothing(recorded):
    """Without `--replace-patterns` the pass only fills gaps: it never drops a stale row, so it
    cannot claim the store matches today's rules."""
    config = BackfillConfig(reprocess_all=True)

    assert record_fingerprint_if_authoritative(config) is False
    assert recorded == []


def test_an_interrupted_pass_does_not_reach_the_recording():
    """The CLI returns on KeyboardInterrupt rather than falling through to the stamp."""
    import inspect

    from honeylens.tools import backfill_attacks

    src = inspect.getsource(backfill_attacks.main)
    interrupt = src.index("except KeyboardInterrupt")
    stamp = src.index("record_fingerprint_if_authoritative(config)")

    assert "return" in src[interrupt:stamp], "the interrupt path must not fall into the stamp"


def test_the_timer_goes_quiet_after_a_recorded_pass(monkeypatch):
    """The whole point: `auto_backfill` must then decide there is nothing to do."""
    from honeylens.tools import auto_backfill

    monkeypatch.setattr(auto_backfill, "rules_fingerprint", lambda: "deadbeefdeadbeef")
    monkeypatch.setattr(auto_backfill, "_get_stored", lambda conn: "deadbeefdeadbeef")

    assert auto_backfill._get_stored(None) == auto_backfill.rules_fingerprint()
