"""A NUL byte in one pattern must not erase a whole batch's labels.

Measured on `sensor-e` 2026-11-19 01:00-01:18. The authoritative nightly pass
(`auto_backfill` -> `replace_patterns=True`) classified 37,832 events, found
16,838 attacks (44.5%) and 43,747 patterns, then failed every write of the
affected batches:

    COPY failed, using batch insert: invalid byte sequence for encoding "UTF8": 0x00
    [ERROR] Error writing patterns: A string literal cannot contain NUL (0x00) characters.

`write_patterns_copy` sanitises tab, newline, CR and backslash in `matched_text`
but not NUL, and this module never imports `strip_nul` -- which the sink, all
four ingests and two sibling backfills do use. The fallback then dies
client-side in psycopg2 and returns 0.

The damage is not the skipped write. In `replace_patterns` mode the caller had
already dropped the central rows for those events and then called
`rebuild_attack_types(batch_ids)`, which derives `attack_types` from the
patterns *actually present* -- none. So one NUL anywhere in a batch wrote
"no attack" over up to `--batch-size` events, including every event whose own
matched_text was clean. The run then printed `Backfill complete` and the
fingerprint was stamped, so the next tick saw no rule change and never retried:
the hole is frozen in until a rule changes.

Three properties below: NUL never reaches the database; a lost batch never
blanks a label; a run that lost a batch does not claim the store matches
today's rules.
"""

from __future__ import annotations

import pytest

from honeylens.tools import backfill_attacks as ba

NUL = "\x00"


class _Cur:
    def __init__(self, sink: dict):
        self.sink = sink

    def copy_from(self, f, table, columns=None, null=None):
        data = f.read()
        self.sink["copy"] = data
        # Postgres refuses the whole COPY stream on one NUL byte.
        if NUL in data:
            raise ba.psycopg2.DataError('invalid byte sequence for encoding "UTF8": 0x00')

    def execute(self, *a, **k):
        pass


class _Conn:
    def __init__(self, sink: dict):
        self.sink = sink

    def cursor(self):
        return _Cur(self.sink)

    def commit(self):
        self.sink.setdefault("commits", 0)
        self.sink["commits"] += 1

    def rollback(self):
        self.sink.setdefault("rollbacks", 0)
        self.sink["rollbacks"] += 1


@pytest.fixture
def db(monkeypatch):
    """A connection that behaves like Postgres and psycopg2 do about NUL."""
    sink: dict = {}
    monkeypatch.setattr(ba, "get_connection", lambda: _Conn(sink))
    monkeypatch.setattr(ba, "put_connection", lambda conn: None)

    def _execute_batch(cur, sql, rows, page_size=None):
        sink["batch"] = list(rows)
        for row in rows:
            for field in row:
                if isinstance(field, str) and NUL in field:
                    raise ValueError("A string literal cannot contain NUL (0x00) characters.")

    monkeypatch.setattr(ba.psycopg2.extras, "execute_batch", _execute_batch)
    return sink


# --- 1. NUL never reaches the database -------------------------------------


def test_copy_carries_no_nul_byte(db):
    """The real payload: `%00` in a path arrives as a true NUL in matched_text."""
    patterns = [("evt-1", "SENSITIVE_FILE", "env_file", f"/.env{NUL}.copy", "high")]

    written = ba.write_patterns_copy(patterns)

    assert NUL not in db["copy"]
    assert written == 1


def test_the_clean_rows_of_a_batch_are_written_too(db):
    """One poisoned row must not cost the other 43,746 their evidence."""
    patterns = [
        ("evt-1", "SCANNER", "scanner_ua", "zgrab", "low"),
        ("evt-2", "SENSITIVE_FILE", "env_file", f"/.env{NUL}", "high"),
        ("evt-3", "WORDPRESS_RECON", "wp_login", "/wp-login.php", "medium"),
    ]

    written = ba.write_patterns_copy(patterns)

    assert written == 3
    assert db["copy"].count("\n") == 3


def test_batch_insert_strips_nul_from_every_text_field(db):
    """The fallback path dies client-side, so it needs the same scrub -- on every
    column, not just matched_text: a NUL in a decoy-authored attack_type would
    kill the batch just as dead."""
    patterns = [(f"evt{NUL}1", f"SC{NUL}ANNER", f"ru{NUL}le", f"te{NUL}xt", "low")]

    written = ba.write_patterns_batch(patterns)

    assert written == 1
    assert all(NUL not in f for f in db["batch"][0] if isinstance(f, str))


def test_batch_insert_without_severity_strips_nul_too(db):
    patterns = [("evt-1", "SCANNER", "rule", f"te{NUL}xt", "low")]

    written = ba.write_patterns_batch(patterns, has_severity=False)

    assert written == 1
    assert all(NUL not in f for f in db["batch"][0] if isinstance(f, str))


# --- 2. A lost batch never blanks a label ----------------------------------


@pytest.fixture
def steps(monkeypatch):
    """Record the authoritative write sequence without a database."""
    calls: list[str] = []
    monkeypatch.setattr(
        ba, "delete_patterns_for_events", lambda ids, dry_run=False: calls.append("delete") or 0
    )
    monkeypatch.setattr(
        ba, "rebuild_attack_types", lambda ids, dry_run=False: calls.append("rebuild") or 0
    )
    return calls


def test_a_lost_pattern_batch_does_not_rebuild_attack_types(steps, monkeypatch):
    """`rebuild_attack_types` derives the label from the patterns present. With the
    write lost, "present" is empty and the rebuild writes NULL over real labels."""
    monkeypatch.setattr(ba, "write_patterns_copy", lambda *a, **k: 0)
    config = ba.BackfillConfig(replace_patterns=True)

    persisted = ba.write_patterns_authoritative(
        ["evt-1", "evt-2"],
        [("evt-1", "SCANNER", "rule", "text", "low")],
        config,
        has_severity=True,
        has_patterns=True,
    )

    assert persisted is False
    assert "rebuild" not in steps


def test_a_written_pattern_batch_does_rebuild(steps, monkeypatch):
    monkeypatch.setattr(ba, "write_patterns_copy", lambda p, **k: len(p))
    config = ba.BackfillConfig(replace_patterns=True)

    persisted = ba.write_patterns_authoritative(
        ["evt-1"],
        [("evt-1", "SCANNER", "rule", "text", "low")],
        config,
        has_severity=True,
        has_patterns=True,
    )

    assert persisted is True
    assert steps == ["delete", "rebuild"]


def test_a_batch_with_no_patterns_still_rebuilds(steps):
    """Nothing matched is a real result: the labels SHOULD clear. Only a failed
    write may not clear them."""
    config = ba.BackfillConfig(replace_patterns=True)

    persisted = ba.write_patterns_authoritative(
        ["evt-1"], [], config, has_severity=True, has_patterns=True
    )

    assert persisted is True
    assert "rebuild" in steps


# --- 3. A run that lost a batch makes no claim about the store -------------


def test_the_fingerprint_is_not_recorded_when_a_batch_was_lost(monkeypatch):
    """Stamping froze the 2026-11-19 hole in: the next tick saw no rule change
    and never retried the lost batches."""
    written: list[str] = []

    class _C:
        def close(self):
            pass

    monkeypatch.setattr("honeylens.database.legacy_get_db", lambda: _C())
    monkeypatch.setattr("honeylens.tools.auto_backfill._ensure_state_table", lambda c: None)
    monkeypatch.setattr("honeylens.tools.auto_backfill._store", lambda c, fp: written.append(fp))
    config = ba.BackfillConfig(replace_patterns=True)

    assert ba.record_fingerprint_if_authoritative(config, lost_batches=1) is False
    assert written == []


def test_auto_backfill_does_not_store_the_fingerprint_when_batches_were_lost(monkeypatch):
    from honeylens.tools import auto_backfill as ab

    written: list[str] = []

    class _C:
        def close(self):
            pass

    monkeypatch.setattr("honeylens.database.legacy_get_db", lambda: _C())
    monkeypatch.setattr(ab, "_ensure_state_table", lambda c: None)
    monkeypatch.setattr(ab, "_get_stored", lambda c: "old")
    monkeypatch.setattr(ab, "_store", lambda c, fp: written.append(fp))
    monkeypatch.setattr(ab, "rules_fingerprint", lambda: "new")
    monkeypatch.setattr(ba, "backfill", lambda config: 3)
    monkeypatch.setattr("sys.argv", ["honeylens-auto-backfill", "--apply"])

    rc = ab.main()

    assert written == []
    assert rc != 0


def test_auto_backfill_stores_the_fingerprint_when_nothing_was_lost(monkeypatch):
    from honeylens.tools import auto_backfill as ab

    written: list[str] = []

    class _C:
        def close(self):
            pass

    monkeypatch.setattr("honeylens.database.legacy_get_db", lambda: _C())
    monkeypatch.setattr(ab, "_ensure_state_table", lambda c: None)
    monkeypatch.setattr(ab, "_get_stored", lambda c: "old")
    monkeypatch.setattr(ab, "_store", lambda c, fp: written.append(fp))
    monkeypatch.setattr(ab, "rules_fingerprint", lambda: "new")
    monkeypatch.setattr(ba, "backfill", lambda config: 0)
    monkeypatch.setattr("sys.argv", ["honeylens-auto-backfill", "--apply"])

    rc = ab.main()

    assert written == ["new"]
    assert rc == 0
