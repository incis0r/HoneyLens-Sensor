"""The ingest offset, and why a silent failure to save it is not a small thing.

PAN-OS, FortiGate and Suricata all kept their byte offset in `/var/run`. That directory is
root-owned; the ingests run from cron as `sensor`; the write was impossible; and
`save_position` logged the failure at DEBUG. Nothing ever said so.

The visible symptom appeared months later and in a different subsystem. Each run re-read
the whole log — 128 MB on DEV, 162 MB on the edge host, once a minute — and re-reading re-inserts,
so the ingest fought the retention job: the nightly archive deleted 9,665 events older than
30 days and the next minute put them back. The same rows were archived every night for
months and the live table never shrank. Deleting them by hand lasted two minutes.

So these tests pin three things: the offset round-trips, a failure to save is loud and
returns False, and none of the three ingests reads or writes a path directly any more.
"""

from __future__ import annotations

import importlib
import logging
import os

import pytest


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("INGEST_STATE_DIR", str(tmp_path))
    import honeylens.ingest.state as st

    return importlib.reload(st)


def test_the_offset_round_trips(state):
    assert state.save_position("probe", 4096) is True
    assert state.read_position("probe") == 4096


def test_an_unknown_ingest_starts_at_zero(state):
    """Zero means "read from the beginning", which is right for a first run."""
    assert state.read_position("never-seen") == 0


def test_a_corrupt_offset_is_treated_as_absent(state):
    open(state.position_path("probe"), "w").write("not a number")
    assert state.read_position("probe") == 0


def test_the_write_is_atomic(state):
    """A crash mid-write must not leave a truncated offset, which would silently rewind
    the ingest and re-insert everything after that point."""
    state.save_position("probe", 999)
    state.save_position("probe", 123456789)
    assert state.read_position("probe") == 123456789
    leftovers = [
        p for p in os.listdir(os.path.dirname(state.position_path("probe"))) if p.endswith(".tmp")
    ]
    assert leftovers == [], leftovers


def test_failing_to_save_is_a_warning_not_a_debug_line(tmp_path, monkeypatch, caplog):
    """The whole defect was a debug-level message nobody reads. If this ever regresses to
    debug, the next occurrence is invisible again for months."""
    monkeypatch.setenv("INGEST_STATE_DIR", "/proc/nonexistent")
    import honeylens.ingest.state as st

    st = importlib.reload(st)
    with caplog.at_level(logging.WARNING, logger=st.logger.name):
        assert st.save_position("probe", 1) is False
    assert caplog.records, "a failed offset save produced no WARNING"
    msg = caplog.records[0].getMessage()
    assert "retention" in msg.lower(), (
        "the warning must say what it costs, not just that a file could not be written"
    )


def test_the_warning_is_not_repeated_per_call(tmp_path, monkeypatch, caplog):
    """A per-minute cron job must not fill the log with the same line."""
    monkeypatch.setenv("INGEST_STATE_DIR", "/proc/nonexistent")
    import honeylens.ingest.state as st

    st = importlib.reload(st)
    with caplog.at_level(logging.WARNING, logger=st.logger.name):
        for _ in range(5):
            st.save_position("probe", 1)
    assert len(caplog.records) == 1, [r.getMessage() for r in caplog.records]


def test_a_legacy_offset_is_still_honoured(tmp_path, monkeypatch):
    """An install whose ingest once ran as root may have a usable offset in /var/run.
    Reading it avoids one needless full re-read on upgrade; it is never written back."""
    import honeylens.ingest.state as st

    monkeypatch.setenv("INGEST_STATE_DIR", str(tmp_path))
    st = importlib.reload(st)
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    monkeypatch.setattr(st, "_LEGACY_DIR", str(legacy))
    (legacy / "ingest_probe.pos").write_text("777")
    assert st.read_position("probe") == 777
    st.save_position("probe", 888)
    assert st.read_position("probe") == 888  # new location wins once written
    assert (legacy / "ingest_probe.pos").read_text() == "777"


@pytest.mark.parametrize(
    "module",
    ["honeylens.ingest.paloalto", "honeylens.ingest.fortigate", "honeylens.ingest.suricata"],
)
def test_no_ingest_touches_a_position_path_itself(module):
    """All three went through the same unwritable directory. Reading the source is the
    only way to be sure a fourth copy of the bug has not been added."""
    import importlib.util

    spec = importlib.util.find_spec(module)
    src = open(spec.origin, encoding="utf-8").read()
    assert "/var/run/ingest" not in src, "still points at the root-owned directory"
    assert "open(POSITION_FILE" not in src and "open(pos_file" not in src, (
        "reads the offset file directly instead of going through ingest.state"
    )


def test_a_rotated_log_rewinds_the_offset(state, tmp_path, caplog):
    """The regression this fix exists for.

    While the offset was never saved, every run started at 0 and rotation was harmless.
    Persisting it introduced the opposite failure: one sensor's Suricata offset stood at
    290 MB against a 66 MB eve.json after a rotation, so seek() landed past the end and
    the ingest read nothing — silently, for as long as nobody looked.
    """
    log = tmp_path / "eve.json"
    log.write_text("x" * 100)
    state.save_position("probe", 5000)
    assert state.read_position("probe", str(log)) == 0
    assert state.read_position("probe") == 5000, (
        "without the log path the stored value must still be returned unchanged"
    )


def test_an_offset_inside_the_file_is_kept(state, tmp_path):
    log = tmp_path / "eve.json"
    log.write_text("x" * 5000)
    state.save_position("probe", 4096)
    assert state.read_position("probe", str(log)) == 4096


def test_an_offset_exactly_at_eof_is_kept(state, tmp_path):
    """The normal steady state: last run consumed the file to its end."""
    log = tmp_path / "eve.json"
    log.write_text("x" * 4096)
    state.save_position("probe", 4096)
    assert state.read_position("probe", str(log)) == 4096


def test_a_missing_log_does_not_rewind(state, tmp_path):
    """A log that is absent right now is not evidence the offset is wrong."""
    state.save_position("probe", 4096)
    assert state.read_position("probe", str(tmp_path / "gone.json")) == 4096


@pytest.mark.parametrize(
    "module",
    ["honeylens.ingest.paloalto", "honeylens.ingest.fortigate", "honeylens.ingest.suricata"],
)
def test_every_ingest_passes_its_log_path(module):
    """A position read without the log path cannot detect rotation, so the guard would be
    dead code for that ingest. Checked in the source because the failure is silent."""
    import importlib.util

    spec = importlib.util.find_spec(module)
    src = open(spec.origin, encoding="utf-8").read()
    for call in ("get_position()", "get_last_position()"):
        assert call not in src, f"{module} reads its offset without the log path"
