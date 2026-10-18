"""events.json must never grow without bound — and a failed truncate must be loud.

sensor.py needs CAP_NET_RAW, so it runs as root and creates events.json as
root:root 0644. The eBPF ingest that drains and truncates that file runs as
`sensor`. The truncate therefore fails with EACCES, and because the handler
logged at DEBUG the failure was invisible: the file just kept growing.

Found 2026-08-26 on two hosts in the same hour — 7 GB on a sensor whose root
filesystem had reached 100%, and 72 GB on a GPU host where the ingest had been
disabled entirely. Both had been silently accumulating for months.

These tests pin the two properties that matter: the truncate happens when it
should, and when it cannot happen the operator is told at WARNING.
"""

from __future__ import annotations

import logging
import os
import sys
import types

import pytest

# scapy is a runtime-only dependency of the ingest module and is not installed in
# the test environment; the truncate logic does not touch it.
if "scapy.all" not in sys.modules:
    for _name in ("scapy", "scapy.all"):
        sys.modules.setdefault(_name, types.ModuleType(_name))
    for _sym in ("IP", "TCP", "UDP", "rdpcap"):
        setattr(sys.modules["scapy.all"], _sym, object())

import honeylens.ingest.ebpf as eb


@pytest.fixture
def events_file(tmp_path, monkeypatch):
    """A stand-in events.json wired into the module's globals."""
    path = tmp_path / "events.json"
    monkeypatch.setattr(eb, "EVENTS_JSON", str(path))
    monkeypatch.setattr(eb, "POSITION_FILE", str(tmp_path / ".ingest_ebpf.pos"))
    return path


def _fill(path, size):
    path.write_bytes(b"x" * size)


def test_oversized_file_is_truncated(events_file, monkeypatch):
    monkeypatch.setattr(eb, "MAX_EVENTS_FILE_SIZE", 1024)
    _fill(events_file, 4096)
    eb._truncate_events_json()
    assert events_file.stat().st_size == 0


def test_position_is_reset_with_the_truncate(events_file, monkeypatch):
    """Truncating without resetting the offset would make the ingest skip every
    event until the file grew back past the stale position."""
    monkeypatch.setattr(eb, "MAX_EVENTS_FILE_SIZE", 1024)
    _fill(events_file, 4096)
    eb._save_position(4096)
    eb._truncate_events_json()
    assert eb._get_position() == 0


def test_a_small_file_is_left_alone(events_file, monkeypatch):
    monkeypatch.setattr(eb, "MAX_EVENTS_FILE_SIZE", 1024)
    _fill(events_file, 512)
    eb._truncate_events_json()
    assert events_file.stat().st_size == 512


def test_a_missing_file_is_not_an_error(events_file):
    eb._truncate_events_json()  # must not raise


def test_failure_to_truncate_is_logged_at_warning(events_file, monkeypatch, caplog):
    """The actual defect. A truncate that cannot happen must not be swallowed:
    the file grows until the filesystem fills, so the log has to say so."""
    monkeypatch.setattr(eb, "MAX_EVENTS_FILE_SIZE", 1024)
    _fill(events_file, 2 * 1024 * 1024)

    real_open = eb.open if hasattr(eb, "open") else open

    def deny_write(path, mode="r", *a, **kw):
        if str(path) == str(events_file) and "w" in mode:
            raise PermissionError(13, "Permission denied")
        return real_open(path, mode, *a, **kw)

    monkeypatch.setattr("builtins.open", deny_write)

    with caplog.at_level(logging.WARNING, logger=eb.logger.name):
        eb._truncate_events_json()

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings, "a failed truncate was logged below WARNING — this is the bug"
    msg = warnings[0].getMessage()
    assert "events.json" in msg
    assert "grow" in msg.lower(), "the message must state the consequence"
    assert "2 MB" in msg, "the message must carry the current size"


def test_the_failure_message_names_the_owner_and_the_running_user(events_file, monkeypatch, caplog):
    """Ownership is the whole cause, so both uids belong in the message — without
    them the operator cannot tell a permission problem from a full disk."""
    monkeypatch.setattr(eb, "MAX_EVENTS_FILE_SIZE", 1024)
    _fill(events_file, 4096)
    monkeypatch.setattr(
        "builtins.open",
        lambda *a, **k: (_ for _ in ()).throw(PermissionError(13, "Permission denied")),
    )

    with caplog.at_level(logging.WARNING, logger=eb.logger.name):
        eb._truncate_events_json()

    msg = caplog.records[0].getMessage()
    assert "owned by uid" in msg
    assert "running as uid" in msg


def test_file_uid_helper_is_defensive():
    assert eb._file_uid(__file__) == str(os.stat(__file__).st_uid)
    assert eb._file_uid("/nonexistent/path/events.json") == "?"
