"""Post-ingest log cleanup — allowlist + truncate semantics.

Regression cover for the bug where every honeypotng file was rejected as
"path traversal" (allowlist built from an undefined HONEYPOTNG_LOG_DIR that
collapsed to the CWD), so logs were never truncated and were re-parsed on
every 30s pass.
"""

import os

import honeylens.ingest.honeypot as ih


def test_allowed_dirs_cover_configured_sources(monkeypatch):
    monkeypatch.setattr(
        ih, "HONEYPOT_LOG_GLOBS", ["/opt/logs/honeypotng/*.json", "/var/log/honeypot_k8s.json"]
    )
    dirs = ih._allowed_cleanup_dirs()
    assert os.path.realpath("/opt/logs/honeypotng") in dirs
    assert os.path.realpath("/var/log") in dirs


def test_honeypotng_file_is_not_refused(monkeypatch):
    """The exact case that regressed: a configured honeypotng log must pass."""
    monkeypatch.setattr(ih, "HONEYPOT_LOG_GLOBS", ["/opt/logs/honeypotng/*.json"])
    allowed = ih._allowed_cleanup_dirs()
    assert any(ih._is_within("/opt/logs/honeypotng/http_8080.json", d) for d in allowed)


def test_is_within_respects_path_boundaries():
    assert ih._is_within("/var/log/honeypot_k8s.json", "/var/log")
    assert ih._is_within("/var/log", "/var/log")
    assert not ih._is_within("/var/logsneaky/evil.json", "/var/log")
    assert not ih._is_within("/etc/passwd", "/var/log")


def test_patterns_state_file_is_excluded():
    """known_patterns.json is honeypotng's auto-detect dedup memory, not an event
    log — it sits in the log dir and matches the glob, so it must be filtered out
    or ingest would parse it as events and then truncate the honeypot's state."""
    assert "known_patterns.json" in ih.NON_EVENT_FILES


def test_drop_prefix_truncates_when_nothing_appended(tmp_path):
    f = tmp_path / "hp.json"
    f.write_text('{"a": 1}\n{"b": 2}\n')
    ih._drop_consumed_prefix(str(f), f.stat().st_size)
    assert f.read_text() == ""


def test_drop_prefix_keeps_records_appended_while_parsing(tmp_path):
    """Events written during a (slow) parse must not be lost by cleanup."""
    f = tmp_path / "hp.json"
    parsed = '{"a": 1}\n'
    f.write_text(parsed)
    consumed = len(parsed)
    with open(f, "a") as fh:  # honeypot keeps appending mid-parse
        fh.write('{"late": true}\n')
    ih._drop_consumed_prefix(str(f), consumed)
    assert f.read_text() == '{"late": true}\n'


def test_drop_prefix_noop_on_zero(tmp_path):
    f = tmp_path / "hp.json"
    f.write_text('{"a": 1}\n')
    ih._drop_consumed_prefix(str(f), 0)
    assert f.read_text() == '{"a": 1}\n'


def test_cleanup_keeps_the_file_in_place(tmp_path):
    """Truncate, never unlink — honeypots hold these logs open for their lifetime."""
    f = tmp_path / "hp.json"
    f.write_text('{"a": 1}\n')
    fh = open(f, "a")  # simulate the honeypot's long-lived handle
    try:
        ih._drop_consumed_prefix(str(f), f.stat().st_size)
        assert f.exists()
        fh.write('{"after": 1}\n')
        fh.flush()
        assert f.read_text() == '{"after": 1}\n'
    finally:
        fh.close()


def test_cleanup_retains_unwritable_file(tmp_path, monkeypatch):
    """Never replace a file whose writer may still hold the original inode."""
    from pathlib import Path

    import pytest

    from honeylens.ingest import logcleanup

    f = tmp_path / "http_80.json"
    original = b'{"a": 1}\n{"late": true}\n'
    f.write_bytes(original)
    real_open = Path.open

    def deny_write(path, mode="r", *args, **kwargs):
        if path == f and "+" in mode:
            raise PermissionError("not writable")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_write)
    with pytest.raises(PermissionError):
        logcleanup.drop_consumed_prefix(f, len(b'{"a": 1}\n'))
    assert f.read_bytes() == original


def test_explicit_payload_field_is_honoured():
    """A honeypot that summarises its own request in `payload` must not get NULL in
    the payload column — the field named after the column was the one omitted from
    the extraction chain (found porting the WAGO honeypot, Idea 54)."""
    import inspect

    src = inspect.getsource(ih._normalise)  # the legacy-line payload chain lives here now
    window = src.split("payload = sanitize_payload(", 1)[1][:500]
    assert 'data.get("payload")' in window
    # and it must outrank the reassembled fallbacks
    assert window.index('data.get("payload")') < window.index('data.get("path")')
