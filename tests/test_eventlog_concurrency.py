"""Writers and cleanup must coordinate across processes without losing a line."""

import json
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from honeylens.eventlog_lock import append_line, log_lock
from honeylens.ingest import honeypot, logcleanup


def _append(path, started, finished):
    started.set()
    append_line(path, '{"new":true}')
    finished.set()


def test_appender_waits_for_cleanup_in_another_process(tmp_path):
    path = tmp_path / "events.json"
    path.write_text('{"old":true}\n')
    ctx = multiprocessing.get_context("spawn")
    started, finished = ctx.Event(), ctx.Event()
    process = ctx.Process(target=_append, args=(str(path), started, finished))
    with log_lock(path):
        process.start()
        assert started.wait(10)
        assert not finished.wait(0.1)
        logcleanup._truncate_in_place(path, path.stat().st_size)
    process.join(10)
    assert process.exitcode == 0
    assert path.read_text() == '{"new":true}\n'


def test_snapshot_excludes_later_records_without_losing_them(tmp_path, monkeypatch):
    path = tmp_path / "events.json"
    append_line(path, '{"id":1}')
    with log_lock(path):
        boundary = path.stat().st_size
    append_line(path, '{"id":2}')
    seen = []
    monkeypatch.setattr(honeypot, "process_record", lambda cur, data: seen.append(data) or True)
    assert honeypot.process_file(None, str(path), limit_bytes=boundary) == 1
    logcleanup.drop_consumed_prefix(path, boundary)
    assert seen == [{"id": 1}]
    assert json.loads(path.read_text()) == {"id": 2}


def test_incomplete_line_is_not_acknowledged(tmp_path, monkeypatch):
    path = tmp_path / "events.json"
    path.write_bytes(b'{"id":')
    monkeypatch.setattr(honeypot, "process_record", lambda cur, data: True)
    with pytest.raises(ValueError, match="Incomplete event"):
        honeypot.process_file(None, str(path), limit_bytes=path.stat().st_size)
    assert path.read_bytes() == b'{"id":'


def test_continuous_writer_and_repeated_ingest_preserve_every_event(tmp_path, monkeypatch):
    path = tmp_path / "events.json"
    path.touch()
    done = Event()
    seen = []
    monkeypatch.setattr(
        honeypot, "process_record", lambda cur, data: seen.append(data["id"]) or True
    )

    def writer():
        try:
            for number in range(150):
                append_line(path, json.dumps({"id": number, "body": "x" * 8192}))
        finally:
            done.set()

    with ThreadPoolExecutor() as pool:
        future = pool.submit(writer)
        while not done.is_set() or path.stat().st_size:
            with log_lock(path):
                boundary = path.stat().st_size
            honeypot.process_file(None, str(path), limit_bytes=boundary)
            logcleanup.drop_consumed_prefix(path, boundary)
        future.result()
    assert seen == list(range(150))
    assert Path(path).read_bytes() == b""


def test_failed_database_insert_does_not_acknowledge_file(tmp_path, monkeypatch):
    path = tmp_path / "events.json"
    append_line(path, '{"id":1}')
    monkeypatch.setattr(honeypot, "process_record", lambda cur, data: False)
    with pytest.raises(ValueError, match="not persisted"):
        honeypot.process_file(None, str(path))
    assert path.read_text() == '{"id":1}\n'
