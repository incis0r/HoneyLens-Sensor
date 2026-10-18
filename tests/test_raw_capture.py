"""Keeping the bytes when the payload rides in the body.

A decoy that reconstructs a request into fields proves what it *understood*, not
what arrived. For an exploit whose whole substance is in the body - the
CVE-2024-4577 loader that reached sensor-a on 2026-08-31 carried an operator's SSH
private key inside base64 inside a PHP tag - that gap decides whether a capture is
evidence or a summary of evidence.

We found it the expensive way: the event store held 184 events of that campaign
and `full_payload` was NULL for every one, so the evidence package shipped with a
stated caveat that nothing could prove the bytes were unaltered.

These tests pin the three properties that make the fix worth having: the hash must
be checkable against what is actually stored, a failed raw write must not cost us the
event, and raw is kept only where it adds something.

Port 1.0: the honeypot no longer writes the column itself. It puts the bytes in the
event line (``raw_hex``) and ``ingest/honeypot.py`` stores them — so the property
"hash over exactly the stored bytes" is now the ingest's to keep, and that is what is
exercised here: honeypot -> line -> ingest -> UPDATE.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from honeylens.honeypots import _base, sink
from honeylens.ingest import honeypot as ih


class _Cur:
    """Records the SQL and parameters the ingest would send."""

    def __init__(self, fail_raw: bool = False):
        self.sql: list[str] = []
        self.params: list = []
        self.rowcount = 0
        self._fail_raw = fail_raw

    def execute(self, sql, params=None):
        self.sql.append(" ".join(sql.split()))
        self.params.append(params)
        if self._fail_raw and "full_payload" in sql:
            raise RuntimeError("column full_payload does not exist")

    def fetchone(self):
        return None

    def fetchall(self):
        return []


@pytest.fixture(autouse=True)
def _sink_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(sink, "HONEYPOTNG_LOG_DIR", tmp_path)
    monkeypatch.setattr(ih, "classify_event_row", lambda **k: [])


def _run(tmp_path, raw, fail_raw: bool = False):
    """log_event with `raw`, then the ingest over the line it wrote."""
    cur = _Cur(fail_raw=fail_raw)
    _base.log_event("http", ("198.51.100.7", 1234), {"dst_port": 80}, raw=raw)
    for f in sorted(Path(tmp_path).glob("*.json")):
        ih.process_file(cur, str(f))
    ins = [
        (s, p)
        for s, p in zip(cur.sql, cur.params, strict=False)
        if "INSERT INTO sensor_events" in s
    ]
    assert len(ins) == 1
    upd = [(s, p) for s, p in zip(cur.sql, cur.params, strict=False) if "full_payload" in s]
    return ins[0], (upd[0] if upd else None), cur


# ------------------------------------------------------------------ the hash


def test_the_hash_verifies_against_the_stored_bytes(tmp_path):
    """A hash of the original would be uncheckable once a capture is truncated.
    Whoever receives this must be able to recompute it against the column."""
    raw = b"POST / HTTP/1.1\r\nHost: x\r\n\r\n<?php shell_exec('id'); ?>"
    _ins, upd, _cur = _run(tmp_path, raw)
    assert upd is not None
    stored, digest, _event_id = upd[1]
    assert hashlib.sha256(stored).hexdigest() == digest


def test_truncation_keeps_the_hash_checkable(tmp_path, monkeypatch):
    monkeypatch.setattr(_base, "MAX_RAW_CAPTURE", 32)
    monkeypatch.setattr(sink, "MAX_RAW_CAPTURE", 32)
    _ins, upd, _cur = _run(tmp_path, b"A" * 500)
    assert upd is not None
    stored, digest, _ = upd[1]
    assert len(stored) == 32
    assert hashlib.sha256(stored).hexdigest() == digest


def test_the_bytes_are_stored_verbatim(tmp_path):
    """Credentials included - the body is the evidence."""
    raw = b"POST /x HTTP/1.1\r\n\r\nuser=admin&pass=hunter2\x00\xff"
    _ins, upd, _cur = _run(tmp_path, raw)
    assert upd is not None
    assert upd[1][0] == raw


def test_the_raw_bytes_belong_to_the_event_row(tmp_path):
    """The UPDATE must address the row the INSERT just made, not any other."""
    (_ins_sql, ins_params), upd, _cur = _run(tmp_path, b"POST /\r\n\r\nx=1")
    assert upd is not None
    assert upd[1][2] == ins_params[0]


# --------------------------------------------------------- when to keep raw


def test_no_raw_means_no_raw_write(tmp_path):
    _ins, upd, _cur = _run(tmp_path, None)
    assert upd is None


def test_an_empty_body_is_not_stored(tmp_path):
    _ins, upd, _cur = _run(tmp_path, b"")
    assert upd is None


# The HTTP decoy's own raw/no-raw decision is driven end to end in tests/test_hp_http_raw.py.


# ------------------------------------------------- a failed raw write must not break


def test_a_failing_raw_write_does_not_cost_us_the_event(tmp_path):
    """The raw bytes ride in a separate statement under a savepoint: if that one
    fails, the event we most wanted to keep is still in the table."""
    (ins_sql, ins_params), _upd, cur = _run(tmp_path, b"POST / HTTP/1.1\r\n\r\nx=1", fail_raw=True)
    assert "INSERT INTO sensor_events" in ins_sql
    assert "198.51.100.7" in ins_params
    assert any("ROLLBACK TO SAVEPOINT sp_raw" in s for s in cur.sql)
