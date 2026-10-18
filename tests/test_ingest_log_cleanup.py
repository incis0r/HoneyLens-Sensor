"""Trimming a honeypot log the ingest has already read — and the order that makes it safe.

`ingest/honeypot.py` and `ingest/ebpf.py` trimmed their input logs; `fortigate.py` and
`paloalto.py` did not. So those two grew without bound: 9.4 MB of FortiGate events back to
March on one sensor, and 107 MB / 470,007 events in honeypot_paloalto_ssh.json on another.

Size was the smaller problem. When the FortiGate offset was lost — the first run after the
offsets moved to /var/lib/honeylens — the ingest replayed all six months, putting 12,812
rows that retention had already archived back into the live table and wedging the Loki
exporter, which rejects samples older than a week and whose cursor only advances after a
successful push.

Trimming is only safe once the database holds everything the file did. It did not:
`raw_body_b64` (the verbatim POST body, PAN-OS) and `headers` (both) lived at the top level
of the JSON event, while the ingests copied only `data` and a handful of named fields. The
2026-05 PAN-OS review recorded that gap — "on disk but not in the DB" — and it stayed open
for four months. These tests pin the dependency: the evidence moves first, the file is
trimmed second.
"""

from __future__ import annotations

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


# --- the trimming mechanics ------------------------------------------------------


@pytest.fixture
def cleanup():
    from honeylens.ingest import logcleanup

    return logcleanup


def test_only_the_consumed_prefix_goes(cleanup, tmp_path):
    """Events appended while the ingest was parsing must survive into the next pass."""
    log = tmp_path / "hp.json"
    log.write_bytes(b'{"a":1}\n{"b":2}\n')
    cleanup.drop_consumed_prefix(str(log), len(b'{"a":1}\n'))
    assert log.read_bytes() == b'{"b":2}\n'


def test_a_fully_consumed_file_is_emptied_not_removed(cleanup, tmp_path):
    """Unlinking would leave a honeypot holding the open descriptor writing into a
    detached inode, losing every later event silently."""
    log = tmp_path / "hp.json"
    log.write_bytes(b'{"a":1}\n')
    cleanup.drop_consumed_prefix(str(log), 8)
    assert log.exists() and log.read_bytes() == b""


def test_a_zero_offset_changes_nothing(cleanup, tmp_path):
    """A pass that read nothing must not be able to destroy the backlog."""
    log = tmp_path / "hp.json"
    log.write_bytes(b'{"a":1}\n')
    cleanup.drop_consumed_prefix(str(log), 0)
    assert log.read_bytes() == b'{"a":1}\n'


def test_a_path_outside_the_allowlist_is_refused(cleanup, tmp_path):
    outside = tmp_path / "elsewhere" / "hp.json"
    outside.parent.mkdir()
    outside.write_bytes(b"x")
    allowed = tmp_path / "logs"
    allowed.mkdir()
    assert cleanup.refuse_outside(str(outside), [str(allowed)]) is False
    assert outside.read_bytes() == b"x", "refusal must not have touched the file"


def test_a_sibling_directory_cannot_pass_as_a_prefix(cleanup):
    """A bare startswith would let /var/logsneaky through as /var/log."""
    assert cleanup.is_within("/var/log/hp.json", "/var/log") is True
    assert cleanup.is_within("/var/logsneaky/hp.json", "/var/log") is False
    assert cleanup.is_within("/var/log", "/var/log") is True


# --- the evidence has to move first ----------------------------------------------


def test_fortigate_keeps_the_headers_it_used_to_drop():
    """The only field of value outside `data` for this honeypot. Bodies and credentials
    (body_sample, body_len, username, password) are inside `data` and were never at risk —
    verified against 9.4 MB of live events before any of this was written."""
    src = _src("src/honeylens/ingest/fortigate.py")
    assert 'payload_parts["headers"] = headers' in src


def test_paloalto_stores_the_raw_post_body_in_the_database():
    """raw_body_b64 is the verbatim body the decoy received and the file was its only
    copy. It goes to full_payload (bytea), not to the 4 KB text column — base64 cut in
    half is not a partial body, it is a corrupt one."""
    src = _src("src/honeylens/ingest/paloalto.py")
    assert "base64.b64decode" in src
    assert "full_payload" in src and "full_payload_hash" in src


def test_paloalto_keeps_headers_and_the_true_body_length():
    src = _src("src/honeylens/ingest/paloalto.py")
    assert 'payload_parts["headers"] = headers' in src
    assert 'payload_parts["raw_body_len"]' in src


def test_a_missing_full_payload_column_does_not_lose_the_event():
    """An install predating the Idea 30 columns must fall back, not fail every insert."""
    src = _src("src/honeylens/ingest/paloalto.py")
    assert "_full_payload_supported" in src
    assert "information_schema.columns" in src


@pytest.mark.parametrize(
    "module", ["src/honeylens/ingest/fortigate.py", "src/honeylens/ingest/paloalto.py"]
)
def test_the_offset_is_reset_when_the_file_is_trimmed(module):
    """Offset and file have to move together. A stale offset seeks past the end of the
    trimmed file and the ingest reads nothing — silently, which is how the equivalent
    Suricata bug hid for as long as it did."""
    src = _src(module)
    m = re.search(r"drop_consumed_prefix\(.*?\n(.*?)\n\s*except", src, re.S)
    assert m, f"{module} no longer trims its log"
    assert re.search(r"save_position\((?:pos_file,\s*)?0\)", m.group(1)), (
        f"{module} trims the file without resetting the offset"
    )


@pytest.mark.parametrize(
    "module", ["src/honeylens/ingest/fortigate.py", "src/honeylens/ingest/paloalto.py"]
)
def test_reprocessing_everything_never_trims(module):
    """`--all` exists to re-read history. Trimming during it would delete the very thing
    the operator asked to reprocess."""
    src = _src(module)
    assert re.search(r"if not dry_run and not process_all and consumed > 0:", src), (
        f"{module} does not exempt --all / --dry-run from cleanup"
    )


@pytest.mark.parametrize(
    "module", ["src/honeylens/ingest/fortigate.py", "src/honeylens/ingest/paloalto.py"]
)
def test_the_trimming_logic_is_not_a_fourth_copy(module):
    """honeypot.py, ebpf.py and these two all need it; the tree has already been through
    one round of copy-paste divergence."""
    src = _src(module)
    assert "from honeylens.ingest import" in src and "logcleanup" in src
    assert "def _truncate_in_place" not in src, "re-implements the shared helper"


def test_honeypot_ingest_now_delegates_too():
    src = _src("src/honeylens/ingest/honeypot.py")
    assert "logcleanup.drop_consumed_prefix" in src
    assert "def _truncate_in_place" not in src
