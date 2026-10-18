"""Dropping the part of a honeypot log an ingest has already consumed.

A honeypot writes events to a JSON-lines file and an ingest lifts them into Postgres.
Nothing else reads those files, so once a pass has committed, the bytes it read are dead
weight — and left alone they are worse than that. `/var/log/honeypot_fortigate.json` on
a sensor reached 9.4 MB holding events back to March, and when the ingest offset was reset
(first run after the offsets moved to /var/lib/honeylens) it replayed all six months:
12,812 rows that retention had already archived went straight back into the live table,
and the Loki exporter wedged on them because Loki rejects anything older than a week.

`ingest/honeypot.py` and `ingest/ebpf.py` already trimmed their inputs; `fortigate.py` and
`paloalto.py` did not, which is exactly why those two grew without bound. This module is
that logic in one place rather than a fourth copy — the same file has already been through
one round of copy-paste divergence.

Truncate, never unlink: a honeypot that holds the log open would keep writing into an
unlinked inode and every later event would vanish without a word.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from honeylens.eventlog_lock import log_lock

logger = logging.getLogger(__name__)


def is_within(resolved: str, directory: str) -> bool:
    """True if `resolved` is `directory` itself or lives underneath it.

    Compares on path boundaries — a bare startswith would let /var/logsneaky pass as
    /var/log.
    """
    directory = directory.rstrip(os.sep)
    return resolved == directory or resolved.startswith(directory + os.sep)


def refuse_outside(path: str | Path, allowed_dirs) -> bool:
    """True when `path` is safe to clean, False (with a log line) when it is not.

    Cleanup destroys data, so the path has to provably sit in a directory an operator
    configured. An earlier version of this check built its allowlist from an undefined
    variable that collapsed to the CWD, so every file was rejected as path traversal,
    nothing was ever truncated, and the logs were re-parsed on every pass — a failure that
    looked like nothing at all.
    """
    resolved = str(Path(path).resolve())
    if any(is_within(resolved, str(Path(d).resolve())) for d in allowed_dirs):
        return True
    logger.error(
        "Cleanup refused — %s resolves to %s, outside %s", path, resolved, sorted(allowed_dirs)
    )
    return False


def drop_consumed_prefix(path: str | Path, consumed: int) -> None:
    """Discard the first `consumed` bytes of `path`, keeping anything appended since.

    `consumed` must be the offset the ingest actually read up to, not the file size now:
    records the honeypot appended while we were parsing have to survive into the next
    pass. Re-reading a few overlapping lines is harmless — event_id is a content hash and
    the inserts are conflict-safe.
    """
    if consumed <= 0:
        return
    # Fail closed on permissions: replacing a vendor log can strand its writer's
    # long-lived descriptor on an unlinked inode. The caller retains the backlog.
    with log_lock(path):
        _truncate_in_place(path, consumed)


def _truncate_in_place(path: str | Path, consumed: int, chunk_size: int = 65536) -> None:
    p = Path(path)
    size = p.stat().st_size
    if size <= consumed:
        p.write_bytes(b"")  # nothing appended since the read — plain truncate
        return
    # Shift the unconsumed tail down to offset 0 in fixed-size chunks. Reading the whole
    # tail at once (fh.read()) spiked RAM — under a heavy scan the tail can be hundreds of
    # MB before the next ingest cycle — and could OOM the host. A 64 KB window is bounded.
    with p.open("r+b") as fh:
        read_pos = consumed
        write_pos = 0
        while read_pos < size:
            fh.seek(read_pos)
            chunk = fh.read(min(chunk_size, size - read_pos))
            if not chunk:
                break
            read_pos += len(chunk)
            fh.seek(write_pos)
            fh.write(chunk)
            write_pos += len(chunk)
        fh.truncate(write_pos)
