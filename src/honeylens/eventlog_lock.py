"""Cross-process log coordination, shared by container writers and host ingest.

The sidecar is never removed: locking the data inode would fail when cleanup has to
replace a file. All appenders must flush before releasing this lock. A separate
consumer lock serializes complete ingest transactions without blocking writers.
"""

import fcntl
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def log_lock(path: str | Path, *, consumer: bool = False):
    suffix = ".ingest.lock" if consumer else ".lock"
    lock_path = Path(str(path) + suffix)
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def append_line(path: str | Path, line: str) -> None:
    """Append and flush a complete JSON line under the cleanup lock."""
    with log_lock(path), Path(path).open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
