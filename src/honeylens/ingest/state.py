"""Where an ingest remembers how far it has read.

Every log-tailing ingest keeps a byte offset so the next run starts where the last one
stopped. Three of them — PAN-OS, FortiGate, Suricata — kept that offset in `/var/run`,
which is root-owned, while the ingests run from cron as the `sensor` user. Writing was
impossible, and the failure went to `logger.debug`, so nothing said so.

The consequence was invisible for months and expensive in two ways. Every run re-read the
entire log: 59 to 162 MB depending on the sensor, once a minute. And because
re-reading re-inserts, it fought the retention job — the nightly archive deleted 9,665
events older than 30 days and the next minute's ingest put them straight back, so the same
rows were "archived" every night for months and the live table never shrank. Deleting them
by hand lasted two minutes.

So the offset needs a home the service user can actually write, and a failure to save it
has to be loud. It is the difference between "this run was cheap" and "this run undid the
retention job", which is not a debug-level distinction.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Overridable per install; the default is created by install.sh with sensor ownership.
STATE_DIR = Path(os.environ.get("INGEST_STATE_DIR", "/var/lib/honeylens"))

# Where these files used to live. Read-only fallback: if an install somehow has a usable
# offset there (an ingest that once ran as root), honour it rather than re-reading the
# whole log once on upgrade. Never written to again.
_LEGACY_DIR = Path("/var/run")

_warned: set[str] = set()


def position_path(name: str) -> Path:
    """Full path of an ingest offset file, e.g. position_path("paloalto_web")."""
    return Path(STATE_DIR) / f"ingest_{name}.pos"


def read_position(name: str, log_path: str | Path | None = None) -> int:
    """Byte offset to resume from, or 0 when there is nothing usable.

    Pass `log_path` and a stored offset larger than the file is treated as 0. That is the
    rotated-or-truncated case, and it has teeth: while the offset was never saved at all,
    every run started from 0 and rotation was harmless. Persisting it introduced the
    opposite failure — one sensor's Suricata offset stood at 290 MB against a 66 MB
    eve.json after a rotation, so `seek()` landed past the end and the ingest read nothing,
    silently, for as long as nobody looked.

    Re-reading a rotated log costs one pass and inserts nothing new (events dedupe on
    event_id). Not re-reading costs every event until someone notices.
    """
    stored = None
    for path in (position_path(name), Path(_LEGACY_DIR) / f"ingest_{name}.pos"):
        try:
            stored = int(path.read_text().strip() or 0)
            break
        except (OSError, ValueError):
            continue
    if stored is None:
        return 0
    if log_path:
        try:
            size = Path(log_path).stat().st_size
        except OSError:
            return stored
        if stored > size:
            logger.info(
                "%s: stored offset %d exceeds %s (%d bytes) — log rotated, "
                "restarting from the beginning",
                name,
                stored,
                log_path,
                size,
            )
            return 0
    return stored


def save_position(name: str, pos: int) -> bool:
    """Persist the offset. Returns False and warns — once per process — on failure.

    Warning rather than debug on purpose: a silent failure here does not degrade the
    ingest, it reverses the retention job, and the only symptom is a disk that fills
    months later.
    """
    path = position_path(name)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".pos.tmp")
        tmp.write_text(str(pos))
        tmp.replace(path)  # atomic: a crash cannot leave a half-written offset behind
        return True
    except OSError as e:
        if str(path) not in _warned:
            _warned.add(str(path))
            logger.warning(
                "cannot save ingest position to %s (%s) — this run will re-read the whole "
                "log next time, and re-inserting old events undoes the retention job. "
                "Create the directory writable by the service user, or set INGEST_STATE_DIR.",
                path,
                e,
            )
        return False
