"""Schema capability probes shared by the ingests.

The fleet is not on one schema. `prod`'s `sensor_events` is older than the rest — `attack_types`
is still `text` there — and migrations are applied per host, by hand, after the code ships. An
`INSERT` naming a column that does not exist fails the whole statement, and on this path a failed
statement means the event is gone: the log position has already moved, or the row is dropped and
the file keeps processing.

So every column added to the event insert is probed once per process and the statement falls back
to the previous shape when the column is absent. `paloalto._full_payload_supported` established
the pattern for the Idea 30 bytea columns; this is the same thing for `source_class`, in one place
because Phase C touches five modules instead of one.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("ingest.schema")

_SOURCE_CLASS_OK: bool | None = None


def source_class_supported(cur) -> bool:
    """Whether `sensor_events.source_class` exists (migration 0013), probed once per process.

    False on a host that has not run the migration yet. The caller then uses its pre-0013
    statement and the event is stored without provenance — which the backfill in Task C5 can
    still fill in afterwards, whereas a lost event cannot be recovered at all.
    """
    global _SOURCE_CLASS_OK
    if _SOURCE_CLASS_OK is None:
        try:
            cur.execute("""
                SELECT count(*) FROM information_schema.columns
                WHERE table_name = 'sensor_events'
                  AND column_name = 'source_class'
            """)
            _SOURCE_CLASS_OK = bool(cur.fetchone()[0])
            if not _SOURCE_CLASS_OK:
                logger.warning(
                    "sensor_events has no source_class column — provenance will not be "
                    "stored; run migration 0013 (events are still inserted)"
                )
        except Exception as exc:  # a probe must never cost an event
            logger.debug("source_class probe failed, assuming absent: %s", exc)
            _SOURCE_CLASS_OK = False
    return _SOURCE_CLASS_OK


def reset_capability_cache() -> None:
    """Forget the probe result. For tests, and for a service restarted after a migration."""
    global _SOURCE_CLASS_OK
    _SOURCE_CLASS_OK = None
