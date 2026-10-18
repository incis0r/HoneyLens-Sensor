#!/usr/bin/env python3
"""backfill_source_class.py — fill `sensor_events.source_class` for rows already stored.

Phase C, Task C5. Migration 0013 adds the column as nullable with no default, so every row
written before the ingest change says NULL — which reads as "a real actor". Measured over 30
days to 2026-11-04, 2,139,975 rows (12.8% of everything recorded) are ours, and they are the
root cause behind `ANOMALY` reading 99.7% own traffic, `SURICATA_ALERT` 97.9% and `SCANNER`
83.1%. This pass is what makes the column true about the past.

**The classification runs in SQL, and the networks come from `intelligence.source_class`.** A
Python loop over 16.7 million rows would take hours and hold a connection the whole time;
Postgres does `inet` containment natively. The risk in writing the predicate twice is that the
two drift apart, so the arrays are built from that module's own lists and a test asserts it —
there is one source of truth for what counts as ours, and this tool reads it.

Batched by `event_id` ranges with a commit per batch, so an interrupted run is simply a run that
got partway: every batch it finished is correct and re-running is idempotent (it only touches
rows whose class differs from what it would write).

    honeylens-backfill-source-class --dry-run          # report, writes nothing
    honeylens-backfill-source-class --apply            # write
    honeylens-backfill-source-class --apply --batch 50000

⚠️ Reports and writes nothing until `SOURCE_CLASS_OWN_INFRA` / `SOURCE_CLASS_VALIDATION` are set
in the deployment's env file. With both empty only `internal` is claimed, which is correct but is
not the measurement the review asked for — the tool says so rather than reporting a clean zero.
"""

from __future__ import annotations

import argparse
import logging
import sys

from honeylens.database import legacy_get_db
from honeylens.intelligence import source_class as sc

logger = logging.getLogger("backfill_source_class")

# The CASE must mirror `classify_source`'s precedence exactly: own_infra, then validation, then
# internal, then NULL for an actor. Built from the module's compiled networks so the two cannot
# drift; `tests/test_backfill_source_class.py` asserts that it is these lists and not a copy.
_CASE_SQL = """
    CASE
        WHEN src_ip <<= ANY(%(own)s::inet[])        THEN %(own_class)s
        WHEN src_ip <<= ANY(%(validation)s::inet[]) THEN %(validation_class)s
        WHEN src_ip <<= ANY(%(internal)s::inet[])   THEN %(internal_class)s
        ELSE NULL
    END
"""


def _params() -> dict[str, object]:
    """The network arrays and class names the SQL binds, straight from `source_class`."""
    return {
        "own": [str(n) for n in sc._OWN_INFRA],
        "validation": [str(n) for n in sc._VALIDATION],
        "internal": [str(n) for n in sc._INTERNAL_NETS],
        "own_class": sc.OWN_INFRA,
        "validation_class": sc.VALIDATION,
        "internal_class": sc.INTERNAL,
    }


def report(conn) -> dict[str, int]:
    """Row counts per class this tool would write. Read-only.

    Grouped by class and never by address: one of the validation sources is the operator's own
    connection, and that address does not belong in a report.
    """
    cur = conn.cursor()
    cur.execute(
        f"SELECT {_CASE_SQL} AS cls, count(*) FROM sensor_events GROUP BY 1",  # nosec B608 — a fixed CASE, values bound as parameters
        _params(),
    )
    counts = {(row[0] or "external"): row[1] for row in cur.fetchall()}
    cur.execute("SELECT count(*) FROM sensor_events WHERE source_class IS NOT NULL")
    counts["already_written"] = cur.fetchone()[0]
    return counts


def pending(conn) -> int:
    """Rows whose stored class differs from what this tool would write."""
    cur = conn.cursor()
    cur.execute(
        f"SELECT count(*) FROM sensor_events WHERE source_class IS DISTINCT FROM ({_CASE_SQL})",  # nosec B608 — a fixed CASE, values bound as parameters
        _params(),
    )
    return cur.fetchone()[0]


def apply_batches(conn, batch: int = 50_000, limit_batches: int | None = None) -> int:
    """Write the class in batches, committing each one. Returns rows written.

    Only rows whose stored value differs are touched, so a second run is a no-op and an
    interrupted run can simply be repeated.
    """
    written = 0
    batches = 0
    params = {**_params(), "batch": batch}
    while True:
        cur = conn.cursor()
        cur.execute(
            f"""
            WITH todo AS (
                SELECT event_id
                  FROM sensor_events
                 WHERE source_class IS DISTINCT FROM ({_CASE_SQL})
                 LIMIT %(batch)s
            )
            UPDATE sensor_events e
               SET source_class = ({_CASE_SQL})
              FROM todo
             WHERE e.event_id = todo.event_id
            """,  # nosec B608 — a fixed CASE, values bound as parameters
            params,
        )
        rows = cur.rowcount or 0
        conn.commit()
        written += rows
        batches += 1
        logger.info("batch %d: %d rows (%d total)", batches, rows, written)
        if rows == 0 or (limit_batches is not None and batches >= limit_batches):
            break
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write (default is report only)")
    parser.add_argument("--batch", type=int, default=50_000, help="rows per batch")
    parser.add_argument("--max-batches", type=int, default=None, help="stop after N batches")
    parser.add_argument("--dry-run", action="store_true", help="report only (the default)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if not sc._OWN_INFRA and not sc._VALIDATION:
        logger.warning(
            "SOURCE_CLASS_OWN_INFRA and SOURCE_CLASS_VALIDATION are both empty — only "
            "RFC1918/loopback/link-local will be claimed. Set them in the env file first."
        )

    conn = legacy_get_db()
    try:
        counts = report(conn)
        total = sum(v for k, v in counts.items() if k != "already_written")
        logger.info("rows: %d", total)
        for cls in (sc.OWN_INFRA, sc.VALIDATION, sc.INTERNAL, "external"):
            logger.info("  %-11s %d", cls, counts.get(cls, 0))
        logger.info("  already written: %d", counts["already_written"])
        logger.info("rows needing a write: %d", pending(conn))

        if args.apply and not args.dry_run:
            written = apply_batches(conn, batch=args.batch, limit_batches=args.max_batches)
            logger.info("written: %d", written)
            logger.info("rows still needing a write: %d", pending(conn))
        else:
            logger.info("dry run — nothing written")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
