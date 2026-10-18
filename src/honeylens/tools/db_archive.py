#!/usr/bin/env python3
"""
db_archive.py — Database Archival and Cleanup
==============================================
Moves events older than N days to monthly archive tables.
Optionally exports to compressed CSV files.

Usage:
    python db_archive.py                    # Archive events older than 30 days
    python db_archive.py --days 60          # Archive events older than 60 days
    python db_archive.py --export           # Also export to CSV.gz
    python db_archive.py --dry-run          # Show what would be archived
    python db_archive.py --no-cleanup       # Archive but don't delete from main table
    python db_archive.py --stats            # Show archive statistics
    python db_archive.py --vacuum           # Vacuum and analyze tables

Requires: psycopg2
"""

from __future__ import annotations

import argparse
import csv
import gzip
import logging
import os
from datetime import UTC, date, datetime, timedelta

from psycopg2 import sql

from honeylens.database import legacy_get_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("db_archive")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


from honeylens.config import DB_ARCHIVE_CLEANUP, DB_ARCHIVE_DAYS, DB_ARCHIVE_DIR

BATCH_SIZE = 10000
PROGRESS_INTERVAL = 50000


# ---------------------------------------------------------------------------
# Database Connection
# ---------------------------------------------------------------------------


def get_conn():
    """Get database connection."""
    return legacy_get_db()


# ---------------------------------------------------------------------------
# Archive Table Management
# ---------------------------------------------------------------------------


def get_archive_table_name(year: int, month: int) -> str:
    """Generate archive table name for a given year/month."""
    return f"archive_events_{year}_{month:02d}"


def ensure_archive_table(conn, year: int, month: int) -> str:
    """Create archive table if it doesn't exist."""
    table_name = get_archive_table_name(year, month)
    cur = conn.cursor()

    # Create table with same structure as sensor_events plus archived_at
    cur.execute(
        sql.SQL("""
        CREATE TABLE IF NOT EXISTS {} (
            event_id        VARCHAR(64) NOT NULL,
            timestamp       TIMESTAMPTZ NOT NULL,
            source          VARCHAR(32),
            protocol        VARCHAR(32),
            src_ip          INET,
            src_port        INTEGER,
            dst_ip          INET,
            dst_port        INTEGER,
            payload         TEXT,
            payload_hash    VARCHAR(64),
            scan_score      DOUBLE PRECISION,
            port_entropy    DOUBLE PRECISION,
            ja3             VARCHAR(64),
            metadata        JSONB,
            attack_types    TEXT,
            archived_at     TIMESTAMPTZ DEFAULT NOW()
        )
    """).format(sql.Identifier(table_name))
    )

    # Create indexes on archive table
    idx_ts = f"idx_{table_name}_ts"
    idx_src = f"idx_{table_name}_src"
    idx_event = f"idx_{table_name}_event"
    idx_attack = f"idx_{table_name}_attack"
    cur.execute(
        sql.SQL("""
        CREATE INDEX IF NOT EXISTS {} ON {}(timestamp DESC)
    """).format(sql.Identifier(idx_ts), sql.Identifier(table_name))
    )
    cur.execute(
        sql.SQL("""
        CREATE INDEX IF NOT EXISTS {} ON {}(src_ip)
    """).format(sql.Identifier(idx_src), sql.Identifier(table_name))
    )
    cur.execute(
        sql.SQL("""
        CREATE INDEX IF NOT EXISTS {} ON {}(event_id)
    """).format(sql.Identifier(idx_event), sql.Identifier(table_name))
    )
    cur.execute(
        sql.SQL("""
        CREATE INDEX IF NOT EXISTS {} ON {}(attack_types)
    """).format(sql.Identifier(idx_attack), sql.Identifier(table_name))
    )

    conn.commit()
    logger.info("Ensured archive table: %s", table_name)
    return table_name


def get_archive_tables(conn) -> list[str]:
    """Get list of existing archive tables."""
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name LIKE 'archive_events_%'
        ORDER BY table_name
    """)
    return [row[0] for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# Partition retention
# ---------------------------------------------------------------------------


def _partition_is_expired(table_name: str, retention_days: int, today: date) -> bool:
    """True when a monthly archive partition's entire month is older than
    retention_days. Pure / DB-free so it is unit-testable.

    archive_events_YYYY_MM is expired when the LAST day of YYYY_MM is before
    (today - retention_days).
    """
    suffix = table_name[len("archive_events_") :]
    try:
        year, month = int(suffix[:4]), int(suffix[5:7])
        month_end = (
            date(year, 12, 31) if month == 12 else date(year, month + 1, 1) - timedelta(days=1)
        )
    except (ValueError, IndexError):
        return False
    return month_end < (today - timedelta(days=retention_days))


def drop_old_partitions(conn, retention_days: int, dry_run: bool = False) -> list[str]:
    """Drop archive_events_YYYY_MM partitions whose entire month is older than
    retention_days, enforcing a hard total-retention window. DROP TABLE frees
    the on-disk page files immediately — no VACUUM needed. Idempotent.

    Returns the list of dropped (or, in dry-run, would-drop) table names.
    """
    today = datetime.now(UTC).date()
    dropped: list[str] = []
    cur = conn.cursor()
    for tbl in get_archive_tables(conn):
        if not _partition_is_expired(tbl, retention_days, today):
            continue
        if dry_run:
            logger.info(
                "[dry-run] would drop expired partition %s (> %d days)", tbl, retention_days
            )
        else:
            cur.execute(sql.SQL("DROP TABLE IF EXISTS {}").format(sql.Identifier(tbl)))
            conn.commit()
            logger.info("dropped expired partition %s (> %d days)", tbl, retention_days)
        dropped.append(tbl)
    return dropped


# Tables whose rows describe exactly one sensor_event and are meaningless without it.
ANALYSIS_TABLES = ("ai_analysis", "claude_analysis_log")
# Everything the orphan sweep covers: the analyses plus every other per-event
# derivation. These are not analyses, so they live here and not in ANALYSIS_TABLES.
# A table belongs here only if its event_id REFERENCES a sensor_event. Sharing the
# column name is not enough: mitm_events mints its own ids and must stay out. See
# `delete_orphaned_analyses`. An entry in this tuple means the nightly timer deletes
# matching rows with nobody running a command, so check the referent first.
ORPHAN_TABLES = (*ANALYSIS_TABLES, "ics_events", "llm_honeypot_events")
ORPHAN_BATCH = 100000


def _event_exists_clause(conn, alias="t"):
    """SQL asking whether `alias.event_id` still exists in the live table or any
    surviving archive partition. Composed from the partitions that exist *now*,
    so it follows the retention window automatically."""
    parts = [
        sql.SQL("SELECT 1 FROM sensor_events e WHERE e.event_id = {}.event_id").format(
            sql.Identifier(alias)
        )
    ]
    for tbl in get_archive_tables(conn):
        parts.append(
            sql.SQL("SELECT 1 FROM {} a WHERE a.event_id = {}.event_id").format(
                sql.Identifier(tbl), sql.Identifier(alias)
            )
        )
    return sql.SQL(" UNION ALL ").join(parts)


def delete_orphaned_analyses(conn, dry_run: bool = False) -> dict[str, int]:
    """Delete per-event derivations whose event no longer exists anywhere.

    Covers ORPHAN_TABLES: the analyses (ai_analysis, claude_analysis_log), ics_events
    and llm_honeypot_events. Every row in them describes one sensor_event. Once
    retention has
    dropped that event — from the live table AND from every archive partition — the
    row points at evidence nobody can look at any more. It is not history, it is a
    dangling reference occupying disk. The name predates ics_events; the function
    is kept so callers and the CLI do not change.

    ics_events also has a NOT VALID ON DELETE CASCADE key (migration 0010), which
    covers deletes from now on but leaves rows orphaned before it; this sweep clears
    those and any later orphans left by dropped archive partitions.

    llm_honeypot_events (0008_llm_honeypot_events.sql:10) joined this list on
    2026-10-25. ingest/honeypot.py writes it from the same event line that writes the
    sensor_event, so its event_id is that event's id; it has no foreign key of its own,
    which makes this sweep its only mechanism -- unlike ics_events, which also has the
    cascade from migration 0010. Measured that day: 61 of one sensor's 62 rows had no event in
    the live table or any archive partition, the newest dated 2026-09-21. A second sensor 33 rows
    and a third 1 row, both 0 orphaned.

    mitm_events is NOT here, and the reason is worth the paragraph because it was first
    added to this tuple by mistake.

    It looks exactly like a per-event derivation -- event_id VARCHAR(64) UNIQUE NOT NULL,
    no foreign key, and on prod 4280 of 4280 rows with no matching sensor_event, a 100%
    rate that reads as the worst orphaning on the fleet. It is nothing of the kind.
    intelligence/mitm_detector.py mints its own id (`generate_event_id(f"arp-{ip}-{mac}-
    {ts}")` and the same for dns/dhcp/icmp-redir/llmnr/sslstrip/grat), and the row
    records a network observation the detector made on its own. There is no referent,
    there never was, and 100% is therefore the correct and permanent state.

    Measuring it exposed the mistake: prod's newest mitm_events row was 20 minutes old
    and already "orphaned", and the table was taking 209 rows a day. Retention cannot
    orphan a row that young. Sweeping this table would not clean up a backlog, it would
    delete a working subsystem's output every night, in silence. The shared column name
    is the whole trap -- before adding any table here, check that its event_id has a
    referent, not merely the same name.

    pcap_index: 0 rows on all seven sensors; every other host/table pair: 0 orphaned.

    Runs AFTER drop_old_partitions, because dropping a partition is precisely what
    turns these rows into orphans.

    Measured on PROD 2026-08-27 before this existed: 1,324,162 of 2,105,638
    ai_analysis rows (63%) and 1,394,329 of 2,255,294 claude_analysis_log rows
    (62%) were orphaned, holding 4.4 GB. Nothing had ever removed them because
    retention covered sensor_events alone.

    Deletes in batches so one long transaction cannot block ingest, and returns
    {table: rows_deleted}.
    """
    out: dict[str, int] = {}
    cur = conn.cursor()
    for tbl in ORPHAN_TABLES:
        cur.execute("SELECT to_regclass(%s)", (tbl,))
        if cur.fetchone()[0] is None:
            continue  # table absent on this sensor — fine
        exists = _event_exists_clause(conn)
        count_q = sql.SQL(
            "SELECT count(*) FROM {} t WHERE t.event_id IS NOT NULL AND NOT EXISTS ({})"
        ).format(sql.Identifier(tbl), exists)
        cur.execute(count_q)
        n = cur.fetchone()[0]
        if not n:
            out[tbl] = 0
            continue
        if dry_run:
            logger.info("[dry-run] would delete %d orphaned rows from %s", n, tbl)
            out[tbl] = n
            continue
        deleted = 0
        del_q = sql.SQL(
            "DELETE FROM {t} WHERE ctid IN (SELECT t.ctid FROM {t} t "
            "WHERE t.event_id IS NOT NULL AND NOT EXISTS ({e}) LIMIT %s)"
        ).format(t=sql.Identifier(tbl), e=exists)
        while True:
            cur.execute(del_q, (ORPHAN_BATCH,))
            got = cur.rowcount
            conn.commit()
            if not got:
                break
            deleted += got
        logger.info("deleted %d orphaned rows from %s", deleted, tbl)
        out[tbl] = deleted
    return out


# ---------------------------------------------------------------------------
# Archive Operations
# ---------------------------------------------------------------------------


def get_months_to_archive(conn, days: int) -> list[tuple[int, int, int]]:
    """
    Find distinct year/month combinations that have events older than N days.
    Returns list of (year, month, count) tuples — count is -1 when the
    cheap-path (MIN timestamp + month enumeration) is used, indicating
    "unknown, will be counted at archive time".

    Implementation history: the previous version did
        SELECT EXTRACT(YEAR FROM ts), EXTRACT(MONTH FROM ts), COUNT(*)
        FROM sensor_events WHERE timestamp < cutoff GROUP BY 1, 2
    which over a 70+ M-row sensor_events on DEV (2026-05-08, table at
    77 GB) timed out at the default 30s statement_timeout — a self-
    reinforcing failure: nightly archive never ran, so the table grew,
    so the next night's query took even longer.

    New approach: read MIN(timestamp) via idx_se_timestamp (≈1ms — the
    index returns the first leaf entry for ASC walks), then enumerate
    every (year, month) tuple from there to the last full month before
    cutoff. Each archive_month() call later determines the precise
    row count when it actually does the move.
    """
    cur = conn.cursor()
    # This is a maintenance batch job, not a user query; bypass the
    # session-level statement_timeout so the read can't be killed.
    cur.execute("SET LOCAL statement_timeout = 0")

    cur.execute("SELECT MIN(timestamp) FROM sensor_events")
    row = cur.fetchone()
    min_ts = row[0] if row else None
    if min_ts is None:
        return []

    cutoff = datetime.now(min_ts.tzinfo) - timedelta(days=days)
    if min_ts >= cutoff:
        return []

    months: list[tuple[int, int, int]] = []
    y, m = min_ts.year, min_ts.month
    cutoff_y, cutoff_m = cutoff.year, cutoff.month
    # `<=`, not `<`: the cutoff month is included and archive_month() clamps it to the
    # cutoff timestamp. Stopping before it left a whole month of over-age data in the
    # live table until the month happened to close — 476,605 rows on one sensor.
    while (y, m) <= (cutoff_y, cutoff_m):
        months.append((y, m, -1))  # count deferred
        m += 1
        if m > 12:
            y += 1
            m = 1
    return months


def archive_month(
    conn, year: int, month: int, dry_run: bool = False, cleanup: bool = True, not_after=None
) -> int:
    """
    Archive events for a specific month, up to `not_after` if given.

    `not_after` is what lets the *current* month be archived. Without it this
    function moves whole months only, so the caller had to stop before the month
    containing the cutoff — and every row in that month stayed live no matter how
    old. With `--days 30` on the 11th of a month that meant the previous month's
    entire contents, 476,605 rows on one sensor, waiting for the month to close.

    Returns count of archived events.
    """
    table_name = get_archive_table_name(year, month)

    # Calculate date range for this month
    start_date = datetime(year, month, 1, tzinfo=UTC)
    if month == 12:
        end_date = datetime(year + 1, 1, 1, tzinfo=UTC)
    else:
        end_date = datetime(year, month + 1, 1, tzinfo=UTC)
    if not_after is not None:
        # Month ranges are in UTC; we bring the cutoff clamp into UTC (naive = treated as
        # UTC), so the comparison does not mix aware with naive.
        bound = not_after if not_after.tzinfo else not_after.replace(tzinfo=UTC)
        if bound < end_date:
            end_date = bound
    if end_date <= start_date:
        return 0

    cur = conn.cursor()

    # Count events to archive
    cur.execute(
        """
        SELECT COUNT(*) FROM sensor_events
        WHERE timestamp >= %s AND timestamp < %s
    """,
        (start_date, end_date),
    )
    count = cur.fetchone()[0]

    if count == 0:
        logger.info("No events to archive for %d-%02d", year, month)
        return 0

    logger.info("Found %d events to archive for %d-%02d", count, year, month)

    if dry_run:
        logger.info("[DRY RUN] Would archive %d events to %s", count, table_name)
        return count

    # Ensure archive table exists
    ensure_archive_table(conn, year, month)

    # Copy events to archive table in batches
    archived = 0
    offset = 0

    while offset < count:
        cur.execute(
            sql.SQL("""
            INSERT INTO {} (
                event_id, timestamp, source, protocol,
                src_ip, src_port, dst_ip, dst_port,
                payload, payload_hash, scan_score, port_entropy,
                ja3, metadata, attack_types
            )
            SELECT
                event_id, timestamp, source, protocol,
                src_ip, src_port, dst_ip, dst_port,
                payload, payload_hash, scan_score, port_entropy,
                ja3, metadata, attack_types
            FROM sensor_events
            WHERE timestamp >= %s AND timestamp < %s
            ORDER BY timestamp
            LIMIT %s OFFSET %s
        """).format(sql.Identifier(table_name)),
            (start_date, end_date, BATCH_SIZE, offset),
        )

        batch_count = cur.rowcount
        archived += batch_count
        offset += BATCH_SIZE

        if archived % PROGRESS_INTERVAL == 0 or archived >= count:
            logger.info("Archived %d/%d events for %d-%02d", archived, count, year, month)

        conn.commit()

    logger.info("Archived %d events to %s", archived, table_name)

    # Delete from main table if cleanup enabled
    if cleanup and archived > 0:
        logger.info("Deleting archived events from sensor_events...")

        deleted = 0
        while True:
            cur.execute(
                """
                DELETE FROM sensor_events
                WHERE event_id IN (
                    SELECT event_id FROM sensor_events
                    WHERE timestamp >= %s AND timestamp < %s
                    LIMIT %s
                )
            """,
                (start_date, end_date, BATCH_SIZE),
            )

            batch_deleted = cur.rowcount
            deleted += batch_deleted
            conn.commit()

            if batch_deleted == 0:
                break

            if deleted % PROGRESS_INTERVAL == 0:
                logger.info("Deleted %d events from main table", deleted)

        logger.info("Deleted %d events from sensor_events", deleted)

    return archived


def archive_events(days: int = 30, dry_run: bool = False, cleanup: bool = True) -> dict[str, int]:
    """
    Archive all events older than specified days.
    Returns dict with counts per month.
    """
    conn = get_conn()

    months = get_months_to_archive(conn, days)
    # The same cutoff the month list was built from; archive_month clamps the final
    # month to it so nothing newer than `days` is ever moved.
    cutoff = datetime.now(UTC) - timedelta(days=days)

    if not months:
        logger.info("No events older than %d days to archive", days)
        conn.close()
        return {}

    counts = [m[2] for m in months if m[2] >= 0]
    if counts and len(counts) == len(months):
        total = sum(counts)
        logger.info("Found %d events across %d months to archive", total, len(months))
    else:
        logger.info("Found %d months to archive (counts deferred to per-month pass)", len(months))

    results = {}

    for year, month, _expected_count in months:
        key = f"{year}-{month:02d}"
        try:
            archived = archive_month(conn, year, month, dry_run, cleanup, not_after=cutoff)
            results[key] = archived
        except Exception as e:
            logger.error("Error archiving %s: %s", key, e)
            results[key] = -1
            conn.rollback()

    conn.close()
    return results


# ---------------------------------------------------------------------------
# Export Operations
# ---------------------------------------------------------------------------


def export_archive_to_csv(year: int, month: int, output_dir: str | None = None) -> str | None:
    """
    Export an archive table to compressed CSV.
    Returns path to exported file.
    """
    if output_dir is None:
        output_dir = DB_ARCHIVE_DIR

    os.makedirs(output_dir, exist_ok=True)

    table_name = get_archive_table_name(year, month)
    output_file = os.path.join(output_dir, f"{table_name}.csv.gz")

    conn = get_conn()
    cur = conn.cursor()

    # Check if table exists
    cur.execute(
        """
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = %s
        )
    """,
        (table_name,),
    )

    if not cur.fetchone()[0]:
        logger.warning("Archive table %s does not exist", table_name)
        conn.close()
        return None

    # Get column names
    cur.execute(sql.SQL("SELECT * FROM {} LIMIT 0").format(sql.Identifier(table_name)))
    columns = [desc[0] for desc in cur.description]

    # Export to compressed CSV
    logger.info("Exporting %s to %s", table_name, output_file)

    cur.execute(sql.SQL("SELECT * FROM {} ORDER BY timestamp").format(sql.Identifier(table_name)))

    row_count = 0
    with gzip.open(output_file, "wt", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(columns)

        while True:
            rows = cur.fetchmany(BATCH_SIZE)
            if not rows:
                break

            for row in rows:
                # Convert special types to strings
                processed_row = []
                for val in row:
                    if val is None:
                        processed_row.append("")
                    elif isinstance(val, datetime):
                        processed_row.append(val.isoformat())
                    elif isinstance(val, dict):
                        import json

                        processed_row.append(json.dumps(val))
                    else:
                        processed_row.append(str(val))
                writer.writerow(processed_row)

            row_count += len(rows)

    conn.close()

    file_size = os.path.getsize(output_file)
    logger.info("Exported %d rows to %s (%.2f MB)", row_count, output_file, file_size / 1024 / 1024)

    return output_file


# ---------------------------------------------------------------------------
# Statistics and Maintenance
# ---------------------------------------------------------------------------


def get_archive_stats() -> dict:
    """Get statistics about archive tables."""
    conn = get_conn()
    cur = conn.cursor()

    # Get archive tables with sizes
    cur.execute("""
        SELECT
            table_name,
            pg_size_pretty(pg_total_relation_size(quote_ident(table_name))) as size,
            pg_total_relation_size(quote_ident(table_name)) as size_bytes
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name LIKE 'archive_events_%'
        ORDER BY table_name
    """)

    tables = []
    total_size = 0
    total_events = 0

    for row in cur.fetchall():
        table_name = row[0]

        # Get row count
        cur.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table_name)))
        count = cur.fetchone()[0]

        # Parse year/month from table name
        parts = table_name.split("_")
        year, month = int(parts[2]), int(parts[3])

        tables.append(
            {
                "table": table_name,
                "year": year,
                "month": month,
                "size": row[1],
                "size_bytes": row[2],
                "events": count,
            }
        )

        total_size += row[2]
        total_events += count

    # Get main table stats
    cur.execute("SELECT COUNT(*) FROM sensor_events")
    active_events = cur.fetchone()[0]

    cur.execute("""
        SELECT pg_size_pretty(pg_total_relation_size('sensor_events'))
    """)
    active_size = cur.fetchone()[0]

    # Get date range of active events
    cur.execute("""
        SELECT MIN(timestamp), MAX(timestamp) FROM sensor_events
    """)
    date_range = cur.fetchone()

    conn.close()

    return {
        "archive_tables": len(tables),
        "archived_events": total_events,
        "archived_size": f"{total_size / 1024 / 1024:.2f} MB",
        "archived_size_bytes": total_size,
        "active_events": active_events,
        "active_size": active_size,
        "active_date_range": {
            "min": date_range[0].isoformat() if date_range[0] else None,
            "max": date_range[1].isoformat() if date_range[1] else None,
        },
        "tables": tables,
    }


def vacuum_tables(full: bool = False, analyze: bool = True):
    """
    Vacuum and optionally analyze tables.
    """
    conn = get_conn()
    conn.autocommit = True  # VACUUM cannot run in a transaction
    cur = conn.cursor()

    tables = ["sensor_events", "attack_patterns", "ja4_fingerprints"]

    # Add archive tables
    cur.execute("""
        SELECT table_name FROM information_schema.tables
        WHERE table_name LIKE 'archive_events_%'
    """)
    tables.extend([row[0] for row in cur.fetchall()])

    for table in tables:
        try:
            if full:
                logger.info("Running VACUUM FULL on %s...", table)
                cur.execute(sql.SQL("VACUUM FULL {}").format(sql.Identifier(table)))
            else:
                logger.info("Running VACUUM on %s...", table)
                cur.execute(sql.SQL("VACUUM {}").format(sql.Identifier(table)))

            if analyze:
                logger.info("Running ANALYZE on %s...", table)
                cur.execute(sql.SQL("ANALYZE {}").format(sql.Identifier(table)))

            logger.info("Completed maintenance on %s", table)

        except Exception as e:
            logger.error("Error on %s: %s", table, e)

    conn.close()
    logger.info("Vacuum complete")


def reindex_tables():
    """Reindex all main tables."""
    conn = get_conn()
    conn.autocommit = True
    cur = conn.cursor()

    tables = ["sensor_events", "attack_patterns", "ja4_fingerprints", "mitm_events", "ics_events"]

    for table in tables:
        try:
            logger.info("Reindexing %s...", table)
            cur.execute(sql.SQL("REINDEX TABLE {}").format(sql.Identifier(table)))
            logger.info("Reindexed %s", table)
        except Exception as e:
            logger.error("Error reindexing %s: %s", table, e)

    conn.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Database archival and maintenance tool")
    parser.add_argument(
        "--days",
        type=int,
        default=DB_ARCHIVE_DAYS,
        help=f"Archive events older than N days (default: {DB_ARCHIVE_DAYS})",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=None,
        help="After archiving, DROP archive partitions whose month is "
        "entirely older than N days (enforces total retention so "
        "the database cannot grow unbounded)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be archived without making changes"
    )
    parser.add_argument(
        "--no-cleanup", action="store_true", help="Don't delete from main table after archiving"
    )
    parser.add_argument(
        "--no-orphan-cleanup",
        action="store_true",
        help="Keep per-event rows (ai_analysis, claude_analysis_log, ics_events, "
        "llm_honeypot_events) whose event "
        "has been dropped by retention (default: delete them — "
        "they reference evidence that no longer exists)",
    )
    parser.add_argument("--export", action="store_true", help="Export archives to compressed CSV")
    parser.add_argument(
        "--export-dir",
        type=str,
        default=DB_ARCHIVE_DIR,
        help=f"Directory for CSV exports (default: {DB_ARCHIVE_DIR})",
    )
    parser.add_argument("--stats", action="store_true", help="Show archive statistics")
    parser.add_argument("--vacuum", action="store_true", help="Vacuum and analyze tables")
    parser.add_argument(
        "--vacuum-full", action="store_true", help="Full vacuum (reclaims disk space, locks tables)"
    )
    parser.add_argument("--reindex", action="store_true", help="Reindex tables")

    args = parser.parse_args()

    # Show stats
    if args.stats:
        stats = get_archive_stats()
        print("\n=== Archive Statistics ===")
        print(f"Active events: {stats['active_events']:,}")
        print(f"Active table size: {stats['active_size']}")
        if stats["active_date_range"]["min"]:
            print(
                f"Active date range: {stats['active_date_range']['min'][:10]} to {stats['active_date_range']['max'][:10]}"
            )
        print(f"\nArchived events: {stats['archived_events']:,}")
        print(f"Archive size: {stats['archived_size']}")
        print(f"Archive tables: {stats['archive_tables']}")

        if stats["tables"]:
            print("\nArchive Tables:")
            print("-" * 60)
            for t in stats["tables"]:
                print(f"  {t['table']}: {t['events']:,} events ({t['size']})")
        return

    # Vacuum
    if args.vacuum or args.vacuum_full:
        vacuum_tables(full=args.vacuum_full)
        return

    # Reindex
    if args.reindex:
        reindex_tables()
        return

    # Archive
    cleanup = not args.no_cleanup and DB_ARCHIVE_CLEANUP

    print("\n=== Database Archival ===")
    print(f"Archiving events older than {args.days} days")
    print(f"Cleanup after archive: {cleanup}")
    print(f"Dry run: {args.dry_run}")
    print()

    results = archive_events(days=args.days, dry_run=args.dry_run, cleanup=cleanup)

    failed_months = [m for m, c in results.items() if c < 0]
    if results:
        print("\n=== Archive Results ===")
        total = 0
        for month, count in sorted(results.items()):
            status = "✓" if count >= 0 else "✗"
            print(f"  {status} {month}: {abs(count):,} events")
            if count > 0:
                total += count
        print(f"\nTotal archived: {total:,} events")
        if failed_months:
            # A month that could not be archived is not a detail — the live table
            # keeps growing while the partition-drop step below still deletes old
            # archives, so the database silently loses both ways. Observed in production
            # 2026-08-30: every month failed on a foreign key, "Total archived: 0
            # events" was printed, the unit exited 0, and 7.8 million rows older
            # than 60 days sat in sensor_events while their archive partitions
            # were dropped. Make it visible, and make systemd show it red.
            print("\n=== ARCHIVE FAILURES ===")
            print("  could not archive: {}".format(", ".join(sorted(failed_months))))
            print("  the live table is NOT being trimmed — see the errors above")
    else:
        print("No events to archive")

    # Export if requested
    if args.export and results:
        print("\n=== Exporting Archives ===")
        for month_str in results.keys():
            if results[month_str] > 0:
                year, month = month_str.split("-")
                export_archive_to_csv(int(year), int(month), args.export_dir)

    # Retention: drop archive partitions whose month is entirely older than N days
    if args.retention_days is not None:
        conn = get_conn()
        try:
            dropped = drop_old_partitions(conn, args.retention_days, dry_run=args.dry_run)
            # Dropping a partition is what orphans the analyses that describe its
            # events, so this belongs immediately after — never before.
            orphans = (
                {}
                if args.no_orphan_cleanup
                else delete_orphaned_analyses(conn, dry_run=args.dry_run)
            )
        finally:
            conn.close()
        print(f"\n=== Partition Retention ({args.retention_days} days) ===")
        verb = "Would drop" if args.dry_run else "Dropped"
        print(f"  {verb}: {', '.join(dropped) if dropped else 'none'}")
        if orphans:
            print("\n=== Orphaned Rows ===")
            verb = "Would delete" if args.dry_run else "Deleted"
            for tbl, n in sorted(orphans.items()):
                print(f"  {verb}: {n:,} from {tbl}")

    if failed_months:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main() or 0)
