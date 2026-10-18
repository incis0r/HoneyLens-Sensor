#!/usr/bin/env python3
"""
backfill_attacks.py - Optimized Retroactive Attack Classification
===================================================================
High-performance backfill using:
- Multiprocessing (parallel workers)
- Connection pooling
- Cursor-based pagination (no slow OFFSET)
- Bulk COPY for pattern inserts
- Pre-filtering NULL/empty payloads
- Batch commits with minimal round-trips

Usage:
    python backfill_attacks.py                    # Process unclassified events
    python backfill_attacks.py --reprocess        # Reprocess ALL events
    python backfill_attacks.py --workers 8        # Use 8 parallel workers
    python backfill_attacks.py --batch-size 10000 # Larger batches
    python backfill_attacks.py --dry-run          # Test without writing

Performance: ~10,000-50,000 events/sec depending on hardware
"""

from __future__ import annotations

import argparse
import io
import logging
import multiprocessing as mp
import signal
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass

import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool

from honeylens.database import legacy_get_db as _legacy_get_db

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
)
logger = logging.getLogger("backfill")

# Import config
try:
    from honeylens.config import DB_CONFIG
except ImportError:
    logger.error("Could not import DB_CONFIG from config.py")
    sys.exit(1)

# Import classifier - done per-worker to avoid pickling issues
_classifier = None


def _get_classifier():
    """Lazy load classifier (for multiprocessing)."""
    global _classifier
    if _classifier is None:
        try:
            # Post-2026-04-21 refactor: classify_payload + get_severity live
            # in classification.scoring (extracted from attack_classifier.py).
            from honeylens.classification.scoring import classify_payload, get_severity

            _classifier = (classify_payload, get_severity)
        except ImportError as exc:
            logger.error("Could not import classifier: %s", exc)
            sys.exit(1)
    return _classifier


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class BackfillConfig:
    """Backfill configuration."""

    batch_size: int = 10000  # Events per batch
    workers: int = 0  # 0 = auto (CPU count)
    reprocess_all: bool = False  # Reprocess already-classified events
    dry_run: bool = False  # Don't write to database
    limit: int | None = None  # Max events to process
    progress_interval: int = 50000  # Log progress every N events
    use_copy: bool = True  # Use COPY for pattern inserts (faster)
    include_severity: bool = True  # Include severity in patterns table
    # Reprocess authoritative: purge each batch's attack_patterns before re-inserting, and
    # NULL out attack_types for events that no longer match any rule. Without this a rule that
    # was tightened leaves stale pattern rows and a stale summary behind. Only meaningful with
    # reprocess_all.
    replace_patterns: bool = False


# =============================================================================
# Database Helpers
# =============================================================================

_pool: ThreadedConnectionPool | None = None


def get_pool() -> ThreadedConnectionPool:
    """Get or create connection pool."""
    global _pool
    if _pool is None:
        _pool = ThreadedConnectionPool(minconn=2, maxconn=20, **DB_CONFIG)
    return _pool


def get_connection():
    """Get connection from pool."""
    return get_pool().getconn()


def put_connection(conn):
    """Return connection to pool."""
    try:
        get_pool().putconn(conn)
    except Exception as _exc:  # silent: best effort connection pool return
        logging.getLogger(__name__).debug("ignored: %s", _exc)


def get_direct_connection():
    """Get direct connection (not from pool) for workers."""
    return _legacy_get_db()


# =============================================================================
# Optimized Event Fetching (Cursor-based pagination)
# =============================================================================


def get_total_count(reprocess_all: bool = False) -> int:
    """Get total count of events to process."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        if reprocess_all:
            cur.execute("""
                SELECT COUNT(*) FROM sensor_events
                WHERE payload IS NOT NULL AND payload != ''
            """)
            return cur.fetchone()[0]
        # For unclassified-only mode, the exact COUNT(*) times out on
        # large tables (>5M rows). Use the pg_class table-stats estimate
        # instead — it's a hint for progress reporting, not a hard
        # number that must be exact.
        try:
            cur.execute("SET LOCAL statement_timeout = '5s'")
            cur.execute("""
                SELECT COUNT(*) FROM sensor_events
                WHERE attack_types IS NULL
                  AND payload IS NOT NULL AND payload != ''
            """)
            return cur.fetchone()[0]
        except psycopg2.errors.QueryCanceled:
            conn.rollback()
            cur.execute("""
                SELECT GREATEST(reltuples::bigint, 0)
                FROM pg_class
                WHERE relname = 'sensor_events'
            """)
            row = cur.fetchone()
            return int(row[0]) if row else 0
    finally:
        put_connection(conn)


def fetch_event_batch_cursor(
    last_event_id: str | None, batch_size: int, reprocess_all: bool = False
) -> list[tuple[str, str]]:
    """
    Fetch batch of events using cursor-based pagination.
    Much faster than OFFSET for large tables.

    Returns: List of (event_id, payload) tuples
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        if reprocess_all:
            if last_event_id:
                cur.execute(
                    """
                    SELECT event_id, payload
                    FROM sensor_events
                    WHERE event_id > %s
                      AND payload IS NOT NULL AND payload != ''
                    ORDER BY event_id
                    LIMIT %s
                """,
                    (last_event_id, batch_size),
                )
            else:
                cur.execute(
                    """
                    SELECT event_id, payload
                    FROM sensor_events
                    WHERE payload IS NOT NULL AND payload != ''
                    ORDER BY event_id
                    LIMIT %s
                """,
                    (batch_size,),
                )
        else:
            if last_event_id:
                cur.execute(
                    """
                    SELECT event_id, payload
                    FROM sensor_events
                    WHERE event_id > %s
                      AND attack_types IS NULL
                      AND payload IS NOT NULL AND payload != ''
                    ORDER BY event_id
                    LIMIT %s
                """,
                    (last_event_id, batch_size),
                )
            else:
                cur.execute(
                    """
                    SELECT event_id, payload
                    FROM sensor_events
                    WHERE attack_types IS NULL
                      AND payload IS NOT NULL AND payload != ''
                    ORDER BY event_id
                    LIMIT %s
                """,
                    (batch_size,),
                )

        return cur.fetchall()
    finally:
        put_connection(conn)


# =============================================================================
# Batch Classification (runs in worker process)
# =============================================================================


def classify_batch(
    events: list[tuple[str, str]], include_severity: bool = True
) -> tuple[list, list]:
    """
    Classify a batch of events.

    Args:
        events: List of (event_id, payload) tuples
        include_severity: Include severity in pattern records

    Returns:
        (updates, patterns) where:
        - updates: List of (attack_summary, event_id) for UPDATE
        - patterns: List of (event_id, attack_type, rule_name, matched_text, severity)
    """
    classify_payload, get_severity = _get_classifier()

    updates = []
    patterns = []

    for event_id, payload in events:
        if not payload:
            continue

        try:
            result = classify_payload(payload)
            if result is None:
                continue

            attack_summary, hits = result
            if not hits or not attack_summary:
                continue

            updates.append((attack_summary, event_id))

            # Collect patterns
            for hit in hits:
                if len(hit) >= 3:
                    attack_type, rule_name, matched_text = hit[0], hit[1], hit[2]
                    severity = get_severity(attack_type, rule_name) if include_severity else None
                    patterns.append(
                        (
                            event_id,
                            attack_type,
                            rule_name,
                            (matched_text[:500] if matched_text else None),
                            severity,
                        )
                    )
        except Exception as e:
            # Log but continue
            logger.debug("Error classifying %s: %s", event_id, e)
            continue

    return updates, patterns


def worker_classify_batch(args):
    """Worker function for ProcessPoolExecutor."""
    events, include_severity = args
    return classify_batch(events, include_severity)


# =============================================================================
# Optimized Database Writes
# =============================================================================


def write_updates_batch(updates: list[tuple[str, str]], dry_run: bool = False) -> int:
    """Write attack_types updates using execute_batch."""
    if not updates or dry_run:
        return len(updates)

    conn = get_connection()
    try:
        cur = conn.cursor()
        psycopg2.extras.execute_batch(
            cur,
            "UPDATE sensor_events SET attack_types = %s WHERE event_id = %s",
            updates,
            page_size=1000,
        )
        conn.commit()
        return len(updates)
    except Exception as e:
        logger.error("Error writing updates: %s", e)
        conn.rollback()
        return 0
    finally:
        put_connection(conn)


def write_patterns_copy(
    patterns: list[tuple], dry_run: bool = False, has_severity: bool = True
) -> int:
    """
    Write patterns using COPY (much faster than INSERT).
    Falls back to execute_batch if COPY fails.
    """
    if not patterns or dry_run:
        return len(patterns)

    conn = get_connection()
    try:
        cur = conn.cursor()

        # Build COPY data
        buffer = io.StringIO()
        for p in patterns:
            # Escape special characters for COPY
            event_id = p[0] or ""
            attack_type = p[1] or ""
            rule_name = p[2] or ""
            matched_text = (
                (p[3] or "")
                .replace("\t", " ")
                .replace("\n", " ")
                .replace("\r", "")
                .replace("\\", "\\\\")
            )
            severity = p[4] or "medium" if has_severity else ""

            if has_severity:
                buffer.write(
                    f"{event_id}\t{attack_type}\t{rule_name}\t{matched_text}\t{severity}\n"
                )
            else:
                buffer.write(f"{event_id}\t{attack_type}\t{rule_name}\t{matched_text}\n")

        buffer.seek(0)

        # Try COPY
        try:
            if has_severity:
                cur.copy_from(
                    buffer,
                    "attack_patterns",
                    columns=("event_id", "attack_type", "rule_name", "matched_text", "severity"),
                    null="",
                )
            else:
                cur.copy_from(
                    buffer,
                    "attack_patterns",
                    columns=("event_id", "attack_type", "rule_name", "matched_text"),
                    null="",
                )
            conn.commit()
            return len(patterns)
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            # Fall back to execute_batch with ON CONFLICT
            return write_patterns_batch(patterns, dry_run, has_severity, conn)
        except Exception as e:
            conn.rollback()
            logger.warning("COPY failed, using batch insert: %s", e)
            return write_patterns_batch(patterns, dry_run, has_severity, conn)
    finally:
        put_connection(conn)


def write_patterns_batch(
    patterns: list[tuple], dry_run: bool = False, has_severity: bool = True, conn=None
) -> int:
    """Write patterns using execute_batch with ON CONFLICT."""
    if not patterns or dry_run:
        return len(patterns)

    should_close = conn is None
    if conn is None:
        conn = get_connection()

    try:
        cur = conn.cursor()

        if has_severity:
            psycopg2.extras.execute_batch(
                cur,
                """
                INSERT INTO attack_patterns (event_id, attack_type, rule_name, matched_text, severity)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                patterns,
                page_size=1000,
            )
        else:
            psycopg2.extras.execute_batch(
                cur,
                """
                INSERT INTO attack_patterns (event_id, attack_type, rule_name, matched_text)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                [(p[0], p[1], p[2], p[3]) for p in patterns],
                page_size=1000,
            )

        conn.commit()
        return len(patterns)
    except Exception as e:
        logger.error("Error writing patterns: %s", e)
        conn.rollback()
        return 0
    finally:
        if should_close:
            put_connection(conn)


_CENTRAL_RULE_NAMES: frozenset[str] | None = None


def _central_rule_names() -> frozenset[str]:
    """Rule names the central text classifier produces — the only attack_patterns rows a
    reprocess owns. Honeypot decoys author their OWN rows at ingest (e.g. the ns-* tags),
    which the central classifier does not reproduce; those must be preserved on reprocess."""
    global _CENTRAL_RULE_NAMES
    if _CENTRAL_RULE_NAMES is None:
        from honeylens.classification.text_rules import _RULES

        _CENTRAL_RULE_NAMES = frozenset(n for _, n, _ in _RULES)
    return _CENTRAL_RULE_NAMES


def delete_patterns_for_events(event_ids: list[str], dry_run: bool = False) -> int:
    """Delete only the CENTRAL classifier's rows for these events, so reprocess can re-insert
    them. Honeypot-authored detections (decoy ns-* tags, vendor-emulation CVE tags) are kept —
    deleting them would lose data the central classifier cannot regenerate."""
    if not event_ids or dry_run:
        return 0
    names = list(_central_rule_names())
    if not names:
        return 0
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM attack_patterns WHERE event_id = ANY(%s) AND rule_name = ANY(%s) "
            "AND (attack_type IS NULL OR attack_type NOT LIKE 'ns-%%')",
            (list(event_ids), names),
        )
        conn.commit()
        return cur.rowcount
    except Exception as e:
        logger.error("Error deleting patterns: %s", e)
        conn.rollback()
        return 0
    finally:
        put_connection(conn)


def rebuild_attack_types(event_ids: list[str], dry_run: bool = False) -> int:
    """Set each event's attack_types summary to the union of its *remaining* attack_patterns
    (honeypot-authored plus the freshly re-inserted central ones), or NULL when it has none.
    Replaces the old 'NULL when the central classifier found nothing', which erased the
    decoys' own tags."""
    if not event_ids or dry_run:
        return 0
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE sensor_events e SET attack_types = sub.types
            FROM (
                SELECT ev.event_id,
                       NULLIF(string_agg(DISTINCT ap.attack_type, ',' ORDER BY ap.attack_type), '')
                           AS types
                FROM unnest(%s::text[]) AS ev(event_id)
                LEFT JOIN attack_patterns ap ON ap.event_id = ev.event_id
                GROUP BY ev.event_id
            ) sub
            WHERE e.event_id = sub.event_id
            """,
            (list(event_ids),),
        )
        conn.commit()
        return cur.rowcount
    except Exception as e:
        logger.error("Error rebuilding attack_types: %s", e)
        conn.rollback()
        return 0
    finally:
        put_connection(conn)


# =============================================================================
# Check Schema
# =============================================================================


def check_schema() -> tuple[bool, bool]:
    """
    Check database schema.
    Returns: (has_patterns_table, has_severity_column)
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        # Check attack_patterns table
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_name = 'attack_patterns'
            )
        """)
        has_patterns = cur.fetchone()[0]

        # Check severity column
        has_severity = False
        if has_patterns:
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'attack_patterns' AND column_name = 'severity'
                )
            """)
            has_severity = cur.fetchone()[0]

        return has_patterns, has_severity
    finally:
        put_connection(conn)


# =============================================================================
# Main Backfill Logic
# =============================================================================


def backfill_sequential(config: BackfillConfig):
    """Single-threaded backfill (for debugging or small datasets)."""

    has_patterns, has_severity = check_schema()
    total = get_total_count(config.reprocess_all)

    if config.limit:
        total = min(total, config.limit)

    if total == 0:
        logger.info("No events to process")
        return

    logger.info("Processing %s events (sequential mode)", total)
    if not has_patterns:
        logger.warning("attack_patterns table not found - skipping pattern inserts")

    start_time = time.time()
    processed = 0
    total_attacks = 0
    total_patterns = 0
    last_event_id = None
    last_progress = 0

    while processed < total:
        # Fetch batch
        events = fetch_event_batch_cursor(last_event_id, config.batch_size, config.reprocess_all)

        if not events:
            break

        last_event_id = events[-1][0]

        # Classify
        updates, patterns = classify_batch(events, has_severity)

        # Write
        if not config.dry_run:
            batch_ids = [e[0] for e in events]
            if config.replace_patterns:
                # Authoritative reprocess: drop only the central classifier's own rows,
                # re-insert them, then rebuild each summary from the union of what remains
                # (so honeypot-authored ns-* tags survive).
                if has_patterns:
                    delete_patterns_for_events(batch_ids)
                    if patterns:
                        if config.use_copy:
                            write_patterns_copy(patterns, has_severity=has_severity)
                        else:
                            write_patterns_batch(patterns, has_severity=has_severity)
                rebuild_attack_types(batch_ids)
            else:
                write_updates_batch(updates)
                if has_patterns and patterns:
                    if config.use_copy:
                        write_patterns_copy(patterns, has_severity=has_severity)
                    else:
                        write_patterns_batch(patterns, has_severity=has_severity)

        processed += len(events)
        total_attacks += len(updates)
        total_patterns += len(patterns)

        # Progress
        if processed - last_progress >= config.progress_interval:
            elapsed = time.time() - start_time
            rate = processed / elapsed if elapsed > 0 else 0
            pct = 100 * processed / total
            eta = (total - processed) / rate if rate > 0 else 0
            logger.info(
                "Progress: %s/%s (%s%%) | %s attacks | %s/sec | ETA: %ss",
                f"{processed:,}",
                f"{total:,}",
                f"{pct:.1f}",
                total_attacks,
                f"{rate:.0f}",
                f"{eta:.0f}",
            )
            last_progress = processed

        if config.limit and processed >= config.limit:
            break

    # Final stats
    elapsed = time.time() - start_time
    rate = processed / elapsed if elapsed > 0 else 0
    logger.info("=" * 60)
    logger.info("Backfill complete%s", " (dry run)" if config.dry_run else "")
    logger.info("  Events: %s", processed)
    if processed:
        logger.info(
            "  Attacks: %s (%s%%)", f"{total_attacks:,}", f"{100 * total_attacks / processed:.1f}"
        )
    else:
        logger.info("  Attacks: 0")
    logger.info("  Patterns: %s", total_patterns)
    logger.info("  Time: %ss | Rate: %s/sec", elapsed, rate)


def backfill_parallel(config: BackfillConfig):
    """
    Multi-process parallel backfill for maximum performance.
    """

    has_patterns, has_severity = check_schema()
    total = get_total_count(config.reprocess_all)

    if config.limit:
        total = min(total, config.limit)

    if total == 0:
        logger.info("No events to process")
        return

    # Auto-detect workers
    workers = config.workers if config.workers > 0 else max(1, mp.cpu_count() - 1)

    logger.info("Processing %s events with %s workers", total, workers)
    if not has_patterns:
        logger.warning("attack_patterns table not found - skipping pattern inserts")

    start_time = time.time()
    processed = 0
    total_attacks = 0
    total_patterns = 0
    last_event_id = None
    last_progress = 0

    # Pre-fetch batches for parallel processing
    fetch_batch_size = config.batch_size
    process_batch_size = max(1000, config.batch_size // workers)

    with ProcessPoolExecutor(max_workers=workers) as executor:
        while processed < total:
            # Fetch a larger batch to split among workers
            events = fetch_event_batch_cursor(last_event_id, fetch_batch_size, config.reprocess_all)

            if not events:
                break

            last_event_id = events[-1][0]

            # Split into chunks for parallel processing
            chunks = []
            for i in range(0, len(events), process_batch_size):
                chunk = events[i : i + process_batch_size]
                chunks.append((chunk, has_severity))

            # Process in parallel
            all_updates = []
            all_patterns = []

            futures = [executor.submit(worker_classify_batch, chunk) for chunk in chunks]

            for future in as_completed(futures):
                try:
                    updates, patterns = future.result()
                    all_updates.extend(updates)
                    all_patterns.extend(patterns)
                except Exception as e:
                    logger.error("Worker error: %s", e)

            # Write results
            if not config.dry_run:
                batch_ids = [e[0] for e in events]
                if config.replace_patterns:
                    if has_patterns:
                        delete_patterns_for_events(batch_ids)
                        if all_patterns:
                            if config.use_copy:
                                write_patterns_copy(all_patterns, has_severity=has_severity)
                            else:
                                write_patterns_batch(all_patterns, has_severity=has_severity)
                    rebuild_attack_types(batch_ids)
                else:
                    write_updates_batch(all_updates)
                    if has_patterns and all_patterns:
                        if config.use_copy:
                            write_patterns_copy(all_patterns, has_severity=has_severity)
                        else:
                            write_patterns_batch(all_patterns, has_severity=has_severity)

            processed += len(events)
            total_attacks += len(all_updates)
            total_patterns += len(all_patterns)

            # Progress
            if processed - last_progress >= config.progress_interval:
                elapsed = time.time() - start_time
                rate = processed / elapsed if elapsed > 0 else 0
                pct = 100 * processed / total
                eta = (total - processed) / rate if rate > 0 else 0
                logger.info(
                    "Progress: %s/%s (%s%%) | %s attacks | %s/sec | ETA: %ss",
                    f"{processed:,}",
                    f"{total:,}",
                    f"{pct:.1f}",
                    total_attacks,
                    f"{rate:.0f}",
                    f"{eta:.0f}",
                )
                last_progress = processed

            if config.limit and processed >= config.limit:
                break

    # Final stats
    elapsed = time.time() - start_time
    rate = processed / elapsed if elapsed > 0 else 0
    logger.info("=" * 60)
    logger.info("Backfill complete%s", " (dry run)" if config.dry_run else "")
    logger.info("  Events: %s", processed)
    if processed:
        logger.info(
            "  Attacks: %s (%s%%)", f"{total_attacks:,}", f"{100 * total_attacks / processed:.1f}"
        )
    else:
        logger.info("  Attacks: 0")
    logger.info("  Patterns: %s", total_patterns)
    logger.info("  Time: %ss | Rate: %s/sec", elapsed, rate)
    logger.info("  Workers: %s", workers)


def backfill(config: BackfillConfig):
    """Run backfill with optimal strategy."""

    total = get_total_count(config.reprocess_all)

    if config.limit:
        total = min(total, config.limit)

    # Use parallel for large datasets, sequential for small
    if total > 50000 and config.workers != 1:
        backfill_parallel(config)
    else:
        backfill_sequential(config)


# =============================================================================
# CLI
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Optimized attack classification backfill",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                        # Process unclassified events
    %(prog)s --reprocess            # Reprocess ALL events
    %(prog)s --workers 8            # Use 8 parallel workers
    %(prog)s --batch-size 20000     # Larger batches
    %(prog)s --dry-run              # Test without writing
    %(prog)s --sequential           # Force single-threaded mode
        """,
    )

    parser.add_argument(
        "--reprocess",
        "-r",
        action="store_true",
        help="Reprocess all events (including already classified)",
    )
    parser.add_argument(
        "--dry-run", "-n", action="store_true", help="Test mode - don't write to database"
    )
    parser.add_argument("--limit", "-l", type=int, default=None, help="Maximum events to process")
    parser.add_argument(
        "--batch-size", "-b", type=int, default=10000, help="Events per batch (default: 10000)"
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=0,
        help="Number of parallel workers (0=auto, 1=sequential)",
    )
    parser.add_argument(
        "--sequential", "-s", action="store_true", help="Force single-threaded mode"
    )
    parser.add_argument(
        "--no-copy",
        action="store_true",
        help="Don't use COPY for pattern inserts (slower but safer)",
    )
    parser.add_argument(
        "--replace-patterns",
        action="store_true",
        help="Authoritative reprocess: purge each batch's attack_patterns before re-inserting "
        "and NULL attack_types for events that no longer match (implies --reprocess)",
    )
    parser.add_argument(
        "--progress-interval",
        "-p",
        type=int,
        default=50000,
        help="Log progress every N events (default: 50000)",
    )

    args = parser.parse_args()

    config = BackfillConfig(
        batch_size=args.batch_size,
        workers=1 if args.sequential else args.workers,
        reprocess_all=args.reprocess or args.replace_patterns,  # replace implies reprocess
        dry_run=args.dry_run,
        limit=args.limit,
        progress_interval=args.progress_interval,
        use_copy=not args.no_copy,
        replace_patterns=args.replace_patterns,
    )

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        logger.info("\nInterrupted - finishing current batch...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        backfill(config)
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error("Fatal error: %s", e)
        raise


if __name__ == "__main__":
    main()
