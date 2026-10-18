#!/usr/bin/env python3
"""
cleanup_high_ports.py - Remove events with dst_port > 30000
=============================================================
⚠️  LAB TESTING ONLY - DO NOT RUN ON PRODUCTION ⚠️

This script removes sensor events where the destination port is above
a threshold (default 30000). These are typically ephemeral ports used
for outbound connections from the sensor itself.

Usage:
    python cleanup_high_ports.py                    # Dry run (default)
    python cleanup_high_ports.py --execute          # Actually delete
    python cleanup_high_ports.py --port 40000       # Custom threshold
    python cleanup_high_ports.py --execute --batch 5000  # Custom batch size

Safety features:
    - Dry run by default (must use --execute to delete)
    - Shows count before deleting
    - Deletes in batches to avoid long locks
    - Handles related tables (attack_patterns, ja4_fingerprints, ics_events)
"""

import argparse
import logging
import time

import psycopg2

from honeylens.database import legacy_get_db

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
)
logger = logging.getLogger("cleanup_high_ports")


def get_connection():
    return legacy_get_db()


def get_event_count(port_threshold: int) -> dict:
    """Count events that would be deleted."""
    conn = get_connection()
    cur = conn.cursor()

    counts = {}

    # Main events
    cur.execute(
        """
        SELECT COUNT(*) FROM sensor_events
        WHERE dst_port > %s
    """,
        (port_threshold,),
    )
    counts["sensor_events"] = cur.fetchone()[0]

    # Attack patterns (via FK)
    cur.execute(
        """
        SELECT COUNT(*) FROM attack_patterns ap
        JOIN sensor_events se ON ap.event_id = se.event_id
        WHERE se.dst_port > %s
    """,
        (port_threshold,),
    )
    counts["attack_patterns"] = cur.fetchone()[0]

    # JA4 fingerprints (via FK)
    try:
        cur.execute(
            """
            SELECT COUNT(*) FROM ja4_fingerprints jf
            JOIN sensor_events se ON jf.event_id = se.event_id
            WHERE se.dst_port > %s
        """,
            (port_threshold,),
        )
        counts["ja4_fingerprints"] = cur.fetchone()[0]
    except psycopg2.errors.UndefinedTable:
        conn.rollback()
        counts["ja4_fingerprints"] = 0

    # ICS events (via FK)
    try:
        cur.execute(
            """
            SELECT COUNT(*) FROM ics_events ie
            JOIN sensor_events se ON ie.event_id = se.event_id
            WHERE se.dst_port > %s
        """,
            (port_threshold,),
        )
        counts["ics_events"] = cur.fetchone()[0]
    except psycopg2.errors.UndefinedTable:
        conn.rollback()
        counts["ics_events"] = 0

    # Sample of what would be deleted
    cur.execute(
        """
        SELECT event_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol
        FROM sensor_events
        WHERE dst_port > %s
        ORDER BY timestamp DESC
        LIMIT 10
    """,
        (port_threshold,),
    )
    counts["samples"] = cur.fetchall()

    # Port distribution
    cur.execute(
        """
        SELECT dst_port, COUNT(*) as cnt
        FROM sensor_events
        WHERE dst_port > %s
        GROUP BY dst_port
        ORDER BY cnt DESC
        LIMIT 20
    """,
        (port_threshold,),
    )
    counts["port_distribution"] = cur.fetchall()

    conn.close()
    return counts


def delete_events(port_threshold: int, batch_size: int = 1000) -> dict:
    """Delete events with dst_port > threshold."""
    conn = get_connection()
    cur = conn.cursor()

    results = {
        "attack_patterns": 0,
        "ja4_fingerprints": 0,
        "ics_events": 0,
        "sensor_events": 0,
    }

    start_time = time.time()

    # Step 1: Get event IDs to delete
    logger.info("Finding event IDs to delete...")
    cur.execute(
        """
        SELECT event_id FROM sensor_events
        WHERE dst_port > %s
    """,
        (port_threshold,),
    )
    event_ids = [row[0] for row in cur.fetchall()]

    total_events = len(event_ids)
    if total_events == 0:
        logger.info("No events found to delete")
        conn.close()
        return results

    logger.info("Found %s events to delete", total_events)

    # Step 2: Delete from related tables first (FK constraints)
    # Delete in batches to avoid long transactions

    for i in range(0, len(event_ids), batch_size):
        batch = event_ids[i : i + batch_size]
        batch_num = i // batch_size + 1
        total_batches = (len(event_ids) + batch_size - 1) // batch_size

        logger.info("Processing batch %s/%s (%s events)", batch_num, total_batches, len(batch))

        # Attack patterns
        try:
            cur.execute(
                """
                DELETE FROM attack_patterns
                WHERE event_id = ANY(%s)
            """,
                (batch,),
            )
            results["attack_patterns"] += cur.rowcount
        except psycopg2.errors.UndefinedTable:
            conn.rollback()

        # JA4 fingerprints
        try:
            cur.execute(
                """
                DELETE FROM ja4_fingerprints
                WHERE event_id = ANY(%s)
            """,
                (batch,),
            )
            results["ja4_fingerprints"] += cur.rowcount
        except psycopg2.errors.UndefinedTable:
            conn.rollback()

        # ICS events
        try:
            cur.execute(
                """
                DELETE FROM ics_events
                WHERE event_id = ANY(%s)
            """,
                (batch,),
            )
            results["ics_events"] += cur.rowcount
        except psycopg2.errors.UndefinedTable:
            conn.rollback()

        # Main events
        cur.execute(
            """
            DELETE FROM sensor_events
            WHERE event_id = ANY(%s)
        """,
            (batch,),
        )
        results["sensor_events"] += cur.rowcount

        conn.commit()

        # Progress
        progress = min(i + batch_size, total_events)
        pct = 100 * progress / total_events
        elapsed = time.time() - start_time
        rate = progress / elapsed if elapsed > 0 else 0
        eta = (total_events - progress) / rate if rate > 0 else 0

        logger.info(
            "  Progress: %s/%s (%s%%) - %s/sec - ETA: %ss",
            f"{progress:,}",
            f"{total_events:,}",
            f"{pct:.1f}",
            f"{rate:.0f}",
            f"{eta:.0f}",
        )

    conn.close()

    elapsed = time.time() - start_time
    logger.info("Deletion completed in %ss", elapsed)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Remove events with high destination ports (lab testing only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️  WARNING: This script PERMANENTLY DELETES data!

    Always run without --execute first to see what would be deleted.

Examples:
    python cleanup_high_ports.py                    # Dry run
    python cleanup_high_ports.py --port 40000       # Check ports > 40000
    python cleanup_high_ports.py --execute          # Actually delete
        """,
    )

    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=30000,
        help="Port threshold - delete events with dst_port > this value (default: 30000)",
    )

    parser.add_argument(
        "--execute",
        "-x",
        action="store_true",
        help="Actually execute the deletion (default is dry run)",
    )

    parser.add_argument(
        "--batch", "-b", type=int, default=1000, help="Batch size for deletion (default: 1000)"
    )

    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    args = parser.parse_args()

    print("=" * 70)
    print("  CLEANUP HIGH PORT EVENTS")
    print("  ⚠️  LAB TESTING ONLY - DO NOT RUN ON PRODUCTION ⚠️")
    print("=" * 70)
    print()

    # Get counts
    logger.info("Checking events with dst_port > %s...", args.port)
    counts = get_event_count(args.port)

    print()
    print("Records that would be deleted:")
    print("-" * 40)
    print(f"  sensor_events:    {counts['sensor_events']:>10,}")
    print(f"  attack_patterns:  {counts['attack_patterns']:>10,}")
    print(f"  ja4_fingerprints: {counts['ja4_fingerprints']:>10,}")
    print(f"  ics_events:       {counts['ics_events']:>10,}")
    print("-" * 40)
    total = counts["sensor_events"]
    print(f"  TOTAL EVENTS:     {total:>10,}")
    print()

    if counts["port_distribution"]:
        print("Top destination ports:")
        print("-" * 40)
        for port, cnt in counts["port_distribution"][:10]:
            print(f"  Port {port:>5}: {cnt:>8,} events")
        print()

    if counts["samples"]:
        print("Sample events (most recent):")
        print("-" * 70)
        for row in counts["samples"][:5]:
            _event_id, ts, src_ip, dst_ip, src_port, dst_port, proto = row
            print(f"  {ts} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {proto}")
        print()

    if total == 0:
        logger.info("No events to delete. Exiting.")
        return

    if not args.execute:
        print("=" * 70)
        print("  DRY RUN - No data was deleted")
        print("  Use --execute to actually delete these records")
        print("=" * 70)
        return

    # Confirmation
    if not args.yes:
        print("=" * 70)
        print(f"  ⚠️  WARNING: About to DELETE {total:,} events!")
        print("  This action is PERMANENT and cannot be undone!")
        print("=" * 70)
        print()

        confirm = input("Type 'DELETE' to confirm: ")
        if confirm != "DELETE":
            logger.info("Deletion cancelled")
            return

    print()
    logger.info("Starting deletion...")

    results = delete_events(args.port, args.batch)

    print()
    print("=" * 70)
    print("  DELETION COMPLETE")
    print("=" * 70)
    print()
    print("Records deleted:")
    print("-" * 40)
    print(f"  sensor_events:    {results['sensor_events']:>10,}")
    print(f"  attack_patterns:  {results['attack_patterns']:>10,}")
    print(f"  ja4_fingerprints: {results['ja4_fingerprints']:>10,}")
    print(f"  ics_events:       {results['ics_events']:>10,}")
    print("-" * 40)
    print()

    # Suggest vacuum
    print("Recommended: Run VACUUM to reclaim disk space:")
    print("  python db_archive.py --vacuum")
    print()


if __name__ == "__main__":
    main()
