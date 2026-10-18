#!/usr/bin/env python3
"""
db_optimize.py — Database Optimization and Index Management
============================================================
Creates optimized indexes, analyzes query performance, and tunes PostgreSQL.

Usage:
    python db_optimize.py                    # Create all optimized indexes
    python db_optimize.py --check            # Check index usage and health
    python db_optimize.py --reindex          # Reindex all tables
    python db_optimize.py --bloat            # Check for index/table bloat
    python db_optimize.py --slow-queries     # Show slow query analysis
    python db_optimize.py --missing-indexes  # Suggest missing indexes

Requires: psycopg2
"""

from __future__ import annotations

import argparse
import logging
from datetime import UTC, datetime

from psycopg2 import sql
from psycopg2.extras import RealDictCursor

from honeylens.database import legacy_get_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("db_optimize")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def get_conn():
    """Get database connection."""
    return legacy_get_db()


# ---------------------------------------------------------------------------
# Optimized Index Definitions
# ---------------------------------------------------------------------------

OPTIMIZED_INDEXES = [
    # ==========================================================================
    # sensor_events - Main event table
    # ==========================================================================
    # Composite index for dashboard queries (most common)
    {
        "name": "idx_se_dash_recent",
        "table": "sensor_events",
        "columns": "timestamp DESC, source, attack_types",
        "where": "timestamp >= NOW() - INTERVAL '7 days'",
        "comment": "Dashboard recent events query",
    },
    # Partial index for last 24 hours (hot data)
    {
        "name": "idx_se_24h",
        "table": "sensor_events",
        "columns": "timestamp DESC",
        "where": "timestamp >= NOW() - INTERVAL '24 hours'",
        "comment": "Last 24 hours - most queried range",
    },
    # Composite index for IP + time lookups
    {
        "name": "idx_se_ip_time",
        "table": "sensor_events",
        "columns": "src_ip, timestamp DESC",
        "comment": "IP investigation queries",
    },
    # Index for honeypot filtering
    {
        "name": "idx_se_honeypot_time",
        "table": "sensor_events",
        "columns": "source, timestamp DESC",
        "where": "source ILIKE '%honeypot%'",
        "comment": "Honeypot-specific queries",
    },
    # Index for attack type filtering
    {
        "name": "idx_se_attack_time",
        "table": "sensor_events",
        "columns": "attack_types, timestamp DESC",
        "where": "attack_types IS NOT NULL",
        "comment": "Attack filtering - only events with attacks",
    },
    # Index for protocol + port analysis
    {
        "name": "idx_se_proto_port",
        "table": "sensor_events",
        "columns": "protocol, dst_port, timestamp DESC",
        "comment": "Protocol/port analysis",
    },
    # ==========================================================================
    # attack_patterns - Attack detail table
    # ==========================================================================
    # Composite for attack type + time
    {
        "name": "idx_ap_type_time",
        "table": "attack_patterns",
        "columns": "attack_type, created_at DESC",
        "comment": "Attack type queries with time ordering",
    },
    # ==========================================================================
    # ja4_fingerprints - TLS fingerprint table
    # ==========================================================================
    # Composite for fingerprint lookups
    {
        "name": "idx_ja4_fp_time",
        "table": "ja4_fingerprints",
        "columns": "fingerprint, created_at DESC",
        "comment": "Fingerprint lookup with time",
    },
    # Index for SNI analysis
    {
        "name": "idx_ja4_sni",
        "table": "ja4_fingerprints",
        "columns": "sni, created_at DESC",
        "where": "sni IS NOT NULL",
        "comment": "SNI-based queries",
    },
    # ==========================================================================
    # mitm_events - MiTM detection table
    # ==========================================================================
    # Unacknowledged events (alert queue)
    {
        "name": "idx_mitm_unacked_sev",
        "table": "mitm_events",
        "columns": "severity, timestamp DESC",
        "where": "acknowledged = FALSE",
        "comment": "Unacknowledged alerts by severity",
    },
    # ==========================================================================
    # ics_events - ICS/OT event table
    # ==========================================================================
    # Protocol + MITRE technique
    {
        "name": "idx_ics_proto_mitre",
        "table": "ics_events",
        "columns": "protocol, mitre_technique, timestamp DESC",
        "comment": "ICS protocol + MITRE mapping",
    },
    # Critical operations (writes/controls)
    {
        "name": "idx_ics_critical",
        "table": "ics_events",
        "columns": "timestamp DESC",
        "where": "is_write = TRUE OR is_control = TRUE",
        "comment": "Critical ICS operations",
    },
]


# ---------------------------------------------------------------------------
# Index Operations
# ---------------------------------------------------------------------------


def create_optimized_indexes(dry_run: bool = False) -> dict[str, bool]:
    """Create all optimized indexes."""
    # Create connection with autocommit for CONCURRENTLY indexes
    conn = legacy_get_db()
    conn.set_session(autocommit=True)
    cur = conn.cursor()

    results = {}

    for idx in OPTIMIZED_INDEXES:
        name = idx["name"]
        table = idx["table"]
        columns = idx["columns"]
        where = idx.get("where")
        comment = idx.get("comment", "")

        # Check if index already exists
        cur.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM pg_indexes
                WHERE indexname = %s
            )
        """,
            (name,),
        )

        if cur.fetchone()[0]:
            logger.info("Index %s already exists, skipping", name)
            results[name] = True
            continue

        # Check if table exists
        cur.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_name = %s
            )
        """,
            (table,),
        )

        if not cur.fetchone()[0]:
            logger.warning("Table %s does not exist, skipping index %s", table, name)
            results[name] = False
            continue

        # Build CREATE INDEX statement
        create_stmt = sql.SQL("CREATE INDEX CONCURRENTLY IF NOT EXISTS {} ON {} ({})").format(
            sql.Identifier(name),
            sql.Identifier(table),
            sql.SQL(columns),
        )
        if where:
            create_stmt = sql.SQL("{} WHERE {}").format(create_stmt, sql.SQL(where))

        stmt_str = create_stmt.as_string(cur.connection)
        logger.info("Creating index: %s", name)
        logger.info("  Comment: %s", comment)
        logger.info("  SQL: %s", stmt_str[:100] + "..." if len(stmt_str) > 100 else stmt_str)

        if dry_run:
            logger.info("  [DRY RUN] Would create index")
            results[name] = True
            continue

        try:
            cur.execute(create_stmt)

            # Add comment
            if comment:
                cur.execute(
                    sql.SQL("COMMENT ON INDEX {} IS %s").format(sql.Identifier(name)), (comment,)
                )

            logger.info("  ✓ Created successfully")
            results[name] = True

        except Exception as e:
            logger.error("  ✗ Failed: %s", e)
            results[name] = False

    conn.close()
    return results


def check_index_usage() -> list[dict]:
    """Check index usage statistics."""
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT
            schemaname,
            relname as table_name,
            indexrelname as index_name,
            idx_scan as scans,
            idx_tup_read as tuples_read,
            idx_tup_fetch as tuples_fetched,
            pg_size_pretty(pg_relation_size(indexrelid)) as index_size
        FROM pg_stat_user_indexes
        WHERE schemaname = 'public'
        ORDER BY idx_scan DESC
    """)

    results = [dict(row) for row in cur.fetchall()]
    conn.close()
    return results


def check_unused_indexes() -> list[dict]:
    """Find indexes that are never or rarely used."""
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT
            schemaname,
            relname as table_name,
            indexrelname as index_name,
            idx_scan as scans,
            pg_size_pretty(pg_relation_size(indexrelid)) as index_size,
            pg_relation_size(indexrelid) as size_bytes
        FROM pg_stat_user_indexes
        WHERE schemaname = 'public'
          AND idx_scan < 10
          AND indexrelname NOT LIKE '%_pkey'
          AND indexrelname NOT LIKE '%_key'
        ORDER BY pg_relation_size(indexrelid) DESC
    """)

    results = [dict(row) for row in cur.fetchall()]
    conn.close()
    return results


def check_table_bloat() -> list[dict]:
    """Check for table and index bloat."""
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # This query estimates bloat based on dead tuples
    cur.execute("""
        SELECT
            schemaname,
            relname as table_name,
            n_live_tup as live_tuples,
            n_dead_tup as dead_tuples,
            CASE WHEN n_live_tup > 0
                THEN round(100.0 * n_dead_tup / n_live_tup, 2)
                ELSE 0
            END as dead_ratio_pct,
            pg_size_pretty(pg_total_relation_size(relid)) as total_size,
            last_vacuum,
            last_autovacuum,
            last_analyze
        FROM pg_stat_user_tables
        WHERE schemaname = 'public'
        ORDER BY n_dead_tup DESC
    """)

    results = [dict(row) for row in cur.fetchall()]
    conn.close()
    return results


def check_index_health() -> dict:
    """Check overall index health metrics."""
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Index hit ratio
    cur.execute("""
        SELECT
            sum(idx_blks_hit) as hits,
            sum(idx_blks_read) as reads,
            CASE WHEN sum(idx_blks_hit) + sum(idx_blks_read) > 0
                THEN round(100.0 * sum(idx_blks_hit) / (sum(idx_blks_hit) + sum(idx_blks_read)), 2)
                ELSE 0
            END as hit_ratio
        FROM pg_statio_user_indexes
    """)
    index_stats = dict(cur.fetchone())

    # Table hit ratio
    cur.execute("""
        SELECT
            sum(heap_blks_hit) as hits,
            sum(heap_blks_read) as reads,
            CASE WHEN sum(heap_blks_hit) + sum(heap_blks_read) > 0
                THEN round(100.0 * sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read)), 2)
                ELSE 0
            END as hit_ratio
        FROM pg_statio_user_tables
    """)
    table_stats = dict(cur.fetchone())

    # Total index size
    cur.execute("""
        SELECT pg_size_pretty(sum(pg_relation_size(indexrelid))) as total_index_size
        FROM pg_stat_user_indexes
        WHERE schemaname = 'public'
    """)
    size_stats = dict(cur.fetchone())

    conn.close()

    return {
        "index_hit_ratio": index_stats["hit_ratio"],
        "table_hit_ratio": table_stats["hit_ratio"],
        "total_index_size": size_stats["total_index_size"],
        "recommendation": "Good"
        if float(index_stats["hit_ratio"] or 0) > 99
        else "Consider adding indexes or increasing shared_buffers",
    }


def suggest_missing_indexes() -> list[dict]:
    """Suggest potentially missing indexes based on query patterns."""
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Check for sequential scans on large tables
    cur.execute("""
        SELECT
            schemaname,
            relname as table_name,
            seq_scan as sequential_scans,
            seq_tup_read as seq_tuples_read,
            idx_scan as index_scans,
            n_live_tup as live_tuples,
            CASE WHEN seq_scan > 0 AND idx_scan > 0
                THEN round(100.0 * seq_scan / (seq_scan + idx_scan), 2)
                ELSE 100
            END as seq_scan_ratio
        FROM pg_stat_user_tables
        WHERE schemaname = 'public'
          AND n_live_tup > 10000
          AND seq_scan > idx_scan
        ORDER BY seq_tup_read DESC
        LIMIT 10
    """)

    results = [dict(row) for row in cur.fetchall()]
    conn.close()
    return results


def reindex_tables(tables: list[str] | None = None):
    """Reindex specified tables or all main tables."""
    if tables is None:
        tables = [
            "sensor_events",
            "attack_patterns",
            "ja4_fingerprints",
            "mitm_events",
            "mitm_arp_cache",
            "ics_events",
            "ics_baselines",
            "users",
            "admin_audit_log",
        ]

    conn = get_conn()
    conn.autocommit = True
    cur = conn.cursor()

    for table in tables:
        # Check if table exists
        cur.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_name = %s
            )
        """,
            (table,),
        )

        if not cur.fetchone()[0]:
            logger.warning("Table %s does not exist, skipping", table)
            continue

        try:
            logger.info("Reindexing %s...", table)
            start = datetime.now(UTC)
            cur.execute(sql.SQL("REINDEX TABLE {}").format(sql.Identifier(table)))
            elapsed = (datetime.now(UTC) - start).total_seconds()
            logger.info("  ✓ Completed in %.2f seconds", elapsed)
        except Exception as e:
            logger.error("  ✗ Failed: %s", e)

    conn.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Database optimization and index management")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be done without making changes"
    )
    parser.add_argument("--check", action="store_true", help="Check index usage and health")
    parser.add_argument("--reindex", action="store_true", help="Reindex all main tables")
    parser.add_argument("--bloat", action="store_true", help="Check for table/index bloat")
    parser.add_argument("--unused", action="store_true", help="Show unused indexes")
    parser.add_argument(
        "--missing-indexes", action="store_true", help="Suggest potentially missing indexes"
    )

    args = parser.parse_args()

    # Check mode
    if args.check:
        print("\n=== Index Health ===")
        health = check_index_health()
        print(f"Index hit ratio: {health['index_hit_ratio']}%")
        print(f"Table hit ratio: {health['table_hit_ratio']}%")
        print(f"Total index size: {health['total_index_size']}")
        print(f"Recommendation: {health['recommendation']}")

        print("\n=== Index Usage (Top 20) ===")
        usage = check_index_usage()[:20]
        print(f"{'Index Name':<40} {'Scans':>10} {'Size':>10}")
        print("-" * 62)
        for idx in usage:
            print(f"{idx['index_name']:<40} {idx['scans']:>10} {idx['index_size']:>10}")
        return

    # Bloat check
    if args.bloat:
        print("\n=== Table Bloat Analysis ===")
        bloat = check_table_bloat()
        print(f"{'Table':<30} {'Live':>12} {'Dead':>12} {'Dead %':>8} {'Size':>12}")
        print("-" * 78)
        for t in bloat:
            print(
                f"{t['table_name']:<30} {t['live_tuples']:>12,} {t['dead_tuples']:>12,} {t['dead_ratio_pct']:>7}% {t['total_size']:>12}"
            )
        return

    # Unused indexes
    if args.unused:
        print("\n=== Unused Indexes (< 10 scans) ===")
        unused = check_unused_indexes()
        if unused:
            print(f"{'Index Name':<50} {'Scans':>8} {'Size':>12}")
            print("-" * 72)
            for idx in unused:
                print(f"{idx['index_name']:<50} {idx['scans']:>8} {idx['index_size']:>12}")
            print("\nConsider dropping these indexes to save space")
        else:
            print("No unused indexes found")
        return

    # Missing indexes
    if args.missing_indexes:
        print("\n=== Tables with High Sequential Scan Ratio ===")
        missing = suggest_missing_indexes()
        if missing:
            print(f"{'Table':<30} {'Seq Scans':>12} {'Idx Scans':>12} {'Seq %':>8} {'Rows':>12}")
            print("-" * 78)
            for t in missing:
                print(
                    f"{t['table_name']:<30} {t['sequential_scans']:>12,} {t['index_scans']:>12,} {t['seq_scan_ratio']:>7}% {t['live_tuples']:>12,}"
                )
            print("\nThese tables may benefit from additional indexes")
        else:
            print("No tables with concerning sequential scan ratios found")
        return

    # Reindex
    if args.reindex:
        print("\n=== Reindexing Tables ===")
        reindex_tables()
        return

    # Default: Create optimized indexes
    print("\n=== Creating Optimized Indexes ===")
    print(f"Dry run: {args.dry_run}")
    print()

    results = create_optimized_indexes(dry_run=args.dry_run)

    print("\n=== Results ===")
    success = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    print(f"Created/verified: {success}")
    print(f"Failed: {failed}")

    if failed > 0:
        print("\nFailed indexes:")
        for name, ok in results.items():
            if not ok:
                print(f"  - {name}")


if __name__ == "__main__":
    main()
