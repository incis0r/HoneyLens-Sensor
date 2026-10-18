#!/usr/bin/env python3
"""
normalize_attack_types.py — One-time migration to fix mixed-case attack types.

Problem: AI-generated rules stored attack_type in lowercase (e.g., 'lfi', 'credential_theft')
while attack_classifier.py uses uppercase (e.g., 'LFI', 'CREDENTIAL').
This caused 400 errors on /attack/type/{type} endpoint and duplicate entries in dashboards.

This script normalises all attack_type/attack_types values to UPPERCASE across all tables.

Usage:
    python normalize_attack_types.py              # dry-run (default)
    python normalize_attack_types.py --apply       # apply changes
    python normalize_attack_types.py --apply --verbose  # apply with row details

Safe to run multiple times — only updates rows where case differs.
"""

import argparse
import sys

try:
    from honeylens.database import legacy_get_db
except ImportError:
    print("ERROR: core.database not available. Run from sensor directory.")
    sys.exit(1)


MIGRATIONS = [
    {
        "table": "attack_patterns",
        "column": "attack_type",
        "description": "Attack classifier pattern entries",
        "count_sql": """
            SELECT COUNT(*) FROM attack_patterns
            WHERE attack_type IS NOT NULL
              AND attack_type != UPPER(attack_type)
        """,
        "preview_sql": """
            SELECT attack_type, UPPER(attack_type) AS fixed, COUNT(*) AS rows_affected
            FROM attack_patterns
            WHERE attack_type IS NOT NULL
              AND attack_type != UPPER(attack_type)
            GROUP BY attack_type
            ORDER BY COUNT(*) DESC
        """,
        "update_sql": """
            UPDATE attack_patterns
            SET attack_type = UPPER(attack_type)
            WHERE attack_type IS NOT NULL
              AND attack_type != UPPER(attack_type)
        """,
    },
    {
        "table": "sensor_events",
        "column": "attack_types",
        "description": "Sensor events summary field (comma-separated)",
        "count_sql": """
            SELECT COUNT(*) FROM sensor_events
            WHERE attack_types IS NOT NULL
              AND attack_types != UPPER(attack_types)
        """,
        "preview_sql": """
            SELECT attack_types, UPPER(attack_types) AS fixed, COUNT(*) AS rows_affected
            FROM sensor_events
            WHERE attack_types IS NOT NULL
              AND attack_types != UPPER(attack_types)
            GROUP BY attack_types
            ORDER BY COUNT(*) DESC
        """,
        "update_sql": """
            UPDATE sensor_events
            SET attack_types = UPPER(attack_types)
            WHERE attack_types IS NOT NULL
              AND attack_types != UPPER(attack_types)
        """,
    },
    {
        "table": "ai_custom_rules",
        "column": "attack_type",
        "description": "AI-approved custom detection rules",
        "count_sql": """
            SELECT COUNT(*) FROM ai_custom_rules
            WHERE attack_type IS NOT NULL
              AND attack_type != UPPER(attack_type)
        """,
        "preview_sql": """
            SELECT rule_name, attack_type, UPPER(attack_type) AS fixed
            FROM ai_custom_rules
            WHERE attack_type IS NOT NULL
              AND attack_type != UPPER(attack_type)
        """,
        "update_sql": """
            UPDATE ai_custom_rules
            SET attack_type = UPPER(attack_type)
            WHERE attack_type IS NOT NULL
              AND attack_type != UPPER(attack_type)
        """,
    },
    {
        "table": "mitm_events",
        "column": "attack_type",
        "description": "MiTM proxy events",
        "count_sql": """
            SELECT COUNT(*) FROM mitm_events
            WHERE attack_type IS NOT NULL
              AND attack_type != UPPER(attack_type)
        """,
        "preview_sql": """
            SELECT attack_type, UPPER(attack_type) AS fixed, COUNT(*) AS rows_affected
            FROM mitm_events
            WHERE attack_type IS NOT NULL
              AND attack_type != UPPER(attack_type)
            GROUP BY attack_type
            ORDER BY COUNT(*) DESC
        """,
        "update_sql": """
            UPDATE mitm_events
            SET attack_type = UPPER(attack_type)
            WHERE attack_type IS NOT NULL
              AND attack_type != UPPER(attack_type)
        """,
    },
]


def table_exists(cur, table_name):
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_name = %s
        )
    """,
        (table_name,),
    )
    return cur.fetchone()[0]


def column_exists(cur, table_name, column_name):
    cur.execute(
        """
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = %s AND column_name = %s
        )
    """,
        (table_name, column_name),
    )
    return cur.fetchone()[0]


def main():
    parser = argparse.ArgumentParser(description="Normalize attack types to UPPERCASE")
    parser.add_argument("--apply", action="store_true", help="Apply changes (default: dry-run)")
    parser.add_argument("--verbose", action="store_true", help="Show individual row changes")
    args = parser.parse_args()

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"{'=' * 60}")
    print(f"  Attack Type Case Normalization — {mode}")
    print(f"{'=' * 60}\n")

    conn = legacy_get_db()
    cur = conn.cursor()

    total_affected = 0

    for mig in MIGRATIONS:
        tbl = mig["table"]
        col = mig["column"]

        # Check table/column exist
        if not table_exists(cur, tbl):
            print(f"  [{tbl}.{col}] — table does not exist, skipping")
            continue
        if not column_exists(cur, tbl, col):
            print(f"  [{tbl}.{col}] — column does not exist, skipping")
            continue

        # Count affected rows
        cur.execute(mig["count_sql"])
        count = cur.fetchone()[0]

        if count == 0:
            print(f"  [{tbl}.{col}] — already clean (0 rows need fixing)")
            continue

        print(f"  [{tbl}.{col}] — {count} rows need normalization")
        print(f"    {mig['description']}")

        # Show preview
        if args.verbose:
            cur.execute(mig["preview_sql"])
            for row in cur.fetchall():
                print(f"    {row}")

        # Apply or skip
        if args.apply:
            cur.execute(mig["update_sql"])
            updated = cur.rowcount
            print(f"    ✓ Updated {updated} rows")
            total_affected += updated
        else:
            total_affected += count
            print(f"    → Would update {count} rows (use --apply to execute)")

        print()

    if args.apply:
        conn.commit()
        print(f"{'=' * 60}")
        print(f"  DONE — {total_affected} rows normalized to UPPERCASE")
        print(f"{'=' * 60}")
    else:
        conn.rollback()
        print(f"{'=' * 60}")
        print(f"  DRY-RUN COMPLETE — {total_affected} rows would be updated")
        print("  Run with --apply to execute changes")
        print(f"{'=' * 60}")

    conn.close()


if __name__ == "__main__":
    main()
