#!/usr/bin/env python3
"""
backfill_k8s_patterns.py
========================
Backfills attack_patterns rows for K8s honeypot events that were ingested
BEFORE the pre-classified trust fix landed in ingest_honeypot.py.

These events already exist in sensor_events (via ON CONFLICT DO NOTHING they
were silently skipped on re-ingest), but they have no corresponding rows in
attack_patterns because the classifier ran before the new rules were deployed.

What it does:
  1. Finds all sensor_events rows where source='honeypot_k8s' (or protocol='https'
     on K8s ports) that have no attack_patterns rows yet.
  2. For each, loads the metadata JSON, extracts the honeypot-set attack_type +
     rule_name, and also runs classify_event_row for additional hits.
  3. Inserts the missing attack_patterns rows (ON CONFLICT DO NOTHING).

Usage:
    python backfill_k8s_patterns.py [--dry-run] [--limit N]

Options:
    --dry-run    Show what would be inserted, don't write to DB
    --limit N    Process at most N events (default: all)
    --since DATE Backfill only events after this timestamp (ISO format)
"""

import argparse
import json
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("backfill_k8s")


# ─── args ────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser()
parser.add_argument("--dry-run", action="store_true")
parser.add_argument("--limit", type=int, default=0)
parser.add_argument("--since", default=None)
args = parser.parse_args()


# ─── db + classifier ──────────────────────────────────────────────────────────

try:
    import psycopg2.extras

    from honeylens.database import legacy_get_db
except ImportError as e:
    sys.exit(f"Import error: {e}")

from honeylens.classification.attack_classifier import (
    classify_event_row,
)

HAS_CLASSIFIER = True


INSERT_SQL = """
    INSERT INTO attack_patterns (event_id, attack_type, rule_name, matched_text)
    VALUES (%s, %s, %s, %s)
    ON CONFLICT DO NOTHING
"""

# ─── find unclassified K8s events ────────────────────────────────────────────

FIND_SQL = """
    SELECT e.event_id, e.payload, e.protocol, e.dst_port, e.metadata
    FROM sensor_events e
    WHERE (
        e.source = 'honeypot_k8s'
        OR e.dst_port IN (6443, 8001, 8080, 10250, 10255, 2379, 2380, 30000)
    )
    AND NOT EXISTS (
        SELECT 1 FROM attack_patterns ap WHERE ap.event_id = e.event_id
    )
    {since_clause}
    ORDER BY e.timestamp DESC
    {limit_clause}
"""

since_clause = f"AND e.timestamp >= '{args.since}'" if args.since else ""
limit_clause = f"LIMIT {args.limit}" if args.limit else ""
query = FIND_SQL.format(since_clause=since_clause, limit_clause=limit_clause)


# ─── main ─────────────────────────────────────────────────────────────────────


def strip_nul(v):
    if isinstance(v, str):
        return v.replace("\x00", "")
    return v


def build_hits(event_id, payload, protocol, dst_port, metadata):
    """Return list of (atype, rule, matched) to insert."""
    hits = []
    seen = set()

    # Trust honeypot pre-classification first
    pre_atype = metadata.get("attack_type") if metadata else None
    pre_rule = metadata.get("rule_name") if metadata else None
    if pre_atype and pre_rule:
        pre_matched = f"{metadata.get('method', '')} {metadata.get('path', '')}".strip() or pre_rule
        hits.append((pre_atype, pre_rule, pre_matched[:500]))
        seen.add((pre_atype, pre_rule))

    # Run classifier for additional hits
    if HAS_CLASSIFIER and payload:
        try:
            for atype, rule, matched in classify_event_row(
                payload=payload, protocol=protocol, metadata=metadata
            ):
                if (atype, rule) not in seen:
                    hits.append((atype, rule, matched[:500]))
                    seen.add((atype, rule))
        except Exception as exc:
            logger.warning("classify failed for %s: %s", event_id, exc)

    return hits


def main():
    conn = legacy_get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    logger.info("Finding unclassified K8s events...")
    cur.execute(query)
    rows = cur.fetchall()
    logger.info("Found %d events without attack_patterns rows", len(rows))

    if not rows:
        logger.info("Nothing to backfill.")
        conn.close()
        return

    total_inserted = 0
    total_events = 0

    write_cur = conn.cursor()

    for row in rows:
        event_id = row["event_id"]
        payload = row["payload"] or ""
        protocol = row["protocol"] or ""
        dst_port = row["dst_port"]

        metadata = {}
        if row["metadata"]:
            try:
                metadata = (
                    json.loads(row["metadata"])
                    if isinstance(row["metadata"], str)
                    else row["metadata"]
                )
            except (json.JSONDecodeError, TypeError):
                pass  # silent: best effort JSON parse, skip malformed metadata

        hits = build_hits(event_id, payload, protocol, dst_port, metadata)
        if not hits:
            continue

        total_events += 1
        for atype, rule, matched in hits:
            if args.dry_run:
                print(f"  DRY  {event_id[:12]}…  {atype}/{rule}  {matched[:60]!r}")
                total_inserted += 1
            else:
                try:
                    write_cur.execute("SAVEPOINT sp_bf")
                    write_cur.execute(
                        INSERT_SQL,
                        (
                            strip_nul(event_id),
                            strip_nul(atype),
                            strip_nul(rule),
                            strip_nul(matched),
                        ),
                    )
                    write_cur.execute("RELEASE SAVEPOINT sp_bf")
                    total_inserted += 1
                except Exception as exc:
                    write_cur.execute("ROLLBACK TO SAVEPOINT sp_bf")
                    write_cur.execute("RELEASE SAVEPOINT sp_bf")
                    logger.warning("Insert failed for %s/%s: %s", event_id, rule, exc)

    if not args.dry_run:
        conn.commit()

    logger.info(
        "%s %d attack_patterns rows across %d events",
        "Would insert" if args.dry_run else "Inserted",
        total_inserted,
        total_events,
    )
    conn.close()


if __name__ == "__main__":
    main()
