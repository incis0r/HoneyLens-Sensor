#!/usr/bin/env python3
"""
backfill_fingerprints.py — Extract fingerprints from historical events (Idea 28)
=================================================================================
Processes existing sensor_events to extract fingerprints into the
attacker_fingerprints table. Run once after deploying Idea 28, then
real-time extraction takes over via ingest.py.

Usage:
    python backfill_fingerprints.py                # Process all
    python backfill_fingerprints.py --limit 10000  # Process N events
    python backfill_fingerprints.py --ip 1.2.3.4   # Process one IP

Compatible with Python 3.9+.
"""

from __future__ import annotations

import json
import logging
import sys
import time

from honeylens.database import legacy_get_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("backfill_fp")


def main():
    from honeylens.classification.fingerprint_extractor import (
        extract_all_fingerprints,
        store_fingerprints,
    )

    limit = 100000
    ip_filter = None

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--limit" and i < len(sys.argv) - 1:
            limit = int(sys.argv[i + 1])
        elif arg == "--ip" and i < len(sys.argv) - 1:
            ip_filter = sys.argv[i + 1]

    conn = legacy_get_db()
    conn.autocommit = True
    cur = conn.cursor()

    # Check table exists
    cur.execute("""
        SELECT EXISTS (SELECT 1 FROM information_schema.tables
                       WHERE table_name = 'attacker_fingerprints')
    """)
    if not cur.fetchone()[0]:
        print("ERROR: attacker_fingerprints table not found. Run setup_db.py first.")
        sys.exit(1)

    # Build query
    where = ""
    params: list = []
    if ip_filter:
        where = "WHERE src_ip = %s::inet"
        params = [ip_filter]

    logger.info("Querying events (limit=%d)...", limit)
    cur.execute(
        f"""
        SELECT event_id, host(src_ip) AS src_ip, protocol, payload, ja3, metadata
        FROM sensor_events
        {where}
        ORDER BY timestamp DESC
        LIMIT %s
    """,  # nosec B608 — fixed columns, {where} from constant fragments, values as parameters
        [*params, limit],
    )

    rows = cur.fetchall()
    logger.info("Processing %d events...", len(rows))

    t0 = time.time()
    total_fps = 0
    processed = 0
    ips_seen: set = set()

    for _event_id, src_ip, protocol, payload, ja3, metadata in rows:
        if not src_ip:
            continue

        meta = {}
        if metadata:
            if isinstance(metadata, str):
                try:
                    meta = json.loads(metadata)
                except Exception as _exc:  # silent: best effort JSON parse, skip malformed metadata
                    logging.getLogger(__name__).debug("ignored: %s", _exc)
            elif isinstance(metadata, dict):
                meta = metadata

        fps = extract_all_fingerprints(
            payload=payload,
            protocol=protocol,
            metadata=meta,
            ja4=ja3,  # ja3 column may contain JA4+ data
        )

        if fps:
            stored = store_fingerprints(conn, src_ip, fps)
            total_fps += stored
            ips_seen.add(src_ip)

        processed += 1
        if processed % 5000 == 0:
            elapsed = time.time() - t0
            rate = processed / max(elapsed, 0.1)
            logger.info(
                "  %d/%d events, %d fingerprints, %d IPs (%.0f/s)",
                processed,
                len(rows),
                total_fps,
                len(ips_seen),
                rate,
            )

    elapsed = time.time() - t0
    conn.close()

    logger.info(
        "Done: %d events → %d fingerprints for %d IPs (%.1fs)",
        processed,
        total_fps,
        len(ips_seen),
        elapsed,
    )


if __name__ == "__main__":
    main()
