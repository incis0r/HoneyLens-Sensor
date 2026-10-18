#!/usr/bin/env python3
"""repair_netscaler_tags.py — regenerate the NetScaler decoy's own detection tags.

One-off repair for the 2026-10-04 incident where the nightly ``--replace-patterns``
backfill deleted the decoys' honeypot-authored ``ns-*`` attack_patterns (it reprocessed
with the central classifier, which does not reproduce them). The events and their stored
request metadata are intact, so this re-runs the decoy's own detection
(:func:`honeylens.honeypots.honeypot_netscaler._behaviours`) over each stored request and
re-inserts the ``ns-<behaviour>`` / CVE rows, then rebuilds the affected summaries.

Idempotent (``ON CONFLICT DO NOTHING``); safe to re-run.

    honeylens-repair-netscaler-tags --dry-run
    honeylens-repair-netscaler-tags [--days N]
"""

from __future__ import annotations

import argparse
import logging

import psycopg2.extras

from honeylens.honeypots.honeypot_netscaler import _behaviours
from honeylens.tools.backfill_attacks import get_connection, put_connection, rebuild_attack_types

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("repair-ns-tags")


def _request_from_meta(meta: dict) -> tuple[str, str, dict, bytes] | None:
    """Reconstruct (method, path_qs, headers, body) the way the decoy saw it, from the
    stored event metadata. Returns None when the metadata is unusable."""
    if not isinstance(meta, dict):
        return None
    method = meta.get("method")
    path = meta.get("path")
    if not method or not path:
        return None
    query = meta.get("query") or ""
    path_qs = f"{path}?{query}" if query else str(path)
    h = meta.get("headers")
    headers: dict = h if isinstance(h, dict) else {}
    body_sample = meta.get("body_sample") or ""
    body = body_sample.encode("utf-8", "replace") if isinstance(body_sample, str) else b""
    return str(method), path_qs, headers, body


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", default="netscaler")
    ap.add_argument("--days", type=int, default=0, help="limit to the last N days (0 = all)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.days:
        sql = (
            "SELECT event_id, metadata FROM sensor_events WHERE source=%s"
            " AND timestamp > now() - (%s || ' days')::interval"
        )
        params: tuple = (args.source, str(args.days))
    else:
        sql = "SELECT event_id, metadata FROM sensor_events WHERE source=%s"
        params = (args.source,)

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        events = cur.fetchall()
    finally:
        put_connection(conn)

    logger.info("scanning %s %s events", len(events), args.source)
    rows: list[tuple] = []
    touched: set[str] = set()
    for event_id, meta in events:
        req = _request_from_meta(meta)
        if not req:
            continue
        for b in _behaviours(*req):
            rows.append(
                (
                    event_id,
                    f"ns-{b['behaviour']}",
                    b["cve"],
                    req[1][:500],  # matched_text: the request path
                    b["severity"].lower(),
                )
            )
            touched.add(event_id)

    logger.info("re-derived %s decoy tags across %s events", len(rows), len(touched))
    if args.dry_run:
        from collections import Counter

        for (at, rn), n in Counter((r[1], r[2]) for r in rows).most_common():
            logger.info("  would insert %s / %s : %s", at, rn, n)
        return 0
    if not rows:
        return 0

    conn = get_connection()
    try:
        cur = conn.cursor()
        psycopg2.extras.execute_batch(
            cur,
            "INSERT INTO attack_patterns (event_id, attack_type, rule_name, matched_text, severity)"
            " VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            rows,
            page_size=1000,
        )
        conn.commit()
    finally:
        put_connection(conn)

    rebuild_attack_types(sorted(touched))
    logger.info("repair complete: %s tags restored, %s summaries rebuilt", len(rows), len(touched))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
