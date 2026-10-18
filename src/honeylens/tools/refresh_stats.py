#!/usr/bin/env python3
"""refresh_stats.py — refresh the dashboard KPI materialised view.

The main dashboard's top strip (Total events / 24h / 1h / 5m / unique IPs) reads
``mv_event_stats`` so it never runs COUNT(*) over the full sensor_events table. That view
is a snapshot: it must be refreshed on a schedule or it stays frozen at the values it had
when it was created (which is why the KPIs read zero on a fresh install — the cron line in
the base migration was only ever a comment). This entry point does the refresh; the
``honeylens-refresh-stats.timer`` runs it every 5 minutes.

    honeylens-refresh-stats
"""

from __future__ import annotations

import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("refresh-stats")


def main() -> int:
    from honeylens.database import legacy_get_db

    conn = legacy_get_db()
    conn.autocommit = True  # REFRESH cannot run inside a transaction block
    cur = conn.cursor()
    try:
        # CONCURRENTLY keeps the view readable during refresh; it needs the unique index
        # the migration creates and a prior non-concurrent populate (both hold here).
        try:
            cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY mv_event_stats")
        except Exception as exc:
            logger.warning("concurrent refresh failed (%s); retrying non-concurrent", exc)
            cur.execute("REFRESH MATERIALIZED VIEW mv_event_stats")
        cur.execute("SELECT total_events, recent_5m, refreshed_at FROM mv_event_stats")
        row = cur.fetchone()
        if row:
            logger.info("mv_event_stats refreshed: total=%s recent_5m=%s at=%s", *row)
        return 0
    except Exception as exc:
        logger.error("refresh failed: %s", exc)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
