#!/usr/bin/env python3
"""Verify pooled leases against PostgreSQL without modifying production tables."""

from concurrent.futures import ThreadPoolExecutor

import psycopg2

from honeylens import database as db
from honeylens.config import DB_CONFIG


def main():
    db.init_pool(minconn=1, maxconn=8)
    observer = psycopg2.connect(**DB_CONFIG)
    observer.autocommit = True
    try:
        first = db.legacy_get_db()
        with first.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(714029, 77)")
            cur.execute("CREATE TEMP TABLE pool_check (n integer)")
            cur.execute("SET application_name='honeylens-pool-check'")
        first.commit()
        first.close()
        second = db.legacy_get_db()
        first.close()  # stale scope cleanup must not release this new lease
        with second.cursor() as cur:
            cur.execute(
                "SELECT to_regclass('pg_temp.pool_check'), current_setting('application_name')"
            )
            name, app = cur.fetchone()
            assert name is None and app != "honeylens-pool-check"
        with observer.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(714029, 77)")
            assert cur.fetchone()[0], "lease return leaked the advisory lock"
            cur.execute("SELECT pg_advisory_unlock(714029, 77)")
        second.close()

        # More operations than maxconn exposes legacy close() slot leaks.
        def exercise(_):
            pids = set()
            for _ in range(20):
                conn = db.legacy_get_db()
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT pg_backend_pid(), 1")
                        pid, value = cur.fetchone()
                        assert value == 1
                        pids.add(pid)
                finally:
                    conn.close()
            return pids

        with ThreadPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(exercise, range(6)))
        assert all(results)
        print(
            "PASS: 120 concurrent checkouts, legacy close, stale lease, session reset, advisory unlock"
        )
    finally:
        observer.close()
        db.close_pool()


if __name__ == "__main__":
    main()
