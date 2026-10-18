#!/usr/bin/env python3
"""Exercise hunting SQL using session-local PostgreSQL tables, never production rows.

Run with the sensor's environment and installed package. Closing the connection drops
all fixtures. No OSINT or AI requests are made.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import psycopg2

from honeylens.analysis import attacker_profiler, hunt_queue
from honeylens.config import DB_CONFIG
from honeylens.db.migrate import MIGRATIONS_DIR, split_statements


def main():
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = '10s'")
            cur.execute(
                "CREATE TEMP TABLE attacker_profiles (LIKE public.attacker_profiles INCLUDING ALL)"
            )
            cur.execute(
                "CREATE TEMP TABLE sensor_events (event_id TEXT PRIMARY KEY, src_ip INET, timestamp TIMESTAMPTZ, attack_types TEXT)"
            )
            cur.execute("CREATE TEMP TABLE attack_patterns (event_id TEXT, attack_type TEXT)")
            migration = Path(MIGRATIONS_DIR) / "0009_hunting_queue_and_osint.sql"
            ddl = migration.read_text().replace(
                "CREATE TABLE IF NOT EXISTS", "CREATE TEMP TABLE IF NOT EXISTS"
            )
            for _ in range(2):
                for statement in split_statements(ddl):
                    cur.execute(statement)
            # Fail before any DML if a fixture accidentally resolves outside pg_temp.
            for name in (
                "attacker_profiles",
                "sensor_events",
                "attack_patterns",
                "attacker_hunt_queue",
                "attacker_osint_log",
                "attacker_tags",
            ):
                cur.execute(
                    "SELECT relnamespace = pg_my_temp_schema() FROM pg_class WHERE oid = %s::regclass",
                    (name,),
                )
                assert cur.fetchone()[0], name
            cur.execute(
                "INSERT INTO sensor_events VALUES ('a','203.0.113.12',NOW(),'XSS,SCANNER'), ('b','203.0.113.12',NOW(),'SCANNER')"
            )
            cur.execute(
                "INSERT INTO attack_patterns VALUES ('a','XSS'),('a','SCANNER'),('b','SCANNER')"
            )
            cur.execute(
                "INSERT INTO attacker_profiles (ip, hunt_status, updated_at) VALUES ('203.0.113.12','FINISHED','2020-01-01Z')"
            )
        info = attacker_profiler.fetch_ip_info(conn, "203.0.113.12")
        assert info["total_events"] == 2, info
        assert info["total_attacks"] == 2, info
        hunt_queue.enqueue(conn, ["203.0.113.12", "203.0.113.12"])
        old = hunt_queue.pending(conn, 1)[0]
        with conn.cursor() as cur:
            cur.execute("SELECT hunt_status, extract(year from updated_at) FROM attacker_profiles")
            assert cur.fetchone() == ("ACTIVE", 2020)
        # A new user request while an older job runs must not be deleted by that job.
        hunt_queue.enqueue(conn, ["203.0.113.12"])
        hunt_queue.complete(conn, *old)
        current = hunt_queue.pending(conn, 1)
        assert len(current) == 1
        hunt_queue.failed(conn, *current[0], "test retry")
        assert hunt_queue.pending(conn, 1) == []
        hunt_queue.enqueue(conn, ["203.0.113.12"])
        with patch.object(
            attacker_profiler, "profile_ip", AsyncMock(return_value={"ai_threat_level": "LOW"})
        ) as profile:
            assert (
                asyncio.run(attacker_profiler.daemon_cycle(conn, [], {"auto_profile": False})) == 1
            )
            assert profile.call_args.args[1]["total_events"] == 2
        assert hunt_queue.pending(conn, 1) == []
        print(
            "PASS: migration twice, unique event counts, durable queue, requeue race, retry, worker"
        )
    finally:
        conn.close()


if __name__ == "__main__":
    main()
