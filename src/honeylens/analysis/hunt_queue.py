"""Durable, bounded hunting requests consumed by the profiler daemon."""


def enqueue(conn, ips: list[str]) -> int:
    with conn.cursor() as cur:
        for ip in dict.fromkeys(ips):
            cur.execute(
                """INSERT INTO attacker_hunt_queue (ip) VALUES (%s::inet)
                   ON CONFLICT (ip) DO UPDATE SET requested_at = clock_timestamp(),
                       attempts = 0, retry_at = NOW(), last_error = NULL""",
                (ip,),
            )
            # Reopen immediately, but don't postpone profiling by changing updated_at.
            cur.execute(
                """UPDATE attacker_profiles SET hunt_status = 'ACTIVE',
                       finished_at = NULL, finish_notes = NULL WHERE ip = %s::inet""",
                (ip,),
            )
    conn.commit()
    return len(set(ips))


def pending(conn, limit: int) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute(
            """SELECT host(ip), requested_at FROM attacker_hunt_queue
               WHERE retry_at <= NOW() ORDER BY requested_at LIMIT %s""",
            (limit,),
        )
        return cur.fetchall()


def complete(conn, ip, requested_at):
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM attacker_hunt_queue WHERE ip = %s::inet AND requested_at = %s",
            (ip, requested_at),
        )
    conn.commit()


def failed(conn, ip, requested_at, error):
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE attacker_hunt_queue SET attempts = attempts + 1,
                   retry_at = NOW() + INTERVAL '5 minutes', last_error = %s
               WHERE ip = %s::inet AND requested_at = %s""",
            (str(error)[:1000], ip, requested_at),
        )
    conn.commit()
