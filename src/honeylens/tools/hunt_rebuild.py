#!/usr/bin/env python3
"""
hunt_rebuild.py — Rebuild Hunting Database After Event Cleanup
================================================================
Fixes attacker_profiles after bulk event deletion:

1. FINISH profiles with zero remaining events (ghost profiles)
2. Recalculate event counts for profiles that still have data
3. Optionally re-queue profiles for OSINT re-enrichment

Usage:
    python hunt_rebuild.py                  # dry-run (safe)
    python hunt_rebuild.py --apply          # execute changes
    python hunt_rebuild.py --apply --verbose
"""

import argparse
import logging
import sys
from datetime import UTC, datetime

import psycopg2.extras

from honeylens.database import legacy_get_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("hunt_rebuild")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def get_conn():
    conn = legacy_get_db()
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    return conn


def main():
    parser = argparse.ArgumentParser(description="Rebuild hunting database after event cleanup")
    parser.add_argument("--apply", action="store_true", help="Execute changes (default: dry-run)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show per-IP details")
    args = parser.parse_args()

    mode = "%sAPPLY%s" % (RED, RESET) if args.apply else "%sDRY-RUN%s" % (YELLOW, RESET)

    print()
    print("%s%s══════════════════════════════════════════════════════════%s" % (BOLD, CYAN, RESET))
    print("%s%s  Hunt Rebuild — Post-Cleanup Database Repair  [%s]%s" % (BOLD, CYAN, mode, RESET))
    print("%s%s══════════════════════════════════════════════════════════%s" % (BOLD, CYAN, RESET))
    print()

    conn = get_conn()
    cur = conn.cursor()

    # ── Phase 1: Find ghost profiles (ACTIVE, zero events) ──
    print(
        "%s%s[Phase 1] Finding ghost profiles (ACTIVE with zero events)...%s" % (BOLD, CYAN, RESET)
    )

    cur.execute("""
        SELECT host(p.ip) AS ip_str, p.country, p.as_org, p.hunt_status,
               p.total_events AS old_total, p.abuse_score
        FROM attacker_profiles p
        WHERE p.hunt_status = 'ACTIVE'
          AND NOT EXISTS (
              SELECT 1 FROM sensor_events se WHERE host(se.src_ip) = host(p.ip)
          )
        ORDER BY p.last_seen DESC NULLS LAST
    """)
    ghosts = cur.fetchall()

    print("  Found: %s%d ghost profiles%s to FINISH" % (RED, len(ghosts), RESET))

    if args.verbose and ghosts:
        for g in ghosts[:30]:
            print(
                "    %s%-18s%s  %s  AS(%s)  was: %d events  abuse=%s"
                % (
                    RED,
                    g["ip_str"],
                    RESET,
                    g.get("country") or "??",
                    (g.get("as_org") or "?")[:30],
                    g.get("old_total") or 0,
                    g.get("abuse_score") or "?",
                )
            )
        if len(ghosts) > 30:
            print("    %s... and %d more%s" % (DIM, len(ghosts) - 30, RESET))
    print()

    # ── Phase 2: Find stale profiles (ACTIVE, have events, counts wrong) ──
    print("%s%s[Phase 2] Finding profiles needing count recalculation...%s" % (BOLD, CYAN, RESET))

    cur.execute("""
        SELECT
            host(p.ip) AS ip_str,
            p.total_events AS old_total,
            p.total_attacks AS old_attacks,
            COUNT(se.event_id) AS real_events,
            COUNT(DISTINCT ap.id) AS real_attacks,
            MIN(se.timestamp) AS real_first,
            MAX(se.timestamp) AS real_last,
            array_agg(DISTINCT ap.attack_type) FILTER (WHERE ap.attack_type IS NOT NULL) AS real_attack_types
        FROM attacker_profiles p
        JOIN sensor_events se ON host(se.src_ip) = host(p.ip)
        LEFT JOIN attack_patterns ap ON ap.event_id = se.event_id
        WHERE p.hunt_status = 'ACTIVE'
        GROUP BY p.ip, p.total_events, p.total_attacks
        HAVING COUNT(se.event_id) != COALESCE(p.total_events, 0)
            OR COUNT(DISTINCT ap.id) != COALESCE(p.total_attacks, 0)
    """)
    stale = cur.fetchall()

    print("  Found: %s%d profiles%s with wrong event counts" % (YELLOW, len(stale), RESET))

    if args.verbose and stale:
        for s in stale[:20]:
            print(
                "    %s%-18s%s  events: %d→%d  attacks: %d→%d"
                % (
                    YELLOW,
                    s["ip_str"],
                    RESET,
                    s.get("old_total") or 0,
                    s["real_events"],
                    s.get("old_attacks") or 0,
                    s["real_attacks"],
                )
            )
        if len(stale) > 20:
            print("    %s... and %d more%s" % (DIM, len(stale) - 20, RESET))
    print()

    # ── Phase 3: Check for IPs with events but no profile ──
    print("%s%s[Phase 3] Finding IPs with events but no profile...%s" % (BOLD, CYAN, RESET))

    cur.execute("""
        SELECT host(se.src_ip) AS ip_str, COUNT(*) AS event_count
        FROM sensor_events se
        WHERE NOT EXISTS (
            SELECT 1 FROM attacker_profiles p WHERE host(p.ip) = host(se.src_ip)
        )
        AND host(se.src_ip) NOT LIKE '192.168.%%'
        AND host(se.src_ip) NOT LIKE '10.%%'
        AND host(se.src_ip) NOT LIKE '127.%%'
        GROUP BY host(se.src_ip)
        HAVING COUNT(*) >= 5
        ORDER BY COUNT(*) DESC
    """)
    untracked = cur.fetchall()

    print(
        "  Found: %s%d IPs%s with 5+ events but no hunting profile" % (GREEN, len(untracked), RESET)
    )

    if args.verbose and untracked:
        for u in untracked[:15]:
            print("    %s%-18s%s  %d events" % (GREEN, u["ip_str"], RESET, u["event_count"]))
        if len(untracked) > 15:
            print("    %s... and %d more%s" % (DIM, len(untracked) - 15, RESET))
    print()

    # ── Summary ──
    print("%s%s── Summary ──%s" % (BOLD, CYAN, RESET))
    print("  Ghost profiles to FINISH:    %s%d%s" % (RED, len(ghosts), RESET))
    print("  Profiles to recalculate:     %s%d%s" % (YELLOW, len(stale), RESET))
    print("  Untracked IPs (5+ events):   %s%d%s" % (GREEN, len(untracked), RESET))
    print()

    if not args.apply:
        print(
            "  %s%s[DRY-RUN]%s  No changes made. Run with --apply to execute."
            % (BOLD, YELLOW, RESET)
        )
        print()
        conn.close()
        return 0

    # ══════════════════════════════════════════════════════════
    # APPLY CHANGES
    # ══════════════════════════════════════════════════════════

    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    finished_count = 0
    recalc_count = 0

    # ── Apply Phase 1: Finish ghost profiles ──
    if ghosts:
        print(
            "%s%s[Applying Phase 1] Finishing %d ghost profiles...%s"
            % (BOLD, RED, len(ghosts), RESET)
        )

        ghost_ips = [g["ip_str"] for g in ghosts]

        # Batch update in chunks of 200
        for i in range(0, len(ghost_ips), 200):
            batch = ghost_ips[i : i + 200]
            placeholders = ",".join(["%s"] * len(batch))

            note = "Auto-finished by hunt_rebuild.py: events deleted during cleanup [%s]" % ts

            cur.execute(
                """
                UPDATE attacker_profiles
                SET hunt_status  = 'FINISHED',
                    finished_at  = NOW(),
                    finish_notes = %%s
                WHERE host(ip) IN (%s)
                  AND hunt_status = 'ACTIVE'
            """  # nosec B608 — fixed UPDATE, IN placeholders assembled from constant %s
                % placeholders,
                [note, *batch],
            )

            finished_count += cur.rowcount
            conn.commit()

        print("  %s[OK]%s  Finished %d profiles" % (GREEN, RESET, finished_count))

    # ── Apply Phase 2: Recalculate event counts ──
    if stale:
        print(
            "%s%s[Applying Phase 2] Recalculating %d profiles...%s"
            % (BOLD, YELLOW, len(stale), RESET)
        )

        for s in stale:
            ip = s["ip_str"]
            attack_types = s.get("real_attack_types") or []
            # Filter None values from array
            attack_types = [t for t in attack_types if t]

            cur.execute(
                """
                UPDATE attacker_profiles
                SET total_events  = %s,
                    total_attacks = %s,
                    first_seen    = %s,
                    last_seen     = %s,
                    attack_types  = %s,
                    updated_at    = NOW()
                WHERE host(ip) = %s
            """,
                (
                    s["real_events"],
                    s["real_attacks"],
                    s["real_first"],
                    s["real_last"],
                    attack_types,
                    ip,
                ),
            )
            recalc_count += 1

        conn.commit()
        print("  %s[OK]%s  Recalculated %d profiles" % (GREEN, RESET, recalc_count))

    # ── Report ──
    print()
    print("%s%s══════════════════════════════════════════════════════════%s" % (BOLD, CYAN, RESET))
    print("%s%s  Rebuild Complete%s" % (BOLD, GREEN, RESET))
    print("%s%s══════════════════════════════════════════════════════════%s" % (BOLD, CYAN, RESET))
    print("  Ghost profiles finished:     %d" % finished_count)
    print("  Event counts recalculated:   %d" % recalc_count)
    print("  Untracked IPs found:         %d (run attacker_profiler.py to enrich)" % len(untracked))
    print()

    if untracked:
        print(
            "  %sTip:%s Run the attacker profiler to pick up the %d untracked IPs:"
            % (CYAN, RESET, len(untracked))
        )
        print("    python attacker_profiler.py")
        print()

    print("  %sTip:%s Run VACUUM to reclaim space after bulk updates:" % (CYAN, RESET))
    print("    psql -U sensor_user -d sensor -h localhost -c 'VACUUM ANALYZE attacker_profiles;'")
    print()

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
