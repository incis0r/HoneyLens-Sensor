#!/usr/bin/env python3
"""
cleanup_ssh_noise.py — Remove Real SSHD Traffic from Sensor Database
=====================================================================
Removes events where dst_port=22 (traffic to the sensor's real SSH service,
not the honeypot). Handles three categories of affected IPs:

  1. SSH-only IPs (1,766) — delete all events + FINISH their hunting profiles
  2. Mixed IPs (3) — delete only port 22 events, keep profiles, recalculate counts
  3. Orphaned related records — cascade-clean attack_patterns, ai_analysis, etc.

Usage:
    python cleanup_ssh_noise.py                 # dry-run (safe)
    python cleanup_ssh_noise.py --apply         # execute cleanup
    python cleanup_ssh_noise.py --apply --verbose
"""

import argparse
import logging
import sys
import time
from datetime import UTC, datetime

from honeylens.database import legacy_get_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cleanup_ssh")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def get_conn():
    return legacy_get_db()


def main():
    parser = argparse.ArgumentParser(
        description="Remove real SSHD (port 22) noise from sensor database"
    )
    parser.add_argument("--apply", action="store_true", help="Execute cleanup (default: dry-run)")
    parser.add_argument(
        "--batch", type=int, default=5000, help="Batch size for deletions (default: 5000)"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show per-IP details")
    args = parser.parse_args()

    mode = f"{RED}APPLY{RESET}" if args.apply else f"{YELLOW}DRY-RUN{RESET}"

    print()
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{CYAN}  SSH Noise Cleanup  [{mode}]{RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════{RESET}")
    print()

    conn = get_conn()
    cur = conn.cursor()

    # ── Analyse ──
    print(f"{BOLD}[1/4] Analysing port 22 traffic...{RESET}")

    cur.execute("SELECT COUNT(*) FROM sensor_events WHERE dst_port = 22")
    total_ssh_events = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(DISTINCT src_ip) FROM sensor_events
        WHERE dst_port = 22
          AND NOT EXISTS (
              SELECT 1 FROM sensor_events se2
              WHERE host(se2.src_ip) = host(sensor_events.src_ip)
                AND se2.dst_port != 22
          )
    """)
    ssh_only_ips = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(DISTINCT src_ip) FROM sensor_events
        WHERE dst_port = 22
          AND EXISTS (
              SELECT 1 FROM sensor_events se2
              WHERE host(se2.src_ip) = host(sensor_events.src_ip)
                AND se2.dst_port != 22
          )
    """)
    mixed_ips = cur.fetchone()[0]

    # Count related records
    cur.execute("""
        SELECT COUNT(*) FROM attack_patterns ap
        JOIN sensor_events se ON se.event_id = ap.event_id
        WHERE se.dst_port = 22
    """)
    related_attacks = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM ai_analysis aa
        JOIN sensor_events se ON se.event_id = aa.event_id
        WHERE se.dst_port = 22
    """)
    related_ai = cur.fetchone()[0]

    related_ts = 0
    try:
        cur.execute("""
            SELECT COUNT(*) FROM threat_scores ts
            JOIN sensor_events se ON se.event_id = ts.event_id
            WHERE se.dst_port = 22
        """)
        related_ts = cur.fetchone()[0]
    except Exception:
        conn.rollback()

    related_ja4 = 0
    try:
        cur.execute("""
            SELECT COUNT(*) FROM ja4_fingerprints jf
            JOIN sensor_events se ON se.event_id = jf.event_id
            WHERE se.dst_port = 22
        """)
        related_ja4 = cur.fetchone()[0]
    except Exception:
        conn.rollback()

    # Hunting profiles that are SSH-only
    cur.execute("""
        SELECT COUNT(*) FROM attacker_profiles p
        WHERE hunt_status = 'ACTIVE'
          AND EXISTS (
              SELECT 1 FROM sensor_events se
              WHERE host(se.src_ip) = host(p.ip) AND se.dst_port = 22
          )
          AND NOT EXISTS (
              SELECT 1 FROM sensor_events se
              WHERE host(se.src_ip) = host(p.ip) AND se.dst_port != 22
          )
    """)
    ssh_only_profiles = cur.fetchone()[0]

    print()
    print(f"  {BOLD}── Records to Remove ──{RESET}")
    print("  sensor_events (port 22):   %s%10s%s" % (RED, f"{total_ssh_events:,}", RESET))
    print("  attack_patterns:           %s%10s%s" % (RED, f"{related_attacks:,}", RESET))
    print("  ai_analysis:               %s%10s%s" % (RED, f"{related_ai:,}", RESET))
    print("  threat_scores:             %s%10s%s" % (RED, f"{related_ts:,}", RESET))
    print("  ja4_fingerprints:          %s%10s%s" % (RED, f"{related_ja4:,}", RESET))
    print()
    print(f"  {BOLD}── IP Categories ──{RESET}")
    print("  SSH-only IPs (full purge): %s%10s%s" % (RED, f"{ssh_only_ips:,}", RESET))
    print("  Mixed IPs (keep profile):  %s%10s%s" % (YELLOW, f"{mixed_ips:,}", RESET))
    print()
    print(f"  {BOLD}── Hunting Profiles ──{RESET}")
    print("  SSH-only profiles → FINISH: %s%9s%s" % (RED, f"{ssh_only_profiles:,}", RESET))
    print("  Mixed profiles → recalc:    %s%9s%s" % (YELLOW, f"{mixed_ips:,}", RESET))
    print()

    if not args.apply:
        print(f"  {BOLD}{YELLOW}[DRY-RUN]{RESET}  No changes made. Run with --apply to execute.")
        print()
        conn.close()
        return 0

    # ══════════════════════════════════════════════════════════
    # APPLY
    # ══════════════════════════════════════════════════════════
    start_time = time.time()

    # ── Step 1: Collect event_ids for port 22 ──
    print(f"{BOLD}[2/4] Collecting event IDs...{RESET}")
    cur.execute("SELECT event_id FROM sensor_events WHERE dst_port = 22")
    event_ids = [r[0] for r in cur.fetchall()]
    print("  Collected {} event IDs".format(f"{len(event_ids):,}"))

    # ── Step 2: Delete related records in batches ──
    print(f"{BOLD}[3/4] Deleting records in batches of {args.batch}...{RESET}")

    del_attacks = 0
    del_ai = 0
    del_ts = 0
    del_ja4 = 0
    del_events = 0

    total_batches = (len(event_ids) + args.batch - 1) // args.batch

    for i in range(0, len(event_ids), args.batch):
        batch = event_ids[i : i + args.batch]
        batch_num = i // args.batch + 1

        # attack_patterns
        try:
            cur.execute("DELETE FROM attack_patterns WHERE event_id = ANY(%s)", (batch,))
            del_attacks += cur.rowcount
        except Exception:
            conn.rollback()

        # ai_analysis
        try:
            cur.execute("DELETE FROM ai_analysis WHERE event_id = ANY(%s)", (batch,))
            del_ai += cur.rowcount
        except Exception:
            conn.rollback()

        # threat_scores
        try:
            cur.execute("DELETE FROM threat_scores WHERE event_id = ANY(%s)", (batch,))
            del_ts += cur.rowcount
        except Exception:
            conn.rollback()

        # ja4_fingerprints
        try:
            cur.execute("DELETE FROM ja4_fingerprints WHERE event_id = ANY(%s)", (batch,))
            del_ja4 += cur.rowcount
        except Exception:
            conn.rollback()

        # sensor_events
        cur.execute("DELETE FROM sensor_events WHERE event_id = ANY(%s)", (batch,))
        del_events += cur.rowcount

        conn.commit()

        elapsed = time.time() - start_time
        rate = (i + len(batch)) / elapsed if elapsed > 0 else 0
        eta = (len(event_ids) - i - len(batch)) / rate if rate > 0 else 0

        if batch_num % 10 == 0 or batch_num == total_batches:
            print(
                "  Batch %d/%d — %s events deleted — %.0f/sec — ETA %.0fs"
                % (
                    batch_num,
                    total_batches,
                    f"{del_events:,}",
                    rate,
                    eta,
                )
            )

    # ── Step 3: Finish SSH-only hunting profiles ──
    print(f"{BOLD}[4/4] Cleaning hunting profiles...{RESET}")

    ts_note = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    finish_note = f"Auto-finished: SSH-only IP (real SSHD traffic, not honeypot) [{ts_note}]"

    # Finish profiles that now have zero events
    cur.execute(
        """
        UPDATE attacker_profiles
        SET hunt_status  = 'FINISHED',
            finished_at  = NOW(),
            finish_notes = %s
        WHERE hunt_status = 'ACTIVE'
          AND NOT EXISTS (
              SELECT 1 FROM sensor_events se
              WHERE host(se.src_ip) = host(attacker_profiles.ip)
          )
    """,
        (finish_note,),
    )
    finished_profiles = cur.rowcount
    conn.commit()
    print(f"  Finished {finished_profiles} SSH-only profiles")

    # Recalculate counts for mixed IPs (the 3 that also hit other ports)
    cur.execute("""
        UPDATE attacker_profiles p
        SET total_events = sub.cnt,
            total_attacks = sub.atk,
            first_seen = sub.fs,
            last_seen = sub.ls,
            updated_at = NOW()
        FROM (
            SELECT host(se.src_ip) AS ip_str,
                   COUNT(*) AS cnt,
                   COUNT(DISTINCT ap.id) AS atk,
                   MIN(se.timestamp) AS fs,
                   MAX(se.timestamp) AS ls
            FROM sensor_events se
            LEFT JOIN attack_patterns ap ON ap.event_id = se.event_id
            GROUP BY host(se.src_ip)
        ) sub
        WHERE host(p.ip) = sub.ip_str
          AND p.hunt_status = 'ACTIVE'
          AND (p.total_events != sub.cnt OR p.total_events IS NULL)
    """)
    recalc = cur.rowcount
    conn.commit()
    print(f"  Recalculated {recalc} mixed profiles")

    elapsed = time.time() - start_time

    # ── Summary ──
    print()
    print(f"{BOLD}{GREEN}══════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN}  Cleanup Complete — {elapsed:.1f}s{RESET}")
    print(f"{BOLD}{GREEN}══════════════════════════════════════════════════════════{RESET}")
    print("  sensor_events deleted:    {}".format(f"{del_events:,}"))
    print("  attack_patterns deleted:  {}".format(f"{del_attacks:,}"))
    print("  ai_analysis deleted:      {}".format(f"{del_ai:,}"))
    print("  threat_scores deleted:    {}".format(f"{del_ts:,}"))
    print("  ja4_fingerprints deleted: {}".format(f"{del_ja4:,}"))
    print(f"  Profiles finished:        {finished_profiles}")
    print(f"  Profiles recalculated:    {recalc}")
    print()
    print(f"  {CYAN}Next steps:{RESET}")
    print("  1. Add to config.py to prevent future port 22 ingestion:")
    print('     IGNORE_DST_HOST_PORTS = {"192.0.2.153": [22]}')
    print("  2. VACUUM: psql -U sensor_user -d sensor -h localhost \\")
    print("     -c 'VACUUM ANALYZE sensor_events, attack_patterns, attacker_profiles;'")
    print()

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
