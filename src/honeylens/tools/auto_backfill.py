#!/usr/bin/env python3
"""auto_backfill.py — nightly, self-triggering reclassification backfill.

Runs daily (systemd timer, 01:00). It answers one question: *did the attack
classification change centrally since the last backfill?* If yes, stored events may
now carry stale/wrong ``attack_types``, so it reruns the existing
:mod:`honeylens.tools.backfill_attacks` reprocess over the events. If the rules are
unchanged it does nothing and exits — cheap to run every night.

"Changed centrally" is decided by a fingerprint of the text-rule registry
(``classification.text_rules._RULES`` — the same multiset the golden-snapshot test
pins) plus ``LOGIC_VERSION`` below. Bump ``LOGIC_VERSION`` to force a one-off backfill
after a classification change the rule fingerprint does not capture (binary detectors,
scoring). The last-applied fingerprint lives in the ``classification_state`` table, so
the decision is central and survives restarts.

    honeylens-auto-backfill              # DRY-RUN: report what it would do, write nothing (E1)
    honeylens-auto-backfill --apply      # actually backfill, if the rules changed
    honeylens-auto-backfill --apply --force   # actually backfill regardless
    honeylens-auto-backfill --check      # print status and exit (never backfills)

Writing is opt-in (``--apply``): a bare run — a human testing it, or a timer that lost its
flag — must not modify data. This is the job whose first unattended run wiped decoy tags; the
scheduled unit passes ``--apply`` explicitly, so the write intent lives in the reviewed unit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
)
logger = logging.getLogger("auto-backfill")

# Bump to force a backfill on the next run when the change is NOT in the text-rule
# registry (e.g. a binary_detectors.py or classification/scoring.py fix).
LOGIC_VERSION = 1

_STATE_KEY = "classification_rules_fingerprint"


def rules_fingerprint() -> str:
    """Stable SHA-256 of the current classification rule surface."""
    from honeylens.classification import text_rules as t

    rules = sorted([a, n, rx.pattern, rx.flags] for a, n, rx in t._RULES)
    blob = json.dumps({"version": LOGIC_VERSION, "rules": rules}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def _ensure_state_table(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS classification_state (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    conn.commit()


def _get_stored(conn) -> str | None:
    with conn.cursor() as cur:
        cur.execute("SELECT value FROM classification_state WHERE key = %s", (_STATE_KEY,))
        row = cur.fetchone()
    return row[0] if row else None


def _store(conn, fingerprint: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO classification_state (key, value, updated_at)
            VALUES (%s, %s, now())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
            """,
            (_STATE_KEY, fingerprint),
        )
    conn.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--force", action="store_true", help="backfill even if rules are unchanged")
    # E1: dry-run is the DEFAULT for this data-modifying scheduled job — a bare run (e.g. a human
    # testing it, or a timer that lost its flag) must write nothing. Writing is an explicit opt-in
    # (--apply), the same convention the migrator and the ICS simulator already follow. This is the
    # job whose first unattended run with the authoritative replace mode wiped decoy tags fleet-wide.
    parser.add_argument(
        "--apply", action="store_true", help="actually write (default: dry-run, writes nothing)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report the decision, write nothing (now the default)",
    )
    parser.add_argument(
        "--check", action="store_true", help="print current vs stored fingerprint and exit"
    )
    parser.add_argument("--limit", type=int, default=None, help="cap events reprocessed (testing)")
    parser.add_argument("--workers", type=int, default=0, help="backfill workers (0=auto)")
    args = parser.parse_args()
    # Dry-run unless the caller explicitly opted into writing; --dry-run still forces it too.
    dry_run = args.dry_run or not args.apply

    from honeylens.database import legacy_get_db

    current = rules_fingerprint()
    conn = legacy_get_db()
    try:
        _ensure_state_table(conn)
        stored = _get_stored(conn)
    finally:
        conn.close()

    changed = stored != current
    logger.info("rule fingerprint current=%s stored=%s", current[:12], (stored or "none")[:12])

    if args.check:
        print(f"current={current}\nstored={stored}\nchanged={changed}")
        return 0

    if not changed and not args.force:
        logger.info("classification unchanged since last backfill — nothing to do")
        return 0

    reason = "forced" if (args.force and not changed) else "classification changed centrally"
    logger.info("backfill triggered (%s)%s", reason, " [dry-run]" if dry_run else "")

    from honeylens.tools.backfill_attacks import BackfillConfig, backfill

    backfill(
        BackfillConfig(
            reprocess_all=True,  # the fix may have tightened a rule; recheck every event
            replace_patterns=True,  # authoritative: drop stale pattern rows + clear now-benign tags
            dry_run=dry_run,
            limit=args.limit,
            workers=args.workers,
        )
    )

    if not dry_run:
        conn = legacy_get_db()
        try:
            _store(conn, current)
        finally:
            conn.close()
        logger.info("stored fingerprint %s", current[:12])

    return 0


if __name__ == "__main__":
    sys.exit(main())
