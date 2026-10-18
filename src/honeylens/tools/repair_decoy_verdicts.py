#!/usr/bin/env python3
"""repair_decoy_verdicts.py — correct stored verdicts the authoritative reprocess cannot touch.

Phase Z, step 8. `backfill_attacks --replace-patterns` owns exactly the rows whose `rule_name` is
in the central text registry; everything a decoy or a vendor ingest wrote is preserved by design,
because the central classifier cannot reproduce it. That is the right rule — it is why decoy tags
survive a reprocess — and it means three verdicts corrected in code this week are still wrong in
the store:

* **`SMB_EXPLOIT_PROBE` / `smb1_detected`** — `hp_smb` wrote it at HIGH for any frame carrying the
  SMB1 magic. 347,045 rows on sensor-a. An SMB1 frame is legacy-dialect negotiation; the exploit
  verdict needs a trans2 or NT-trans command plus the `1807c0` marker.
* **`PANOS_CAPTIVE`** — the captive portal's catch-all asserted a PAN-OS captive interaction for
  every request that reached the route meaning "this is NOT one of the captive paths". 759 rows on
  sensor-a, 446 on prod.
* **`sp-webshell-aspx`** — HIGH with CVE-2025-53770 for a bare GET of `spinstall0.aspx`. 102 rows
  on sensor-a, 8 on prod, and every one of them a GET with no body.

Each correction re-runs **the fixed writer's own decision function** over what was stored, rather
than reimplementing the judgement here — `hp_smb.smb1_verdict`, `paloalto.decide_attack_types`,
and the method test from `honeypot_sharepoint`. A repair that re-derives a verdict differently
from the writer is how two subsystems start disagreeing, which is the defect this whole plan is
about.

Verified re-derivable before writing this, on sensor-a and prod:

* SMB: 347,045 of 347,045 rows still carry the frame in `metadata->>'hex'`.
* PAN-OS: `metadata` is NULL on every row — the vendor ingest never wrote it — but the decoy's
  own JSON is the `payload`, and 400 of 400 sampled parse and carry `event_type`. Re-deciding
  them gives SCANNER 222, RECON 85, **PANOS_CAPTIVE 60** (the three real captive paths, which
  keep it correctly), PANOS_PROBE 29, LFI 3.
* SharePoint: 110 of 110 carry `metadata->>'method'`, all GET.

    honeylens-repair-decoy-verdicts              # report, writes nothing
    honeylens-repair-decoy-verdicts --apply
    honeylens-repair-decoy-verdicts --apply --only smb

Writing is opt-in, as in every other repair tool here: this is the class of job whose first
unattended run wiped decoy tags.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter

from honeylens.classification.scoring import get_severity
from honeylens.database import legacy_get_db

logger = logging.getLogger("repair-decoy-verdicts")

_BATCH = 5000


def _rows(cur, sql: str, params: tuple) -> list:
    cur.execute(sql, params)
    return cur.fetchall()


def _replace_pattern(cur, event_id: str, old_type: str, old_rule: str, new: list[tuple[str, str]]):
    """Swap one decoy-authored pattern row for the verdict its writer would produce today.

    DELETE then INSERT rather than UPDATE: migration 0012's unique index is on
    `(event_id, attack_type, rule_name)`, and an UPDATE into a pair that already exists would
    fail the statement. `ON CONFLICT DO NOTHING` makes the insert idempotent, so a second run of
    this tool is a no-op.
    """
    cur.execute(
        "DELETE FROM attack_patterns WHERE event_id = %s AND attack_type = %s AND rule_name = %s",
        (event_id, old_type, old_rule),
    )
    for attack_type, rule_name in new:
        cur.execute(
            """INSERT INTO attack_patterns (event_id, attack_type, rule_name, severity, confidence)
               VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""",
            (event_id, attack_type, rule_name, get_severity(attack_type, rule_name), "medium"),
        )


def repair_smb(conn, apply: bool, touched: set[str]) -> Counter:
    """`SMB_EXPLOIT_PROBE` for a bare SMB1 negotiation becomes `SMB_SCAN`."""
    from honeylens.honeypots.hp_smb import smb1_verdict

    stats: Counter = Counter()
    cur = conn.cursor()
    rows = _rows(
        cur,
        """SELECT p.event_id, e.metadata->>'hex'
             FROM attack_patterns p JOIN sensor_events e ON e.event_id = p.event_id
            WHERE p.attack_type = %s AND p.rule_name = %s
              AND e.metadata ? 'hex'""",
        ("SMB_EXPLOIT_PROBE", "smb1_detected"),
    )
    for event_id, hexframe in rows:
        stats["examined"] += 1
        try:
            frame = bytes.fromhex(hexframe)
        except (ValueError, TypeError):
            stats["unreadable_frame"] += 1
            continue
        attack_type, _severity, rule = smb1_verdict(frame)
        if (attack_type, rule) == ("SMB_EXPLOIT_PROBE", "smb1_detected"):
            stats["already_correct"] += 1
            continue
        stats[f"-> {attack_type}"] += 1
        if apply:
            _replace_pattern(
                cur, event_id, "SMB_EXPLOIT_PROBE", "smb1_detected", [(attack_type, rule)]
            )
            touched.add(event_id)
            stats["written"] += 1
            if stats["written"] % _BATCH == 0:
                conn.commit()
    if apply:
        conn.commit()
    return stats


def repair_panos_captive(conn, apply: bool, touched: set[str]) -> Counter:
    """The captive catch-all stops asserting PAN-OS, decided from the decoy's own JSON."""
    from honeylens.ingest.paloalto import decide_attack_types

    stats: Counter = Counter()
    cur = conn.cursor()
    rows = _rows(
        cur,
        """SELECT p.event_id, p.rule_name, e.payload
             FROM attack_patterns p JOIN sensor_events e ON e.event_id = p.event_id
            WHERE p.attack_type = %s""",
        ("PANOS_CAPTIVE",),
    )
    for event_id, rule_name, payload in rows:
        stats["examined"] += 1
        try:
            data = json.loads(payload or "")
        except (TypeError, ValueError):
            stats["payload_not_json"] += 1
            continue
        event_type = data.get("event_type")
        if not event_type:
            stats["no_event_type"] += 1
            continue
        types, rules = decide_attack_types(event_type, {**data, "path": data.get("path") or "/"})
        new = [(t[0], rules.get(t[0], rule_name)) for t in types]
        if any(t[0] == "PANOS_CAPTIVE" for t in types):
            stats["already_correct"] += 1
            continue
        stats["-> " + (",".join(sorted({t[0] for t in types})) or "(none)")] += 1
        if apply:
            _replace_pattern(cur, event_id, "PANOS_CAPTIVE", rule_name, new)
            touched.add(event_id)
            stats["written"] += 1
            if stats["written"] % _BATCH == 0:
                conn.commit()
    if apply:
        conn.commit()
    return stats


def repair_sharepoint(conn, apply: bool, touched: set[str]) -> Counter:
    """A bare GET of the webshell path is a probe, not a drop, and claims no CVE."""
    stats: Counter = Counter()
    cur = conn.cursor()
    rows = _rows(
        cur,
        """SELECT p.event_id, p.rule_name, e.metadata->>'method',
                  coalesce(length(e.metadata->>'body_sample'), 0)
             FROM attack_patterns p JOIN sensor_events e ON e.event_id = p.event_id
            WHERE p.attack_type = %s""",
        ("sp-webshell-aspx",),
    )
    for event_id, rule_name, method, body_len in rows:
        stats["examined"] += 1
        if method in ("POST", "PUT") and body_len:
            stats["already_correct"] += 1
            continue
        stats["-> sp-webshell-aspx-probe"] += 1
        if apply:
            _replace_pattern(
                cur,
                event_id,
                "sp-webshell-aspx",
                rule_name,
                [("sp-webshell-aspx-probe", "sp-webshell-aspx-probe")],
            )
            touched.add(event_id)
            stats["written"] += 1
    if apply:
        conn.commit()
    return stats


_REPAIRS = {
    "smb": repair_smb,
    "panos": repair_panos_captive,
    "sharepoint": repair_sharepoint,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write (default is report only)")
    parser.add_argument("--only", choices=sorted(_REPAIRS), help="run one correction")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    conn = legacy_get_db()
    # The events this run actually changed. Scoped deliberately: an earlier draft selected every
    # event carrying one of the new verdict types, which on sensor-a is millions of rows of work for
    # a few hundred thousand swaps — and rebuilding an event this tool never touched is a chance
    # to get that event wrong for no reason.
    touched: set[str] = set()
    try:
        for name, fn in _REPAIRS.items():
            if args.only and name != args.only:
                continue
            stats = fn(conn, args.apply, touched)
            logger.info("%s: %s", name, dict(stats) or "nothing to do")

        if args.apply and touched:
            # Each event's summary is the union of its remaining pattern rows, so it has to be
            # rebuilt after the swap — the same contract `backfill_attacks` honours.
            from honeylens.tools.backfill_attacks import rebuild_attack_types

            ids = sorted(touched)
            logger.info("rebuilding attack_types for %d events", len(ids))
            for i in range(0, len(ids), _BATCH):
                rebuild_attack_types(ids[i : i + _BATCH])
        elif not args.apply:
            logger.info("--- REPORT ONLY (use --apply to write)")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
