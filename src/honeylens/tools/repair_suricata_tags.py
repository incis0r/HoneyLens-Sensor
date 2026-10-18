#!/usr/bin/env python3
"""repair_suricata_tags.py — restore the Suricata labels a reprocess erased.

A Suricata detection lived only in ``sensor_events.attack_types``: the ingest's companion
``attack_patterns`` insert carried ``ON CONFLICT (event_id, attack_type, rule_name)``, no unique
index matched those columns until migration 0012, and the resulting error was logged at debug
level. A reprocess rebuilds ``attack_types`` from the union of an event's ``attack_patterns``, so
every pass deleted labels that had no row behind them. Measured on sensor-a 2026-11-01: 1,991,772 of
1,991,772 pre-pass Suricata events untagged, against 196,539 of 196,539 tagged after it.

Nothing was lost that cannot be recomputed: ``suricata_sid``, ``suricata_signature`` and the whole
alert JSON in ``payload`` are intact. This re-derives the label exactly as the ingest does and
writes the missing pattern row behind it, so the next reprocess leaves it alone.

**It corrects as well as restores.** The label is re-derived through the current gates, so a row
whose CVE was promoted to a verdict before those gates existed comes back without that CVE:
an ``ET HUNTING`` hit (2026-10-30), and from 2026-11-04 a CVE whose affected service does not run
on the destination port or whose rule declares a CVE for reconnaissance. Measured fleet-wide that
second class is our nginx rule 9026731 (402 rows, three of them on the nginx decoy), our Apache
rule 9026500 (575 rows over 28 ports) and ET sid 2019526's phpinfo access (393 rows). In every
case the declared CVE stays in the payload as evidence; it just stops being a finding.

Reports by default; ``--apply`` writes. Idempotent: an event whose recomputed label already
matches is left alone.

    honeylens-repair-suricata-tags                     # report only
    honeylens-repair-suricata-tags --apply
    honeylens-repair-suricata-tags --apply --drop-central   # also drop the alert-JSON matches
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from typing import NamedTuple

import psycopg2.extras

from honeylens.ingest.cve_service_ports import cve_is_a_finding, cve_is_in_service
from honeylens.ingest.suricata import SEVERITY_MAP, classify_attack
from honeylens.tools.backfill_attacks import (
    _central_rule_names,
    get_connection,
    put_connection,
    write_updates_batch,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("repair-suricata-tags")

#: What classify_attack returns when neither the signature nor the category decides. Treated as
#: "unknown", never written over a label that already says something.
_GENERIC_TYPE = "SURICATA_ALERT"


def derive_label(
    sid, signature: str, payload_json: str | None, dst_port: int | None = None
) -> tuple[str, str, str] | None:
    """Re-derive ``(attack_types, rule_name, severity)`` for one stored Suricata event.

    Mirrors :func:`honeylens.ingest.suricata.process_alert`: the attack_type comes from the
    signature then the category, and a declared CVE is appended only when the rule is not a
    hunting rule, when that rule's declaration describes exploitation rather than
    reconnaissance, and when ``dst_port`` runs the affected service. Returns None when the row
    carries too little to decide.

    ``dst_port`` defaults to None, which passes the service gate: a caller that cannot supply
    the port gets the pre-2026-11-04 behaviour rather than a silent mass removal.
    """
    if sid is None:
        return None
    meta: dict = {}
    if payload_json:
        try:
            parsed = json.loads(payload_json)
            if isinstance(parsed, dict):
                meta = parsed
        except (ValueError, TypeError):
            meta = {}

    sig = signature or str(meta.get("signature") or "")
    if not sig:
        return None
    category = str(meta.get("category") or "")

    attack_type = classify_attack(sig, category)
    attack_types = attack_type

    # The hunting rule is re-applied here rather than trusted from the payload, because rows
    # written before 2026-10-30 stored the promoted CVE in `cve`. The service and demotion gates
    # (2026-11-04) are re-applied for the same reason: the rows that need them were written
    # before they existed, and the payload still holds everything needed to decide.
    if "hunting" not in sig.lower():
        cve = meta.get("cve") or ""
        if cve and cve_is_a_finding(cve, sid) and cve_is_in_service(cve, dst_port):
            attack_types += "," + str(cve).replace("-", "_")

    try:
        severity = SEVERITY_MAP.get(int(meta.get("severity")), "MEDIUM")  # type: ignore[arg-type]
    except (TypeError, ValueError):
        severity = "MEDIUM"

    return attack_types, f"suricata_sid_{sid}", severity


def decide(current: str | None, derived: str) -> str:
    """What to do with one row: ``"restore"``, ``"correct"``, ``"keep"`` or ``"ok"``.

    This tool repairs three named defects and nothing else: a label a reprocess erased
    (``restore``), and a CVE that should never have been asserted -- by a hunting rule, or by a
    rule whose CVE names a service the destination port does not run (both ``correct``, because
    the base attack_type is unchanged and only the CVE token goes). Anything else that differs is
    left alone, because a repair that quietly relabels is a reclassification wearing a repair's
    name.

    Two guards, both measured on sensor-b 2026-11-01 over its 121,475 Suricata events:

    ``keep`` on a generic derivation (1,769 rows) -- the category lives only in the payload, so an
    unreadable payload leaves ``classify_attack`` with the signature alone and it falls back to
    the generic type. Writing that over a label an earlier, intact ingest produced would destroy
    information in the name of restoring it. An untagged row still takes the generic label: it is
    what the ingest itself would have written from the same inputs.

    That guard is **narrowed to a differing base type** (2026-11-04). It used to fire on any
    generic derivation, which hid the whole phpinfo class from the repair: ``SURICATA_ALERT`` is
    both the generic fallback and the genuine label of those rows, so
    ``SURICATA_ALERT,CVE_2002_1149`` -> ``SURICATA_ALERT`` was read as "a generic label about to
    overwrite a specific one" when the base type is identical and only the withheld CVE differs.
    Measured: 393 rows fleet-wide that the first report-only run left untouched. Nothing is lost
    by narrowing it -- when the base types agree there is no information to destroy.

    ``drift`` on a different base type (sensor-a 17,749 rows: ``RCE``->``PROTO_ABUSE`` 14,824,
    ``ORACLE_SCAN``->``SCANNER`` 1,638, ``SCANNER``->``ANOMALY`` 511; sensor-b 444) -- the signature
    rules have changed since those rows were written. That is reclassification rather than
    repair, so it is reported by default and written only under ``--apply-drift``: a relabel
    nobody asked for is indistinguishable from a bug, and the counts have to be readable before
    anyone agrees to them.
    """
    base_current = (current or "").split(",")[0]
    base_derived = derived.split(",")[0]
    if base_derived == _GENERIC_TYPE and current and base_current != base_derived:
        return "keep"
    if not current:
        return "restore"
    if current == derived:
        return "ok"
    if base_current != base_derived:
        return "drift"
    return "correct"


def _fetch_page(last_event_id: str | None, page: int) -> list[tuple]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        if last_event_id:
            cur.execute(
                """
                SELECT e.event_id, e.suricata_sid, e.suricata_signature, e.payload,
                       e.attack_types, e.dst_port,
                       EXISTS (SELECT 1 FROM attack_patterns ap
                               WHERE ap.event_id = e.event_id
                                 AND ap.rule_name = 'suricata_sid_' || e.suricata_sid) AS has_row
                FROM sensor_events e
                WHERE e.source = 'suricata' AND e.event_id > %s
                ORDER BY e.event_id
                LIMIT %s
                """,
                (last_event_id, page),
            )
        else:
            cur.execute(
                """
                SELECT e.event_id, e.suricata_sid, e.suricata_signature, e.payload,
                       e.attack_types, e.dst_port,
                       EXISTS (SELECT 1 FROM attack_patterns ap
                               WHERE ap.event_id = e.event_id
                                 AND ap.rule_name = 'suricata_sid_' || e.suricata_sid) AS has_row
                FROM sensor_events e
                WHERE e.source = 'suricata'
                ORDER BY e.event_id
                LIMIT %s
                """,
                (page,),
            )
        return cur.fetchall()
    finally:
        put_connection(conn)


class RowPlan(NamedTuple):
    """What one row's action means in writes and counters. Separated from the loop because the
    loop cannot be unit-tested and this is where a mistake is silent: an earlier edit of the
    branch chain dropped the restore/correct body, and the tool reported nothing at all rather
    than failing -- the kind of bug that only shows when there is nothing left to repair."""

    counter: str
    write_label: bool
    pattern_type: str
    #: new attack_type for this event's existing suricata_sid_* row, or None to leave it
    move_pattern_to: str | None
    record_as_drift: bool


def plan_row(action: str, current: str | None, derived: str, *, relabel_drift: bool) -> RowPlan:
    """Map a :func:`decide` action to writes and a counter.

    The pattern row must always agree with whatever label ends up on the event, because
    ``rebuild_attack_types`` composes the label from the pattern rows: a label written without
    moving the row is reverted by the next reprocess.
    """
    base_current = (current or "").split(",")[0]
    base_derived = derived.split(",")[0]

    if action in ("restore", "correct"):
        return RowPlan(
            "restored" if action == "restore" else "corrected",
            True,
            base_derived,
            base_derived if base_current and base_current != base_derived else None,
            False,
        )
    if action == "drift":
        if relabel_drift:
            return RowPlan(
                "drift_relabelled",
                True,
                base_derived,
                base_derived if base_current != base_derived else None,
                True,
            )
        # Declined: the label stays, so the pattern row must keep agreeing with it.
        return RowPlan("rule_drift", False, base_current or base_derived, None, True)
    if action == "keep":
        return RowPlan("kept_generic", False, base_current or base_derived, None, False)
    return RowPlan("label_ok", False, base_current or base_derived, None, False)


def _replace_pattern_types(moves: list[tuple[str, str, str]]) -> int:
    """Re-point each event's own ``suricata_sid_*`` row at the new attack_type.

    Needed because ``rebuild_attack_types`` composes the label from the pattern rows: updating
    ``attack_types`` alone would be undone by the next reprocess, which would read the OLD
    attack_type still sitting in the pattern row and put the old label back. The insert is
    conditional on 0012's unique index, so a re-run is a no-op rather than a duplicate.
    """
    if not moves:
        return 0
    conn = get_connection()
    try:
        cur = conn.cursor()
        psycopg2.extras.execute_batch(
            cur,
            "UPDATE attack_patterns SET attack_type = %s"
            " WHERE event_id = %s AND rule_name = %s"
            "   AND NOT EXISTS (SELECT 1 FROM attack_patterns dup"
            "                   WHERE dup.event_id = attack_patterns.event_id"
            "                     AND dup.rule_name = attack_patterns.rule_name"
            "                     AND dup.attack_type = %s)",
            [(new, event_id, rule_name, new) for new, event_id, rule_name in moves],
            page_size=1000,
        )
        conn.commit()
        return len(moves)
    except psycopg2.Error as exc:
        conn.rollback()
        logger.error("pattern re-point failed: %s", exc)
        return 0
    finally:
        put_connection(conn)


def _write_patterns(rows: list[tuple]) -> int:
    """Insert the pattern rows behind the labels. Requires migration 0012 for the conflict
    target; a plain DO NOTHING would silently duplicate on a re-run."""
    if not rows:
        return 0
    conn = get_connection()
    try:
        cur = conn.cursor()
        psycopg2.extras.execute_batch(
            cur,
            "INSERT INTO attack_patterns"
            " (event_id, attack_type, rule_name, matched_text, severity, confidence)"
            " VALUES (%s,%s,%s,%s,%s,'high')"
            " ON CONFLICT (event_id, attack_type, rule_name) DO NOTHING",
            rows,
            page_size=1000,
        )
        conn.commit()
        return len(rows)
    except psycopg2.Error as exc:
        conn.rollback()
        logger.error("pattern insert failed (is migration 0012 applied?): %s", exc)
        return 0
    finally:
        put_connection(conn)


def _drop_central_patterns() -> int:
    """Remove central-classifier rows from Suricata events. Those rules were written for
    attacker input and matched our own alert JSON -- 6,699 ``Custom_Exploit`` on sensor-a."""
    names = list(_central_rule_names())
    if not names:
        return 0
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM attack_patterns ap USING sensor_events e"
            " WHERE ap.event_id = e.event_id AND e.source = 'suricata'"
            " AND ap.rule_name = ANY(%s)",
            (names,),
        )
        conn.commit()
        return cur.rowcount
    except psycopg2.Error as exc:
        conn.rollback()
        logger.error("central pattern cleanup failed: %s", exc)
        return 0
    finally:
        put_connection(conn)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true", help="write (default: report only)")
    ap.add_argument(
        "--apply-drift",
        action="store_true",
        help="also re-label rows where today's signature rules disagree (reclassification, "
        "not repair; requires --apply)",
    )
    ap.add_argument(
        "--drop-central",
        action="store_true",
        help="also delete central-classifier pattern rows from Suricata events",
    )
    ap.add_argument("--page", type=int, default=20000, help="rows per page (default 20000)")
    ap.add_argument("--limit", type=int, default=0, help="stop after N events (0 = all)")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.apply_drift and not args.apply:
        logger.info("--apply-drift without --apply: reporting only, nothing will be written")

    stats: Counter = Counter()
    label_changes: Counter = Counter()
    drift_changes: Counter = Counter()
    last_event_id: str | None = None
    seen = 0

    while True:
        page = _fetch_page(last_event_id, args.page)
        if not page:
            break
        last_event_id = page[-1][0]

        updates: list[tuple[str, str]] = []
        patterns: list[tuple] = []
        pattern_moves: list[tuple[str, str, str]] = []

        for event_id, sid, signature, payload, current, dst_port, has_row in page:
            seen += 1
            derived = derive_label(sid, signature, payload, dst_port)
            if derived is None:
                stats["undecidable"] += 1
                continue
            attack_types, rule_name, severity = derived

            action = decide(current, attack_types)
            plan = plan_row(action, current, attack_types, relabel_drift=args.apply_drift)
            stats[plan.counter] += 1
            if plan.write_label:
                updates.append((attack_types, event_id))
            if plan.record_as_drift:
                drift_changes[(current, attack_types)] += 1
            elif plan.write_label:
                label_changes[((current or "(null)"), attack_types)] += 1
            if plan.move_pattern_to and has_row:
                # The pattern row still names the old type; move it or the next pass reverts.
                pattern_moves.append((plan.move_pattern_to, event_id, rule_name))

            # Every Suricata event needs its pattern row, including the ones whose label we did
            # not touch -- a label with no row behind it is what the next reprocess deletes.
            if not has_row:
                patterns.append(
                    (
                        event_id,
                        plan.pattern_type,
                        rule_name,
                        (signature or "")[:500],
                        severity,
                    )
                )
                stats["pattern_missing"] += 1

        if args.apply:
            if patterns:
                stats["patterns_written"] += _write_patterns(patterns)
            if pattern_moves:
                stats["patterns_repointed"] += _replace_pattern_types(pattern_moves)
            if updates:
                stats["labels_written"] += write_updates_batch(updates)

        logger.info(
            "%s events scanned | restored %s, corrected %s, already correct %s, "
            "missing pattern rows %s",
            seen,
            stats["restored"],
            stats["corrected"],
            stats["label_ok"],
            stats["pattern_missing"],
        )
        if args.limit and seen >= args.limit:
            break

    if args.drop_central:
        if args.apply:
            stats["central_dropped"] = _drop_central_patterns()
        else:
            logger.info("would delete central-classifier pattern rows from Suricata events")

    logger.info("--- %s", "APPLIED" if args.apply else "REPORT ONLY (use --apply to write)")
    for k in sorted(stats):
        logger.info("  %-20s %s", k, stats[k])
    for (before, after), n in label_changes.most_common(15):
        logger.info("  %r -> %r : %s", before, after, n)
    if drift_changes:
        logger.info(
            "--- rule drift, %s (today's signature rules disagree with the label these rows "
            "were given):",
            "RE-LABELLED" if (args.apply and args.apply_drift) else "reported only",
        )
        verb = "became" if (args.apply and args.apply_drift) else "would become"
        for (before, after), n in drift_changes.most_common(15):
            logger.info("  %r %s %r : %s", before, verb, after, n)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
