#!/usr/bin/env python3
"""backfill_rule_profile.py — label the history a newly added rule now covers.

`classification/rules/proxy_relay.py` added four rules on 2026-11-08 for the fleet's largest
unlabelled family: 12,197 HTTP `CONNECT` requests from 207 sources over 30 days on the public
sensor, 11,622 of them (95%) with no verdict at all. New rules only label new events, so this
pass is what makes the stored history agree with them.

**Additive, and that is the whole point.** The fleet already has a general tool for a rule
change -- `honeylens-auto-backfill`, which the nightly timer runs with `--apply` -- but it
reprocesses *every* event with `replace_patterns=True`, dropping pattern rows and clearing
tags it no longer derives. That is the right mode for a rule that was *tightened* and it is
the job whose first unattended run in that mode wiped decoy tags fleet-wide. This change
tightens nothing: it adds four rules and removes none, so the only history that needs
touching is the rows those four rules match. This tool writes `OPEN_PROXY_RELAY` beside
whatever a row already carries and deletes nothing, ever.

**It writes both halves.** A row whose `attack_types` names a verdict with no matching
`attack_patterns` row is the defect this project has already paid for twice, so the summary
column and the pattern rows are written in the same transaction or not at all.

**The rules decide, not a predicate written twice.** SQL narrows the candidates cheaply;
`classify_event_row` then says what each one is, so this tool cannot drift from the
classifier the way a hand-copied `WHERE` clause would.

    honeylens-backfill-rule-profile --list                            # the profiles
    honeylens-backfill-rule-profile open-proxy-relay                  # report, writes nothing
    honeylens-backfill-rule-profile open-proxy-relay --apply          # write
    honeylens-backfill-rule-profile wordpress-baits --apply --since-days 60

A **profile** is one rule addition: the rule names it introduced, and a cheap SQL predicate
that finds the rows those rules could possibly match. Adding a profile is how the next
additive rule change gets its history corrected; the alternative is the nightly authoritative
reprocess, which is right for a rule that was *tightened* and wrong for one that only adds.

Re-running is idempotent: a row already carrying the verdict is counted and skipped, and the
pattern insert is `ON CONFLICT DO NOTHING` against `idx_ap_event_type_rule` (migration 0012).
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.scoring import get_severity
from honeylens.database import db_cursor
from honeylens.sanitise import strip_nul

logger = logging.getLogger("backfill_rule_profile")


@dataclass(frozen=True)
class Profile:
    """One rule addition: what it introduced, and where its candidates live."""

    name: str
    rules: frozenset[str]
    slice_sql: str
    why: str


# One day at a time, bounded by the timestamp index. Every profile's SQL takes two parameters,
# the day offsets, and only has to be a cheap SUPERSET -- the rules decide what each candidate
# actually is, so the predicate can never drift from the classifier.
_BY_METHOD = """
    SELECT se.event_id, se.payload, se.protocol, se.metadata, se.attack_types
      FROM sensor_events se
     WHERE se.timestamp >= NOW() - (%s || ' days')::interval
       AND se.timestamp <  NOW() - (%s || ' days')::interval
       AND se.metadata->>'method' = %s
"""

_BY_PATH = """
    SELECT se.event_id, se.payload, se.protocol, se.metadata, se.attack_types
      FROM sensor_events se
     WHERE se.timestamp >= NOW() - (%s || ' days')::interval
       AND se.timestamp <  NOW() - (%s || ' days')::interval
       AND se.metadata ? 'path'
       AND (se.metadata->>'path' ILIKE ANY(%s) OR se.metadata->>'query' ILIKE ANY(%s))
"""

PROFILES: dict[str, Profile] = {
    "open-proxy-relay": Profile(
        name="open-proxy-relay",
        rules=frozenset(
            {
                "open_proxy_connect_request",
                "open_proxy_connect_json",
                "open_proxy_connect_no_authority",
                "open_proxy_reachability_check",
            }
        ),
        slice_sql=_BY_METHOD,
        why=(
            "12,197 CONNECT requests from 207 sources in 30 days on the public sensor, "
            "11,622 of them with no verdict at all"
        ),
    ),
    "credential-and-framework-gaps": Profile(
        name="credential-and-framework-gaps",
        rules=frozenset(
            {
                "aws_cli_credentials_file",
                "aws_beanstalk_dockerrun",
                "thinkphp_invokefunction",
                "thinkphp_invokefunction_exec",
                "docker_api_remote_list",
            }
        ),
        slice_sql=_BY_PATH,
        why=(
            "four shapes that matched nothing in the whole registry -- not the family verdict, "
            "not even SCANNER -- while GET /.env beside them matched three rules plus SCANNER: "
            "3,605 candidate rows over 30 days on the reachable fleet, 3,288 with no verdict"
        ),
    ),
    "wordpress-baits": Profile(
        name="wordpress-baits",
        rules=frozenset(
            {
                "wordpress_debug_log_probe",
                "wordpress_upgrade_window_probe",
                "wordpress_rest_batch",
            }
        ),
        slice_sql=_BY_PATH,
        why=(
            "the surfaces the CMS decoy baits: 34 requests for wp-content/debug.log, 25 for "
            "wp-content/upgrade/ and 238 for the REST batch route, all labelled SCANNER and "
            "nothing else"
        ),
    ),
}

# The same list on both sides of the predicate: `path` carries the shape for the AWS, Docker and
# path-form ThinkPHP rows, `query` carries it for the ThinkPHP rows whose path is a bare
# `/index.php`. An earlier draft of this also listed `%function=%` and `%vars[0]=%` on the query
# side for the escalation rule, which anchors on those keys -- that was a mistake: every row in
# the store matching them also contains `invokefunction` (measured, 2 of 2), and `%function=%`
# alone would drag the whole query-string corpus through an unindexable ILIKE on every day slice.
# The open-proxy backfill already paid for that lesson with a QueryCanceled on prod.
_GAP_SHAPES: list = [
    [
        "%.aws/credential%",
        "%.aws/config%",
        "%.aws/sso%",
        "%dockerrun.aws.json%",
        "%containers/json%",
        "%images/json%",
        "%invokefunction%",
    ],
]
_GAP_SHAPES.append(_GAP_SHAPES[0])

_SLICE_ARGS: dict[str, list] = {
    "open-proxy-relay": ["CONNECT"],
    # Deliberately a superset of what the five rules match -- the rules decide, this only has to
    # find the candidates cheaply. Verified 2026-11-08 that `path OR query` is sufficient: of the
    # rows whose PAYLOAD mentions `invokefunction`, the path-or-query predicate finds 140/140 on
    # sensor-a, 127/127 on sensor-b, 44/44 on sensor-c, 16/16 on sensor-e and 25/25 on prod. The only rows it
    # misses fleet-wide are 11 on sensor-a where an HTTP scanner spoke HTTP at the SSH and Redis
    # ports, so the row carries no `path` key at all; those are already labelled `SSH_SCAN`.
    "credential-and-framework-gaps": _GAP_SHAPES,
    "wordpress-baits": [
        ["%/wp-content/debug.log%", "%/wp-content/upgrade%", "%/wp-json/batch/v%"],
        ["%rest_route=/batch/%"],
    ],
}

_SLICE_TIMEOUT_MS = 120_000

_INSERT_PATTERN_SQL = """
    INSERT INTO attack_patterns (
        event_id, attack_type, rule_name, matched_text, severity, confidence
    )
    VALUES (%s, %s, %s, %s, %s, %s)
    ON CONFLICT DO NOTHING
"""

# `attack_types` is a comma-joined text column with no canonical order, so membership is a
# token test. `LIKE '%OPEN_PROXY_RELAY%'` would be wrong the day a longer label contains it.
_UPDATE_TYPES_SQL = """
    UPDATE sensor_events
       SET attack_types = CASE
               WHEN attack_types IS NULL OR attack_types = '' THEN %s
               ELSE attack_types || ',' || %s
           END
     WHERE event_id = %s
       AND NOT (%s = ANY(string_to_array(COALESCE(attack_types, ''), ',')))
"""


def _tokens(attack_types: str | None) -> set[str]:
    """`attack_types` as a set. The column is comma-joined text with no canonical order, so
    membership is a token test -- `LIKE '%X%'` is wrong the day a longer label contains X."""
    return {t.strip() for t in (attack_types or "").split(",") if t.strip()}


def backfill(
    profile: Profile, *, since_days: int, apply: bool, slice_args: list | None = None
) -> dict[str, int]:
    """Walk the window a day at a time and label the rows `profile`'s rules claim.

    The day slice is the unit of work and of recovery: it bounds each statement, and an
    interrupted run is simply a run that got partway, because re-running is idempotent -- a
    row already carrying a verdict is counted and its summary column left alone, while the
    pattern insert is `ON CONFLICT DO NOTHING` against `idx_ap_event_type_rule`.

    Additive only. A row keeps every verdict it already has; this adds the ones the new rules
    derive and removes nothing, which is the whole reason this exists instead of the
    authoritative reprocess.
    """
    args = slice_args if slice_args is not None else _SLICE_ARGS[profile.name]
    counts = {
        "slices": 0,
        "candidates": 0,
        "matched": 0,
        "already_tagged": 0,
        "types_written": 0,
        "patterns_written": 0,
    }
    for day in range(since_days, 0, -1):
        with db_cursor() as cur:
            cur.execute(f"SET LOCAL statement_timeout = '{_SLICE_TIMEOUT_MS}ms'")
            cur.execute(profile.slice_sql, (str(day), str(day - 1), *args))
            rows = cur.fetchall()
        counts["slices"] += 1
        counts["candidates"] += len(rows)

        for event_id, payload, protocol, metadata, attack_types in rows:
            # Only the rules this profile introduced. A row may already carry other verdicts
            # from rules that predate it, and those are none of this pass's business.
            hits = [
                (atype, rule, snippet)
                for atype, rule, snippet in classify_event_row(payload, protocol, metadata)
                if rule in profile.rules
            ]
            if not hits:
                continue
            counts["matched"] += 1
            have = _tokens(attack_types)
            wanted = {atype for atype, _rule, _snippet in hits}
            if wanted <= have:
                counts["already_tagged"] += 1
            if not apply:
                continue

            # One transaction per event: the summary column and its pattern rows land
            # together, or neither does.
            with db_cursor() as cur:
                for atype, rule, snippet in hits:
                    cur.execute(
                        _INSERT_PATTERN_SQL,
                        (
                            event_id,
                            atype,
                            rule,
                            strip_nul((snippet or "")[:500]),
                            get_severity(atype, rule),
                            "high",
                        ),
                    )
                    counts["patterns_written"] += cur.rowcount
                for atype in sorted(wanted - have):
                    cur.execute(_UPDATE_TYPES_SQL, (atype, atype, event_id, atype))
                    counts["types_written"] += cur.rowcount
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("profile", nargs="?", help="which rule addition to backfill")
    parser.add_argument("--list", action="store_true", help="print the profiles and exit")
    parser.add_argument("--apply", action="store_true", help="write (default is report only)")
    parser.add_argument("--dry-run", action="store_true", help="report only (the default)")
    parser.add_argument("--since-days", type=int, default=60, help="how far back to look")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    if args.list or not args.profile:
        for name, prof in PROFILES.items():
            print(f"{name}\n    rules: {', '.join(sorted(prof.rules))}\n    why:   {prof.why}")
        return 0 if args.list else 2
    if args.profile not in PROFILES:
        logger.error("unknown profile %r; --list shows them", args.profile)
        return 2

    profile = PROFILES[args.profile]
    apply = args.apply and not args.dry_run
    counts = backfill(profile, since_days=args.since_days, apply=apply)
    logger.info(
        "%s [%s]: %d day slices, %d candidates, %d matched by the rules, %d already tagged, "
        "%d summary columns written, %d pattern rows written",
        "APPLIED" if apply else "DRY RUN (nothing written)",
        profile.name,
        counts["slices"],
        counts["candidates"],
        counts["matched"],
        counts["already_tagged"],
        counts["types_written"],
        counts["patterns_written"],
    )
    if not apply:
        logger.info("re-run with --apply to write")
    return 0


if __name__ == "__main__":
    sys.exit(main())
