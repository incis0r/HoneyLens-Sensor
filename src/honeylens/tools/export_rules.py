#!/usr/bin/env python3
"""
tools/export_rules.py — Export custom rules to JSON bundle
=============================================================
Idea 42 Phase 1: Export AI-generated custom detection rules as a
signed JSON bundle for import on other HoneyLens sensors.

Usage:
    python -m tools.export_rules -o rules.json
    python -m tools.export_rules -o rules.json --include-disabled
    python -m tools.export_rules -o rules.json --category WEB_EXPLOIT
    python -m tools.export_rules --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
from datetime import UTC, datetime

import psycopg2.extras

from honeylens.database import legacy_get_db
from honeylens.version import VERSION


def export_rules(args):
    conn = legacy_get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    sql = "SELECT * FROM ai_custom_rules"
    conditions = []
    params = []

    if not args.include_disabled:
        conditions.append("enabled = TRUE")
    if args.category:
        conditions.append("rule_category = %s")
        params.append(args.category.upper())
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY rule_name"

    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    # Filter by tag if requested
    if args.tag:
        rows = [r for r in rows if args.tag in (r.get("tags") or [])]

    # Build rules array
    rules = []
    for r in rows:
        rule = {
            "rule_name": r.get("rule_name", ""),
            "rule_regex": r.get("rule_regex") or r.get("regex_pattern", ""),
            "rule_category": r.get("rule_category") or r.get("attack_type", "UNKNOWN"),
            "rule_severity": r.get("rule_severity") or r.get("severity", "MEDIUM"),
            "rule_description": r.get("rule_description") or r.get("description", ""),
            "mitre_technique": r.get("mitre_technique", ""),
            "source_model": r.get("source_model", ""),
            "source_event_id": r.get("source_event_id") or r.get("event_id", ""),
            "approved_by": r.get("approved_by", ""),
            "approved_at": r["approved_at"].isoformat() if r.get("approved_at") else "",
            "enabled": bool(r.get("enabled", True)),
            "tags": r.get("tags") or [],
            "test_payloads": r.get("test_payloads") or [],
        }
        rules.append(rule)

    # Build bundle
    rules_json = json.dumps(rules, sort_keys=True, separators=(",", ":"))
    sha256 = hashlib.sha256(rules_json.encode()).hexdigest()

    bundle = {
        "honeylens_rule_bundle": {
            "version": 1,
            "format": "honeylens-rules-v1",
            "exported_at": datetime.now(UTC).isoformat(),
            "exported_from": {
                "sensor_id": f"sensor-{socket.gethostname()}",
                "sensor_version": VERSION,
                "hostname": socket.gethostname(),
            },
            "rule_count": len(rules),
            "sha256": sha256,
        },
        "rules": rules,
    }

    if args.dry_run:
        print(f"Would export {len(rules)} rules")
        for r in rules:
            print(f"  {r['rule_name']:40s} {r['rule_category']:20s} {r['rule_severity']}")
        return

    output = json.dumps(bundle, indent=2, default=str)

    if args.output == "-":
        print(output)
    else:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Exported {len(rules)} rules to {args.output} ({len(output):,} bytes)")
        print(f"SHA-256: {sha256}")


def main():
    parser = argparse.ArgumentParser(description="Export custom rules to JSON bundle")
    parser.add_argument("-o", "--output", default="-", help="Output file (- for stdout)")
    parser.add_argument("--include-disabled", action="store_true", help="Include disabled rules")
    parser.add_argument("--category", help="Filter by attack category")
    parser.add_argument("--tag", help="Filter by tag")
    parser.add_argument("--dry-run", action="store_true", help="Print summary without writing")
    args = parser.parse_args()
    export_rules(args)


if __name__ == "__main__":
    main()
