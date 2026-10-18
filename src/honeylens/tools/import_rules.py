#!/usr/bin/env python3
"""
tools/import_rules.py — Import custom rules from JSON bundle
================================================================
Idea 42 Phase 1: Import AI-generated custom detection rules from a
signed JSON bundle exported by another HoneyLens sensor.

Usage:
    python -m tools.import_rules rules.json
    python -m tools.import_rules rules.json --on-conflict=overwrite
    python -m tools.import_rules rules.json --on-conflict=rename
    python -m tools.import_rules rules.json --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime

from honeylens.database import legacy_get_db

# Validation constants
MAX_BUNDLE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_RULES = 500
RULE_NAME_RE = re.compile(r"^[A-Z0-9_]{3,128}$")
TAG_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_CATEGORIES = {
    "SQL_INJECTION",
    "XSS",
    "LFI",
    "RFI",
    "COMMAND_INJECTION",
    "DIRECTORY_TRAVERSAL",
    "AUTHENTICATION",
    "BRUTE_FORCE",
    "WEB_EXPLOIT",
    "SCANNER",
    "PROTOCOL_ABUSE",
    "SMB",
    "SSH_ATTACK",
    "FTP_ATTACK",
    "RDP_ATTACK",
    "TELNET_ATTACK",
    "MQTT_ATTACK",
    "MODBUS_ATTACK",
    "ICS_ATTACK",
    "K8S_ATTACK",
    "DNS_ATTACK",
    "SMTP_ATTACK",
    "VNC_ATTACK",
    "REDIS_ATTACK",
    "MYSQL_ATTACK",
    "MSSQL_ATTACK",
    "HTTP_EXPLOIT",
    "BOT",
    "MALWARE",
    "CRYPTO_MINER",
    "C2_BEACON",
    "AI_DETECTED",
    "UNKNOWN",
    "LLM_LLM01",
    "LLM_LLM02",
    "LLM_LLM03",
    "LLM_LLM04",
    "LLM_LLM05",
    "LLM_LLM06",
    "LLM_LLM07",
    "LLM_LLM08",
    "LLM_LLM09",
    "LLM_LLM10",
}


def validate_bundle(data: dict) -> tuple:
    """Validate bundle structure. Returns (is_valid, error_message)."""
    header = data.get("honeylens_rule_bundle")
    if not header:
        return False, "Missing honeylens_rule_bundle header"
    if header.get("format") != "honeylens-rules-v1":
        return False, f"Unknown format: {header.get('format')}"
    if header.get("version") != 1:
        return False, f"Unknown version: {header.get('version')}"

    rules = data.get("rules")
    if not isinstance(rules, list):
        return False, "Missing or invalid rules array"
    if len(rules) > MAX_RULES:
        return False, f"Too many rules: {len(rules)} (max {MAX_RULES})"
    if len(rules) != header.get("rule_count", -1):
        return False, f"Rule count mismatch: {len(rules)} vs header {header.get('rule_count')}"

    # SHA-256 integrity check
    rules_json = json.dumps(rules, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(rules_json.encode()).hexdigest()
    if header.get("sha256") != expected:
        return False, "SHA-256 mismatch: bundle corrupted"

    return True, None


def validate_rule(rule: dict) -> tuple:
    """Validate a single rule. Returns (is_valid, error_or_None)."""
    name = rule.get("rule_name", "")
    if not RULE_NAME_RE.match(name):
        return False, f"Invalid rule_name: {name!r}"

    regex = rule.get("rule_regex", "")
    if not regex or len(regex) > 2048:
        return False, f"Invalid rule_regex length for {name}"
    try:
        re.compile(regex)
    except re.error as e:
        return False, f"Invalid regex for {name}: {e}"

    category = rule.get("rule_category", "")
    if category not in VALID_CATEGORIES:
        return False, f"Unknown category for {name}: {category}"

    severity = rule.get("rule_severity", "")
    if severity not in VALID_SEVERITIES:
        return False, f"Invalid severity for {name}: {severity}"

    return True, None


def import_rules(args):
    # Read and parse bundle
    with open(args.bundle) as f:
        raw = f.read()
    if len(raw) > MAX_BUNDLE_SIZE:
        print(f"ERROR: Bundle too large ({len(raw):,} bytes, max {MAX_BUNDLE_SIZE:,})")
        sys.exit(1)

    data = json.loads(raw)

    # Validate bundle
    valid, error = validate_bundle(data)
    if not valid:
        print(f"ERROR: {error}")
        sys.exit(1)

    header = data["honeylens_rule_bundle"]
    rules = data["rules"]
    print(f"Bundle: {header['rule_count']} rules from {header['exported_from']['sensor_id']}")
    print(f"Exported: {header['exported_at']}")
    print(f"SHA-256: {header['sha256'][:16]}... ✓")
    print()

    # Validate each rule
    valid_rules = []
    skipped = 0
    for rule in rules:
        ok, err = validate_rule(rule)
        if ok:
            valid_rules.append(rule)
        else:
            print(f"  SKIP: {err}")
            skipped += 1

    # Deduplicate within bundle
    seen_names = set()
    deduped = []
    for rule in valid_rules:
        if rule["rule_name"] in seen_names:
            print(f"  SKIP: Duplicate rule_name {rule['rule_name']}")
            skipped += 1
        else:
            seen_names.add(rule["rule_name"])
            deduped.append(rule)
    valid_rules = deduped

    print(f"Valid: {len(valid_rules)}, Skipped: {skipped}")

    if args.dry_run:
        print("\nDry run — no changes made. Rules that would be imported:")
        for r in valid_rules:
            print(f"  {r['rule_name']:40s} {r['rule_category']:20s} {r['rule_severity']}")
        return

    # Import to database
    conn = legacy_get_db()
    cur = conn.cursor()

    imported = 0
    conflicts = 0
    for rule in valid_rules:
        # Check if exists
        cur.execute(
            "SELECT rule_name FROM ai_custom_rules WHERE rule_name = %s", (rule["rule_name"],)
        )
        exists = cur.fetchone()

        if exists:
            if args.on_conflict == "skip":
                conflicts += 1
                continue
            elif args.on_conflict == "overwrite":
                cur.execute(
                    "DELETE FROM ai_custom_rules WHERE rule_name = %s", (rule["rule_name"],)
                )
            elif args.on_conflict == "rename":
                # Find next available suffix
                for i in range(1, 100):
                    new_name = f"{rule['rule_name']}_IMPORTED_{i}"
                    cur.execute("SELECT 1 FROM ai_custom_rules WHERE rule_name = %s", (new_name,))
                    if not cur.fetchone():
                        rule["rule_name"] = new_name
                        break

        # Insert
        cur.execute(
            """
            INSERT INTO ai_custom_rules (
                rule_name, regex_pattern, attack_type, severity,
                description, mitre_technique, source_model,
                event_id, approved_by, approved_at,
                enabled, pending_review, tags
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, FALSE, %s
            )
        """,
            (
                rule["rule_name"],
                rule["rule_regex"],
                rule["rule_category"],
                rule["rule_severity"],
                (rule.get("rule_description") or "")[:512],
                rule.get("mitre_technique", ""),
                rule.get("source_model", "imported"),
                rule.get("source_event_id", ""),
                rule.get("approved_by", "import"),
                rule.get("approved_at") or datetime.now(UTC).isoformat(),
                rule.get("enabled", True),
                rule.get("tags") or [],
            ),
        )
        imported += 1

    conn.commit()
    conn.close()

    print(
        f"\nImported: {imported}, Conflicts: {conflicts} ({args.on_conflict}), Skipped: {skipped}"
    )
    if imported > 0:
        print("Rules are active immediately. Reload classifier to apply.")


def main():
    parser = argparse.ArgumentParser(description="Import custom rules from JSON bundle")
    parser.add_argument("bundle", help="Path to rules JSON bundle")
    parser.add_argument(
        "--on-conflict",
        choices=["skip", "overwrite", "rename"],
        default="skip",
        help="Conflict resolution (default: skip)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate without importing")
    args = parser.parse_args()
    import_rules(args)


if __name__ == "__main__":
    main()
