#!/usr/bin/env python3
"""
cleanup_false_positives.py — Remove False Positive Attack Detections
=====================================================================
Identifies and removes known false positive attack patterns from the database,
then optionally re-classifies affected events with the updated attack classifier.

Known False Positives Fixed:
- ICS_ATTACK rules triggering on HTTP/HTTPS traffic (Caldera, DNP3, S7comm, etc.)
- SUPPLY_CHAIN typosquat_requests matching HTTP headers
- mqtt_qos_abuse matching any byte 0x34/0x35 (ASCII 4/5)
- MODBUS binary patterns matching random TLS/HTTP data

Usage:
    python cleanup_false_positives.py --dry-run          # Preview what would be deleted
    python cleanup_false_positives.py --execute          # Delete false positives
    python cleanup_false_positives.py --execute --reclassify  # Delete and re-classify
    python cleanup_false_positives.py --stats            # Show current FP statistics

Requirements:
    pip install psycopg2-binary

⚠️  BACKUP YOUR DATABASE BEFORE RUNNING WITH --execute
"""

import argparse
import json
import logging
import sys
from typing import Any

try:
    import psycopg2.extras

    from honeylens.database import legacy_get_db
except ImportError:
    print("ERROR: core.database not available. Run from sensor directory.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================


# HTTP-related ports where ICS rules should NOT have triggered
HTTP_PORTS = {
    80,
    443,
    8080,
    8443,
    8000,
    8008,
    8888,
    3000,
    3443,
    5000,
    # K8s/Container ports
    6443,
    8001,
    10250,
    10255,
    # FortiGate honeypot
    9443,
}

# False positive rule patterns to remove
# Format: (rule_name, condition) where condition is SQL or None for unconditional
FALSE_POSITIVE_RULES = {
    # -------------------------------------------------------------------------
    # ICS_ATTACK rules that should NOT match on HTTP ports
    # -------------------------------------------------------------------------
    # Caldera rules (match on web APIs, JSON configs)
    "caldera_ability_execute": "http_port",
    "caldera_agent_beacon": "http_port",
    "caldera_c2_api": "http_port",
    "caldera_payload_download": "http_port",
    "caldera_executor_config": "http_port",
    "caldera_adversary_profile": "http_port",
    "caldera_ics_fieldmanual": "http_port",
    # Generic ICS recon patterns
    "ics_port_scan": "http_port",
    "ics_shodan_query": "http_port",
    "ics_banner_grab": "http_port",
    # S7comm patterns (match TLS handshakes, binary data)
    "s7comm_header": "http_port",
    "s7comm_list_blocks": "http_port",
    "s7comm_read_szl": "http_port",
    "s7comm_cpu_info": "http_port",
    "s7comm_download_block": "http_port",
    "s7comm_write_var": "http_port",
    "s7comm_stop_cpu": "http_port",
    "s7comm_plc_control": "http_port",
    "s7comm_set_clock": "http_port",
    "s7comm_set_password": "http_port",
    "s7comm_scanner_plcscan": "http_port",
    "s7comm_metasploit": "http_port",
    # DNP3 patterns
    "dnp3_data_link_probe": "http_port",
    "dnp3_read_request": "http_port",
    "dnp3_cold_restart": "http_port",
    "dnp3_warm_restart": "http_port",
    "dnp3_disable_unsolicited": "http_port",
    "dnp3_direct_operate": "http_port",
    "dnp3_select_operate": "http_port",
    "dnp3_write_request": "http_port",
    "dnp3_file_transfer": "http_port",
    "dnp3_clear_restart_iin": "http_port",
    "dnp3_scanner_aegis": "http_port",
    # IEC-104 patterns
    "iec104_startdt": "http_port",
    "iec104_interrogation": "http_port",
    "iec104_read_command": "http_port",
    "iec104_counter_interrogation": "http_port",
    "iec104_single_command": "http_port",
    "iec104_double_command": "http_port",
    "iec104_regulating_step": "http_port",
    "iec104_setpoint": "http_port",
    "iec104_reset_process": "http_port",
    "iec104_scanner": "http_port",
    # BACnet patterns
    "bacnet_whois": "http_port",
    "bacnet_device_discovery": "http_port",
    "bacnet_read_property": "http_port",
    "bacnet_read_property_multiple": "http_port",
    "bacnet_read_range": "http_port",
    "bacnet_write_property": "http_port",
    "bacnet_write_property_multiple": "http_port",
    "bacnet_subscribe_cov": "http_port",
    "bacnet_reinitialize": "http_port",
    "bacnet_scanner_bacpypes": "http_port",
    # EtherNet/IP patterns
    "enip_list_identity": "http_port",
    "enip_list_services": "http_port",
    "enip_list_interfaces": "http_port",
    "cip_get_attributes": "http_port",
    "cip_get_all_attributes": "http_port",
    "cip_set_attribute": "http_port",
    "cip_execute": "http_port",
    "cip_reset_service": "http_port",
    "cip_stop_service": "http_port",
    "enip_scanner_nmap": "http_port",
    "enip_scanner_plcinfo": "http_port",
    # OPC UA patterns
    "opcua_find_servers": "http_port",
    "opcua_browse": "http_port",
    "opcua_read_attributes": "http_port",
    "opcua_create_subscription": "http_port",
    "opcua_history_read": "http_port",
    "opcua_write": "http_port",
    "opcua_call_method": "http_port",
    "opcua_no_security": "http_port",
    "opcua_scanner": "http_port",
    # Modbus binary patterns (match random binary data)
    "modbus_read_coils": "http_port",
    "modbus_read_discrete_inputs": "http_port",
    "modbus_read_holding_registers": "http_port",
    "modbus_read_input_registers": "http_port",
    "modbus_write_coil_binary": "http_port",
    "modbus_write_register_binary": "http_port",
    "modbus_write_multi_coils_binary": "http_port",
    "modbus_write_multi_registers_binary": "http_port",
    "modbus_diagnostics_binary": "http_port",
    "modbus_device_id_binary": "http_port",
    "modbus_report_slave_binary": "http_port",
    "modbus_broadcast_binary": "http_port",
    "modbus_illegal_fc_binary": "http_port",
    # -------------------------------------------------------------------------
    # Rules to remove unconditionally (too many false positives)
    # -------------------------------------------------------------------------
    # Old mqtt_qos_abuse matched \x34|\x35 (ASCII 4 or 5) - massive FPs
    "mqtt_qos_abuse": "all",
    # typosquat_requests old pattern matched HTTP "Request:" headers
    "typosquat_requests": "all",
    # credential_combo_list old pattern matched binary data with @ and :
    # Pattern was: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+:[^\s]{6,}
    # Matched: K@z:.y3���, H@X:eWL#�, etc.
    "credential_combo_list": "all",
    # nosql_mongo_injection old pattern used \w which matches Unicode/Cyrillic
    # Pattern was: (\{|\[)\s*['\"]?\$\w+['\"]?\s*:
    # Matched: {$шM : (binary garbage decoded as Cyrillic)
    "nosql_mongo_injection": "all",
    # RCE chain patterns used \w which matches Unicode/Cyrillic
    # Matched: ш;NC, ё;wget (binary garbage decoded as Cyrillic + command)
    "rce_chain_network": "all",
    "rce_chain_cat_ls": "all",
    "rce_chain_id_whoami": "all",
    "rce_chain_shell": "all",
    "rce_chain_python": "all",
    "rce_chain_dangerous": "all",
    "rce_chain_admin": "all",
    # Old rule rce_pipe_semicolon no longer exists but records remain in DB
    # Matched: ; Nmap in User-Agent strings
    "rce_pipe_semicolon": "all",
    # rce_backtick_subst old pattern used [^\s`]+ which matched binary garbage
    # Binary data with backticks + short commands (id, ls) caused false positives
    # Matched: `JwY..., `id ���`
    "rce_backtick_subst": "all",
    # mqtt_default_creds old pattern matched admin/admin without MQTT context
    # Pattern was: \b(admin|root|mqtt|...)/(admin|password|...)\b
    # Matched on any text containing "admin/admin" regardless of protocol
    "mqtt_default_creds": "all",
    # iot_default_creds old pattern matched admin:admin without IoT context
    # Pattern was: (admin:admin|root:root|...) - too generic
    "iot_default_creds": "all",
    # mqtt_qos2_publish matched payloads starting with '4','5','6','7' (0x34-0x37)
    # These are ASCII digits that appear in many protocols (Modbus, HTTP, etc.)
    "mqtt_qos2_publish": "all",
    # mqtt_large_payload matched payloads starting with '0' (0x30)
    "mqtt_large_payload": "all",
}


# =============================================================================
# Database Functions
# =============================================================================


def get_db_connection():
    """Get database connection."""
    return legacy_get_db()


def get_false_positive_stats(conn) -> dict[str, dict]:
    """Get statistics on potential false positives."""
    cur = conn.cursor()

    stats: dict[str, Any] = {
        "by_rule": {},
        "by_type": {},
        "total_fps": 0,
        "total_attack_patterns": 0,
    }

    # Get total attack patterns
    cur.execute("SELECT COUNT(*) FROM attack_patterns")
    stats["total_attack_patterns"] = cur.fetchone()[0]

    # Build port tuple for parameterized queries
    port_tuple = tuple(HTTP_PORTS)

    # Count potential FPs by rule
    for rule_name, condition in FALSE_POSITIVE_RULES.items():
        if condition == "all":
            cur.execute(
                """
                SELECT COUNT(*) FROM attack_patterns
                WHERE rule_name = %s
            """,
                (rule_name,),
            )
        elif condition == "http_port":
            cur.execute(
                """
                SELECT COUNT(*) FROM attack_patterns ap
                JOIN sensor_events se ON ap.event_id = se.event_id
                WHERE ap.rule_name = %s
                  AND se.dst_port IN %s
            """,
                (rule_name, port_tuple),
            )
        else:
            continue

        count = cur.fetchone()[0]
        if count > 0:
            stats["by_rule"][rule_name] = count
            stats["total_fps"] += count

    # Get FPs by attack type
    http_rules = [r for r, c in FALSE_POSITIVE_RULES.items() if c == "http_port"]
    all_rules_list = [r for r, c in FALSE_POSITIVE_RULES.items() if c == "all"]
    cur.execute(
        """
        SELECT ap.attack_type, COUNT(*)
        FROM attack_patterns ap
        JOIN sensor_events se ON ap.event_id = se.event_id
        WHERE (
            -- HTTP port condition
            (ap.rule_name = ANY(%s)
             AND se.dst_port IN %s)
            OR
            -- Unconditional removals
            ap.rule_name = ANY(%s)
        )
        GROUP BY ap.attack_type
        ORDER BY COUNT(*) DESC
    """,
        (http_rules, port_tuple, all_rules_list),
    )

    for row in cur.fetchall():
        stats["by_type"][row[0]] = row[1]

    return stats


def get_sample_false_positives(conn, limit: int = 10) -> list[dict]:
    """Get sample false positive events for review."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    port_tuple = tuple(HTTP_PORTS)
    http_rules = [r for r, c in FALSE_POSITIVE_RULES.items() if c == "http_port"]
    all_rules = [r for r, c in FALSE_POSITIVE_RULES.items() if c == "all"]

    cur.execute(
        """
        SELECT
            ap.id,
            ap.event_id,
            ap.attack_type,
            ap.rule_name,
            se.dst_port,
            se.protocol,
            LEFT(se.payload, 200) as payload_preview,
            se.timestamp
        FROM attack_patterns ap
        JOIN sensor_events se ON ap.event_id = se.event_id
        WHERE (
            (ap.rule_name = ANY(%s)
             AND se.dst_port IN %s)
            OR
            ap.rule_name = ANY(%s)
        )
        ORDER BY se.timestamp DESC
        LIMIT %s
    """,
        (http_rules, port_tuple, all_rules, limit),
    )

    return [dict(row) for row in cur.fetchall()]


def delete_false_positives(conn, dry_run: bool = True) -> tuple[int, list[str]]:
    """Delete false positive attack patterns."""
    cur = conn.cursor()

    deleted_total = 0
    deleted_rules = []

    port_tuple = tuple(HTTP_PORTS)

    for rule_name, condition in FALSE_POSITIVE_RULES.items():
        if condition == "all":
            if dry_run:
                cur.execute(
                    """
                    SELECT COUNT(*) FROM attack_patterns
                    WHERE rule_name = %s
                """,
                    (rule_name,),
                )
                count = cur.fetchone()[0]
            else:
                cur.execute(
                    """
                    DELETE FROM attack_patterns
                    WHERE rule_name = %s
                """,
                    (rule_name,),
                )
                count = cur.rowcount

        elif condition == "http_port":
            if dry_run:
                cur.execute(
                    """
                    SELECT COUNT(*) FROM attack_patterns ap
                    JOIN sensor_events se ON ap.event_id = se.event_id
                    WHERE ap.rule_name = %s
                      AND se.dst_port IN %s
                """,
                    (rule_name, port_tuple),
                )
                count = cur.fetchone()[0]
            else:
                cur.execute(
                    """
                    DELETE FROM attack_patterns ap
                    USING sensor_events se
                    WHERE ap.event_id = se.event_id
                      AND ap.rule_name = %s
                      AND se.dst_port IN %s
                """,
                    (rule_name, port_tuple),
                )
                count = cur.rowcount
        else:
            continue

        if count > 0:
            deleted_rules.append(f"{rule_name}: {count}")
            deleted_total += count
            logger.info(
                "  %s %s patterns for rule: %s",
                "Would delete" if dry_run else "Deleted",
                count,
                rule_name,
            )

    if not dry_run:
        conn.commit()

    return deleted_total, deleted_rules


def get_affected_event_ids(conn, limit: int = 10000) -> list[str]:
    """Get event IDs that had false positives removed (for re-classification)."""
    cur = conn.cursor()

    port_tuple = tuple(HTTP_PORTS)
    http_rules = [r for r, c in FALSE_POSITIVE_RULES.items() if c == "http_port"]
    all_rules = [r for r, c in FALSE_POSITIVE_RULES.items() if c == "all"]

    cur.execute(
        """
        SELECT DISTINCT ap.event_id
        FROM attack_patterns ap
        JOIN sensor_events se ON ap.event_id = se.event_id
        WHERE (
            (ap.rule_name = ANY(%s)
             AND se.dst_port IN %s)
            OR
            ap.rule_name = ANY(%s)
        )
        LIMIT %s
    """,
        (http_rules, port_tuple, all_rules, limit),
    )

    return [row[0] for row in cur.fetchall()]


def reclassify_events(conn, event_ids: list[str], batch_size: int = 100) -> int:
    """Re-classify events with updated attack classifier."""
    try:
        from honeylens.classification.attack_classifier import (
            classify_attack_summary,
            classify_event_row,
        )
    except ImportError:
        logger.error("Could not import attack_classifier. Skipping re-classification.")
        return 0

    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    reclassified = 0
    total = len(event_ids)

    for i in range(0, total, batch_size):
        batch_ids = event_ids[i : i + batch_size]

        # Get event data
        cur.execute(
            """
            SELECT event_id, payload, protocol, dst_port, metadata
            FROM sensor_events
            WHERE event_id = ANY(%s)
        """,
            (batch_ids,),
        )

        events = cur.fetchall()

        for event in events:
            event_id = event["event_id"]
            payload = event["payload"]
            protocol = event["protocol"]

            # Build metadata
            metadata = event.get("metadata") or {}
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except Exception:
                    metadata = {}
            metadata["dst_port"] = event["dst_port"]

            # Re-classify
            hits = classify_event_row(payload, protocol, metadata)

            if hits:
                # Get existing patterns for this event - use a regular cursor for this query
                cur2 = conn.cursor()  # Regular cursor returns tuples
                cur2.execute(
                    """
                    SELECT rule_name FROM attack_patterns
                    WHERE event_id = %s
                """,
                    (event_id,),
                )
                existing_rules = {row[0] for row in cur2.fetchall()}
                cur2.close()

                # Add new patterns (that don't already exist)
                for attack_type, rule_name, snippet in hits:
                    if rule_name not in existing_rules:
                        cur.execute(
                            """
                            INSERT INTO attack_patterns (event_id, attack_type, rule_name, matched_text)
                            VALUES (%s, %s, %s, %s)
                            ON CONFLICT DO NOTHING
                        """,
                            (event_id, attack_type, rule_name, snippet[:500]),
                        )

                # Update attack_types summary in sensor_events
                summary = classify_attack_summary(hits)
                if summary:
                    cur.execute(
                        """
                        UPDATE sensor_events SET attack_types = %s
                        WHERE event_id = %s
                    """,
                        (summary, event_id),
                    )

            reclassified += 1

        conn.commit()

        if (i + batch_size) % 1000 == 0 or i + batch_size >= total:
            logger.info("  Re-classified %s/%s events", min(i + batch_size, total), total)

    return reclassified


def update_event_attack_types(conn) -> int:
    """Update attack_types column in sensor_events based on attack_patterns."""
    cur = conn.cursor()

    logger.info("Updating attack_types in sensor_events...")

    # Update attack_types to reflect current attack_patterns
    cur.execute("""
        UPDATE sensor_events se
        SET attack_types = subq.types
        FROM (
            SELECT
                event_id,
                STRING_AGG(DISTINCT attack_type, ',' ORDER BY attack_type) as types
            FROM attack_patterns
            GROUP BY event_id
        ) subq
        WHERE se.event_id = subq.event_id
          AND (se.attack_types IS DISTINCT FROM subq.types)
    """)

    updated = cur.rowcount

    # Clear attack_types for events with no patterns
    cur.execute("""
        UPDATE sensor_events se
        SET attack_types = NULL
        WHERE se.attack_types IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM attack_patterns ap
            WHERE ap.event_id = se.event_id
          )
    """)

    cleared = cur.rowcount

    conn.commit()

    logger.info("  Updated %s events, cleared %s events", updated, cleared)

    return updated + cleared


# =============================================================================
# Main
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Remove false positive attack detections from database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python cleanup_false_positives.py --stats
    python cleanup_false_positives.py --dry-run
    python cleanup_false_positives.py --execute
    python cleanup_false_positives.py --execute --reclassify
    python cleanup_false_positives.py --sample 20

⚠️  Always run --dry-run first to preview changes!
        """,
    )

    parser.add_argument("--stats", action="store_true", help="Show false positive statistics")
    parser.add_argument(
        "--sample", type=int, metavar="N", help="Show N sample false positive events"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview what would be deleted (no changes)"
    )
    parser.add_argument("--execute", action="store_true", help="Actually delete false positives")
    parser.add_argument(
        "--reclassify", action="store_true", help="Re-classify affected events after deletion"
    )
    parser.add_argument(
        "--update-summary", action="store_true", help="Update attack_types column in sensor_events"
    )
    parser.add_argument(
        "--batch", type=int, default=100, help="Batch size for re-classification (default: 100)"
    )

    args = parser.parse_args()

    if not any([args.stats, args.sample, args.dry_run, args.execute, args.update_summary]):
        parser.print_help()
        return

    conn = get_db_connection()

    try:
        # Show statistics
        if args.stats or args.dry_run:
            print("\n" + "=" * 70)
            print("FALSE POSITIVE STATISTICS")
            print("=" * 70)

            stats = get_false_positive_stats(conn)

            print(f"\nTotal attack patterns in database: {stats['total_attack_patterns']:,}")
            print(f"Potential false positives: {stats['total_fps']:,}")

            if stats["total_attack_patterns"] > 0:
                pct = (stats["total_fps"] / stats["total_attack_patterns"]) * 100
                print(f"False positive rate: {pct:.1f}%")

            if stats["by_type"]:
                print("\nBy Attack Type:")
                for atype, count in sorted(stats["by_type"].items(), key=lambda x: -x[1]):
                    print(f"  {atype:20s}: {count:,}")

            if stats["by_rule"] and args.dry_run:
                print("\nBy Rule (top 20):")
                for rule, count in sorted(stats["by_rule"].items(), key=lambda x: -x[1])[:20]:
                    print(f"  {rule:40s}: {count:,}")

            print()

        # Show sample false positives
        if args.sample:
            print("\n" + "=" * 70)
            print(f"SAMPLE FALSE POSITIVES (showing {args.sample})")
            print("=" * 70 + "\n")

            samples = get_sample_false_positives(conn, args.sample)

            for i, sample in enumerate(samples, 1):
                print(f"--- Sample {i} ---")
                print(f"  Event ID:    {sample['event_id']}")
                print(f"  Attack Type: {sample['attack_type']}")
                print(f"  Rule:        {sample['rule_name']}")
                print(f"  Port:        {sample['dst_port']}")
                print(f"  Protocol:    {sample['protocol']}")
                print(f"  Timestamp:   {sample['timestamp']}")
                print(f"  Payload:     {sample['payload_preview'][:100]}...")
                print()

        # Dry run
        if args.dry_run:
            print("\n" + "=" * 70)
            print("DRY RUN - No changes will be made")
            print("=" * 70 + "\n")

            deleted, _rules = delete_false_positives(conn, dry_run=True)

            print(f"\nWould delete {deleted:,} false positive patterns")
            print("\nRun with --execute to apply changes")

        # Execute deletion
        if args.execute:
            print("\n" + "=" * 70)
            print("EXECUTING FALSE POSITIVE CLEANUP")
            print("=" * 70 + "\n")

            # Get affected event IDs before deletion (for re-classification)
            affected_ids = []
            if args.reclassify:
                logger.info("Collecting affected event IDs...")
                affected_ids = get_affected_event_ids(conn)
                logger.info("Found %s affected events", len(affected_ids))

            # Delete false positives
            logger.info("Deleting false positive patterns...")
            deleted, _rules = delete_false_positives(conn, dry_run=False)

            print(f"\n✅ Deleted {deleted:,} false positive patterns")

            # Re-classify affected events
            if args.reclassify and affected_ids:
                print("\n" + "-" * 40)
                logger.info("Re-classifying affected events...")
                reclassified = reclassify_events(conn, affected_ids, args.batch)
                print(f"✅ Re-classified {reclassified:,} events")

            # Update summary column
            print("\n" + "-" * 40)
            update_event_attack_types(conn)

            print("\n✅ Cleanup complete!")
            print("\nRecommendation: Run VACUUM ANALYZE to reclaim space:")
            print("  psql -d sensor -c 'VACUUM ANALYZE attack_patterns;'")

        # Just update summary
        if args.update_summary and not args.execute:
            print("\n" + "=" * 70)
            print("UPDATING ATTACK_TYPES SUMMARY")
            print("=" * 70 + "\n")

            updated = update_event_attack_types(conn)
            print(f"✅ Updated {updated:,} events")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
