#!/usr/bin/env python3
"""
backfill_ics.py - Populate ics_events from existing attack_patterns
=====================================================================
Scans attack_patterns table for MODBUS and ICS_ATTACK entries
and creates corresponding ics_events records with MITRE mappings.

Usage:
    python backfill_ics.py              # Process all ICS patterns
    python backfill_ics.py --dry-run    # Test without writing
    python backfill_ics.py --limit 1000 # Process up to 1000
"""

import argparse
import logging
import time

from psycopg2.extras import execute_batch

from honeylens.database import legacy_get_db

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
)
logger = logging.getLogger("backfill_ics")

try:
    HAS_MITRE = True
except ImportError:
    HAS_MITRE = False
    logger.warning("mitre_mapping not available - MITRE fields will be empty")


# ICS function code classifications (same as ingest.py)
ICS_FUNCTION_CLASSES = {
    # text-rule names
    "modbus_read_coils": {"fc": 1, "is_read": True, "is_write": False, "severity": "LOW"},
    "modbus_read_discrete": {"fc": 2, "is_read": True, "is_write": False, "severity": "LOW"},
    "modbus_read_holding": {"fc": 3, "is_read": True, "is_write": False, "severity": "LOW"},
    "modbus_read_input": {"fc": 4, "is_read": True, "is_write": False, "severity": "LOW"},
    "modbus_write_single_coil": {"fc": 5, "is_read": False, "is_write": True, "severity": "HIGH"},
    "modbus_write_single_register": {
        "fc": 6,
        "is_read": False,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_write_multiple_coils": {
        "fc": 15,
        "is_read": False,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_write_multiple_registers": {
        "fc": 16,
        "is_read": False,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_mask_write_register": {
        "fc": 22,
        "is_read": False,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_read_write_registers": {
        "fc": 23,
        "is_read": True,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_read_device_id": {
        "fc": 43,
        "is_read": True,
        "is_write": False,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_report_slave_id": {
        "fc": 17,
        "is_read": True,
        "is_write": False,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_diagnostics": {
        "fc": 8,
        "is_read": False,
        "is_write": False,
        "is_control": True,
        "severity": "HIGH",
    },
    "modbus_restart_comm": {
        "fc": 8,
        "is_read": False,
        "is_write": False,
        "is_control": True,
        "severity": "CRITICAL",
    },
    # binary-detector names (ICS_ATTACK)
    "modbus_fc01_read_coils": {"fc": 1, "is_read": True, "severity": "LOW"},
    "modbus_fc02_read_discrete_inputs": {"fc": 2, "is_read": True, "severity": "LOW"},
    "modbus_fc03_read_holding_registers": {"fc": 3, "is_read": True, "severity": "LOW"},
    "modbus_fc04_read_input_registers": {"fc": 4, "is_read": True, "severity": "LOW"},
    "modbus_fc05_write_single_coil": {"fc": 5, "is_write": True, "severity": "HIGH"},
    "modbus_fc06_write_single_register": {"fc": 6, "is_write": True, "severity": "HIGH"},
    "modbus_fc08_diagnostics": {"fc": 8, "is_control": True, "severity": "HIGH"},
    "modbus_fc15_write_multiple_coils": {"fc": 15, "is_write": True, "severity": "HIGH"},
    "modbus_fc16_write_multiple_registers": {"fc": 16, "is_write": True, "severity": "HIGH"},
    "modbus_fc17_report_slave_id": {
        "fc": 17,
        "is_read": True,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_fc22_mask_write_register": {"fc": 22, "is_write": True, "severity": "HIGH"},
    "modbus_fc23_read_write_registers": {
        "fc": 23,
        "is_read": True,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_fc43_read_device_id": {
        "fc": 43,
        "is_read": True,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_illegal_fc": {"is_anomaly": True, "severity": "HIGH"},
    "modbus_user_defined_fc": {"is_anomaly": True, "severity": "MEDIUM"},
    "modbus_reserved_fc": {"is_anomaly": True, "severity": "MEDIUM"},
    # S7comm
    "s7comm_stop_cpu": {"is_control": True, "severity": "CRITICAL"},
    "s7comm_plc_stop": {"is_control": True, "severity": "CRITICAL"},
    "s7comm_write_var": {"is_write": True, "severity": "HIGH"},
    "s7comm_download_block": {"is_write": True, "severity": "CRITICAL"},
    # DNP3
    "dnp3_cold_restart": {"is_control": True, "severity": "CRITICAL"},
    "dnp3_warm_restart": {"is_control": True, "severity": "HIGH"},
    "dnp3_direct_operate": {"is_write": True, "severity": "HIGH"},
    "dnp3_direct_operate_noack": {"is_write": True, "severity": "HIGH"},
    "dnp3_select": {"is_write": True, "severity": "MEDIUM"},
    "dnp3_operate": {"is_write": True, "severity": "HIGH"},
    "dnp3_write_request": {"is_write": True, "severity": "HIGH"},
    # BACnet
    "bacnet_write_property": {"is_write": True, "severity": "HIGH"},
    "bacnet_write_property_multiple": {"is_write": True, "severity": "HIGH"},
    "bacnet_reinitialize": {"is_control": True, "severity": "CRITICAL"},
    "bacnet_reinitialize_device": {"is_control": True, "severity": "CRITICAL"},
    # OPC-UA
    "opcua_write": {"is_write": True, "severity": "HIGH"},
    "opcua_call_method": {"is_control": True, "severity": "HIGH"},
    # IEC-104
    "iec104_single_command": {"is_write": True, "severity": "HIGH"},
    "iec104_single_command_time": {"is_write": True, "severity": "HIGH"},
    "iec104_double_command": {"is_write": True, "severity": "HIGH"},
    "iec104_setpoint": {"is_write": True, "severity": "HIGH"},
    "iec104_setpoint_command": {"is_write": True, "severity": "HIGH"},
    "iec104_reset_process": {"is_control": True, "severity": "CRITICAL"},
    "iec104_regulating_step": {"is_write": True, "severity": "HIGH"},
    "iec104_parameter_change": {"is_write": True, "severity": "MEDIUM"},
    "iec104_parameter_activation": {"is_control": True, "severity": "HIGH"},
}


def get_connection():
    return legacy_get_db()


def check_tables():
    """Check required tables exist."""
    conn = get_connection()
    cur = conn.cursor()

    # Check attack_patterns
    cur.execute("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_name = 'attack_patterns'
        )
    """)
    has_patterns = cur.fetchone()[0]

    # Check ics_events
    cur.execute("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_name = 'ics_events'
        )
    """)
    has_ics = cur.fetchone()[0]

    conn.close()
    return has_patterns, has_ics


def get_ics_pattern_count():
    """Count ICS patterns to process."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT COUNT(*) FROM attack_patterns
        WHERE attack_type IN ('MODBUS', 'ICS_ATTACK')
          AND event_id NOT IN (SELECT event_id FROM ics_events)
    """)
    count = cur.fetchone()[0]
    conn.close()
    return count


# ---------------------------------------------------------------------------
# ICS MITRE selector — shared helper used by all ingest paths
# ---------------------------------------------------------------------------
_ICS_RULE_WRITE = frozenset(
    [
        "write",
        "operate",
        "direct_operate",
        "set_attribute",
        "set_password",
        "setpoint",
        "double_command",
        "single_command",
        "regulating_step",
        "download_block",
        "write_var",
        "write_property",
        "write_property_multiple",
        "opcua_write",
        "cip_set_attribute",
        "cip_execute",
        "bacnet_reinitialize",
        "bacnet_reinitialize_device",
        "iec104_setpoint_command",
        "iec104_parameter_change",
    ]
)
_ICS_RULE_CONTROL = frozenset(
    [
        "restart",
        "cold_restart",
        "warm_restart",
        "stop_cpu",
        "plc_stop",
        "plc_control",
        "reset_process",
        "parameter_activation",
        "diagnostics",
        "reinitialize",
        "cip_reset",
        "cip_stop_service",
        "stopdt",
        "disable_unsolicited",
        "dnp3_broadcast",
        "iec104_stopdt_act",
    ]
)
_ICS_RULE_SCAN = frozenset(
    [
        "scanner",
        "shodan",
        "banner_grab",
        "port_scan",
        "nmap",
        "plcscan",
        "plcinfo",
        "aegis",
        "bacpypes",
        "ics_port_scan",
        "ics_shodan_query",
        "ics_banner_grab",
        "metasploit",
        "caldera",
    ]
)
_ICS_RULE_ENUMERATE = frozenset(
    [
        "list_identity",
        "list_services",
        "list_interfaces",
        "list_blocks",
        "whois",
        "whohas",
        "iam",
        "device_discovery",
        "get_attributes",
        "get_all_attributes",
        "interrogation",
        "counter_interrogation",
        "bacnet_whois",
        "bacnet_whohas",
        "enip_list",
        "report_slave_id",
        "read_device_id",
        "find_servers",
        "read_szl",
        "cpu_info",
        "s7comm_header",
        "data_link_probe",
    ]
)
_ICS_RULE_DISCOVERY = frozenset(
    [
        "browse",
        "opcua_browse",
        "opcua_find_servers",
        "opcua_create_subscription",
        "bacnet_subscribe_cov",
        "read_range",
        "history_read",
        "enip_register_session",
        "enip_send_rr_data",
        "register_session",
        "startdt",
        "agent_beacon",
        "c2_api",
        "cotp_connect",
    ]
)
_ICS_RULE_READ = frozenset(
    [
        "read_property",
        "read_property_multiple",
        "read_request",
        "read_attributes",
        "read_command",
        "opcua_read_attributes",
        "bacnet_read_property",
        "bacnet_read_property_multiple",
        "iec104_read_command",
        "dnp3_read_request",
        "clear_restart_iin",
        "enable_unsolicited",
    ]
)


def _ics_op_from_rule(rule_name: str) -> str:
    r = rule_name.lower()
    for t in _ICS_RULE_SCAN:
        if t in r:
            return "scan"
    for t in _ICS_RULE_CONTROL:
        if t in r:
            return "control"
    for t in _ICS_RULE_WRITE:
        if t in r:
            return "write"
    for t in _ICS_RULE_ENUMERATE:
        if t in r:
            return "enumerate"
    for t in _ICS_RULE_DISCOVERY:
        if t in r:
            return "discovery"
    for t in _ICS_RULE_READ:
        if t in r:
            return "read"
    return "unknown"


def _pick_ics_mitre(atype: str, rule_name: str, fc_info: dict):
    """Return (technique, tactic) for an ICS classifier hit.
    Tactics stored as slugs: 'collection-ics', 'impair-process-control', etc."""
    try:
        from honeylens.classification.mitre_mapping import get_mitre_mapping as _gmm
    except ImportError:
        return None, None
    mappings = _gmm(atype)
    if not mappings:
        return None, None
    if fc_info.get("is_anomaly"):
        op = "anomaly"
    elif fc_info.get("is_control"):
        op = "control"
    elif fc_info.get("is_write"):
        op = "write"
    elif fc_info.get("is_discovery"):
        op = "enumerate"
    elif fc_info.get("is_read"):
        op = "read"
    else:
        op = _ics_op_from_rule(rule_name)
    matchers = {
        "read": (lambda t: "collection" in t, lambda f: f == "read"),
        "enumerate": (lambda t: "collection" in t, lambda f: f == "discovery"),
        "discovery": (lambda t: "discovery" in t, None),
        "scan": (lambda t: "discovery" in t, None),
        "write": (lambda t: "impair" in t, lambda f: f == "write"),
        "control": (lambda t: "impair" in t or "inhibit" in t, lambda f: f == "control"),
        "anomaly": (lambda t: "inhibit" in t, None),
        "command": (lambda t: "execution" in t, None),
        "unknown": (lambda t: False, None),
    }
    tactic_ok, for_ok = matchers.get(op, (lambda t: False, None))
    for m in mappings:
        if not tactic_ok(m.get("tactic", "")):
            continue
        if for_ok is not None and not for_ok(m.get("for", "")):
            continue
        return m["technique"], m["tactic"]
    for m in mappings:
        if tactic_ok(m.get("tactic", "")):
            return m["technique"], m["tactic"]
    return mappings[0]["technique"], mappings[0]["tactic"]


def parse_ics_event(row):
    """
    Parse attack_patterns row into ics_events record.

    row: (event_id, attack_type, rule_name, matched_text, timestamp,
          src_ip, src_port, dst_ip, dst_port)
    """
    (
        event_id,
        attack_type,
        rule_name,
        _matched_text,
        timestamp,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    ) = row

    # Determine protocol from rule name
    protocol = "ics-generic"
    if rule_name.startswith("modbus_"):
        protocol = "modbus"
    elif rule_name.startswith("dnp3_"):
        protocol = "dnp3"
    elif rule_name.startswith("s7comm_"):
        protocol = "s7comm"
    elif rule_name.startswith("enip_") or rule_name.startswith("cip_"):
        protocol = "enip"
    elif rule_name.startswith("bacnet_"):
        protocol = "bacnet"
    elif rule_name.startswith("opcua_"):
        protocol = "opcua"
    elif rule_name.startswith("iec104_"):
        protocol = "iec104"
    elif rule_name.startswith("caldera_"):
        protocol = "caldera"
    elif dst_port:
        # Detect from port
        port_map = {
            502: "modbus",
            102: "s7comm",
            20000: "dnp3",
            44818: "enip",
            47808: "bacnet",
            4840: "opcua",
            2404: "iec104",
        }
        protocol = port_map.get(dst_port, "ics-generic")

    # Get classification
    fc_info = ICS_FUNCTION_CLASSES.get(rule_name, {})

    # MITRE mapping
    mitre_technique, mitre_tactic = _pick_ics_mitre(attack_type, rule_name, fc_info)

    # Severity
    severity = fc_info.get("severity", "MEDIUM")
    if "scanner" in rule_name or "probe" in rule_name:
        severity = "LOW"
    elif "restart" in rule_name or "stop" in rule_name or "crash" in rule_name:
        severity = "CRITICAL"
    elif "write" in rule_name or "download" in rule_name:
        severity = "HIGH"

    function_name = rule_name.replace("modbus_", "").replace("dnp3_", "").replace("s7comm_", "")
    function_name = function_name.replace("_", " ").title()

    return (
        event_id,
        timestamp,
        protocol,
        fc_info.get("fc"),
        function_name[:64] if function_name else None,
        str(src_ip) if src_ip else None,
        src_port,
        str(dst_ip) if dst_ip else None,
        dst_port,
        fc_info.get("is_read", False),
        fc_info.get("is_write", False),
        fc_info.get("is_control", False),
        fc_info.get("is_discovery", False),
        mitre_tactic,
        mitre_technique,
        attack_type,
        rule_name,
        "backfill",
        severity,
    )


def backfill(dry_run=False, limit=None):
    """Run backfill."""
    has_patterns, has_ics = check_tables()

    if not has_patterns:
        logger.error("attack_patterns table not found")
        return

    if not has_ics:
        logger.error("ics_events table not found - run setup_db.py first")
        return

    total = get_ics_pattern_count()
    if limit:
        total = min(total, limit)

    if total == 0:
        logger.info("No ICS patterns to process")
        return

    logger.info("Processing %s ICS patterns%s", total, " (dry run)" if dry_run else "")

    conn = get_connection()
    cur = conn.cursor()

    # Fetch patterns with event metadata
    query = """
        SELECT ap.event_id, ap.attack_type, ap.rule_name, ap.matched_text,
               se.timestamp, se.src_ip, se.src_port, se.dst_ip, se.dst_port
        FROM attack_patterns ap
        JOIN sensor_events se ON ap.event_id = se.event_id
        WHERE ap.attack_type IN ('MODBUS', 'ICS_ATTACK')
          AND ap.event_id NOT IN (SELECT event_id FROM ics_events)
    """
    if limit:
        query += f" LIMIT {limit}"

    cur.execute(query)
    rows = cur.fetchall()

    start_time = time.time()
    processed = 0
    errors = 0

    insert_sql = """
        INSERT INTO ics_events (
            event_id, timestamp, protocol, function_code, function_name,
            src_ip, src_port, dst_ip, dst_port,
            is_read, is_write, is_control, is_discovery,
            mitre_tactic, mitre_technique, attack_type, rule_name,
            source, severity
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (event_id) DO NOTHING
    """

    batch = []
    batch_size = 1000

    for row in rows:
        try:
            ics_record = parse_ics_event(row)
            batch.append(ics_record)

            if len(batch) >= batch_size:
                if not dry_run:
                    execute_batch(cur, insert_sql, batch, page_size=500)
                    conn.commit()
                processed += len(batch)
                batch = []

                elapsed = time.time() - start_time
                rate = processed / elapsed if elapsed > 0 else 0
                logger.info(
                    "Progress: %s/%s (%s%%) - %s/sec",
                    f"{processed:,}",
                    f"{total:,}",
                    f"{100 * processed / total:.1f}",
                    f"{rate:.0f}",
                )

        except Exception as e:
            errors += 1
            logger.debug("Error processing %s: %s", row[0], e)

    # Final batch
    if batch:
        if not dry_run:
            execute_batch(cur, insert_sql, batch, page_size=500)
            conn.commit()
        processed += len(batch)

    conn.close()

    elapsed = time.time() - start_time
    rate = processed / elapsed if elapsed > 0 else 0

    logger.info("=" * 60)
    logger.info("Backfill complete%s", " (dry run)" if dry_run else "")
    logger.info("  Processed: %s", processed)
    logger.info("  Errors: %s", errors)
    logger.info("  Time: %ss | Rate: %s/sec", elapsed, rate)


def fix_mitre(dry_run=False):
    """UPDATE ics_events rows with NULL mitre_technique/tactic using _pick_ics_mitre."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT event_id, attack_type, rule_name
        FROM ics_events
        WHERE mitre_technique IS NULL OR mitre_tactic IS NULL
    """)
    rows = cur.fetchall()
    if not rows:
        logger.info("No rows with NULL MITRE fields")
        conn.close()
        return
    logger.info("Fixing MITRE on %s rows", len(rows))
    updated = 0
    for event_id, attack_type, rule_name in rows:
        fc_info = ICS_FUNCTION_CLASSES.get(rule_name or "", {})
        tech, tactic = _pick_ics_mitre(attack_type or "ICS_ATTACK", rule_name or "", fc_info)
        if not dry_run:
            cur.execute(
                "UPDATE ics_events SET mitre_technique=%s, mitre_tactic=%s WHERE event_id=%s",
                (tech, tactic, event_id),
            )
        updated += 1
    if not dry_run:
        conn.commit()
        logger.info("Fixed MITRE on %s rows", updated)
    else:
        logger.info("[dry-run] Would fix %s rows", updated)
    conn.close()


def fix_registers(dry_run=False):
    """UPDATE ics_events rows with NULL register fields from sensor_events.metadata."""
    import json as _json

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT ie.event_id, se.metadata
        FROM ics_events ie
        JOIN sensor_events se ON ie.event_id = se.event_id
        WHERE ie.protocol = 'modbus'
          AND (ie.unit_id IS NULL OR ie.register_start IS NULL
               OR ie.register_count IS NULL OR ie.data_value IS NULL)
          AND se.metadata IS NOT NULL
    """)
    rows = cur.fetchall()
    if not rows:
        logger.info("No ics_events rows with missing register fields")
        conn.close()
        return
    logger.info("Fixing register fields on %s rows", len(rows))
    updated = 0
    for event_id, metadata_raw in rows:
        try:
            meta = (
                _json.loads(metadata_raw) if isinstance(metadata_raw, str) else (metadata_raw or {})
            )
        except Exception as _exc:
            logging.getLogger(__name__).debug("skipping row with bad metadata: %s", _exc)
            continue
        unit_id = meta.get("unit_id")
        register_start = meta.get("address")
        register_count = meta.get("quantity")
        _dv = meta.get("value")
        if _dv is None and meta.get("pdu_hex"):
            _dv = meta["pdu_hex"]
        data_value = str(_dv) if _dv is not None else None
        if all(v is None for v in (unit_id, register_start, register_count, data_value)):
            continue
        if not dry_run:
            cur.execute(
                """
                UPDATE ics_events
                SET unit_id        = COALESCE(unit_id,        %s),
                    register_start = COALESCE(register_start, %s),
                    register_count = COALESCE(register_count, %s),
                    data_value     = COALESCE(data_value,     %s)
                WHERE event_id = %s
            """,
                (unit_id, register_start, register_count, data_value, event_id),
            )
        updated += 1
    if not dry_run:
        conn.commit()
        logger.info("Fixed register fields on %s rows", updated)
    else:
        logger.info("[dry-run] Would fix %s rows", updated)
    conn.close()


def normalize_tactics(dry_run=False):
    """Normalise mitre_tactic to slugs and recompute mitre_technique for ALL rows.

    Fixes:
    - Title-cased tactics ('Collection Ics') -> slugs ('collection-ics')
    - Wrong technique assignments from the old ICS_FUNCTION_CLASSES gap
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT event_id, attack_type, rule_name, mitre_tactic, mitre_technique
        FROM ics_events
        WHERE mitre_tactic IS NOT NULL OR mitre_technique IS NOT NULL
    """)
    rows = cur.fetchall()
    if not rows:
        logger.info("No ics_events rows to normalise")
        conn.close()
        return
    logger.info("Normalising MITRE fields on %s rows", len(rows))
    updated = 0
    for event_id, attack_type, rule_name, old_tactic, old_technique in rows:
        fc_info = ICS_FUNCTION_CLASSES.get(rule_name or "", {})
        new_technique, new_tactic = _pick_ics_mitre(
            attack_type or "ICS_ATTACK", rule_name or "", fc_info
        )
        if new_tactic == old_tactic and new_technique == old_technique:
            continue
        if not dry_run:
            cur.execute(
                "UPDATE ics_events SET mitre_tactic=%s, mitre_technique=%s WHERE event_id=%s",
                (new_tactic, new_technique, event_id),
            )
        else:
            logger.debug(
                "[dry-run] %s... %r/%r -> %r/%r",
                event_id[:8],
                old_technique,
                old_tactic,
                new_technique,
                new_tactic,
            )
        updated += 1
    if not dry_run:
        conn.commit()
        logger.info("Normalised %s rows", updated)
    else:
        logger.info("[dry-run] Would normalise %s rows", updated)
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="Backfill ICS events from attack patterns")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Test without writing")
    parser.add_argument("--limit", "-l", type=int, help="Max records to process")
    parser.add_argument(
        "--fix-mitre",
        action="store_true",
        help="UPDATE existing ics_events rows that have NULL MITRE fields",
    )
    parser.add_argument(
        "--fix-registers",
        action="store_true",
        help="UPDATE existing ics_events rows that have NULL unit_id/register fields",
    )
    parser.add_argument(
        "--normalize-tactics",
        action="store_true",
        help="Normalise mitre_tactic to slug format and recompute mitre_technique",
    )
    args = parser.parse_args()

    try:
        if args.fix_mitre:
            fix_mitre(dry_run=args.dry_run)
        elif args.fix_registers:
            fix_registers(dry_run=args.dry_run)
        elif args.normalize_tactics:
            normalize_tactics(dry_run=args.dry_run)
        else:
            backfill(dry_run=args.dry_run, limit=args.limit)
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error("Error: %s", e)
        raise


if __name__ == "__main__":
    main()
