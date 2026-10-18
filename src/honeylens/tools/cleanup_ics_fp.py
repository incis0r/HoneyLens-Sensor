#!/usr/bin/env python3
"""
cleanup_ics_fp.py — Remove ICS/MODBUS false positives from ics_events and attack_patterns.

Deletes rows where ICS/S7/DNP3/caldera rules fired on traffic with no genuine
ICS context (wrong port, non-ICS source, non-ICS protocol).

Tables:
  ics_events       — direct delete of FP rows
  attack_patterns  — delete FP rule hits
  sensor_events    — rebuild attack_types TEXT column

Usage:
  python cleanup_ics_fp.py [--dry-run] [--verbose]
"""

import argparse

from psycopg2 import sql as psql

from honeylens.database import legacy_get_db

ICS_PORTS = (
    102,
    502,
    20000,
    44818,
    2222,
    47808,
    4840,
    4843,
    2404,
    1911,
    9600,
    18245,
    5094,
    1883,
    8883,
)

ICS_SOURCES = (
    "honeypotng",
    "honeypot_k8s",
    "ics-honeypot",
    "ics-sensor",
    "modbus-honeypot",
    "dnp3-honeypot",
    "s7comm-honeypot",
    "enip-honeypot",
    "bacnet-honeypot",
    "iec104-honeypot",
    "opcua-honeypot",
)

ICS_PROTOCOLS = (
    "modbus",
    "modbus_tcp",
    "modbus/tcp",
    "dnp3",
    "s7comm",
    "s7",
    "enip",
    "ethernet/ip",
    "bacnet",
    "opcua",
    "opc-ua",
    "opc_ua",
    "iec104",
    "iec60870",
    "mqtt",
)

# Complete set of rules that require ICS context — derived from
# _ICS_PORT_CONTEXT_RULES | _ICS_ALL_TEXT_RULES in attack_classifier.py
ICS_GATED_RULES = [
    "bacnet_device_discovery",
    "bacnet_read_property",
    "bacnet_read_property_multiple",
    "bacnet_read_range",
    "bacnet_reinitialize",
    "bacnet_scanner_bacpypes",
    "bacnet_subscribe_cov",
    "bacnet_whois",
    "bacnet_write_property",
    "bacnet_write_property_multiple",
    "caldera_ability_execute",
    "caldera_adversary_profile",
    "caldera_agent_beacon",
    "caldera_c2_api",
    "caldera_executor_config",
    "caldera_ics_fieldmanual",
    "caldera_payload_download",
    "cip_execute",
    "cip_get_all_attributes",
    "cip_get_attributes",
    "cip_reset_service",
    "cip_set_attribute",
    "cip_stop_service",
    "dnp3_clear_restart_iin",
    "dnp3_cold_restart",
    "dnp3_data_link_probe",
    "dnp3_direct_operate",
    "dnp3_disable_unsolicited",
    "dnp3_file_transfer",
    "dnp3_read_request",
    "dnp3_scanner_aegis",
    "dnp3_select_operate",
    "dnp3_warm_restart",
    "dnp3_write_request",
    "enip_list_identity",
    "enip_list_interfaces",
    "enip_list_services",
    "enip_scanner_nmap",
    "enip_scanner_plcinfo",
    "ics_banner_grab",
    "ics_port_scan",
    "ics_shodan_query",
    "iec104_counter_interrogation",
    "iec104_double_command",
    "iec104_interrogation",
    "iec104_read_command",
    "iec104_regulating_step",
    "iec104_reset_process",
    "iec104_scanner",
    "iec104_setpoint",
    "iec104_single_command",
    "modbus_broadcast_unit_id",
    "modbus_crash_plc",
    "modbus_critical_register_write",
    "modbus_diagnostics",
    "modbus_illegal_fc_reserved",
    "modbus_illegal_fc_user_defined",
    "modbus_mask_write_register",
    "modbus_read_device_id",
    "modbus_read_exception",
    "modbus_read_file_record",
    "modbus_read_write_registers",
    "modbus_register_max_value",
    "modbus_register_zero_value",
    "modbus_report_slave_id",
    "modbus_restart_comm",
    "modbus_scanner_mbtget",
    "modbus_scanner_metasploit_modbus",
    "modbus_scanner_modbuspwn",
    "modbus_scanner_smod",
    "modbus_schneider_quantum",
    "modbus_schneider_unity",
    "modbus_siemens_s7_probe",
    "modbus_write_file_record",
    "modbus_write_multiple_coils",
    "modbus_write_multiple_registers",
    "modbus_write_single_coil",
    "modbus_write_single_register",
    "opcua_browse",
    "opcua_call_method",
    "opcua_create_subscription",
    "opcua_find_servers",
    "opcua_hello",
    "opcua_history_read",
    "opcua_no_security",
    "opcua_read_attributes",
    "opcua_scanner",
    "opcua_write",
    "s7comm_cpu_info",
    "s7comm_download_block",
    "s7comm_header",
    "s7comm_list_blocks",
    "s7comm_metasploit",
    "s7comm_plc_control",
    "s7comm_read_szl",
    "s7comm_scanner_plcscan",
    "s7comm_set_clock",
    "s7comm_set_password",
    "s7comm_stop_cpu",
    "s7comm_write_var",
]

# Caldera rules: purged from ics_events unconditionally (never valid there)
CALDERA_RULES = [
    "caldera_agent_beacon",
    "caldera_c2_api",
    "caldera_payload_download",
    "caldera_ability_execute",
    "caldera_executor_config",
    "caldera_adversary_profile",
    "caldera_ics_fieldmanual",
]

NO_ICS_SQL = psql.SQL("""
    NOT (
        se.dst_port = ANY(%(ports)s)
        OR se.src_port = ANY(%(ports)s)
        OR se.source = ANY(%(sources)s)
        OR lower(coalesce(se.protocol,'')) = ANY(%(protos)s)
    )
""")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    conn = legacy_get_db()
    cur = conn.cursor()

    p = dict(ports=list(ICS_PORTS), sources=list(ICS_SOURCES), protos=list(ICS_PROTOCOLS))

    # ── 1. FP rows in ics_events (joined to sensor_events for context) ────────
    cur.execute(
        psql.SQL("""
        SELECT ie.event_id, ie.dst_port, ie.src_port, ie.source,
               ie.protocol, ie.rule_name
        FROM ics_events ie
        JOIN sensor_events se ON ie.event_id = se.event_id
        WHERE ie.rule_name = ANY(%(rules)s)
          AND {}
        ORDER BY ie.event_id
    """).format(NO_ICS_SQL),
        dict(**p, rules=ICS_GATED_RULES),
    )
    ics_rows = cur.fetchall()
    ics_ids = [r[0] for r in ics_rows]
    print(f"ics_events FPs (wrong context):  {len(ics_rows)}")
    if args.verbose:
        for eid, dp, sp, src, proto, rule in ics_rows:
            print(f"  {eid[:20]}... dst={dp} src_port={sp} src={src} proto={proto} rule={rule}")

    # ── 2. FP rows in attack_patterns (same context check) ───────────────────
    cur.execute(
        psql.SQL("""
        SELECT DISTINCT se.event_id
        FROM sensor_events se
        JOIN attack_patterns ap ON se.event_id = ap.event_id
        WHERE ap.rule_name = ANY(%(rules)s)
          AND {}
    """).format(NO_ICS_SQL),
        dict(**p, rules=ICS_GATED_RULES),
    )
    ap_ids = [r[0] for r in cur.fetchall()]
    print(f"attack_patterns FPs:             {len(ap_ids)}")

    # ── 3. Caldera rows in ics_events — unconditional purge ──────────────────
    cur.execute("SELECT event_id FROM ics_events WHERE rule_name = ANY(%s)", (CALDERA_RULES,))
    caldera_ids = [r[0] for r in cur.fetchall()]
    print(f"ics_events caldera rows (purge): {len(caldera_ids)}")

    total = len(set(ics_ids + ap_ids + caldera_ids))
    print(f"\nTotal unique events affected: {total}")

    if total == 0:
        print("Nothing to clean up.")
        conn.close()
        return

    if args.dry_run:
        print("\n[DRY RUN] No changes made.")
        conn.close()
        return

    # ── Apply ─────────────────────────────────────────────────────────────────
    if ics_ids:
        cur.execute(
            """
            DELETE FROM ics_events
            WHERE event_id = ANY(%s) AND rule_name = ANY(%s)
        """,
            (ics_ids, ICS_GATED_RULES),
        )
        print(f"\nDeleted {cur.rowcount} rows from ics_events (no ICS context)")

    if caldera_ids:
        cur.execute("DELETE FROM ics_events WHERE rule_name = ANY(%s)", (CALDERA_RULES,))
        print(f"Deleted {cur.rowcount} caldera rows from ics_events (unconditional)")

    if ap_ids:
        cur.execute(
            """
            DELETE FROM attack_patterns
            WHERE event_id = ANY(%s) AND rule_name = ANY(%s)
        """,
            (ap_ids, ICS_GATED_RULES),
        )
        print(f"Deleted {cur.rowcount} rows from attack_patterns")

        cur.execute(
            """
            UPDATE sensor_events se
            SET attack_types = (
                SELECT string_agg(DISTINCT ap.attack_type, ',' ORDER BY ap.attack_type)
                FROM attack_patterns ap WHERE ap.event_id = se.event_id
            )
            WHERE se.event_id = ANY(%s)
        """,
            (ap_ids,),
        )
        print(f"Rebuilt attack_types on {cur.rowcount} sensor_events rows")

    conn.commit()
    conn.close()
    print("\n✓ Done.")


if __name__ == "__main__":
    main()
