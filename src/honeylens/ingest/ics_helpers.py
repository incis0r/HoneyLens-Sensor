"""
ingest/ics_helpers.py — ICS/OT Event Helpers (Shared)
=======================================================
Extracted from ingest.py and ingest_honeypot.py to eliminate duplication.

Contains:
    - ICS port/protocol validation
    - ICS function code mapping (50+ entries)
    - MITRE ICS tactic selection
    - ICS event row builder

Usage:
    from honeylens.ingest.ics_helpers import ics_context, build_ics_row, ICS_FC
"""

from __future__ import annotations

import re
from typing import Any

# ── ICS Valid Ports ───────────────────────────────────────────────────────

ICS_VALID_PORTS = frozenset(
    {
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
    }
)

ICS_VALID_PROTOCOLS = frozenset(
    {
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
    }
)

# Service ports that legitimately carry each ICS protocol. Used by the PASSIVE
# eBPF capture path, where `protocol` is *inferred from payload bytes* and is
# therefore unreliable — the binary detectors are port-agnostic, so the
# sensor's own outbound traffic (e.g. the Ollama API on :11434, or an internal
# service on :3100) gets misread as Modbus / IEC-104 / ENIP / OPC-UA. Anchoring
# a passively-classified protocol to its real service port drops those false
# positives. (The honeypot ingest path keeps using ics_context(), where the
# protocol is ground truth.)
ICS_PROTO_PORTS = {
    "modbus": {502},
    "s7comm": {102},
    "mms": {102},
    "dnp3": {20000, 19999},
    "enip": {44818, 2222},
    "bacnet": {47808},
    "opcua": {4840, 4843},
    "iec104": {2404},
    "fins": {9600},
    "melsec": {5006, 5007},
    "fox": {1911},
    "profinet": {34964},
    "mqtt": {1883, 8883},
    "coap": {5683},
}


def ics_port_consistent(protocol: Any, src_port: Any, dst_port: Any) -> bool:
    """True when the flow's ports are consistent with an ICS session.

    A specific protocol must see its own service port (as source — our
    honeypot's reply — or destination — an inbound probe); a generic/unknown
    ICS hit must see *some* valid ICS port. Otherwise the detection is the
    sensor's own outbound traffic misread as ICS, and is a false positive.
    """
    ports = set()
    for p in (src_port, dst_port):
        try:
            ports.add(int(p))
        except (TypeError, ValueError):
            pass
    expected = ICS_PROTO_PORTS.get(str(protocol).lower()) if protocol else None
    if expected:
        return bool(ports & expected)
    return bool(ports & set(ICS_VALID_PORTS))


# ── Caldera Rules (excluded from ICS) ────────────────────────────────────

CALDERA_RULES = frozenset(
    {
        "caldera_agent_beacon",
        "caldera_c2_api",
        "caldera_payload_download",
        "caldera_ability_execute",
        "caldera_executor_config",
        "caldera_adversary_profile",
        "caldera_ics_fieldmanual",
    }
)

# ── ICS Function Code Mapping ────────────────────────────────────────────
# Maps rule_name → {fc, is_read, is_write, is_control, is_discovery, severity}

ICS_FC = {
    # Modbus — named rules
    "modbus_read_coils": {"fc": 1, "is_read": True, "severity": "LOW"},
    "modbus_read_discrete": {"fc": 2, "is_read": True, "severity": "LOW"},
    "modbus_read_holding": {"fc": 3, "is_read": True, "severity": "LOW"},
    "modbus_read_input": {"fc": 4, "is_read": True, "severity": "LOW"},
    "modbus_write_single_coil": {"fc": 5, "is_write": True, "severity": "HIGH"},
    "modbus_write_single_register": {"fc": 6, "is_write": True, "severity": "HIGH"},
    "modbus_write_multiple_coils": {"fc": 15, "is_write": True, "severity": "HIGH"},
    "modbus_write_multiple_registers": {"fc": 16, "is_write": True, "severity": "HIGH"},
    "modbus_mask_write_register": {"fc": 22, "is_write": True, "severity": "HIGH"},
    "modbus_read_write_registers": {
        "fc": 23,
        "is_read": True,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_read_device_id": {
        "fc": 43,
        "is_read": True,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_report_slave_id": {
        "fc": 17,
        "is_read": True,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_diagnostics": {"fc": 8, "is_control": True, "severity": "HIGH"},
    "modbus_restart_comm": {"fc": 8, "is_control": True, "severity": "CRITICAL"},
    # Modbus — binary-detector names (modbus_fc##_*)
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
    "modbus_user_defined_fc": {"is_anomaly": True, "severity": "MEDIUM"},
    "modbus_reserved_fc": {"is_anomaly": True, "severity": "HIGH"},
    "modbus_illegal_fc": {"is_anomaly": True, "severity": "HIGH"},
    # S7comm
    "s7comm_stop_cpu": {"is_control": True, "severity": "CRITICAL"},
    "s7comm_write_var": {"is_write": True, "severity": "HIGH"},
    "s7comm_download_block": {"is_write": True, "severity": "CRITICAL"},
    # DNP3
    "dnp3_cold_restart": {"is_control": True, "severity": "CRITICAL"},
    "dnp3_warm_restart": {"is_control": True, "severity": "HIGH"},
    "dnp3_direct_operate": {"is_write": True, "severity": "HIGH"},
    "dnp3_write_request": {"is_write": True, "severity": "HIGH"},
    # BACnet
    "bacnet_write_property": {"is_write": True, "severity": "HIGH"},
    "bacnet_reinitialize": {"is_control": True, "severity": "CRITICAL"},
    # OPC-UA
    "opcua_write": {"is_write": True, "severity": "HIGH"},
    "opcua_call_method": {"is_control": True, "severity": "HIGH"},
    # IEC 104
    "iec104_single_command": {"is_write": True, "severity": "HIGH"},
    "iec104_double_command": {"is_write": True, "severity": "HIGH"},
    "iec104_setpoint": {"is_write": True, "severity": "HIGH"},
    "iec104_reset_process": {"is_control": True, "severity": "CRITICAL"},
}


# ── ICS Operation Classification Sets ────────────────────────────────────

ICS_RULE_WRITE = frozenset(
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
ICS_RULE_CONTROL = frozenset(
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
ICS_RULE_SCAN = frozenset(
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
ICS_RULE_ENUMERATE = frozenset(
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
ICS_RULE_DISCOVERY = frozenset(
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
ICS_RULE_READ = frozenset(
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


# ── Helper Functions ─────────────────────────────────────────────────────


def ics_context(dst_port: Any, src_port: Any, protocol: Any) -> bool:
    """Return True when traffic is in genuine ICS/OT context."""
    for p in (dst_port, src_port):
        try:
            if int(p) in ICS_VALID_PORTS:
                return True
        except (TypeError, ValueError):
            pass  # silent: non-numeric port/address value
    if protocol and str(protocol).lower() in ICS_VALID_PROTOCOLS:
        return True
    return False


def ics_op_from_rule(rule_name: str) -> str:
    """Classify an ICS rule into an operation type."""
    r = rule_name.lower()
    for t in ICS_RULE_SCAN:
        if t in r:
            return "scan"
    for t in ICS_RULE_CONTROL:
        if t in r:
            return "control"
    for t in ICS_RULE_WRITE:
        if t in r:
            return "write"
    for t in ICS_RULE_ENUMERATE:
        if t in r:
            return "enumerate"
    for t in ICS_RULE_DISCOVERY:
        if t in r:
            return "discovery"
    for t in ICS_RULE_READ:
        if t in r:
            return "read"
    return "unknown"


def pick_ics_mitre(atype: str, rule_name: str, fc_info: dict) -> tuple[str | None, str | None]:
    """Return (technique, tactic) for an ICS classifier hit."""
    from honeylens.classification.mitre_mapping import get_mitre_mapping

    mappings = get_mitre_mapping(atype)
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
        op = ics_op_from_rule(rule_name)

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


def build_ics_row(event_id, ts, atype, rule, src_ip, src_port, dst_port, protocol, meta=None):
    """
    Return INSERT tuple for ics_events or None if rule/context is not ICS.

    The tuple matches the INSERT_ICS_SQL column order used by all ingest paths.
    """
    if rule in CALDERA_RULES:
        return None
    if not ics_context(dst_port, src_port, protocol):
        return None

    fi = ICS_FC.get(rule, {})

    # Protocol label from rule prefix
    proto = str(protocol or "ics-generic").lower()
    for pfx, lbl in (
        ("modbus", "modbus"),
        ("dnp3", "dnp3"),
        ("s7comm", "s7comm"),
        ("enip", "enip"),
        ("cip", "enip"),
        ("bacnet", "bacnet"),
        ("opcua", "opcua"),
        ("iec104", "iec104"),
        ("mqtt", "mqtt"),
    ):
        if rule.startswith(pfx + "_"):
            proto = lbl
            break

    # Human-readable function name
    fn = re.sub(
        r"^(modbus_fc\d+_|modbus_|dnp3_|s7comm_|enip_|bacnet_|opcua_|iec104_|mqtt_|cip_)", "", rule
    )
    fn = fn.replace("_", " ").title()[:64]

    sev = fi.get("severity", "MEDIUM")

    # Extract ICS device/register fields from honeypot log data
    _m = meta or {}
    unit_id = _m.get("unit_id")
    register_start = _m.get("address")
    register_count = _m.get("quantity")
    _dv = _m.get("value")
    if _dv is None and _m.get("pdu_hex"):
        _dv = _m["pdu_hex"]
    data_value = str(_dv) if _dv is not None else None

    technique, tactic = pick_ics_mitre(atype, rule, fi)

    return (
        str(event_id),
        ts,
        proto,
        fi.get("fc"),
        fn,
        str(src_ip) if src_ip else None,
        src_port,
        None,
        dst_port,
        unit_id,
        register_start,
        register_count,
        data_value,
        bool(fi.get("is_read", False)),
        bool(fi.get("is_write", False)),
        bool(fi.get("is_control", False)),
        bool(fi.get("is_discovery", False)),
        technique,
        tactic,
        atype,
        rule,
        "honeypotng",
        sev,
    )
