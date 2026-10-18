"""
ingest/ics_helpers.py — ICS/OT Event Helpers (Shared)
=======================================================
Extracted from ingest.py and ingest_honeypot.py to eliminate duplication.

Contains:
    - ICS port validation for the passive eBPF path (`ics_port_consistent`)
    - ICS function code mapping (50+ entries)
    - MITRE ICS tactic selection
    - per-protocol metadata -> ics_events column mapping

Usage:
    from honeylens.ingest.ics_helpers import ICS_FC, map_protocol_fields
"""

from __future__ import annotations

import re
from typing import Any, cast

from honeylens.ics import decode_hex, flags_for, flags_for_semantics, frame_for_code, ics_frame_hex
from honeylens.ics.frame import Semantics

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

# Service ports that legitimately carry each ICS protocol. Used by the PASSIVE
# eBPF capture path, where `protocol` is *inferred from payload bytes* and is
# therefore unreliable — the binary detectors are port-agnostic, so the
# sensor's own outbound traffic (e.g. the Ollama API on :11434, or an internal
# service on :3100) gets misread as Modbus / IEC-104 / ENIP / OPC-UA. Anchoring
# a passively-classified protocol to its real service port drops those false
# positives. The honeypot ingest path applies no port guard at all: there the decoy's
# own name is ground truth, and a port list would have dropped profinet, whose 34964
# is not in ICS_VALID_PORTS. (Until 2026-10-25 this comment said that path "keeps
# using ics_context()". It had stopped, and then ics_context lost its last caller
# and was deleted -- a comment claiming behaviour the code does not have is the
# defect this whole phase was written around.)
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
        "anomaly": (lambda t: "inhibit" in t, lambda f: f == "anomaly"),
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

    if op == "anomaly":  # an illegal function code asserts no technique (no anomaly entry)
        return None, None

    for m in mappings:
        if tactic_ok(m.get("tactic", "")):
            return m["technique"], m["tactic"]

    return mappings[0]["technique"], mappings[0]["tactic"]


# ── MITRE ICS from what the frame means ───────────────────────────────────
# One table: semantics -> (technique, tactic). ``ATTACK_TO_MITRE["ICS_ATTACK"]`` is derived
# from it at import, so the coverage matrix lists exactly the techniques the ingest can
# assign. Until 2026-10-26 the two were separate: the store wrote nine verdict names against
# three ICS keys, and two of the seven mapped operations could not be reached at all.
# ``anomaly`` asserts nothing: an undefined function code is not a read.
SEMANTICS_TO_MITRE: dict[Semantics, tuple[str, str] | None] = {
    "read": ("T0801", "collection-ics"),
    "enumerate": ("T0861", "collection-ics"),
    "discovery": ("T0846", "discovery-ics"),
    "write": ("T0836", "impair-process-control"),
    "command": ("T0855", "execution-ics"),
    "control": ("T0816", "inhibit-response-function"),
    "anomaly": None,
}

# Verdicts that carry a meaning of their own when the bytes did not decode. ICS_ATTACK and
# CREDENTIAL_CAPTURE are deliberately absent: they say "hostile", not "what it did".
_VERDICT_SEMANTICS: dict[str, Semantics] = {
    "ICS_RECON": "enumerate",
    "MODBUS_RECON": "enumerate",
    "MQTT_PROBE": "enumerate",
    "MQTT_ENUMERATION": "enumerate",
    "ics_enumeration": "enumerate",
    "SCANNER": "discovery",
    "ics_recon_function_code": "discovery",
    "MQTT_INJECT": "write",
}


def semantics_to_mitre(semantics: str | None) -> tuple[str | None, str | None]:
    """(technique, tactic) for a semantics value; (None, None) when it asserts none."""
    mitre = SEMANTICS_TO_MITRE.get(cast("Semantics", semantics))
    return mitre or (None, None)


def verdict_to_semantics(attack_type: str | None) -> Semantics | None:
    """The semantics a single classifier verdict implies, for a row with no decodable bytes."""
    return _VERDICT_SEMANTICS.get(attack_type or "")


# ── Per-protocol field map ────────────────────────────────────────────────
# Each decoy speaks its own vocabulary; the ics_events columns were modelled on
# Modbus. column -> ordered candidate metadata keys (first present, non-null wins).
# s7comm, mms, profinet and fox parse no protocol and deliberately have no entry.
ICS_FIELD_MAP: dict[str, dict[str, tuple[str, ...]]] = {
    "modbus": {
        "function_code": ("fc",),
        "function_name": ("fc_name",),
        "unit_id": ("unit_id",),
        "register_start": ("address",),
        "register_count": ("quantity",),
        "data_value": ("value", "pdu_hex"),
    },
    "iec104": {
        "function_code": ("type_id",),
        "function_name": ("type_name",),
        "device_address": ("common_address",),
        "register_start": ("ioa",),
        "data_value": ("asdu_hex",),
    },
    "dnp3": {
        "function_code": ("fc",),
        "function_name": ("fc_name",),
        "device_address": ("station_address",),
        "data_value": ("app_objects_hex",),
    },
    "bacnet": {
        "function_code": ("service",),
        "function_name": ("service_name",),
        "data_value": ("apdu_hex",),
    },
    "opcua": {
        "function_code": ("service_id",),
        "function_name": ("service_name",),
        "data_value": ("body_hex",),
    },
    "enip": {
        "function_code": ("command",),
        "function_name": ("rule",),
        "data_value": ("data_hex",),
    },
    "fins": {
        "function_code": ("mrc",),
        "function_name": ("mrc_src_name",),
        "data_value": ("frame_hex",),
    },
    "mqtt": {
        "function_code": ("pkt_type",),
        "function_name": ("rule",),
        "device_address": ("topic",),
        "data_value": ("message",),
    },
}

_INT4_COLUMNS = frozenset({"function_code", "unit_id", "register_start", "register_count"})
_VARCHAR64_COLUMNS = frozenset({"function_name", "device_address"})
_INT4_MIN, _INT4_MAX = -(2**31), 2**31 - 1


def _coerce_int4(value: Any) -> int | None:
    """int or digit string within PostgreSQL int4, else None (bool is not a number here)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        if not re.fullmatch(r"-?[0-9]+", value.strip()):
            return None
        try:
            value = int(value)
        except ValueError:  # e.g. more than 4300 digits: CPython refuses the conversion
            return None
    if not isinstance(value, int):
        return None
    return value if _INT4_MIN <= value <= _INT4_MAX else None


def map_protocol_fields(honeypot: str, meta: dict) -> dict[str, Any]:
    """Translate a decoy's metadata into ics_events columns; only fillable keys appear.

    A bad value (non-numeric, out-of-range or absurdly long digit string) never raises: it
    becomes absent (integers) or truncated (VARCHAR(64)), since an out-of-range value would
    abort the INSERT and silently drop the ICS row. `meta` must be a dict.
    """
    out: dict[str, Any] = {}
    for column, keys in ICS_FIELD_MAP.get(honeypot, {}).items():
        raw = next((meta[k] for k in keys if meta.get(k) is not None), None)
        if raw is None:
            continue
        if column in _INT4_COLUMNS:
            number = _coerce_int4(raw)
            if number is not None:
                out[column] = number
        elif column in _VARCHAR64_COLUMNS:
            out[column] = str(raw)[:64]
        else:
            out[column] = str(raw)
    return out


def resolve_semantics(
    protocol: str,
    meta: dict,
    function_code: Any,
    verdict_types: str | None,
) -> tuple[Semantics | None, dict[str, bool], str]:
    """What an ICS row means: (semantics, the five flags before the decoy's own override,
    which tier answered). The one decision the ingest and the corrective backfill share.

    Tiers, strongest first: the captured bytes; the stored function code where it is byte 0
    of the frame (modbus, iec104) -- the decoy's own recording of what it saw; the single
    classifier verdict (``ICS_ATTACK`` and ``CREDENTIAL_CAPTURE`` carry none). The tier is
    ``"bytes"``, ``"bytes_undecoded"`` (hex was stored but decodes to nothing and no lower
    tier answered), ``"function_code"``, ``"verdict"`` or ``"none"`` (no bytes at all).
    """
    hex_str = ics_frame_hex(meta)
    frame = decode_hex(protocol, hex_str)
    if frame.semantics:
        return frame.semantics, flags_for(frame), "bytes"
    coded = frame_for_code(protocol, function_code)
    if coded is not None and coded.semantics:
        return coded.semantics, flags_for(coded), "function_code"
    for verdict_type in (verdict_types or "").split(","):
        semantics = verdict_to_semantics(verdict_type.strip())
        if semantics:
            return semantics, flags_for_semantics(semantics), "verdict"
    return None, flags_for_semantics(None), "bytes_undecoded" if hex_str else "none"
