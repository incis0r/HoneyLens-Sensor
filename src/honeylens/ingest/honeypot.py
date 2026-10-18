"""
ingest_honeypot.py — HoneypotNG Log Ingestion Pipeline (Enhanced)

==================================================================
Reads all *.json log files written by the honeypots, normalises and sanitises each
record, then upserts into sensor_events. Log files are truncated only after a
successful database commit.

Port 1.0: two line formats arrive here. The legacy one (monolith, K8s, FortiGate,
PAN-OS) is unchanged. The new one, ``schema: honeylens-event/1`` from
``honeypots/sink.py``, is what every honeypot that used to write to the database
itself now emits — a container never holds database credentials. For those lines
this module also does what ``honeypots/_base.log_event`` did in 0.9: honours the
honeypot's own verdict instead of re-classifying, writes ``attack_patterns`` rows
with severity and confidence, ``ics_events`` for ICS decoys, ``full_payload`` from
the raw bytes, the LLM decoy's own table, canary registration and SIEM fan-out.
``_normalise()`` is where the two formats meet; everything after it is one path.

The schema (``attack_types`` column, ``attack_patterns``, ``ics_events``) is
guaranteed by ``honeylens-migrate``, which runs before any service starts. The 0.9
import-time probes — three connections per process start, a silent downgrade when
the database was unreachable — are gone with it.

Requires: Python >= 3.9 (Rocky Linux 9 default)

Run manually or from cron:
    python ingest_honeypot.py
"""

from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.scoring import classify_attack_summary, get_severity
from honeylens.config import (
    HONEYPOT_LOG_GLOBS,
    HONEYPOTNG_GLOB,
    HONEYPOTNG_PATTERNS_FILE,
    K8S_HONEYPOT_LOG_FILE,
)
from honeylens.database import legacy_get_db
from honeylens.eventlog_lock import log_lock
from honeylens.honeypots.sink import LLM_COLUMNS
from honeylens.honeypots.sink import SCHEMA as HONEYPOT_SCHEMA
from honeylens.ingest import logcleanup
from honeylens.ingest.ics_helpers import pick_ics_mitre
from honeylens.intelligence import canary_store
from honeylens.sanitise import safe_json_dumps, sanitize_payload, strip_nul

logger = logging.getLogger("honeylens.ingest.honeypot")

# honeypotng keeps its auto-detection dedup memory in the same directory, so it matches the
# log glob. It is STATE, not an event log — never parse or truncate it.
NON_EVENT_FILES = {Path(HONEYPOTNG_PATTERNS_FILE).name}

# ---------------------------------------------------------------------------
# NUL byte sanitisation — PostgreSQL text columns cannot contain 0x00
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def get_db():
    return legacy_get_db()


INSERT_SQL = """
    INSERT INTO sensor_events (
        event_id, timestamp, source, protocol,
        src_ip, src_port, dst_ip, dst_port,
        payload, payload_hash,
        scan_score, port_entropy,
        ja3, metadata, attack_types
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON CONFLICT (event_id) DO NOTHING
"""

# severity/confidence: columns from migrations 0001/0002 with defaults 'medium'/'high'.
# Rows from the legacy format get explicitly the same values the defaults used to give them.
INSERT_ATTACK_SQL = """
    INSERT INTO attack_patterns (
        event_id, attack_type, rule_name, matched_text, severity, confidence
    )
    VALUES (%s, %s, %s, %s, %s, %s)
    ON CONFLICT DO NOTHING
"""

# Request bytes, when the honeypot sent them (``raw_hex``). A separate UPDATE, not columns
# in the INSERT: the event row must go in even when this write fails.
UPDATE_RAW_SQL = """
    UPDATE sensor_events
       SET full_payload = %s, full_payload_hash = %s
     WHERE event_id = %s AND full_payload IS NULL
"""

# The ICS honeypot's own verdict (what ``_base.log_event`` wrote to ics_events in 0.9).
INSERT_ICS_VERDICT_SQL = """
    INSERT INTO ics_events (
        event_id, timestamp, protocol, function_code, function_name,
        src_ip, src_port, dst_ip, dst_port,
        is_read, is_write, is_control, is_discovery,
        attack_type, rule_name, source, severity
    ) VALUES (
        %s, %s, %s, %s, %s,
        %s::inet, %s, %s::inet, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s
    ) ON CONFLICT (event_id) DO NOTHING
"""

# LLM honeypot table (migration 0008); columns from the contract in honeypots/sink.py.
_LLM_VALUES = ", ".join("%s::inet" if c == "src_ip" else "%s" for c in LLM_COLUMNS)
INSERT_LLM_SQL = (
    f"INSERT INTO llm_honeypot_events ({', '.join(LLM_COLUMNS)}) "  # noqa: S608 # nosec B608 — columns from the constant contract tuple
    f"VALUES ({_LLM_VALUES}) ON CONFLICT (event_id) DO NOTHING"
)

# Honeypots whose verdict also goes to ics_events (list from ``_base.log_event`` in 0.9).
_ICS_HONEYPOTS = frozenset(
    {
        "modbus",
        "s7comm",
        "dnp3",
        "iec104",
        "bacnet",
        "enip",
        "opcua",
        "fins",
        "mqtt",
        "profinet",
        "melsec",
        "coap",
        "mms",
        "fox",
    }
)

INSERT_ICS_SQL = """
    INSERT INTO ics_events (
        event_id, timestamp, protocol, function_code, function_name,
        src_ip, src_port, dst_ip, dst_port,
        unit_id, register_start, register_count, data_value,
        is_read, is_write, is_control, is_discovery,
        mitre_tactic, mitre_technique, attack_type, rule_name,
        source, severity
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON CONFLICT (event_id) DO NOTHING
"""


# ── ICS context + function class tables (mirrors ingest.py) ─────────────────
_ICS_VALID_PORTS = frozenset(
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
_ICS_VALID_PROTOCOLS = frozenset(
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
_CALDERA_RULES = frozenset(
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
_ICS_FC = {
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
    # binary-detector names  (modbus_fc##_*)
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
    "s7comm_stop_cpu": {"is_control": True, "severity": "CRITICAL"},
    "s7comm_write_var": {"is_write": True, "severity": "HIGH"},
    "s7comm_download_block": {"is_write": True, "severity": "CRITICAL"},
    "dnp3_cold_restart": {"is_control": True, "severity": "CRITICAL"},
    "dnp3_warm_restart": {"is_control": True, "severity": "HIGH"},
    "dnp3_direct_operate": {"is_write": True, "severity": "HIGH"},
    "dnp3_write_request": {"is_write": True, "severity": "HIGH"},
    "bacnet_write_property": {"is_write": True, "severity": "HIGH"},
    "bacnet_reinitialize": {"is_control": True, "severity": "CRITICAL"},
    "opcua_write": {"is_write": True, "severity": "HIGH"},
    "opcua_call_method": {"is_control": True, "severity": "HIGH"},
    "iec104_single_command": {"is_write": True, "severity": "HIGH"},
    "iec104_double_command": {"is_write": True, "severity": "HIGH"},
    "iec104_setpoint": {"is_write": True, "severity": "HIGH"},
    "iec104_reset_process": {"is_control": True, "severity": "CRITICAL"},
}


def _ics_context(dst_port, src_port, protocol):
    """Return True when traffic is genuinely ICS/OT context."""
    for p in (dst_port, src_port):
        try:
            if int(p) in _ICS_VALID_PORTS:
                return True
        except (TypeError, ValueError):
            pass  # silent: port value may be None or non-numeric string
    if protocol and str(protocol).lower() in _ICS_VALID_PROTOCOLS:
        return True
    return False


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


def _build_ics_row(event_id, ts, atype, rule, src_ip, src_port, dst_port, protocol, meta=None):
    """Return INSERT_ICS_SQL tuple or None if rule/context not ICS."""
    if rule in _CALDERA_RULES:
        return None
    if not _ics_context(dst_port, src_port, protocol):
        return None

    fi = _ICS_FC.get(rule, {})

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
    import re as _re

    fn = _re.sub(
        r"^(modbus_fc\d+_|modbus_|dnp3_|s7comm_|enip_|bacnet_|opcua_|iec104_|mqtt_|cip_)", "", rule
    )
    fn = fn.replace("_", " ").title()[:64]

    sev = fi.get("severity", "MEDIUM")

    # Extract ICS device/register fields from raw honeypot log data
    _m = meta or {}
    unit_id = _m.get("unit_id")
    register_start = _m.get("address")  # Modbus start address
    register_count = _m.get("quantity")  # number of registers/coils
    # data_value: written value (FC5/FC6) or raw PDU hex for reads
    _dv = _m.get("value")
    if _dv is None and _m.get("pdu_hex"):
        _dv = _m["pdu_hex"]
    data_value = str(_dv) if _dv is not None else None

    return (
        str(event_id),
        ts,
        proto,
        fi.get("fc"),
        fn,
        str(src_ip) if src_ip else None,
        src_port,
        None,
        dst_port,  # dst_ip unknown from honeypot log
        unit_id,
        register_start,
        register_count,
        data_value,
        bool(fi.get("is_read", False)),
        bool(fi.get("is_write", False)),
        bool(fi.get("is_control", False)),
        bool(fi.get("is_discovery", False)),
        pick_ics_mitre(atype, rule, fi)[0],  # mitre_technique
        pick_ics_mitre(atype, rule, fi)[1],  # mitre_tactic (slug)
        atype,
        rule,
        "honeypotng",
        sev,
    )


def safe_insert(cur, row):
    """
    Insert one row using a savepoint so a single bad row cannot abort the
    surrounding transaction.  On failure the savepoint is rolled back and
    the error is logged; the caller can continue with the next row.
    """
    cur.execute("SAVEPOINT sp_row")
    try:
        cur.execute(INSERT_SQL, row)
        cur.execute("RELEASE SAVEPOINT sp_row")
    except Exception as exc:
        cur.execute("ROLLBACK TO SAVEPOINT sp_row")
        cur.execute("RELEASE SAVEPOINT sp_row")
        logger.error("Insert failed: %s — event_id=%s", exc, row[0][:16] if row else "?")
        raise


# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------


def _canary_register(cur, data, event_id, ts):
    """Register an AI canary, or correlate a callback with the artefact that carried it.

    Mutates `data` on a callback so the recovered origin is stored with the event —
    the honeypot could only fill those fields in when it had issued the canary itself.
    """
    if canary_store is None:
        return
    nonce = data.get("canary_nonce")
    src_ip = data.get("peer_ip") or data.get("src_ip")

    if data.get("action") != "ai_canary_callback":
        canary_store.record_issue(
            cur,
            nonce,
            canary_type=data.get("canary_type") or "prompt_injection_header",
            carrier=data.get("carrier") or "http_response_header",
            origin_event_id=event_id,
            origin_protocol=data.get("origin_protocol") or data.get("protocol"),
            origin_path=data.get("path"),
            origin_src_ip=src_ip,
            issued_at=ts,
        )
        return

    origin = canary_store.record_callback(
        cur,
        nonce,
        callback_at=ts,
        src_ip=src_ip,
        user_agent=data.get("user_agent"),
        headers=data.get("callback_headers"),
        body_sample=data.get("callback_body_sample"),
    )
    if not origin:
        return

    data["canary_correlated"] = True
    for field in ("origin_protocol", "origin_path", "origin_src_ip"):
        if origin.get(field) and not data.get(field):
            data[field] = origin[field]
    if data.get("callback_delay_ms") is None:
        delay = canary_store.callback_delay_ms(origin.get("issued_at"), _as_dt(ts))
        if delay is not None:
            data["callback_delay_ms"] = delay


def _as_dt(ts):
    """Honeypot logs carry ISO timestamps; the store needs a datetime to subtract."""
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _normalise(data: dict) -> dict:
    """One shape for both line formats; from here on there is a single path.

    The ``honeylens-event/1`` format (``honeypots/sink.py``) carries an envelope and a
    separate ``event``; the legacy format (monolith, K8s, FortiGate, PAN-OS) is flat and
    ``metadata`` is the whole line. Result: a dict with the column fields, ``metadata``
    (for the column and the classifier), ``verdict`` (the honeypot's verdict or None),
    ``raw`` (bytes or None), ``llm``, ``canary`` (dict to register or None),
    ``forward_siem`` and ``honeypot`` (honeypot name, for ics_events).
    """
    if data.get("schema") == HONEYPOT_SCHEMA:
        event: dict = data["event"] if isinstance(data.get("event"), dict) else {}
        src_ip = data.get("peer_ip")
        proto = data.get("protocol") or "unknown"
        verdict = None
        if data.get("attack_type"):
            verdict = {
                "attack_type": data["attack_type"],
                "severity": (data.get("severity") or "MEDIUM").upper(),
                "confidence": data.get("confidence") or "high",
                "rules": [r for r in (data.get("rules") or []) if r],
            }
        raw = None
        if data.get("raw_hex"):
            try:
                raw = bytes.fromhex(data["raw_hex"])
            except ValueError as exc:
                logger.warning("raw_hex not decodable, stored without raw bytes: %s", exc)
        canary = None
        if event.get("canary_nonce"):
            canary = {**event, "peer_ip": src_ip, "protocol": proto}
        return {
            "ts": data.get("timestamp"),
            "proto": proto,
            "src_ip": src_ip,
            "src_port": data.get("peer_port"),
            "dst_ip": data.get("dst_ip"),
            "dst_port": data.get("dst_port") or data.get("port"),
            "payload": sanitize_payload(data.get("payload")),
            "source": data.get("source") or "honeypotng",
            "honeypot": data.get("honeypot"),
            "event_id": data.get("event_id"),
            "metadata": event,
            "verdict": verdict,
            "raw": raw,
            "llm": data.get("llm") if isinstance(data.get("llm"), dict) else None,
            "canary": canary,
            "forward_siem": True,
        }

    # --- legacy format, unchanged from 0.9 ---
    proto = data.get("protocol", "unknown")
    # Handle both old format (peer=[ip,port]) and new format (peer_ip, peer_port)
    peer = data.get("peer", [None, None])
    src_ip = data.get("peer_ip") or (peer[0] if isinstance(peer, list) and peer else None)
    src_port = data.get("peer_port") or (
        peer[1] if isinstance(peer, list) and len(peer) > 1 else None
    )
    # Extract payload from various possible fields
    # K8s honeypot uses: path, method, user_agent
    # NG honeypot uses: data, hex, raw
    payload = sanitize_payload(
        # An explicit `payload` field is the honeypot's own summary of the
        # request and outranks anything we could reassemble here. It was
        # missing from this chain, so a honeypot that filled in the one
        # field named after the column got NULL in it.
        data.get("payload")
        or data.get("data")
        or data.get("hex")
        or data.get("raw")
        or data.get("path")
        or data.get("request_line")
    )
    # For K8s/HTTP logs, construct a more complete payload representation
    if data.get("method") and data.get("path"):
        request_line = f"{data.get('method')} {data.get('path')}"
        if data.get("user_agent"):
            request_line += f" User-Agent: {data.get('user_agent')}"
        if not payload or payload == data.get("path"):
            payload = sanitize_payload(request_line)
    proto_lower = (proto or "").lower()
    if any(x in proto_lower for x in ("k8s_", "kubernetes", "kubelet", "etcd", "kubectl")):
        source = "honeypot_k8s"
    else:
        source = "honeypotng"
    return {
        "ts": data.get("timestamp"),
        "proto": proto,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": None,
        "dst_port": data.get("port") or data.get("dst_port"),
        "payload": payload,
        "source": source,
        "honeypot": None,
        "event_id": None,
        "metadata": data,
        "verdict": None,
        "raw": None,
        "llm": None,
        "canary": data if data.get("canary_nonce") else None,
        "forward_siem": False,
    }


def _attack_hits(rec: dict, payload: str | None) -> tuple[str | None, list[tuple]]:
    """``(attack_types, [(atype, rule, matched, severity, confidence)])`` for an event.

    The honeypot's verdict (1.0 format) stands alone: it is higher fidelity than a regex
    and is neither overridden nor supplemented — that is what ``_base.log_event`` did.
    Without a verdict we ask the central rule set; for legacy lines as in 0.9: the
    honeypot's own classification (``attack_type`` + ``rule_name``) as the first hit,
    the rest from the classifier.
    """
    verdict = rec["verdict"]
    if verdict:
        rows = [
            (verdict["attack_type"], rule, None, verdict["severity"], verdict["confidence"])
            for rule in verdict["rules"]
        ]
        return strip_nul(verdict["attack_type"]), rows

    data = rec["metadata"]
    hits: list[tuple] = []
    if rec["source"] in ("honeypotng", "honeypot_k8s") and not rec["honeypot"]:
        pre_atype = data.get("attack_type")
        pre_rule = data.get("rule_name")
        if pre_atype and pre_rule:
            pre_matched = f"{data.get('method', '')} {data.get('path', '')}".strip() or pre_rule
            hits.append((strip_nul(pre_atype), strip_nul(pre_rule), strip_nul(pre_matched[:500])))
    try:
        seen = {(h[0], h[1]) for h in hits}
        for h in classify_event_row(payload=payload, protocol=rec["proto"], metadata=data):
            if (h[0], h[1]) not in seen:
                hits.append(h)
                seen.add((h[0], h[1]))
    except Exception as e:
        logger.warning("attack classifier failed, event stored unclassified: %s", e)
    attack_types = classify_attack_summary(hits)
    if rec["honeypot"]:
        # Regex hits on a 1.0 honeypot event: confidence "medium", severity from the taxonomy —
        # a regex is weaker evidence than a honeypot recognising its own protocol.
        rows = [(a, r, m, (get_severity(a, r) or "medium").upper(), "medium") for a, r, m in hits]
    else:
        rows = [(a, r, m, "medium", "high") for a, r, m in hits]
    return (strip_nul(attack_types) if attack_types else None), rows


def _ics_verdict_row(rec: dict, event_id: str, attack_types: str) -> tuple:
    """ics_events row from an ICS honeypot's verdict — the logic of ``_base.log_event`` 0.9."""
    data = rec["metadata"]
    hp = rec["honeypot"]
    rule = data.get("rule") or data.get("phase") or f"{hp}_event"
    rule_l = rule.lower()
    verdict = rec["verdict"] or {}
    return (
        event_id,
        rec["ts"],
        hp,
        data.get("function_code") or data.get("fc"),
        rule.replace("_", " ").title(),
        rec["src_ip"],
        rec["src_port"],
        rec["dst_ip"] or "0.0.0.0",  # noqa: S104 — unknown destination address, not a bind
        rec["dst_port"] or 0,
        "read" in rule_l or "recon" in attack_types.lower(),
        "write" in rule_l or "inject" in rule_l,
        any(k in rule_l for k in ("control", "stop", "restart", "run")),
        any(k in rule_l for k in ("discover", "enumerate", "probe", "hello")),
        attack_types,
        rule,
        rec["source"],
        verdict.get("severity") or "MEDIUM",
    )


def _guarded(cur, name: str, what: str, fn) -> bool:
    """``fn(cur)`` inside a savepoint: a failure does not break the file's transaction.

    A failure is a warning, not debug: in a daemon unit nobody sees debug, and a permanent
    schema error would silently zero out a whole table. The ``RELEASE`` after ``fn`` also
    detects an error that ``fn`` itself swallowed — PostgreSQL holds the transaction in the
    "aborted" state and ``RELEASE`` then fails, so we roll back to the savepoint instead of
    dragging a broken transaction through the rest of the file (and through ``commit``,
    which in that state is a silent rollback).
    """
    try:
        cur.execute(f"SAVEPOINT {name}")
        fn(cur)
        cur.execute(f"RELEASE SAVEPOINT {name}")
        return True
    except Exception as exc:
        try:
            cur.execute(f"ROLLBACK TO SAVEPOINT {name}")
            cur.execute(f"RELEASE SAVEPOINT {name}")
        except Exception as e2:
            logger.warning("%s: savepoint rollback failed: %s", what, e2)
        logger.warning("%s write skipped: %s", what, exc)
        return False


def _savepoint(cur, name: str, sql: str, params: tuple, what: str) -> bool:
    """A single statement inside a savepoint (see ``_guarded``)."""
    return _guarded(cur, name, what, lambda c: c.execute(sql, params))


def process_record(cur, data: dict) -> bool:
    """One (already parsed) event into the database. ``False`` when the row was skipped."""
    data = strip_nul(data)
    rec = _normalise(data)
    ts, proto, src_ip, src_port = rec["ts"], rec["proto"], rec["src_ip"], rec["src_port"]
    dst_port, payload = rec["dst_port"], rec["payload"]

    payload_hash = hashlib.sha256((payload or "").encode(errors="ignore")).hexdigest()
    event_id = (
        rec["event_id"]
        or hashlib.sha256(
            (f"{ts}:{src_ip}:{src_port}:{dst_port}:{payload_hash}").encode()
        ).hexdigest()
    )

    # AI canary registry (Idea 52). The K8s honeypot holds no DB credentials
    # by design, so its canaries reach the durable store here, on their way
    # through the log. Callbacks are correlated here too, not in the honeypot:
    # the canary may have been issued by a different process (the LLM
    # honeypot), which in-memory correlation can never see. Runs before the
    # metadata is serialised so the correlation it recovers is stored with
    # the event.
    if rec["canary"]:
        # canary_store swallows its own exceptions but does not undo the transaction's
        # "aborted" state — without a savepoint one bad canary lost every event in the file
        # (in 0.9 as well).
        canary = rec["canary"]
        _guarded(cur, "sp_canary", "canary", lambda c: _canary_register(c, canary, event_id, ts))

    metadata_json = safe_json_dumps(rec["metadata"])
    attack_types, attack_rows = _attack_hits(rec, payload)

    row: tuple[Any, ...] = (
        strip_nul(event_id),
        strip_nul(ts),
        rec["source"],
        strip_nul(proto),
        strip_nul(src_ip),
        src_port,
        rec["dst_ip"],
        dst_port,
        payload,  # already sanitised
        strip_nul(payload_hash),
        None,
        None,
        None,
        metadata_json,  # already sanitised
        attack_types,
    )
    try:
        safe_insert(cur, row)
    except Exception as exc:
        # Row-level savepoint already rolled back inside safe_insert.
        # Skip this row and continue — do NOT raise so the file keeps
        # processing and the transaction stays healthy.
        logger.debug("row skipped: %s", exc)
        return False

    # The bytes exactly as they arrived. The hash is over precisely what we store, so anyone
    # can recompute it against the column and see that nothing changed between capture
    # and disk.
    if rec["raw"]:
        raw_hash = hashlib.sha256(rec["raw"]).hexdigest()
        _savepoint(cur, "sp_raw", UPDATE_RAW_SQL, (rec["raw"], raw_hash, event_id), "raw capture")

    if rec["llm"]:
        llm = rec["llm"]
        params = tuple(
            json.dumps(llm.get(c)) if c == "headers" else llm.get(c) for c in LLM_COLUMNS
        )
        _savepoint(cur, "sp_llm", INSERT_LLM_SQL, params, "llm_honeypot_events")

    # Insert individual attack pattern rows.
    # INSERT_ATTACK_SQL uses ON CONFLICT DO NOTHING so this is safe even
    # when the sensor_events row already existed (re-ingest scenario).
    for atype, rule, matched, severity, confidence in attack_rows:
        _savepoint(
            cur,
            "sp_atk",
            INSERT_ATTACK_SQL,
            (
                strip_nul(event_id),
                strip_nul(atype),
                strip_nul(rule),
                strip_nul(matched[:500]) if matched else None,
                severity,
                confidence,
            ),
            "Attack pattern",
        )

    # ICS/OT events. A 1.0 ICS decoy with a verdict (own or the classifier's) gets the
    # row `_base.log_event` used to write; otherwise MODBUS/ICS_ATTACK hits on ICS
    # ports, as for every legacy line.
    if rec["honeypot"] and rec["honeypot"].lower() in _ICS_HONEYPOTS and attack_types:
        _savepoint(
            cur,
            "sp_ics",
            INSERT_ICS_VERDICT_SQL,
            _ics_verdict_row(rec, event_id, attack_types),
            "ICS",
        )
    else:
        for atype, rule, _matched, _sev, _conf in attack_rows:
            if atype not in ("MODBUS", "ICS_ATTACK"):
                continue
            try:
                ics_row = _build_ics_row(
                    event_id,
                    ts,
                    atype,
                    rule,
                    src_ip,
                    src_port,
                    dst_port,
                    proto,
                    meta=rec["metadata"],
                )
            except Exception as exc:
                logger.debug("ICS row build error: %s", exc)
                continue
            if ics_row:
                _savepoint(cur, "sp_ics", INSERT_ICS_SQL, ics_row, "ICS")

    # Fan-out to configured SIEM forwarders (no-op if none configured). Only for
    # events that reached SIEM in 0.9, i.e. the honeypots that wrote to the database
    # themselves; legacy lines never did and that is a separate decision.
    if rec["forward_siem"]:
        try:
            from honeylens.siem import forward_event_dict

            forward_event_dict(
                {
                    "event_id": event_id,
                    "source": rec["source"],
                    "protocol": proto,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_port": dst_port or 0,
                    "payload": payload or "",
                    "attack_types": attack_types or "",
                }
            )
        except Exception as exc:
            logger.debug("SIEM forward skipped: %s", exc)
    return True


def process_file(cur, path, limit_bytes=None):
    """Parse one log file and insert all valid records. Returns count inserted."""
    logger.info("Processing %s", path)
    inserted = 0

    with open(path, "rb") as fh:
        line_no = 0
        while limit_bytes is None or fh.tell() < limit_bytes:
            remaining = -1 if limit_bytes is None else limit_bytes - fh.tell()
            raw_line = fh.readline(remaining)
            if not raw_line:
                break
            line_no += 1
            if not raw_line.endswith(b"\n"):
                raise ValueError(f"Incomplete event at {path}:{line_no}; keeping log for retry")
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                data = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at {path}:{line_no}; keeping log for inspection"
                ) from exc
            if not isinstance(data, dict):
                raise ValueError(
                    f"Non-object event at {path}:{line_no}; keeping log for inspection"
                )

            if not process_record(cur, data):
                raise ValueError(f"Event not persisted at {path}:{line_no}; keeping log for retry")
            inserted += 1

    logger.info("Inserted %d records from %s", inserted, path)
    return inserted


# ---------------------------------------------------------------------------
# Post-ingest cleanup
# ---------------------------------------------------------------------------


def _allowed_cleanup_dirs():
    """Directories we may clean up in — derived from the configured log sources.

    Anything outside these is refused: cleanup deletes data, so the path must
    provably come from a directory an operator configured.
    """
    dirs = set()
    for pattern in [*list(HONEYPOT_LOG_GLOBS), HONEYPOTNG_GLOB, K8S_HONEYPOT_LOG_FILE]:
        dirs.add(os.path.realpath(os.path.dirname(pattern) or "."))
    return dirs


# The truncate/replace mechanics moved to ingest/logcleanup.py when fortigate.py and
# paloalto.py needed the same thing — a fourth copy of this was not worth having.
_is_within = logcleanup.is_within
_drop_consumed_prefix = logcleanup.drop_consumed_prefix


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def ingest():
    files = []
    for pattern in HONEYPOT_LOG_GLOBS:
        if "*" in pattern:
            files.extend(glob.glob(pattern))
        elif os.path.isfile(pattern):
            files.append(pattern)
    files = list(dict.fromkeys(f for f in files if os.path.basename(f) not in NON_EVENT_FILES))
    if not files:
        logger.info("No honeypot log files found — nothing to do.")
        return

    total = errors = 0
    allowed = _allowed_cleanup_dirs()
    for path in files:
        db = None
        try:
            # Serialize consumers through commit AND cleanup. Writers only wait for
            # the size snapshot and cleanup, never for database work or SIEM calls.
            with log_lock(path, consumer=True):
                with log_lock(path):
                    consumed = os.path.getsize(path)
                if not consumed:
                    continue
                db = get_db()
                cur = db.cursor()
                count = process_file(cur, path, limit_bytes=consumed)
                db.commit()
                cur.close()
                total += count
                resolved = os.path.realpath(path)
                if not any(_is_within(resolved, d) for d in allowed):
                    logger.error("Cleanup refused — %s outside configured directories", path)
                    continue
                _drop_consumed_prefix(path, consumed)
        except Exception as exc:
            logger.error("Error processing %s: %s", path, exc)
            if db:
                try:
                    db.rollback()
                except Exception as e2:
                    logger.debug("DB rollback error: %s", e2)
            errors += 1
        finally:
            if db:
                db.close()
    logger.info("Honeypot ingestion complete — %d records, %d errors.", total, errors)


POLL_INTERVAL = 30  # seconds between passes; keeps systemd and the logs quiet


def main() -> int:
    """Entry point for ``honeylens-ingest-honeypot`` (systemd unit sensor-ingest-honeypot).

    An unhandled exception in one pass is logged and the loop carries on — a process that
    dies once a day and silently restarts is a class of failure we do not want here.
    """
    from honeylens.logging_setup import setup_logging

    setup_logging()
    logger.info("ingest_honeypot starting — polling every %ds", POLL_INTERVAL)
    while True:
        try:
            ingest()
        except Exception:
            logger.exception("Unhandled error in ingest()")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
