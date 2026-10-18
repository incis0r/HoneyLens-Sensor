"""
classification/text_rules.py — Text Regex Attack Detection Rules
================================================================
621 regex rules + port/context gating sets + custom DB rules loader.
Extracted from attack_classifier.py (Phase 1 cleanup).
"""

from __future__ import annotations

import logging
import re

import psycopg2

from honeylens.classification.rules import register_all
from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY

logger = logging.getLogger("honeylens.classifier")

# Rule storage — same type alias as attack_classifier.py
AttackHit = tuple[str, str, str]  # (attack_type, rule_name, matched_text)
_RULES: list[tuple[str, str, re.Pattern[str]]] = []


class _CountingPattern:
    r"""A rule that counts occurrences instead of backtracking over a repeated group.

    Duck-types the only parts of ``re.Pattern`` anything here uses — ``.pattern``,
    ``.flags`` and ``.search()`` — so the classifier and the scoring helpers need no
    change, and the golden snapshot still records a pattern and flags.

    It exists because "ten or more alias constructs" is a *counting* problem, and
    writing it as one repeated group turned it into a quadratic one. The original
    ``graphql_alias_dos`` was ``(\w+\s*:\s*\w+\s*\{.*?){10,}``: the lazy ``.*?`` inside a
    ``{10,}`` group lets the engine redistribute the tail across the repetitions, so a
    payload that *almost* matches forces it to try every split. Measured: 3.5 s for an
    836-byte payload, 59.6 s for 3.2 KB, growing as O(n²) — with the attacker choosing
    the length, on a path that had no length cap.

    ``finditer`` over a sub-pattern with no nesting is linear, stops as soon as the
    threshold is reached, and says exactly what the rule means.
    """

    __slots__ = ("_min", "_rx", "flags", "pattern")

    def __init__(self, sub_pattern: str, min_count: int, flags: int):
        self._rx = re.compile(sub_pattern, flags)
        self._min = int(min_count)
        self.pattern = sub_pattern
        self.flags = self._rx.flags

    def search(self, target: str):
        """Return the first occurrence once `min_count` of them exist, else None."""
        first = None
        count = 0
        for match in self._rx.finditer(target):
            if first is None:
                first = match
            count += 1
            if count >= self._min:
                return first
        return None

    def __repr__(self) -> str:
        return f"<_CountingPattern {self.pattern!r} x>={self._min}>"


def compile_rule(pattern, flags=re.IGNORECASE, *, min_count=None):
    """Build the matcher for one rule definition.

    Public because the `add` sink is not only ours: tests build their own to get a lookup
    table of the registry. They have to construct rules the same way we do, or a counting
    rule silently degrades into "one occurrence" there and the test is no longer testing
    the shipped behaviour.
    """
    if min_count is not None:
        return _CountingPattern(pattern, min_count, flags)
    return re.compile(pattern, flags)


def _add(attack_type, rule_name, pattern, flags=re.IGNORECASE, *, min_count=None):
    """Register a rule. With `min_count`, `pattern` is one occurrence and N are required."""
    try:
        compiled = compile_rule(pattern, flags, min_count=min_count)
    except re.error:
        logger.debug("Skipping invalid rule regex: %s", rule_name)
        return
    _RULES.append((attack_type, rule_name, compiled))


# The rule definitions live in the classification/rules package; register_all recreates
# them via _add, building _RULES exactly as it was before the extraction.
register_all(_add)
_ICS_PORTS = {
    102,  # S7comm (Siemens)
    502,  # Modbus TCP
    20000,  # DNP3
    44818,  # EtherNet/IP (CIP)
    2222,  # EtherNet/IP (alternate)
    47808,  # BACnet
    4840,  # OPC UA
    4843,  # OPC UA (secure)
    2404,  # IEC 60870-5-104
    1911,  # Niagara Fox
    9600,  # OMRON FINS
    18245,  # GE SRTP
    5094,  # HART-IP
    1883,  # MQTT
    8883,  # MQTT-TLS
}
_HTTP_PORTS = {
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
    # K8s/Container ports that serve HTTP
    6443,
    8001,
    10250,
    10255,
    # FortiGate honeypot
    9443,
}
_ICS_PORT_CONTEXT_RULES = {
    # Binary pattern rules
    "s7comm_header",
    "s7comm_list_blocks",
    "dnp3_data_link_probe",
    "enip_list_identity",
    "enip_list_services",
    "bacnet_whois",
    "opcua_hello",
    "iec104_interrogation",
    # Caldera rules (too generic, match on normal web traffic)
    "caldera_agent_beacon",
    "caldera_c2_api",
    "caldera_payload_download",
    "caldera_ability_execute",
    "caldera_executor_config",
    "caldera_adversary_profile",
    "caldera_ics_fieldmanual",
    # Generic ICS recon (match on too many things)
    "ics_port_scan",
    "ics_shodan_query",
    "ics_banner_grab",
}
_HTTP_EXCLUDED_RULES = {
    # All Caldera rules (match on web APIs)
    "caldera_agent_beacon",
    "caldera_c2_api",
    "caldera_payload_download",
    "caldera_ability_execute",
    "caldera_executor_config",
    "caldera_adversary_profile",
    "caldera_ics_fieldmanual",
    # Generic ICS patterns
    "ics_port_scan",
    "ics_shodan_query",
    "ics_banner_grab",
    # S7comm patterns that match TLS/binary data
    "s7comm_header",
    "s7comm_list_blocks",
    "s7comm_read_szl",
    "s7comm_cpu_info",
    "s7comm_download_block",
    "s7comm_write_var",
    "s7comm_stop_cpu",
    "s7comm_plc_control",
    "s7comm_set_clock",
    "s7comm_set_password",
    "s7comm_scanner_plcscan",
    "s7comm_metasploit",
    # DNP3 patterns
    "dnp3_data_link_probe",
    "dnp3_read_request",
    "dnp3_cold_restart",
    "dnp3_warm_restart",
    "dnp3_disable_unsolicited",
    "dnp3_direct_operate",
    "dnp3_select_operate",
    "dnp3_write_request",
    "dnp3_file_transfer",
    "dnp3_clear_restart_iin",
    "dnp3_scanner_aegis",
    # IEC-104 patterns
    "iec104_startdt",
    "iec104_interrogation",
    "iec104_read_command",
    "iec104_counter_interrogation",
    "iec104_single_command",
    "iec104_double_command",
    "iec104_regulating_step",
    "iec104_setpoint",
    "iec104_reset_process",
    "iec104_scanner",
    # EtherNet/IP patterns
    "enip_list_identity",
    "enip_list_services",
    "enip_list_interfaces",
    "cip_get_attributes",
    "cip_get_all_attributes",
    "cip_set_attribute",
    "cip_execute",
    "cip_reset_service",
    "cip_stop_service",
    "enip_scanner_nmap",
    "enip_scanner_plcinfo",
    # BACnet patterns
    "bacnet_whois",
    "bacnet_device_discovery",
    "bacnet_read_property",
    "bacnet_read_property_multiple",
    "bacnet_read_range",
    "bacnet_write_property",
    "bacnet_write_property_multiple",
    "bacnet_subscribe_cov",
    "bacnet_reinitialize",
    "bacnet_scanner_bacpypes",
    # OPC UA patterns
    "opcua_find_servers",
    "opcua_browse",
    "opcua_read_attributes",
    "opcua_create_subscription",
    "opcua_history_read",
    "opcua_write",
    "opcua_call_method",
    "opcua_no_security",
    "opcua_scanner",
    # Modbus binary patterns (can match random binary in TLS/HTTP)
    "modbus_read_coils",
    "modbus_read_discrete_inputs",
    "modbus_read_holding_registers",
    "modbus_read_input_registers",
    "modbus_write_coil_binary",
    "modbus_write_register_binary",
    "modbus_write_multi_coils_binary",
    "modbus_write_multi_registers_binary",
    "modbus_diagnostics_binary",
    "modbus_device_id_binary",
    "modbus_report_slave_binary",
    "modbus_broadcast_binary",
    "modbus_illegal_fc_binary",
    # MQTT patterns (should only match on MQTT ports 1883, 8883)
    "mqtt_default_user_text",
    "mqtt_default_pass_text",
    "mqtt_anonymous_connect",
    "mqtt_weak_credentials",
    "mqtt_topic_sensitive",
    "mqtt_config_disclosure",
    "mqtt_iot_keywords",
}
_K8S_PORTS = {6443, 8001, 10250, 10255, 2379, 2380, 30000, 30001, 30080, 30443}

# =========================================================================
# AI-Approved Custom Rules — loaded from PostgreSQL at import time
#
# Importing this module therefore makes one database connection. Without a database
# (refused) this costs a fraction of a second; with an unreachable host it costs as much as
# DB_CONNECT_TIMEOUT from the configuration (default 5 s — without this limit the import
# hung for over a minute, measured 2026-09-19).
# =========================================================================
# Rules approved by analysts via /ai/rules dashboard are stored in the
# ai_custom_rules table and loaded here alongside the built-in rules above.
#
# Schema: ai_custom_rules (rule_name, attack_type, regex_pattern, severity,
#         mitre_technique, enabled, source_event_id, ...)
#
# This section is self-contained — if the DB is unavailable or the table
# doesn't exist, it silently skips. No external dependencies beyond psycopg2
# and config.py which are already required by the sensor.

#: Compilation flags for custom rules. analysis/rule_validator MUST use the same ones,
#: so that validation and classification agree on matches.
CUSTOM_RULE_FLAGS = re.IGNORECASE | re.DOTALL

_CUSTOM_RULES_LOADED = False
_CUSTOM_RULE_NAMES: set = set()


def _load_custom_rules_from_db() -> int:
    """
    Load enabled custom rules from ai_custom_rules table into _RULES.
    Called once at import time. Returns number of rules loaded.
    Safe to call multiple times (idempotent unless force-reloaded).
    """
    global _CUSTOM_RULES_LOADED, _CUSTOM_RULE_NAMES

    if _CUSTOM_RULES_LOADED:
        return len(_CUSTOM_RULE_NAMES)

    try:
        from honeylens.database import db_cursor
    except ImportError:
        _CUSTOM_RULES_LOADED = True
        return 0

    rows = []
    try:
        with db_cursor() as cur:
            # Check table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_name = 'ai_custom_rules'
                )
            """)
            if not cur.fetchone()[0]:
                _CUSTOM_RULES_LOADED = True
                return 0

            # Fetch enabled rules
            cur.execute("""
                SELECT rule_name, attack_type, regex_pattern, severity
                FROM ai_custom_rules
                WHERE enabled = TRUE
                ORDER BY id
            """)
            rows = cur.fetchall()
    except (psycopg2.Error, OSError) as e:
        # No database at import time is normal (tools, tests); a bad database response is not.
        logger.debug("Custom rules DB load failed: %s", e)
        _CUSTOM_RULES_LOADED = True
        return 0

    if not rows:
        _CUSTOM_RULES_LOADED = True
        return 0

    # Build set of existing rule names to avoid conflicts
    existing_names = {r[1] for r in _RULES}
    loaded = 0

    for rule_name, attack_type, regex_pattern, severity in rows:
        # Skip if name conflicts with built-in rule
        if rule_name in existing_names:
            continue

        # Validate and compile regex
        try:
            compiled = re.compile(regex_pattern, CUSTOM_RULE_FLAGS)
        except re.error as e:
            logger.debug("Skipping invalid custom rule regex '%s': %s", rule_name, e)
            continue

        _RULES.append((attack_type, rule_name, compiled))
        _CUSTOM_RULE_NAMES.add(rule_name)
        existing_names.add(rule_name)

        # Register severity for new attack types
        if attack_type not in ATTACK_TYPE_SEVERITY:
            sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
            ATTACK_TYPE_SEVERITY[attack_type] = sev_map.get((severity or "").upper(), "high")

        loaded += 1

    _CUSTOM_RULES_LOADED = True
    return loaded


def reload_custom_rules() -> int:
    """
    Hot-reload custom rules: remove previously injected rules,
    then load fresh from database. Called by POST /ai/rules/reload.
    Returns number of rules loaded.
    """
    global _CUSTOM_RULES_LOADED

    # In-place, not by replacing the list: attack_classifier imports _RULES by reference at
    # startup, so `_RULES = [...]` would leave the classifier with a stale list forever. In
    # 0.9 this path never worked (the loader was dead), so no one saw it.
    if _CUSTOM_RULE_NAMES:
        _RULES[:] = [r for r in _RULES if r[1] not in _CUSTOM_RULE_NAMES]
        _CUSTOM_RULE_NAMES.clear()

    _CUSTOM_RULES_LOADED = False
    return _load_custom_rules_from_db()


def get_custom_rule_names():
    """Return set of currently loaded custom rule names."""
    return _CUSTOM_RULE_NAMES.copy()


def is_custom_rule(rule_name: str) -> bool:
    """Check if a rule is an AI-approved custom rule."""
    return rule_name in _CUSTOM_RULE_NAMES


# Auto-load custom rules on module import
_custom_count = _load_custom_rules_from_db()

# Encrypted/binary protocols — skip text regex rules
_ENCRYPTED_PROTOCOLS = frozenset(
    {
        "TLS",
        "TLS/1.0",
        "TLS/1.2+",
        "SSL",
        "SSH",
        "RDP",
        "PostgreSQL/SSL",
        "MQTTS",
        "HTTPS",
        "IMAPS",
        "POP3S",
        "FTPS",
        "LDAPS",
        "SMTPS",
    }
)

_BINARY_PROTOCOLS = frozenset(
    {
        # ICS/OT — handled by dedicated binary detectors below
        "Modbus",
        "S7comm",
        "S7COMM",
        "BACnet",
        "BACNET",
        "EtherNet/IP",
        "ENIP",
        "IEC-104",
        "DNP3",
        "OPC-UA",
        "OPCUA",
        "PROFINET",
        "PNIO",
        "FINS",
        "Omron",
        "Melsec",
        "MC_Protocol",
        "CoAP",
        "LwM2M",
        # Network infrastructure
        "ICMP",
        "DNS",
        "NTP",
        "SNMP",
        "DHCP",
        "RADIUS",
        "STUN",
        "VXLAN",
        "IKE",
        "TFTP",
        "mDNS",
        "SSDP",
        # Database binary protocols (after initial handshake)
        "MySQL",
        "PostgreSQL",
        "Oracle/TNS",
        "MSSQL/TDS",
        # Other binary protocols
        "Java-RMI",
        "VNC/RFB",
        "SMB",
        "SMB2",
        "ADB",
        "Cassandra",
        "Bitcoin",
        "Diameter",
        "Kafka",
        "Memcached/bin",
    }
)

_PLAINTEXT_PROTOCOLS = frozenset(
    {
        "HTTP",
        "FTP",
        "SMTP",
        "Telnet",
        "MQTT",
        "Redis",
        "Memcached",
        "IRC",
        "XMPP",
        "Syslog",
        "POP3",
        "IMAP",
        "LDAP",
        "Elasticsearch",
        "CoAP",
    }
)
