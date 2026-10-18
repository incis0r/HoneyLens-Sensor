"""HoneyLens SIEM / log-forwarding integrations.

Public API:
    from honeylens.siem import get_manager, forward_event

    get_manager()       — returns the singleton SiemManager
    forward_event(ev)   — non-blocking enqueue for fan-out to all enabled forwarders

Forwarder types (built-in):
    syslog    — RFC 5424 over TCP / UDP / TCP+TLS
    wazuh     — JSON over TCP to Wazuh manager (default 1514)
    loki      — HTTP push to /loki/api/v1/push
    splunk    — Splunk HEC (HTTPS + token)
    elastic   — Elastic / OpenSearch _bulk index API
    webhook   — generic POST JSON (SSRF-guarded)

Configuration is in ``config.SIEM_FORWARDERS`` (a list of dicts) and credentials
are sourced from environment variables — never put raw secrets in config.
"""

import datetime
import time

from honeylens.siem.base import SiemError, SiemEvent, SiemForwarder
from honeylens.siem.manager import SiemManager, forward_event, get_manager

__all__ = [
    "SiemError",
    "SiemEvent",
    "SiemForwarder",
    "SiemManager",
    "forward_event",
    "forward_event_dict",
    "get_manager",
]


_SEVERITY_FROM_TAGS = (
    # ordered: first match wins
    ("critical", ("RCE", "EXPLOIT", "CVE_", "RANSOMWARE", "LATERAL_MOVE", "PSEXEC")),
    (
        "high",
        (
            "BRUTE",
            "CREDENTIAL_CAPTURE",
            "AUTH_ATTACK",
            "PANOS_SSH_CRED",
            "FORTIWEB",
            "FORTI_",
            "PANOS_",
            "K8S_ATTACK",
            "ICS_ATTACK",
        ),
    ),
    (
        "medium",
        (
            "SCANNER",
            "SMB_SCAN",
            "SMB_EXPLOIT_PROBE",
            "SQLI",
            "XSS",
            "LFI",
            "RFI",
            "PROTO_ABUSE",
            "MQTT_ATTACK",
        ),
    ),
    ("low", ("BANNER_GRAB", "PORT_SCAN", "INFO_DISCLOSURE", "SMTP_PROBE")),
)


def _severity_from_attack_types(attack_types: str) -> tuple[str, int]:
    """Map a comma-separated attack_types string → (severity_label, syslog_num).

    Conservative default is 'informational' (syslog 6). The mapping is
    deliberately simple and operator-tunable (edit this table). The labels
    are stable across SIEM destinations.
    """
    if not attack_types:
        return "informational", 6
    upper_tags = attack_types.upper()
    for label, prefixes in _SEVERITY_FROM_TAGS:
        if any(p in upper_tags for p in prefixes):
            return label, {"critical": 2, "high": 3, "medium": 4, "low": 5}[label]
    return "informational", 6


def forward_event_dict(row: dict) -> bool:
    """Build a SiemEvent from a sensor_events DB row dict and forward it.

    This is the helper most ingest paths should call right after the row
    has been INSERTed. It's safe to call when SIEM_FORWARDERS is empty
    (returns False without doing any work).

    Expected dict keys (all optional except event_id and source):
        event_id, timestamp, source, protocol, src_ip, src_port,
        dst_ip, dst_port, attack_types, payload, payload_hash, metadata
    """
    mgr = get_manager()
    # Cheap fast-path: no forwarders configured → don't allocate a SiemEvent.
    if not mgr.get_forwarders():
        return False
    sev_label, sev_num = _severity_from_attack_types(row.get("attack_types", "") or "")
    ts = row.get("timestamp")
    if isinstance(ts, datetime.date):  # datetime is a subclass of date
        ts_str = ts.isoformat()
    elif ts:
        ts_str = str(ts)
    else:
        ts_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    meta = row.get("metadata")
    event = SiemEvent(
        event_id=str(row.get("event_id") or ""),
        timestamp=ts_str,
        source=str(row.get("source") or ""),
        protocol=str(row.get("protocol") or ""),
        src_ip=str(row.get("src_ip") or ""),
        src_port=row.get("src_port"),
        dst_ip=str(row.get("dst_ip") or ""),
        dst_port=row.get("dst_port"),
        attack_types=str(row.get("attack_types") or ""),
        severity=sev_label,
        severity_num=sev_num,
        payload=str(row.get("payload") or ""),
        payload_hash=str(row.get("payload_hash") or ""),
        metadata=meta if isinstance(meta, dict) else {},
    )
    return mgr.forward(event)
