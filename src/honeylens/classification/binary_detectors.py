"""
classification/binary_detectors.py — Binary Protocol Attack Detectors
=====================================================================
14 binary protocol detectors + K8s detector + payload heuristics.
Extracted from attack_classifier.py (Phase 1 cleanup).

Each detector: takes payload (hex string or bytes), returns List[AttackHit].
"""

from __future__ import annotations

import logging
import re

from honeylens.classification.text_rules import _K8S_PORTS

logger = logging.getLogger("honeylens.classifier.binary")

AttackHit = tuple[str, str, str]

# A port number alone is not evidence of an attack: eBPF records a ~60-byte frame
# for every SYN scan, and its few bytes of TCP header are enough to get past an
# `if not payload` guard. Rules keyed only on a destination port must therefore
# require the request itself before claiming a protocol-specific attack.
_HTTP_REQUEST_RE = re.compile(r"\b(get|post|put|patch|delete|head|options)\s+/")


def _has_http_request(payload_lower: str) -> bool:
    """True if the payload actually contains an HTTP request, not just bytes."""
    return bool(_HTTP_REQUEST_RE.search(payload_lower)) or "http/1." in payload_lower


# Paths that mean the caller is actually talking to a Kubernetes API surface rather
# than merely touching a port we happen to present on. Deliberately narrow: `/version`
# and `/healthz` are here because kubectl proxy answers them, but a bare `/` is not.
#
# `/api` must not be treated as a wildcard. A first cut used `/api\b`, which promptly
# counted `GET /api/mcp` — Model Context Protocol probing, of which there is a lot right
# now — as a Kubernetes attack. Kubernetes exposes `/api` itself, `/api/v<N>` and
# `/apis/`; anything else under `/api/` belongs to somebody else's product.
#
# Kubernetes resource nouns. The path prefix alone is not evidence: a scanner spraying a
# generic web wordlist produces `/api/v1/config.json`, `/api/v1/swagger.json`,
# `/api/v1/sms-sender` and `/apis/.env.dev` — all of which match `/api/v<N>` and none of
# which is Kubernetes. What a real client asks for is a *resource*.
_K8S_RESOURCES = (
    "pods?|secrets?|namespaces?|nodes?|configmaps?|services?|deployments?|"
    "replicasets?|daemonsets?|statefulsets?|jobs?|cronjobs?|ingresses|ingress|"
    "serviceaccounts?|persistentvolumeclaims?|persistentvolumes?|events?|"
    "endpoints?|roles?|rolebindings?|clusterroles?|clusterrolebindings?"
)

_K8S_API_PATH_RE = re.compile(
    r"(?:^|\s)(?:get|post|put|patch|delete|head)\s+"
    r"(?:https?://[^/\s]+)?"
    r"(?:"
    rf"/api/v\d+(?:beta\d*)?/(?:{_K8S_RESOURCES})\b"
    + rf"|/api/v\d+/namespaces/[^/\s]+/(?:{_K8S_RESOURCES})\b"
    + rf"|/apis/[a-z0-9.\-]+/v\d+[a-z0-9]*/(?:{_K8S_RESOURCES})\b"
    +
    # An API group listing is a real discovery request: /apis/apps/v1. The version
    # segment is what separates it from /apis/config/config.js, which is a wordlist hit.
    r"|/apis/[a-z0-9.\-]+/v\d+[a-z0-9]*(?:[/?\s]|$)"
    r"|/api(?:[?\s]|$)"  # the API root itself, nothing after it
    r"|/apis(?:[?\s]|$)"
    r"|/version(?:[?\s]|$)|/livez\b|/readyz\b|/openapi/v\d"
    r")"
)


def _has_k8s_api_path(payload_lower: str) -> bool:
    """True if the request asks for something Kubernetes-shaped."""
    return bool(_K8S_API_PATH_RE.search(payload_lower))


def _detect_k8s_attack(
    payload: str, protocol: str | None, metadata: dict | None
) -> list[AttackHit]:
    """
    Context-aware Kubernetes attack detection.
    Only triggers on K8s-specific ports or when protocol indicates K8s.
    """
    hits: list[AttackHit] = []

    if not payload:
        return hits

    # Determine if this is a K8s context
    dst_port = None
    if metadata:
        dst_port = metadata.get("dst_port") or metadata.get("port")
        if isinstance(dst_port, str):
            try:
                dst_port = int(dst_port)
            except ValueError:
                dst_port = None

    proto_lower = (protocol or "").lower()
    is_k8s_context = (
        dst_port in _K8S_PORTS
        or "kubernetes" in proto_lower
        or "kubelet" in proto_lower
        or "etcd" in proto_lower
        or proto_lower in ("kubernetes_api", "kubelet_api", "etcd_api")
    )

    if not is_k8s_context:
        return hits

    # Now check for K8s-specific patterns that would be too generic otherwise
    payload_lower = payload.lower()

    # API Server endpoints (only in K8s context)
    if "/version" in payload_lower and dst_port in (6443, 8001, 10250, 10255):
        hits.append(
            ("K8S_ATTACK", "k8s_version_disclosure", f"K8s version endpoint on port {dst_port}")
        )

    if "/healthz" in payload_lower and dst_port in (6443, 8001, 10250, 10255):
        hits.append(("K8S_ATTACK", "k8s_healthz_probe", f"K8s health endpoint on port {dst_port}"))

    # Same discipline as the proxy gate below: `/api/v1` and `/apis/` are prefixes a
    # generic web scanner produces by accident (/api/v1/config.json, /apis/.env.dev).
    # Enumerating the Kubernetes API means naming a Kubernetes resource.
    if dst_port in (6443, 8001) and _has_k8s_api_path(payload_lower):
        hits.append(
            ("K8S_ATTACK", "k8s_api_enumeration", f"K8s API enumeration on port {dst_port}")
        )

    # Kubelet-specific endpoints
    if dst_port in (10250, 10255):
        if "/pods" in payload_lower or "/runningpods" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_kubelet_pods", "Kubelet pods endpoint access"))
        if "/spec" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_kubelet_spec", "Kubelet spec endpoint access"))
        if "/metrics" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_kubelet_metrics", "Kubelet metrics endpoint access"))
        if "/configz" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_kubelet_configz", "Kubelet config disclosure"))
        if "/exec/" in payload_lower or "/run/" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_kubelet_exec", "Kubelet exec/run attempt"))
        if "/attach/" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_kubelet_attach", "Kubelet attach attempt"))
        if "/logs/" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_kubelet_logs", "Kubelet logs access"))

    # etcd endpoints
    if dst_port in (2379, 2380):
        if "/version" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_etcd_version", "etcd version disclosure"))
        if "/health" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_etcd_health", "etcd health check"))
        if "/v2/keys" in payload_lower or "/v3/kv" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_etcd_data_access", "etcd data access attempt"))
        if "/v2/members" in payload_lower:
            hits.append(("K8S_ATTACK", "k8s_etcd_members", "etcd cluster enumeration"))

    # kubectl proxy / Dashboard. These two ports carry no protocol marker of their own,
    # so the port alone says nothing: requiring a request line (2026-08-12) stopped SYN
    # scans being called K8s attacks, but "any HTTP on this port" was still too generous.
    # On PROD it produced 20,432 events from a single host doing `GET /` and
    # `GET /1:0:1:3ABD:...` with wget — 98.7% of every K8s finding on that sensor, none
    # of it kubectl proxy access.
    #
    # Reaching a kubectl proxy means asking it for something Kubernetes-shaped. A bare
    # `GET /` is a port probe, which is worth recording under its own name rather than
    # inflating the attack count.
    if dst_port in (8001, 30000) and _has_http_request(payload_lower):
        dashboard = dst_port == 30000
        k8s_shaped = _has_k8s_api_path(payload_lower) or (
            dashboard and ("/#/" in payload_lower or "/#!/" in payload_lower)
        )
        # If any rule above already recognised this as Kubernetes — a kubelet endpoint,
        # an etcd key, /healthz, an API group listing — then it is not a blind port
        # probe, whatever this path pattern thinks. Deciding that here rather than by
        # enumerating every path keeps the two labels from contradicting each other on
        # the same event, which is what happened when they were independent.
        already_k8s = any(h[0] == "K8S_ATTACK" for h in hits)
        if k8s_shaped:
            hits.append(
                (
                    "K8S_ATTACK",
                    "k8s_dashboard_access" if dashboard else "k8s_kubectl_proxy",
                    "Kubernetes Dashboard access" if dashboard else "kubectl proxy API access",
                )
            )
        elif not already_k8s:
            hits.append(
                (
                    "RECON",
                    "k8s_dashboard_port_probe" if dashboard else "k8s_proxy_port_probe",
                    "HTTP request to the %s port, no Kubernetes path"
                    % ("Dashboard" if dashboard else "kubectl-proxy"),
                )
            )

    # Deception: honeytoken reuse (injected by honeypot with rule_name field)
    # This block handles events coming through ingest where the honeypot has
    # already set action=honeytoken_reuse — we re-emit as CRITICAL.
    injected_rule = metadata.get("rule_name", "") if metadata else ""
    if injected_rule == "k8s_honeytoken_reuse":
        hits.append(
            (
                "K8S_ATTACK",
                "k8s_honeytoken_reuse",
                "CRITICAL: Bearer token reuse from honeytoken — confirmed attacker",
            )
        )

    # ServiceAccount enumeration
    if "/serviceaccounts" in payload_lower and "/api/v1" in payload_lower:
        if dst_port in (6443, 8001, 8080):
            hits.append(
                ("K8S_ATTACK", "k8s_serviceaccount_enum", "Kubernetes ServiceAccount enumeration")
            )

    # TokenRequest API
    if "/serviceaccounts/" in payload_lower and payload_lower.endswith("/token"):
        if dst_port in (6443, 8001, 8080):
            hits.append(
                (
                    "K8S_ATTACK",
                    "k8s_token_request",
                    "Kubernetes TokenRequest API — service account token theft attempt",
                )
            )

    # Individual secret read
    if "/secrets/" in payload_lower and "/namespaces/" in payload_lower:
        if dst_port in (6443, 8001, 8080):
            hits.append(
                (
                    "K8S_ATTACK",
                    "k8s_secret_read",
                    "Kubernetes individual secret read — potential credential theft",
                )
            )

    return hits


# =========================================================================
# Binary SMB Pattern Detection (for raw packet analysis)
# =========================================================================


def _detect_smb_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect SMB attacks from raw hex payload.

    SMB2 Header Structure:
      [0:4]   ProtocolId (0xFE 'S' 'M' 'B' = 0xFE534D42)
      [4:6]   StructureSize (64)
      [6:8]   CreditCharge
      [8:12]  Status/ChannelSequence
      [12:14] Command
      [14:16] CreditRequest/Response
      [16:20] Flags
      [20:24] NextCommand
      [24:32] MessageId
      [32:36] Reserved/AsyncId
      [36:40] TreeId/AsyncId
      [40:48] SessionId
      [48:64] Signature

    SMB1 Header:
      [0:4]   ProtocolId (0xFF 'S' 'M' 'B' = 0xFF534D42)
      [4]     Command
    """
    hits: list[AttackHit] = []

    if not payload_hex or len(payload_hex) < 8:
        return hits

    try:
        # Handle both hex strings and raw binary (same pattern as _detect_modbus_binary)
        if isinstance(payload_hex, bytes):
            hex_clean = payload_hex.hex().lower()
        else:
            try:
                if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                    hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
                else:
                    hex_clean = (
                        payload_hex.replace(" ", "").replace(":", "").replace("-", "").lower()
                    )
            except (UnicodeDecodeError, AttributeError):
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()

        # Check for SMB2/3 magic bytes (0xFE534D42 = "þSMB")
        if hex_clean.startswith("fe534d42") or "fe534d42" in hex_clean[:64]:
            # Extract command (bytes 12-14)
            if len(hex_clean) >= 28:
                try:
                    cmd_offset = hex_clean.find("fe534d42")
                    if cmd_offset >= 0:
                        cmd_hex = hex_clean[cmd_offset + 24 : cmd_offset + 28]
                        cmd = int(cmd_hex[:2], 16)  # Little-endian

                        # SMB2 Create (0x05) - file access
                        if cmd == 0x05:
                            hits.append(
                                (
                                    "SMB",
                                    "smb2_create_request",
                                    f"SMB2 Create command in {hex_clean[:40]}",
                                )
                            )

                        # SMB2 Write (0x09) - file write
                        elif cmd == 0x09:
                            hits.append(
                                (
                                    "SMB",
                                    "smb2_write_request",
                                    f"SMB2 Write command in {hex_clean[:40]}",
                                )
                            )

                        # SMB2 IOCTL (0x0B) - often used in exploits
                        elif cmd == 0x0B:
                            hits.append(
                                (
                                    "SMB",
                                    "smb2_ioctl_request",
                                    f"SMB2 IOCTL command in {hex_clean[:40]}",
                                )
                            )

                        # SMB2 TreeConnect (0x03) - share access
                        elif cmd == 0x03:
                            hits.append(
                                (
                                    "SMB",
                                    "smb2_tree_connect",
                                    f"SMB2 TreeConnect in {hex_clean[:40]}",
                                )
                            )

                except (ValueError, IndexError):
                    pass  # silent: malformed binary protocol data

        # Check for SMB1 magic bytes (0xFF534D42 = "ÿSMB")
        elif hex_clean.startswith("ff534d42") or "ff534d42" in hex_clean[:64]:
            hits.append(
                ("SMB", "smb1_detected", f"SMBv1 protocol detected (vulnerable): {hex_clean[:32]}")
            )

            # Extract SMB1 command
            if len(hex_clean) >= 10:
                try:
                    cmd_offset = hex_clean.find("ff534d42")
                    if cmd_offset >= 0:
                        cmd = int(hex_clean[cmd_offset + 8 : cmd_offset + 10], 16)

                        # Trans2 (0x32) - commonly used in exploits
                        if cmd == 0x32:
                            hits.append(
                                (
                                    "SMB",
                                    "smb1_trans2",
                                    f"SMB1 Trans2 (exploit vector): {hex_clean[:32]}",
                                )
                            )

                        # NT Trans (0xA0) - used in EternalBlue
                        elif cmd == 0xA0:
                            hits.append(
                                (
                                    "SMB",
                                    "smb1_nt_trans",
                                    f"SMB1 NT Trans (EternalBlue vector): {hex_clean[:32]}",
                                )
                            )

                except (ValueError, IndexError):
                    pass  # silent: malformed binary protocol data

        # Check for NTLM authentication markers.
        # NTLMSSP is a credential-bearing protocol; classify as CREDENTIAL rather
        # than SMB (the transport) so downstream scoring/aggregation handles it
        # as the credential signal it is.
        if "4e544c4d53535000" in hex_clean:  # "NTLMSSP\0" in hex
            hits.append(("CREDENTIAL", "smb_ntlm_auth", "NTLM authentication detected"))

            # Check NTLM message type
            ntlm_pos = hex_clean.find("4e544c4d53535000")
            if len(hex_clean) > ntlm_pos + 18:
                try:
                    msg_type = int(hex_clean[ntlm_pos + 16 : ntlm_pos + 18], 16)
                except ValueError:
                    msg_type = None
                if msg_type == 1:
                    hits.append(
                        ("CREDENTIAL", "smb_ntlm_negotiate", "NTLM Type 1 (Negotiate) message")
                    )
                elif msg_type == 2:
                    hits.append(
                        ("CREDENTIAL", "smb_ntlm_challenge", "NTLM Type 2 (Challenge) message")
                    )
                elif msg_type == 3:
                    hits.append(
                        ("CREDENTIAL", "smb_ntlm_auth_response", "NTLM Type 3 (Auth) message")
                    )

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# Binary Modbus Pattern Detection (for hex payload analysis)
# =========================================================================


def _detect_modbus_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect Modbus attacks from raw hex payload or binary data.

    Modbus TCP structure:
      [0:2]   Transaction ID
      [2:4]   Protocol ID (0x0000 for Modbus)
      [4:6]   Length
      [6]     Unit ID
      [7]     Function Code
      [8:]    Data

    MITRE ATT&CK for ICS mappings:
      T0846 - Remote System Discovery (read operations, device ID)
      T0831 - Manipulation of Control (write operations)
      T0814 - Denial of Service (diagnostics abuse, broadcasts)
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    # Handle both hex strings and raw binary
    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
    else:
        # Check if it's raw binary (non-printable chars)
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                # Likely raw binary, convert to hex
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
            else:
                # Assume it's a hex string
                hex_clean = payload_hex.replace(" ", "").replace(":", "").replace("-", "").lower()
        except (UnicodeDecodeError, AttributeError):
            hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()

    if len(hex_clean) < 16:
        return hits

    try:
        # Check Modbus protocol ID (bytes 2-4 should be 0000)
        if hex_clean[4:8] == "0000":
            # Extract function code (byte 7, hex positions 14-16)
            if len(hex_clean) >= 16:
                fc_hex = hex_clean[14:16]
                try:
                    fc = int(fc_hex, 16)
                except ValueError:
                    return hits

                # Extract Unit ID (byte 6, hex positions 12-14)
                unit_id = 0
                try:
                    unit_id = int(hex_clean[12:14], 16)
                except ValueError:
                    pass  # silent: non-hex payload data

                # ============================================================
                # T0846 - Remote System Discovery (Reconnaissance)
                # ============================================================

                # Read Coils (FC 1) - T0846
                if fc == 0x01:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc01_read_coils",
                            f"T0846 Read Coils FC=0x01 unit={unit_id}",
                        )
                    )

                # Read Discrete Inputs (FC 2) - T0846
                elif fc == 0x02:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc02_read_discrete_inputs",
                            f"T0846 Read Discrete Inputs FC=0x02 unit={unit_id}",
                        )
                    )

                # Read Holding Registers (FC 3) - T0846
                elif fc == 0x03:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc03_read_holding_registers",
                            f"T0846 Read Holding Registers FC=0x03 unit={unit_id}",
                        )
                    )

                # Read Input Registers (FC 4) - T0846
                elif fc == 0x04:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc04_read_input_registers",
                            f"T0846 Read Input Registers FC=0x04 unit={unit_id}",
                        )
                    )

                # Report Slave ID (FC 17) - T0846
                elif fc == 0x11:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc17_report_slave_id",
                            f"T0846 Report Slave ID FC=0x11 unit={unit_id}",
                        )
                    )

                # Read Device Identification / MEI (FC 43) - T0846
                elif fc == 0x2B:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc43_read_device_id",
                            f"T0846 Read Device ID FC=0x2B unit={unit_id}",
                        )
                    )

                # ============================================================
                # T0831 - Manipulation of Control (Write Operations)
                # ============================================================

                # Write Single Coil (FC 5) - T0831
                elif fc == 0x05:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc05_write_single_coil",
                            f"T0831 Write Single Coil FC=0x05 unit={unit_id}",
                        )
                    )

                # Write Single Register (FC 6) - T0831
                elif fc == 0x06:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc06_write_single_register",
                            f"T0831 Write Single Register FC=0x06 unit={unit_id}",
                        )
                    )

                # Write Multiple Coils (FC 15) - T0831
                elif fc == 0x0F:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc15_write_multiple_coils",
                            f"T0831 Write Multiple Coils FC=0x0F unit={unit_id}",
                        )
                    )

                # Write Multiple Registers (FC 16) - T0831
                elif fc == 0x10:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc16_write_multiple_registers",
                            f"T0831 Write Multiple Registers FC=0x10 unit={unit_id}",
                        )
                    )

                # Mask Write Register (FC 22) - T0831
                elif fc == 0x16:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc22_mask_write_register",
                            f"T0831 Mask Write Register FC=0x16 unit={unit_id}",
                        )
                    )

                # Read/Write Multiple Registers (FC 23) - T0831
                elif fc == 0x17:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc23_read_write_registers",
                            f"T0831 Read/Write Registers FC=0x17 unit={unit_id}",
                        )
                    )

                # ============================================================
                # T0814 - Denial of Service / Diagnostics Abuse
                # ============================================================

                # Diagnostics (FC 8) - can be abused for DoS
                elif fc == 0x08:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_fc08_diagnostics",
                            f"T0814 Diagnostics FC=0x08 unit={unit_id}",
                        )
                    )

                # ============================================================
                # Suspicious/Anomalous Function Codes
                # ============================================================

                # User-defined function codes (65-72, 100-110)
                elif (65 <= fc <= 72) or (100 <= fc <= 110):
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_user_defined_fc",
                            f"User-defined FC={fc} unit={unit_id}",
                        )
                    )

                # Reserved/illegal function codes (125-127)
                elif 125 <= fc <= 127:
                    hits.append(
                        ("ICS_ATTACK", "modbus_reserved_fc", f"Reserved FC={fc} unit={unit_id}")
                    )

                # ============================================================
                # Broadcast Detection (Unit ID 0 or 255)
                # ============================================================
                if unit_id == 0 or unit_id == 255:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "modbus_broadcast_attack",
                            f"Broadcast Unit ID={unit_id} FC={fc}",
                        )
                    )

                # ============================================================
                # Suspicious Write Data Patterns
                # ============================================================
                if fc in (0x05, 0x06, 0x0F, 0x10, 0x16, 0x17):
                    if len(hex_clean) >= 24:
                        data_portion = hex_clean[16:24]
                        # Check for all zeros (potential reset/disable)
                        if data_portion == "00000000":
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "modbus_write_zeros",
                                    f"Write all zeros: {data_portion}",
                                )
                            )
                        # Check for max values (65535 / 0xFFFF)
                        if "ffff" in data_portion:
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "modbus_write_max_value",
                                    f"Write max value: {data_portion}",
                                )
                            )

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# DNP3 Binary Detection (Port 20000)
# =========================================================================


def _detect_dnp3_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect DNP3 attacks from raw binary payload.

    DNP3 Data Link Layer structure:
      [0:2]   Start bytes (0x0564)
      [2]     Length
      [3]     Control byte
      [4:6]   Destination address (little endian)
      [6:8]   Source address (little endian)
      [8:10]  CRC
      [10:]   Transport + Application layer

    DNP3 Application Layer Function Codes:
      0x00 = Confirm
      0x01 = Read
      0x02 = Write
      0x03 = Select
      0x04 = Operate
      0x05 = Direct Operate
      0x06 = Direct Operate No Ack
      0x0D = Cold Restart
      0x0E = Warm Restart
      0x14 = Enable Unsolicited
      0x15 = Disable Unsolicited
      0x18 = Record Current Time

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery
      T0831 - Manipulation of Control
      T0814 - Denial of Service
      T0816 - Device Restart/Shutdown
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    # Handle both hex strings and raw binary
    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").replace("-", "").lower()
        except (UnicodeDecodeError, AttributeError):
            hex_clean = payload_hex.replace(" ", "").lower()

    if len(hex_clean) < 16:
        return hits

    try:
        # Check DNP3 start bytes (0x0564)
        if hex_clean[:4] == "0564":
            # Extract control byte
            ctrl = int(hex_clean[6:8], 16) if len(hex_clean) >= 8 else 0

            # Extract destination and source addresses
            dst_addr = int(hex_clean[8:10] + hex_clean[10:12], 16) if len(hex_clean) >= 12 else 0
            src_addr = int(hex_clean[12:14] + hex_clean[14:16], 16) if len(hex_clean) >= 16 else 0

            # Basic DNP3 frame detection
            hits.append(
                (
                    "ICS_ATTACK",
                    "dnp3_frame_detected",
                    f"DNP3 frame ctrl=0x{ctrl:02x} dst={dst_addr} src={src_addr}",
                )
            )

            # Try to extract function code from application layer (after transport)
            # Application layer starts around byte 11+ depending on transport header
            if len(hex_clean) >= 24:
                # Look for function code patterns in the payload
                fc_offset = 22  # Approximate offset for function code
                if len(hex_clean) > fc_offset + 2:
                    try:
                        fc = int(hex_clean[fc_offset : fc_offset + 2], 16)

                        # T0846 - Discovery
                        if fc == 0x01:  # Read
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "dnp3_read_request",
                                    "T0846 DNP3 Read Request FC=0x01",
                                )
                            )

                        # T0831 - Control
                        elif fc == 0x02:  # Write
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "dnp3_write_request",
                                    "T0831 DNP3 Write Request FC=0x02",
                                )
                            )
                        elif fc == 0x03:  # Select
                            hits.append(("ICS_ATTACK", "dnp3_select", "T0831 DNP3 Select FC=0x03"))
                        elif fc == 0x04:  # Operate
                            hits.append(
                                ("ICS_ATTACK", "dnp3_operate", "T0831 DNP3 Operate FC=0x04")
                            )
                        elif fc == 0x05:  # Direct Operate
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "dnp3_direct_operate",
                                    "T0831 DNP3 Direct Operate FC=0x05",
                                )
                            )
                        elif fc == 0x06:  # Direct Operate No Ack
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "dnp3_direct_operate_noack",
                                    "T0831 DNP3 Direct Operate No Ack FC=0x06",
                                )
                            )

                        # T0816 - Restart/Shutdown
                        elif fc == 0x0D:  # Cold Restart
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "dnp3_cold_restart",
                                    "T0816 DNP3 Cold Restart FC=0x0D",
                                )
                            )
                        elif fc == 0x0E:  # Warm Restart
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "dnp3_warm_restart",
                                    "T0816 DNP3 Warm Restart FC=0x0E",
                                )
                            )

                        # T0814 - DoS
                        elif fc == 0x15:  # Disable Unsolicited
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "dnp3_disable_unsolicited",
                                    "T0814 DNP3 Disable Unsolicited FC=0x15",
                                )
                            )
                        elif fc == 0x14:  # Enable Unsolicited
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "dnp3_enable_unsolicited",
                                    "DNP3 Enable Unsolicited FC=0x14",
                                )
                            )

                    except ValueError:
                        pass  # silent: malformed DNP3 hex data

            # Broadcast detection (destination 0xFFFF)
            if dst_addr == 0xFFFF:
                hits.append(("ICS_ATTACK", "dnp3_broadcast", "DNP3 Broadcast Address dst=0xFFFF"))

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# IEC 60870-5-104 Binary Detection (Port 2404)
# =========================================================================


def _detect_iec104_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect IEC 104 attacks from raw binary payload.

    IEC 104 APDU structure:
      [0]     Start byte (0x68)
      [1]     APDU Length
      [2:6]   Control fields (4 bytes)
      [6:]    ASDU (Application Service Data Unit)

    APCI U-format control bytes:
      0x07 = STARTDT act
      0x0B = STARTDT con
      0x13 = STOPDT act
      0x23 = STOPDT con
      0x43 = TESTFR act
      0x83 = TESTFR con

    ASDU Type IDs (critical):
      45 (0x2D) = C_SC_NA_1 - Single command
      46 (0x2E) = C_DC_NA_1 - Double command
      47 (0x2F) = C_RC_NA_1 - Regulating step command
      48-51    = C_SE_*     - Setpoint commands
      100 (0x64) = C_IC_NA_1 - Interrogation command
      105 (0x69) = C_RP_NA_1 - Reset process

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery
      T0831 - Manipulation of Control
      T0814 - Denial of Service
      T0816 - Device Restart/Shutdown
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    # Handle both hex strings and raw binary
    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()
        except (UnicodeDecodeError, AttributeError):
            hex_clean = payload_hex.replace(" ", "").lower()

    if len(hex_clean) < 12:
        return hits

    try:
        # Check IEC 104 start byte (0x68)
        if hex_clean[:2] == "68":
            _apdu_len = int(hex_clean[2:4], 16) if len(hex_clean) >= 4 else 0

            # Extract control field (bytes 2-5)
            if len(hex_clean) >= 12:
                ctrl1 = int(hex_clean[4:6], 16)
                _ctrl2 = int(hex_clean[6:8], 16)
                _ctrl3 = int(hex_clean[8:10], 16)
                _ctrl4 = int(hex_clean[10:12], 16)

                # U-format detection
                if ctrl1 == 0x07:
                    hits.append(("ICS_ATTACK", "iec104_startdt_act", "IEC-104 STARTDT Activation"))
                elif ctrl1 == 0x0B:
                    hits.append(
                        ("ICS_ATTACK", "iec104_startdt_con", "IEC-104 STARTDT Confirmation")
                    )
                elif ctrl1 == 0x13:
                    hits.append(
                        ("ICS_ATTACK", "iec104_stopdt_act", "T0814 IEC-104 STOPDT Activation")
                    )
                elif ctrl1 == 0x43:
                    hits.append(("ICS_ATTACK", "iec104_testfr_act", "IEC-104 TESTFR Activation"))

                # I-format (data transfer) - check for ASDU
                elif (ctrl1 & 0x01) == 0:  # I-format has LSB = 0
                    # ASDU starts at byte 6 (hex position 12)
                    if len(hex_clean) >= 14:
                        type_id = int(hex_clean[12:14], 16)

                        # T0846 - Discovery
                        if type_id == 100:  # C_IC_NA_1 - Interrogation
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_interrogation",
                                    "T0846 IEC-104 General Interrogation TypeID=100",
                                )
                            )
                        elif type_id == 101:  # C_CI_NA_1 - Counter Interrogation
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_counter_interrogation",
                                    "T0846 IEC-104 Counter Interrogation TypeID=101",
                                )
                            )
                        elif type_id == 102:  # C_RD_NA_1 - Read Command
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_read_command",
                                    "T0846 IEC-104 Read Command TypeID=102",
                                )
                            )

                        # T0831 - Control Commands
                        elif type_id == 45:  # C_SC_NA_1 - Single Command
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_single_command",
                                    "T0831 IEC-104 Single Command TypeID=45",
                                )
                            )
                        elif type_id == 46:  # C_DC_NA_1 - Double Command
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_double_command",
                                    "T0831 IEC-104 Double Command TypeID=46",
                                )
                            )
                        elif type_id == 47:  # C_RC_NA_1 - Regulating Step
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_regulating_step",
                                    "T0831 IEC-104 Regulating Step TypeID=47",
                                )
                            )
                        elif 48 <= type_id <= 51:  # Setpoint commands
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_setpoint_command",
                                    f"T0831 IEC-104 Setpoint Command TypeID={type_id}",
                                )
                            )
                        elif type_id == 58:  # C_SC_TA_1 - Single Command with Time
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_single_command_time",
                                    "T0831 IEC-104 Single Command w/Time TypeID=58",
                                )
                            )

                        # T0816 - Restart/Reset
                        elif type_id == 105:  # C_RP_NA_1 - Reset Process
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_reset_process",
                                    "T0816 IEC-104 Reset Process TypeID=105",
                                )
                            )

                        # Parameter/Config changes
                        elif type_id == 110:  # P_ME_NA_1 - Parameter Measured Value
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_parameter_change",
                                    "T0831 IEC-104 Parameter Change TypeID=110",
                                )
                            )
                        elif type_id == 112:  # P_AC_NA_1 - Parameter Activation
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "iec104_parameter_activation",
                                    "T0831 IEC-104 Parameter Activation TypeID=112",
                                )
                            )

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# S7comm/Siemens Binary Detection (Port 102)
# =========================================================================


def _detect_s7comm_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect S7comm attacks from raw binary payload.

    S7comm structure (over TPKT + COTP):
      TPKT: [0x03, 0x00, length_hi, length_lo]
      COTP: [length, pdu_type, ...]
      S7:   [0x32, msg_type, ...]

    S7comm Message Types:
      0x01 = Job (request)
      0x02 = Ack
      0x03 = Ack-Data (response)
      0x07 = Userdata

    S7comm Function Codes:
      0x00 = CPU Services
      0x04 = Read Variable
      0x05 = Write Variable
      0x1A = Request Download
      0x1B = Download Block
      0x1C = Download Ended
      0x1D = Start Upload
      0x1E = Upload
      0x1F = End Upload
      0x28 = PLC Control
      0x29 = PLC Stop

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery
      T0831 - Manipulation of Control
      T0843 - Program Download
      T0816 - Device Restart/Shutdown
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    # Handle both hex strings and raw binary
    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()
        except (UnicodeDecodeError, AttributeError):
            hex_clean = payload_hex.replace(" ", "").lower()

    if len(hex_clean) < 14:
        return hits

    try:
        # Check TPKT header (0x0300)
        if hex_clean[:4] == "0300":
            # COTP starts at byte 4
            _cotp_len = int(hex_clean[8:10], 16) if len(hex_clean) >= 10 else 0
            cotp_pdu = int(hex_clean[10:12], 16) if len(hex_clean) >= 12 else 0

            # COTP Connection Request (0xE0)
            if cotp_pdu == 0xE0:
                hits.append(
                    (
                        "ICS_ATTACK",
                        "s7comm_cotp_connect_request",
                        "T0846 S7comm COTP Connection Request",
                    )
                )
            # COTP Connection Confirm (0xD0)
            elif cotp_pdu == 0xD0:
                hits.append(
                    ("ICS_ATTACK", "s7comm_cotp_connect_confirm", "S7comm COTP Connection Confirm")
                )
            # COTP Data (0xF0) - contains S7comm
            elif cotp_pdu == 0xF0:
                # S7comm header starts after COTP (typically byte 7 = hex position 14)
                # Look for S7 protocol ID (0x32)
                s7_start = hex_clean.find("32", 12)
                if s7_start >= 0 and s7_start + 6 <= len(hex_clean):
                    # S7comm message type
                    msg_type = int(hex_clean[s7_start + 2 : s7_start + 4], 16)

                    if msg_type == 0x01:  # Job request
                        # Function code is deeper in the packet
                        # Simplified: look for function codes in the rest
                        rest = hex_clean[s7_start:]

                        # Read SZL (System Status List) - discovery
                        if "0001" in rest or "0011" in rest:
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "s7comm_read_szl",
                                    "T0846 S7comm Read SZL (CPU Info)",
                                )
                            )

                        # Check for specific function codes
                        if len(rest) >= 16:
                            # Look for function area
                            if "04" in rest[8:16]:  # Read
                                hits.append(
                                    ("ICS_ATTACK", "s7comm_read_var", "T0846 S7comm Read Variable")
                                )
                            elif "05" in rest[8:16]:  # Write
                                hits.append(
                                    (
                                        "ICS_ATTACK",
                                        "s7comm_write_var",
                                        "T0831 S7comm Write Variable",
                                    )
                                )

                    elif msg_type == 0x07:  # Userdata
                        hits.append(("ICS_ATTACK", "s7comm_userdata", "S7comm Userdata Message"))

            # Look for PLC Stop command pattern
            if "29" in hex_clean and "505f50524f4752414d" in hex_clean:  # P_PROGRAM
                hits.append(("ICS_ATTACK", "s7comm_plc_stop", "T0816 S7comm PLC Stop Command"))

            # Look for download patterns
            if "1a" in hex_clean[14:30] or "1b" in hex_clean[14:30]:
                hits.append(("ICS_ATTACK", "s7comm_download_block", "T0843 S7comm Block Download"))

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# BACnet Binary Detection (Port 47808 UDP)
# =========================================================================


def _detect_bacnet_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect BACnet attacks from raw binary payload.

    BACnet/IP structure:
      BVLC: [type, function, length]
      NPDU: [version, control, ...]
      APDU: [pdu_type, service_choice, ...]

    BVLC Functions:
      0x00 = Result
      0x0A = Original-Unicast-NPDU
      0x0B = Original-Broadcast-NPDU

    APDU Services (Confirmed):
      0x00 = AcknowledgeAlarm
      0x0C = ReadProperty
      0x0E = ReadPropertyMultiple
      0x0F = WriteProperty
      0x10 = WritePropertyMultiple
      0x14 = ReinitializeDevice
      0x1A = SubscribeCOV

    APDU Services (Unconfirmed):
      0x00 = I-Am
      0x01 = I-Have
      0x08 = Who-Is
      0x07 = Who-Has

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery
      T0831 - Manipulation of Control
      T0816 - Device Restart/Shutdown
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    # Handle both hex strings and raw binary
    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()
        except (UnicodeDecodeError, AttributeError):
            hex_clean = payload_hex.replace(" ", "").lower()

    if len(hex_clean) < 16:
        return hits

    try:
        # Check BVLC header (0x81 for BACnet/IP)
        if hex_clean[:2] == "81":
            bvlc_func = int(hex_clean[2:4], 16)
            _bvlc_len = int(hex_clean[4:8], 16)

            # NPDU starts after BVLC (byte 4 = hex position 8)
            if len(hex_clean) >= 12:
                npdu_version = int(hex_clean[8:10], 16)
                npdu_ctrl = int(hex_clean[10:12], 16) if len(hex_clean) >= 12 else 0

                # Check for valid BACnet
                if npdu_version == 0x01:
                    # APDU offset depends on NPDU control flags
                    apdu_offset = 12
                    if npdu_ctrl & 0x08:  # Has DNET
                        apdu_offset += 6
                    if npdu_ctrl & 0x04:  # Has SNET
                        apdu_offset += 6

                    if len(hex_clean) > apdu_offset + 2:
                        apdu_type = int(hex_clean[apdu_offset : apdu_offset + 2], 16) >> 4

                        # Unconfirmed (type 1)
                        if apdu_type == 1:
                            service = int(hex_clean[apdu_offset : apdu_offset + 2], 16) & 0x0F

                            if service == 0x08:  # Who-Is
                                hits.append(
                                    ("ICS_ATTACK", "bacnet_whois", "T0846 BACnet Who-Is Discovery")
                                )
                            elif service == 0x07:  # Who-Has
                                hits.append(
                                    (
                                        "ICS_ATTACK",
                                        "bacnet_whohas",
                                        "T0846 BACnet Who-Has Discovery",
                                    )
                                )
                            elif service == 0x00:  # I-Am
                                hits.append(("ICS_ATTACK", "bacnet_iam", "BACnet I-Am Response"))

                        # Confirmed (type 0)
                        elif apdu_type == 0:
                            if len(hex_clean) > apdu_offset + 4:
                                service = int(hex_clean[apdu_offset + 2 : apdu_offset + 4], 16)

                                # T0846 - Discovery/Read
                                if service == 0x0C:  # ReadProperty
                                    hits.append(
                                        (
                                            "ICS_ATTACK",
                                            "bacnet_read_property",
                                            "T0846 BACnet ReadProperty",
                                        )
                                    )
                                elif service == 0x0E:  # ReadPropertyMultiple
                                    hits.append(
                                        (
                                            "ICS_ATTACK",
                                            "bacnet_read_property_multiple",
                                            "T0846 BACnet ReadPropertyMultiple",
                                        )
                                    )

                                # T0831 - Control/Write
                                elif service == 0x0F:  # WriteProperty
                                    hits.append(
                                        (
                                            "ICS_ATTACK",
                                            "bacnet_write_property",
                                            "T0831 BACnet WriteProperty",
                                        )
                                    )
                                elif service == 0x10:  # WritePropertyMultiple
                                    hits.append(
                                        (
                                            "ICS_ATTACK",
                                            "bacnet_write_property_multiple",
                                            "T0831 BACnet WritePropertyMultiple",
                                        )
                                    )

                                # T0816 - Restart
                                elif service == 0x14:  # ReinitializeDevice
                                    hits.append(
                                        (
                                            "ICS_ATTACK",
                                            "bacnet_reinitialize_device",
                                            "T0816 BACnet ReinitializeDevice",
                                        )
                                    )

                                # Subscription (monitoring)
                                elif service == 0x1A:  # SubscribeCOV
                                    hits.append(
                                        (
                                            "ICS_ATTACK",
                                            "bacnet_subscribe_cov",
                                            "BACnet SubscribeCOV",
                                        )
                                    )

            # Broadcast detection
            if bvlc_func == 0x0B:
                hits.append(("ICS_ATTACK", "bacnet_broadcast", "BACnet Broadcast Message"))

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# EtherNet/IP Binary Detection (Port 44818)
# =========================================================================


def _detect_enip_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect EtherNet/IP attacks from raw binary payload.

    EtherNet/IP Encapsulation Header:
      [0:2]   Command (little endian)
      [2:4]   Length
      [4:8]   Session Handle
      [8:12]  Status
      [12:20] Sender Context
      [20:24] Options
      [24:]   Command Data

    Commands:
      0x0001 = RegisterSession
      0x0004 = ListServices
      0x0063 = ListIdentity
      0x0064 = ListInterfaces
      0x0065 = RegisterSession
      0x0066 = UnregisterSession
      0x006F = SendRRData (CIP request)
      0x0070 = SendUnitData

    CIP Services:
      0x01 = Get Attribute All
      0x02 = Set Attribute All
      0x03 = Get Attribute List
      0x04 = Set Attribute List
      0x05 = Reset
      0x0E = Get Attribute Single
      0x10 = Set Attribute Single
      0x4B = Execute
      0x4C = Forward Open
      0x4E = Forward Close

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery
      T0831 - Manipulation of Control
      T0816 - Device Restart/Shutdown
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    # Handle both hex strings and raw binary
    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()
        except (UnicodeDecodeError, AttributeError):
            hex_clean = payload_hex.replace(" ", "").lower()

    if len(hex_clean) < 48:  # Min EtherNet/IP header
        return hits

    try:
        # Extract command (little endian)
        cmd = int(hex_clean[2:4] + hex_clean[0:2], 16)

        # T0846 - Discovery Commands
        if cmd == 0x0063:  # ListIdentity
            hits.append(("ICS_ATTACK", "enip_list_identity", "T0846 EtherNet/IP ListIdentity"))
        elif cmd == 0x0004:  # ListServices
            hits.append(("ICS_ATTACK", "enip_list_services", "T0846 EtherNet/IP ListServices"))
        elif cmd == 0x0064:  # ListInterfaces
            hits.append(("ICS_ATTACK", "enip_list_interfaces", "T0846 EtherNet/IP ListInterfaces"))

        # Session Management
        elif cmd == 0x0065:  # RegisterSession
            hits.append(("ICS_ATTACK", "enip_register_session", "EtherNet/IP RegisterSession"))
        elif cmd == 0x0066:  # UnregisterSession
            hits.append(("ICS_ATTACK", "enip_unregister_session", "EtherNet/IP UnregisterSession"))

        # CIP Requests
        elif cmd == 0x006F:  # SendRRData
            hits.append(("ICS_ATTACK", "enip_send_rr_data", "EtherNet/IP SendRRData (CIP Request)"))

            # Look for CIP service codes in payload
            if len(hex_clean) >= 60:
                # CIP service is typically after encapsulation + CPF
                # Simplified: look for service patterns
                cip_data = hex_clean[48:]

                # Get Attribute commands
                if cip_data[:2] in ("01", "03", "0e"):
                    hits.append(("ICS_ATTACK", "cip_get_attribute", "T0846 CIP Get Attribute"))
                # Set Attribute commands
                elif cip_data[:2] in ("02", "04", "10"):
                    hits.append(("ICS_ATTACK", "cip_set_attribute", "T0831 CIP Set Attribute"))
                # Reset
                elif cip_data[:2] == "05":
                    hits.append(("ICS_ATTACK", "cip_reset", "T0816 CIP Reset Service"))
                # Execute
                elif cip_data[:2] == "4b":
                    hits.append(("ICS_ATTACK", "cip_execute", "T0855 CIP Execute Service"))

        elif cmd == 0x0070:  # SendUnitData
            hits.append(("ICS_ATTACK", "enip_send_unit_data", "EtherNet/IP SendUnitData"))

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# MQTT Binary Detection (Port 1883, 8883)
# =========================================================================


def _detect_mqtt_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect MQTT attacks from raw binary payload.

    MQTT Packet structure:
      [0]     Fixed Header: Packet Type (4 bits) + Flags (4 bits)
      [1..]   Remaining Length (variable 1-4 bytes)
      [..]    Variable Header + Payload

    Packet Types:
      1  = CONNECT
      2  = CONNACK
      3  = PUBLISH
      4  = PUBACK
      5  = PUBREC
      6  = PUBREL
      7  = PUBCOMP
      8  = SUBSCRIBE
      9  = SUBACK
      10 = UNSUBSCRIBE
      11 = UNSUBACK
      12 = PINGREQ
      13 = PINGRESP
      14 = DISCONNECT

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery
      T0831 - Manipulation of Control
      T0801 - Monitor Process State
      T0814 - Denial of Service
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    # Handle both hex strings and raw binary
    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
        raw_bytes = payload_hex
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
                raw_bytes = payload_hex.encode("latin-1", errors="ignore")
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()
                raw_bytes = bytes.fromhex(hex_clean)
        except (UnicodeDecodeError, AttributeError, ValueError):
            hex_clean = payload_hex.replace(" ", "").lower()
            try:
                raw_bytes = bytes.fromhex(hex_clean)
            except ValueError:
                return hits

    if len(hex_clean) < 4:
        return hits

    try:
        # Extract packet type from first byte
        first_byte = int(hex_clean[0:2], 16)
        packet_type = (first_byte >> 4) & 0x0F
        flags = first_byte & 0x0F

        # CONNECT (type 1)
        if packet_type == 1:
            hits.append(("MQTT_ATTACK", "mqtt_connect_binary", "MQTT CONNECT packet"))

            # Check for protocol name "MQTT" or "MQIsdp"
            if b"MQTT" in raw_bytes:
                # Look for suspicious credentials
                payload_str = raw_bytes.decode("latin-1", errors="ignore")

                # Anonymous/empty credentials
                if b"\x00\x00" in raw_bytes[10:20]:
                    hits.append(
                        (
                            "MQTT_ATTACK",
                            "mqtt_anonymous_connect_binary",
                            "T0846 MQTT Anonymous Connection",
                        )
                    )

                # Default credentials check
                default_users = [b"admin", b"root", b"mqtt", b"guest", b"user", b"test"]
                for user in default_users:
                    if user in raw_bytes:
                        hits.append(
                            (
                                "MQTT_ATTACK",
                                "mqtt_default_user_binary",
                                f"MQTT Default Username: {user.decode()}",
                            )
                        )
                        break

        # PUBLISH (type 3)
        elif packet_type == 3:
            qos = (flags >> 1) & 0x03
            retain = flags & 0x01

            if retain:
                hits.append(
                    (
                        "MQTT_ATTACK",
                        "mqtt_publish_retain_binary",
                        "T0831 MQTT PUBLISH with Retain flag",
                    )
                )

            if qos == 2:
                hits.append(("MQTT_ATTACK", "mqtt_publish_qos2_binary", "MQTT PUBLISH with QoS 2"))

            # Check topic patterns
            payload_str = raw_bytes[2:].decode("latin-1", errors="ignore")

            # Control topics
            control_keywords = [
                "command",
                "control",
                "actuator",
                "valve",
                "pump",
                "motor",
                "relay",
                "switch",
                "setpoint",
                "config",
            ]
            for kw in control_keywords:
                if kw in payload_str.lower():
                    hits.append(
                        (
                            "MQTT_ATTACK",
                            "mqtt_control_topic_publish",
                            f"T0831 MQTT Publish to control topic: {kw}",
                        )
                    )
                    break

            # $SYS topics
            if "$SYS" in payload_str or "$sys" in payload_str.lower():
                hits.append(("MQTT_ATTACK", "mqtt_sys_topic_publish", "MQTT Publish to $SYS topic"))

        # SUBSCRIBE (type 8)
        elif packet_type == 8:
            hits.append(("MQTT_ATTACK", "mqtt_subscribe_binary", "MQTT SUBSCRIBE packet"))

            payload_str = raw_bytes[2:].decode("latin-1", errors="ignore")

            # Wildcard subscriptions
            if "#" in payload_str:
                hits.append(
                    (
                        "MQTT_ATTACK",
                        "mqtt_wildcard_all_binary",
                        "T0801 MQTT Subscribe to # (all topics)",
                    )
                )
            if "+" in payload_str:
                hits.append(
                    ("MQTT_ATTACK", "mqtt_wildcard_single_binary", "MQTT Subscribe with + wildcard")
                )

            # $SYS topics
            if "$SYS" in payload_str:
                hits.append(
                    (
                        "MQTT_ATTACK",
                        "mqtt_sys_subscribe_binary",
                        "T0846 MQTT Subscribe to $SYS topics",
                    )
                )

        # DISCONNECT (type 14)
        elif packet_type == 14:
            hits.append(("MQTT_ATTACK", "mqtt_disconnect_binary", "MQTT DISCONNECT packet"))

        # PINGREQ flood detection (type 12)
        elif packet_type == 12:
            hits.append(
                ("MQTT_ATTACK", "mqtt_pingreq_binary", "MQTT PINGREQ (potential DoS if rapid)")
            )

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# HTTP-specific extraction: parse URIs and headers from raw payload
# =========================================================================


# =========================================================================
# URL decode helper — handles double-encoding and plus signs
# =========================================================================


# =========================================================================
# Protocol Gating — Encrypted & Binary Protocol Guards (v2.2.0)
# =========================================================================
# Plaintext regex rules MUST NOT run against encrypted or binary protocol
# payloads.  Encrypted data decoded as UTF-8 produces random-looking text
# that accidentally matches broad regex patterns (SQLi, XSS, LFI, RCE),
# creating massive false positives on any internet-facing sensor.

# Protocols that carry encrypted payloads — NO text regex rules at all.
# JA3/JA4 and banner-only checks are handled elsewhere in the pipeline.
_ENCRYPTED_PROTOCOLS = frozenset(
    {
        # TLS variants (from protocol classifier)
        "TLS",
        "TLS/1.0",
        "TLS/1.2+",
        "TLS/1.3",
        "SSL",
        "SSL/TLS",
        # SSH — binary KEX after the banner line
        "SSH",
        # RDP uses TLS/NLA (CredSSP) after initial X.224
        "RDP",
        # TLS-wrapped protocol variants
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

# Protocols that are binary (not human-readable text) — only run
# protocol-specific binary detectors, skip ALL text regex rules.
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

# Protocols where plaintext regex rules ARE appropriate — full rule set.
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


def _is_binary_payload(text: str) -> bool:
    """
    Heuristic: detect if a 'decoded' payload is actually binary/encrypted
    data that was forced through UTF-8 decode with errors='replace'.

    Used as fallback when protocol is unknown (e.g. "TCP" generic).
    """
    if not text or len(text) < 8:
        return False

    sample = text[:512]
    sample_len = len(sample)
    if sample_len == 0:
        return False

    # Check 1: U+FFFD replacement characters — binary data produces many
    replacement_count = sample.count("\ufffd")
    if replacement_count > sample_len * 0.05:
        return True

    # Check 2: high ratio of non-printable control characters
    control_count = sum(1 for c in sample if ord(c) < 0x20 and c not in ("\t", "\n", "\r"))
    if control_count > sample_len * 0.10:
        return True

    # Check 3: low printable ASCII ratio — encrypted data is ~uniform random
    printable_count = sum(1 for c in sample if 0x20 <= ord(c) <= 0x7E)
    if sample_len > 16 and printable_count < sample_len * 0.50:
        return True

    # Check 4: starts with TLS record magic bytes
    # 0x14=CCS, 0x15=Alert, 0x16=Handshake, 0x17=AppData, followed by 0x03
    if len(text) >= 2:
        b0 = ord(text[0])
        b1 = ord(text[1])
        if b0 in (0x14, 0x15, 0x16, 0x17) and b1 == 0x03:
            return True

    return False


# =========================================================================
# Public API
# =========================================================================


def _detect_opcua_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect OPC UA Binary protocol attacks from raw payload.

    OPC UA Binary Message structure:
      [0:3]   Message Type: "HEL", "ACK", "OPN", "MSG", "CLO", "ERR"
      [3]     Chunk Type: 'C' (intermediate), 'F' (final), 'A' (abort)
      [4:8]   Message Size (little endian, uint32)
      [8:]    Payload (depends on message type)

    For MSG messages, the payload contains service requests:
      Service NodeId encoding varies, but common numeric IDs:
        426 = FindServersRequest
        428 = GetEndpointsRequest
        461 = CreateSessionRequest
        467 = ActivateSessionRequest
        473 = CloseSessionRequest
        527 = BrowseRequest
        631 = ReadRequest
        673 = WriteRequest
        710 = CallRequest (method invocation)
        790 = CreateSubscriptionRequest
        826 = CreateMonitoredItemsRequest

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery (Browse, Read, FindServers, GetEndpoints)
      T0831 - Manipulation of Control (Write, Call)
      T0859 - Valid Accounts (CreateSession, ActivateSession)
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
        raw_bytes = payload_hex
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
                raw_bytes = payload_hex.encode("latin-1", errors="ignore")
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()
                raw_bytes = bytes.fromhex(hex_clean)
        except (UnicodeDecodeError, AttributeError, ValueError):
            hex_clean = payload_hex.replace(" ", "").lower()
            try:
                raw_bytes = bytes.fromhex(hex_clean)
            except ValueError:
                return hits

    if len(raw_bytes) < 8:
        return hits

    try:
        # Message type is first 3 ASCII bytes
        msg_type = raw_bytes[0:3]

        # HEL = Hello (client discovery)
        if msg_type == b"HEL":
            hits.append(("ICS_ATTACK", "opcua_hello", "T0846 OPC UA Hello (endpoint discovery)"))

        # OPN = OpenSecureChannel
        elif msg_type == b"OPN":
            hits.append(
                ("ICS_ATTACK", "opcua_open_secure_channel", "T0859 OPC UA OpenSecureChannel")
            )

        # CLO = CloseSecureChannel
        elif msg_type == b"CLO":
            hits.append(("ICS_ATTACK", "opcua_close_secure_channel", "OPC UA CloseSecureChannel"))

        # MSG = Service request/response
        elif msg_type == b"MSG":
            hits.append(("ICS_ATTACK", "opcua_message", "OPC UA MSG service request"))

            # Try to extract service NodeId from payload
            # After MSG header (8 bytes) + SecureChannelId(4) + SecurityTokenId(4)
            # + SequenceNumber(4) + RequestId(4) = offset 24
            # Then NodeId encoding: byte 0 = encoding type
            # For numeric (type 0x01): namespace(1) + id(2 bytes LE)
            if len(raw_bytes) >= 28:
                # Scan for known service IDs in the payload region
                payload_region = raw_bytes[24:]
                if len(payload_region) >= 4:
                    # Check for numeric NodeId encoding (0x01)
                    for offset in range(min(len(payload_region) - 3, 16)):
                        if payload_region[offset] == 0x01 and payload_region[offset + 1] == 0x00:
                            svc_id = int.from_bytes(
                                payload_region[offset + 2 : offset + 4], "little"
                            )

                            # T0846 - Discovery/Reconnaissance
                            if svc_id == 426:
                                hits.append(
                                    ("ICS_ATTACK", "opcua_find_servers", "T0846 OPC UA FindServers")
                                )
                                break
                            elif svc_id == 428:
                                hits.append(
                                    (
                                        "ICS_ATTACK",
                                        "opcua_get_endpoints",
                                        "T0846 OPC UA GetEndpoints",
                                    )
                                )
                                break
                            elif svc_id == 527:
                                hits.append(("ICS_ATTACK", "opcua_browse", "T0846 OPC UA Browse"))
                                break
                            elif svc_id == 631:
                                hits.append(("ICS_ATTACK", "opcua_read", "T0846 OPC UA Read"))
                                break

                            # T0831 - Control/Manipulation
                            elif svc_id == 673:
                                hits.append(("ICS_ATTACK", "opcua_write", "T0831 OPC UA Write"))
                                break
                            elif svc_id == 710:
                                hits.append(
                                    (
                                        "ICS_ATTACK",
                                        "opcua_call",
                                        "T0831 OPC UA Call (method invocation)",
                                    )
                                )
                                break

                            # T0859 - Session/Authentication
                            elif svc_id == 461:
                                hits.append(
                                    (
                                        "ICS_ATTACK",
                                        "opcua_create_session",
                                        "T0859 OPC UA CreateSession",
                                    )
                                )
                                break
                            elif svc_id == 467:
                                hits.append(
                                    (
                                        "ICS_ATTACK",
                                        "opcua_activate_session",
                                        "T0859 OPC UA ActivateSession",
                                    )
                                )
                                break

                            # Monitoring
                            elif svc_id == 790:
                                hits.append(
                                    (
                                        "ICS_ATTACK",
                                        "opcua_create_subscription",
                                        "T0801 OPC UA CreateSubscription",
                                    )
                                )
                                break
                            elif svc_id == 826:
                                hits.append(
                                    (
                                        "ICS_ATTACK",
                                        "opcua_create_monitored_items",
                                        "T0801 OPC UA CreateMonitoredItems",
                                    )
                                )
                                break

        # ERR = Error
        elif msg_type == b"ERR":
            hits.append(("ICS_ATTACK", "opcua_error", "OPC UA Error response"))

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# PROFINET DCP Detection (Port 34962-34964)
# =========================================================================


def _detect_profinet_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect PROFINET attacks from raw binary payload.

    PROFINET uses several frame types over TCP (ports 34962-34964):
    - PN-IO (cyclic real-time I/O data)
    - PN-CM (connection management via RPC)
    - DCP (Discovery and Configuration Protocol)

    For TCP-based PROFINET CM, the protocol uses DCE/RPC:
      [0:1]   RPC Version (0x04 for connectionless, 0x05 for connection-oriented)
      [1]     Packet Type
      ...

    DCE/RPC Packet Types:
      0  = Request
      2  = Response
      11 = Bind
      12 = Bind ACK
      14 = Alter Context

    PROFINET-specific RPC operations are identified by their UUID:
      DEA00001-6C97-11D1-8271-00A02442DF7D = IO Controller
      DEA00002-6C97-11D1-8271-00A02442DF7D = IO Supervisor
      DEA00003-6C97-11D1-8271-00A02442DF7D = IO Device (parameter server)

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery (DCP Identify)
      T0831 - Manipulation of Control (IO Write, parameter changes)
      T0814 - Denial of Service (IO Controller abuse)
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
        raw_bytes = payload_hex
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
                raw_bytes = payload_hex.encode("latin-1", errors="ignore")
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()
                raw_bytes = bytes.fromhex(hex_clean)
        except (UnicodeDecodeError, AttributeError, ValueError):
            hex_clean = payload_hex.replace(" ", "").lower()
            try:
                raw_bytes = bytes.fromhex(hex_clean)
            except ValueError:
                return hits

    if len(raw_bytes) < 8:
        return hits

    try:
        # Check for DCE/RPC version 4 (connectionless) or 5 (connection-oriented)
        rpc_ver = raw_bytes[0]

        if rpc_ver == 0x05:
            # Connection-oriented DCE/RPC
            pkt_type = raw_bytes[2] if len(raw_bytes) > 2 else 0xFF

            # Bind request — attacker establishing RPC connection
            if pkt_type == 11:  # Bind
                hits.append(("ICS_ATTACK", "profinet_rpc_bind", "T0846 PROFINET DCE/RPC Bind"))
                # Check for PROFINET IO UUIDs in bind payload
                if len(raw_bytes) >= 80:
                    payload_str = hex_clean[48:]
                    # IO Controller UUID (LE byte order parts)
                    if "dea00001" in payload_str:
                        hits.append(
                            (
                                "ICS_ATTACK",
                                "profinet_io_controller",
                                "T0831 PROFINET IO Controller connection",
                            )
                        )
                    elif "dea00002" in payload_str:
                        hits.append(
                            (
                                "ICS_ATTACK",
                                "profinet_io_supervisor",
                                "T0846 PROFINET IO Supervisor connection",
                            )
                        )
                    elif "dea00003" in payload_str:
                        hits.append(
                            (
                                "ICS_ATTACK",
                                "profinet_io_paramserver",
                                "T0831 PROFINET IO Parameter Server",
                            )
                        )

            elif pkt_type == 0:  # Request
                hits.append(("ICS_ATTACK", "profinet_rpc_request", "PROFINET DCE/RPC Request"))

                # Check for PROFINET operation codes in the stub data
                # After RPC header (typically 80 bytes), PROFINET PDU starts
                if len(raw_bytes) >= 84:
                    # PROFINET IO operation codes:
                    # 0x0000 = Connect
                    # 0x0003 = Read
                    # 0x0004 = Write
                    # 0x0008 = Control (PLC stop/start)
                    # 0x000F = ReadImplicit
                    stub_start = min(80, len(raw_bytes) - 4)
                    for off in range(stub_start, min(stub_start + 8, len(raw_bytes) - 1)):
                        opcode = int.from_bytes(raw_bytes[off : off + 2], "big")
                        if opcode == 0x0004:
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "profinet_write",
                                    "T0831 PROFINET Write (parameter/IO data)",
                                )
                            )
                            break
                        elif opcode == 0x0008:
                            hits.append(
                                (
                                    "ICS_ATTACK",
                                    "profinet_control",
                                    "T0831 PROFINET Control (PLC state change)",
                                )
                            )
                            break
                        elif opcode == 0x0003:
                            hits.append(("ICS_ATTACK", "profinet_read", "T0846 PROFINET Read"))
                            break

        elif rpc_ver == 0x04:
            # Connectionless DCE/RPC (PROFINET DCP over UDP)
            hits.append(("ICS_ATTACK", "profinet_dcp_probe", "T0846 PROFINET DCP discovery probe"))

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# FINS (Omron) Binary Detection (Port 9600, UDP)
# =========================================================================


def _detect_fins_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect Omron FINS protocol attacks from raw binary payload.

    FINS TCP Header:
      [0:4]   Magic: "FINS" (0x46494E53)
      [4:8]   Length (big endian)
      [8:12]  Command (0x00000002 = FINS Frame Send)
      [12:16] Error Code
      [16:]   FINS Frame

    FINS Frame (after TCP header, or directly in UDP):
      [0]     ICF (Information Control Field)
      [1]     RSV (Reserved)
      [2]     GCT (Permissible Gateway Count)
      [3]     DNA (Destination Network Address)
      [4]     DA1 (Destination Node)
      [5]     DA2 (Destination Unit)
      [6]     SNA (Source Network Address)
      [7]     SA1 (Source Node)
      [8]     SA2 (Source Unit)
      [9]     SID (Service ID)
      [10]    MRC (Main Request Code)
      [11]    SRC (Sub Request Code)
      [12:]   Data

    Command codes (MRC + SRC):
      01 01 = Memory Area Read
      01 02 = Memory Area Write
      01 03 = Memory Area Fill
      02 01 = Parameter Area Read
      02 02 = Parameter Area Write
      03 06 = CPU Unit Status Read
      04 01 = Run (PLC Start)
      04 02 = Stop (PLC Stop)
      05 01 = Controller Data Read
      06 01 = Status Read
      07 01 = Clock Read
      07 02 = Clock Write
      09 20 = Error Clear
      21 01 = Error Log Read
      22 01 = File Read
      22 02 = File Write
      26 01 = Program Area Read
      26 02 = Program Area Write

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery (reads, status)
      T0831 - Manipulation of Control (writes, run/stop)
      T0843 - Program Download (program area write)
      T0816 - Device Restart/Shutdown (stop)
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
        raw_bytes = payload_hex
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
                raw_bytes = payload_hex.encode("latin-1", errors="ignore")
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()
                raw_bytes = bytes.fromhex(hex_clean)
        except (UnicodeDecodeError, AttributeError, ValueError):
            hex_clean = payload_hex.replace(" ", "").lower()
            try:
                raw_bytes = bytes.fromhex(hex_clean)
            except ValueError:
                return hits

    if len(raw_bytes) < 12:
        return hits

    try:
        fins_offset = 0

        # Check for FINS TCP wrapper: magic "FINS" (0x46494E53)
        if raw_bytes[0:4] == b"FINS":
            # TCP FINS frame — skip 16-byte TCP header
            if len(raw_bytes) < 28:
                return hits
            fins_offset = 16
            hits.append(("ICS_ATTACK", "fins_tcp_frame", "Omron FINS TCP connection"))

        # Alternatively check for FINS UDP frame (ICF byte)
        # ICF: bit 7 = 1 (command), bit 6 = response type
        elif raw_bytes[0] & 0x80:
            # Looks like a FINS UDP frame (ICF has command bit set)
            fins_offset = 0
        else:
            return hits

        # Extract FINS command codes (MRC + SRC)
        if len(raw_bytes) < fins_offset + 12:
            return hits

        mrc = raw_bytes[fins_offset + 10]
        src = raw_bytes[fins_offset + 11]

        # T0846 - Reconnaissance / Discovery
        if mrc == 0x05 and src == 0x01:
            hits.append(
                ("ICS_ATTACK", "fins_controller_data_read", "T0846 FINS Controller Data Read")
            )
        elif mrc == 0x06 and src == 0x01:
            hits.append(("ICS_ATTACK", "fins_status_read", "T0846 FINS Status Read"))
        elif mrc == 0x03 and src == 0x06:
            hits.append(("ICS_ATTACK", "fins_cpu_status_read", "T0846 FINS CPU Unit Status Read"))
        elif mrc == 0x07 and src == 0x01:
            hits.append(("ICS_ATTACK", "fins_clock_read", "T0846 FINS Clock Read"))
        elif mrc == 0x01 and src == 0x01:
            hits.append(("ICS_ATTACK", "fins_memory_area_read", "T0846 FINS Memory Area Read"))
        elif mrc == 0x02 and src == 0x01:
            hits.append(
                ("ICS_ATTACK", "fins_parameter_area_read", "T0846 FINS Parameter Area Read")
            )
        elif mrc == 0x21 and src == 0x01:
            hits.append(("ICS_ATTACK", "fins_error_log_read", "T0846 FINS Error Log Read"))
        elif mrc == 0x22 and src == 0x01:
            hits.append(("ICS_ATTACK", "fins_file_read", "T0846 FINS File Read"))
        elif mrc == 0x26 and src == 0x01:
            hits.append(("ICS_ATTACK", "fins_program_area_read", "T0846 FINS Program Area Read"))

        # T0831 - Manipulation / Control
        elif mrc == 0x01 and src == 0x02:
            hits.append(("ICS_ATTACK", "fins_memory_area_write", "T0831 FINS Memory Area Write"))
        elif mrc == 0x01 and src == 0x03:
            hits.append(("ICS_ATTACK", "fins_memory_area_fill", "T0831 FINS Memory Area Fill"))
        elif mrc == 0x02 and src == 0x02:
            hits.append(
                ("ICS_ATTACK", "fins_parameter_area_write", "T0831 FINS Parameter Area Write")
            )
        elif mrc == 0x07 and src == 0x02:
            hits.append(("ICS_ATTACK", "fins_clock_write", "T0831 FINS Clock Write"))

        # T0816 - Run/Stop (PLC state control)
        elif mrc == 0x04 and src == 0x01:
            hits.append(("ICS_ATTACK", "fins_run", "T0831 FINS Run (PLC Start)"))
        elif mrc == 0x04 and src == 0x02:
            hits.append(("ICS_ATTACK", "fins_stop", "T0816 FINS Stop (PLC Shutdown)"))

        # T0843 - Program manipulation
        elif mrc == 0x26 and src == 0x02:
            hits.append(("ICS_ATTACK", "fins_program_area_write", "T0843 FINS Program Area Write"))
        elif mrc == 0x22 and src == 0x02:
            hits.append(("ICS_ATTACK", "fins_file_write", "T0843 FINS File Write"))

        # Error clear — potential cover-up
        elif mrc == 0x09 and src == 0x20:
            hits.append(
                ("ICS_ATTACK", "fins_error_clear", "T0814 FINS Error Clear (log tampering)")
            )

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# Melsec / MC Protocol (Mitsubishi) Detection (Port 5000-5002)
# =========================================================================


def _detect_melsec_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect Mitsubishi MC (Melsec Communication) protocol attacks.

    MC Protocol Binary (Type 3E / Type 4E):

    Type 3E Frame:
      [0:2]   Subheader: 0x5000 (request) / 0xD000 (response)
      [2:4]   Network Number + PC Number
      [4:6]   Request Destination (module I/O + station)
      [6:8]   Reserved
      [8:10]  Data Length (remaining bytes)
      [10:12] Timer (monitoring timeout)
      [12:14] Command (2 bytes)
      [14:16] Subcommand (2 bytes)
      [16:]   Data

    Commands (hex, little-endian in wire format):
      0x0401 = Batch Read (Device)
      0x1401 = Random Read
      0x0402 = Batch Write
      0x1402 = Random Write
      0x0403 = Random Read (Block)
      0x0406 = Read Buffer Memory
      0x1406 = Write Buffer Memory
      0x0619 = Remote Run
      0x1619 = Remote Stop
      0x1620 = Remote Pause
      0x0630 = Read CPU Model Name
      0x0101 = Read PLC Status

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery (read commands)
      T0831 - Manipulation of Control (write commands)
      T0816 - Device Restart/Shutdown (remote stop/pause)
      T0843 - Program Download (write operations)
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    if isinstance(payload_hex, bytes):
        hex_clean = payload_hex.hex().lower()
        raw_bytes = payload_hex
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                hex_clean = payload_hex.encode("latin-1", errors="ignore").hex().lower()
                raw_bytes = payload_hex.encode("latin-1", errors="ignore")
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()
                raw_bytes = bytes.fromhex(hex_clean)
        except (UnicodeDecodeError, AttributeError, ValueError):
            hex_clean = payload_hex.replace(" ", "").lower()
            try:
                raw_bytes = bytes.fromhex(hex_clean)
            except ValueError:
                return hits

    if len(raw_bytes) < 16:
        return hits

    try:
        # Check for MC Protocol Type 3E subheader
        subheader = int.from_bytes(raw_bytes[0:2], "big")

        if subheader == 0x5000:
            # MC Protocol request frame
            hits.append(("ICS_ATTACK", "melsec_mc_request", "Mitsubishi MC Protocol request"))

            # Extract command (bytes 12-14, big-endian)
            if len(raw_bytes) >= 16:
                cmd = int.from_bytes(raw_bytes[12:14], "big")
                _subcmd = int.from_bytes(raw_bytes[14:16], "big")

                # T0846 - Read / Discovery commands
                if cmd == 0x0401:
                    hits.append(("ICS_ATTACK", "melsec_batch_read", "T0846 MC Protocol Batch Read"))
                elif cmd == 0x1401:
                    hits.append(
                        ("ICS_ATTACK", "melsec_random_read", "T0846 MC Protocol Random Read")
                    )
                elif cmd == 0x0403:
                    hits.append(("ICS_ATTACK", "melsec_block_read", "T0846 MC Protocol Block Read"))
                elif cmd == 0x0406:
                    hits.append(
                        ("ICS_ATTACK", "melsec_buffer_read", "T0846 MC Protocol Buffer Memory Read")
                    )
                elif cmd == 0x0630:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "melsec_read_cpu_model",
                            "T0846 MC Protocol Read CPU Model Name",
                        )
                    )
                elif cmd == 0x0101:
                    hits.append(
                        ("ICS_ATTACK", "melsec_read_status", "T0846 MC Protocol Read PLC Status")
                    )

                # T0831 - Write / Control commands
                elif cmd == 0x0402:
                    hits.append(
                        ("ICS_ATTACK", "melsec_batch_write", "T0831 MC Protocol Batch Write")
                    )
                elif cmd == 0x1402:
                    hits.append(
                        ("ICS_ATTACK", "melsec_random_write", "T0831 MC Protocol Random Write")
                    )
                elif cmd == 0x1406:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "melsec_buffer_write",
                            "T0831 MC Protocol Buffer Memory Write",
                        )
                    )

                # T0816 / T0831 - Remote control
                elif cmd == 0x0619:
                    hits.append(("ICS_ATTACK", "melsec_remote_run", "T0831 MC Protocol Remote Run"))
                elif cmd == 0x1619:
                    hits.append(
                        ("ICS_ATTACK", "melsec_remote_stop", "T0816 MC Protocol Remote Stop")
                    )
                elif cmd == 0x1620:
                    hits.append(
                        ("ICS_ATTACK", "melsec_remote_pause", "T0816 MC Protocol Remote Pause")
                    )

        # Check for MC Protocol Type 4E (newer, extended header)
        elif subheader == 0x5400:
            hits.append(
                ("ICS_ATTACK", "melsec_mc4e_request", "Mitsubishi MC Protocol Type 4E request")
            )
            # Type 4E has 6 extra bytes of serial number + reserved
            if len(raw_bytes) >= 22:
                cmd = int.from_bytes(raw_bytes[18:20], "big")
                if cmd in (0x0402, 0x1402, 0x1406):
                    hits.append(
                        ("ICS_ATTACK", "melsec_4e_write", "T0831 MC Protocol 4E Write command")
                    )
                elif cmd in (0x1619, 0x1620):
                    hits.append(
                        ("ICS_ATTACK", "melsec_4e_stop", "T0816 MC Protocol 4E Remote Stop/Pause")
                    )

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


# =========================================================================
# CoAP / LwM2M Detection (Port 5683/5684 UDP)
# =========================================================================


def _detect_coap_binary(payload_hex: str) -> list[AttackHit]:
    """
    Detect CoAP and LwM2M attacks from raw binary payload.

    CoAP Message structure (RFC 7252):
      [0] bits 0-1: Version (1)
          bits 2-3: Type (0=CON, 1=NON, 2=ACK, 3=RST)
          bits 4-7: Token Length (0-8)
      [1] Code: class(3 bits).detail(5 bits)
          0.01 = GET, 0.02 = POST, 0.03 = PUT, 0.04 = DELETE
          2.01 = Created, 2.05 = Content
          4.01 = Unauthorized, 4.04 = Not Found
      [2:4] Message ID (big endian)
      [4:4+TKL] Token
      [4+TKL:] Options + Payload (0xFF marker separates options from payload)

    CoAP Options for LwM2M (identified by option number):
      11 = Uri-Path (used for LwM2M object paths like /3/0/0)

    LwM2M Object IDs:
      /0/x   = Security
      /1/x   = Server
      /3/x   = Device
      /4/x   = Connectivity
      /5/x   = Firmware Update
      /6/x   = Location

    MITRE ATT&CK for ICS:
      T0846 - Remote System Discovery (GET on device info)
      T0831 - Manipulation of Control (PUT/POST on actuators)
      T0843 - Program Download (firmware update)
      T0814 - Denial of Service (RST flooding, DELETE)
    """
    hits: list[AttackHit] = []

    if not payload_hex:
        return hits

    if isinstance(payload_hex, bytes):
        raw_bytes = payload_hex
    else:
        try:
            if any(ord(c) < 32 or ord(c) > 126 for c in payload_hex[:20] if c not in "\r\n\t"):
                raw_bytes = payload_hex.encode("latin-1", errors="ignore")
            else:
                hex_clean = payload_hex.replace(" ", "").replace(":", "").lower()
                raw_bytes = bytes.fromhex(hex_clean)
        except (UnicodeDecodeError, AttributeError, ValueError):
            try:
                raw_bytes = bytes.fromhex(payload_hex.replace(" ", "").lower())
            except ValueError:
                return hits

    if len(raw_bytes) < 4:
        return hits

    try:
        # Parse CoAP header
        ver = (raw_bytes[0] >> 6) & 0x03
        if ver != 1:  # CoAP version must be 1
            return hits

        msg_type = (raw_bytes[0] >> 4) & 0x03
        tkl = raw_bytes[0] & 0x0F
        code_class = (raw_bytes[1] >> 5) & 0x07
        code_detail = raw_bytes[1] & 0x1F

        # RST flood
        if msg_type == 3:  # RST
            hits.append(("ICS_ATTACK", "coap_reset", "T0814 CoAP Reset"))
            return hits

        # Request codes (class 0)
        if code_class == 0:
            if code_detail == 1:  # GET
                hits.append(("ICS_ATTACK", "coap_get", "T0846 CoAP GET request"))
            elif code_detail == 2:  # POST
                hits.append(("ICS_ATTACK", "coap_post", "T0831 CoAP POST request"))
            elif code_detail == 3:  # PUT
                hits.append(("ICS_ATTACK", "coap_put", "T0831 CoAP PUT request"))
            elif code_detail == 4:  # DELETE
                hits.append(("ICS_ATTACK", "coap_delete", "T0814 CoAP DELETE request"))

        # Try to extract Uri-Path options for LwM2M context
        # Options start after token
        opt_start = 4 + tkl
        if opt_start < len(raw_bytes):
            uri_path = ""
            option_num = 0
            idx = opt_start
            while idx < len(raw_bytes):
                if raw_bytes[idx] == 0xFF:
                    break  # Payload marker
                delta = (raw_bytes[idx] >> 4) & 0x0F
                length = raw_bytes[idx] & 0x0F
                idx += 1
                if delta == 13:
                    delta = raw_bytes[idx] + 13
                    idx += 1
                elif delta == 14:
                    delta = int.from_bytes(raw_bytes[idx : idx + 2], "big") + 269
                    idx += 2
                if length == 13:
                    length = raw_bytes[idx] + 13
                    idx += 1
                elif length == 14:
                    length = int.from_bytes(raw_bytes[idx : idx + 2], "big") + 269
                    idx += 2
                option_num += delta

                if idx + length > len(raw_bytes):
                    break

                # Uri-Path (option 11)
                if option_num == 11:
                    segment = raw_bytes[idx : idx + length].decode(errors="ignore")
                    uri_path += "/" + segment

                idx += length

            # LwM2M object detection
            if uri_path:
                if uri_path.startswith("/0"):
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "lwm2m_security_access",
                            "T0859 LwM2M Security Object access" + " " + uri_path,
                        )
                    )
                elif uri_path.startswith("/3"):
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "lwm2m_device_info",
                            "T0846 LwM2M Device Object access" + " " + uri_path,
                        )
                    )
                elif uri_path.startswith("/5"):
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "lwm2m_firmware_update",
                            "T0843 LwM2M Firmware Update Object" + " " + uri_path,
                        )
                    )
                elif uri_path.startswith("/.well-known"):
                    hits.append(
                        ("ICS_ATTACK", "coap_discovery", "T0846 CoAP .well-known/core discovery")
                    )
                elif uri_path:
                    hits.append(
                        (
                            "ICS_ATTACK",
                            "lwm2m_object_access",
                            "LwM2M Object access" + " " + uri_path,
                        )
                    )

    except Exception as exc:  # malformed binary payload: we return partial hits
        logger.debug("malformed binary payload, partial hits kept: %s", exc)

    return hits


def _is_hex_string(s: str) -> bool:
    """Check if string looks like a hex dump."""
    if not s:
        return False
    # Remove common separators and check if remaining is hex
    cleaned = s.replace(" ", "").replace(":", "").replace("-", "")
    if len(cleaned) < 16:
        return False
    try:
        int(cleaned[:16], 16)
        return True
    except ValueError:
        return False
