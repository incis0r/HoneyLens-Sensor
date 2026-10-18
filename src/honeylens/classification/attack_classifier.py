"""
classification/attack_classifier.py — Attack Classification Orchestrator
=========================================================================
Main entry point: classify_event_row()
Imports text regex rules from text_rules.py and binary detectors from
binary_detectors.py. Scoring functions in scoring.py.

This file was 5,676 lines before refactoring. Now ~700 lines.
"""

from __future__ import annotations

import logging
import os
import re
import urllib.parse

from honeylens.classification.binary_detectors import (
    _detect_bacnet_binary,
    _detect_coap_binary,
    _detect_dnp3_binary,
    _detect_enip_binary,
    _detect_fins_binary,
    _detect_iec104_binary,
    _detect_k8s_attack,
    _detect_melsec_binary,
    _detect_modbus_binary,
    _detect_mqtt_binary,
    _detect_opcua_binary,
    _detect_profinet_binary,
    _detect_s7comm_binary,
    _detect_smb_binary,
    _is_binary_payload,
    _is_hex_string,
)
from honeylens.classification.scoring import (
    ATTACK_TYPE_SEVERITY,
    RULE_SEVERITY_OVERRIDE,
    SEVERITY_WEIGHTS,
    calculate_threat_score,
    classify_attack_summary,
    detect_attack_chains,
    get_all_rules,
    get_attack_types,
    get_classifier_stats,
    get_rules_flat,
    get_severity,
    get_severity_weight,
)
from honeylens.classification.text_rules import (
    _BINARY_PROTOCOLS,
    _ENCRYPTED_PROTOCOLS,
    _HTTP_EXCLUDED_RULES,
    _HTTP_PORTS,
    _ICS_PORT_CONTEXT_RULES,
    _ICS_PORTS,
    _K8S_PORTS,
    _PLAINTEXT_PROTOCOLS,
    _RULES,
    get_custom_rule_names,
    reload_custom_rules,
)
from honeylens.honeypots.deception_waf import is_canary_callback

# Facade from 0.9: api.py, routes/classifier.py, routes/ai/rules.py and tools/attack_kb_builder
# import scoring, statistics and rule reload FROM HERE, not from the submodules. __all__ keeps
# these names alive, because otherwise ruff would strip the "unused" imports — that is exactly
# how they disappeared on the first pass of the port.
__all__ = [
    "ATTACK_TYPE_SEVERITY",
    "RULE_SEVERITY_OVERRIDE",
    "SEVERITY_WEIGHTS",
    "_K8S_PORTS",
    "AttackHit",
    "_is_hex_string",
    "calculate_threat_score",
    "classify_attack_summary",
    "classify_event_row",
    "detect_attack_chains",
    "get_all_rules",
    "get_attack_types",
    "get_classifier_stats",
    "get_custom_rule_names",
    "get_rules_flat",
    "get_severity",
    "get_severity_weight",
    "reload_custom_rules",
]

logger = logging.getLogger("honeylens.classifier")

# Type alias
AttackHit = tuple[str, str, str]  # (attack_type, rule_name, matched_text)

# How much of the captured request body the rules get. The body itself is kept in full in
# the metadata as evidence; this only bounds the classification work, which in practice is
# nearly quadratic (every rule against every target, after _deep_decode).
_BODY_CLASSIFY_BYTES = int(os.environ.get("CLASSIFY_BODY_BYTES", 8192))

# The hard ceiling on a body the whole-body PHP2Shell check will read: the decoys' MAX_CAPTURE.
_WHOLE_BODY_MAX = 64 * 1024

# PHP2Shell is two anchored literals, so it can see the WHOLE body at linear cost, which the
# 678-rule regex sweep cannot (it is nearly quadratic, hence the head/tail cap). A head+tail
# window left a blind middle that a real 22,619-byte dropper fell into: no verdict at all.
# These are deliberately NOT the lookahead rules in rules/web_injection.py: that pattern
# restarts a scan to the end of the text at every occurrence of the field, which is quadratic
# on a body that repeats the field name. Here: one search for the field, one search after it.
_PHP2SHELL_FIELD = re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.IGNORECASE)
_PHP2SHELL_OPEN_TAG = re.compile(r"<\?(?:php\b|=|\s)", re.IGNORECASE)

# CVE-2026-109618 is the OTHER half of the pair and had no verdict at all until 2026-10-30:
# the identifier appeared in this file only inside comments, so every event of this shape was
# stored as a bare `PHP2SHELL`. Measured on sensor-a that day: 85.11.167.243 sent a 62,929-byte body
# padded with `A`, under the user-agent `php2shell-109618` -- it names its own CVE -- and
# 94.154.43.7 sent ten bodies from 1,786 up to 422,970 bytes whose form field is a 240-deep
# nested array (`name="f0[k0][k1]...[k239]"`). Neither carries a PHP open tag, so the 109619
# rule correctly declined both, and nothing else claimed them.
#
# Two independent structural tells, either of which is enough, because an attacker can drop
# whichever one is cheaper:
#   * nested array keys -- three consecutive `[kN]` groups. Measured over the whole fleet, this
#     form appears on exactly one source and nowhere else, so it costs no precision.
#   * an oversize body on the vector. 16 KB is not a new number: the nginx decoy's own private
#     overflow indicator used that threshold before any shared rule existed, and the real
#     droppers measured so far sit under it (77.90.185.20's is 14,402 bytes), so the two
#     verdicts stay apart instead of both firing on every dropper.
_PHP2SHELL_NESTED_KEYS = re.compile(r"(?:\[k\d+\]){3}", re.IGNORECASE)
_PHP2SHELL_OVERSIZE_BYTES = 16 * 1024
_PHP2SHELL_RULES = (
    "php2shell_upload_progress_field",
    "php2shell_upload_progress_rce",
    "php2shell_upload_progress_exhaustion",
)


def _php2shell_whole_body(body: str) -> list[AttackHit]:
    """The two PHP2Shell verdicts over an entire body: the field alone, and a PHP open tag
    anywhere after it. Linear in the body; no body length can hide either token."""
    hits: list[AttackHit] = []
    field = _PHP2SHELL_FIELD.search(body)
    if field is None:
        return hits
    hits.append(("PHP2SHELL", _PHP2SHELL_RULES[0], field.group(0)))
    tag = _PHP2SHELL_OPEN_TAG.search(body, field.end())
    if tag is not None:
        hits.append(("CVE_2026_109619", _PHP2SHELL_RULES[1], field.group(0) + "..." + tag.group(0)))
    nested = _PHP2SHELL_NESTED_KEYS.search(body)
    if nested is not None:
        hits.append(
            ("CVE_2026_109618", _PHP2SHELL_RULES[2], field.group(0) + "..." + nested.group(0))
        )
    elif len(body) >= _PHP2SHELL_OVERSIZE_BYTES:
        hits.append(
            ("CVE_2026_109618", _PHP2SHELL_RULES[2], f"{field.group(0)}...{len(body)} bytes")
        )
    return hits


_HTTP_METHOD_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/",
    re.MULTILINE,
)
_HTTP_HEADER_RE = re.compile(r"^([A-Za-z\-]+):\s*(.+)$", re.MULTILINE)


def _extract_http_parts(text: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Extract (method, uri, user_agent, headers_str) from raw HTTP payload."""
    m = _HTTP_METHOD_RE.search(text)
    if not m:
        return None, None, None, None
    method = m.group(1)
    uri = m.group(2)
    ua = None
    for hm in _HTTP_HEADER_RE.finditer(text):
        if hm.group(1).lower() == "user-agent":
            ua = hm.group(2).strip()
            break
    # Everything from start to double newline is headers
    hdr_end = text.find("\r\n\r\n")
    if hdr_end == -1:
        hdr_end = text.find("\n\n")
    headers = text[:hdr_end] if hdr_end > 0 else text[:2000]
    return method, uri, ua, headers


# =========================================================================
# URL decode helper — handles double-encoding and plus signs
# =========================================================================


def _deep_decode(text: str) -> str:
    """Apply URL decoding up to 3 times to catch double/triple encoding."""
    decoded = text
    for _ in range(3):
        prev = decoded
        try:
            decoded = urllib.parse.unquote(decoded)
        except Exception:
            break  # silent: URL decode failure on binary data
        if decoded == prev:
            break
    return decoded


# =========================================================================
# Protocol Gating — Encrypted & Binary Protocol Guards (v2.2.0)
# =========================================================================
# Plaintext regex rules MUST NOT run against encrypted or binary protocol
# payloads.  Encrypted data decoded as UTF-8 produces random-looking text
# that accidentally matches broad regex patterns (SQLi, XSS, LFI, RCE),
# creating massive false positives on any internet-facing sensor.


# Binary/ICS protocol keywords. A rule that targets a binary protocol (Modbus,
# S7, MQTT, BACnet, …) — built-in OR AI-generated — must never fire on identified
# HTTP traffic. This is the root cause of false "Modbus/MQTT attack" tags on plain
# web requests (e.g. an AI rule's `\x5a` byte matching the 'z' in a Mozilla
# User-Agent, or `FC=90` heuristics running against a GET /).
_BINARY_PROTO_KW = (
    "modbus",
    "s7comm",
    "s7",
    "mqtt",
    "bacnet",
    "dnp3",
    "enip",
    "ethernetip",
    "opcua",
    "opc-ua",
    "iec104",
    "iec-104",
    "profinet",
    "fox",
    "coap",
    "fins",
    "cip",
)


def _rule_targets_binary_proto(rname, atype):
    """True if a rule's name/attack_type implies a binary/ICS protocol."""
    s = (str(rname) + " " + str(atype or "")).lower()
    return any(kw in s for kw in _BINARY_PROTO_KW)


_HTTP_METHODS = frozenset(
    (
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "CONNECT",
    )
)


def _sensor_decrypted_this(metadata: dict | None) -> bool:
    """True when the sensor terminated TLS itself and parsed the request.

    `_ENCRYPTED_PROTOCOLS` exists for packet capture, where a TLS record really is
    ciphertext and no text rule can say anything useful about it. A honeypot is the
    opposite case: it holds the server key, completes the handshake, and hands us the
    decrypted request. Labelling that traffic `HTTPS` and taking the capture branch
    meant **no text rule could fire on any TLS listener at all** — an AnyConnect
    tunnel-group campaign put ~145 000 events through :8443 over two weeks and every
    one was stored with no attack type, not because a rule was missing but because the
    rules were never consulted.

    The test is structural rather than a flag, so it cannot drift out of sync with what
    the honeypots actually send: a decoy that saw only ciphertext cannot report an HTTP
    method, and one that parsed a request reports the path or the body alongside it.
    Both halves are required — a stray `method` key on its own is not evidence that
    anything was decrypted.
    """
    if not metadata:
        return False
    method = metadata.get("method")
    if not isinstance(method, str) or method.upper() not in _HTTP_METHODS:
        return False
    return "path" in metadata or "body_sample" in metadata


def classify_event_row(
    payload: str | None, protocol: str | None, metadata: dict | None = None
) -> list[AttackHit]:
    """Classify one event into (attack_type, rule_name, snippet) hits (for ingest).

    Thin wrapper over the protocol-gated rule engine that ALSO surfaces the WAF-canary
    callback: a request reflecting one of our fictional WAF-vendor tokens read the header off a
    decoy response and sent it back (``is_canary_callback``; fleet-wide, any source). The tag is
    ADDED, never substituted, so a request that both reflects a token and carries a real exploit
    keeps its exploit classification — no detection short-circuit."""
    if not payload:
        return []
    hits = _classify_rules(payload, protocol, metadata)
    if is_canary_callback(payload):
        canary: AttackHit = (
            "waf-canary-callback",
            "waf-canary-callback",
            "fictional WAF vendor reflected",
        )
        if canary not in hits:
            hits = [canary, *hits]
    return hits


def _classify_rules(
    payload: str | None, protocol: str | None, metadata: dict | None = None
) -> list[AttackHit]:
    """
    Classify a single event.  Returns list of (attack_type, rule_name, snippet).
    Designed to be called from ingest.py and ingest_honeypot.py.

    Protocol-aware gating (v2.2.0):
    - Encrypted protocols (TLS, SSH, RDP): skip ALL text regex rules.
      JA3/JA4 fingerprint checks happen in ingest.py, not here.
    - Binary protocols (Modbus, DNS, S7, etc.): skip text regex rules,
      only run dedicated binary protocol detectors (below).
    - Plaintext protocols (HTTP, FTP, SMTP, Telnet): full rule set.
    - Unknown protocol ("TCP"): use binary heuristic to decide.
    """
    if not payload:
        return []

    proto_raw = (protocol or "").strip()
    proto_upper = proto_raw.upper()

    # =================================================================
    # GATE 1: Encrypted protocols — no text analysis possible
    # =================================================================
    if proto_raw in _ENCRYPTED_PROTOCOLS or proto_upper in {
        p.upper() for p in _ENCRYPTED_PROTOCOLS
    }:
        # Exception: SSH banner line is plaintext ("SSH-2.0-...")
        if proto_upper.startswith("SSH") and payload.startswith("SSH-"):
            hits: list[AttackHit] = []
            for atype, rname, regex in _RULES:
                if rname == "ssh_exploit_banner":
                    m = regex.search(payload[:256])
                    if m:
                        hits.append((atype, rname, m.group(0)[:200]))
            return hits
        # Exception: our own honeypots terminate TLS, so what reaches here is the
        # decrypted request, not a ciphertext record. See _sensor_decrypted_this.
        if not _sensor_decrypted_this(metadata):
            return []

    # =================================================================
    # GATE 2: Binary protocols — skip text rules, only run binary
    #         detectors (Modbus, SMB, S7, DNP3, etc.) further below
    # =================================================================
    _is_binary_proto = proto_raw in _BINARY_PROTOCOLS or proto_upper in {
        p.upper() for p in _BINARY_PROTOCOLS
    }

    # =================================================================
    # GATE 3: Unknown protocol — use binary payload heuristic
    # =================================================================
    _is_plaintext_proto = proto_raw in _PLAINTEXT_PROTOCOLS or proto_upper in {
        p.upper() for p in _PLAINTEXT_PROTOCOLS
    }

    if not _is_binary_proto and not _is_plaintext_proto:
        # Protocol is unknown (e.g. "TCP", "TCP/SYN-ACK", empty)
        if _is_binary_payload(payload):
            _is_binary_proto = True

    # =================================================================
    # TEXT REGEX RULES — only for plaintext payloads
    # =================================================================
    hits = []
    seen_rules: set[str] = set()

    if not _is_binary_proto:
        # Bound the input here, not only the body pulled out of metadata further down.
        #
        # The cap existed for that one source and the comment on _BODY_CLASSIFY_BYTES
        # already called this work "nearly quadratic" — but `payload` and `text` are the
        # primary targets and were passed in whole, so the bound did not apply where it
        # mattered. Measured consequence: the shipped `graphql_alias_dos` rule
        # (`(\w+\s*:\s*\w+\s*\{.*?){10,}`) is O(n²) with a heavy constant — 3.5 s on an
        # 836-byte payload, 59.6 s on 3.2 KB, and the attacker chooses the length. One
        # event could occupy the classifier for hours while the sensor looked healthy.
        #
        # Capping before `_deep_decode` also bounds the decode itself, which walks the
        # string repeatedly. A signature's shape is at the head of a payload; the full
        # body is kept in metadata as evidence either way.
        head = payload[:_BODY_CLASSIFY_BYTES]
        text = _deep_decode(head)

        # --- Targets to scan: original + decoded + URI + headers (if HTTP) ---
        targets = [head, text] if head != text else [text]

        # A cost cap buys a blind spot, so pay for the obvious half of it back: scan the
        # tail as well. Otherwise "send 8 KB of padding, then the exploit" is a one-line
        # evasion, and on a sensor a missed detection is the expensive kind of failure.
        # Bounded the same way as the head, so the worst case stays flat — twice a
        # constant is still a constant. Padding in the *middle* of a very large payload
        # still evades, which is inherent to capping at all: making that visible needs a
        # per-event "partially classified" marker, which is an ingest change, not this one.
        if len(payload) > _BODY_CLASSIFY_BYTES:
            tail = payload[-_BODY_CLASSIFY_BYTES:]
            targets.append(tail)
            decoded_tail = _deep_decode(tail)
            if decoded_tail != tail:
                targets.append(decoded_tail)
            logger.debug(
                "payload %d bytes > cap %d: classified head and tail only",
                len(payload),
                _BODY_CLASSIFY_BYTES,
            )

        method, uri, ua, headers = _extract_http_parts(text)
        if uri:
            decoded_uri = _deep_decode(uri)
            targets.append(decoded_uri)
            if uri != decoded_uri:
                targets.append(uri)
        if ua:
            targets.append(ua)
        if headers:
            targets.append(headers)

        # Honeypot metadata may have extra fields
        hex_payload = None
        whole_bodies: list[str] = []
        if metadata:
            for key in (
                "data",
                "request_line",
                "raw_request",
                "hex",
                "request",
                "command",
                "uri",
                "url",
                "query",
                "headers",
                "body",
                "body_sample",
                "user_agent",
            ):
                val = metadata.get(key)
                if val and isinstance(val, str):
                    if key == "body_sample":
                        # Captured bodies run to MAX_CAPTURE (64 KB). Every rule is
                        # matched against every target, and _deep_decode walks the
                        # string repeatedly, so handing the classifier a full 64 KB
                        # body per event is how ingest starts burning CPU. Evidence
                        # keeps the whole body in metadata.
                        #
                        # Head AND tail, for the same reason `payload` above takes both:
                        # the head alone is a one-line evasion. "classification only
                        # needs the head, where the exploit shape is" was measured wrong
                        # on 2026-10-26 — a multipart body puts the shape wherever the
                        # attacker puts the part. With the PHP2Shell progress field at
                        # 8,143 bytes and its `<?php` value at 10,903, the event came back
                        # as the bare vector at medium instead of the CVE at critical,
                        # while the campaign's real bodies run to 22,619 bytes. Bounded
                        # the same way as the payload's: twice a constant is a constant.
                        # That still left a blind middle, and a 22,619-byte dropper fell into
                        # it (2026-10-27): the two anchored PHP2Shell literals therefore read
                        # the whole body, linearly, outside the rule sweep.
                        if len(val) > _BODY_CLASSIFY_BYTES:
                            # The window still leaves a middle; the two anchored PHP2Shell
                            # literals are checked over the whole body instead (below).
                            whole = val[:_WHOLE_BODY_MAX]
                            whole_bodies.append(whole)
                            whole_decoded = _deep_decode(whole)
                            if whole_decoded != whole:
                                whole_bodies.append(whole_decoded)
                            tail = val[-_BODY_CLASSIFY_BYTES:]
                            decoded_tail = _deep_decode(tail)
                            if decoded_tail not in targets:
                                targets.append(decoded_tail)
                            if tail != decoded_tail and tail not in targets:
                                targets.append(tail)
                        val = val[:_BODY_CLASSIFY_BYTES]
                    decoded = _deep_decode(val)
                    if decoded not in targets:
                        targets.append(decoded)
            hex_payload = metadata.get("hex") or metadata.get("payload_hex")

        # --- Run every rule against every target ---
        dst_port = None
        if metadata:
            dst_port = metadata.get("dst_port") or metadata.get("port")
            if isinstance(dst_port, str):
                try:
                    dst_port = int(dst_port)
                except ValueError:
                    dst_port = None

        is_ics_port = dst_port in _ICS_PORTS if dst_port else False
        is_http_port = dst_port in _HTTP_PORTS if dst_port else False
        is_http_traffic = method is not None
        is_mqtt_port = dst_port in (1883, 8883, 8084) if dst_port else False
        is_mqtt_proto = "mqtt" in (protocol or "").lower()
        is_smtp_port = dst_port in (25, 465, 587, 2525) if dst_port else False
        is_smtp_proto = "smtp" in (protocol or "").lower()

        # Final clamp: whatever appended to `targets` above — a decoded URI, a header
        # block, a decoded metadata field — nothing reaches a rule longer than the cap.
        # Decoding can lengthen a string, so capping the inputs alone is not enough.
        targets = [t[:_BODY_CLASSIFY_BYTES] for t in targets if t]

        for target in targets:
            if not target:
                continue
            for atype, rname, regex in _RULES:
                if rname in seen_rules:
                    continue
                if rname in _ICS_PORT_CONTEXT_RULES and not is_ics_port:
                    continue
                if rname in _HTTP_EXCLUDED_RULES and (is_http_port or is_http_traffic):
                    continue
                # MQTT text rules only fire on MQTT ports/protocol (prevent
                # false positives on SMTP, FTP, Telnet, etc.).
                #
                # Keyed on the ATTACK TYPE, not the rule name. It used to test
                # `rname.startswith("mqtt_")`, which is prefix- and case-sensitive:
                # `MQTT_Command_Injection_Detection` — an AI-generated name — was
                # the one MQTT rule of 34 that slipped through, and with a pattern
                # of `\d{10}` it tagged SIP INVITEs (phone numbers) and PostgreSQL
                # password messages as MQTT_ATTACK. Observed in production 2026-08-27.
                if atype == "MQTT_ATTACK" and not is_mqtt_port and not is_mqtt_proto:
                    continue
                # Same reasoning for SMTP: an EHLO/VRFY/RCPT verb inside an HTTP
                # request is a multi-protocol scanner (LeakIX sends exactly that),
                # and Scanner-* rules already name it correctly. None of the 11
                # SMTP_PROBE rules were excluded from HTTP before this.
                if atype == "SMTP_PROBE" and not is_smtp_port and not is_smtp_proto:
                    continue
                # Binary/ICS-protocol rules (built-in or AI-generated) must not
                # fire on identified HTTP traffic — a web request is never a
                # Modbus/S7/MQTT/binary-ICS attack.
                if _rule_targets_binary_proto(rname, atype) and (is_http_traffic or is_http_port):
                    continue
                m = regex.search(target)
                if m:
                    snippet = m.group(0)[:200]
                    hits.append((atype, rname, snippet))
                    seen_rules.add(rname)
        for whole_body in whole_bodies:
            for atype, rname, snippet in _php2shell_whole_body(whole_body):
                if rname not in seen_rules:
                    hits.append((atype, rname, snippet[:200]))
                    seen_rules.add(rname)
    else:
        # Binary protocol — extract hex_payload from metadata for
        # the binary detectors below, but skip all text regex rules
        hex_payload = None
        if metadata:
            hex_payload = metadata.get("hex") or metadata.get("payload_hex")
        # Set text for binary detectors that still reference it
        text = payload

    # --- Binary Modbus detection (for ICS/SCADA traffic) ---
    proto_lower = (protocol or "").lower()
    dst_port = None
    if metadata:
        dst_port = metadata.get("dst_port") or metadata.get("port")
        if isinstance(dst_port, str):
            try:
                dst_port = int(dst_port)
            except ValueError:
                dst_port = None

    # NOTE: hex_payload is already set above (in both text and binary paths)

    is_modbus_context = (
        "modbus" in proto_lower
        or proto_lower in ("modbus", "modbus_tcp", "modbus/tcp")
        or dst_port == 502
    )

    # Try Modbus detection on ICS ports or when we have binary-looking data
    should_try_modbus = (
        is_modbus_context
        or dst_port == 502
        or hex_payload
        or (
            payload
            and len(payload) >= 8
            and any(ord(c) < 32 for c in payload[:8] if c not in "\r\n\t")
        )
    )

    if should_try_modbus:
        # Try to detect from hex payload first
        if hex_payload:
            binary_hits = _detect_modbus_binary(hex_payload)
            for hit in binary_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

        # Try raw payload (binary or hex string)
        if payload:
            binary_hits = _detect_modbus_binary(payload)
            for hit in binary_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary SMB detection (for lateral movement / exploitation) ---
    is_smb_context = (
        "smb" in proto_lower
        or proto_lower in ("smb", "smb2", "smb3", "cifs", "microsoft-ds", "netbios-ssn")
        or (metadata and metadata.get("dst_port") in (445, 139))
    )

    if is_smb_context or hex_payload:
        # Try to detect from hex payload
        if hex_payload:
            smb_hits = _detect_smb_binary(hex_payload)
            for hit in smb_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

        # Also try raw payload — detector handles hex-string or raw-binary input
        if payload:
            smb_hits = _detect_smb_binary(payload)
            for hit in smb_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Context-aware Kubernetes detection (port-based) ---
    # Only check K8s patterns when on K8s-specific ports to avoid false positives
    k8s_hits = _detect_k8s_attack(text, protocol, metadata)
    for hit in k8s_hits:
        if hit[1] not in seen_rules:
            hits.append(hit)
            seen_rules.add(hit[1])

    # --- Binary DNP3 detection (Port 20000) ---
    is_dnp3_context = (
        "dnp3" in proto_lower or dst_port == 20000 or (hex_payload and hex_payload[:4] == "0564")
    )

    if is_dnp3_context:
        if hex_payload:
            dnp3_hits = _detect_dnp3_binary(hex_payload)
            for hit in dnp3_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            dnp3_hits = _detect_dnp3_binary(payload)
            for hit in dnp3_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary IEC 60870-5-104 detection (Port 2404) ---
    is_iec104_context = (
        "iec" in proto_lower
        or "104" in proto_lower
        or "60870" in proto_lower
        or dst_port == 2404
        or (hex_payload and hex_payload[:2] == "68")
    )

    if is_iec104_context:
        if hex_payload:
            iec_hits = _detect_iec104_binary(hex_payload)
            for hit in iec_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            iec_hits = _detect_iec104_binary(payload)
            for hit in iec_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary S7comm detection (Port 102) ---
    is_s7_context = (
        "s7" in proto_lower
        or "siemens" in proto_lower
        or dst_port == 102
        or (hex_payload and hex_payload[:4] == "0300")
    )

    if is_s7_context:
        if hex_payload:
            s7_hits = _detect_s7comm_binary(hex_payload)
            for hit in s7_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            s7_hits = _detect_s7comm_binary(payload)
            for hit in s7_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary BACnet detection (Port 47808 UDP) ---
    is_bacnet_context = (
        "bacnet" in proto_lower or dst_port == 47808 or (hex_payload and hex_payload[:2] == "81")
    )

    if is_bacnet_context:
        if hex_payload:
            bacnet_hits = _detect_bacnet_binary(hex_payload)
            for hit in bacnet_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            bacnet_hits = _detect_bacnet_binary(payload)
            for hit in bacnet_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary EtherNet/IP detection (Port 44818) ---
    is_enip_context = (
        "enip" in proto_lower
        or "ethernet/ip" in proto_lower
        or "cip" in proto_lower
        or dst_port == 44818
    )

    if is_enip_context:
        if hex_payload:
            enip_hits = _detect_enip_binary(hex_payload)
            for hit in enip_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            enip_hits = _detect_enip_binary(payload)
            for hit in enip_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary MQTT detection (Ports 1883, 8883) ---
    # NOTE: Do NOT match on magic bytes alone (0x10, 0x30, 0x82) — these collide
    # with TLS (0x14 ChangeCipherSpec), ASN.1 SEQUENCE (0x30), and TLS record
    # length prefixes (0x82). Only match on explicit MQTT port or protocol hint.
    is_mqtt_context = "mqtt" in proto_lower or dst_port in (1883, 8883, 8084)

    if is_mqtt_context:
        if hex_payload:
            mqtt_hits = _detect_mqtt_binary(hex_payload)
            for hit in mqtt_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            mqtt_hits = _detect_mqtt_binary(payload)
            for hit in mqtt_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary OPC UA detection (Port 4840) ---
    is_opcua_context = (
        "opcua" in proto_lower
        or "opc" in proto_lower
        or dst_port == 4840
        or (
            hex_payload and hex_payload[:6] in ("48454c", "4f504e", "4d5347", "434c4f")
        )  # HEL, OPN, MSG, CLO
        or (payload and len(payload) >= 3 and payload[:3] in ("HEL", "OPN", "MSG", "CLO"))
    )

    if is_opcua_context:
        if hex_payload:
            opcua_hits = _detect_opcua_binary(hex_payload)
            for hit in opcua_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            opcua_hits = _detect_opcua_binary(payload)
            for hit in opcua_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary PROFINET detection (Ports 34962-34964) ---
    is_profinet_context = (
        "profinet" in proto_lower or "pnio" in proto_lower or dst_port in (34962, 34963, 34964)
    )

    if is_profinet_context:
        if hex_payload:
            pn_hits = _detect_profinet_binary(hex_payload)
            for hit in pn_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            pn_hits = _detect_profinet_binary(payload)
            for hit in pn_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary FINS (Omron) detection (Port 9600) ---
    is_fins_context = (
        "fins" in proto_lower
        or "omron" in proto_lower
        or dst_port == 9600
        or (hex_payload and hex_payload[:8] == "46494e53")  # "FINS" magic
        or (payload and len(payload) >= 4 and payload[:4] == "FINS")
    )

    if is_fins_context:
        if hex_payload:
            fins_hits = _detect_fins_binary(hex_payload)
            for hit in fins_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            fins_hits = _detect_fins_binary(payload)
            for hit in fins_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary Melsec/MC Protocol (Mitsubishi) detection (Ports 5000-5002) ---
    is_melsec_context = (
        "melsec" in proto_lower
        or "mitsubishi" in proto_lower
        or "mc_protocol" in proto_lower
        or dst_port in (5000, 5001, 5002)
        or (hex_payload and hex_payload[:4] in ("5000", "5400"))  # Type 3E / Type 4E subheader
    )

    if is_melsec_context:
        if hex_payload:
            mc_hits = _detect_melsec_binary(hex_payload)
            for hit in mc_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            mc_hits = _detect_melsec_binary(payload)
            for hit in mc_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    # --- Binary CoAP / LwM2M detection (Ports 5683, 5684 UDP) ---
    is_coap_context = "coap" in proto_lower or "lwm2m" in proto_lower or dst_port in (5683, 5684)

    if is_coap_context:
        if hex_payload:
            coap_hits = _detect_coap_binary(hex_payload)
            for hit in coap_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])
        if payload:
            coap_hits = _detect_coap_binary(payload)
            for hit in coap_hits:
                if hit[1] not in seen_rules:
                    hits.append(hit)
                    seen_rules.add(hit[1])

    return hits


# =========================================================================
# OPC UA Binary Detection (Port 4840)
# =========================================================================
