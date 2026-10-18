"""
classification/scoring.py — Attack Scoring, Chains & Stats
============================================================
Severity mapping, attack chain detection, threat scoring, classifier stats.
Extracted from attack_classifier.py (Phase 1 cleanup).
"""

from __future__ import annotations

import re
from typing import Any

AttackHit = tuple[str, str, str]

SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
}

ATTACK_TYPE_SEVERITY = {
    "RCE": "critical",
    "DESERIALIZE": "critical",
    "LOG4SHELL": "critical",
    "SHELLSHOCK": "critical",
    "REDIS_HEAP_CORRUPT": "critical",
    "REDIS_TOPK_WILDFREE": "critical",
    "REDIS_TDIGEST_OVERFLOW": "critical",
    "REDIS_EXPLOIT_CHAIN": "critical",
    "SQLI": "high",
    "LFI": "high",
    "RFI": "high",
    "XXE": "high",
    "SSTI": "high",
    "AUTH_ATTACK": "high",
    "waf-canary-callback": "high",  # deception_waf: reflected fictional-WAF-vendor token
    "CLOUD_ATTACK": "high",
    "ICS_ATTACK": "high",
    "MODBUS": "high",
    "SMB": "high",
    "FORTI_ATTACK": "high",
    "K8S_ATTACK": "high",
    "SUPPLY_CHAIN": "high",
    "XSS": "medium",
    "SSRF": "medium",
    "CRLF": "medium",
    "LDAPI": "medium",
    "API_ABUSE": "medium",
    "GRAPHQL": "medium",
    "CREDENTIAL": "medium",
    "SENSITIVE_FILE": "medium",  # direct config/.env/.git disclosure (NOT path-traversal LFI)
    "ORACLE_TNS": "medium",
    "MQTT_ATTACK": "medium",
    "AI_ATTACK": "medium",
    "PHP": "medium",
    # PHP2Shell (CVE-2026-109618/109619): the exploitation variant executes code, the probe
    # variants only test for the vector. Kept apart so a scan never scores as a dropper.
    "CVE_2026_109619": "critical",
    # 109618 is the parser/resource half of the pair: a 423 KB body or a 240-deep nested array
    # takes the interpreter down or wedges it, but it carries no code of its own. High, not
    # critical -- it is a real hit on a real weakness, and it is not a shell.
    "CVE_2026_109618": "high",
    "PHP2SHELL": "medium",
    "EXPLOIT_KIT": "high",
    "MALWARE": "high",
    "CRYPTOMINING": "high",
    "AI_AGENT_CALLBACK": "high",  # AI agent obeyed a prompt-injection canary (Idea 52)
    # Reconnaissance for exposed AI endpoints — interesting, but a probe is not a hit.
    "AI_ENDPOINT_PROBE": "medium",
    # WAGO PFC200 RTU honeypot (Idea 54). CONTROL_WRITE is critical because on a real
    # controller that is someone moving a valve, not reading a page.
    "WAGO_RECON": "medium",
    "WAGO_IO_DISCLOSURE": "high",
    "WAGO_CREDENTIAL_CAPTURE": "high",
    "WAGO_CONTROL_WRITE": "critical",
    "WAGO_FIRMWARE_UPLOAD": "critical",
    "WAGO_EXPLOIT_ATTEMPT": "critical",
    # Exploitation of an edge appliance — Ivanti, PAN-OS, Cisco, SonicWall. Auth
    # bypasses and command injection against the device that fronts a network, so a
    # hit here is not reconnaissance.
    "APPLIANCE_EXPLOIT": "critical",
    # Cisco AnyConnect / ASA tunnel-group enumeration. A handshake against a decoy is
    # reconnaissance, not a compromise — medium. The forged-MAC variant is promoted
    # below, because a client announcing impossible hardware is no longer ambiguous.
    "VPN_RECON": "medium",
    "BRUTE_FORCE": "medium",
    "PROTO_ABUSE": "low",
    "SESSION": "low",
    # Suricata engine/decoder events (SURICATA STREAM|TLS|HTTP|Applayer ...).
    # Capture-quality telemetry, not attacker behaviour — see ingest/suricata.py.
    "ENGINE_ANOMALY": "info",
    "SCANNER": "info",
    "SMTP_PROBE": "info",
    "REPUTATION": "info",
    "TOR": "info",
}

RULE_SEVERITY_OVERRIDE = {
    "rce_reverse_shell_bash": "critical",
    "rce_reverse_shell_nc": "critical",
    "rce_reverse_shell_python": "critical",
    "rce_dev_tcp": "critical",
    "java_ysoserial_gadgets": "critical",
    "modbus_fc05_write_single_coil": "critical",
    "modbus_fc16_write_multiple_registers": "critical",
    "aws_imds_credentials": "critical",
    "jwt_none_algorithm": "critical",
    "k8s_honeytoken_reuse": "critical",  # nosec B105 — a severity label, not a secret
    "k8s_token_request": "high",  # nosec B105 — a severity label, not a secret
    "k8s_secret_read": "high",  # nosec B105 — a severity label, not a secret
    "k8s_serviceaccount_enum": "medium",
    "sqli_union_select": "high",
    "xss_script_tag": "high",
    "lfi_etc_passwd": "high",
    "prompt_ignore_previous": "high",
    "jailbreak_dan": "high",  # nosec B105 — a severity label, not a secret
    "scan_user_agent_bot": "low",
    "scan_vuln_paths": "low",
    "graphql_introspection_typename": "info",
    "smtp_helo": "info",
    "smtp_ehlo": "info",
    # A VPN client reporting a multicast MAC is not a misconfigured endpoint — that
    # address cannot belong to any NIC, so the client is generated.
    "cisco_anyconnect_forged_mac": "high",
}


def get_severity(attack_type: str, rule_name: str) -> str:
    """Get severity level for a detection."""
    # Check rule-specific override first
    if rule_name in RULE_SEVERITY_OVERRIDE:
        return RULE_SEVERITY_OVERRIDE[rule_name]
    # Fall back to attack type default
    return ATTACK_TYPE_SEVERITY.get(attack_type, "medium")


def get_severity_weight(severity: str) -> int:
    """Get numeric weight for severity level."""
    return SEVERITY_WEIGHTS.get(severity, 50)


# =========================================================================
# Attack Chain Detection
# =========================================================================
# Detect multi-stage attacks by looking for patterns across hits

ATTACK_CHAINS: dict[str, dict[str, Any]] = {
    "web_intrusion": {
        "stages": ["SCANNER", "SQLI|XSS|LFI|RFI", "RCE|CREDENTIAL"],
        "description": "Web application intrusion chain",
        "severity_boost": 20,
    },
    "cloud_compromise": {
        "stages": ["SSRF|CLOUD_ATTACK", "CLOUD_ATTACK.*credential|CLOUD_ATTACK.*token"],
        "description": "Cloud credential theft chain",
        "severity_boost": 25,
    },
    "ics_attack": {
        "stages": ["ICS_ATTACK.*read|MODBUS.*read", "ICS_ATTACK.*write|MODBUS.*write"],
        "description": "ICS reconnaissance to manipulation",
        "severity_boost": 30,
    },
    "api_takeover": {
        "stages": ["API_ABUSE.*jwt|AUTH_ATTACK", "API_ABUSE.*mass_assignment|API_ABUSE.*idor"],
        "description": "API authentication bypass chain",
        "severity_boost": 20,
    },
}


def detect_attack_chains(hits: list[AttackHit]) -> list[dict[str, Any]]:
    """Detect attack chains from a list of hits."""
    detected_chains = []

    for chain_name, chain_def in ATTACK_CHAINS.items():
        stages_matched = 0
        for stage_pattern in chain_def["stages"]:
            # Check if any hit matches this stage
            for hit in hits:
                combined = f"{hit[0]}:{hit[1]}"
                if re.search(stage_pattern, combined, re.IGNORECASE):
                    stages_matched += 1
                    break

        # Chain detected if 2+ stages match
        if stages_matched >= 2:
            detected_chains.append(
                {
                    "chain": chain_name,
                    "description": chain_def["description"],
                    "stages_matched": stages_matched,
                    "severity_boost": chain_def["severity_boost"],
                }
            )

    return detected_chains


def calculate_threat_score(hits: list[AttackHit]) -> dict[str, Any]:
    """
    Calculate composite threat score from detections.

    Returns dict with:
    - score: 0-100 threat score
    - severity: overall severity level
    - attack_types: list of detected attack types
    - chains: detected attack chains
    - top_hits: most severe detections
    """
    if not hits:
        return {"score": 0, "severity": "none", "attack_types": [], "chains": [], "top_hits": []}

    # Calculate base score from individual hits
    scored_hits = []
    for hit in hits:
        severity = get_severity(hit[0], hit[1])
        weight = get_severity_weight(severity)
        scored_hits.append((hit, severity, weight))

    # Sort by weight descending
    scored_hits.sort(key=lambda x: x[2], reverse=True)

    # Base score: sum of top 5 hits (avoid over-counting)
    base_score = sum(h[2] for h in scored_hits[:5])

    # Normalize to 0-100 scale
    base_score = min(base_score, 100)

    # Detect attack chains
    chains = detect_attack_chains(hits)

    # Apply chain bonuses
    chain_bonus = sum(c["severity_boost"] for c in chains)

    # Diversity bonus: multiple attack types indicate sophisticated attack
    unique_types = len(set(h[0] for h in hits))
    diversity_bonus = min((unique_types - 1) * 5, 20) if unique_types > 1 else 0

    # Final score
    final_score = min(base_score + chain_bonus + diversity_bonus, 100)

    # Determine overall severity
    if final_score >= 80:
        overall_severity = "critical"
    elif final_score >= 60:
        overall_severity = "high"
    elif final_score >= 40:
        overall_severity = "medium"
    elif final_score >= 20:
        overall_severity = "low"
    else:
        overall_severity = "info"

    return {
        "score": final_score,
        "severity": overall_severity,
        "attack_types": list(set(h[0] for h in hits)),
        "chains": chains,
        "top_hits": [(h[0][0], h[0][1], h[1]) for h in scored_hits[:5]],  # (type, rule, severity)
        "hit_count": len(hits),
    }


# =========================================================================
# Rule definitions — compiled once at import time
def classify_attack_summary(hits: list[AttackHit]) -> str | None:
    """
    Return a comma-separated list of unique attack_type values,
    e.g. "SQLI,XSS,LFI".  Returns None if no attacks detected.
    """
    if not hits:
        return None
    types: list[str] = []
    seen: set = set()
    for atype, _, _ in hits:
        if atype not in seen:
            types.append(atype)
            seen.add(atype)
    return ",".join(types) if types else None


def classify_payload(payload: str | None) -> tuple[str | None, list[AttackHit]]:
    """
    Convenience: classify a raw payload string without event context.
    Returns (summary_string, hits_list).
    """
    # Lazy import to break the scoring <-> attack_classifier import cycle.
    from honeylens.classification.attack_classifier import classify_event_row

    hits = classify_event_row(payload=payload, protocol=None)
    return classify_attack_summary(hits), hits


def classify_with_severity(
    payload: str | None, protocol: str | None = None, metadata: dict | None = None
) -> dict[str, Any]:
    """
    Enhanced classification with severity scoring and attack chain detection.

    Returns dict with:
    - summary: comma-separated attack types
    - hits: list of (attack_type, rule_name, snippet)
    - threat_score: dict with score, severity, chains, etc.
    - severity: overall severity level
    - score: 0-100 threat score
    """
    # Lazy import to break the scoring <-> attack_classifier import cycle.
    from honeylens.classification.attack_classifier import classify_event_row

    hits = classify_event_row(payload=payload, protocol=protocol, metadata=metadata)
    summary = classify_attack_summary(hits)
    threat_score = calculate_threat_score(hits)

    return {
        "summary": summary,
        "hits": hits,
        "hits_with_severity": [(h[0], h[1], h[2], get_severity(h[0], h[1])) for h in hits],
        "threat_score": threat_score,
        "severity": threat_score["severity"],
        "score": threat_score["score"],
        "attack_types": threat_score["attack_types"],
        "chains": threat_score["chains"],
    }


def get_rule_info(rule_name: str) -> dict[str, Any] | None:
    """Get information about a specific rule.

    In 0.9 this function (and the two below) raised NameError — it used _RULES without an
    import. No one called it, so no one noticed. The import is local, because text_rules
    imports this module at startup.
    """
    from honeylens.classification.text_rules import _RULES

    for atype, rname, regex in _RULES:
        if rname == rule_name:
            return {
                "attack_type": atype,
                "rule_name": rname,
                "pattern": regex.pattern,
                "severity": get_severity(atype, rname),
                "severity_weight": get_severity_weight(get_severity(atype, rname)),
            }
    return None


def get_rules_by_severity(severity: str) -> list[dict[str, Any]]:
    """Get all rules with a specific severity level."""
    from honeylens.classification.text_rules import _RULES

    rules = []
    for atype, rname, _regex in _RULES:
        rule_severity = get_severity(atype, rname)
        if rule_severity == severity:
            rules.append(
                {
                    "attack_type": atype,
                    "rule_name": rname,
                    "severity": rule_severity,
                }
            )
    return rules


def get_rules_by_type(attack_type: str) -> list[dict[str, Any]]:
    """Get all rules for a specific attack type."""
    from honeylens.classification.text_rules import _RULES

    rules = []
    for atype, rname, regex in _RULES:
        if atype == attack_type:
            rules.append(
                {
                    "attack_type": atype,
                    "rule_name": rname,
                    "severity": get_severity(atype, rname),
                    "pattern": regex.pattern[:100],
                }
            )
    return rules


def get_classifier_stats() -> dict[str, Any]:
    """Get statistics about the classifier."""
    from collections import Counter

    from honeylens.classification.text_rules import _CUSTOM_RULE_NAMES, _RULES

    type_counts = Counter(r[0] for r in _RULES)
    severity_counts = Counter(get_severity(r[0], r[1]) for r in _RULES)

    return {
        "total_rules": len(_RULES),
        "builtin_rules": len(_RULES) - len(_CUSTOM_RULE_NAMES),
        "custom_rules": len(_CUSTOM_RULE_NAMES),
        "custom_rule_names": sorted(_CUSTOM_RULE_NAMES),
        "attack_types": len(type_counts),
        "by_type": dict(type_counts.most_common()),
        "by_severity": dict(severity_counts),
        "version": "2.1.0",  # Idea 12 + AI custom rules
    }


# =========================================================================
# CLI for testing
# =========================================================================


def get_all_rules() -> dict[str, list[dict[str, Any]]]:
    """All rules grouped by attack type (classifier panel)."""
    from honeylens.classification.text_rules import _CUSTOM_RULE_NAMES, _RULES

    rules_by_type: dict[str, list[dict[str, Any]]] = {}
    for attack_type, rule_name, compiled_regex in _RULES:
        pattern = compiled_regex.pattern
        rules_by_type.setdefault(attack_type, []).append(
            {
                "rule_name": rule_name,
                "pattern": pattern[:100] + ("..." if len(pattern) > 100 else ""),
                "is_custom": rule_name in _CUSTOM_RULE_NAMES,
            }
        )
    return rules_by_type


def get_rules_flat() -> list[dict[str, Any]]:
    """All rules as a flat list."""
    from honeylens.classification.text_rules import _CUSTOM_RULE_NAMES, _RULES

    return [
        {"attack_type": at, "rule_name": rn, "is_custom": rn in _CUSTOM_RULE_NAMES}
        for at, rn, _ in _RULES
    ]


def get_attack_types() -> list[str]:
    """Sorted list of all attack types."""
    from honeylens.classification.text_rules import _RULES

    return sorted({at for at, _, _ in _RULES})
