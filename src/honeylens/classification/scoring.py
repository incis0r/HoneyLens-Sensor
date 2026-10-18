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
    # hp_http h2_capture (HTTP/2 on :80). The 49975 trio is emitted by h2bomb.py (nginx decoy, and
    # now hp_http); h2c_upgrade_recon by hp_http._classify for a bare `Upgrade: h2c`.
    "cve_2026_119618_flood": "high",  # h2_capture: many 119618-shaped streams with a high reset ratio
    "cve_2026_119618_probe": "medium",  # h2_capture: 119618-shaped request(s) without flood volume
    "h2_rapid_reset": "medium",  # h2_capture: reset flood without the 119618 shape
    "h2_prior_knowledge": "low",  # h2_capture: HTTP/2 preface and nothing else fired
    "h2_protocol_error": "low",  # h2_capture: the peer broke HTTP/2 and nothing else fired
    "h2c_upgrade_recon": "low",  # hp_http: bare `Upgrade: h2c`
    "cve_2026_49975_zero_window": "high",  # h2bomb: initial flow-control window of 0
    "cve_2026_49975_window_drip": "medium",  # h2bomb: many tiny WINDOW_UPDATE increments
    "cve_2026_49975_hpack_bomb": "medium",  # h2bomb: header blocks at or over the flood count
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
    # Someone asked this host to relay a connection. Medium because that is the whole claim:
    # one CONNECT establishes the attempt, not the intent -- 12,197 of them in 30 days on the
    # public sensor, 95% previously unlabelled, mostly one botnet reaching its own fronted
    # infrastructure but a measured minority being reachability surveys.
    "OPEN_PROXY_RELAY": "medium",
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
    # CVE-2026-114938 "Java4Shell": the malformed `Authorization: Basic` blob drives
    # `java.util.Base64.decode` on a pre-fix HotSpot JDK (AVX-512 VBMI) 64 bytes past its
    # output buffer, pre-auth, in one header. Critical because the primitive is a controlled
    # out-of-bounds write reached without credentials -- not because we can prove the target
    # fired. Severity grades what the request attempts; the host-side conjunction (vulnerable
    # JDK + VBMI silicon + intrinsic on) is an exposure question and lives in the inventory.
    "CVE_2026_114938": "critical",
    "PHP2SHELL": "medium",
    # NODE2SHELL (CVE-2026-111497): a Brotli-encoded request body. Medium for the same reason
    # PHP2SHELL is -- it says the vector is present, not that the decoder was driven out of
    # bounds. Nothing on the fleet has ever sent one, so a medium here is still a verdict that
    # gets looked at, and there is no CVE type to score because none can be demonstrated.
    "NODE2SHELL": "medium",
    # React2Shell (CVE-2025-55182). The pollution pair is a real exploitation attempt against
    # the action handler -- high. What the evaluated string did is scored by its own rules: a
    # JS-only arithmetic oracle down to medium, a spawned command or a socket back to the
    # operator up to critical through `RCE` and `C2`. The fleet has seen 313 bodies and exactly
    # one shell, and a verdict that treats them alike is wrong about both.
    "CVE_2025_55182": "high",
    # The kit's footprint on a path sweep: 2,721 rows carry the header, 313 carry the exploit.
    # No rule emits this any more (2026-11-09): the `Next-Action` header rule that produced it
    # fired on 4,766 rows of which 75% were a sweeper spraying the header at SharePoint, phpinfo
    # and `.env` paths, so it was retargeted to SCANNER. The entry stays because the stored rows
    # still carry the token until a corrective pass runs, and an unmapped verdict renders blank.
    "REACT_SERVER_ACTION": "low",
    # AndroxGh0st's twenty-byte opening probe. Reconnaissance: nothing in that body executes
    # anything, and on this fleet nothing follows it from the same address in the same minute.
    # 1,402 rows over 30 days with an empty attack_types, which is why it has a verdict now.
    "ANDROXGH0ST": "low",
    # The `/k7f3a9` beacon and its key. A check-in is not a scan: the operator is polling
    # something they believe they already own, on a three-hour cycle, and any host that answers
    # it has been compromised by them or is a honeypot. High on both counts. HOST_PROFILING is
    # what the implant ASKED for -- our decoys answer with a static page and never tell it
    # anything -- so medium.
    "WEBSHELL_CHECKIN": "high",
    "WEBSHELL_KEY": "high",
    "HOST_PROFILING": "medium",
    # B4d, the carried indicator bundle. A webshell being WRITTEN is the event the
    # `sp-webshell-aspx` verdict confused with one being probed, and a successful write is a
    # shell on the host. An exposed code-execution API is a hit on a real weakness but the
    # request still only asked. The Citrix traversal family and the Node-stack paths are named
    # so they stop reading as a generic `/etc/passwd` attempt and a generic scan; both only
    # asked for something, so both stay low. Forged CDN provenance is deception about origin --
    # medium, because it says who they are pretending to be, not what they did.
    "WEBSHELL_UPLOAD": "critical",
    "CODE_EXEC_API": "high",
    "CITRIX_TRAVERSAL": "low",
    "NODE_RECON": "low",
    "FORGED_ORIGIN": "medium",
    # B5a. Both of these fell through to this table's `medium` default, so a legacy-dialect
    # negotiation and an EternalBlue attempt scored identically -- the distinction the two
    # names promise was not in the data. An SMB1 frame is the internet's baseline against any
    # exposed :445 (342,608 rows on one sensor); the exploit verdict now requires the exploit's
    # own bytes.
    "SMB_SCAN": "low",
    "SMB_EXPLOIT_PROBE": "high",
    # A callback to attacker-controlled infrastructure. Suricata's ingest has mapped two ET
    # categories to this type since before any rule produced it (ingest/suricata.py), and with
    # no entry here every one of those rows took this table's `medium` default -- the same
    # silent fallback measured on `RECON` a day earlier. The React2Shell reverse shell is
    # promoted to critical by its own rule below: a literal address and port is not a domain
    # reputation hit.
    "C2": "high",
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
    # `RECON` existed with no entry here, so it fell back to this table's `medium` default.
    # Exactly one rule emitted it — `k8s_proxy_port_probe`, which exists after 20,432 rows of
    # `GET /` were called K8s attacks on `prod` — meaning the verdict whose whole purpose is
    # to say "this was only a probe" scored like enumerating an etcd cluster. Measured and
    # fixed 2026-11-04; pinned by tests/test_recon_is_scored_and_probes_are_named.py.
    "RECON": "low",
    # WordPress, split so the dashboard can tell "what is installed here?" from "here are
    # some credentials". Before 2026-11-05 neither existed and `wp-json` / `wp-content`
    # matched no committed rule at all.
    "WORDPRESS_RECON": "low",
    "WORDPRESS_CRED": "medium",
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
    # React2Shell, graded by what the evaluated string did rather than by the delivery.
    # `cl.connect(12323,'91.92.40.12')` is an interactive shell in the Node process, measured
    # on the fleet 2026-11-03 and filed as `(none)`.
    "node_reverse_shell_connect": "critical",
    # Evaluation proven, nothing else: `206104+true+7358727` spawns no process and writes no
    # file. Medium so a capability check never reads like the one real shell.
    "react2shell_eval_oracle_arith": "medium",
    # Java4Shell, graded by whether the blob could reach the intrinsic at all. The VBMI gate
    # is 31 bytes on the 21 line and 128 on the 17 line, so a 5-character malformed blob
    # (`AAA==`, the first rung of the ladder measured 2026-11-18) is a capability check that
    # cannot write. Medium so it never reads like the 65- or 129-character shape.
    "java4shell_basic_auth_malformed_short": "medium",
    # The same grading, for the shape path that judges a decoded token rather than wire text
    # (`honeylens.b64_shape.shape_verdict`). Two of the four carriers arrive transport-encoded
    # -- `SAMLRequest` writes `=` as `%3D`, `BinarySecurityToken` folds across lines -- so a
    # text rule counting characters there measures the encoding. Measured on this fleet: 52
    # SAMLRequest rows from 29 sources read `mod4 == 2` for that reason alone.
    #
    # Only the exact 64+1 shape keeps the critical. F5 (`AdjProbe8/9`) measured 129, 193 and
    # 259 with every malformed tail at zero fires, and the actor on 2026-11-18 behaved as if
    # they knew it: 5 / 65 / 129 once at 05:01, then only the 65 at 05:05, 05:30, 05:46, 05:52.
    "java4shell_b64_fires_65": "critical",
    "java4shell_b64_malformed_length": "medium",
    # Illegal padding says the token cannot be Base64; it does not say the shape reaches the
    # intrinsic. Medium, and it is the only gate that survives a clipped field.
    "java4shell_b64_illegal_padding": "medium",
    # The header-carrier text rules, graded by the same three gates. The two `fires_65` rules
    # are absent on purpose: they take the attack type's own critical.
    "java4shell_ntlm_malformed_length": "medium",
    # Padding in a Bearer value says the standard decoder is probably in the path (F4 leaves
    # only the hand-rolled `-_`->`+/` re-pad reachable), not that the blob is the firing shape.
    "java4shell_bearer_padded_segment": "medium",
    "java4shell_illegal_padding_header": "medium",
    # Demoted 2026-11-18: this fires on any `mod4 == 1` blob of 33 characters or more, which
    # includes the rungs F5 measured as non-firing. Left critical, every rung of a sweep read
    # like the one shape that writes, and the shape that writes now has its own rule.
    "java4shell_basic_auth_overwrite_length": "medium",
    # WordPress, graded by what the request does rather than by which path it used.
    # Posting credentials outranks asking which plugins are installed; one `system.multicall`
    # carrying hundreds of `wp.getUsersBlogs` calls outranks a single login attempt; and a
    # reachable `wp-config.php` backup — database credentials and auth salts in cleartext —
    # outranks all of it. Pinned by tests/test_wordpress_verdicts.py.
    "wordpress_content_enum": "low",
    "wordpress_plugin_probe": "low",
    "wordpress_admin_probe": "low",
    "wordpress_login_attempt": "medium",
    "wordpress_xmlrpc_multicall": "high",
    # A readable debug.log returns a live session cookie, so it outranks a login attempt;
    # `wp-config.php` still outranks it, because that one also hands over the database.
    "wordpress_debug_log_probe": "high",
    # Not generic enumeration: each is the precondition check for one named core flaw.
    "wordpress_upgrade_window_probe": "medium",
    "wordpress_rest_batch": "medium",
    "wordpress_config_exposure": "critical",
    # Open-proxy relay, graded by what the request reveals rather than by the method used.
    # A tunnel to a known what-is-my-IP endpoint is someone testing whether we relay;
    # Shadowserver's survey arrives this way and must not read like the botnet next to it.
    "open_proxy_reachability_check": "low",
    # An unauthenticated Docker API listing returns the container inventory, so it is not mere
    # reconnaissance -- but inventory is not credentials, and the request is a bare GET from
    # scanner ranges. One rung below CLOUD_ATTACK's default; see the rule's own comment.
    "docker_api_remote_list": "medium",
    # Kubernetes Secrets, ordered by how much of the cluster one request asks for
    # (2026-11-04). Every Secret in the cluster in a single response is the most valuable
    # read there is, so it outranks a named secret rather than sharing K8S_ATTACK's default.
    "k8s_secrets_cluster_wide": "critical",
    "k8s_secrets_namespace_list": "high",
    # `k8s_secret_read` is already pinned at `high` further down; the two above sit beside it
    # so a named secret and a whole-namespace listing rank together, and the cluster-wide
    # listing above both.
    # etcd, ordered deliberately (2026-11-04). Before this every verdict on :2379 resolved
    # to K8S_ATTACK's default `high` — a version disclosure scored like destroying the
    # cluster key store, so the field said nothing. Mutating cluster state outranks reading
    # it; reading it outranks enumerating the cluster; enumerating outranks an endpoint etcd
    # serves unauthenticated by design. Pinned by tests/test_etcd_verdicts.py.
    "k8s_etcd_kv_write": "critical",
    "k8s_etcd_kv_delete": "critical",
    "k8s_etcd_kv_read": "high",
    "k8s_etcd_keys": "high",
    "consul_kv_read": "high",
    "k8s_etcd_members": "medium",
    "k8s_etcd_maintenance": "medium",
    "k8s_etcd_auth_probe": "medium",
    "k8s_etcd_version": "low",
    "k8s_etcd_health": "low",
    "k8s_etcd_metrics": "low",
    "k8s_etcd_stats": "low",
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
