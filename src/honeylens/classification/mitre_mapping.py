#!/usr/bin/env python3
"""
mitre_mapping.py — MITRE ATT&CK Mapping for Attack Classification
==================================================================
Maps attack types from attack_classifier.py to MITRE ATT&CK techniques.
Supports both Enterprise and ICS frameworks.

Usage:
    from mitre_mapping import get_mitre_mapping, enrich_event_with_mitre

    # Get mapping for an attack type
    mappings = get_mitre_mapping("SQLI")
    # [{"technique": "T1190", "tactic": "initial-access", "name": "Exploit Public-Facing Application"}]

    # Enrich an event with MITRE data
    event = {"attack_types": "SQLI,XSS", ...}
    enriched = enrich_event_with_mitre(event)
    # event now has mitre_techniques and mitre_tactics fields

Requires: Python >= 3.9
"""

from __future__ import annotations

from typing import Any

# =============================================================================
# MITRE ATT&CK Tactics (Enterprise)
# =============================================================================

TACTICS: dict[str, dict[str, Any]] = {
    "reconnaissance": {
        "id": "TA0043",
        "order": 1,
        "color": "#ff6b6b",
        "name": "Reconnaissance",
    },
    "resource-development": {
        "id": "TA0042",
        "order": 2,
        "color": "#ff8787",
        "name": "Resource Development",
    },
    "initial-access": {
        "id": "TA0001",
        "order": 3,
        "color": "#fa5252",
        "name": "Initial Access",
    },
    "execution": {
        "id": "TA0002",
        "order": 4,
        "color": "#e64980",
        "name": "Execution",
    },
    "persistence": {
        "id": "TA0003",
        "order": 5,
        "color": "#be4bdb",
        "name": "Persistence",
    },
    "privilege-escalation": {
        "id": "TA0004",
        "order": 6,
        "color": "#7950f2",
        "name": "Privilege Escalation",
    },
    "defense-evasion": {
        "id": "TA0005",
        "order": 7,
        "color": "#4c6ef5",
        "name": "Defense Evasion",
    },
    "credential-access": {
        "id": "TA0006",
        "order": 8,
        "color": "#228be6",
        "name": "Credential Access",
    },
    "discovery": {
        "id": "TA0007",
        "order": 9,
        "color": "#15aabf",
        "name": "Discovery",
    },
    "lateral-movement": {
        "id": "TA0008",
        "order": 10,
        "color": "#12b886",
        "name": "Lateral Movement",
    },
    "collection": {
        "id": "TA0009",
        "order": 11,
        "color": "#40c057",
        "name": "Collection",
    },
    "command-and-control": {
        "id": "TA0011",
        "order": 12,
        "color": "#82c91e",
        "name": "Command and Control",
    },
    "exfiltration": {
        "id": "TA0010",
        "order": 13,
        "color": "#fab005",
        "name": "Exfiltration",
    },
    "impact": {
        "id": "TA0040",
        "order": 14,
        "color": "#fd7e14",
        "name": "Impact",
    },
}

# ICS-specific tactics
TACTICS_ICS = {
    "initial-access-ics": {
        "id": "TA0108",
        "order": 1,
        "color": "#fa5252",
        "name": "Initial Access",
    },
    "execution-ics": {
        "id": "TA0104",
        "order": 2,
        "color": "#e64980",
        "name": "Execution",
    },
    "persistence-ics": {
        "id": "TA0110",
        "order": 3,
        "color": "#be4bdb",
        "name": "Persistence",
    },
    "evasion-ics": {
        "id": "TA0103",
        "order": 4,
        "color": "#4c6ef5",
        "name": "Evasion",
    },
    "discovery-ics": {
        "id": "TA0102",
        "order": 5,
        "color": "#15aabf",
        "name": "Discovery",
    },
    "lateral-movement-ics": {
        "id": "TA0109",
        "order": 6,
        "color": "#12b886",
        "name": "Lateral Movement",
    },
    "collection-ics": {
        "id": "TA0100",
        "order": 7,
        "color": "#40c057",
        "name": "Collection",
    },
    "command-and-control-ics": {
        "id": "TA0101",
        "order": 8,
        "color": "#82c91e",
        "name": "Command and Control",
    },
    "inhibit-response-function": {
        "id": "TA0107",
        "order": 9,
        "color": "#fab005",
        "name": "Inhibit Response Function",
    },
    "impair-process-control": {
        "id": "TA0106",
        "order": 10,
        "color": "#fd7e14",
        "name": "Impair Process Control",
    },
    "impact-ics": {
        "id": "TA0105",
        "order": 11,
        "color": "#f03e3e",
        "name": "Impact",
    },
}


# =============================================================================
# ICS techniques, derived from the ingest's own table
# =============================================================================

# Display metadata per semantics. The technique and tactic come from
# ``SEMANTICS_TO_MITRE`` -- the table the ingest assigns from -- so the matrix cannot list
# a technique the ingest cannot produce. ``for`` is the discriminator ``pick_ics_mitre``
# reads (the passive eBPF path).
_ICS_ENTRY_META: dict[str, tuple[str, str, str]] = {
    # semantics: (technique name, description, "for")
    "read": ("Monitor Process State", "Read ICS registers/coils to observe process state", "read"),
    "enumerate": (
        "Point & Tag Identification",
        "Enumerate ICS device tags and data points",
        "discovery",
    ),
    "discovery": (
        "Remote System Discovery",
        "ICS device scanning and enumeration",
        "scan",
    ),
    "write": (
        "Modify Parameter",
        "Write to PLC registers, coils, or setpoints",
        "write",
    ),
    "command": (
        "Unauthorized Command Message",
        "Send unauthorized commands to ICS device",
        "command",
    ),
    "control": (
        "Device Restart/Shutdown",
        "Control operations that halt or restart the device",
        "control",
    ),
}


def _ics_attack_entries() -> list[dict]:
    from honeylens.ingest.ics_helpers import SEMANTICS_TO_MITRE

    entries = []
    for semantics, mitre in SEMANTICS_TO_MITRE.items():
        if not mitre:
            continue
        name, description, discriminator = _ICS_ENTRY_META[semantics]
        technique, tactic = mitre
        entries.append(
            {
                "technique": technique,
                "tactic": tactic,
                "name": name,
                "description": description,
                "framework": "ics",
                "for": discriminator,
            }
        )
    return entries


# =============================================================================
# Attack Type to MITRE ATT&CK Mapping
# =============================================================================

ATTACK_TO_MITRE: dict[str, list[dict]] = {
    # =========================================================================
    # SQL Injection
    # =========================================================================
    "SQLI": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "SQL injection to compromise web application",
        },
    ],
    # =========================================================================
    # Cross-Site Scripting
    # =========================================================================
    "XSS": [
        {
            "technique": "T1059.007",
            "tactic": "execution",
            "name": "Command and Scripting Interpreter: JavaScript",
            "description": "Execute malicious JavaScript in victim's browser",
        },
        {
            "technique": "T1185",
            "tactic": "collection",
            "name": "Browser Session Hijacking",
            "description": "Steal session cookies or credentials via XSS",
        },
    ],
    # =========================================================================
    # Remote Code Execution
    # =========================================================================
    "RCE": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "Exploit vulnerability for remote code execution",
        },
        {
            "technique": "T1059",
            "tactic": "execution",
            "name": "Command and Scripting Interpreter",
            "description": "Execute commands on target system",
        },
    ],
    # =========================================================================
    # Local File Inclusion
    # =========================================================================
    "LFI": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "Path traversal to access local files",
        },
        {
            "technique": "T1083",
            "tactic": "discovery",
            "name": "File and Directory Discovery",
            "description": "Read sensitive files via LFI",
        },
        {
            "technique": "T1552.001",
            "tactic": "credential-access",
            "name": "Unsecured Credentials: Credentials In Files",
            "description": "Extract credentials from configuration files",
        },
    ],
    # =========================================================================
    # Remote File Inclusion
    # =========================================================================
    "RFI": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "Include remote malicious file",
        },
        {
            "technique": "T1105",
            "tactic": "command-and-control",
            "name": "Ingress Tool Transfer",
            "description": "Download and execute remote payload",
        },
    ],
    # =========================================================================
    # Server-Side Request Forgery
    # =========================================================================
    "SSRF": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "SSRF to access internal resources",
        },
        {
            "technique": "T1552.005",
            "tactic": "credential-access",
            "name": "Unsecured Credentials: Cloud Instance Metadata API",
            "description": "Access cloud metadata for credentials",
        },
        {
            "technique": "T1046",
            "tactic": "discovery",
            "name": "Network Service Discovery",
            "description": "Scan internal network via SSRF",
        },
    ],
    # =========================================================================
    # Server-Side Template Injection
    # =========================================================================
    "SSTI": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "Template injection for code execution",
        },
        {
            "technique": "T1059",
            "tactic": "execution",
            "name": "Command and Scripting Interpreter",
            "description": "Execute code via template engine",
        },
    ],
    # =========================================================================
    # XML External Entity
    # =========================================================================
    "XXE": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "XXE to read files or SSRF",
        },
        {
            "technique": "T1552.001",
            "tactic": "credential-access",
            "name": "Unsecured Credentials: Credentials In Files",
            "description": "Read sensitive files via XXE",
        },
    ],
    # =========================================================================
    # Log4Shell
    # =========================================================================
    "LOG4SHELL": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "Log4j JNDI injection (CVE-2021-44228)",
        },
        {
            "technique": "T1059.007",
            "tactic": "execution",
            "name": "Command and Scripting Interpreter: JavaScript",
            "description": "Execute code via JNDI lookup",
        },
        {
            "technique": "T1105",
            "tactic": "command-and-control",
            "name": "Ingress Tool Transfer",
            "description": "Download malicious class from remote server",
        },
    ],
    # =========================================================================
    # Shellshock
    # =========================================================================
    "SHELLSHOCK": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "Bash Shellshock (CVE-2014-6271)",
        },
        {
            "technique": "T1059.004",
            "tactic": "execution",
            "name": "Command and Scripting Interpreter: Unix Shell",
            "description": "Execute bash commands via environment variables",
        },
    ],
    # =========================================================================
    # PHP Attacks
    # =========================================================================
    "PHP": [
        {
            "technique": "T1059",
            "tactic": "execution",
            "name": "Command and Scripting Interpreter",
            "description": "PHP code execution",
        },
        {
            "technique": "T1505.003",
            "tactic": "persistence",
            "name": "Server Software Component: Web Shell",
            "description": "Deploy PHP web shell for persistence",
        },
    ],
    # =========================================================================
    # Credential Attacks
    # =========================================================================
    "CREDENTIAL": [
        {
            "technique": "T1110",
            "tactic": "credential-access",
            "name": "Brute Force",
            "description": "Password guessing or brute force attack",
        },
        {
            "technique": "T1110.001",
            "tactic": "credential-access",
            "name": "Brute Force: Password Guessing",
            "description": "Attempt common passwords",
        },
        {
            "technique": "T1110.003",
            "tactic": "credential-access",
            "name": "Brute Force: Password Spraying",
            "description": "Try few passwords against many accounts",
        },
    ],
    # =========================================================================
    # LDAP Injection
    # =========================================================================
    "LDAPI": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "LDAP injection attack",
        },
        {
            "technique": "T1087",
            "tactic": "discovery",
            "name": "Account Discovery",
            "description": "Enumerate accounts via LDAP",
        },
        {
            "technique": "T1069",
            "tactic": "discovery",
            "name": "Permission Groups Discovery",
            "description": "Discover group memberships via LDAP",
        },
    ],
    # =========================================================================
    # Scanner Detection
    # =========================================================================
    "SCANNER": [
        {
            "technique": "T1595.002",
            "tactic": "reconnaissance",
            "name": "Active Scanning: Vulnerability Scanning",
            "description": "Automated vulnerability scanning",
        },
        {
            "technique": "T1046",
            "tactic": "discovery",
            "name": "Network Service Discovery",
            "description": "Port scanning and service enumeration",
        },
    ],
    # =========================================================================
    # Kubernetes Attacks
    # =========================================================================
    "K8S_ATTACK": [
        {
            "technique": "T1613",
            "tactic": "discovery",
            "name": "Container and Resource Discovery",
            "description": "Enumerate Kubernetes resources",
        },
        {
            "technique": "T1609",
            "tactic": "execution",
            "name": "Container Administration Command",
            "description": "Execute commands in containers",
        },
        {
            "technique": "T1610",
            "tactic": "execution",
            "name": "Deploy Container",
            "description": "Deploy malicious container",
        },
        {
            "technique": "T1552.007",
            "tactic": "credential-access",
            "name": "Unsecured Credentials: Container API",
            "description": "Access Kubernetes secrets",
        },
    ],
    # =========================================================================
    # SMB Attacks
    # =========================================================================
    "SMB": [
        {
            "technique": "T1021.002",
            "tactic": "lateral-movement",
            "name": "Remote Services: SMB/Windows Admin Shares",
            "description": "Lateral movement via SMB",
        },
        {
            "technique": "T1570",
            "tactic": "lateral-movement",
            "name": "Lateral Tool Transfer",
            "description": "Transfer tools via SMB shares",
        },
        {
            "technique": "T1187",
            "tactic": "credential-access",
            "name": "Forced Authentication",
            "description": "Capture NTLM hashes via SMB",
        },
    ],
    # =========================================================================
    # FortiGate Attacks
    # =========================================================================
    "FORTI_ATTACK": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "FortiGate CVE exploitation",
        },
        {
            "technique": "T1078",
            "tactic": "persistence",
            "name": "Valid Accounts",
            "description": "Compromise FortiGate admin credentials",
        },
        {
            "technique": "T1562.001",
            "tactic": "defense-evasion",
            "name": "Impair Defenses: Disable or Modify Tools",
            "description": "Disable firewall security features",
        },
    ],
    # =========================================================================
    # CRLF Injection
    # =========================================================================
    "CRLF": [
        {
            "technique": "T1071.001",
            "tactic": "command-and-control",
            "name": "Application Layer Protocol: Web Protocols",
            "description": "HTTP response splitting",
        },
    ],
    # =========================================================================
    # MQTT Attacks
    # =========================================================================
    "MQTT_ATTACK": [
        {
            "technique": "T1071",
            "tactic": "command-and-control",
            "name": "Application Layer Protocol",
            "description": "MQTT protocol abuse for C2",
        },
        {
            "technique": "T1119",
            "tactic": "collection",
            "name": "Automated Collection",
            "description": "Subscribe to MQTT topics for data collection",
        },
    ],
    # =========================================================================
    # Oracle TNS Attacks
    # =========================================================================
    "ORACLE_TNS": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "Oracle database exploitation",
        },
        {
            "technique": "T1505",
            "tactic": "persistence",
            "name": "Server Software Component",
            "description": "Database persistence mechanisms",
        },
    ],
    # =========================================================================
    # SMTP Probes
    # =========================================================================
    "SMTP_PROBE": [
        {
            "technique": "T1589.002",
            "tactic": "reconnaissance",
            "name": "Gather Victim Identity Information: Email Addresses",
            "description": "SMTP user enumeration",
        },
        {
            "technique": "T1598.003",
            "tactic": "reconnaissance",
            "name": "Phishing for Information: Spearphishing Link",
            "description": "SMTP reconnaissance for phishing",
        },
    ],
    # =========================================================================
    # Modbus/ICS Attacks
    # =========================================================================
    "MODBUS": [
        {
            "technique": "T0801",
            "tactic": "collection-ics",
            "name": "Monitor Process State",
            "description": "Read Modbus registers",
            "framework": "ics",
        },
        {
            "technique": "T0861",
            "tactic": "collection-ics",
            "name": "Point & Tag Identification",
            "description": "Enumerate Modbus devices",
            "framework": "ics",
        },
        {
            "technique": "T0821",
            "tactic": "impair-process-control",
            "name": "Modify Controller Tasking",
            "description": "Write Modbus registers",
            "framework": "ics",
        },
    ],
    # =========================================================================
    # ICS Generic Attacks
    # =========================================================================
    "ICS_ATTACK": _ics_attack_entries(),
    # =========================================================================
    # MiTM Attacks
    # =========================================================================
    "ARP_SPOOF": [
        {
            "technique": "T1557.002",
            "tactic": "credential-access",
            "name": "Adversary-in-the-Middle: ARP Cache Poisoning",
            "description": "ARP spoofing for traffic interception",
        },
        {
            "technique": "T1557",
            "tactic": "collection",
            "name": "Adversary-in-the-Middle",
            "description": "Intercept network traffic",
        },
    ],
    "ARP_SCAN": [
        {
            "technique": "T1046",
            "tactic": "discovery",
            "name": "Network Service Discovery",
            "description": "ARP scanning for host discovery",
        },
    ],
    "DNS_SPOOF": [
        {
            "technique": "T1557.001",
            "tactic": "credential-access",
            "name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
            "description": "DNS spoofing for credential capture",
        },
        {
            "technique": "T1557",
            "tactic": "collection",
            "name": "Adversary-in-the-Middle",
            "description": "Redirect traffic via DNS poisoning",
        },
    ],
    "DNS_UNTRUSTED": [
        {
            "technique": "T1071.004",
            "tactic": "command-and-control",
            "name": "Application Layer Protocol: DNS",
            "description": "DNS tunneling or rogue DNS",
        },
    ],
    # =========================================================================
    # Session Attacks
    # =========================================================================
    "SESSION": [
        {
            "technique": "T1539",
            "tactic": "credential-access",
            "name": "Steal Web Session Cookie",
            "description": "Session hijacking",
        },
        {
            "technique": "T1185",
            "tactic": "collection",
            "name": "Browser Session Hijacking",
            "description": "Take over browser session",
        },
    ],
    # =========================================================================
    # Protocol Abuse
    # =========================================================================
    "PROTO_ABUSE": [
        {
            "technique": "T1071",
            "tactic": "command-and-control",
            "name": "Application Layer Protocol",
            "description": "Protocol abuse for C2 or data exfiltration",
        },
    ],
    # =========================================================================
    # Cloud Attacks (Idea 12 - New)
    # =========================================================================
    "CLOUD_ATTACK": [
        {
            "technique": "T1552.005",
            "tactic": "credential-access",
            "name": "Unsecured Credentials: Cloud Instance Metadata API",
            "description": "Access cloud instance metadata for credentials",
        },
        {
            "technique": "T1078.004",
            "tactic": "initial-access",
            "name": "Valid Accounts: Cloud Accounts",
            "description": "Use stolen cloud credentials",
        },
        {
            "technique": "T1580",
            "tactic": "discovery",
            "name": "Cloud Infrastructure Discovery",
            "description": "Enumerate cloud resources and configurations",
        },
        {
            "technique": "T1538",
            "tactic": "discovery",
            "name": "Cloud Service Dashboard",
            "description": "Access cloud service management console",
        },
    ],
    # =========================================================================
    # GraphQL Attacks (Idea 12 - New)
    # =========================================================================
    "GRAPHQL": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "GraphQL injection or introspection abuse",
        },
        {
            "technique": "T1087",
            "tactic": "discovery",
            "name": "Account Discovery",
            "description": "GraphQL introspection for schema enumeration",
        },
    ],
    # =========================================================================
    # API Abuse (Idea 12 - New)
    # =========================================================================
    "API_ABUSE": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "API endpoint exploitation",
        },
        {
            "technique": "T1550.001",
            "tactic": "defense-evasion",
            "name": "Use Alternate Authentication Material: Application Access Token",
            "description": "JWT token manipulation or theft",
        },
        {
            "technique": "T1110.001",
            "tactic": "credential-access",
            "name": "Brute Force: Password Guessing",
            "description": "API authentication brute force",
        },
    ],
    # =========================================================================
    # Supply Chain Attacks (Idea 12 - New)
    # =========================================================================
    "SUPPLY_CHAIN": [
        {
            "technique": "T1195.002",
            "tactic": "initial-access",
            "name": "Supply Chain Compromise: Compromise Software Supply Chain",
            "description": "Malicious package injection",
        },
        {
            "technique": "T1195.001",
            "tactic": "initial-access",
            "name": "Supply Chain Compromise: Compromise Software Dependencies",
            "description": "Dependency confusion or typosquatting",
        },
    ],
    # =========================================================================
    # AI/LLM Attacks (Idea 12 - New)
    # =========================================================================
    "AI_ATTACK": [
        {
            "technique": "T1059",
            "tactic": "execution",
            "name": "Command and Scripting Interpreter",
            "description": "Prompt injection to execute commands",
        },
        {
            "technique": "T1530",
            "tactic": "collection",
            "name": "Data from Cloud Storage",
            "description": "Extract training data or system prompts",
        },
    ],
    # =========================================================================
    # Authentication Attacks (Idea 12 - New)
    # =========================================================================
    "AUTH_ATTACK": [
        {
            "technique": "T1110",
            "tactic": "credential-access",
            "name": "Brute Force",
            "description": "Credential stuffing or brute force",
        },
        {
            "technique": "T1539",
            "tactic": "credential-access",
            "name": "Steal Web Session Cookie",
            "description": "Session fixation or theft",
        },
        {
            "technique": "T1111",
            "tactic": "credential-access",
            "name": "Multi-Factor Authentication Interception",
            "description": "2FA bypass attempts",
        },
        {
            "technique": "T1556",
            "tactic": "credential-access",
            "name": "Modify Authentication Process",
            "description": "OAuth redirect manipulation",
        },
    ],
    # =========================================================================
    # Deserialization Attacks (Idea 12 - New)
    # =========================================================================
    "DESERIALIZE": [
        {
            "technique": "T1190",
            "tactic": "initial-access",
            "name": "Exploit Public-Facing Application",
            "description": "Insecure deserialization exploit",
        },
        {
            "technique": "T1059",
            "tactic": "execution",
            "name": "Command and Scripting Interpreter",
            "description": "Code execution via deserialization",
        },
    ],
}


# =============================================================================
# Helper Functions
# =============================================================================


def get_mitre_mapping(attack_type: str, rule_name: str | None = None) -> list[dict]:
    """
    Get MITRE ATT&CK mapping for an attack type.

    Args:
        attack_type: Attack type from attack_classifier (e.g., "SQLI", "XSS")
        rule_name: Optional specific rule name for more precise mapping

    Returns:
        List of technique dictionaries with technique, tactic, name, description
    """
    return ATTACK_TO_MITRE.get(attack_type, [])


def get_all_techniques() -> set[str]:
    """Get set of all technique IDs we can detect."""
    techniques = set()
    for mappings in ATTACK_TO_MITRE.values():
        for m in mappings:
            techniques.add(m["technique"])
    return techniques


def get_techniques_by_tactic(tactic: str) -> list[dict]:
    """Get all techniques for a specific tactic."""
    techniques = []
    seen = set()

    for attack_type, mappings in ATTACK_TO_MITRE.items():
        for m in mappings:
            if m["tactic"] == tactic and m["technique"] not in seen:
                techniques.append(
                    {
                        "technique": m["technique"],
                        "name": m["name"],
                        "attack_types": [attack_type],
                    }
                )
                seen.add(m["technique"])
            elif m["tactic"] == tactic and m["technique"] in seen:
                # Add attack type to existing technique
                for t in techniques:
                    if t["technique"] == m["technique"]:
                        if attack_type not in t["attack_types"]:
                            t["attack_types"].append(attack_type)

    return techniques


def get_attack_types_for_technique(technique_id: str) -> list[str]:
    """Get all attack types that map to a specific technique."""
    attack_types = []
    for attack_type, mappings in ATTACK_TO_MITRE.items():
        for m in mappings:
            if m["technique"] == technique_id:
                attack_types.append(attack_type)
                break
    return attack_types


def enrich_event_with_mitre(event: dict) -> dict:
    """
    Enrich an event dictionary with MITRE ATT&CK data.

    Args:
        event: Event dictionary with 'attack_types' field

    Returns:
        Event with added 'mitre_techniques' and 'mitre_tactics' fields
    """
    attack_types_str = event.get("attack_types", "")
    if not attack_types_str:
        event["mitre_techniques"] = []
        event["mitre_tactics"] = []
        return event

    techniques = []
    tactics = set()
    seen_techniques = set()

    # Parse attack types (comma-separated string)
    for attack_type in attack_types_str.split(","):
        attack_type = attack_type.strip()
        if not attack_type:
            continue

        mappings = get_mitre_mapping(attack_type)

        for m in mappings:
            tech_id = m["technique"]
            if tech_id not in seen_techniques:
                techniques.append(
                    {
                        "id": tech_id,
                        "name": m["name"],
                        "tactic": m["tactic"],
                        "attack_type": attack_type,
                        "framework": m.get("framework", "enterprise"),
                    }
                )
                seen_techniques.add(tech_id)
            tactics.add(m["tactic"])

    event["mitre_techniques"] = techniques
    event["mitre_tactics"] = sorted(list(tactics))

    return event


def get_tactic_info(tactic: str) -> dict | None:
    """Get tactic metadata (id, color, name)."""
    if tactic in TACTICS:
        return TACTICS[tactic]
    if tactic in TACTICS_ICS:
        return TACTICS_ICS[tactic]
    return None


def get_tactics_ordered() -> list[str]:
    """Get list of tactics in display order."""
    return sorted(TACTICS.keys(), key=lambda t: TACTICS[t]["order"])


def get_coverage_summary() -> dict:
    """Get summary of MITRE coverage."""
    all_techniques = get_all_techniques()

    # Count by tactic
    by_tactic = {}
    for tactic in TACTICS.keys():
        techniques = get_techniques_by_tactic(tactic)
        by_tactic[tactic] = {
            "count": len(techniques),
            "techniques": [t["technique"] for t in techniques],
        }

    return {
        "total_techniques": len(all_techniques),
        "total_attack_types": len(ATTACK_TO_MITRE),
        "by_tactic": by_tactic,
    }


# =============================================================================
# CLI for testing
# =============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        attack_type = sys.argv[1].upper()
        mappings = get_mitre_mapping(attack_type)
        if mappings:
            print(f"\nMITRE ATT&CK mapping for {attack_type}:")
            for m in mappings:
                print(f"  {m['technique']}: {m['name']} ({m['tactic']})")
        else:
            print(f"No mapping found for {attack_type}")
    else:
        # Print summary
        summary = get_coverage_summary()
        print("\nMITRE ATT&CK Coverage Summary:")
        print(f"  Total techniques: {summary['total_techniques']}")
        print(f"  Attack types mapped: {summary['total_attack_types']}")
        print("\nBy Tactic:")
        for tactic in get_tactics_ordered():
            info = summary["by_tactic"].get(tactic, {})
            count = info.get("count", 0)
            if count > 0:
                print(f"  {tactic}: {count} techniques")
