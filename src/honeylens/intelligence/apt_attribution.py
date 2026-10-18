#!/usr/bin/env python3
"""
apt_attribution.py — MITRE ATT&CK technique-overlap matching (Idea 22)
Hybrid Intelligence Sensor

This module loads MITRE ATT&CK STIX data and ranks intrusion-set groups
whose documented techniques overlap with what the sensor observes.

A note on what this is and isn't
--------------------------------
The function name is historical; this is **not** probabilistic APT
attribution. Honeypot interactions are a weak signal for that:
  - The source IP is almost always compromised infrastructure, not the
    actor's own.
  - Honeypot traffic is overwhelmingly opportunistic scanning (Mirai-
    style, mass-CVE), which most APT groups do not do directly.
  - We see at most a few minutes of one-way protocol probing, not the
    multi-stage kill chains attribution depends on (custom tooling,
    targeting patterns, infrastructure overlap).

What we *can* do, and what this module does, is **technique-overlap
matching**: given the techniques observed in a session, return the
MITRE intrusion-set groups whose technique catalogue has the most
overlap, with a discriminator-driven score and a categorical
``confidence`` label. The score is unitless — its only purpose is
ranking. Operators should make decisions from the ``confidence`` field,
the matched-technique list, and the ``reasoning`` trail, not the
numeric score.

Scoring (option β rework — see the APT-attribution rework plan)
-------------------------------------------------------------------
    score = rarest_discriminator x adjusted_coverage x group_prior

Filter: if a technique is used by >MAX_GROUPS_PER_TECHNIQUE (default 10)
known groups, it's excluded as too generic to discriminate.

Compatible with Python 3.9+ (no X|Y union syntax).
"""

import json
import logging
import os
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import requests as http_requests

from honeylens.config import DATA_DIR

logger = logging.getLogger("sensor.apt")

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_STIX_PATH = str(DATA_DIR / "enterprise-attack.json")
MAX_GROUPS_PER_TECHNIQUE = 10
MIN_ATTRIBUTION_PROBABILITY = 0.10  # legacy alias; new code uses MIN_SCORE
MIN_SCORE = 0.01  # raw-score floor; below = "none" band, dropped

# ---------------------------------------------------------------------------
# Internal tagging: attack patterns → MITRE techniques
# ---------------------------------------------------------------------------
# The mapping table lives in data/attack_to_mitre.json so operators can edit
# without touching code. We try a few common deploy paths in order and fall
# back to a small bundled dict if none are readable (keeps imports working
# in unit-test / dev environments without /opt/sensor).

_DEFAULT_MAPPING_PATHS = (
    str(DATA_DIR / "attack_to_mitre.json"),  # the operator's copy takes precedence
    str(Path(__file__).resolve().parent.parent / "data" / "attack_to_mitre.json"),  # dane pakietu
)

_FALLBACK_ATTACK_TO_MITRE = {
    "ssh_brute": ["T1110.001", "T1110.003"],
    "default_creds": ["T1078.001"],
    "sqli": ["T1190"],
    "rce": ["T1190", "T1059"],
    "port_scan": ["T1595.001", "T1046"],
    "cve_exploit": ["T1190", "T1203"],
}


def _load_attack_to_mitre(paths=_DEFAULT_MAPPING_PATHS):
    """Load and flatten the categorised JSON mapping into a single dict.

    Categories in the JSON (``brute_force``, ``web_exploitation``, …) are
    documentation only — they don't affect lookup. Returns a fresh dict on
    every call; ``ATTACK_TO_MITRE`` is the cached module-level result.
    """
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("attack_to_mitre.json not readable at %s: %s", path, exc)
            continue

        flat = {}
        for cat, mapping in (raw or {}).items():
            if cat.startswith("_"):  # _documentation, _comment, etc.
                continue
            if not isinstance(mapping, dict):
                continue
            for k, v in mapping.items():
                if isinstance(v, list):
                    flat[k] = list(v)
        if flat:
            logger.info(
                "loaded attack→MITRE mapping from %s (%d patterns)",
                path,
                len(flat),
            )
            return flat

    logger.warning(
        "attack_to_mitre.json not found; using bundled fallback mapping (%d patterns)",
        len(_FALLBACK_ATTACK_TO_MITRE),
    )
    return dict(_FALLBACK_ATTACK_TO_MITRE)


ATTACK_TO_MITRE = _load_attack_to_mitre()

# Internal tags: human-readable labels for behavioral clusters
TAG_DEFINITIONS = {
    "SSH_BRUTER": {
        "patterns": ["ssh_brute", "ssh_auth_fail"],
        "techniques": ["T1110.001", "T1110.003"],
    },
    "WEB_EXPLOITER": {
        "patterns": [
            "sqli",
            "xss",
            "lfi",
            "rfi",
            "rce",
            "path_traversal",
            "cmd_injection",
            "ssrf",
            "xxe",
            "deserialization",
            "template_inject",
        ],
        "techniques": ["T1190", "T1059"],
    },
    "IOT_BOTNET": {
        "patterns": ["mirai_scan", "mirai_payload", "telnet_brute", "default_creds"],
        "techniques": ["T1078", "T1110", "T1021"],
    },
    "ICS_SCANNER": {
        "patterns": [
            "modbus_scan",
            "modbus_write",
            "s7comm_scan",
            "bacnet_scan",
            "iec104_scan",
            "dnp3_scan",
        ],
        "techniques": ["T0846", "T0869"],
    },
    "RECON_SCANNER": {
        "patterns": ["port_scan", "service_enum", "banner_grab", "web_scanner", "vuln_scan"],
        "techniques": ["T1595", "T1046"],
    },
    "CREDENTIAL_STEALER": {
        "patterns": [
            "ntlm_capture",
            "ftp_brute",
            "mysql_brute",
            "rdp_brute",
            "kerberoast",
            "credential_dump",
        ],
        "techniques": ["T1110", "T1557"],
    },
    "C2_OPERATOR": {
        "patterns": ["reverse_shell", "beacon", "dns_tunnel", "botnet_c2"],
        "techniques": ["T1071", "T1572", "T1095"],
    },
    "CRYPTO_MINER": {
        "patterns": ["crypto_mining", "stratum_connect", "xmrig"],
        "techniques": ["T1496"],
    },
    "RANSOMWARE_ACTOR": {
        "patterns": ["smb_exploit", "psexec", "wmi_exec", "lateral_move", "ransomware"],
        "techniques": ["T1486", "T1021"],
    },
    "DATA_EXFIL": {
        "patterns": ["dns_exfil", "http_exfil", "icmp_tunnel"],
        "techniques": ["T1048", "T1572"],
    },
    "VULN_EXPLOITER": {"patterns": ["cve_exploit", "log4shell"], "techniques": ["T1190", "T1203"]},
    "SPAM_BOT": {
        "patterns": ["smtp_relay", "smtp_brute", "mass_mail", "phishing"],
        "techniques": ["T1566"],
    },
    "VPN_PROXY": {"patterns": ["vpn_proxy"], "techniques": ["T1090"]},
    "TOR_EXIT": {"patterns": ["tor_exit"], "techniques": ["T1090.003"]},
    "KNOWN_BOTNET_C2": {
        "patterns": ["botnet_c2", "malware_download"],
        "techniques": ["T1071", "T1583"],
    },
    # Idea 52: an AI agent obeyed a prompt-injection canary -> AI-assisted automation.
    "AI_ASSISTED_AUTOMATION": {
        "patterns": ["ai_agent_callback", "prompt_injection_canary"],
        "techniques": ["T1119"],
    },
}


# ---------------------------------------------------------------------------
# MITRE STIX Loader
# ---------------------------------------------------------------------------


class MitreAttackData:
    """
    Loads and queries MITRE ATT&CK STIX enterprise data.
    Builds: technique→groups mapping, group details, technique usage counts.
    """

    def __init__(self, stix_path: str = DEFAULT_STIX_PATH, stix_url: str = DEFAULT_STIX_URL):
        self.stix_path = stix_path
        self.stix_url = stix_url

        # Indexed data
        self.groups = {}  # type: dict[str, dict[str, Any]]  # group_id → group info
        self.techniques = {}  # type: dict[str, dict[str, Any]]  # tech_id → tech info
        self.group_techniques = {}  # type: dict[str, set[str]]  # group_id → set of tech IDs
        self.technique_groups = defaultdict(set)  # type: dict[str, set[str]]  # tech_id → set of group_ids
        self.technique_group_counts = {}  # type: dict[str, int]  # tech_id → count of groups

        self.loaded = False
        self.load_timestamp = 0.0

    def download_stix(self) -> bool:
        """Download enterprise-attack.json from MITRE GitHub."""

        try:
            logger.info("Downloading MITRE ATT&CK STIX from %s", self.stix_url)
            resp = http_requests.get(self.stix_url, timeout=60)
            resp.raise_for_status()

            os.makedirs(os.path.dirname(self.stix_path), exist_ok=True)
            with open(self.stix_path, "w", encoding="utf-8") as f:
                f.write(resp.text)

            logger.info("STIX data saved to %s (%d bytes)", self.stix_path, len(resp.text))
            return True
        except Exception as e:
            logger.error("Failed to download STIX data: %s", e)
            return False

    def load(self, force_download: bool = False) -> bool:
        """Load and index STIX data."""
        # Download if missing or forced
        if force_download or not os.path.exists(self.stix_path):
            if not self.download_stix():
                return False

        try:
            with open(self.stix_path, encoding="utf-8") as f:
                stix_bundle = json.load(f)
        except Exception as e:
            logger.error("Failed to load STIX file %s: %s", self.stix_path, e)
            return False

        objects = stix_bundle.get("objects", [])
        logger.info("Parsing %d STIX objects from %s", len(objects), self.stix_path)

        # Index objects by STIX ID
        stix_index: dict[str, dict] = {}
        for obj in objects:
            stix_id = obj.get("id", "")
            stix_index[stix_id] = obj

            obj_type = obj.get("type", "")

            # Skip deprecated/revoked
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue

            # Groups (intrusion-set)
            if obj_type == "intrusion-set":
                ext_refs = obj.get("external_references", [])
                attack_id = ""
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        attack_id = ref.get("external_id", "")
                        break

                self.groups[obj["id"]] = {
                    "stix_id": obj["id"],
                    "attack_id": attack_id,
                    "name": obj.get("name", ""),
                    "aliases": obj.get("aliases", []),
                    "description": (obj.get("description", "") or "")[:500],
                }
                self.group_techniques[obj["id"]] = set()

            # Techniques (attack-pattern)
            elif obj_type == "attack-pattern":
                ext_refs = obj.get("external_references", [])
                attack_id = ""
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        attack_id = ref.get("external_id", "")
                        break

                self.techniques[obj["id"]] = {
                    "stix_id": obj["id"],
                    "attack_id": attack_id,
                    "name": obj.get("name", ""),
                    "platforms": obj.get("x_mitre_platforms", []),
                }

        # Build technique→group relationships
        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
                continue
            if obj.get("relationship_type") != "uses":
                continue

            source_ref = obj.get("source_ref", "")
            target_ref = obj.get("target_ref", "")

            # Group uses Technique
            if source_ref in self.groups and target_ref in self.techniques:
                tech_attack_id = self.techniques[target_ref].get("attack_id", "")
                if tech_attack_id:
                    self.group_techniques[source_ref].add(tech_attack_id)
                    self.technique_groups[tech_attack_id].add(source_ref)

        # Build group count per technique
        for tech_id, group_set in self.technique_groups.items():
            self.technique_group_counts[tech_id] = len(group_set)

        self.loaded = True
        self.load_timestamp = time.time()

        logger.info(
            "MITRE ATT&CK loaded: %d groups, %d techniques, %d group→technique relationships",
            len(self.groups),
            len(self.techniques),
            sum(len(v) for v in self.group_techniques.values()),
        )
        return True

    def get_group_attack_ids(self) -> dict[str, dict[str, Any]]:
        """Return group info keyed by ATT&CK group ID (e.g. G0007)."""
        result = {}
        for stix_id, info in self.groups.items():
            attack_id = info.get("attack_id", "")
            if attack_id:
                result[attack_id] = {
                    **info,
                    "techniques": list(self.group_techniques.get(stix_id, set())),
                }
        return result


# ---------------------------------------------------------------------------
# Tag computation
# ---------------------------------------------------------------------------


def compute_tags(
    attack_types: list[str],
    osint_data: dict[str, Any] | None = None,
) -> list[str]:
    """
    Compute internal tags based on observed attack types and OSINT flags.

    Returns a sorted list of tag names.
    """
    tags: set[str] = set()
    attack_set = set(at.lower().strip() for at in attack_types)

    for tag_name, definition in TAG_DEFINITIONS.items():
        patterns = set(p.lower() for p in definition["patterns"])
        if attack_set & patterns:  # any overlap
            tags.add(tag_name)

    # OSINT-derived tags
    if osint_data:
        ipinfo = osint_data.get("ipinfo", {})
        feodo = osint_data.get("feodo", {})
        threatfox = osint_data.get("threatfox", {})

        if ipinfo.get("is_vpn") or ipinfo.get("is_proxy"):
            tags.add("VPN_PROXY")
        if ipinfo.get("is_tor"):
            tags.add("TOR_EXIT")
        if feodo.get("is_botnet_c2"):
            tags.add("KNOWN_BOTNET_C2")
        if threatfox.get("found"):
            tags.add("KNOWN_BOTNET_C2")

    return sorted(tags)


def compute_mitre_techniques(
    attack_types: list[str],
    tags: list[str],
) -> list[str]:
    """
    Compute the set of MITRE ATT&CK techniques from observed attack types.
    """
    techniques: set[str] = set()

    for attack in attack_types:
        key = attack.lower().strip()
        if key in ATTACK_TO_MITRE:
            for tech in ATTACK_TO_MITRE[key]:
                techniques.add(tech)

    # Also include techniques from tag definitions
    for tag_name in tags:
        defn = TAG_DEFINITIONS.get(tag_name, {})
        for tech in defn.get("techniques", []):
            techniques.add(tech)

    return sorted(techniques)


# ---------------------------------------------------------------------------
# APT Attribution scoring
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Scoring model (option β rework — see the APT-attribution rework plan)
# ---------------------------------------------------------------------------
# This is technique-overlap matching, not probabilistic attribution. The
# emitted ``score`` is unitless and only meaningful for ranking. The UI
# should surface ``confidence`` (low / medium / high) — that's the part
# operators can act on.

EFFECTIVE_TECH_BUDGET = 8

# Tier-1 groups get a higher prior. Hand-picked from the set most likely to
# be operationally relevant in our threat model. Phase 2 (deferred) will
# derive this from MITRE last-seen / activity metadata instead of a list.
TIER1_GROUPS = frozenset(
    {
        "G0007",  # APT28
        "G0016",  # APT29
        "G0096",  # APT41
        "G0032",  # Lazarus Group
        "G0034",  # Sandworm
        "G0094",  # Kimsuky
        "G0129",  # Mustang Panda
        "G1017",  # Volt Typhoon
    }
)


def _group_prior(attack_id: str) -> float:
    """Per-group prior in [0.5, 1.0]. Tier-1 groups get the higher weight."""
    return 1.0 if attack_id in TIER1_GROUPS else 0.5


def _compute_score(
    overlap: set[str],
    technique_group_counts: dict[str, int],
    group_attack_id: str,
) -> float:
    """Score how strongly observed techniques align with a single group.

    Formula:
        score = rarest_discriminator x adjusted_coverage x group_prior

    Where:
        rarest_discriminator = 1 / min(n_groups for tech in overlap)
            — the *single most discriminating* observed technique drives
              the score. (The previous implementation used the mean rarity,
              which let common techniques dilute one rare match.)
        adjusted_coverage    = min(|overlap| / EFFECTIVE_TECH_BUDGET, 1.0)
            — capped coverage. Rewards multiple matches but doesn't blow
              up for low-tech-count groups (the previous |overlap|/|group|
              biased toward small / under-documented groups).
        group_prior          = 1.0 for tier-1 groups, 0.5 otherwise.

    NOT a calibrated probability. Use _band() for the human-readable
    confidence label.
    """
    if not overlap:
        return 0.0

    rare_n = min(
        (technique_group_counts.get(t, 999) for t in overlap),
        default=999,
    )
    rarest = 1.0 / max(rare_n, 1)

    adj_cov = min(len(overlap) / float(EFFECTIVE_TECH_BUDGET), 1.0)

    score = rarest * adj_cov * _group_prior(group_attack_id)
    return round(min(score, 1.0), 4)


def _band(score: float) -> str:
    """Map a raw score to a human-readable confidence label.

    Boundaries (≥):
        0.20 → high
        0.05 → medium
        0.01 → low
        else → none (filtered out before return)
    """
    if score >= 0.20:
        return "high"
    if score >= 0.05:
        return "medium"
    if score >= 0.01:
        return "low"
    return "none"


def compute_apt_attribution(
    observed_techniques: list[str],
    mitre_data: MitreAttackData,
    max_groups_per_technique: int = MAX_GROUPS_PER_TECHNIQUE,
    min_probability: float = MIN_SCORE,
) -> list[dict[str, Any]]:
    """Compute MITRE group overlap candidates from observed techniques.

    This is *technique-overlap matching* — given a set of techniques
    observed by the sensor, return MITRE intrusion-set groups whose
    documented techniques overlap, ranked by a discriminator-driven
    score. Honeypot data is a weak APT signal at best, so the
    ``confidence`` band on each result is the right thing to surface;
    the numeric ``score`` is for sorting, not for operator decisions.

    Algorithm:
        1. Drop observed techniques used by > ``max_groups_per_technique``
           known groups (too common to discriminate).
        2. For each group with non-empty overlap with the remaining
           techniques, compute ``score`` via _compute_score().
        3. Filter out scores below ``min_probability`` (alias kept for
           backwards compat; the threshold is now MIN_SCORE).
        4. Sort by score desc, then by group_id asc for stability.
        5. Return top 10.

    Returned dicts:
        group_id, group_name, aliases,
        score, confidence, probability (alias for score, deprecated),
        matching_techniques, rarest_technique, rarest_technique_groups,
        filtered_out_techniques, tier1_prior_applied, reasoning.
    """
    if not mitre_data.loaded or not observed_techniques:
        return []

    observed_set = set(observed_techniques)

    # Step 1: filter techniques by global group count
    usable_techniques: set[str] = set()
    filtered_out: set[str] = set()

    for tech in observed_set:
        count = mitre_data.technique_group_counts.get(tech, 0)
        if count == 0:
            continue  # technique not in any known group → skip silently
        if count > max_groups_per_technique:
            filtered_out.add(tech)
        else:
            usable_techniques.add(tech)

    if not usable_techniques:
        return []

    # Step 2: score each group with non-empty overlap
    candidates = []

    for stix_id, group_info in mitre_data.groups.items():
        group_techs = mitre_data.group_techniques.get(stix_id, set())
        if not group_techs:
            continue

        overlap = usable_techniques & group_techs
        if not overlap:
            continue

        attack_id = group_info.get("attack_id", "")
        score = _compute_score(overlap, mitre_data.technique_group_counts, attack_id)
        if score < min_probability:
            continue

        # Identify the discriminating technique for the reasoning trail
        rarest_tech = min(
            overlap,
            key=lambda t: mitre_data.technique_group_counts.get(t, 999),
        )
        rarest_count = mitre_data.technique_group_counts.get(rarest_tech, 0)
        group_filtered = filtered_out & group_techs

        # Build reasoning trail (human-readable)
        reasoning_parts = [
            f"{len(overlap)} of {len(group_techs)} group techniques matched.",
            f"Rarest match: {rarest_tech} used by {rarest_count} group(s).",
        ]
        if attack_id in TIER1_GROUPS:
            reasoning_parts.append("Tier-1 group prior applied.")
        if group_filtered:
            for ft in sorted(group_filtered):
                count = mitre_data.technique_group_counts.get(ft, 0)
                reasoning_parts.append(f"{ft} excluded as too common ({count} groups).")

        confidence = _band(score)

        candidates.append(
            {
                "group_id": attack_id,
                "group_name": group_info.get("name", ""),
                "aliases": group_info.get("aliases", []),
                "score": score,
                "confidence": confidence,
                # Backwards-compatibility alias — kept for one release. Callers
                # should switch to `score` + `confidence`. To be removed in a
                # future cleanup commit.
                "probability": score,
                "matching_techniques": sorted(overlap),
                "rarest_technique": rarest_tech,
                "rarest_technique_groups": rarest_count,
                "filtered_out_techniques": sorted(group_filtered),
                "tier1_prior_applied": attack_id in TIER1_GROUPS,
                "reasoning": " ".join(reasoning_parts),
            }
        )

    # Stable ordering: highest score first, then alphabetical group_id
    candidates.sort(key=lambda c: (-c["score"], c["group_id"]))
    return candidates[:10]


# ---------------------------------------------------------------------------
# Convenience: load + attribute in one call
# ---------------------------------------------------------------------------

_global_mitre: MitreAttackData | None = None


def get_mitre_data(config: dict[str, Any] | None = None) -> MitreAttackData:
    """Get or initialize the global MitreAttackData instance."""
    global _global_mitre
    if _global_mitre is None or not _global_mitre.loaded:
        cfg = config or {}
        stix_path = cfg.get("mitre_stix_path", DEFAULT_STIX_PATH)
        stix_url = cfg.get("mitre_stix_url", DEFAULT_STIX_URL)
        _global_mitre = MitreAttackData(stix_path, stix_url)
        _global_mitre.load()
    return _global_mitre


def attribute_attacker(
    attack_types: list[str],
    osint_data: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Full attribution pipeline:
    1. Compute tags from attack types + OSINT
    2. Map to MITRE techniques
    3. Run APT attribution scoring

    Returns: {tags, mitre_techniques, apt_candidates}
    """
    cfg = config or {}

    tags = compute_tags(attack_types, osint_data)
    techniques = compute_mitre_techniques(attack_types, tags)

    mitre_data = get_mitre_data(cfg)
    apt_candidates = compute_apt_attribution(
        techniques,
        mitre_data,
        max_groups_per_technique=cfg.get("apt_max_groups_per_technique", MAX_GROUPS_PER_TECHNIQUE),
        min_probability=cfg.get("apt_min_probability", MIN_ATTRIBUTION_PROBABILITY),
    )

    return {
        "tags": tags,
        "mitre_techniques": techniques,
        "apt_candidates": apt_candidates,
    }
