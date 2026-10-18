#!/usr/bin/env python3
"""
tools/attack_kb_builder.py — Attack Knowledge Base Generator (Idea 27)
======================================================================
Enumerates all attack types from attack_classifier.py, generates
structured definitions using Claude or Ollama, and stores them in
attack_definitions / attack_rule_definitions / attack_cve_links tables.

Usage:
    python -m tools.attack_kb_builder                    # generate all missing
    python -m tools.attack_kb_builder --type SQLI        # generate one type
    python -m tools.attack_kb_builder --refresh          # regenerate all
    python -m tools.attack_kb_builder --stats            # update sensor stats only
    python -m tools.attack_kb_builder --use-ollama       # force Ollama
    python -m tools.attack_kb_builder --dry-run          # print prompts, no DB write
"""

import argparse
import json
import logging
import os
import re
import time

from honeylens.config import ATTACK_KB, OLLAMA_URL
from honeylens.database import legacy_get_db

logger = logging.getLogger("attack-kb-builder")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def get_conn():
    return legacy_get_db()


# ---------------------------------------------------------------------------
# Enumerate attack types from classifier
# ---------------------------------------------------------------------------


def enumerate_attack_types():
    """Get all attack types with rule counts and sample rule names."""
    from honeylens.classification.attack_classifier import _RULES

    types = {}
    for attack_type, rule_name, _compiled_re in _RULES:
        if attack_type not in types:
            types[attack_type] = {"attack_type": attack_type, "rules": []}
        types[attack_type]["rules"].append(rule_name)

    result = []
    for at in sorted(types.keys()):
        rules = types[at]["rules"]
        result.append(
            {
                "attack_type": at,
                "rule_count": len(rules),
                "sample_rules": rules[:8],
            }
        )
    return result


def fetch_sample_payloads(conn, attack_type, limit=5):
    """Fetch sanitized sample payloads from sensor data for an attack type."""
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT DISTINCT LEFT(se.payload, 200) AS payload_sample
            FROM attack_patterns ap
            JOIN sensor_events se ON ap.event_id = se.event_id
            WHERE ap.attack_type = %s
              AND se.payload IS NOT NULL
              AND LENGTH(se.payload) > 10
            ORDER BY RANDOM()
            LIMIT %s
        """,
            (attack_type, limit),
        )
        rows = cur.fetchall()
        payloads = []
        for r in rows:
            p = r[0]
            if ATTACK_KB.get("sanitize_payloads", True):
                p = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "[IP]", p)
            payloads.append(p)
        return payloads
    except Exception:
        return []


# ---------------------------------------------------------------------------
# LLM Prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a senior cybersecurity analyst writing a comprehensive knowledge base
entry for a Security Operations Centre. Generate a complete technical
definition for the given attack type. Be specific, factual, and thorough.
Respond ONLY with valid JSON — no markdown fences, no commentary."""


def build_type_prompt(attack_type, rule_count, sample_rules, sample_payloads):
    """Build the user prompt for attack type definition generation."""
    rules_str = ", ".join(sample_rules[:8])
    payloads_str = "\n".join(f"  {i + 1}. {p[:150]}" for i, p in enumerate(sample_payloads[:5]))
    if not payloads_str:
        payloads_str = "  (no payloads observed yet)"

    user_prompt = f"""Attack Type: {attack_type}
Current Rules: {rule_count} detection rules
Example Rule Names: {rules_str}
Example Payloads Observed by Sensor:
{payloads_str}

Respond ONLY with valid JSON matching this schema:
{{
    "display_name": "string — full human-readable name",
    "short_description": "string — 1-2 sentence summary",
    "category": "web|network|ics|auth|recon|crypto|supply_chain|dos|iot|ai|cloud|misc",
    "full_description": "string — 3-5 paragraph technical explanation",
    "how_it_works": "string — step-by-step attack mechanism",
    "impact": "string — consequences of successful exploitation",
    "prerequisites": "string — what attacker needs",
    "detection_methods": "string — detection approaches beyond regex",
    "prevention": "string — defensive measures",
    "remediation": "string — incident response steps when detected",
    "default_severity": "critical|high|medium|low|info",
    "owasp_category": "string - e.g. A03:2021 - Injection, or null",
    "owasp_id": "string — e.g. A03, or null",
    "cwe_ids": ["CWE-xxx", ...],
    "capec_ids": ["CAPEC-xxx", ...],
    "mitre_techniques": ["T1xxx", ...],
    "mitre_tactics": ["tactic name", ...],
    "notable_cves": [
        {{"cve": "CVE-xxxx-xxxxx", "name": "common name", "product": "affected product",
         "year": 2024, "impact": "critical|high|medium", "note": "brief description"}},
        ...up to 5
    ],
    "ms_bulletin_ids": ["MSxx-xxx", ...],
    "threat_actors": ["APT group names known to use this"],
    "malware_families": ["malware names using this technique"],
    "target_industries": ["industry names commonly targeted"],
    "tools_used": ["security tools/frameworks used for this attack"],
    "references": [
        {{"title": "reference title", "url": "https://...", "type": "paper|blog|cve|tool|owasp"}},
        ...up to 5
    ]
}}"""
    return SYSTEM_PROMPT, user_prompt


# ---------------------------------------------------------------------------
# LLM Backends
# ---------------------------------------------------------------------------


def generate_via_claude(system, user, model="claude-sonnet-4-6"):
    """Generate definition using Anthropic Claude API."""
    try:
        import anthropic
    except ImportError:
        logger.error("anthropic package not installed: pip install anthropic")
        return None

    try:
        from honeylens.config import ANTHROPIC_API_KEY
    except ImportError:
        ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

    if not ANTHROPIC_API_KEY:
        logger.error("ANTHROPIC_API_KEY not configured")
        return None

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    try:
        resp = client.messages.create(
            model=model,
            max_tokens=8192,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return resp.content[0].text
    except Exception as e:
        logger.error("Claude API error: %s", e)
        return None


def generate_via_ollama(system, user, model="qwen2.5:14b"):
    """Generate definition using local Ollama."""
    import urllib.request

    url = f"{OLLAMA_URL}/api/generate"
    payload = json.dumps(
        {
            "model": model,
            "prompt": user,
            "system": system,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 4096},
        }
    ).encode()

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=120) as resp:  # nosec B310
            data = json.loads(resp.read())
            return data.get("response", "")
    except Exception as e:
        logger.error("Ollama error: %s", e)
        return None


# ---------------------------------------------------------------------------
# JSON Parsing
# ---------------------------------------------------------------------------


def parse_response(raw):
    """Parse LLM JSON response, stripping markdown fences and fixing common issues."""
    if not raw:
        return None
    text = raw.strip()
    # Strip markdown code fences
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        text = "\n".join(lines)
    # Find JSON object
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        text = text[start:end]
    # Fix trailing commas (common LLM issue)
    text = re.sub(r",\s*}", "}", text)
    text = re.sub(r",\s*]", "]", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        logger.error("JSON parse error: %s", e)
        logger.debug("Raw text around error: %s", text[max(0, e.pos - 100) : e.pos + 100])
        return None


REQUIRED_FIELDS = {"display_name", "short_description", "category", "default_severity"}


def validate(data):
    """Validate required fields exist."""
    if not data or not isinstance(data, dict):
        return False
    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        logger.warning("Missing fields: %s", missing)
        return False
    return True


# ---------------------------------------------------------------------------
# Database Storage
# ---------------------------------------------------------------------------


def store_definition(conn, attack_type, data, generated_by, model_name):
    """Insert or update an attack_definitions row."""
    try:
        conn.rollback()
    except Exception as _exc:  # silent: best effort rollback before insert
        logging.getLogger(__name__).debug("ignored: %s", _exc)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO attack_definitions (
            attack_type, display_name, short_description, category,
            full_description, how_it_works, impact, prerequisites,
            detection_methods, prevention, remediation,
            default_severity, owasp_category, owasp_id,
            cwe_id, cwe_ids, capec_ids,
            mitre_techniques, mitre_tactics, mitre_data_sources,
            ms_bulletin_ids, notable_cves,
            threat_actors, malware_families, campaigns, target_industries,
            references_, tools_used,
            generated_by, generated_model, updated_at
        ) VALUES (
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s,
            %s, %s,
            %s, %s, %s, %s,
            %s, %s,
            %s, %s, NOW()
        )
        ON CONFLICT (attack_type) DO UPDATE SET
            display_name = EXCLUDED.display_name,
            short_description = EXCLUDED.short_description,
            category = EXCLUDED.category,
            full_description = EXCLUDED.full_description,
            how_it_works = EXCLUDED.how_it_works,
            impact = EXCLUDED.impact,
            prerequisites = EXCLUDED.prerequisites,
            detection_methods = EXCLUDED.detection_methods,
            prevention = EXCLUDED.prevention,
            remediation = EXCLUDED.remediation,
            default_severity = EXCLUDED.default_severity,
            owasp_category = EXCLUDED.owasp_category,
            owasp_id = EXCLUDED.owasp_id,
            cwe_id = EXCLUDED.cwe_id,
            cwe_ids = EXCLUDED.cwe_ids,
            capec_ids = EXCLUDED.capec_ids,
            mitre_techniques = EXCLUDED.mitre_techniques,
            mitre_tactics = EXCLUDED.mitre_tactics,
            mitre_data_sources = EXCLUDED.mitre_data_sources,
            ms_bulletin_ids = EXCLUDED.ms_bulletin_ids,
            notable_cves = EXCLUDED.notable_cves,
            threat_actors = EXCLUDED.threat_actors,
            malware_families = EXCLUDED.malware_families,
            campaigns = EXCLUDED.campaigns,
            target_industries = EXCLUDED.target_industries,
            references_ = EXCLUDED.references_,
            tools_used = EXCLUDED.tools_used,
            generated_by = EXCLUDED.generated_by,
            generated_model = EXCLUDED.generated_model,
            updated_at = NOW()
    """,
        (
            attack_type,
            data.get("display_name", attack_type),
            data.get("short_description", ""),
            data.get("category"),
            data.get("full_description"),
            data.get("how_it_works"),
            data.get("impact"),
            data.get("prerequisites"),
            data.get("detection_methods"),
            data.get("prevention"),
            data.get("remediation"),
            data.get("default_severity", "medium"),
            data.get("owasp_category"),
            data.get("owasp_id"),
            (data.get("cwe_ids") or [None])[0] if data.get("cwe_ids") else None,
            json.dumps(data.get("cwe_ids")) if data.get("cwe_ids") else None,
            json.dumps(data.get("capec_ids")) if data.get("capec_ids") else None,
            json.dumps(data.get("mitre_techniques")) if data.get("mitre_techniques") else None,
            json.dumps(data.get("mitre_tactics")) if data.get("mitre_tactics") else None,
            None,  # mitre_data_sources
            json.dumps(data.get("ms_bulletin_ids")) if data.get("ms_bulletin_ids") else None,
            json.dumps(data.get("notable_cves")) if data.get("notable_cves") else None,
            json.dumps(data.get("threat_actors")) if data.get("threat_actors") else None,
            json.dumps(data.get("malware_families")) if data.get("malware_families") else None,
            json.dumps(data.get("campaigns")) if data.get("campaigns") else None,
            json.dumps(data.get("target_industries")) if data.get("target_industries") else None,
            json.dumps(data.get("references")) if data.get("references") else None,
            json.dumps(data.get("tools_used")) if data.get("tools_used") else None,
            generated_by,
            model_name,
        ),
    )
    conn.commit()


def store_cve_links(conn, attack_type, notable_cves):
    """Store CVE links from the generated notable_cves list."""
    if not notable_cves:
        return
    cur = conn.cursor()
    for cve in notable_cves:
        if not isinstance(cve, dict) or not cve.get("cve"):
            continue
        cur.execute(
            """
            INSERT INTO attack_cve_links (attack_type, cve_id, cve_name, product, description, link_type)
            VALUES (%s, %s, %s, %s, %s, 'primary')
            ON CONFLICT (attack_type, cve_id) DO UPDATE SET
                cve_name = EXCLUDED.cve_name,
                product = EXCLUDED.product,
                description = EXCLUDED.description
        """,
            (
                attack_type,
                cve["cve"],
                cve.get("name"),
                cve.get("product"),
                cve.get("note"),
            ),
        )
    conn.commit()


# ---------------------------------------------------------------------------
# Sensor Stats
# ---------------------------------------------------------------------------


def update_sensor_stats(conn, attack_type):
    """Update observed_count, unique_ips, first/last seen, trends."""
    cur = conn.cursor()
    try:
        # Basic counts
        cur.execute(
            """
            SELECT COUNT(*), COUNT(DISTINCT se.src_ip),
                   MIN(se.timestamp), MAX(se.timestamp)
            FROM attack_patterns ap
            JOIN sensor_events se ON ap.event_id = se.event_id
            WHERE ap.attack_type = %s
        """,
            (attack_type,),
        )
        row = cur.fetchone()
        if not row or not row[0]:
            return

        total, unique_ips, first_seen, last_seen = row

        # 7-day trend
        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE ap.created_at >= NOW() - INTERVAL '7 days') AS recent,
                COUNT(*) FILTER (WHERE ap.created_at >= NOW() - INTERVAL '14 days'
                                   AND ap.created_at < NOW() - INTERVAL '7 days') AS prev
            FROM attack_patterns ap WHERE ap.attack_type = %s
        """,
            (attack_type,),
        )
        tr = cur.fetchone()
        trend_7d = None
        if tr and tr[1] and tr[1] > 0:
            trend_7d = round(((tr[0] - tr[1]) / tr[1]) * 100, 1)

        # 30-day trend
        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE ap.created_at >= NOW() - INTERVAL '30 days') AS recent,
                COUNT(*) FILTER (WHERE ap.created_at >= NOW() - INTERVAL '60 days'
                                   AND ap.created_at < NOW() - INTERVAL '30 days') AS prev
            FROM attack_patterns ap WHERE ap.attack_type = %s
        """,
            (attack_type,),
        )
        tr30 = cur.fetchone()
        trend_30d = None
        if tr30 and tr30[1] and tr30[1] > 0:
            trend_30d = round(((tr30[0] - tr30[1]) / tr30[1]) * 100, 1)

        cur.execute(
            """
            UPDATE attack_definitions SET
                observed_count = %s, observed_unique_ips = %s,
                first_observed = %s, last_observed = %s,
                trend_7d = %s, trend_30d = %s,
                updated_at = NOW()
            WHERE attack_type = %s
        """,
            (total, unique_ips, first_seen, last_seen, trend_7d, trend_30d, attack_type),
        )
        conn.commit()
    except Exception as e:
        logger.warning("Stats update failed for %s: %s", attack_type, e)
        conn.rollback()


def update_example_payloads(conn, attack_type, limit=5):
    """Fetch and store sanitized example payloads."""
    payloads = fetch_sample_payloads(conn, attack_type, limit)
    if payloads:
        cur = conn.cursor()
        examples = [{"payload": p, "source": "sensor", "sanitized": True} for p in payloads]
        cur.execute(
            """
            UPDATE attack_definitions SET example_payloads = %s, updated_at = NOW()
            WHERE attack_type = %s
        """,
            (json.dumps(examples), attack_type),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Existing definitions check
# ---------------------------------------------------------------------------


def get_existing_types(conn):
    """Return set of attack_types already in the KB."""
    cur = conn.cursor()
    try:
        cur.execute("SELECT attack_type FROM attack_definitions")
        return {r[0] for r in cur.fetchall()}
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Main Builder
# ---------------------------------------------------------------------------


def build_all(args):
    conn = get_conn()

    # Ensure tables exist
    cur = conn.cursor()
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'attack_definitions')"
    )
    if not cur.fetchone()[0]:
        logger.error("Table attack_definitions does not exist. Run: python setup_db.py")
        conn.close()
        return

    attack_types = enumerate_attack_types()
    existing = get_existing_types(conn)

    # Filter
    if args.type:
        attack_types = [t for t in attack_types if t["attack_type"] == args.type.upper()]
        if not attack_types:
            logger.error("Attack type '%s' not found in classifier", args.type)
            conn.close()
            return

    if not args.refresh:
        attack_types = [t for t in attack_types if t["attack_type"] not in existing]

    # Stats-only mode
    if args.stats:
        logger.info("Updating sensor stats for %d types...", len(existing))
        for at in existing:
            update_sensor_stats(conn, at)
            update_example_payloads(conn, at)
            logger.info("  Stats updated: %s", at)
        conn.close()
        return

    if not attack_types:
        logger.info(
            "All %d attack types already in KB. Use --refresh to regenerate.", len(existing)
        )
        conn.close()
        return

    # Determine backend
    use_claude = ATTACK_KB.get("use_claude", True) and not args.use_ollama
    if args.use_claude:
        use_claude = True
    model = args.model or (
        ATTACK_KB.get("claude_model", "claude-sonnet-4-6")
        if use_claude
        else ATTACK_KB.get("ollama_model", "qwen2.5:14b")
    )
    backend = "claude" if use_claude else "ollama"

    logger.info("=" * 60)
    logger.info("  Attack Knowledge Base Builder")
    logger.info("  Backend: %s (%s)", backend, model)
    logger.info("  Types to generate: %d", len(attack_types))
    logger.info("  Mode: %s", "dry-run" if args.dry_run else "live")
    logger.info("=" * 60)

    generated = 0
    failed = 0

    for i, at_info in enumerate(attack_types, 1):
        at = at_info["attack_type"]
        logger.info(
            "[%d/%d] Generating: %s (%d rules)...", i, len(attack_types), at, at_info["rule_count"]
        )

        try:
            payloads = fetch_sample_payloads(conn, at, ATTACK_KB.get("max_example_payloads", 5))
        except Exception:
            payloads = []
            try:
                conn.rollback()
            except Exception as _exc:
                logging.getLogger(__name__).debug("ignored: %s", _exc)
        system, user = build_type_prompt(
            at, at_info["rule_count"], at_info["sample_rules"], payloads
        )

        if args.dry_run:
            logger.info("  [DRY-RUN] Prompt length: %d chars", len(user))
            print(f"\n--- {at} ---\n{user[:500]}...\n")
            continue

        # Generate
        if use_claude:
            raw = generate_via_claude(system, user, model)
        else:
            raw = generate_via_ollama(system, user, model)

        if not raw:
            logger.error("  FAILED: no response from %s", backend)
            failed += 1
            continue

        # Parse
        data = parse_response(raw)
        if not validate(data):
            # Retry once with higher temperature hint
            logger.warning("  Retrying %s...", at)
            if use_claude:
                raw = generate_via_claude(system, user, model)
            else:
                raw = generate_via_ollama(system, user, model)
            data = parse_response(raw)
            if not validate(data):
                logger.error("  FAILED: invalid JSON after retry for %s", at)
                failed += 1
                continue

        # Store
        store_definition(conn, at, data, backend, model)
        store_cve_links(conn, at, data.get("notable_cves", []))

        # Update stats
        if ATTACK_KB.get("include_sensor_stats", True):
            update_sensor_stats(conn, at)
            update_example_payloads(conn, at)

        generated += 1
        logger.info("  OK: %s — %s", at, data.get("display_name", "?"))

        # Rate limit
        if i < len(attack_types):
            time.sleep(1.5 if use_claude else 0.5)

    conn.close()

    logger.info("=" * 60)
    logger.info(
        "  Done. Generated: %d, Failed: %d, Skipped: %d",
        generated,
        failed,
        len(attack_types) - generated - failed,
    )
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# Phase 2 — Rule-Level Enrichment
# ---------------------------------------------------------------------------

RULE_SYSTEM_PROMPT = """You are a detection engineer writing documentation for a security operations team.
For each detection rule, provide a clear description, explain the regex in plain English,
and note when it might produce false positives. Respond ONLY with valid JSON — no markdown fences."""


def build_rules_prompt(attack_type, rules_batch):
    """Build prompt for a batch of rules (up to 25 at once)."""
    rules_text = ""
    for r in rules_batch:
        rules_text += f"\n  - rule_name: {r['rule_name']}\n    regex: {r['pattern'][:200]}\n"

    user_prompt = f"""Attack Type: {attack_type}

Rules to document ({len(rules_batch)} rules):
{rules_text}

For EACH rule, respond with a JSON object. Return a JSON array of objects:
[
  {{
    "rule_name": "exact rule name from above",
    "display_name": "human-friendly name",
    "description": "1-2 sentences: what this rule detects",
    "regex_explanation": "plain English explanation of the regex pattern",
    "true_positive_note": "when this correctly fires (real attack scenario)",
    "false_positive_note": "known false positive scenarios, or 'Low FP rate' if unlikely",
    "tuning_guidance": "how to reduce noise without missing attacks"
  }},
  ...
]"""
    return RULE_SYSTEM_PROMPT, user_prompt


def store_rule_definition(
    conn, rule_name, attack_type, data, severity, is_custom, generated_by, model_name
):
    """Insert or update an attack_rule_definitions row."""
    try:
        conn.rollback()
    except Exception as _exc:  # silent: best effort rollback before insert
        logging.getLogger(__name__).debug("ignored: %s", _exc)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO attack_rule_definitions (
            rule_name, attack_type, display_name, description, severity,
            regex_explanation, true_positive_note, false_positive_note, tuning_guidance,
            is_custom, generated_by, updated_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (rule_name) DO UPDATE SET
            display_name = EXCLUDED.display_name,
            description = EXCLUDED.description,
            regex_explanation = EXCLUDED.regex_explanation,
            true_positive_note = EXCLUDED.true_positive_note,
            false_positive_note = EXCLUDED.false_positive_note,
            tuning_guidance = EXCLUDED.tuning_guidance,
            generated_by = EXCLUDED.generated_by,
            updated_at = NOW()
    """,
        (
            rule_name,
            attack_type,
            data.get("display_name", rule_name),
            data.get("description"),
            severity,
            data.get("regex_explanation"),
            data.get("true_positive_note"),
            data.get("false_positive_note"),
            data.get("tuning_guidance"),
            is_custom,
            generated_by,
        ),
    )
    conn.commit()


def update_rule_hit_stats(conn, rule_name, attack_type):
    """Update hit_count, unique_source_ips, last_hit for a rule."""
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT COUNT(*), COUNT(DISTINCT se.src_ip), MAX(ap.created_at)
            FROM attack_patterns ap
            JOIN sensor_events se ON ap.event_id = se.event_id
            WHERE ap.rule_name = %s AND ap.attack_type = %s
        """,
            (rule_name, attack_type),
        )
        row = cur.fetchone()
        if row and row[0]:
            cur.execute(
                """
                UPDATE attack_rule_definitions
                SET hit_count = %s, unique_source_ips = %s, last_hit = %s, updated_at = NOW()
                WHERE rule_name = %s
            """,
                (row[0], row[1], row[2], rule_name),
            )
            conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception as _exc:  # silent: best effort rollback in error handler
            logging.getLogger(__name__).debug("ignored: %s", _exc)


def build_rules(args):
    """Generate rule-level KB entries for all rules, batched by attack type."""
    conn = get_conn()

    # Check table
    cur = conn.cursor()
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'attack_rule_definitions')"
    )
    if not cur.fetchone()[0]:
        logger.error("Table attack_rule_definitions does not exist. Run: python setup_db.py")
        conn.close()
        return

    from honeylens.classification.attack_classifier import _CUSTOM_RULE_NAMES, _RULES, get_severity

    # Group rules by attack type
    rules_by_type = {}
    for attack_type, rule_name, compiled_re in _RULES:
        if args.type and attack_type != args.type.upper():
            continue
        rules_by_type.setdefault(attack_type, []).append(
            {
                "rule_name": rule_name,
                "attack_type": attack_type,
                "pattern": compiled_re.pattern,
                "severity": get_severity(attack_type, rule_name),
                "is_custom": rule_name in _CUSTOM_RULE_NAMES,
            }
        )

    # Check existing rule definitions
    existing = set()
    if not args.refresh:
        cur.execute("SELECT rule_name FROM attack_rule_definitions")
        existing = {r[0] for r in cur.fetchall()}

    # Only process types that have a KB entry (FK constraint)
    cur.execute("SELECT attack_type FROM attack_definitions")
    kb_types = {r[0] for r in cur.fetchall()}
    skipped_types = set(rules_by_type.keys()) - kb_types
    if skipped_types:
        logger.warning("Skipping types without KB entry: %s", ", ".join(sorted(skipped_types)))
    rules_by_type = {at: rules for at, rules in rules_by_type.items() if at in kb_types}

    # Determine backend
    use_claude = ATTACK_KB.get("use_claude", True) and not args.use_ollama
    if args.use_claude:
        use_claude = True
    model = args.model or (
        ATTACK_KB.get("claude_model", "claude-sonnet-4-6")
        if use_claude
        else ATTACK_KB.get("ollama_model", "qwen2.5:14b")
    )
    backend = "claude" if use_claude else "ollama"

    total_rules = sum(len(v) for v in rules_by_type.values())
    total_new = sum(
        1 for rules in rules_by_type.values() for r in rules if r["rule_name"] not in existing
    )

    if not args.refresh and total_new == 0:
        logger.info("All %d rules already in KB. Use --refresh to regenerate.", total_rules)
        # Still update stats
        if args.stats:
            logger.info("Updating hit stats...")
            for at, rules in rules_by_type.items():
                for r in rules:
                    update_rule_hit_stats(conn, r["rule_name"], at)
            logger.info("Stats updated for %d rules.", total_rules)
        conn.close()
        return

    logger.info("=" * 60)
    logger.info("  Attack KB — Rule-Level Enrichment (Phase 2)")
    logger.info("  Backend: %s (%s)", backend, model)
    logger.info("  Types: %d, Rules: %d (%d new)", len(rules_by_type), total_rules, total_new)
    logger.info("  Mode: %s", "dry-run" if args.dry_run else "live")
    logger.info("=" * 60)

    generated = 0
    failed = 0

    for i, (attack_type, rules) in enumerate(sorted(rules_by_type.items()), 1):
        # Filter already done
        if not args.refresh:
            rules = [r for r in rules if r["rule_name"] not in existing]
        if not rules:
            continue

        # Batch: up to 25 rules per prompt
        for batch_start in range(0, len(rules), 25):
            batch = rules[batch_start : batch_start + 25]
            logger.info(
                "[%d/%d] %s: batch of %d rules (from %d)...",
                i,
                len(rules_by_type),
                attack_type,
                len(batch),
                batch_start,
            )

            system, user = build_rules_prompt(attack_type, batch)

            if args.dry_run:
                logger.info("  [DRY-RUN] Prompt: %d chars, %d rules", len(user), len(batch))
                continue

            # Generate
            if use_claude:
                raw = generate_via_claude(system, user, model)
            else:
                raw = generate_via_ollama(system, user, model)

            if not raw:
                logger.error("  FAILED: no response for %s batch", attack_type)
                failed += len(batch)
                continue

            # Parse — expect JSON array
            parsed = parse_response(raw)

            # Handle both array and single object
            if isinstance(parsed, dict):
                parsed = [parsed]
            if not isinstance(parsed, list):
                # Try wrapping in array
                text = raw.strip()
                if text.startswith("```"):
                    text = "\n".join(
                        ln for ln in text.split("\n") if not ln.strip().startswith("```")
                    )
                start = text.find("[")
                end = text.rfind("]") + 1
                if start >= 0 and end > start:
                    text = text[start:end]
                    text = re.sub(r",\s*}", "}", text)
                    text = re.sub(r",\s*]", "]", text)
                    try:
                        parsed = json.loads(text)
                    except json.JSONDecodeError:
                        logger.error("  FAILED: cannot parse array for %s", attack_type)
                        failed += len(batch)
                        continue
                else:
                    logger.error("  FAILED: no JSON array for %s", attack_type)
                    failed += len(batch)
                    continue

            # Map by rule_name
            result_map = {}
            for item in parsed:
                if isinstance(item, dict) and item.get("rule_name"):
                    result_map[item["rule_name"]] = item

            for r in batch:
                rn = r["rule_name"]
                data = result_map.get(rn, {})
                if not data:
                    # Try fuzzy match
                    for k, v in result_map.items():
                        if k.lower() == rn.lower():
                            data = v
                            break
                if not data.get("description"):
                    data["description"] = f"Detects {r['attack_type']} patterns via regex matching"
                    data["display_name"] = rn.replace("_", " ").title()

                store_rule_definition(
                    conn, rn, r["attack_type"], data, r["severity"], r["is_custom"], backend, model
                )
                update_rule_hit_stats(conn, rn, r["attack_type"])
                generated += 1

            logger.info("  OK: %d/%d rules stored for %s", len(batch), len(batch), attack_type)
            time.sleep(1.5 if use_claude else 0.5)

    conn.close()
    logger.info("=" * 60)
    logger.info("  Done. Rules generated: %d, Failed: %d", generated, failed)
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# Seed Data Import
# ---------------------------------------------------------------------------


def load_seed(args):
    """Load baseline KB from seed SQL file (data/attack_kb_seed.sql)."""
    seed_path = args.seed or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "attack_kb_seed.sql"
    )
    if not os.path.exists(seed_path):
        logger.error("Seed file not found: %s", seed_path)
        return

    conn = get_conn()
    cur = conn.cursor()

    # Check if tables exist
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'attack_definitions')"
    )
    if not cur.fetchone()[0]:
        logger.error("Table attack_definitions does not exist. Run: python setup_db.py")
        conn.close()
        return

    # Check if already populated
    cur.execute("SELECT count(*) FROM attack_definitions")
    existing = cur.fetchone()[0]
    if existing > 0 and not args.refresh:
        logger.info("KB already has %d entries. Use --refresh to overwrite.", existing)
        conn.close()
        return

    # Clear existing if refreshing
    if existing > 0 and args.refresh:
        logger.info("Clearing %d existing KB entries...", existing)
        cur.execute("DELETE FROM attack_cve_links")
        cur.execute("DELETE FROM attack_rule_definitions")
        cur.execute("DELETE FROM attack_definitions")
        conn.commit()

    # Load seed SQL — split on statement boundaries and execute each INSERT
    with open(seed_path) as f:
        content = f.read()

    # Split into individual statements (INSERT ... );)
    statements = re.split(r";\s*\n", content)

    loaded = 0
    errors = 0
    for stmt in statements:
        stmt = stmt.strip()
        if not stmt.upper().startswith("INSERT"):
            continue
        if not stmt.endswith(")"):
            stmt += ")"
        try:
            cur.execute(stmt)
            loaded += 1
        except Exception as e:
            logger.warning("Seed statement error: %s", str(e)[:200])
            conn.rollback()
            errors += 1

    conn.commit()
    cur.execute("SELECT count(*) FROM attack_definitions")
    count = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM attack_cve_links")
    cve_count = cur.fetchone()[0]
    logger.info(
        "Seed loaded: %d definitions, %d CVE links (%d inserts, %d skipped)",
        count,
        cve_count,
        loaded,
        errors,
    )

    conn.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="HoneyLens Attack Knowledge Base Generator (Idea 27)"
    )
    parser.add_argument("--type", help="Generate for a specific attack type only")
    parser.add_argument(
        "--refresh", action="store_true", help="Regenerate all (overwrite existing)"
    )
    parser.add_argument(
        "--rules", action="store_true", help="Generate rule-level descriptions (Phase 2)"
    )
    parser.add_argument("--stats", action="store_true", help="Update sensor stats only (no LLM)")
    parser.add_argument(
        "--load-seed", action="store_true", help="Load baseline KB from seed SQL file"
    )
    parser.add_argument("--seed", help="Path to seed SQL file (default: data/attack_kb_seed.sql)")
    parser.add_argument("--use-claude", action="store_true", help="Force Claude backend")
    parser.add_argument("--use-ollama", action="store_true", help="Force Ollama backend")
    parser.add_argument("--model", help="Override model name")
    parser.add_argument("--dry-run", action="store_true", help="Print prompts without generating")
    args = parser.parse_args()

    if args.load_seed:
        load_seed(args)
    elif args.rules:
        build_rules(args)
    else:
        build_all(args)


if __name__ == "__main__":
    main()
