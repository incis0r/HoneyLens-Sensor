#!/usr/bin/env python3
"""
blog_publisher.py — Threat Intelligence Blog Publisher
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Gathers sensor data for a given attacker IP, generates a BLUF advisory
via Ollama, and pushes it to the external threat blog API.

Usage:
    from blog_publisher import BlogPublisher
    pub = BlogPublisher()
    result = pub.publish(ip="154.0.30.234", trigger="ai_analysis")

CLI:
    python blog_publisher.py --ip 154.0.30.234
    python blog_publisher.py --ip 154.0.30.234 --dry-run
    python blog_publisher.py --ip 154.0.30.234 --trigger manual
"""

import argparse
import json
import logging
import os
import re
import sys
from ipaddress import ip_address, ip_network
from typing import Any

import psycopg2.extras
import requests
from psycopg2 import sql

from honeylens.database import legacy_get_db

try:
    from honeylens.config import OLLAMA_DEEP_MODEL, OLLAMA_URL
except ImportError:
    OLLAMA_URL = "http://127.0.0.1:11434"
    OLLAMA_DEEP_MODEL = "qwen2.5:3b"

# Claude / Anthropic SDK (primary content generator)
try:
    from honeylens.config import ANTHROPIC_API_KEY, ANTHROPIC_DEEP_MODEL

    _HAS_ANTHROPIC_CFG = True
except ImportError:
    ANTHROPIC_API_KEY = ""
    ANTHROPIC_DEEP_MODEL = "claude-sonnet-4-20250514"
    _HAS_ANTHROPIC_CFG = False

try:
    import anthropic as _anthropic_mod

    _HAS_ANTHROPIC = _HAS_ANTHROPIC_CFG and bool(ANTHROPIC_API_KEY)
except ImportError:
    _HAS_ANTHROPIC = False

# Try to import BLOG config; fall back to empty dict
try:
    from honeylens.config import BLOG as BLOG_CFG
except ImportError:
    BLOG_CFG = {}

logger = logging.getLogger("blog_publisher")

# RFC1918 + link-local — never publish these
_PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("169.254.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]

# OPSEC: sensor public IPs that must never appear in published content.
# Attackers send Host: headers containing our IP — these leak through payloads.
# Set via SENSOR_PUBLIC_IPS env var (comma-separated) or hardcode known IPs here.
_SENSOR_PUBLIC_IPS = [
    ip.strip() for ip in os.environ.get("SENSOR_PUBLIC_IPS", "").split(",") if ip.strip()
]

# OPSEC: strip these patterns from any published content
_OPSEC_STRIP_PATTERNS = [
    re.compile(r"honeypot", re.IGNORECASE),
    re.compile(r"honey\s*token", re.IGNORECASE),
    re.compile(r"/opt/sensor", re.IGNORECASE),
    re.compile(r"10\.\d+\.\d+\.\d+"),
    re.compile(r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"),
    re.compile(r"192\.168\.\d+\.\d+"),
] + [re.compile(re.escape(ip)) for ip in _SENSOR_PUBLIC_IPS]


def _is_private_ip(ip_str: str) -> bool:
    """Check if IP is RFC1918/link-local/loopback."""
    try:
        addr = ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True  # invalid = reject


def _is_own_ip(ip_str: str) -> bool:
    """True if the address belongs to this sensor (configured or observed)."""
    return ip_str.strip() in _own_ips()


def _own_ips() -> set:
    """Our own public addresses: configured plus any learned from Host headers.

    SENSOR_PUBLIC_IPS is the intended source, but it is one unset variable away from
    silently publishing our own address — it was unset on DEV when the leak happened.
    A Host header in a request captured BY us names, by construction, an address of
    ours, so payload traffic teaches us the same fact without configuration.
    """
    return set(_SENSOR_PUBLIC_IPS) | _LEARNED_OWN_IPS


_LEARNED_OWN_IPS: set[str] = set()
_HOST_HEADER_RE = re.compile(r"(?im)^\s*Host:\s*((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\s*$")


def _learn_own_ips(text: str) -> None:
    """Record addresses seen in captured Host headers as ours."""
    if not text:
        return
    for m in _HOST_HEADER_RE.finditer(text):
        _LEARNED_OWN_IPS.add(m.group(1))


# Captured credential pairs must never be published. Honeypot payloads carry them in
# the clear on purpose (they link campaigns and expose reused victim credentials), and
# an attacker's password is quite often somebody else's real one.
_CREDENTIAL_RE = re.compile(r"\b(password|passwd|pwd|secretkey|secret)\s*[=:]\s*\S+", re.I)


def _strip_credentials(text: str) -> str:
    return _CREDENTIAL_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", text or "")


def _opsec_sanitise(text: str) -> str:
    """Remove internal details and markdown artifacts from published content."""
    if not text:
        return text
    _learn_own_ips(text)
    for pat in _OPSEC_STRIP_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    # Configured list first, then anything a Host header told us is ours. Done as a
    # literal pass so a newly learned address is stripped in the same call that
    # taught us about it — the leak this fixes was a published payload whose
    # captured request line read "Host: <our own public IP>:6443".
    for own in _own_ips():
        if own:
            text = text.replace(own, "[REDACTED]")
    # Strip markdown formatting that doesn't render in plain text
    text = text.replace("**", "")
    text = re.sub(r"^## ", "", text, flags=re.MULTILINE)
    text = re.sub(r"^# ", "", text, flags=re.MULTILINE)
    return text


def _sanitise_payload(text: str, max_len: int = 200) -> str:
    """
    Sanitise a payload sample for public blog display.
    - Strips internal IPs, paths, honeypot references
    - Truncates to max_len
    - Removes null bytes and control characters
    - Escapes HTML-dangerous characters
    """
    if not text:
        return ""
    # Strip nulls and control chars (except newline/tab)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # OPSEC strip — credentials first, so a truncation can never leave half a
    # password visible on the way out.
    text = _strip_credentials(text)
    text = _opsec_sanitise(text)
    # Truncate
    if len(text) > max_len:
        text = text[:max_len] + " [...]"
    return text.strip()


def _get_db_conn():
    """Open a PostgreSQL connection with RealDictCursor (publisher runs heavy aggregates)."""
    conn = legacy_get_db()
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    with conn.cursor() as cur:
        cur.execute("SET statement_timeout = '120s'")
    conn.commit()
    return conn


def _column_exists(cur, table: str, column: str) -> bool:
    """Check if a column exists in a table (graceful degradation)."""
    cur.execute(
        """
        SELECT 1 FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s
        LIMIT 1
    """,
        (table, column),
    )
    return cur.fetchone() is not None


class BlogPublisher:
    """Gathers sensor data, generates BLUF via Ollama, pushes to blog API."""

    def __init__(self, config: dict | None = None):
        cfg = config or BLOG_CFG
        self.enabled = cfg.get("enabled", False)
        self.blog_url = cfg.get("blog_url", "").rstrip("/")
        self.api_key = cfg.get("api_key", "")
        self.basic_user = cfg.get("basic_user", "sensor")
        self.basic_pass = cfg.get("basic_pass", "")
        # A private origin may use a pinned self-signed certificate. Requests
        # accepts either a boolean or a CA bundle path for ``verify``.
        self.verify_tls = cfg.get("ca_bundle") or cfg.get("verify_tls", True)
        self.timeout = cfg.get("publish_timeout_sec", 30)
        self.ollama_url = cfg.get("ollama_url", OLLAMA_URL)
        self.ollama_model = cfg.get("ollama_model", OLLAMA_DEEP_MODEL)

        # Claude Sonnet (primary) — falls back to Ollama if unavailable
        self.use_claude = _HAS_ANTHROPIC
        self.anthropic_model = cfg.get("anthropic_model", ANTHROPIC_DEEP_MODEL)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish(self, ip: str, trigger: str = "manual", dry_run: bool = False) -> dict[str, Any]:
        """
        Gather all data for IP, generate BLUF via Claude Sonnet (or Ollama fallback),
        push to blog API. Returns dict with status, or error details.
        """
        if not self.enabled and not dry_run:
            return {"status": "disabled", "msg": "Blog publishing is disabled in config"}

        if _is_private_ip(ip):
            return {"status": "rejected", "msg": "RFC1918/private IPs cannot be published"}

        # Never publish a threat profile about our own infrastructure. The text
        # sanitiser cannot save us here: it rewrites the prose but the post's own IP
        # field, its slug and therefore its public URL still name the address. This
        # is how a profile of one of our own sensors came to exist on the live blog
        # (removed 2026-08-13) with a body that had been scrubbed to "[SENSOR-IP]".
        if _is_own_ip(ip):
            logger.warning("blog_publisher: refusing to publish our own address %s", ip)
            return {"status": "rejected", "msg": "Sensor's own public IP cannot be published"}

        # Skip known research scanners
        # 0.9 imported this by the bare name `scanner_exclusions` (which did not exist), and the
        # ImportError was swallowed — the "do not publish known research scanners" gate NEVER worked.
        try:
            from honeylens.intelligence.scanner_exclusions import is_known_scanner as _is_scanner

            if _is_scanner(ip=ip):
                logger.info("blog_publisher: skipping %s — known research scanner", ip)
                return {"status": "skipped", "msg": f"Known research scanner: {ip}"}
        except ImportError as exc:
            logger.debug(
                "scanner_exclusions unavailable, publishing without the scanner gate: %s", exc
            )

        logger.info("blog_publisher: gathering data for %s (trigger=%s)", ip, trigger)

        # 1. Gather sensor data from PostgreSQL
        try:
            data = self._gather_data(ip)
        except Exception as e:
            logger.error("blog_publisher: data gather failed for %s: %s", ip, e)
            return {"status": "error", "msg": f"Data gather failed: {e!s}"}

        if not data.get("event_count"):
            return {"status": "skipped", "msg": f"No events found for IP {ip}"}

        # 2. Generate BLUF + technical content via Ollama
        try:
            content = self._generate_content(ip, data, trigger)
        except Exception as e:
            logger.error("blog_publisher: content generation failed for %s: %s", ip, e)
            # Fall back to template-only content (no AI)
            content = self._fallback_content(ip, data, trigger)

        # 3. OPSEC sanitisation
        content = self._sanitise_content(content)

        if dry_run:
            return {"status": "dry_run", "ip": ip, "content": content, "data": data}

        # 4. Push to blog API
        try:
            result = self._push_to_blog(ip, content)
            logger.info("blog_publisher: published %s — %s", ip, result.get("status"))
            return result
        except Exception as e:
            logger.error("blog_publisher: push failed for %s: %s", ip, e)
            return {"status": "error", "msg": f"Push failed: {e!s}"}

    # Publishing is manual only (operator-triggered from hunting). There is no
    # auto-publish path: `publish()` is called with trigger="manual" by the export
    # route and the CLI, never automatically on a profile save.

    # ------------------------------------------------------------------
    # Data gathering from PostgreSQL
    # ------------------------------------------------------------------

    def _gather_data(self, ip: str) -> dict[str, Any]:
        """Pull all relevant data from local PostgreSQL for the given IP."""
        conn = _get_db_conn()
        try:
            cur = conn.cursor()
            result: dict[str, Any] = {}

            # --- attacker_profiles ---
            # Columns verified against actual schema
            profile_cols = [
                "ip",
                "country",
                "asn",
                "as_org",
                "abuse_score",
                "open_ports",
                "hostname",
                "city",
                "is_vpn",
                "is_noise",
                "os_guess",
                "ai_summary",
                "ai_intent",
                "ai_threat_level",
                "hunt_status",
                "finish_notes",
                "internal_tags",
                "cluster_tags",
                "mitre_techniques",
                "apt_candidates",
                "claude_verdict",
                "claude_summary",
                "claude_technique",
                "claude_cve",
                "claude_threat_actor",
                "total_events",
                "total_attacks",
                "attack_types",
                "first_seen",
                "last_seen",
                "osint_data",
            ]

            cols = sql.SQL(", ").join([sql.Identifier(c) for c in profile_cols])
            query = sql.SQL("SELECT {} FROM attacker_profiles WHERE ip = %s::inet").format(cols)
            cur.execute(query, (ip,))
            profile = cur.fetchone()
            result["profile"] = dict(profile) if profile else {}

            # --- ai_analysis (latest for this IP, joined via sensor_events) ---
            cur.execute(
                """
                SELECT
                    a.event_id,
                    a.triage_class,
                    a.triage_confidence,
                    a.triage_reasoning,
                    a.novelty_score,
                    a.known_cve,
                    a.deep_model,
                    a.deep_analysis,
                    a.zero_day_score,
                    a.suggested_rule_name,
                    a.suggested_mitre,
                    a.claude_verdict,
                    a.claude_confidence,
                    a.claude_attack_type,
                    a.claude_technique,
                    a.claude_tactic,
                    a.claude_cve,
                    a.claude_zero_day_prob,
                    a.claude_threat_actor,
                    a.claude_kill_chain,
                    a.claude_summary,
                    a.claude_iocs,
                    a.claude_recommendations
                FROM ai_analysis a
                JOIN sensor_events se ON se.event_id = a.event_id
                WHERE se.src_ip = %s::inet
                ORDER BY a.timestamp DESC
                LIMIT 1
            """,
                (ip,),
            )
            ai = cur.fetchone()
            result["ai"] = dict(ai) if ai else {}

            # --- sensor_events aggregate ---
            cur.execute(
                """
                SELECT
                    COUNT(*)                                  AS event_count,
                    MIN(timestamp)                            AS first_seen,
                    MAX(timestamp)                            AS last_seen,
                    COUNT(DISTINCT dst_port)                  AS unique_ports,
                    array_agg(DISTINCT dst_port)              AS ports,
                    array_agg(DISTINCT protocol)              AS protocols
                FROM sensor_events
                WHERE src_ip = %s::inet
            """,
                (ip,),
            )
            events = cur.fetchone()
            result["events"] = dict(events) if events else {}
            result["event_count"] = (events or {}).get("event_count", 0)

            # Attack types from attacker_profiles (already aggregated there)
            result["events"]["attack_types"] = result["profile"].get("attack_types") or []

            # --- attack_patterns for this IP (join via sensor_events) ---
            cur.execute(
                """
                SELECT ap.attack_type, ap.rule_name, ap.severity,
                       COUNT(*) AS hit_count
                FROM attack_patterns ap
                JOIN sensor_events se ON se.event_id = ap.event_id
                WHERE se.src_ip = %s::inet
                GROUP BY ap.attack_type, ap.rule_name, ap.severity
                ORDER BY hit_count DESC
                LIMIT 20
            """,
                (ip,),
            )
            result["attack_patterns"] = [dict(r) for r in cur.fetchall()]

            # --- Payload samples (most interesting matched attack strings) ---
            # Grab matched_text from attack_patterns (the regex-matched snippet)
            # plus a few raw payloads from sensor_events for context
            cur.execute(
                """
                SELECT DISTINCT ON (ap.attack_type)
                    ap.attack_type,
                    ap.rule_name,
                    ap.severity,
                    LEFT(ap.matched_text, 300) AS matched_text,
                    LEFT(se.payload, 500) AS raw_payload,
                    se.protocol,
                    se.dst_port
                FROM attack_patterns ap
                JOIN sensor_events se ON se.event_id = ap.event_id
                WHERE se.src_ip = %s::inet
                  AND ap.matched_text IS NOT NULL
                  AND LENGTH(ap.matched_text) > 5
                ORDER BY ap.attack_type, ap.severity DESC, ap.created_at DESC
                LIMIT 15
            """,
                (ip,),
            )
            result["payload_samples"] = [dict(r) for r in cur.fetchall()]

            # --- threat_scores (if table exists) ---
            try:
                cur.execute(
                    """
                    SELECT
                        MAX(ts.score)       AS max_score,
                        MAX(ts.severity)    AS max_severity,
                        COUNT(*)            AS scored_events,
                        SUM(ts.hit_count)   AS total_hits
                    FROM threat_scores ts
                    JOIN sensor_events se ON se.event_id = ts.event_id
                    WHERE se.src_ip = %s::inet
                """,
                    (ip,),
                )
                ts = cur.fetchone()
                result["threat_score"] = dict(ts) if ts else {}
            except Exception:
                result["threat_score"] = {}
                conn.rollback()

            # --- MITRE techniques (from profile + ai_analysis) ---
            mitre: list[str] = []
            # From attacker_profiles (text[] array)
            prof_mitre = result.get("profile", {}).get("mitre_techniques")
            if prof_mitre and isinstance(prof_mitre, list):
                mitre.extend(str(t) for t in prof_mitre if t)
            # From ai_analysis
            ai_mitre = result.get("ai", {}).get("mitre_techniques")
            if ai_mitre:
                if isinstance(ai_mitre, str):
                    mitre.extend(
                        t.strip()
                        for t in ai_mitre.split(",")
                        if t.strip() and t.strip() not in mitre
                    )
                elif isinstance(ai_mitre, list):
                    mitre.extend(str(t) for t in ai_mitre if t and str(t) not in mitre)
            result["mitre"] = mitre

            return result
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Content generation — Claude Sonnet (primary) / Ollama (fallback)
    # ------------------------------------------------------------------

    def _generate_content(self, ip: str, data: dict, trigger: str) -> dict[str, Any]:
        """Generate BLUF + technical advisory via Claude Sonnet, fall back to Ollama."""
        prompt = self._build_prompt(ip, data)

        # Try Claude Sonnet first
        if self.use_claude:
            try:
                raw = self._call_claude(prompt)
                logger.info("blog_publisher: generated content via Claude Sonnet for %s", ip)
                return self._parse_ai_response(raw, ip, data, trigger)
            except Exception as e:
                logger.warning("blog_publisher: Claude call failed: %s — trying Ollama", e)

        # Fallback to Ollama
        try:
            raw = self._call_ollama(prompt)
            logger.info("blog_publisher: generated content via Ollama for %s", ip)
            return self._parse_ai_response(raw, ip, data, trigger)
        except Exception as e:
            logger.warning("blog_publisher: Ollama call failed: %s — using template fallback", e)
            return self._fallback_content(ip, data, trigger)

    def _build_prompt(self, ip: str, data: dict) -> str:
        """Build the shared prompt for both Claude and Ollama."""
        profile = data.get("profile", {})
        ai = data.get("ai", {})
        events = data.get("events", {})
        patterns = data.get("attack_patterns", [])

        # Extract OSINT sub-fields from osint_data JSONB
        osint = profile.get("osint_data") or {}
        if isinstance(osint, str):
            try:
                osint = json.loads(osint)
            except Exception:
                osint = {}

        context_lines = [
            "You are a senior threat intelligence analyst writing a formal advisory",
            "for a public-facing threat intelligence blog.",
            "Write in BLUF (Bottom Line Up Front) format — concise, factual, actionable.",
            "OPSEC: Never reveal internal sensor details, honeypot infrastructure,",
            "detection rule names/regexes, or private/internal IP addresses.",
            "Round timestamps to hour precision in the output.",
            "",
            "=== ATTACKER DATA ===",
            f"IP: {ip}",
            "Country: {} ({})".format(profile.get("country", "??"), profile.get("city", "")),
            "ASN: AS{} ({})".format(profile.get("asn", "?"), profile.get("as_org", "?")),
            "AbuseIPDB score: {}/100".format(profile.get("abuse_score", "N/A")),
            "GreyNoise: {}".format(osint.get("greynoise", {}).get("classification", "N/A")),
            "Reverse DNS: %s" % (profile.get("hostname") or "none"),
            "VPN: %s" % ("Yes" if profile.get("is_vpn") else "No"),
            "OS guess: %s" % (profile.get("os_guess") or "unknown"),
            "Open ports: %s" % (profile.get("open_ports") or "N/A"),
            "",
            "Events: %s" % (profile.get("total_events") or events.get("event_count", 0)),
            "First seen: {}".format(events.get("first_seen", "?")),
            "Last seen: {}".format(events.get("last_seen", "?")),
            "Protocols: {}".format(", ".join(str(p) for p in (events.get("protocols") or []))),
            "Attack types: {}".format(
                ", ".join(str(a) for a in (events.get("attack_types") or []) if a)
            ),
            "Unique destination ports: {}".format(events.get("unique_ports", 0)),
            "",
        ]

        if ai:
            verdict = ai.get("claude_verdict") or ai.get("triage_class") or "N/A"
            confidence = ai.get("claude_confidence") or ai.get("triage_confidence") or "?"
            summary = ai.get("claude_summary") or ai.get("triage_reasoning") or "N/A"
            cve = ai.get("claude_cve") or ai.get("known_cve") or "none"
            zday = ai.get("claude_zero_day_prob") or ai.get("zero_day_score") or "?"
            kill_chain = ai.get("claude_kill_chain") or "?"
            technique = ai.get("claude_technique") or ai.get("suggested_mitre") or "?"
            threat_actor = ai.get("claude_threat_actor") or "unknown"

            context_lines.extend(
                [
                    "=== AI ANALYSIS ===",
                    f"Verdict: {verdict} (confidence {confidence}%)",
                    "Novelty score: {}/10".format(ai.get("novelty_score", "?")),
                    f"Summary: {summary}",
                    f"CVEs: {cve}",
                    f"Zero-day probability: {zday}%",
                    f"Kill chain phase: {kill_chain}",
                    f"MITRE technique: {technique}",
                    f"Threat actor: {threat_actor}",
                    "",
                ]
            )

        if patterns:
            context_lines.append("=== TOP ATTACK PATTERNS ===")
            for p in patterns[:10]:
                context_lines.append(
                    "  - {} / {} [{}] (hits: {})".format(
                        p.get("attack_type", "?"),
                        p.get("rule_name", "?"),
                        p.get("severity", "?"),
                        p.get("hit_count", 0),
                    )
                )
            context_lines.append("")

        # Payload samples for richer threat intel
        payloads = data.get("payload_samples", [])
        if payloads:
            context_lines.append("=== CAPTURED PAYLOAD SAMPLES ===")
            context_lines.append(
                "(Include sanitised examples in the blog post to show what was observed)"
            )
            for ps in payloads[:8]:
                matched = _sanitise_payload(ps.get("matched_text", ""), max_len=200)
                if matched:
                    context_lines.append(
                        "  [{}] {} (port {}/{}):".format(
                            ps.get("severity", "?"),
                            ps.get("attack_type", "?"),
                            ps.get("dst_port", "?"),
                            ps.get("protocol", "?"),
                        )
                    )
                    context_lines.append(f"    {matched}")
            context_lines.append("")

        # Profile AI summary if available
        ai_summary = profile.get("ai_summary")
        if ai_summary:
            context_lines.extend(
                [
                    "=== PROFILER ASSESSMENT ===",
                    ai_summary[:500],
                    "",
                ]
            )

        prompt = "\n".join(context_lines) + (
            "\n\nGenerate a threat advisory with these exact section labels:\n"
            "BLUF:\n"
            "(2-3 sentences: what happened, assessed threat level, recommended action)\n\n"
            "TECHNICAL:\n"
            "(Key findings: protocols, techniques, attack volumes, MITRE mappings, IOCs)\n\n"
            "RECOMMENDATIONS:\n"
            "(3-5 actionable items for network defenders, one per line starting with •)\n"
        )
        return prompt

    def _call_claude(self, prompt: str) -> str:
        """Call Anthropic Claude Sonnet API and return raw text response."""
        client: Any = _anthropic_mod.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model=self.anthropic_model,
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
        )
        # Extract text from response content blocks
        parts = []
        for block in message.content:
            if hasattr(block, "text"):
                parts.append(block.text)
        return "\n".join(parts)

    def _call_ollama(self, prompt: str) -> str:
        """Call local Ollama API and return raw text response."""
        resp = requests.post(
            f"{self.ollama_url}/api/generate",
            json={
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": 600},
            },
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")

    def _parse_ai_response(self, raw: str, ip: str, data: dict, trigger: str) -> dict[str, Any]:
        """Parse AI response (Claude or Ollama) into structured content dict."""
        profile = data.get("profile", {})
        ai = data.get("ai", {})
        events = data.get("events", {})

        bluf = ""
        technical = ""
        recommendations: list[str] = []

        # Split by section labels
        sections = re.split(r"(?:BLUF|TECHNICAL|RECOMMENDATIONS)\s*:\s*", raw, flags=re.IGNORECASE)
        # sections[0] = preamble (discard), [1] = bluf, [2] = technical, [3] = recommendations
        if len(sections) >= 2:
            bluf = sections[1].strip()
        if len(sections) >= 3:
            technical = sections[2].strip()
        if len(sections) >= 4:
            rec_text = sections[3].strip()
            recommendations = [
                line.lstrip("•-* ").strip()
                for line in rec_text.splitlines()
                if line.strip() and not line.strip().startswith("RECOMMENDATION")
            ]

        if not bluf:
            _verdict = ai.get("claude_verdict") or ai.get("triage_class") or "UNKNOWN"
            bluf = "Activity detected from {} — {} events, AI verdict: {}.".format(
                ip,
                events.get("event_count", "?"),
                _verdict,
            )

        # Determine threat level
        threat_level = self._determine_threat_level(data)

        # Build tags
        tags = self._build_tags(data)

        # Build IOCs
        iocs = {"ip": ip}
        asn = profile.get("asn")
        if asn:
            iocs["asn"] = str(asn)
        country = profile.get("country")
        if country:
            iocs["country"] = country

        # Current assessment block
        _ai_verdict = ai.get("claude_verdict") or ai.get("triage_class")
        _ai_conf = ai.get("claude_confidence") or ai.get("triage_confidence")
        current_assessment = {
            "threat_level": threat_level,
            "country": profile.get("country", "??"),
            "asn": str(profile.get("asn", "?")),
            "asn_org": profile.get("as_org", "?"),
            "abuse_score": profile.get("abuse_score"),
            "event_count": events.get("event_count", 0),
            "protocols": [str(p) for p in (events.get("protocols") or []) if p],
            "tags": tags,
            "ai_verdict": _ai_verdict,
            "confidence": _ai_conf,
        }

        return {
            "threat_level": threat_level,
            "bluf": bluf,
            "technical": technical,
            "recommendations": recommendations,
            "payload_samples": self._build_payload_section(data),
            "iocs": iocs,
            "mitre": data.get("mitre", []),
            "tags": tags,
            "trigger": trigger,
            "current_assessment": current_assessment,
        }

    def _fallback_content(self, ip: str, data: dict, trigger: str) -> dict[str, Any]:
        """Generate content without Ollama — template-based fallback."""
        profile = data.get("profile", {})
        ai = data.get("ai", {})
        events = data.get("events", {})
        patterns = data.get("attack_patterns", [])

        threat_level = self._determine_threat_level(data)
        tags = self._build_tags(data)

        protocols = [str(p) for p in (events.get("protocols") or []) if p]
        attack_types = [str(a) for a in (events.get("attack_types") or []) if a]

        _verdict = ai.get("claude_verdict") or ai.get("triage_class") or "UNKNOWN"

        bluf = (
            "Malicious activity detected from {} ({}, AS{}). "
            "{} events observed across {}. "
            "AI verdict: {}.".format(
                ip,
                profile.get("country", "??"),
                profile.get("asn", "?"),
                events.get("event_count", 0),
                ", ".join(protocols[:5]) if protocols else "multiple protocols",
                _verdict,
            )
        )

        tech_lines = []
        if protocols:
            tech_lines.append("Protocols: {}".format(", ".join(protocols)))
        if attack_types:
            tech_lines.append("Attack types: {}".format(", ".join(attack_types[:10])))
        if events.get("unique_ports"):
            tech_lines.append("Unique destination ports: {}".format(events["unique_ports"]))
        if events.get("first_seen") and events.get("last_seen"):
            tech_lines.append(
                "Active window: {} to {}".format(events["first_seen"], events["last_seen"])
            )
        if patterns:
            tech_lines.append(
                "Top patterns: {}".format(", ".join(p.get("rule_name", "?") for p in patterns[:5]))
            )
        _cve = ai.get("claude_cve") or ai.get("known_cve")
        if _cve:
            # Enrich CVE with CIRCL intelligence (Idea 32 Phase E)
            try:
                from honeylens.intelligence.circl_enricher import enrich_cve

                cve_detail = enrich_cve(_cve)
                if cve_detail:
                    score = cve_detail.get("cvss_score", "?")
                    sev = cve_detail.get("cvss_severity", "")
                    title = cve_detail.get("title", "")[:100]
                    kev = " [CISA KEV — actively exploited]" if cve_detail.get("is_kev") else ""
                    tech_lines.append(f"CVE: {_cve} (CVSS {score} {sev}){kev}")
                    if title:
                        tech_lines.append(f"  {title}")
                    cwes = cve_detail.get("cwe", [])
                    if cwes:
                        tech_lines.append("  Weaknesses: {}".format(", ".join(cwes)))
                else:
                    tech_lines.append(f"Associated CVEs: {_cve}")
            except ImportError:
                tech_lines.append(f"Associated CVEs: {_cve}")

        recommendations = [f"Block {ip} at perimeter firewall"]
        if profile.get("asn"):
            recommendations.append("Monitor other traffic from AS{}".format(profile["asn"]))
        if _verdict in ("CRITICAL", "HIGH"):
            recommendations.append("Escalate to incident response team")
        recommendations.append("Review correlated attacker profiles for campaign links")

        iocs = {"ip": ip}
        if profile.get("asn"):
            iocs["asn"] = str(profile["asn"])
        if profile.get("country"):
            iocs["country"] = profile["country"]

        _ai_conf = ai.get("claude_confidence") or ai.get("triage_confidence")
        current_assessment = {
            "threat_level": threat_level,
            "country": profile.get("country", "??"),
            "asn": str(profile.get("asn", "?")),
            "asn_org": profile.get("as_org", "?"),
            "abuse_score": profile.get("abuse_score"),
            "event_count": events.get("event_count", 0),
            "protocols": protocols,
            "tags": tags,
            "ai_verdict": _verdict,
            "confidence": _ai_conf,
        }

        return {
            "threat_level": threat_level,
            "bluf": bluf,
            "technical": "\n".join(tech_lines),
            "recommendations": recommendations,
            "payload_samples": self._build_payload_section(data),
            "iocs": iocs,
            "mitre": data.get("mitre", []),
            "tags": tags,
            "trigger": trigger,
            "current_assessment": current_assessment,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_payload_section(self, data: dict) -> list[dict[str, str]]:
        """
        Build sanitised payload samples for blog display.
        Returns list of dicts: {attack_type, severity, protocol, port, payload}
        """
        samples = data.get("payload_samples", [])
        if not samples:
            return []

        result = []
        seen: set = set()

        for ps in samples[:10]:
            matched = ps.get("matched_text") or ""
            raw = ps.get("raw_payload") or ""

            # Prefer matched_text (the specific attack string), fall back to raw payload
            display = matched if matched else raw
            if not display:
                continue

            # Sanitise for public display
            display = _sanitise_payload(display, max_len=250)
            if not display or len(display) < 6:
                continue

            # Deduplicate similar payloads
            sig = display[:60]
            if sig in seen:
                continue
            seen.add(sig)

            result.append(
                {
                    "attack_type": ps.get("attack_type", "UNKNOWN"),
                    "severity": ps.get("severity", "medium"),
                    "protocol": ps.get("protocol", "?"),
                    "port": str(ps.get("dst_port", "?")),
                    "payload": display,
                }
            )

        return result

    def _determine_threat_level(self, data: dict) -> str:
        """Determine threat level from AI verdict + event volume."""
        ai = data.get("ai", {})
        # Best verdict from ai_analysis: Claude verdict > triage class
        ai_verdict = (ai.get("claude_verdict") or ai.get("triage_class") or "").upper()
        event_count = data.get("events", {}).get("event_count", 0)
        profile = data.get("profile", {})
        profile_claude = (profile.get("claude_verdict") or "").upper()
        profile_threat = (profile.get("ai_threat_level") or "").upper()

        # Use strongest signal
        if "CRITICAL" in (ai_verdict, profile_claude, profile_threat):
            return "CRITICAL"
        if "HIGH" in (ai_verdict, profile_claude, profile_threat):
            return "HIGH"
        if ai_verdict == "SUSPICIOUS" or profile_claude == "SUSPICIOUS":
            if event_count > 10000:
                return "HIGH"
            return "MEDIUM"
        if event_count > 50000:
            return "HIGH"
        if event_count > 5000:
            return "MEDIUM"
        return "LOW"

    def _build_tags(self, data: dict) -> list[str]:
        """Build tag list from profile + patterns."""
        tags: list[str] = []
        profile = data.get("profile", {})

        # Tags from attacker_profiles
        profile_tags = profile.get("internal_tags") or profile.get("cluster_tags") or []
        if isinstance(profile_tags, str) and profile_tags:
            tags.extend(t.strip() for t in profile_tags.split(",") if t.strip())
        elif isinstance(profile_tags, list):
            tags.extend(str(t) for t in profile_tags if t)

        # Also add cluster_tags if internal_tags was used above
        cluster = profile.get("cluster_tags") or []
        if isinstance(cluster, list):
            for t in cluster:
                if t and str(t) not in tags:
                    tags.append(str(t))

        # Tags from attack patterns (top categories)
        for p in data.get("attack_patterns", [])[:5]:
            cat = p.get("attack_type", "")
            if cat and cat not in tags:
                tags.append(cat)

        return list(dict.fromkeys(tags))  # dedupe, preserve order

    def _sanitise_content(self, content: dict) -> dict:
        """Apply OPSEC sanitisation to all string fields."""
        for key in ("bluf", "technical"):
            if key in content and isinstance(content[key], str):
                content[key] = _opsec_sanitise(content[key])
        if "recommendations" in content:
            content["recommendations"] = [_opsec_sanitise(r) for r in content["recommendations"]]
        # Payload samples are already sanitised by _sanitise_payload,
        # but run OPSEC strip again as a safety net
        if "payload_samples" in content:
            for ps in content["payload_samples"]:
                if "payload" in ps:
                    ps["payload"] = _opsec_sanitise(ps["payload"])
        return content

    # ------------------------------------------------------------------
    # Push to blog API
    # ------------------------------------------------------------------

    def _push_to_blog(self, ip: str, content: dict) -> dict[str, Any]:
        """POST to blog API with triple auth (IP whitelist checked server-side)."""
        payload = {
            "ip": ip,
            "threat_level": content["threat_level"],
            "bluf": content["bluf"],
            "technical": content.get("technical", ""),
            "recommendations": content.get("recommendations", []),
            "payload_samples": content.get("payload_samples", []),
            "iocs": content.get("iocs", {}),
            "mitre": content.get("mitre", []),
            "tags": content.get("tags", []),
            "trigger": content.get("trigger", "unknown"),
            "current_assessment": content.get("current_assessment", {}),
        }

        url = f"{self.blog_url}/api/post"

        response = requests.post(
            url,
            json=payload,
            headers={
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
            },
            auth=(self.basic_user, self.basic_pass),
            verify=self.verify_tls,
            timeout=self.timeout,
        )

        if response.status_code == 200 or response.status_code == 201:
            return response.json()
        else:
            return {
                "status": "error",
                "http_code": response.status_code,
                "msg": response.text[:500],
            }


# ------------------------------------------------------------------
# CLI entrypoint
# ------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Publish threat advisory to blog")
    parser.add_argument("--ip", required=True, help="Attacker IP to publish")
    parser.add_argument(
        "--trigger", default="manual", help="Trigger source (manual|ai_analysis|attacker_profiler)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Gather data and generate content but do not push"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    pub = BlogPublisher()

    if args.dry_run:
        pub.enabled = True  # override for dry run

    result = pub.publish(ip=args.ip, trigger=args.trigger, dry_run=args.dry_run)

    if args.dry_run and result.get("status") == "dry_run":
        print("\n=== DRY RUN — Content that would be published ===\n")
        content = result.get("content", {})
        print("Threat Level: {}".format(content.get("threat_level", "?")))
        print("Tags: {}".format(", ".join(content.get("tags", []))))
        print("MITRE: {}".format(", ".join(content.get("mitre", []))))
        print("\nBLUF:\n{}".format(content.get("bluf", "")))
        print("\nTechnical:\n{}".format(content.get("technical", "")))
        print("\nRecommendations:")
        for r in content.get("recommendations", []):
            print(f"  - {r}")
        print("\nIOCs: {}".format(json.dumps(content.get("iocs", {}), indent=2)))
        print(
            "\nCurrent Assessment: {}".format(
                json.dumps(content.get("current_assessment", {}), indent=2)
            )
        )
    else:
        print(json.dumps(result, indent=2, default=str))

    sys.exit(0 if result.get("status") in ("created", "updated", "dry_run") else 1)


if __name__ == "__main__":
    main()
