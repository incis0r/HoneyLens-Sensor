#!/usr/bin/env python3
"""
ai_analyzer.py — AI Event Analysis Daemon (Phase 1: Local Ollama)
==================================================================
Polls the sensor database for unanalysed events, sends them to a local
Ollama instance for triage classification, and stores results.

Phase 1: Ollama only — fully air-gapped, zero cost, no data leaves network.
Phase 2 (future): Anthropic Claude integration for deep analysis.

Usage:
    python ai_analyzer.py                    # Run daemon
    python ai_analyzer.py --once             # Process one batch and exit
    python ai_analyzer.py --dry-run          # Show what would be analysed
    python ai_analyzer.py --stats            # Show analysis statistics
    python ai_analyzer.py --reanalyze        # Re-triage all events
    python ai_analyzer.py --event <id>       # Analyse a specific event
    python ai_analyzer.py --test-ollama      # Test Ollama connectivity

Requires: Ollama running at http://localhost:11434
Platform: Rocky Linux 9 / RHEL 9
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import signal
import sys
import time
from contextlib import contextmanager
from typing import Any

import httpx
import psycopg2.extras

from honeylens.analysis.ai_prompts import build_deep_prompt, build_triage_prompt
from honeylens.analysis.cve_normalize import normalize_cve
from honeylens.analysis.triage_guard import apply_triage_guard
from honeylens.config import (
    AI_ANALYSIS_ENABLED,
    AI_BATCH_SIZE,
    AI_CYCLE_INTERVAL,
    AI_TRIAGE_MIN_SEVERITY,
    OLLAMA_DEEP_MODEL,
    OLLAMA_TIMEOUT,
    OLLAMA_TRIAGE_MODEL,
    OLLAMA_URL,
)
from honeylens.database import legacy_get_db

# ---------------------------------------------------------------------------
# Configuration — import from config.py or use defaults
# ---------------------------------------------------------------------------
from honeylens.env import env

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FILE = env("AI_ANALYZER_LOG_FILE", "/var/log/sensor_ai_analyzer.log")

logger = logging.getLogger("honeylens.ai_analyzer")


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    """Check if event severity meets the minimum threshold."""
    return SEVERITY_ORDER.get(severity.upper(), 0) >= SEVERITY_ORDER.get(threshold.upper(), 0)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def get_db():
    return legacy_get_db()


@contextmanager
def _db_conn():
    """Lease a pooled connection and ALWAYS return it to the pool.

    The borrow sites below used ``conn = get_db() … conn.close()`` with no try/finally, and the
    pool is replenished ONLY by ``conn.close()`` (the lease's context-manager does transaction
    commit/rollback, not pool-return). So any exception between the borrow and the close — a DB
    hiccup, or an LLM-backend error while a connection was held open — leaked the lease; after
    ~maxconn leaks the per-process pool was exhausted and every cycle failed
    ``connection pool exhausted``. Using this guarantees the return even on an exception.
    """
    conn = get_db()
    try:
        yield conn
    finally:
        conn.close()


def ensure_ai_tables():
    """Create AI analysis tables if they don't exist."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_analysis (
            id                  BIGSERIAL PRIMARY KEY,
            event_id            VARCHAR(64) NOT NULL,
            timestamp           TIMESTAMPTZ DEFAULT NOW(),
            -- Triage (Ollama)
            triage_model        VARCHAR(64),
            triage_class        VARCHAR(32),
            triage_confidence   INTEGER,
            triage_reasoning    TEXT,
            novelty_score       INTEGER,
            known_cve           VARCHAR(32),
            triage_iocs         JSONB,
            triage_duration_ms  INTEGER,
            triage_raw          JSONB,
            -- Deep analysis (Ollama or Claude)
            deep_model          VARCHAR(64),
            deep_analysis       JSONB,
            zero_day_score      INTEGER,
            suggested_rule_name TEXT,
            suggested_rule_regex TEXT,
            suggested_mitre     TEXT,
            attack_chain_id     VARCHAR(64),
            -- Analyst review
            analyst_reviewed    BOOLEAN DEFAULT FALSE,
            analyst_verdict     VARCHAR(32),
            analyst_notes       TEXT,
            -- Cost tracking (Phase 2)
            tokens_in           INTEGER DEFAULT 0,
            tokens_out          INTEGER DEFAULT 0,
            cost_usd            NUMERIC(8,6) DEFAULT 0,
            UNIQUE(event_id)
        );

        -- Migration: widen columns if upgrading from earlier schema
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'ai_analysis' AND column_name = 'suggested_mitre'
                         AND data_type = 'character varying' AND character_maximum_length < 64)
            THEN
                ALTER TABLE ai_analysis ALTER COLUMN suggested_mitre TYPE TEXT;
                RAISE NOTICE 'Widened ai_analysis.suggested_mitre to TEXT';
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns
                       WHERE table_name = 'ai_analysis' AND column_name = 'triage_class'
                         AND character_maximum_length < 32)
            THEN
                ALTER TABLE ai_analysis ALTER COLUMN triage_class TYPE VARCHAR(32);
                RAISE NOTICE 'Widened ai_analysis.triage_class to VARCHAR(32)';
            END IF;
        END $$;

        CREATE INDEX IF NOT EXISTS idx_ai_analysis_class
            ON ai_analysis(triage_class);
        CREATE INDEX IF NOT EXISTS idx_ai_analysis_novelty
            ON ai_analysis(novelty_score DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_analysis_timestamp
            ON ai_analysis(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_analysis_zeroday
            ON ai_analysis(zero_day_score DESC)
            WHERE zero_day_score IS NOT NULL;
    """)

    conn.commit()
    conn.close()
    logger.info("AI analysis tables verified/created")


def fetch_unanalysed_events(limit: int = 10, min_severity: str = "MEDIUM") -> list[dict]:
    """Fetch events that haven't been analysed yet."""
    with _db_conn() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        [s for s, v in SEVERITY_ORDER.items() if v >= SEVERITY_ORDER.get(min_severity.upper(), 0)]

        cur.execute(
            """
            SELECT se.event_id, se.timestamp, se.protocol, se.src_ip::text,
                   se.src_port, se.dst_ip::text, se.dst_port,
                   se.payload, se.attack_types, se.scan_score
            FROM sensor_events se
            LEFT JOIN ai_analysis aa ON aa.event_id = se.event_id
            WHERE aa.event_id IS NULL
              AND se.attack_types IS NOT NULL
              AND se.attack_types != ''
              AND se.source != 'suricata'
              AND se.suricata_sid IS NULL
            ORDER BY se.timestamp DESC
            LIMIT %s
        """,
            (limit,),
        )

        events = [dict(row) for row in cur.fetchall()]

    # Post-filter by severity from attack_types
    filtered = []
    for ev in events:
        atk = ev.get("attack_types") or ""
        # Estimate severity from attack types
        if any(h in atk.upper() for h in ["CRITICAL", "RCE", "0DAY"]):
            ev["severity"] = "CRITICAL"
        elif any(
            h in atk.upper()
            for h in ["HIGH", "SQLI", "XSS", "LFI", "LOG4J", "DESERIALIZATION", "SMB", "ICS_ATTACK"]
        ):
            ev["severity"] = "HIGH"
        elif any(h in atk.upper() for h in ["MEDIUM", "SCANNER", "AUTH", "SSRF", "SSTI"]):
            ev["severity"] = "MEDIUM"
        else:
            ev["severity"] = "LOW"

        if severity_meets_threshold(ev["severity"], min_severity):
            filtered.append(ev)

    return filtered[:limit]


def fetch_related_events(src_ip: str, exclude_id: str, limit: int = 10) -> list[dict]:
    """Fetch recent events from the same source IP."""
    if not src_ip:
        return []
    with _db_conn() as conn:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            """
            SELECT event_id, timestamp, protocol, dst_port, attack_types,
                   LEFT(payload, 200) AS payload
            FROM sensor_events
            WHERE src_ip = %s::inet AND event_id != %s
            ORDER BY timestamp DESC LIMIT %s
        """,
            (src_ip, exclude_id, limit),
        )
        events = [dict(row) for row in cur.fetchall()]
    return events


def store_triage_result(event_id: str, model: str, result: dict, duration_ms: int):
    """Store triage classification result."""
    with _db_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO ai_analysis (
                event_id, triage_model, triage_class, triage_confidence,
                triage_reasoning, novelty_score, known_cve, triage_iocs,
                triage_duration_ms, triage_raw
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_id) DO UPDATE SET
                triage_model = EXCLUDED.triage_model,
                triage_class = EXCLUDED.triage_class,
                triage_confidence = EXCLUDED.triage_confidence,
                triage_reasoning = EXCLUDED.triage_reasoning,
                novelty_score = EXCLUDED.novelty_score,
                known_cve = EXCLUDED.known_cve,
                triage_iocs = EXCLUDED.triage_iocs,
                triage_duration_ms = EXCLUDED.triage_duration_ms,
                triage_raw = EXCLUDED.triage_raw,
                timestamp = NOW()
        """,
            (
                event_id,
                model,
                result.get("classification", "NOISE"),
                result.get("confidence", 0),
                result.get("reasoning", ""),
                result.get("novelty_score", 0),
                normalize_cve(result.get("known_cve")),
                json.dumps(result.get("iocs", [])),
                duration_ms,
                json.dumps(result),
            ),
        )
        conn.commit()


def store_deep_result(event_id: str, model: str, result: dict):
    """Store deep analysis result (updates existing triage row)."""
    with _db_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE ai_analysis SET
                deep_model = %s,
                deep_analysis = %s,
                zero_day_score = %s,
                suggested_rule_name = %s,
                suggested_rule_regex = %s,
                suggested_mitre = %s
            WHERE event_id = %s
        """,
            (
                model,
                json.dumps(result),
                result.get("zero_day_probability", 0),
                result.get("suggested_rule_name"),
                result.get("suggested_rule_regex"),
                result.get("mitre_technique"),
                event_id,
            ),
        )
        conn.commit()


def get_stats() -> dict:
    """Get analysis statistics."""
    with _db_conn() as conn:
        cur = conn.cursor()

        stats = {}

        # Check if table exists
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_name = 'ai_analysis'
            )
        """)
        if not cur.fetchone()[0]:
            return {"error": "ai_analysis table does not exist"}

        cur.execute("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE triage_class = 'NOISE') AS noise,
                COUNT(*) FILTER (WHERE triage_class = 'KNOWN') AS known,
                COUNT(*) FILTER (WHERE triage_class = 'SUSPICIOUS') AS suspicious,
                COUNT(*) FILTER (WHERE triage_class = 'CRITICAL') AS critical,
                AVG(novelty_score) FILTER (WHERE novelty_score IS NOT NULL) AS avg_novelty,
                MAX(novelty_score) AS max_novelty,
                COUNT(*) FILTER (WHERE zero_day_score >= 70) AS zero_day_candidates,
                COUNT(*) FILTER (WHERE deep_analysis IS NOT NULL) AS deep_analysed,
                COUNT(*) FILTER (WHERE analyst_reviewed) AS reviewed,
                AVG(triage_duration_ms) AS avg_triage_ms,
                COUNT(*) FILTER (WHERE suggested_rule_regex IS NOT NULL) AS suggested_rules,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') AS last_24h,
                COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour') AS last_1h
            FROM ai_analysis
        """)
        row = cur.fetchone()
        stats = {
            "total_analysed": row[0],
            "by_class": {
                "NOISE": row[1],
                "KNOWN": row[2],
                "SUSPICIOUS": row[3],
                "CRITICAL": row[4],
            },
            "avg_novelty": round(float(row[5]), 1) if row[5] else 0,
            "max_novelty": row[6] or 0,
            "zero_day_candidates": row[7],
            "deep_analysed": row[8],
            "analyst_reviewed": row[9],
            "avg_triage_ms": round(float(row[10])) if row[10] else 0,
            "suggested_rules": row[11],
            "last_24h": row[12],
            "last_1h": row[13],
        }

        # Pending analysis
        cur.execute("""
            SELECT COUNT(*) FROM sensor_events se
            LEFT JOIN ai_analysis aa ON aa.event_id = se.event_id
            WHERE aa.event_id IS NULL
              AND se.attack_types IS NOT NULL AND se.attack_types != ''
        """)
        stats["pending"] = cur.fetchone()[0]

        # Recent interesting findings
        cur.execute("""
            SELECT event_id, triage_class, novelty_score, triage_reasoning,
                   known_cve, zero_day_score
            FROM ai_analysis
            WHERE triage_class IN ('SUSPICIOUS', 'CRITICAL')
            ORDER BY timestamp DESC LIMIT 5
        """)
        stats["recent_findings"] = [
            {
                "event_id": r[0],
                "class": r[1],
                "novelty": r[2],
                "reasoning": r[3],
                "cve": r[4],
                "zero_day_score": r[5],
            }
            for r in cur.fetchall()
        ]

    return stats


# ---------------------------------------------------------------------------
# Ollama Client
# ---------------------------------------------------------------------------


class OllamaClient:
    """HTTP client for the Ollama REST API."""

    def __init__(self, base_url: str = OLLAMA_URL, timeout: int = OLLAMA_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def is_available(self) -> bool:
        """Check if Ollama is reachable and running."""
        try:
            resp = self._get_client().get(f"{self.base_url}/api/tags")
            return resp.status_code == 200
        except Exception:
            return False  # silent: connectivity check, failure is expected

    def list_models(self) -> list[str]:
        """list available models."""
        try:
            resp = self._get_client().get(f"{self.base_url}/api/tags")
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []  # silent: model listing, Ollama may be unavailable

    def has_model(self, model: str) -> bool:
        """Check if a specific model is available."""
        models = self.list_models()
        # Match both exact and partial (e.g. "llama3.1:8b" matches "llama3.1:8b")
        return any(model in m or m.startswith(model.split(":")[0]) for m in models)

    def generate(
        self, model: str, system: str, prompt: str, temperature: float = 0.1
    ) -> tuple[str, int, int]:
        """
        Send a generation request to Ollama.
        Returns: (response_text, tokens_in, tokens_out)
        """
        payload = {
            "model": model,
            "system": system,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": 4096,
            },
        }

        resp = self._get_client().post(
            f"{self.base_url}/api/generate",
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

        response_text = data.get("response", "")
        tokens_in = data.get("prompt_eval_count", 0)
        tokens_out = data.get("eval_count", 0)

        return response_text, tokens_in, tokens_out

    def close(self):
        if self._client:
            self._client.close()
            self._client = None


# ---------------------------------------------------------------------------
# JSON response parser (resilient)
# ---------------------------------------------------------------------------


def parse_json_response(text: str) -> dict:
    """Parse JSON from LLM response, handling common issues."""
    if not text:
        return {}

    # Strip markdown code fences
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass  # silent: AI response not valid JSON, try regex fallback

    # Try to find JSON object in the text
    match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass  # silent: JSON regex extract also failed, return raw text

    # Last resort: extract key fields with regex
    result = {}
    for key in [
        "classification",
        "confidence",
        "reasoning",
        "known_cve",
        "novelty_score",
        "attack_technique",
    ]:
        m = re.search(rf'"{key}"\s*:\s*"?([^",\n}}]+)"?', text)
        if m:
            val = m.group(1).strip().strip('"')
            if key in ("confidence", "novelty_score"):
                try:
                    val = int(val)
                except ValueError:
                    val = 0
            result[key] = val

    return result


# ---------------------------------------------------------------------------
# Analysis Engine
# ---------------------------------------------------------------------------


class AnalysisEngine:
    """Main analysis engine — orchestrates triage and deep analysis.

    Optional `deep_backend` (an OpenAIBackendEngine / ClaudeBackendEngine)
    enables a hybrid mode: Ollama runs triage locally, but deep analysis
    is delegated to a cloud backend. Set via `AI_DEEP_BACKEND=openai` (or
    `=claude`) in the env. Useful when the local Ollama deep model is
    weaker than the cloud option but triage is cheap enough to keep local.
    """

    def __init__(self, ollama: OllamaClient, deep_backend=None):
        self.ollama = ollama
        self.triage_model = OLLAMA_TRIAGE_MODEL
        self.deep_backend = deep_backend
        # If a hybrid deep backend is wired, advertise *its* model so logs
        # and the dashboard report what's actually doing the deep work.
        self.deep_model = deep_backend.deep_model if deep_backend else OLLAMA_DEEP_MODEL
        self.stats: dict[str, Any] = {
            "triaged": 0,
            "deep": 0,
            "errors": 0,
            "by_class": {"NOISE": 0, "KNOWN": 0, "SUSPICIOUS": 0, "CRITICAL": 0},
        }

    def triage_event(self, event: dict) -> dict:
        """Run triage classification on a single event."""
        system, prompt = build_triage_prompt(event)

        t0 = time.time()
        try:
            response, _tok_in, _tok_out = self.ollama.generate(
                self.triage_model,
                system,
                prompt,
            )
        except Exception as e:
            logger.error("Ollama triage failed for %s: %s", event.get("event_id", "?"), e)
            self.stats["errors"] += 1
            return {
                "classification": "NOISE",
                "confidence": 0,
                "reasoning": f"Ollama error: {e}",
                "novelty_score": 0,
            }

        duration_ms = int((time.time() - t0) * 1000)

        result = parse_json_response(response)
        if not result.get("classification"):
            result["classification"] = "NOISE"
        result["classification"] = result["classification"].upper()
        if result["classification"] not in ("NOISE", "KNOWN", "SUSPICIOUS", "CRITICAL"):
            result["classification"] = "NOISE"

        # Deterministic guard: routine honeypot protocol traffic (e.g. an SMTP
        # EHLO greeting or the AUTH LOGIN credential capture the honeypot exists
        # to record) must not surface as a high-novelty 0-day candidate.
        apply_triage_guard(event, result)

        # Store
        store_triage_result(event["event_id"], self.triage_model, result, duration_ms)

        cls = result["classification"]
        self.stats["triaged"] += 1
        self.stats["by_class"][cls] = self.stats["by_class"].get(cls, 0) + 1

        novelty = result.get("novelty_score", 0)
        logger.info(
            "Triaged %s → %s (confidence=%d, novelty=%d, %dms) %s",
            event["event_id"][:12],
            cls,
            result.get("confidence", 0),
            novelty,
            duration_ms,
            result.get("reasoning", "")[:80],
        )

        return result

    def deep_analyze(self, event: dict, triage: dict) -> dict:
        """Run deep analysis on a suspicious/critical event.

        Delegates to `self.deep_backend` if one was wired in __init__ —
        that's how the Ollama-triage + cloud-deep hybrid works. Otherwise
        runs deep on Ollama locally.
        """
        if self.deep_backend is not None:
            try:
                result = self.deep_backend.deep_analyze(event, triage)
                self.stats["deep"] += 1
                return result
            except Exception as e:
                logger.error("Hybrid deep backend failed for %s: %s", event.get("event_id", "?"), e)
                self.stats["errors"] += 1
                return {}

        related = fetch_related_events(
            event.get("src_ip") or "",
            event.get("event_id", ""),
            limit=10,
        )
        system, prompt = build_deep_prompt(
            event,
            {
                "triage_class": triage.get("classification", "SUSPICIOUS"),
                "triage_reasoning": triage.get("reasoning", ""),
                "novelty_score": triage.get("novelty_score", 0),
            },
            related,
        )

        try:
            response, _tok_in, _tok_out = self.ollama.generate(
                self.deep_model,
                system,
                prompt,
                temperature=0.05,  # Very low for analytical precision
            )
        except Exception as e:
            logger.error("Ollama deep analysis failed for %s: %s", event.get("event_id", "?"), e)
            self.stats["errors"] += 1
            return {}

        result = parse_json_response(response)
        if result:
            store_deep_result(event["event_id"], self.deep_model, result)
            self.stats["deep"] += 1

            zday = result.get("zero_day_probability", 0)
            if zday >= 70:
                logger.warning(
                    "🚨 HIGH 0-DAY PROBABILITY (%d%%) for event %s: %s",
                    zday,
                    event["event_id"][:12],
                    result.get("summary", "")[:120],
                )

            logger.info(
                "Deep analysis %s → 0day=%d%%, rule=%s",
                event["event_id"][:12],
                zday,
                result.get("suggested_rule_name", "none"),
            )

        return result

    def process_batch(self, events: list[dict], do_deep: bool = True):
        """Process a batch of events: triage all, deep-analyse interesting ones."""
        for event in events:
            triage = self.triage_event(event)

            # Deep-analyse SUSPICIOUS/CRITICAL events with high novelty
            if do_deep and triage.get("classification") in ("SUSPICIOUS", "CRITICAL"):
                novelty = triage.get("novelty_score", 0)
                if novelty >= 5:
                    logger.info(
                        "Escalating %s to deep analysis (novelty=%d)",
                        event["event_id"][:12],
                        novelty,
                    )
                    self.deep_analyze(event, triage)


# ---------------------------------------------------------------------------
# Claude backend — used on sensors without a local Ollama instance.
# Mirrors AnalysisEngine's interface so run_daemon / process_batch don't care
# which backend is in use. Internally routes to analysis.claude_analyzer,
# which talks to Anthropic's API using ANTHROPIC_TRIAGE_MODEL (Haiku) for
# triage and ANTHROPIC_DEEP_MODEL (Sonnet) for deep.
#
# Verdict translation (Claude → daemon):
#   MALICIOUS  → CRITICAL    (escalates severity for the deep-trigger gate)
#   SUSPICIOUS → SUSPICIOUS
#   KNOWN      → KNOWN
#   UNKNOWN/anything else → NOISE
# ---------------------------------------------------------------------------

_VERDICT_TO_CLASS = {
    # Severity-style verdicts (what Haiku/Sonnet actually return for this prompt)
    "CRITICAL": "CRITICAL",
    "HIGH": "SUSPICIOUS",
    "MEDIUM": "KNOWN",
    "LOW": "NOISE",
    # Classification-style verdicts (kept for forward-compat / alternate prompts)
    "MALICIOUS": "CRITICAL",
    "SUSPICIOUS": "SUSPICIOUS",
    "KNOWN": "KNOWN",
    "UNKNOWN": "NOISE",
}
_VERDICT_TO_NOVELTY = {
    "CRITICAL": 8,
    "HIGH": 6,
    "MEDIUM": 3,
    "LOW": 0,
    "MALICIOUS": 8,
    "SUSPICIOUS": 6,
    "KNOWN": 2,
    "UNKNOWN": 0,
}


class ClaudeBackendEngine:
    """Claude-backed analysis engine. Drop-in replacement for AnalysisEngine.

    Optional `deep_backend` (an OpenAIBackendEngine) enables a hybrid:
    Claude runs triage, deep analysis is delegated to OpenAI. Used on
    sensors that don't have Ollama but want OpenAI-class deep without
    paying Sonnet rates. Set via `AI_DEEP_BACKEND=openai`.
    """

    def __init__(self, deep_backend=None):
        # Lazy import so DEV-style installs without anthropic SDK still work.
        from honeylens.analysis import claude_analyzer

        self._ca = claude_analyzer
        self.triage_model = claude_analyzer.ANTHROPIC_TRIAGE_MODEL
        self.deep_backend = deep_backend
        # If a hybrid deep backend is wired, advertise *its* model name.
        self.deep_model = (
            deep_backend.deep_model if deep_backend else claude_analyzer.ANTHROPIC_DEEP_MODEL
        )
        self.stats: dict[str, Any] = {
            "triaged": 0,
            "deep": 0,
            "errors": 0,
            "skipped": 0,
            "by_class": {"NOISE": 0, "KNOWN": 0, "SUSPICIOUS": 0, "CRITICAL": 0},
        }

    def triage_event(self, event: dict) -> dict:
        event_id = event["event_id"]
        try:
            raw = self._ca.triage_event(event_id, store=True)
        except Exception as e:
            logger.error("Claude triage failed for %s: %s", event_id[:12], e)
            self.stats["errors"] += 1
            return {
                "classification": "NOISE",
                "confidence": 0,
                "reasoning": f"Claude error: {e}",
                "novelty_score": 0,
            }

        if raw.get("error"):
            # Budget exceeded / API failure / non-JSON — treat as noise so the
            # daemon doesn't get stuck retrying.
            logger.warning("Claude triage error for %s: %s", event_id[:12], raw.get("error"))
            self.stats["errors"] += 1
            return {
                "classification": "NOISE",
                "confidence": 0,
                "reasoning": raw.get("error", "")[:200],
                "novelty_score": 0,
            }

        if raw.get("skip_ai"):
            # Suricata already classified — claude_analyzer short-circuits and
            # returns a synthetic KNOWN. Don't count as a triage; don't bill.
            self.stats["skipped"] += 1
            return {
                "classification": "KNOWN",
                "confidence": 100,
                "reasoning": raw.get("reasoning", "Classified by Suricata"),
                "novelty_score": 0,
                "_skipped": True,
            }

        verdict = (raw.get("verdict") or "UNKNOWN").upper()
        classification = _VERDICT_TO_CLASS.get(verdict, "NOISE")

        result = {
            "classification": classification,
            "confidence": raw.get("confidence", 0) or 0,
            "reasoning": raw.get("reasoning", "")[:500],
            "novelty_score": raw.get("novelty_score", _VERDICT_TO_NOVELTY.get(verdict, 0)),
            "known_cve": raw.get("known_cve"),
            "_claude_raw": raw,
        }

        self.stats["triaged"] += 1
        self.stats["by_class"][classification] = self.stats["by_class"].get(classification, 0) + 1

        meta = raw.get("_meta") or {}
        logger.info(
            "Triaged %s → %s (verdict=%s, %dms, %d+%d tok)",
            event_id[:12],
            classification,
            verdict,
            meta.get("elapsed_ms", 0),
            meta.get("input_tokens", 0),
            meta.get("output_tokens", 0),
        )
        return result

    def deep_analyze(self, event: dict, triage: dict) -> dict:
        # Hybrid override: delegate deep to the configured cloud backend
        # (typically OpenAI gpt-5-mini) while triage keeps using Claude.
        if self.deep_backend is not None:
            try:
                raw = self.deep_backend.deep_analyze(event, triage)
                self.stats["deep"] += 1
                return raw
            except Exception as e:
                logger.error("Hybrid deep backend failed for %s: %s", event["event_id"][:12], e)
                self.stats["errors"] += 1
                return {}

        event_id = event["event_id"]
        try:
            raw = self._ca.analyze_event(event_id, store=True)
        except Exception as e:
            logger.error("Claude deep failed for %s: %s", event_id[:12], e)
            self.stats["errors"] += 1
            return {}

        if raw.get("error"):
            logger.warning("Claude deep error for %s: %s", event_id[:12], raw.get("error"))
            return {}

        self.stats["deep"] += 1
        zday = raw.get("zero_day_probability", 0) or 0
        if zday >= 70:
            logger.warning(
                "🚨 HIGH 0-DAY PROBABILITY (%d%%) for event %s: %s",
                zday,
                event_id[:12],
                (raw.get("summary") or "")[:120],
            )

        logger.info(
            "Deep analysis %s → 0day=%d%%, rule=%s",
            event_id[:12],
            zday,
            (raw.get("suggested_rule") or {}).get("rule_name", "none"),
        )
        return raw

    def process_batch(self, events: list[dict], do_deep: bool = True):
        for event in events:
            triage = self.triage_event(event)
            if triage.get("_skipped"):
                continue
            if do_deep and triage.get("classification") in ("SUSPICIOUS", "CRITICAL"):
                novelty = triage.get("novelty_score", 0)
                if novelty >= 5:
                    logger.info(
                        "Escalating %s to deep analysis (novelty=%d)",
                        event["event_id"][:12],
                        novelty,
                    )
                    self.deep_analyze(event, triage)


class OpenAIBackendEngine:
    """OpenAI-backed analysis engine. Drop-in replacement for AnalysisEngine.

    Mirrors ClaudeBackendEngine; dispatches to analysis.openai_analyzer
    instead of analysis.claude_analyzer. All result-storage / hunting-list /
    budget-tracking flows reuse claude_analyzer's infrastructure.
    """

    def __init__(self):
        from honeylens.analysis import openai_analyzer

        self._oa = openai_analyzer
        self.triage_model = openai_analyzer.OPENAI_TRIAGE_MODEL
        self.deep_model = openai_analyzer.OPENAI_DEEP_MODEL
        self.stats: dict[str, Any] = {
            "triaged": 0,
            "deep": 0,
            "errors": 0,
            "skipped": 0,
            "by_class": {"NOISE": 0, "KNOWN": 0, "SUSPICIOUS": 0, "CRITICAL": 0},
        }

    def triage_event(self, event: dict) -> dict:
        event_id = event["event_id"]
        try:
            raw = self._oa.triage_event(event_id, store=True)
        except Exception as e:
            logger.error("OpenAI triage failed for %s: %s", event_id[:12], e)
            self.stats["errors"] += 1
            return {
                "classification": "NOISE",
                "confidence": 0,
                "reasoning": f"OpenAI error: {e}",
                "novelty_score": 0,
            }

        if raw.get("error"):
            logger.warning("OpenAI triage error for %s: %s", event_id[:12], raw.get("error"))
            self.stats["errors"] += 1
            return {
                "classification": "NOISE",
                "confidence": 0,
                "reasoning": raw.get("error", "")[:200],
                "novelty_score": 0,
            }

        if raw.get("skip_ai"):
            self.stats["skipped"] += 1
            return {
                "classification": "KNOWN",
                "confidence": 100,
                "reasoning": raw.get("reasoning", "Classified by Suricata"),
                "novelty_score": 0,
                "_skipped": True,
            }

        verdict = (raw.get("verdict") or "UNKNOWN").upper()
        classification = _VERDICT_TO_CLASS.get(verdict, "NOISE")

        result = {
            "classification": classification,
            "confidence": raw.get("confidence", 0) or 0,
            "reasoning": raw.get("reasoning", "")[:500],
            "novelty_score": raw.get("novelty_score", _VERDICT_TO_NOVELTY.get(verdict, 0)),
            "known_cve": raw.get("known_cve"),
            "_openai_raw": raw,
        }

        self.stats["triaged"] += 1
        self.stats["by_class"][classification] = self.stats["by_class"].get(classification, 0) + 1

        meta = raw.get("_meta") or {}
        logger.info(
            "Triaged %s → %s (verdict=%s, %dms, %d+%d tok)",
            event_id[:12],
            classification,
            verdict,
            meta.get("elapsed_ms", 0),
            meta.get("input_tokens", 0),
            meta.get("output_tokens", 0),
        )
        return result

    def deep_analyze(self, event: dict, triage: dict) -> dict:
        event_id = event["event_id"]
        try:
            raw = self._oa.analyze_event(event_id, store=True)
        except Exception as e:
            logger.error("OpenAI deep failed for %s: %s", event_id[:12], e)
            self.stats["errors"] += 1
            return {}

        if raw.get("error"):
            logger.warning("OpenAI deep error for %s: %s", event_id[:12], raw.get("error"))
            return {}

        self.stats["deep"] += 1
        zday = raw.get("zero_day_probability", 0) or 0
        if zday >= 70:
            logger.warning(
                "HIGH 0-DAY PROBABILITY (%d%%) for event %s: %s",
                zday,
                event_id[:12],
                (raw.get("summary") or "")[:120],
            )

        logger.info(
            "Deep analysis %s → 0day=%d%%, rule=%s",
            event_id[:12],
            zday,
            (raw.get("suggested_rule") or {}).get("rule_name", "none"),
        )
        return raw

    def process_batch(self, events: list[dict], do_deep: bool = True):
        for event in events:
            triage = self.triage_event(event)
            if triage.get("_skipped"):
                continue
            if do_deep and triage.get("classification") in ("SUSPICIOUS", "CRITICAL"):
                novelty = triage.get("novelty_score", 0)
                if novelty >= 5:
                    logger.info(
                        "Escalating %s to deep analysis (novelty=%d)",
                        event["event_id"][:12],
                        novelty,
                    )
                    self.deep_analyze(event, triage)


def _build_engine():
    """Pick the analysis backend.

    Order of preference:
      1. Ollama (local, free) — when reachable. May optionally delegate
         *deep analysis* to a cloud backend if `AI_DEEP_BACKEND` is set to
         "openai" or "claude" — triage still runs locally on Ollama.
      2. OpenAI — when OPENAI_API_KEY is set
      3. Anthropic Claude — when ANTHROPIC_API_KEY is set

    `AI_FORCE_CLOUD=true` skips the local Ollama for the analyzer and goes straight
    to the cloud primary (both triage and deep) — for hosts where local inference is
    too slow or memory-starved. The local Ollama stays up for other consumers (e.g.
    the LLM honeypot).

    Returns (engine, backend_name) or (None, None) on hard failure.
    """
    force_cloud = env("AI_FORCE_CLOUD", "").strip().lower() in ("1", "true", "yes", "on")
    ollama = OllamaClient()
    if force_cloud:
        logger.info("AI_FORCE_CLOUD set — analyzer skips local Ollama, using the cloud backend")
    if ollama.is_available() and not force_cloud:
        logger.info("Ollama reachable at %s — using local backend", OLLAMA_URL)
        if not ollama.has_model(OLLAMA_TRIAGE_MODEL):
            logger.warning(
                "Triage model '%s' not pulled — ollama pull %s",
                OLLAMA_TRIAGE_MODEL,
                OLLAMA_TRIAGE_MODEL,
            )

        # Hybrid: keep Ollama for triage, override deep with a cloud backend.
        deep_override = env("AI_DEEP_BACKEND", "").strip().lower()
        deep_backend: OpenAIBackendEngine | ClaudeBackendEngine | None = None
        backend_tag = "ollama"
        # AI_DEEP_BACKEND=openai uses the OpenAI-compatible engine, which talks to Nous when
        # AI_PROVIDER=nous — so in that case the key to look for is NOUS_API_KEY, not
        # OPENAI_API_KEY. Without this, "Ollama triage + Nous deep" silently fell back to the
        # local deep model (which the triage-only Ollama host does not have pulled).
        _ollama_ai_provider = env("AI_PROVIDER", "openai").strip().lower()
        _openai_deep_key = env(
            "NOUS_API_KEY" if _ollama_ai_provider == "nous" else "OPENAI_API_KEY", ""
        ).strip()
        if deep_override == "openai" and _openai_deep_key:
            try:
                deep_backend = OpenAIBackendEngine()
                backend_tag = f"ollama+openai-deep({deep_backend.deep_model})"
                logger.info(
                    "Hybrid mode: Ollama triage + OpenAI deep (%s)", deep_backend.deep_model
                )
            except Exception as e:
                logger.warning("OpenAI-deep init failed, full Ollama: %s", e)
        elif deep_override == "claude" and env("ANTHROPIC_API_KEY", "").strip():
            try:
                deep_backend = ClaudeBackendEngine()
                backend_tag = f"ollama+claude-deep({deep_backend.deep_model})"
                logger.info(
                    "Hybrid mode: Ollama triage + Claude deep (%s)", deep_backend.deep_model
                )
            except Exception as e:
                logger.warning("Claude-deep init failed, full Ollama: %s", e)
        return AnalysisEngine(ollama, deep_backend=deep_backend), backend_tag

    # Without Ollama: pick the cloud primary. When BOTH keys are configured
    # AND the operator explicitly requests `AI_DEEP_BACKEND=openai`, prefer
    # Claude for triage — that is the only configuration in which the
    # AI_DEEP_BACKEND override has any effect (otherwise OpenAI would
    # already be running deep).
    ai_provider = env("AI_PROVIDER", "openai").strip().lower()
    openai_key = (
        env("NOUS_API_KEY", "").strip()
        if ai_provider == "nous"
        else env("OPENAI_API_KEY", "").strip()
    )
    anthropic_key = env("ANTHROPIC_API_KEY", "").strip()
    deep_override = env("AI_DEEP_BACKEND", "").strip().lower()
    prefer_claude_triage = deep_override == "openai" and openai_key and anthropic_key

    if openai_key and not prefer_claude_triage:
        logger.info("Ollama unreachable at %s — using %s backend", OLLAMA_URL, ai_provider)
        try:
            engine: OpenAIBackendEngine | ClaudeBackendEngine = OpenAIBackendEngine()
            logger.info(
                "OpenAI backend ready — triage=%s, deep=%s", engine.triage_model, engine.deep_model
            )
            return engine, ai_provider
        except ImportError as e:
            logger.error("%s backend selected but unavailable: %s", ai_provider, e)
            logger.error("Install the project with the 'openai' extra")
            # fall through to Claude

    api_key = anthropic_key
    if api_key:
        logger.info("Ollama unreachable at %s — falling back to Claude backend", OLLAMA_URL)
        try:
            # Hybrid: Claude triage + cloud deep when AI_DEEP_BACKEND=openai
            deep_backend = None
            backend_tag = "claude"
            deep_override = env("AI_DEEP_BACKEND", "").strip().lower()
            if deep_override == "openai" and env("OPENAI_API_KEY", "").strip():
                try:
                    deep_backend = OpenAIBackendEngine()
                    backend_tag = f"claude+openai-deep({deep_backend.deep_model})"
                    logger.info(
                        "Hybrid mode: Claude triage + OpenAI deep (%s)", deep_backend.deep_model
                    )
                except Exception as e:
                    logger.warning("OpenAI-deep init failed, full Claude: %s", e)
            engine = ClaudeBackendEngine(deep_backend=deep_backend)
            logger.info(
                "Backend ready — triage=%s, deep=%s", engine.triage_model, engine.deep_model
            )
            return engine, backend_tag
        except ImportError as e:
            logger.error("Claude backend selected but unavailable: %s", e)
            logger.error("Install: pip install anthropic")
            return None, None

    logger.error(
        "No backend available: Ollama unreachable at %s and ANTHROPIC_API_KEY not set", OLLAMA_URL
    )
    logger.error(
        "Install Ollama (curl -fsSL https://ollama.com/install.sh|sh) "
        "OR set ANTHROPIC_API_KEY in /opt/sensor/.env"
    )
    return None, None


# ---------------------------------------------------------------------------
# Main daemon loop
# ---------------------------------------------------------------------------


def run_daemon(engine: AnalysisEngine, batch_size: int, interval: int, min_severity: str):
    """Main daemon loop — poll DB, triage, sleep, repeat."""
    running = True

    def _stop(signum, frame):
        nonlocal running
        running = False
        logger.info("Shutdown signal received")

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    logger.info("═══════════════════════════════════════════════════")
    logger.info("  AI Analyzer daemon started")
    logger.info("  Triage model:  %s", engine.triage_model)
    logger.info("  Deep model:    %s", engine.deep_model)
    logger.info("  Batch size:    %d", batch_size)
    logger.info("  Interval:      %ds", interval)
    logger.info("  Min severity:  %s", min_severity)
    logger.info("═══════════════════════════════════════════════════")

    cycle = 0
    while running:
        cycle += 1
        try:
            events = fetch_unanalysed_events(batch_size, min_severity)
            if events:
                logger.info("Cycle %d: processing %d events", cycle, len(events))
                engine.process_batch(events)
                logger.info(
                    "Cycle %d: done — triaged=%d, deep=%d, errors=%d",
                    cycle,
                    engine.stats["triaged"],
                    engine.stats["deep"],
                    engine.stats["errors"],
                )
            else:
                logger.debug("Cycle %d: no pending events", cycle)
        except Exception as e:
            logger.error("Cycle %d error: %s", cycle, e)

        # Sleep in small increments for responsive shutdown
        for _ in range(interval):
            if not running:
                break
            time.sleep(1)

    logger.info(
        "AI Analyzer stopped. Total: triaged=%d, deep=%d, errors=%d",
        engine.stats["triaged"],
        engine.stats["deep"],
        engine.stats["errors"],
    )


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


def cmd_run(args):
    """Run the daemon."""
    engine, backend = _build_engine()
    if engine is None:
        return 1

    ensure_ai_tables()
    logger.info("Backend selected: %s", backend)

    if args.once:
        events = fetch_unanalysed_events(args.batch_size or AI_BATCH_SIZE, AI_TRIAGE_MIN_SEVERITY)
        if events:
            engine.process_batch(events)
            logger.info("Processed %d events (backend=%s)", len(events), backend)
        else:
            logger.info("No pending events")
        return 0

    run_daemon(
        engine,
        args.batch_size or AI_BATCH_SIZE,
        args.interval or AI_CYCLE_INTERVAL,
        AI_TRIAGE_MIN_SEVERITY,
    )
    if backend == "ollama":
        engine.ollama.close()
    return 0


def cmd_event(args):
    """Analyse a specific event by ID."""
    ollama = OllamaClient()
    if not ollama.is_available():
        logger.error("Ollama not reachable at %s", OLLAMA_URL)
        return 1

    ensure_ai_tables()

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT event_id, timestamp, protocol, src_ip::text, src_port,
               dst_ip::text, dst_port, payload, attack_types, scan_score
        FROM sensor_events WHERE event_id = %s
    """,
        (args.event_id,),
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        print(f"Event {args.event_id} not found")
        return 1

    event = dict(row)
    event["severity"] = "HIGH"  # Force analysis

    engine = AnalysisEngine(ollama)
    print(f"\nTriaging event {event['event_id'][:16]}...")
    triage = engine.triage_event(event)
    print(f"  Classification: {triage.get('classification')}")
    print(f"  Confidence:     {triage.get('confidence')}%")
    print(f"  Novelty:        {triage.get('novelty_score')}/10")
    print(f"  Reasoning:      {triage.get('reasoning')}")
    if triage.get("known_cve"):
        print(f"  CVE:            {triage['known_cve']}")

    if triage.get("classification") in ("SUSPICIOUS", "CRITICAL"):
        print("\nRunning deep analysis...")
        deep = engine.deep_analyze(event, triage)
        if deep:
            print(f"  0-day score:    {deep.get('zero_day_probability', 0)}%")
            print(f"  Exploit type:   {deep.get('exploit_type', '?')}")
            print(f"  Objective:      {deep.get('attack_objective', '?')}")
            print(f"  Suggested rule: {deep.get('suggested_rule_name', 'none')}")
            if deep.get("summary"):
                print(f"  Summary:        {deep['summary']}")

    ollama.close()
    return 0


def cmd_stats(args):
    """Show analysis statistics."""
    try:
        ensure_ai_tables()
    except Exception as e:
        logger.debug("Could not ensure AI tables for stats: %s", e)

    stats = get_stats()
    if "error" in stats:
        print(f"  {stats['error']}")
        return 1

    print("\n  AI Analysis Statistics")
    print(f"  {'─' * 50}")
    print(f"  Total analysed:     {stats['total_analysed']:,}")
    print(f"  Last 24h:           {stats['last_24h']:,}")
    print(f"  Last 1h:            {stats['last_1h']:,}")
    print(f"  Pending:            {stats['pending']:,}")
    print(f"  Avg triage time:    {stats['avg_triage_ms']}ms")
    print("")
    print("  By classification:")
    for cls, count in stats["by_class"].items():
        print(f"    {cls:<12s}  {count:,}")
    print("")
    print(f"  Avg novelty score:  {stats['avg_novelty']}")
    print(f"  Max novelty score:  {stats['max_novelty']}")
    print(f"  0-day candidates:   {stats['zero_day_candidates']}")
    print(f"  Deep analysed:      {stats['deep_analysed']}")
    print(f"  Suggested rules:    {stats['suggested_rules']}")
    print(f"  Analyst reviewed:   {stats['analyst_reviewed']}")

    if stats.get("recent_findings"):
        print("\n  Recent findings:")
        for f in stats["recent_findings"]:
            zday = f"  0day={f['zero_day_score']}%" if f.get("zero_day_score") else ""
            print(
                f"    [{f['class']}] {f['event_id'][:12]}  "
                f"novelty={f['novelty']}{zday}  {f['reasoning'][:60]}"
            )

    print()
    return 0


def cmd_test_ollama(args):
    """Test Ollama connectivity and model availability."""
    print(f"\n  Testing Ollama at {OLLAMA_URL}...")

    ollama = OllamaClient()
    if not ollama.is_available():
        print("  ✘ Ollama not reachable")
        print("    Install: curl -fsSL https://ollama.com/install.sh | sh")
        return 1

    print("  ✔ Ollama is running")

    models = ollama.list_models()
    print(f"  Available models: {models}")

    for model_name, label in [(OLLAMA_TRIAGE_MODEL, "triage"), (OLLAMA_DEEP_MODEL, "deep")]:
        if ollama.has_model(model_name):
            print(f"  ✔ {label} model '{model_name}' available")
        else:
            print(f"  ✘ {label} model '{model_name}' NOT found")
            print(f"    Pull with: ollama pull {model_name}")

    # Quick test generation
    print(f"\n  Running test generation with {OLLAMA_TRIAGE_MODEL}...")
    try:
        t0 = time.time()
        resp, tok_in, tok_out = ollama.generate(
            OLLAMA_TRIAGE_MODEL,
            "You are a test assistant. Respond with only valid JSON.",
            'Respond with: {"status": "ok", "model": "working"}',
        )
        dur = time.time() - t0
        result = parse_json_response(resp)
        print(f"  ✔ Generation OK ({dur:.1f}s, {tok_in}+{tok_out} tokens)")
        print(f"    Response: {result}")
    except Exception as e:
        print(f"  ✘ Generation failed: {e}")

    ollama.close()
    return 0


def cmd_dry_run(args):
    """Show what would be analysed without actually doing it."""
    try:
        ensure_ai_tables()
    except Exception as e:
        logger.debug("Could not ensure AI tables for dry-run: %s", e)

    events = fetch_unanalysed_events(args.batch_size or AI_BATCH_SIZE, AI_TRIAGE_MIN_SEVERITY)
    print(f"\n  Dry run — {len(events)} events would be analysed:")
    print(f"  {'─' * 70}")
    for ev in events:
        ts = str(ev.get("timestamp", ""))[:19]
        proto = ev.get("protocol", "?")
        port = ev.get("dst_port", "?")
        atk = (ev.get("attack_types") or "")[:40]
        eid = ev["event_id"][:12]
        print(f"  {eid}  [{ts}]  {proto}:{port}  {atk}")
    print()
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    from honeylens.logging_setup import setup_logging

    setup_logging(log_file=LOG_FILE)
    parser = argparse.ArgumentParser(
        description="AI Event Analysis Daemon — Phase 1: Local Ollama",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python %(prog)s                     # Run daemon
  python %(prog)s --once              # Process one batch
  python %(prog)s --stats             # Show statistics
  python %(prog)s --event abc123      # Analyse specific event
  python %(prog)s --test-ollama       # Test Ollama connectivity
  python %(prog)s --dry-run           # Preview pending events
        """,
    )
    parser.add_argument("--once", action="store_true", help="Process one batch and exit")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be analysed")
    parser.add_argument("--stats", action="store_true", help="Show analysis statistics")
    parser.add_argument("--event", dest="event_id", type=str, help="Analyse a specific event by ID")
    parser.add_argument("--test-ollama", action="store_true", help="Test Ollama connectivity")
    parser.add_argument("--reanalyze", action="store_true", help="Clear and re-triage all events")
    parser.add_argument(
        "--batch-size", type=int, default=None, help=f"Events per batch (default: {AI_BATCH_SIZE})"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help=f"Seconds between cycles (default: {AI_CYCLE_INTERVAL})",
    )
    args = parser.parse_args()

    if not AI_ANALYSIS_ENABLED:
        print("AI analysis is disabled in config (AI_ANALYSIS_ENABLED=False)")
        return 0

    if args.test_ollama:
        return cmd_test_ollama(args)
    if args.stats:
        return cmd_stats(args)
    if args.dry_run:
        return cmd_dry_run(args)
    if args.event_id:
        return cmd_event(args)
    if args.reanalyze:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM ai_analysis")
        deleted = cur.rowcount
        conn.commit()
        conn.close()
        logger.info("Cleared %d analysis records — re-triage will start", deleted)

    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
