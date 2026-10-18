"""
claude_analyzer.py — Anthropic Claude Dual-Model Event Analysis
================================================================
Two-tier Claude analysis:
  - TRIAGE (Haiku 4.5): fast, cheap (~$0.003/event), every SUSPICIOUS/CRITICAL
  - DEEP   (Sonnet 4):  thorough (~$0.012/event), manual 🔬 or selected events

Configuration in config.py:
    USE_EXTERNAL_AI        = True/False   — master switch
    AUTO_EXTERNAL_AI       = True/False   — allow auto-trigger
    ANTHROPIC_API_KEY      = ""           — API key (prefer env var)
    ANTHROPIC_TRIAGE_MODEL = "claude-haiku-4-5-20251001"   — fast triage
    ANTHROPIC_DEEP_MODEL   = "claude-sonnet-4-20250514"    — deep analysis
    ANTHROPIC_MODEL        = "..."        — legacy fallback (used if above not set)
    ANTHROPIC_TIMEOUT      = 60
    ANTHROPIC_MAX_TOKENS   = 2048

Env vars (override config.py):
    ANTHROPIC_API_KEY   — API key (recommended over config.py)

Usage:
    from honeylens.analysis.claude_analyzer import triage_event, analyze_event, is_claude_available

    if is_claude_available():
        triage = triage_event(event_id)    # Haiku — fast, cheap
        deep   = analyze_event(event_id)   # Sonnet — thorough

Compatible with Python 3.9+.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
import sys
import time
from typing import Any

logger = logging.getLogger("sensor.claude")

# ---------------------------------------------------------------------------
# Configuration — safe imports with defaults
# ---------------------------------------------------------------------------


# External AI config — all optional with safe defaults
def _cfg(name: str, default: Any = None) -> Any:
    """Read config value with fallback."""
    try:
        from honeylens import config

        return getattr(config, name, default)
    except (ImportError, AttributeError):
        return default


# Master switch
USE_EXTERNAL_AI = _cfg("USE_EXTERNAL_AI", False)

# Auto-trigger switch (if False, only manual WebUI calls work)
AUTO_EXTERNAL_AI = _cfg("AUTO_EXTERNAL_AI", False)

# API configuration
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY") or _cfg("ANTHROPIC_API_KEY", "")
ANTHROPIC_TIMEOUT = _cfg("ANTHROPIC_TIMEOUT", 60)
ANTHROPIC_MAX_TOKENS = _cfg("ANTHROPIC_MAX_TOKENS", 2048)

# Dual-model config: triage (Haiku) + deep (Sonnet)
ANTHROPIC_TRIAGE_MODEL = _cfg("ANTHROPIC_TRIAGE_MODEL", "claude-haiku-4-5-20251001")
ANTHROPIC_DEEP_MODEL = _cfg("ANTHROPIC_DEEP_MODEL", "claude-sonnet-4-20250514")

# Legacy fallback — if only ANTHROPIC_MODEL is set, use it for both
_legacy_model = _cfg("ANTHROPIC_MODEL", "")
if _legacy_model and not _cfg("ANTHROPIC_TRIAGE_MODEL", None):
    ANTHROPIC_TRIAGE_MODEL = _legacy_model
if _legacy_model and not _cfg("ANTHROPIC_DEEP_MODEL", None):
    ANTHROPIC_DEEP_MODEL = _legacy_model

# Alias for backward compat
ANTHROPIC_MODEL = ANTHROPIC_DEEP_MODEL

# ---------------------------------------------------------------------------
# Cost tracking & spending caps (Idea 19 Phase 3)
# ---------------------------------------------------------------------------

# Per-million-token pricing (input, output) by model family
_MODEL_PRICING = {
    "haiku": (1.0, 5.0),  # $1/$5 per MTok
    "sonnet": (3.0, 15.0),  # $3/$15 per MTok
    "opus": (15.0, 75.0),  # $15/$75 per MTok
}

# Budget caps (override via env)
AI_DAILY_BUDGET_USD = float(os.environ.get("AI_DAILY_BUDGET_USD", "5.00"))
AI_MONTHLY_BUDGET_USD = float(os.environ.get("AI_MONTHLY_BUDGET_USD", "100.00"))


def _model_family(model_name: str) -> str:
    """Extract model family from model ID."""
    m = model_name.lower()
    if "opus" in m:
        return "opus"
    elif "sonnet" in m:
        return "sonnet"
    return "haiku"


# OpenAI pricing — kept in sync with analysis/openai_analyzer.py._OPENAI_PRICING
_OPENAI_PRICING = {
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-5-mini": (0.25, 2.00),
    "gpt-5-nano": (0.05, 0.40),
}


def _is_openai_model(model: str) -> bool:
    m = (model or "").lower()
    return m.startswith("gpt-") or m.startswith("o1") or m.startswith("o3") or m.startswith("o4")


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost for a request. Provider-aware via model-name prefix."""
    if _is_openai_model(model):
        rates = _OPENAI_PRICING.get(model.lower(), _OPENAI_PRICING["gpt-4.1-mini"])
        in_rate, out_rate = rates
    else:
        family = _model_family(model)
        in_rate, out_rate = _MODEL_PRICING.get(family, (1.0, 5.0))
    return (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000


def _get_cost_conn():
    """Get a DB connection for cost queries."""
    from honeylens.database import legacy_get_db

    return legacy_get_db()


def get_daily_spend() -> float:
    """Get total Claude spend for today (UTC)."""
    try:
        conn = _get_cost_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT COALESCE(SUM(estimated_cost_usd), 0)
            FROM claude_analysis_log
            WHERE created_at >= date_trunc('day', NOW() AT TIME ZONE 'UTC')
        """)
        cost = float(cur.fetchone()[0])
        conn.close()
        return cost
    except Exception as e:
        logger.debug("Cost query failed: %s", e)
        return 0.0


def get_monthly_spend() -> float:
    """Get total Claude spend for current month."""
    try:
        conn = _get_cost_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT COALESCE(SUM(estimated_cost_usd), 0)
            FROM claude_analysis_log
            WHERE created_at >= date_trunc('month', NOW() AT TIME ZONE 'UTC')
        """)
        cost = float(cur.fetchone()[0])
        conn.close()
        return cost
    except Exception as e:
        logger.debug("Cost query failed: %s", e)
        return 0.0


def check_budget() -> tuple:
    """Check if we're within budget. Returns (allowed, reason)."""
    daily = get_daily_spend()
    if daily >= AI_DAILY_BUDGET_USD:
        return False, f"Daily budget exceeded: ${daily:.2f} >= ${AI_DAILY_BUDGET_USD:.2f}"
    monthly = get_monthly_spend()
    if monthly >= AI_MONTHLY_BUDGET_USD:
        return False, f"Monthly budget exceeded: ${monthly:.2f} >= ${AI_MONTHLY_BUDGET_USD:.2f}"
    return (
        True,
        f"OK (today=${daily:.2f}/{AI_DAILY_BUDGET_USD:.2f}, month=${monthly:.2f}/{AI_MONTHLY_BUDGET_USD:.2f})",
    )


def get_cost_summary() -> dict:
    """Full cost summary for dashboard."""
    try:
        conn = _get_cost_conn()
        cur = conn.cursor()
        # Today
        cur.execute("""
            SELECT COALESCE(SUM(estimated_cost_usd), 0), COUNT(*)
            FROM claude_analysis_log
            WHERE created_at >= date_trunc('day', NOW() AT TIME ZONE 'UTC')
        """)
        today_cost, today_events = cur.fetchone()
        # This month
        cur.execute("""
            SELECT COALESCE(SUM(estimated_cost_usd), 0), COUNT(*)
            FROM claude_analysis_log
            WHERE created_at >= date_trunc('month', NOW() AT TIME ZONE 'UTC')
        """)
        month_cost, month_events = cur.fetchone()
        # By model (this month)
        cur.execute("""
            SELECT model, COUNT(*) as calls,
                   COALESCE(SUM(estimated_cost_usd), 0) as cost,
                   COALESCE(SUM(input_tokens), 0) as input_tok,
                   COALESCE(SUM(output_tokens), 0) as output_tok
            FROM claude_analysis_log
            WHERE created_at >= date_trunc('month', NOW() AT TIME ZONE 'UTC')
            GROUP BY model ORDER BY cost DESC
        """)
        model_breakdown = {}
        for row in cur.fetchall():
            model_breakdown[row[0]] = {
                "calls": row[1],
                "cost_usd": float(row[2]),
                "input_tokens": row[3],
                "output_tokens": row[4],
            }
        # Last 7 days daily
        cur.execute("""
            SELECT created_at::date as day,
                   COUNT(*) as calls,
                   COALESCE(SUM(estimated_cost_usd), 0) as cost
            FROM claude_analysis_log
            WHERE created_at >= NOW() - INTERVAL '7 days'
            GROUP BY day ORDER BY day DESC
        """)
        daily_trend = [
            {"day": str(r[0]), "calls": r[1], "cost_usd": float(r[2])} for r in cur.fetchall()
        ]
        conn.close()

        allowed, reason = check_budget()
        return {
            "today_usd": float(today_cost),
            "today_events": today_events,
            "today_limit_usd": AI_DAILY_BUDGET_USD,
            "month_usd": float(month_cost),
            "month_events": month_events,
            "month_limit_usd": AI_MONTHLY_BUDGET_USD,
            "month_pct": round(100 * float(month_cost) / AI_MONTHLY_BUDGET_USD, 1)
            if AI_MONTHLY_BUDGET_USD
            else 0,
            "model_breakdown": model_breakdown,
            "daily_trend": daily_trend,
            "budget_ok": allowed,
            "budget_status": reason,
            "triage_model": ANTHROPIC_TRIAGE_MODEL,
            "deep_model": ANTHROPIC_DEEP_MODEL,
        }
    except Exception as e:
        logger.error("Cost summary failed: %s", e)
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Anthropic SDK — lazy import
# ---------------------------------------------------------------------------

_client: Any = None


def _get_client():
    """Lazy-init the Anthropic client."""
    global _client
    if _client is not None:
        return _client

    if not ANTHROPIC_API_KEY:
        raise RuntimeError("ANTHROPIC_API_KEY not configured")

    try:
        from anthropic import Anthropic

        _client = Anthropic(api_key=ANTHROPIC_API_KEY)
        logger.info(
            "Anthropic client initialized (triage=%s, deep=%s)",
            ANTHROPIC_TRIAGE_MODEL,
            ANTHROPIC_DEEP_MODEL,
        )
        return _client
    except ImportError:
        raise RuntimeError(
            "anthropic package not installed. Run: pip install anthropic --break-system-packages"
        ) from None


def is_claude_available() -> bool:
    """Check if Claude integration is enabled and configured."""
    if not USE_EXTERNAL_AI:
        return False
    if not ANTHROPIC_API_KEY:
        return False
    try:
        import anthropic  # noqa: F401

        return True
    except ImportError:
        return False


def is_auto_enabled() -> bool:
    """Check if automatic Claude analysis is enabled."""
    return USE_EXTERNAL_AI and AUTO_EXTERNAL_AI and bool(ANTHROPIC_API_KEY)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def _get_db():
    """Get a psycopg2 connection."""
    from honeylens.database import legacy_get_db

    return legacy_get_db()


def _is_hunting_ip(ip: str) -> bool:
    """Check if IP is in attacker_profiles (being actively hunted)."""
    if not ip:
        return False
    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM attacker_profiles WHERE host(ip) = %s LIMIT 1", (ip,))
        return cur.fetchone() is not None
    except Exception as e:
        logger.debug("Profile existence check failed for %s: %s", ip, e)
        return False


def _load_event(event_id: str) -> dict[str, Any] | None:
    """Load full event data from sensor_events + attack_patterns + ai_analysis."""
    conn = _get_db()
    cur = conn.cursor()

    # Main event
    cur.execute(
        """
        SELECT event_id, timestamp, source, protocol,
               host(src_ip) AS src_ip, src_port,
               host(dst_ip) AS dst_ip, dst_port,
               payload, attack_types, scan_score, port_entropy,
               ja3, metadata
        FROM sensor_events
        WHERE event_id = %s
    """,
        (event_id,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return None

    event = {
        "event_id": row[0],
        "timestamp": str(row[1]) if row[1] else None,
        "source": row[2],
        "protocol": row[3],
        "src_ip": row[4],
        "src_port": row[5],
        "dst_ip": row[6],
        "dst_port": row[7],
        "payload": row[8],
        "attack_types": row[9],
        "scan_score": row[10],
        "port_entropy": row[11],
        "ja3": row[12],
        "metadata": row[13] if isinstance(row[13], dict) else {},
    }

    # Attack pattern details
    cur.execute(
        """
        SELECT attack_type, rule_name, matched_text
        FROM attack_patterns
        WHERE event_id = %s
    """,
        (event_id,),
    )
    event["attack_details"] = [{"type": r[0], "rule": r[1], "match": r[2]} for r in cur.fetchall()]

    # Existing AI triage (if any)
    try:
        cur.execute(
            """
            SELECT triage_class, novelty_score, triage_confidence,
                   triage_reasoning, known_cve, zero_day_score
            FROM ai_analysis
            WHERE event_id = %s
        """,
            (event_id,),
        )
        ai_row = cur.fetchone()
        if ai_row:
            event["local_ai_triage"] = {
                "class": ai_row[0],
                "novelty": ai_row[1],
                "confidence": ai_row[2],
                "reasoning": ai_row[3],
                "cve": ai_row[4],
                "zero_day_score": ai_row[5],
            }
    except Exception as e:
        logger.debug("Failed to load AI triage for %s: %s", event_id, e)

    # Attacker profile (if any)
    if event.get("src_ip"):
        try:
            cur.execute(
                """
                SELECT country, asn_org, abuse_score, ai_threat_level,
                       ai_intent, internal_tags, mitre_techniques
                FROM attacker_profiles
                WHERE host(ip) = %s
            """,
                (event["src_ip"],),
            )
            prof = cur.fetchone()
            if prof:
                event["attacker_profile"] = {
                    "country": prof[0],
                    "asn": prof[1],
                    "abuse_score": prof[2],
                    "threat_level": prof[3],
                    "intent": prof[4],
                    "tags": prof[5] if isinstance(prof[5], list) else [],
                    "mitre": prof[6] if isinstance(prof[6], list) else [],
                }
        except Exception as e:
            logger.debug("Failed to load attacker profile for %s: %s", event.get("src_ip"), e)

    conn.close()
    return event


def _store_result(
    event_id: str, result: dict[str, Any], event: dict[str, Any] | None = None
) -> None:
    """Store Claude analysis in ai_analysis + claude_analysis_log, then auto-hunt the IP."""
    conn = _get_db()
    cur = conn.cursor()

    meta = result.get("_meta", {})
    src_ip = (event or {}).get("src_ip")
    input_tok = meta.get("input_tokens", 0)
    output_tok = meta.get("output_tokens", 0)
    # Provider-aware model + cost. Backends populate _meta.model with the
    # actual model that was invoked; fall back to the configured Anthropic
    # deep model for legacy callers that didn't set it.
    model_used = meta.get("model") or ANTHROPIC_MODEL
    cost = estimate_cost(model_used, input_tok, output_tok)

    # 1. Upsert into ai_analysis — fill ALL structured columns
    cur.execute(
        """
        INSERT INTO ai_analysis (
            event_id, timestamp, deep_model, deep_analysis,
            claude_verdict, claude_confidence, claude_attack_type,
            claude_technique, claude_tactic, claude_cve,
            claude_zero_day_prob, claude_threat_actor,
            claude_kill_chain, claude_summary, claude_iocs,
            claude_recommendations, claude_related_cves,
            claude_input_tokens, claude_output_tokens,
            claude_cost_usd, claude_elapsed_ms, claude_analyzed_at
        ) VALUES (
            %s, NOW(), %s, %s,
            %s, %s, %s,
            %s, %s, %s,
            %s, %s,
            %s, %s, %s,
            %s, %s,
            %s, %s,
            %s, %s, NOW()
        )
        ON CONFLICT (event_id) DO UPDATE SET
            deep_model          = EXCLUDED.deep_model,
            deep_analysis       = EXCLUDED.deep_analysis,
            claude_verdict      = EXCLUDED.claude_verdict,
            claude_confidence   = EXCLUDED.claude_confidence,
            claude_attack_type  = EXCLUDED.claude_attack_type,
            claude_technique    = EXCLUDED.claude_technique,
            claude_tactic       = EXCLUDED.claude_tactic,
            claude_cve          = EXCLUDED.claude_cve,
            claude_zero_day_prob = EXCLUDED.claude_zero_day_prob,
            claude_threat_actor = EXCLUDED.claude_threat_actor,
            claude_kill_chain   = EXCLUDED.claude_kill_chain,
            claude_summary      = EXCLUDED.claude_summary,
            claude_iocs         = EXCLUDED.claude_iocs,
            claude_recommendations = EXCLUDED.claude_recommendations,
            claude_related_cves = EXCLUDED.claude_related_cves,
            claude_input_tokens = EXCLUDED.claude_input_tokens,
            claude_output_tokens = EXCLUDED.claude_output_tokens,
            claude_cost_usd     = EXCLUDED.claude_cost_usd,
            claude_elapsed_ms   = EXCLUDED.claude_elapsed_ms,
            claude_analyzed_at  = EXCLUDED.claude_analyzed_at
    """,
        (
            event_id,
            model_used,
            json.dumps(result, default=str),
            result.get("verdict"),
            result.get("confidence"),
            result.get("attack_type"),
            result.get("technique"),
            result.get("tactic"),
            result.get("cve"),
            result.get("zero_day_probability"),
            result.get("threat_actor"),
            result.get("kill_chain_phase"),
            result.get("summary"),
            json.dumps(result.get("indicators_of_compromise", []), default=str),
            json.dumps(result.get("recommendations", []), default=str),
            json.dumps(result.get("related_cves", []), default=str),
            input_tok,
            output_tok,
            round(cost, 6),
            meta.get("elapsed_ms", 0),
        ),
    )

    # 1b. CIRCL CVE enrichment (Idea 32)
    cve_id = result.get("cve")
    if cve_id and cve_id not in ("None", "null", ""):
        try:
            from honeylens.intelligence.circl_enricher import enrich_and_track

            cve_detail = enrich_and_track(cve_id, conn)
            if cve_detail:
                from psycopg2.extras import Json as PgJson

                cur.execute(
                    "UPDATE ai_analysis SET cve_details = %s WHERE event_id = %s",
                    (PgJson(cve_detail), event_id),
                )
                logger.info(
                    "CIRCL enriched %s (CVSS %s, KEV=%s)",
                    cve_id,
                    cve_detail.get("cvss_score"),
                    cve_detail.get("is_kev"),
                )
        except Exception as e:
            logger.debug("CIRCL enrichment skipped: %s", e)

    # 2. Insert into claude_analysis_log (audit trail — keeps every call)
    try:
        cur.execute(
            """
            INSERT INTO claude_analysis_log (
                event_id, src_ip, dst_port, protocol, attack_types,
                verdict, confidence, attack_type, technique, tactic,
                cve, zero_day_prob, threat_actor, kill_chain, summary,
                full_result, model, input_tokens, output_tokens,
                elapsed_ms, estimated_cost_usd
            ) VALUES (
                %s, %s::inet, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s
            )
        """,
            (
                event_id,
                src_ip,
                (event or {}).get("dst_port"),
                (event or {}).get("protocol"),
                (event or {}).get("attack_types"),
                result.get("verdict"),
                result.get("confidence"),
                result.get("attack_type"),
                result.get("technique"),
                result.get("tactic"),
                result.get("cve"),
                result.get("zero_day_probability"),
                result.get("threat_actor"),
                result.get("kill_chain_phase"),
                result.get("summary"),
                json.dumps(result, default=str),
                model_used,
                input_tok,
                output_tok,
                meta.get("elapsed_ms", 0),
                round(cost, 6),
            ),
        )
    except Exception as e:
        logger.warning("Could not write to claude_analysis_log: %s", e)
        conn.rollback()
        # Re-do the ai_analysis upsert since rollback cleared it
        cur.execute(
            """
            INSERT INTO ai_analysis (event_id, deep_model, deep_analysis, timestamp)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (event_id) DO UPDATE SET
                deep_model = EXCLUDED.deep_model,
                deep_analysis = EXCLUDED.deep_analysis
        """,
            (event_id, model_used, json.dumps(result, default=str)),
        )

    conn.commit()

    # 3. Update attacker_profiles with Claude insight — keep highest severity
    if src_ip:
        _SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        new_verdict = result.get("verdict", "")
        new_rank = _SEV_RANK.get(new_verdict, 0)

        try:
            cur2 = conn.cursor()
            # Read current verdict to compare severity
            cur2.execute(
                """
                SELECT claude_verdict FROM attacker_profiles
                WHERE host(ip) = %s
            """,
                (src_ip,),
            )
            row = cur2.fetchone()
            if row:
                old_verdict = row[0] or ""
                old_rank = _SEV_RANK.get(old_verdict, 0)

                if new_rank >= old_rank:
                    # New result is same or higher severity — update profile
                    cur2.execute(
                        """
                        UPDATE attacker_profiles SET
                            claude_verdict      = %s,
                            claude_summary      = %s,
                            claude_technique    = %s,
                            claude_cve          = %s,
                            claude_threat_actor = %s,
                            claude_analyzed_at  = NOW(),
                            updated_at          = NOW()
                        WHERE host(ip) = %s
                    """,
                        (
                            new_verdict,
                            result.get("summary"),
                            result.get("technique"),
                            result.get("cve"),
                            result.get("threat_actor"),
                            src_ip,
                        ),
                    )
                else:
                    # Lower severity — only update timestamp
                    cur2.execute(
                        """
                        UPDATE attacker_profiles SET
                            claude_analyzed_at = NOW(),
                            updated_at = NOW()
                        WHERE host(ip) = %s
                    """,
                        (src_ip,),
                    )
            conn.commit()
        except Exception as e:
            logger.debug("Could not update attacker_profiles with Claude data: %s", e)

    conn.close()
    logger.info("Claude analysis stored for event %s (cost=$%.4f)", event_id[:16], cost)

    # Auto-hunt the source IP (background, best-effort)
    if src_ip:
        _auto_hunt_ip(src_ip, event_id, result)


def _run_coroutine_blocking(coro: Any) -> Any:
    """Run a coroutine from synchronous code, including from under a running event loop.

    Auto-hunt is called from FastAPI routes (``routes/ai/analysis.py`` calls triage
    synchronously from an ``async def``); there ``asyncio.run`` would raise "cannot be called
    from a running event loop" and the hunt would silently not start. A separate thread with
    its own loop handles both cases.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _auto_hunt_ip(ip: str, event_id: str, claude_result: dict[str, Any]) -> None:
    """Auto-trigger attacker profiling for the source IP after Claude analysis."""
    try:
        from honeylens.analysis.attacker_profiler import (
            fetch_ip_info,
            get_db_connection,
            profile_ip,
        )
        from honeylens.intelligence.osint_providers import build_providers

        conn = _get_db()
        cur = conn.cursor()

        # Check if already profiled
        cur.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM attacker_profiles WHERE host(ip) = %s
            )
        """,
            (ip,),
        )
        already_profiled = cur.fetchone()[0]
        conn.close()

        if already_profiled:
            logger.info("IP %s already profiled — skipping auto-hunt", ip)
            # Update the log to mark as hunted
            _update_hunt_status(event_id, ip, already_hunted=True)
            return

        # Profile the IP
        logger.info("Auto-hunting IP %s after Claude analysis of %s", ip, event_id[:16])
        from honeylens.config import ATTACKER_PROFILING

        providers = build_providers(ATTACKER_PROFILING)

        # In 0.9 this call had the wrong signature (profile_ip(ip, db_conn, providers,
        # mitre_data=…)) and treated the coroutine as a dict, so auto-hunt ended with a
        # TypeError caught below as "Auto-hunt failed" — this path never worked.
        # Signature from attacker_profiler: profile_ip(ip, ip_info, conn, providers, config).
        db_conn = get_db_connection()
        try:
            ip_info = fetch_ip_info(db_conn, ip)
            result = _run_coroutine_blocking(
                profile_ip(ip, ip_info, db_conn, providers, ATTACKER_PROFILING)
            )
        finally:
            db_conn.close()

        if result:
            threat_level = result.get("ai_threat_level", "UNKNOWN")
            logger.info("Auto-hunt complete: %s → %s", ip, threat_level)
            _update_hunt_status(event_id, ip, threat_level=threat_level)
        else:
            logger.warning("Auto-hunt returned no result for %s", ip)

    except ImportError as e:
        logger.debug("Auto-hunt skipped (missing module): %s", e)
    except Exception as e:
        logger.warning("Auto-hunt failed for %s: %s", ip, e)


def _update_hunt_status(
    event_id: str, ip: str, threat_level: str | None = None, already_hunted: bool = False
) -> None:
    """Update claude_analysis_log with hunting result."""
    try:
        conn = _get_db()
        cur = conn.cursor()
        if already_hunted:
            # Fetch existing threat level
            cur.execute(
                """
                SELECT ai_threat_level FROM attacker_profiles
                WHERE host(ip) = %s
            """,
                (ip,),
            )
            row = cur.fetchone()
            tl = row[0] if row else None
            cur.execute(
                """
                UPDATE claude_analysis_log
                SET auto_hunted = TRUE, hunt_threat_level = %s
                WHERE event_id = %s AND src_ip = %s::inet
                ORDER BY created_at DESC LIMIT 1
            """,
                (tl, event_id, ip),
            )
        else:
            cur.execute(
                """
                UPDATE claude_analysis_log
                SET auto_hunted = TRUE, hunt_threat_level = %s
                WHERE event_id = %s AND src_ip = %s::inet
                ORDER BY created_at DESC LIMIT 1
            """,
                (threat_level, event_id, ip),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug("Could not update hunt status in log: %s", e)


def _store_suggested_rule(
    event_id: str, rule: dict[str, Any], claude_result: dict[str, Any]
) -> None:
    """Store Claude-suggested detection rule into ai_analysis suggested columns."""
    import re as _re

    rule_name = rule.get("rule_name", "")
    regex_pat = rule.get("regex_pattern", "")

    # Validate regex compiles
    try:
        _re.compile(regex_pat)
    except _re.error:
        logger.warning("Claude suggested invalid regex for %s: %s", event_id[:16], regex_pat[:80])
        return

    # Sanitize rule name
    clean_name = "claude_" + _re.sub(r"[^a-zA-Z0-9_\-]", "_", rule_name)[:120]
    mitre = rule.get("mitre_technique", "") or claude_result.get("technique", "")

    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE ai_analysis SET
                suggested_rule_name  = %s,
                suggested_rule_regex = %s,
                suggested_mitre      = %s
            WHERE event_id = %s
        """,
            (clean_name, regex_pat, mitre, event_id),
        )
        conn.commit()
        conn.close()
        logger.info("Claude suggested rule '%s' stored for event %s", clean_name, event_id[:16])
    except Exception as e:
        logger.warning("Could not store Claude suggested rule: %s", e)


SYSTEM_PROMPT = """You are a senior threat intelligence analyst specializing in network security, ICS/OT systems, and malware analysis. You work at a Security Operations Centre analyzing events captured by a honeypot + eBPF sensor platform.

Your analysis must be:
- Technically precise with specific CVE references where applicable
- Actionable with concrete defensive recommendations
- Honest about uncertainty — say "unknown" rather than guess
- Include a detection rule suggestion when you identify a specific attack pattern

Respond ONLY with valid JSON matching this exact schema:
{
    "verdict": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "confidence": 0-100,
    "attack_type": "string — specific attack classification (SQLI, XSS, LFI, RCE, etc.)",
    "technique": "string — MITRE ATT&CK technique ID if applicable (e.g. T1190)",
    "tactic": "string — MITRE ATT&CK tactic (e.g. Initial Access)",
    "cve": "string or null — the specific published CVE this payload matches for THIS product; null unless confident. Do not guess or carry over a CVE from an example.",
    "zero_day_probability": 0-100,
    "threat_actor": "string or null — APT group attribution if patterns match",
    "exploit_analysis": "string — detailed technical analysis of the payload/attack",
    "indicators_of_compromise": ["list of IOCs: IPs, domains, hashes, file paths"],
    "kill_chain_phase": "string — Reconnaissance|Weaponization|Delivery|Exploitation|Installation|C2|Actions",
    "recommendations": ["list of specific defensive actions"],
    "related_cves": ["ONLY CVEs for the SAME product/vulnerability you are confident about; [] if unsure — never another vendor's CVE, a loose association, or a guess. One payload must not be attributed to unrelated vulnerabilities."],
    "summary": "string — one-paragraph executive summary",
    "suggested_rule": {
        "rule_name": "string — snake_case rule identifier, e.g. login_cmd_injection (do NOT copy a vendor/CVE from this example into your answer)",
        "regex_pattern": "string — Python regex to detect this attack in payloads",
        "attack_type": "string — category: SQLI, XSS, LFI, RCE, CREDENTIAL, etc.",
        "severity": "string — CRITICAL, HIGH, MEDIUM, LOW",
        "mitre_technique": "string — MITRE T-code",
        "description": "string — what this rule detects"
    }
}

For suggested_rule: only include if you can identify a specific, reliable regex pattern in the payload that would detect this type of attack. The regex should be specific enough to avoid false positives but general enough to catch variants. Set to null if no good rule can be derived."""


TRIAGE_PROMPT = """You are a network security triage analyst. Classify this honeypot event quickly and accurately.

Respond ONLY with valid JSON:
{
    "verdict": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "confidence": 0-100,
    "attack_type": "string — SQLI, XSS, LFI, RCE, CREDENTIAL, SCANNER, RECON, etc.",
    "technique": "string — MITRE ATT&CK ID if known (e.g. T1190), or null",
    "cve": "string or null — specific CVE if recognized",
    "zero_day_probability": 0-100,
    "summary": "string — one sentence summary",
    "suggested_rule": {
        "rule_name": "string — snake_case identifier",
        "regex_pattern": "string — Python regex for detection",
        "attack_type": "string — category",
        "severity": "string — CRITICAL/HIGH/MEDIUM/LOW",
        "mitre_technique": "string or null",
        "description": "string — what it detects"
    }
}

Verdict guide:
- CRITICAL: Active exploitation, 0-day, ICS/OT targeting, known APT patterns
- HIGH: Confirmed attack with specific CVE or dangerous payload
- MEDIUM: Likely attack, known scanner or tool, but no confirmed exploit
- LOW: Reconnaissance, benign scanner, information gathering
- INFO: Background noise, health checks, error probes

For suggested_rule: include only if a clear regex pattern exists. Set to null otherwise.
Keep your response concise — this is triage, not deep analysis."""


def _build_prompt(event: dict[str, Any]) -> str:
    """Build analysis prompt from event data."""
    lines = ["Analyze this security event captured by our sensor:"]
    lines.append("")

    # Core fields
    lines.append(f"Protocol: {event.get('protocol', 'unknown')}")
    lines.append(f"Source IP: {event.get('src_ip', 'unknown')}")
    lines.append(f"Source Port: {event.get('src_port', '')}")
    lines.append(f"Destination Port: {event.get('dst_port', '')}")
    lines.append(f"Event Source: {event.get('source', 'unknown')}")
    lines.append(f"Scan Score: {event.get('scan_score', 0)}")
    if event.get("ja3"):
        lines.append(f"JA3 Fingerprint: {event['ja3']}")

    # Attack classification
    if event.get("attack_types"):
        lines.append(f"\nAttack Types Detected: {event['attack_types']}")
    if event.get("attack_details"):
        lines.append("\nAttack Pattern Matches:")
        for ad in event["attack_details"][:15]:
            if not ad or not isinstance(ad, dict):
                continue
            lines.append(
                f"  - [{ad.get('type', '?')}] {ad.get('rule', '?')}: {str(ad.get('match', ''))[:100]}"
            )

    # Local AI triage
    if event.get("local_ai_triage"):
        t = event["local_ai_triage"]
        lines.append(
            f"\nLocal AI Triage: {t.get('class', '?')} "
            f"(confidence={t.get('confidence', '?')}%, "
            f"novelty={t.get('novelty', '?')}/10)"
        )
        if t.get("reasoning"):
            lines.append(f"Local AI Reasoning: {t['reasoning'][:300]}")
        if t.get("cve"):
            lines.append(f"Local AI CVE Match: {t['cve']}")

    # Attacker profile
    if event.get("attacker_profile"):
        p = event["attacker_profile"]
        lines.append("\nAttacker Profile:")
        lines.append(f"  Country: {p.get('country', '?')}, ASN: {p.get('asn', '?')}")
        lines.append(f"  Abuse Score: {p.get('abuse_score', '?')}/100")
        lines.append(f"  Threat Level: {p.get('threat_level', '?')}")
        lines.append(f"  Intent: {p.get('intent', '?')}")
        if p.get("tags"):
            lines.append(f"  Tags: {', '.join(p['tags'][:10])}")
        if p.get("mitre"):
            lines.append(f"  MITRE Techniques: {', '.join(p['mitre'][:10])}")

    # Payload — truncate to avoid excessive token usage
    payload = event.get("payload", "")
    if payload:
        # Cap at ~2000 chars to keep costs reasonable
        truncated = payload[:2000]
        if len(payload) > 2000:
            truncated += f"\n... [truncated, {len(payload)} total chars]"
        lines.append(f"\n--- PAYLOAD ({len(payload)} bytes) ---")
        lines.append(truncated)
        lines.append("--- END PAYLOAD ---")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def triage_event(event_id: str, store: bool = True) -> dict[str, Any]:
    """
    Fast triage using Claude Haiku — cheap classification (~$0.003/event).
    Returns a lighter result than analyze_event (no kill chain, no IOCs list).

    Uses ANTHROPIC_TRIAGE_MODEL (default: claude-haiku-4-5-20251001).
    """
    if not USE_EXTERNAL_AI:
        return {"error": "External AI is disabled (USE_EXTERNAL_AI = False)"}
    if not ANTHROPIC_API_KEY:
        return {"error": "ANTHROPIC_API_KEY not configured"}

    # Budget check
    allowed, reason = check_budget()
    if not allowed:
        logger.warning("Claude triage BLOCKED for %s: %s", event_id[:16], reason)
        return {"error": "Budget exceeded", "detail": reason, "budget_blocked": True}

    event = _load_event(event_id)
    if not event:
        return {"error": f"Event {event_id} not found"}

    # Skip Suricata-classified events — unless IP is in hunting (attacker_profiles)
    if event.get("source") == "suricata" or event.get("suricata_sid"):
        is_hunted = _is_hunting_ip(event.get("src_ip", ""))
        if not is_hunted:
            logger.debug(
                "Skipping %s — already classified by Suricata (SID %s)",
                event_id[:16],
                event.get("suricata_sid"),
            )
            return {
                "verdict": "KNOWN",
                "source": "suricata",
                "suricata_sid": event.get("suricata_sid"),
                "skip_ai": True,
                "reasoning": "Classified by Suricata IDS",
            }
        logger.info(
            "Suricata event %s from hunting IP %s — sending to AI",
            event_id[:16],
            event.get("src_ip"),
        )

    prompt = _build_prompt(event)
    logger.info(
        "Claude TRIAGE (%s) for %s (%s, %s)",
        ANTHROPIC_TRIAGE_MODEL.split("-")[1]
        if "-" in ANTHROPIC_TRIAGE_MODEL
        else ANTHROPIC_TRIAGE_MODEL,
        event_id[:16],
        event.get("protocol", "?"),
        event.get("attack_types", "none"),
    )

    t0 = time.time()
    try:
        client = _get_client()
        message = client.messages.create(
            model=ANTHROPIC_TRIAGE_MODEL,
            max_tokens=1024,  # Shorter response for triage
            system=TRIAGE_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        elapsed_ms = int((time.time() - t0) * 1000)
        raw_text = message.content[0].text

        try:
            result = json.loads(raw_text)
        except json.JSONDecodeError:
            import re

            m = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw_text, re.DOTALL)
            if m:
                result = json.loads(m.group(1))
            else:
                logger.warning("Haiku triage non-JSON for %s: %s", event_id[:16], raw_text[:200])
                result = {
                    "error": "non-JSON",
                    "raw_response": raw_text[:2000],
                    "verdict": "UNKNOWN",
                }

        result["_meta"] = {
            "model": ANTHROPIC_TRIAGE_MODEL,
            "mode": "triage",
            "elapsed_ms": elapsed_ms,
            "input_tokens": message.usage.input_tokens,
            "output_tokens": message.usage.output_tokens,
            "event_id": event_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        result["_raw_response"] = raw_text

        _est_cost = estimate_cost(
            ANTHROPIC_TRIAGE_MODEL, message.usage.input_tokens, message.usage.output_tokens
        )
        logger.info(
            "Claude TRIAGE %s → %s (conf=%s, %dms, %d+%d tok, ~$%.4f)",
            event_id[:16],
            result.get("verdict", "?"),
            result.get("confidence", "?"),
            elapsed_ms,
            message.usage.input_tokens,
            message.usage.output_tokens,
            _est_cost,
        )

        if store:
            _store_result(event_id, result, event=event)
            sr = result.get("suggested_rule")
            if sr and isinstance(sr, dict) and sr.get("rule_name") and sr.get("regex_pattern"):
                _store_suggested_rule(event_id, sr, result)

        return result

    except Exception as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        logger.error("Claude triage failed for %s (%dms): %s", event_id[:16], elapsed_ms, e)
        return {"error": str(e), "elapsed_ms": elapsed_ms}


def analyze_event(event_id: str, store: bool = True) -> dict[str, Any]:
    """
    Deep analysis using Claude Sonnet — thorough analysis (~$0.012/event).
    Full CVE identification, APT attribution, kill chain, IOCs, recommendations.

    Uses ANTHROPIC_DEEP_MODEL (default: claude-sonnet-4-20250514).
    """
    if not USE_EXTERNAL_AI:
        return {"error": "External AI is disabled (USE_EXTERNAL_AI = False)"}

    if not ANTHROPIC_API_KEY:
        return {"error": "ANTHROPIC_API_KEY not configured"}

    # Budget check
    allowed, reason = check_budget()
    if not allowed:
        logger.warning("Claude deep BLOCKED for %s: %s", event_id[:16], reason)
        return {"error": "Budget exceeded", "detail": reason, "budget_blocked": True}

    # Load event data
    event = _load_event(event_id)
    if not event:
        return {"error": f"Event {event_id} not found"}

    # Build prompt
    prompt = _build_prompt(event)
    logger.info(
        "Claude DEEP (%s) for %s (%s, %s)",
        ANTHROPIC_DEEP_MODEL.split("-")[1] if "-" in ANTHROPIC_DEEP_MODEL else ANTHROPIC_DEEP_MODEL,
        event_id[:16],
        event.get("protocol", "?"),
        event.get("attack_types", "none"),
    )

    # Call Anthropic API with DEEP model
    t0 = time.time()
    try:
        client = _get_client()
        message = client.messages.create(
            model=ANTHROPIC_DEEP_MODEL,
            max_tokens=ANTHROPIC_MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        elapsed_ms = int((time.time() - t0) * 1000)
        raw_text = message.content[0].text

        # Parse JSON response
        try:
            result = json.loads(raw_text)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code block
            import re

            m = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw_text, re.DOTALL)
            if m:
                result = json.loads(m.group(1))
            else:
                logger.warning("Claude returned non-JSON for %s: %s", event_id[:16], raw_text[:200])
                result = {
                    "error": "non-JSON response",
                    "raw_response": raw_text[:2000],
                    "verdict": "UNKNOWN",
                }

        # Add metadata
        result["_meta"] = {
            "model": ANTHROPIC_DEEP_MODEL,
            "mode": "deep",
            "elapsed_ms": elapsed_ms,
            "input_tokens": message.usage.input_tokens,
            "output_tokens": message.usage.output_tokens,
            "event_id": event_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        # Preserve full raw response text
        result["_raw_response"] = raw_text

        logger.info(
            "Claude analysis complete for %s → %s (confidence=%s, %dms, tokens: %d in / %d out)",
            event_id[:16],
            result.get("verdict", "?"),
            result.get("confidence", "?"),
            elapsed_ms,
            message.usage.input_tokens,
            message.usage.output_tokens,
        )

        # Store result
        if store:
            _store_result(event_id, result, event=event)

            # If Claude suggested a rule, write it to ai_analysis suggested columns
            sr = result.get("suggested_rule")
            if sr and isinstance(sr, dict) and sr.get("rule_name") and sr.get("regex_pattern"):
                _store_suggested_rule(event_id, sr, result)

        return result

    except Exception as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        logger.error("Claude analysis failed for %s (%dms): %s", event_id[:16], elapsed_ms, e)
        return {"error": str(e), "elapsed_ms": elapsed_ms}


# ---------------------------------------------------------------------------
# Batch analysis (for auto mode)
# ---------------------------------------------------------------------------


def analyze_batch(event_ids: list, store: bool = True) -> list:
    """
    Analyze multiple events sequentially.
    Only works when AUTO_EXTERNAL_AI is True.
    Returns list of results.
    """
    if not is_auto_enabled():
        return [{"error": "AUTO_EXTERNAL_AI is disabled"}]

    results = []
    for eid in event_ids:
        result = analyze_event(eid, store=store)
        results.append(result)
        # Small delay between calls to be respectful of rate limits
        time.sleep(0.5)

    return results


# ---------------------------------------------------------------------------
# CLI for testing
# ---------------------------------------------------------------------------


def main() -> int:
    """Claude backend diagnostics from the shell (``python -m honeylens.analysis.claude_analyzer``)."""
    from honeylens.logging_setup import setup_logging

    setup_logging()

    print("Claude Analyzer")
    print(f"  USE_EXTERNAL_AI:  {USE_EXTERNAL_AI}")
    print(f"  AUTO_EXTERNAL_AI: {AUTO_EXTERNAL_AI}")
    print(f"  Model:            {ANTHROPIC_MODEL}")
    print(f"  API Key:          {'configured' if ANTHROPIC_API_KEY else 'NOT SET'}")
    print(f"  Available:        {is_claude_available()}")
    print(f"  Auto enabled:     {is_auto_enabled()}")
    print()

    if len(sys.argv) > 1:
        eid = sys.argv[1]
        print(f"Analyzing event: {eid}")
        result = analyze_event(eid, store="--no-store" not in sys.argv)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Usage: python claude_analyzer.py <event_id> [--no-store]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
