"""
analysis/openai_analyzer.py — OpenAI-backed triage + deep analysis
===================================================================

Public surface intentionally mirrors `analysis.claude_analyzer` so the
ai_analyzer daemon can swap backends with a single dispatch change.
Supporting infrastructure (event load, result store, hunting-list,
budget check, prompts) is reused from `claude_analyzer` — only the
LLM API call and the cost-pricing table are OpenAI-specific.

Config (env):
    AI_PROVIDER             — openai (default) or nous
    OPENAI_API_KEY          — required for AI_PROVIDER=openai
    NOUS_API_KEY            — required for AI_PROVIDER=nous
    OPENAI_TRIAGE_MODEL     — default: gpt-4.1-mini
    OPENAI_DEEP_MODEL       — default: gpt-5-mini
    OPENAI_TIMEOUT          — default: 60
    OPENAI_MAX_TOKENS       — default: 2048

The module reuses the global cost-tracking + budget functions defined in
claude_analyzer (the same daily / monthly caps and `claude_analysis_log`
table — log rows are tagged with the actual model used).
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from honeylens.analysis import claude_analyzer as _ca
from honeylens.env import env

logger = logging.getLogger("openai-analyzer")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

AI_PROVIDER = env("AI_PROVIDER", "openai").strip().lower()
_IS_NOUS = AI_PROVIDER == "nous"
OPENAI_API_KEY = env("NOUS_API_KEY" if _IS_NOUS else "OPENAI_API_KEY", "").strip()
OPENAI_TRIAGE_MODEL = env(
    "NOUS_TRIAGE_MODEL" if _IS_NOUS else "OPENAI_TRIAGE_MODEL",
    "qwen/qwen3-30b-a3b-instruct-2507" if _IS_NOUS else "gpt-4.1-mini",
).strip()
OPENAI_DEEP_MODEL = env(
    "NOUS_DEEP_MODEL" if _IS_NOUS else "OPENAI_DEEP_MODEL",
    "qwen/qwen3-30b-a3b-instruct-2507" if _IS_NOUS else "gpt-5-mini",
).strip()
OPENAI_TIMEOUT = env("OPENAI_TIMEOUT", 60, cast=int)
OPENAI_MAX_TOKENS = env("OPENAI_MAX_TOKENS", 2048, cast=int)

# Optional per-stage base-URL + API-key overrides. When set, the triage stage
# uses a *separate* OpenAI-compatible client (typically a local vLLM /
# llama-cpp-server / TGI endpoint) while the deep stage keeps using the
# default OpenAI cloud client. Useful for offloading high-volume cheap
# classification to a local model while reserving cloud reasoning models
# (gpt-5-mini, o-series) for the smaller deep-analysis stage.
#
# Example (PROD .env):
#   OPENAI_TRIAGE_BASE_URL = "https://llm.internal.example/v1"
#   OPENAI_TRIAGE_API_KEY  = "sk-..."
#   OPENAI_TRIAGE_MODEL    = "qwen2.5-coder-7b-gptq-int8"
#   OPENAI_DEEP_MODEL      = "gpt-5-mini"   # still hits api.openai.com
_NOUS_BASE_URL = env("NOUS_BASE_URL", "https://inference-api.nousresearch.com/v1").strip()
OPENAI_TRIAGE_BASE_URL = env("OPENAI_TRIAGE_BASE_URL", _NOUS_BASE_URL if _IS_NOUS else "").strip()
OPENAI_TRIAGE_API_KEY = env("OPENAI_TRIAGE_API_KEY", "").strip()
OPENAI_DEEP_BASE_URL = env("OPENAI_DEEP_BASE_URL", _NOUS_BASE_URL if _IS_NOUS else "").strip()

# Explicit local-backend marker. Set to true when the base URL hostname
# resolves to a private/internal IP via /etc/hosts but the hostname
# itself doesn't pattern-match as internal (e.g. lab DNS using a
# public TLD like *.com.pl). Forces _backend_is_local() to True for
# both stages, so budget tracking is skipped and cloud cost rates
# don't get applied to free local calls.
OPENAI_BACKEND_LOCAL = env("OPENAI_BACKEND_LOCAL", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
OPENAI_DEEP_API_KEY = env("OPENAI_DEEP_API_KEY", "").strip()

# Per-million-token pricing (input, output) — keep loose; runtime-overridable
# via OPENAI_PRICE_<family>_IN / _OUT env. Numbers as of 2026-Q1 listings.
# Local models (self-hosted vLLM / Ollama / etc.) have a $0 entry so cost
# tracking accounts them at zero rather than falling back to gpt-4.1-mini.
_OPENAI_PRICING = {
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-5-mini": (0.25, 2.00),
    "gpt-5-nano": (0.05, 0.40),
    # Local / self-hosted models (vLLM endpoint, etc.)
    "qwen2.5-coder-7b-gptq-int8": (0.0, 0.0),
    "qwen2.5:3b": (0.0, 0.0),
    "qwen2.5:7b": (0.0, 0.0),
    "qwen2.5:14b": (0.0, 0.0),
    # Nous Inference API catalog, checked 2026-10-03.
    "qwen/qwen3-30b-a3b-instruct-2507": (0.05, 0.19),
}

# Two distinct lazy-init slots so a single process can talk to two different
# OpenAI-compatible endpoints simultaneously.
_triage_client = None
_deep_client = None


# ---------------------------------------------------------------------------
# Client + availability
# ---------------------------------------------------------------------------


def _new_openai_client(api_key: str, base_url: str = ""):
    """Construct an OpenAI client, optionally pointing at a custom endpoint."""
    from openai import OpenAI

    kwargs = {"api_key": api_key, "timeout": OPENAI_TIMEOUT}
    if base_url:
        kwargs["base_url"] = base_url
    return OpenAI(**kwargs)


def _get_triage_client():
    """Lazy-init the triage OpenAI client.

    Uses OPENAI_TRIAGE_BASE_URL + OPENAI_TRIAGE_API_KEY when set (local /
    self-hosted endpoint), otherwise falls back to the default OpenAI
    cloud client shared with deep analysis.
    """
    global _triage_client
    if _triage_client is not None:
        return _triage_client
    try:
        if OPENAI_TRIAGE_BASE_URL:
            key = OPENAI_TRIAGE_API_KEY or OPENAI_API_KEY
            if not key:
                raise RuntimeError(
                    "OPENAI_TRIAGE_BASE_URL is set but neither "
                    "OPENAI_TRIAGE_API_KEY nor OPENAI_API_KEY is configured"
                )
            _triage_client = _new_openai_client(key, OPENAI_TRIAGE_BASE_URL)
            logger.info(
                "OpenAI triage client → %s (model=%s)", OPENAI_TRIAGE_BASE_URL, OPENAI_TRIAGE_MODEL
            )
        else:
            if not OPENAI_API_KEY:
                raise RuntimeError("OPENAI_API_KEY not configured")
            _triage_client = _new_openai_client(OPENAI_API_KEY)
            logger.info("OpenAI triage client → api.openai.com (model=%s)", OPENAI_TRIAGE_MODEL)
        return _triage_client
    except ImportError:
        raise RuntimeError(
            "openai package not installed. Run: /opt/sensor/venv/bin/pip install openai"
        ) from None


def _get_deep_client():
    """Lazy-init the deep OpenAI client. Same pattern as triage but with
    OPENAI_DEEP_BASE_URL / OPENAI_DEEP_API_KEY overrides."""
    global _deep_client
    if _deep_client is not None:
        return _deep_client
    try:
        if OPENAI_DEEP_BASE_URL:
            key = OPENAI_DEEP_API_KEY or OPENAI_API_KEY
            if not key:
                raise RuntimeError(
                    "OPENAI_DEEP_BASE_URL is set but neither "
                    "OPENAI_DEEP_API_KEY nor OPENAI_API_KEY is configured"
                )
            _deep_client = _new_openai_client(key, OPENAI_DEEP_BASE_URL)
            logger.info(
                "OpenAI deep client → %s (model=%s)", OPENAI_DEEP_BASE_URL, OPENAI_DEEP_MODEL
            )
        else:
            if not OPENAI_API_KEY:
                raise RuntimeError("OPENAI_API_KEY not configured")
            _deep_client = _new_openai_client(OPENAI_API_KEY)
            logger.info("OpenAI deep client → api.openai.com (model=%s)", OPENAI_DEEP_MODEL)
        return _deep_client
    except ImportError:
        raise RuntimeError(
            "openai package not installed. Run: /opt/sensor/venv/bin/pip install openai"
        ) from None


def _get_client():
    """Backward-compat shim — historical callers expected one client.
    Defaults to the deep client (which keeps the cloud OpenAI behaviour
    for any code that doesn't yet know about the triage/deep split)."""
    return _get_deep_client()


def is_openai_available() -> bool:
    if not _ca.USE_EXTERNAL_AI:
        return False
    if not OPENAI_API_KEY:
        return False
    try:
        import openai  # noqa: F401

        return True
    except ImportError:
        return False


_LOCAL_URL_RE = re.compile(
    r"^https?://("
    r"127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|"  # RFC1918 + loopback
    r"localhost|"
    r"[^/]+\.(?:local|internal|lan|corp|home|arpa)(?:[/:]|$)"  # internal TLDs
    r")",
    re.IGNORECASE,
)


def _backend_is_local(stage: str) -> bool:
    """Return True when the configured OpenAI-compatible endpoint for `stage`
    is a local / internal LLM server (vLLM, llama.cpp, TGI on private IPs).

    Local backends are free at the wire — they don't bill against the cloud
    daily/monthly budget cap. The `gpt-4.1-mini` pricing fallback in
    estimate_cost() otherwise treats every self-hosted or local-Ollama call as if it
    were a paid OpenAI call, which silently drains the budget and triggers
    cap-block warnings ("Budget exceeded: $5.00 >= $5.00") on free traffic.
    A production deployment hit this 2026-05-28 after the 2026-05-27 self-hosted vLLM cutover.

    Three detection paths, in order:
      1. Explicit override env `OPENAI_BACKEND_LOCAL=true` — for setups
         where the URL hostname resolves to a private IP via /etc/hosts
         but isn't a known-internal TLD (e.g., `llm.internal.example` →
         192.0.2.193). The operator opts in.
      2. URL pattern: RFC1918 / loopback / `*.local|internal|lan|corp|
         home|arpa` hostnames matched by _LOCAL_URL_RE.
      3. Fallback: cloud (paid).
    """
    if OPENAI_BACKEND_LOCAL:
        return True
    url = OPENAI_TRIAGE_BASE_URL if stage == "triage" else OPENAI_DEEP_BASE_URL
    if not url:
        return False  # default endpoint is api.openai.com (paid)
    return bool(_LOCAL_URL_RE.match(url))


def estimate_cost(
    model: str, input_tokens: int, output_tokens: int, stage: str | None = None
) -> float:
    """USD cost estimate; matches signature of claude_analyzer.estimate_cost.

    Returns 0.0 when the call routed to a local/internal endpoint (see
    _backend_is_local). The stage argument is optional for backward compat
    with the historical 3-arg signature.
    """
    if stage and _backend_is_local(stage):
        return 0.0
    key = model.lower()
    rates = _OPENAI_PRICING.get(key)
    if rates is None:
        # Fall back to gpt-4.1-mini rates for unknown OpenAI models
        rates = _OPENAI_PRICING["gpt-4.1-mini"]
    in_rate, out_rate = rates
    return (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000


# ---------------------------------------------------------------------------
# Core completion call (shared between triage + deep)
# ---------------------------------------------------------------------------


def _is_reasoning_model(model: str) -> bool:
    """gpt-5* and o-series use max_completion_tokens instead of max_tokens."""
    m = model.lower()
    return m.startswith("gpt-5") or m.startswith("o1") or m.startswith("o3") or m.startswith("o4")


def _call_openai(
    model: str, system_prompt: str, user_prompt: str, max_tokens: int, *, stage: str = "deep"
) -> tuple[str, int, int]:
    """Single OpenAI chat completion. Returns (text, input_tokens, output_tokens).

    The `stage` parameter selects which client to use ("triage" or "deep").
    With the per-stage base-URL split a local model can run triage while
    a cloud reasoning model runs deep — the two calls hit completely
    separate endpoints.

    Some local OpenAI-compatible servers (older vLLM versions, llama.cpp's
    server) don't accept the `response_format` JSON-mode parameter and
    return HTTP 400. We retry once without it on that specific failure;
    the prompt already contains an explicit "Respond in JSON only."
    instruction so the model should still emit JSON.
    """
    client = _get_triage_client() if stage == "triage" else _get_deep_client()
    # JSON mode requires the literal word "JSON" in the prompt
    if "JSON" not in system_prompt and "json" not in system_prompt:
        system_prompt = system_prompt + "\n\nRespond in JSON only."
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
    }
    if _is_reasoning_model(model):
        # Reasoning models spend hidden tokens on chain-of-thought before
        # producing visible output, so the budget must be enlarged or the
        # answer comes back empty. 8k floor for deep, scaled up for safety.
        kwargs["max_completion_tokens"] = max(max_tokens, 8192)
    else:
        kwargs["max_tokens"] = max_tokens
    try:
        response = client.chat.completions.create(**kwargs)
    except Exception as e:
        # Local OpenAI-compatible servers often don't implement
        # response_format JSON-mode. Detect and retry without it.
        msg = str(e).lower()
        if (
            "response_format" in msg
            or "json_object" in msg
            or "json_mode" in msg
            or "unsupported" in msg
        ):
            logger.info(
                "retrying %s call without response_format (server doesn't support JSON-mode)", stage
            )
            kwargs.pop("response_format", None)
            response = client.chat.completions.create(**kwargs)
        else:
            raise
    text = response.choices[0].message.content or ""
    # Some servers return usage with different attribute names or omit it.
    usage = getattr(response, "usage", None)
    in_tok = getattr(usage, "prompt_tokens", 0) if usage else 0
    out_tok = getattr(usage, "completion_tokens", 0) if usage else 0
    return text, in_tok, out_tok


def _parse_json_response(raw_text: str, event_id: str, mode: str) -> dict[str, Any]:
    """Parse JSON response, tolerating markdown fences."""
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        m = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw_text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
    logger.warning("OpenAI %s non-JSON for %s: %s", mode, event_id[:16], raw_text[:200])
    return {"error": "non-JSON", "raw_response": raw_text[:2000], "verdict": "UNKNOWN"}


# ---------------------------------------------------------------------------
# Public API — mirrors claude_analyzer.triage_event / analyze_event
# ---------------------------------------------------------------------------


def triage_event(event_id: str, store: bool = True) -> dict[str, Any]:
    """Fast triage using OPENAI_TRIAGE_MODEL (default gpt-4.1-mini)."""
    if not _ca.USE_EXTERNAL_AI:
        return {"error": "External AI is disabled (USE_EXTERNAL_AI = False)"}
    if not OPENAI_API_KEY:
        return {"error": "OPENAI_API_KEY not configured"}

    # Budget cap only applies to cloud-paid endpoints. Local OpenAI-compatible
    # backends (self-hosted vLLM, local Ollama via OPENAI_*_BASE_URL) are free and
    # should bypass both the pre-call check and the post-call cost recording.
    if not _backend_is_local("triage"):
        allowed, reason = _ca.check_budget()
        if not allowed:
            logger.warning("OpenAI triage BLOCKED for %s: %s", event_id[:16], reason)
            return {"error": "Budget exceeded", "detail": reason, "budget_blocked": True}

    event = _ca._load_event(event_id)
    if not event:
        return {"error": f"Event {event_id} not found"}

    # Suricata short-circuit (same logic as claude_analyzer)
    if event.get("source") == "suricata" or event.get("suricata_sid"):
        if not _ca._is_hunting_ip(event.get("src_ip", "")):
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

    prompt = _ca._build_prompt(event)
    logger.info(
        "OpenAI TRIAGE (%s) for %s (%s, %s)",
        OPENAI_TRIAGE_MODEL,
        event_id[:16],
        event.get("protocol", "?"),
        event.get("attack_types", "none"),
    )

    t0 = time.time()
    try:
        raw_text, in_tok, out_tok = _call_openai(
            OPENAI_TRIAGE_MODEL, _ca.TRIAGE_PROMPT, prompt, 1024, stage="triage"
        )
        elapsed_ms = int((time.time() - t0) * 1000)

        result = _parse_json_response(raw_text, event_id, "triage")
        result["_meta"] = {
            "model": OPENAI_TRIAGE_MODEL,
            "mode": "triage",
            "elapsed_ms": elapsed_ms,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "event_id": event_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        result["_raw_response"] = raw_text

        est = estimate_cost(OPENAI_TRIAGE_MODEL, in_tok, out_tok, stage="triage")
        logger.info(
            "OpenAI TRIAGE %s → %s (conf=%s, %dms, %d+%d tok, ~$%.4f)",
            event_id[:16],
            result.get("verdict", "?"),
            result.get("confidence", "?"),
            elapsed_ms,
            in_tok,
            out_tok,
            est,
        )

        if store:
            _ca._store_result(event_id, result, event=event)
            sr = result.get("suggested_rule")
            if sr and isinstance(sr, dict) and sr.get("rule_name") and sr.get("regex_pattern"):
                _ca._store_suggested_rule(event_id, sr, result)
        return result

    except Exception as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        logger.error("OpenAI triage failed for %s (%dms): %s", event_id[:16], elapsed_ms, e)
        return {"error": str(e), "elapsed_ms": elapsed_ms}


def analyze_event(event_id: str, store: bool = True) -> dict[str, Any]:
    """Deep analysis using OPENAI_DEEP_MODEL (default gpt-5-mini)."""
    if not _ca.USE_EXTERNAL_AI:
        return {"error": "External AI is disabled (USE_EXTERNAL_AI = False)"}
    if not OPENAI_API_KEY:
        return {"error": "OPENAI_API_KEY not configured"}

    # Budget cap only applies to cloud-paid endpoints — see triage_event() comment.
    if not _backend_is_local("deep"):
        allowed, reason = _ca.check_budget()
        if not allowed:
            logger.warning("OpenAI deep BLOCKED for %s: %s", event_id[:16], reason)
            return {"error": "Budget exceeded", "detail": reason, "budget_blocked": True}

    event = _ca._load_event(event_id)
    if not event:
        return {"error": f"Event {event_id} not found"}

    prompt = _ca._build_prompt(event)
    logger.info(
        "OpenAI DEEP (%s) for %s (%s, %s)",
        OPENAI_DEEP_MODEL,
        event_id[:16],
        event.get("protocol", "?"),
        event.get("attack_types", "none"),
    )

    t0 = time.time()
    try:
        raw_text, in_tok, out_tok = _call_openai(
            OPENAI_DEEP_MODEL, _ca.SYSTEM_PROMPT, prompt, OPENAI_MAX_TOKENS, stage="deep"
        )
        elapsed_ms = int((time.time() - t0) * 1000)

        result = _parse_json_response(raw_text, event_id, "deep")
        result["_meta"] = {
            "model": OPENAI_DEEP_MODEL,
            "mode": "deep",
            "elapsed_ms": elapsed_ms,
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "event_id": event_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        result["_raw_response"] = raw_text

        est = estimate_cost(OPENAI_DEEP_MODEL, in_tok, out_tok, stage="deep")
        logger.info(
            "OpenAI DEEP %s → %s (conf=%s, %dms, %d+%d tok, ~$%.4f)",
            event_id[:16],
            result.get("verdict", "?"),
            result.get("confidence", "?"),
            elapsed_ms,
            in_tok,
            out_tok,
            est,
        )

        if store:
            _ca._store_result(event_id, result, event=event)
            sr = result.get("suggested_rule")
            if sr and isinstance(sr, dict) and sr.get("rule_name") and sr.get("regex_pattern"):
                _ca._store_suggested_rule(event_id, sr, result)
        return result

    except Exception as e:
        elapsed_ms = int((time.time() - t0) * 1000)
        logger.error("OpenAI deep failed for %s (%dms): %s", event_id[:16], elapsed_ms, e)
        return {"error": str(e), "elapsed_ms": elapsed_ms}
