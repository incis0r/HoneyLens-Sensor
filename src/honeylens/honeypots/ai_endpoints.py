"""OpenAI/Ollama-shaped bait for the ordinary HTTP honeypot ports.

Why this exists: scanners hunting for exposed AI endpoints probe by **path on whatever
HTTP port is open** — 90 days of sensor data shows `/v1/models`, `/v1/chat/completions`
and `/api/generate` arriving on :80, :8080 and even :30000 — while our LLM honeypot sits
on a dedicated :3080 that nobody asks for. The probes were landing on honeypots that
answered 404, so an entire class of AI-directed reconnaissance produced nothing.

This module gives those paths a plausible answer wherever they arrive. Each response also
carries an AI canary (Idea 52): a scanner that pipes the reply into a model is exactly the
actor the canary exists to catch, and a discovery probe is the first thing such a pipeline
reads. Identity matches the LLM honeypot (`CorpAssist AI` / `nexova-assistant-v2`) so a
scanner that finds the model list here and then talks to :3080 sees one consistent system.

Deliberately self-contained: it never calls Ollama. A discovery probe expects an immediate
answer, and the honeypots that mount this (nginx, K8s) must not block on a model backend.
"""

from __future__ import annotations

import json
import time

try:
    from honeylens.intelligence import ai_canary
except ImportError:  # canary is optional
    ai_canary = None  # type: ignore[assignment]  # optional module, idiom from the mypy docs

MODEL_NAME = "nexova-assistant-v2"
MODEL_OWNER = "nexova-technologies"

# Paths worth answering. Kept explicit rather than a prefix match so a stray /v1/... on an
# unrelated app is not mistaken for AI reconnaissance.
OPENAI_PATHS = {
    "/v1/models",
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
}
OLLAMA_PATHS = {
    "/api/tags",
    "/api/generate",
    "/api/chat",
    "/api/show",
}
AI_PATHS = OPENAI_PATHS | OLLAMA_PATHS

ATTACK_TYPE = "AI_ENDPOINT_PROBE"


def normalise(path: str) -> str:
    """Strip the query string and trailing slash so /v1/models?x=1 still matches."""
    p = (path or "").split("?", 1)[0].split("#", 1)[0]
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p.lower()


def is_ai_endpoint(path: str) -> bool:
    return normalise(path) in AI_PATHS


def _models_payload():
    created = 1735689600  # fixed: a model list that changes every poll looks fake
    return {
        "object": "list",
        "data": [
            {"id": MODEL_NAME, "object": "model", "created": created, "owned_by": MODEL_OWNER},
            {
                "id": "nexova-embed-v1",
                "object": "model",
                "created": created,
                "owned_by": MODEL_OWNER,
            },
        ],
    }


def _ollama_tags_payload():
    return {
        "models": [
            {
                "name": f"{MODEL_NAME}:latest",
                "model": f"{MODEL_NAME}:latest",
                "modified_at": "2026-02-11T09:14:22.113Z",
                "size": 4920753328,
                "details": {
                    "family": "llama",
                    "parameter_size": "8B",
                    "quantization_level": "Q4_K_M",
                },
            },
        ]
    }


_ASSISTANT_REPLY = (
    "I can help with internal documentation, deployment runbooks and access requests. "
    "What would you like to look at?"
)


def _chat_payload(model):
    return {
        "id": "chatcmpl-{}".format(format(int(time.time() * 1000) % 0xFFFFFFFF, "08x")),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model or MODEL_NAME,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": _ASSISTANT_REPLY},
            }
        ],
        "usage": {"prompt_tokens": 24, "completion_tokens": 21, "total_tokens": 45},
    }


def _ollama_generate_payload(model):
    return {
        "model": model or f"{MODEL_NAME}:latest",
        "created_at": "2026-02-11T09:14:22.113Z",
        "response": _ASSISTANT_REPLY,
        "done": True,
        "done_reason": "stop",
    }


def _requested_model(body):
    if not body:
        return None
    try:
        data = json.loads(body if isinstance(body, str) else body.decode("utf-8", "replace"))
        return data.get("model") if isinstance(data, dict) else None
    except (ValueError, AttributeError):
        return None


def handle(method, path, host="", src_ip="", body=b""):
    """Answer an AI-endpoint probe.

    Returns ``(status, payload_dict, headers, event)`` or ``None`` when the path is not
    one of ours. ``headers`` carries the canary when it is enabled; ``event`` describes
    the probe for the caller's own log, since each honeypot owns its event schema.
    """
    p = normalise(path)
    if p not in AI_PATHS:
        return None

    method = (method or "GET").upper()
    model = _requested_model(body)

    if p == "/v1/models":
        status, payload = 200, _models_payload()
    elif p == "/api/tags":
        status, payload = 200, _ollama_tags_payload()
    elif p == "/api/show":
        status, payload = 200, {"license": "proprietary", "details": {"family": "llama"}}
    elif p in ("/v1/chat/completions", "/v1/completions"):
        # OpenAI answers a GET on a POST-only route with an error, and a scanner that
        # sees the right error learns the endpoint is real.
        if method == "GET":
            status = 405
            payload = {
                "error": {
                    "message": "Not allowed. You must use POST on this endpoint.",
                    "type": "invalid_request_error",
                    "param": None,
                    "code": None,
                }
            }
        else:
            status, payload = 200, _chat_payload(model)
    elif p == "/v1/embeddings":
        status = 200 if method == "POST" else 405
        payload = (
            {
                "object": "list",
                "model": model or "nexova-embed-v1",
                "data": [
                    {"object": "embedding", "index": 0, "embedding": [0.0012, -0.0043, 0.0071]}
                ],
                "usage": {"prompt_tokens": 8, "total_tokens": 8},
            }
            if status == 200
            else {
                "error": {
                    "message": "Not allowed. You must use POST on this endpoint.",
                    "type": "invalid_request_error",
                }
            }
        )
    else:  # /api/generate, /api/chat
        status, payload = 200, _ollama_generate_payload(model)

    headers, nonce = {}, None
    if (
        ai_canary is not None
        and ai_canary.enabled()
        and ai_canary.carrier_enabled("AI_ENDPOINT_BAIT")
    ):
        nonce, headers = ai_canary.issue(
            "ai-endpoint", p, host, origin_src_ip=src_ip, context="AI model endpoint response"
        )

    event = {
        "action": "ai_endpoint_probe",
        "attack_type": ATTACK_TYPE,
        "rule_name": "ai_endpoint_{}".format(p.strip("/").replace("/", "_")),
        "path": p,
        "method": method,
        "flavour": "ollama" if p in OLLAMA_PATHS else "openai",
        "model_requested": model,
        "canary_nonce": nonce,
        "origin_protocol": "ai-endpoint",
    }
    return status, payload, headers, event
