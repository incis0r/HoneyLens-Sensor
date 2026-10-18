"""Capture of request bodies from honeypot traffic.

Bodies are recorded for every request that carries one. This started life restricted to
the Model Context Protocol paths — MCP servers are being swept hard across the fleet and
we were logging `body_len=241` while discarding the JSON-RPC message that was the whole
point — and was widened on 2026-08-16 to all captured connections, because the same
argument applies to every protocol: the body is what the attacker actually sent.

**Bodies are stored verbatim. Credentials are deliberately not redacted here.**

An earlier version masked anything password-shaped. That was wrong for a honeypot, and
the reasoning is worth keeping because it will look like an oversight to the next reader:

* The captured credential *is* the evidence. Ranking the usernames and passwords actually
  being tried is a first-class question, and it cannot be answered from
  `password=<redacted:7>`.
* On a honeypot inside a client network, a real employee credential arriving in a POST
  dates the compromise — which breach corpus it came from, and therefore roughly when
  the account was taken. Masking it destroys exactly the fact that makes the event worth
  an incident report.

Nothing here *extracts* credentials into a separate store; the body is simply kept whole,
and analysis happens later against the material.

What that obligation implies downstream:

* This data is sensitive by construction. It is attacker-supplied, and on client sensors
  it may contain a real person's password. Treat sensor databases accordingly.
* **Redaction belongs at publication, not at capture.** `redact()` stays in this module
  for that use — `publishing/` is where it should be applied, before anything reaches a
  blog post or a customer-facing report.

The one limit that remains is size. `MAX_CAPTURE` is generous, but a decoy that will
write an unbounded attacker-chosen string to disk is a way to fill the disk; anything
beyond it is truncated and flagged, and the true length is always reported. Retention
timers are what keep the cost bounded — verify `sensor-db-retention.timer` is enabled
before assuming a sensor can absorb this.
"""

from __future__ import annotations

import base64
import os
import re
from typing import Any

# Generous: large enough that a real request — an exploit chain, a serialised payload, a
# firmware blob's first pages — arrives intact, small enough that one client cannot
# choose how much disk we spend. Override with HONEYPOT_BODY_CAPTURE_BYTES.
MAX_CAPTURE = int(os.environ.get("HONEYPOT_BODY_CAPTURE_BYTES", 64 * 1024))

# Paths where the body is the point. Matched case-insensitively against the request path.
CAPTURE_PATHS = re.compile(
    r"^/(?:mcp|sse|api/mcp|messages|jsonrpc|rpc)(?:[/?]|$)"
    r"|^/\.well-known/mcp",
    re.I,
)

# Content types that identify the traffic on their own. Deliberately NOT plain
# `application/json`: that would capture every JSON body on every path — ordinary
# Kubernetes API calls included — which is a much larger change than the one asked for,
# and a much larger pile of attacker-controlled text to hold. MCP arrives on the paths
# above; these two types are for when it arrives somewhere we did not anticipate.
CAPTURE_TYPES = ("application/json-rpc", "text/event-stream")

_SECRET_RE = re.compile(
    r"(?i)"
    r"(\"?(?:authorization|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
    r"bearer|secret|password|passwd|pwd|client[_-]?secret|private[_-]?key|"
    r"session[_-]?token|auth[_-]?token)\"?\s*[:=]\s*\"?)"
    r"([^\"'\s,}&]{4,})"
)

_BEARER_RE = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._\-+/=]{8,})")
# JWTs and long opaque blobs can appear as bare values with no key naming them.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9._\-]{20,}")


def redact(text: str) -> str:
    """Mask credential-shaped values, keeping the structure around them.

    **Not applied at capture** — see the module docstring. This exists for the
    publication path, where a captured body may end up in a blog post or a customer
    report and the credential must not travel with it. Length is preserved as a hint
    because "a 64-character token" and "the string 'x'" mean different things.
    """

    def _mask(m):
        return f"{m.group(1)}<redacted:{len(m.group(2))}>"

    text = _SECRET_RE.sub(_mask, text)
    text = _BEARER_RE.sub(lambda m: f"Bearer <redacted:{len(m.group(1))}>", text)
    text = _JWT_RE.sub(lambda m: f"<redacted-jwt:{len(m.group(0))}>", text)
    return text


def should_capture(path: str, content_type: str = "") -> bool:
    """Every body is captured. Kept as a function because callers use it, and because
    narrowing this again later should be a one-line change rather than a rewrite.

    `CAPTURE_PATHS` and `CAPTURE_TYPES` remain as the record of what was considered
    high-value when the capture was selective, and are still used to mark those events.
    """
    return True


def is_high_value(path: str, content_type: str = "") -> bool:
    """True for traffic whose body was worth capturing even under the narrow policy."""
    path = (path or "").split("#", 1)[0]
    if CAPTURE_PATHS.search(path):
        return True
    ct = (content_type or "").lower()
    return any(t in ct for t in CAPTURE_TYPES)


def capture(body, path: str = "", content_type: str = "", max_capture: int | None = None) -> dict:
    """Return the fields describing this body: always a length, a sample when useful.

    Returns a dict so callers can splat it into their event without caring which case
    applied. Binary bodies are reported as such rather than mangled into replacement
    characters — a byte count and "binary" is honest, a screenful of U+FFFD is not.

    ``max_capture`` overrides the global ``MAX_CAPTURE`` ceiling for this one body, so a
    decoy whose stage-two payloads are larger than the default (e.g. SharePoint's ~535 KB
    forged ``__VIEWSTATE``) can keep a per-honeypot budget without a fleet-wide bump.
    """
    if isinstance(body, str):
        raw = body.encode("utf-8", "replace")
    else:
        raw = body or b""

    limit = MAX_CAPTURE if max_capture is None else max_capture
    out: dict[str, Any] = {"body_len": len(raw)}
    if not raw:
        return out

    sample = raw[:limit]
    out["body_truncated"] = len(raw) > limit
    if is_high_value(path, content_type):
        out["body_high_value"] = True

    try:
        # Verbatim. See the module docstring: the credential is the evidence.
        out["body_sample"] = sample.decode("utf-8")
    except UnicodeDecodeError:
        # Binary is kept rather than dropped — an exploit payload is not text — but it
        # is base64 so it survives JSON and is obviously not a string to read.
        out["body_sample_b64"] = base64.b64encode(sample).decode("ascii")
        out["body_encoding"] = "binary"
    return out
