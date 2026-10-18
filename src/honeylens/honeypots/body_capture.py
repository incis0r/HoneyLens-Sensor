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

import asyncio
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


# How much of a captured body to carry in the `payload` string itself.
#
# `payload` is the field that shows in the event list, in exports, in reports and in a
# plain SQL grep; metadata is where the body is kept in full. Carrying only `body_len`
# there was a real defect twice over: the nginx decoy stored `POST / body_len=702` and
# discarded the 702 bytes (fixed 2026-08-30), and the honeypotng family stored
# `POST /index.php` for a 20 KB exploitation POST whose body it had already captured into
# metadata (found 2026-10-25 — three PHP2Shell attempts were labelled as a WAGO exploit
# because the port was all the classifier had).
#
# Bounded because `payload` is stored on every event and a decoy that writes an
# attacker-chosen string of unbounded length is a way to fill the disk. The full body
# stays in metadata and in `full_payload`, so nothing is lost by the cap.
PAYLOAD_BODY_BYTES = int(os.environ.get("HONEYPOT_PAYLOAD_BODY_BYTES", 8192))


def payload_with_body(summary: str, fields: dict, limit: int | None = None) -> str:
    """Append a captured body to a payload summary, bounded and marked.

    `fields` is the dict `capture()` returned (or any dict carrying its keys). The
    summary line is kept first: reports and greps already key on the
    `METHOD path body_len=N` shape.

    A binary body is named rather than pasted — base64 in the middle of a payload string
    reads as corruption, and the bytes are in `full_payload` where they are useful.
    """
    limit = PAYLOAD_BODY_BYTES if limit is None else limit
    body = fields.get("body_sample")
    if not body:
        b64 = fields.get("body_sample_b64")
        if b64:
            return (
                f"{summary}\n...[binary body, {fields.get('body_len', 0)} bytes; "
                "base64 in metadata, bytes in full_payload]"
            )
        return summary
    shown = body[:limit]
    out = summary + "\n" + shown
    if len(body) > len(shown):
        out += f"\n...[payload truncated at {limit} bytes; full body in metadata]"
    elif fields.get("body_truncated"):
        # The capture layer itself already cut it — say so rather than implying this is
        # the whole request.
        out += "\n...[body truncated by capture]"
    return out


def raw_from_fields(fields: dict) -> bytes | None:
    """The captured bytes back out of a capture dict, for the `full_payload` column.

    A decoy that captured a body into its event has the evidence; before 2026-10-25 the
    legacy ingest path dropped it on the floor (`"raw": None`, hardcoded) and every
    content hunt over `payload`/`full_payload` came back clean on 133 052 rows. This is
    the recovery: text bodies re-encode to the bytes we held, binary bodies come back
    from base64 unchanged.

    Returns ``None`` when there is nothing to store, so callers can test it directly.
    `body_len` alone is not enough — a length is not a body.
    """
    b64 = fields.get("body_sample_b64")
    if b64:
        try:
            return base64.b64decode(b64, validate=False) or None
        except (ValueError, TypeError):
            return None
    sample = fields.get("body_sample")
    if isinstance(sample, str) and sample:
        return sample.encode("utf-8", "replace")
    if isinstance(sample, bytes) and sample:
        return sample
    return None


def _normalise_key(key: Any) -> str:
    return str(key).lower().replace("-", "").replace("_", "")


# Keys whose values are credentials, compared after `_normalise_key`. Matching is by
# EQUALITY, not substring, on purpose: the WAGO decoy emits `password_length` and
# `password_sha256_prefix` beside the captured password. Those are derived analysis
# fields, not secrets; a substring match would redact them and throw their value away
# (`passwordlength` != `password`). Do not "improve" this into `in`.
#
# The set is built THROUGH `_normalise_key`, so an entry may be written the way the key
# actually appears on the wire -- `api_key`, `x-auth-token` -- and still match. Until
# 2026-10-25 the spellings were stored already normalised (`apikey`, `clientid`) while
# only the incoming key was normalised, which made "every entry must be pre-normalised"
# an invariant the next editor had to remember: adding `api_key` in its natural spelling
# would have matched nothing and shipped an unredacted credential. Now the code enforces
# it instead.
_SECRET_KEYS = frozenset(
    _normalise_key(k)
    for k in {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "authorization",
        "api_key",
        "access_token",
        "client_secret",
        "private_key",
        "username",
        "client_id",
    }
)


def redact_structure(value: Any, extra_keys: tuple[str, ...] = ()) -> Any:
    """Mask credential-keyed values in a decoy's structured event, keeping its shape.

    This is the publication-time counterpart to `redact()` for data that is a dict, not
    text. `redact()` could not be reused: it works on text, needs a value of four or more
    characters sitting next to a key in the string, and has no notion of `username` (a
    one-character password in a dict slipped straight through it). Here the key decides,
    not the value. Dicts and lists are walked; any other value is returned unchanged.

    A masked value becomes ``<redacted:N>`` with N the length of its string form, so
    "how long was the credential" stays answerable. Capture still stores everything
    verbatim (see the module docstring); apply this where the data leaves the box.
    """
    secret = _SECRET_KEYS | {_normalise_key(k) for k in extra_keys}

    def walk(v: Any) -> Any:
        if isinstance(v, dict):
            return {
                k: f"<redacted:{len(str(x))}>" if _normalise_key(k) in secret else walk(x)
                for k, x in v.items()
            }
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return walk(value)


# ---------------------------------------------------------------------------
# Reading a whole request off a stream
# ---------------------------------------------------------------------------
# `honeypot_k8s` learned this the expensive way on 2026-10-23: dispatching as soon as
# `\r\n\r\n` appears in the buffer is the moment the *headers* are complete, not the
# request. A 20 KB PHP2Shell POST was stored with `body_len=128`, and the decoy's row sat
# 68 seconds before Suricata's alert on the same bytes — the decoy had answered and closed
# while the client was still writing. That fix was written against `asyncio.Protocol`.
#
# The stream-reader decoys had the same defect and kept it: `HTTPResponder` in
# `honeypot.py` carried the comment "may need multiple reads for large POSTs" directly
# above a single `reader.read(16384)`, and `hp_elasticsearch` read once into 8192 bytes.
# This is the shared version for them, and the header parsers below are the ones
# `honeypot_k8s` uses, so there is one implementation rather than two that drift.

REQUEST_MAX_BYTES = int(os.environ.get("HONEYPOT_REQUEST_MAX_BYTES", 256 * 1024))

# How many verbatim request bytes an event may carry in `raw_hex`. This is what
# ingest/honeypot.py decodes into the `full_payload` BYTEA column, which is itself capped
# at 64 KiB, so a larger value here would be written and then truncated downstream.
# Defined once: honeypot_k8s and honeypot_fortigate each had their own identical copy.
MAX_RAW_EVENT_BYTES = int(os.environ.get("HONEYPOT_RAW_CAPTURE_BYTES", 64 * 1024))

# How long to wait for a body the headers promised. A lying Content-Length, a slow-loris
# upload or a connection that simply stops must not leave the decoy silent: the real
# service answers, so after this we answer with whatever arrived.
BODY_WAIT_SECONDS = float(os.environ.get("HONEYPOT_BODY_WAIT_SECONDS", 10))


def content_length(head: bytes) -> int | None:
    """Declared body length from a header block, or None when none is declared.

    `head` is the block before `\r\n\r\n`. The first line is the request line and is
    skipped deliberately: a path may contain anything, `content-length:` included.
    A non-numeric value is attacker-supplied and must not raise here.
    """
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                return max(0, int(value.strip()))
            except ValueError:
                return None
    return None


def is_chunked(head: bytes) -> bool:
    """Whether the header block declares a chunked body."""
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"transfer-encoding" and b"chunked" in value.lower():
            return True
    return False


async def read_http_request(
    reader: Any,
    *,
    max_bytes: int | None = None,
    body_wait: float | None = None,
) -> bytes:
    """Read one HTTP request — headers **and** body — from a stream reader.

    Returns the verbatim bytes received, which is what belongs in `full_payload` and
    what `raw_from_fields`/`raw_hex` carry to the ingest.

    `body_wait` bounds the *body* phase only, not the wait for the first byte, which is
    why it is not called `timeout`: a caller that must not hang on a connection which
    opens and says nothing keeps its own outer timeout, exactly as the decoys here
    already do. `max_bytes` bounds the whole read,
    because a decoy that will buffer an unbounded attacker-chosen request is a way to
    exhaust memory.

    Returns early and without error in every degenerate case — nothing sent, headers
    never completed, body shorter than declared, peer gone — because a decoy that stays
    silent is more conspicuous than one that answers with what it has.
    """
    limit = REQUEST_MAX_BYTES if max_bytes is None else max_bytes
    wait = BODY_WAIT_SECONDS if body_wait is None else body_wait
    buf = b""

    async def _fill_until(complete: Any) -> None:
        nonlocal buf
        while len(buf) < limit and not complete():
            chunk = await reader.read(limit - len(buf))
            if not chunk:  # peer closed
                return
            buf += chunk

    await _fill_until(lambda: b"\r\n\r\n" in buf)
    if b"\r\n\r\n" not in buf:
        return buf[:limit]  # header flood or a truncated request; answer with it

    head, _, _ = buf.partition(b"\r\n\r\n")
    declared = content_length(head)
    chunked = is_chunked(head)
    if not chunked and not declared:
        return buf[:limit]  # a GET, or Content-Length: 0 — nothing promised

    if chunked:
        # The terminating zero-length chunk. Not a full chunked parse: the point is to
        # keep reading while the client is still writing, and an actor sending
        # Transfer-Encoding here is usually doing it precisely to be read wrongly.
        def complete() -> bool:
            return buf.endswith(b"0\r\n\r\n")
    else:
        head_len = len(head) + 4

        def complete() -> bool:
            return len(buf) - head_len >= (declared or 0)

    try:
        await asyncio.wait_for(_fill_until(complete), timeout=wait)
    except TimeoutError:
        pass  # answer with what arrived; see BODY_WAIT_SECONDS
    return buf[:limit]
