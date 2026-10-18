"""Durable store for AI prompt-injection canaries (Idea 52).

`ai_canary` correlates nonces in process memory, which is enough while one honeypot
both issues a canary and serves its callback. It is not enough across processes: the
LLM honeypot issues a canary, the callback lands on the K8s honeypot's port, and the
two never share memory — so the callback was recorded but never tied back to what the
attacker had been reading. Process restarts dropped every outstanding nonce too.

This module is that missing registry. Every function takes a cursor rather than
opening its own connection, deliberately: the K8s honeypot is internet-facing and
holds no database credentials, and that stays true. Its canaries are registered by
the ingest as it reads the honeypot's log; honeypots that already have a database
(the LLM one) register theirs directly.

All writes are idempotent — logs are re-read after a failed pass, so a canary may be
offered to us more than once.
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger("ai_canary_store")

_INSERT_SQL = """
    INSERT INTO ai_prompt_canaries (
        nonce, canary_type, carrier, origin_event_id, origin_protocol,
        origin_path, origin_src_ip, issued_at, expires_at
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, COALESCE(%s, NOW()), %s)
    ON CONFLICT (nonce) DO NOTHING
"""

# Do not overwrite an existing callback: the first agent to answer is the finding.
_CALLBACK_SQL = """
    UPDATE ai_prompt_canaries
       SET callback_at = COALESCE(%s, NOW()),
           callback_src_ip = %s,
           callback_user_agent = %s,
           callback_headers = %s,
           callback_body_sample = %s
     WHERE nonce = %s AND callback_at IS NULL
    RETURNING origin_protocol, origin_path, origin_src_ip, issued_at
"""

_LOOKUP_SQL = """
    SELECT origin_protocol, origin_path, origin_src_ip, issued_at
      FROM ai_prompt_canaries WHERE nonce = %s
"""


def record_issue(
    cur,
    nonce,
    canary_type="prompt_injection_header",
    carrier="",
    origin_event_id=None,
    origin_protocol=None,
    origin_path=None,
    origin_src_ip=None,
    issued_at=None,
    expires_at=None,
):
    """Register a canary we handed out. Returns True if this call created the row."""
    if not nonce:
        return False
    try:
        cur.execute(
            _INSERT_SQL,
            (
                nonce,
                canary_type or "prompt_injection_header",
                carrier or "",
                origin_event_id,
                origin_protocol,
                origin_path,
                origin_src_ip or None,
                issued_at,
                expires_at,
            ),
        )
        return cur.rowcount > 0
    except Exception as exc:  # never break the caller's ingest
        logger.debug("canary issue not recorded (%s): %s", nonce, exc)
        return False


def record_callback(
    cur, nonce, callback_at=None, src_ip=None, user_agent=None, headers=None, body_sample=None
):
    """Mark a canary as called back.

    Returns the issuing context (origin_protocol, origin_path, origin_src_ip,
    issued_at) so the caller can correlate a callback with the artefact that
    carried it — even when a different process handed the canary out — or None
    when the nonce is unknown or already answered.
    """
    if not nonce:
        return None
    try:
        cur.execute(
            _CALLBACK_SQL,
            (
                callback_at,
                src_ip or None,
                user_agent,
                json.dumps(headers) if headers else None,
                body_sample,
                nonce,
            ),
        )
        row = cur.fetchone()
        if row:
            return _as_origin(row)
        # Already answered, or issued before this registry existed: still useful to
        # report where it came from, so fall back to a plain lookup.
        cur.execute(_LOOKUP_SQL, (nonce,))
        row = cur.fetchone()
        return _as_origin(row) if row else None
    except Exception as exc:
        logger.debug("canary callback not recorded (%s): %s", nonce, exc)
        return None


def _as_origin(row):
    return {
        "origin_protocol": row[0],
        "origin_path": row[1],
        "origin_src_ip": row[2],
        "issued_at": row[3],
    }


def callback_delay_ms(issued_at, callback_at):
    """Milliseconds between issue and callback, or None if either end is missing."""
    if not issued_at or not callback_at:
        return None
    try:
        return max(0, int((callback_at - issued_at).total_seconds() * 1000))
    except (TypeError, AttributeError):
        return None
