"""Honeypot event sink: one JSON line per event, with no knowledge of the database.

In 0.9 there were two families of honeypots. Family A (`hp_*` on `BaseHoneypot`, `hp_nginx`,
`honeypot_llm`) wrote directly to PostgreSQL through `db_cursor`; family B (the monolith,
K8s, FortiGate, PAN-OS) wrote JSON lines that `ingest/honeypot.py` read and
put into the database. In 1.0 every honeypot is a container and **knows nothing about the
database**: no credentials, no driver, no migrations. One road is left — the second one.

This module is the contract between the honeypot and the ingest. The line has a ``schema``
field with a version so the ingest can tell it apart from the family B format (which it
keeps handling unchanged) and so a change of contract can be introduced without guessing
from the fields.

What the line carries and why:

- ``source`` — the honeypot's identity (``honeypot-<name>``), ``protocol`` — the protocol on
  the wire. These are two different things: the ``nginx`` honeypot speaks HTTPS. In 0.9 the
  ingest lost the identity (everything got ``honeypotng``); here it is explicit.
- ``event`` — the event dict in full, exactly what went into the ``metadata`` column.
  Separate, not flattened: the honeypot's keys must not overwrite the envelope
  (``protocol``, ``payload``, ``severity`` occur in both).
- ``attack_type``/``severity``/``rules`` — the honeypot's verdict, if it has one. If it does
  not, the key is absent and the ingest classifies; the honeypot's verdict is of higher
  fidelity than a regex and the ingest does not override it.
- ``raw_hex`` — the bytes as they arrived, when the payload rides in the request body.
  Truncated here to ``HONEYPOT_RAW_CAPTURE_BYTES``; the ingest computes the digest over what
  it actually stores, so it is checkable against the column.
- ``timestamp`` — UTC with offset. The container logs in UTC regardless of the host.

Writing: one line, one ``open`` in append mode, one ``write``. No long-held descriptor —
after processing, the ingest truncates the file and counts on nobody holding an old offset
(see ``ingest/logcleanup.py``).

A write failure is an ``ERROR`` in the process log, not ``debug``: in 0.9 the LLM honeypot
lost every event for ten weeks and said nothing about it.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from honeylens.config import HONEYPOTNG_LOG_DIR
from honeylens.eventlog_lock import append_line

SCHEMA = "honeylens-event/1"

logger = logging.getLogger("honeylens.honeypots.sink")


def _parse_port_map(raw: str) -> dict[int, int]:
    """``"30502:502,30022:22"`` -> ``{30502: 502, 30022: 22}``. Bad entry = ERROR and skipped."""
    out: dict[int, int] = {}
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        bound, _, public = item.partition(":")
        try:
            out[int(bound)] = int(public)
        except ValueError:
            logger.error("HONEYLENS_PORT_MAP: ignoring malformed entry %r", item)
    return out


# The container runs without root, so a protocol port < 1024 is bound as a high port
# (manifest: 30000 + port) and DNAT-ed on the host. The event, however, must carry the
# protocol port — the classifier and the ICS context look at dst_port (502, not 30502), and
# the operator wants to see in the database what the attacker hit, not how it was wired up.
PORT_MAP: dict[int, int] = {}


def public_port(bound: int | None) -> int | None:
    """Protocol port for the port the honeypot actually listens on (or the same one)."""
    if bound is None:
        return None
    try:
        return PORT_MAP.get(int(bound), int(bound))
    except (TypeError, ValueError):
        return bound


MAX_RAW_CAPTURE = int(os.environ.get("HONEYPOT_RAW_CAPTURE_BYTES", 64 * 1024))

# The ``llm`` block of the envelope: columns of the llm_honeypot_events table (migration
# 0008). The ingest inserts exactly these columns, in this order — the line from the
# container does not choose where it writes.
LLM_COLUMNS = (
    "event_id",
    "session_id",
    "src_ip",
    "turn_number",
    "user_message",
    "message_tokens",
    "message_entropy",
    "attack_category",
    "attack_rules",
    "confidence",
    "severity",
    "response_text",
    "response_strategy",
    "response_ms",
    "actor_type",
    "agent_score",
    "timing_ms",
    "endpoint",
    "model_requested",
    "api_key_used",
    "user_agent",
    "headers",
    "mitre_technique",
    "mitre_tactic",
)

PORT_MAP.update(_parse_port_map(os.environ.get("HONEYLENS_PORT_MAP", "")))


def event_log_path(source: str) -> Path:
    """Event file of one honeypot: ``<HONEYPOTNG_LOG_DIR>/<source>.json``.

    One honeypot, one file — the ingest globs ``*.json`` in this directory, and in the
    container the directory is a volume shared with the ingest on the host.
    """
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in source) or "honeypot"
    return Path(HONEYPOTNG_LOG_DIR) / f"{safe}.json"


def build_record(
    *,
    source: str,
    honeypot: str,
    protocol: str,
    peer: tuple,
    event: dict,
    payload: str,
    dst_port: int | None = None,
    dst_ip: str | None = None,
    attack_type: str | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    rules: list[str] | None = None,
    raw: bytes | None = None,
    raw_capture_bytes: int | None = None,
    event_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Event envelope in the ``SCHEMA`` contract. Keys without a value are omitted."""
    src_ip = peer[0] if peer else "0.0.0.0"
    src_port = peer[1] if peer and len(peer) > 1 else 0
    record: dict[str, Any] = {
        "schema": SCHEMA,
        "timestamp": datetime.now(UTC).isoformat(),
        "source": source,
        "honeypot": honeypot,
        "protocol": protocol,
        "peer_ip": src_ip,
        "peer_port": src_port,
        "dst_port": public_port(dst_port) or 0,
        "payload": payload[:2000],
        "event": event,
    }
    if dst_ip:
        record["dst_ip"] = dst_ip
    if event_id:
        record["event_id"] = event_id
    if attack_type:
        record["attack_type"] = attack_type
        record["severity"] = (severity or "MEDIUM").upper()
        record["confidence"] = confidence or "high"
        record["rules"] = list(rules or [])
    if raw:
        limit = MAX_RAW_CAPTURE if raw_capture_bytes is None else raw_capture_bytes
        record["raw_hex"] = raw[:limit].hex()
    if extra:
        record.update(extra)
    return record


def write_record(record: dict[str, Any]) -> bool:
    """Append one line to the honeypot's file. ``False`` on failure (and an ERROR in the log)."""
    path = event_log_path(str(record.get("source") or "honeypot"))
    try:
        # ensure_ascii: NUL and other control characters come out as \\uXXXX, and the ingest
        # strips them with strip_nul — what the honeypot got from the attacker must not
        # break either the JSON or the jsonb column.
        line = json.dumps(record, ensure_ascii=True, default=str, separators=(",", ":"))
    except Exception as exc:
        logger.error("event not serialisable, dropped: %s", exc)
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        append_line(path, line)
        return True
    except OSError as exc:
        logger.error("cannot append event to %s: %s", path, exc)
        return False
