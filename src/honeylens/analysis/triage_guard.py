#!/usr/bin/env python3
"""
triage_guard.py — Deterministic guard against 0-day false positives
====================================================================
The Ollama triage model tends to over-rate ordinary honeypot activity. An SMTP
``EHLO`` greeting from a mass-scanner, or the ``AUTH LOGIN`` credential capture
that the SMTP honeypot exists to record, routinely comes back as ``SUSPICIOUS``
with a novelty score of 6-8. Those land on the "0-Day Candidates" page
(``novelty_score >= 6``), which is pure noise — capturing SMTP credentials is
the honeypot's *job*, not a novel exploit.

This guard recognises benign, well-formed protocol interactions and caps their
novelty deterministically, independent of the model's judgement. It fires ONLY
on clean, standard, bounded traffic: a malformed, oversized, or binary payload
(what a real SMTP exploit would look like) is left untouched so it still
surfaces for review.
"""

from __future__ import annotations

import json
import re

# Novelty is 0-10 in triage. Anything <= this is below the 0-day surface (>= 6).
NOVELTY_CAP = 2

# Standard SMTP command verbs (RFC 5321 + common ESMTP/AUTH). A line that starts
# with one of these is protocol negotiation, not an exploit.
SMTP_VERBS = (
    "EHLO",
    "HELO",
    "MAIL",
    "RCPT",
    "DATA",
    "RSET",
    "NOOP",
    "QUIT",
    "VRFY",
    "EXPN",
    "HELP",
    "STARTTLS",
    "AUTH",
    "BDAT",
    "ETRN",
)

# The SMTP honeypot emits structured events with a ``phase`` marker. Every phase
# below is a normal protocol state — the honeypot recording expected client
# behaviour (including credential capture, which is the whole point).
BENIGN_SMTP_PHASES = frozenset(
    {
        "connect",
        "connected",
        "greeting",
        "banner",
        "ehlo",
        "helo",
        "starttls",
        "auth",
        "auth_login",
        "auth_login_user",
        "auth_login_creds",
        "auth_plain",
        "auth_plain_creds",
        "auth_cram",
        "auth_cram_md5",
        "mail_from",
        "rcpt_to",
        "data",
        "data_start",
        "data_body",
        "data_end",
        "rset",
        "noop",
        "vrfy",
        "expn",
        "help",
        "quit",
        "disconnect",
    }
)

# A base64 token (AUTH LOGIN sends the username/password as base64 lines).
_B64_LINE = re.compile(r"^[A-Za-z0-9+/]{2,}={0,2}$")

# Ceilings beyond which we stop trusting "it's just a handshake" — a real SMTP
# parser overflow lives past these.
_MAX_TOTAL = 2048
_MAX_LINE = 512


def _extract_text(payload) -> str | None:
    """Return the human-readable text of a payload, or None if unusable.

    Honeypot SMTP events are JSON (``{"phase": ..., "raw": ...}``); raw-text
    payloads (``EHLO host``) are returned as-is.
    """
    if payload is None:
        return None
    if isinstance(payload, (dict, list)):
        return json.dumps(payload)
    if not isinstance(payload, str):
        return None
    return payload


def _is_printable(text: str) -> bool:
    # Allow the usual line/whitespace control chars; reject other C0/C1 bytes
    # and NULs (hallmarks of binary exploit payloads).
    return all(c in "\t\r\n" or 32 <= ord(c) < 127 for c in text)


def _looks_like_smtp_phase_json(text: str) -> str | None:
    """If ``text`` is a honeypot SMTP phase record, return the phase, else None."""
    stripped = text.strip()
    if not (stripped.startswith("{") and '"phase"' in stripped):
        return None
    try:
        obj = json.loads(stripped)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    phase = obj.get("phase")
    if not isinstance(phase, str):
        return None
    return phase.strip().lower()


def _all_lines_are_smtp(text: str) -> bool:
    """True if every non-empty line is a standard SMTP verb or a base64 token."""
    saw_line = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        saw_line = True
        if len(line) > _MAX_LINE:
            return False
        upper = line.upper()
        if any(
            upper == v or upper.startswith(v + " ") or upper.startswith(v + ":") for v in SMTP_VERBS
        ):
            continue
        if _B64_LINE.match(line):
            continue
        return False
    return saw_line


def _is_smtp(event: dict) -> bool:
    proto = (event.get("protocol") or "").upper()
    if proto == "SMTP":
        return True
    try:
        port = int(event.get("dst_port") or 0)
    except (TypeError, ValueError):
        port = 0
    return port in (25, 465, 587, 2525)


def is_benign_protocol_event(event: dict) -> tuple[bool, str | None]:
    """Return (is_benign, reason) for well-formed routine honeypot traffic.

    Conservative by design: only clean, bounded, printable, standard protocol
    interactions qualify. Anything unusual (binary, oversized, non-standard) is
    reported as NOT benign so a genuine exploit still reaches the 0-day surface.
    """
    if not _is_smtp(event):
        return False, None

    text = _extract_text(event.get("payload"))
    if text is None:
        return False, None
    if len(text) > _MAX_TOTAL or not _is_printable(text):
        return False, None

    phase = _looks_like_smtp_phase_json(text)
    if phase is not None:
        if phase in BENIGN_SMTP_PHASES:
            return True, f"routine SMTP honeypot interaction (phase={phase})"
        return False, None

    if _all_lines_are_smtp(text):
        return True, "standard SMTP protocol handshake"

    return False, None


def apply_triage_guard(event: dict, result: dict) -> dict:
    """Downgrade a triage ``result`` in place when the event is benign protocol
    traffic. Caps novelty to ``NOVELTY_CAP`` and reclassifies
    SUSPICIOUS/CRITICAL as NOISE, annotating the reasoning. No-op otherwise.
    """
    benign, reason = is_benign_protocol_event(event)
    if not benign:
        return result

    changed = False

    novelty = result.get("novelty_score") or 0
    try:
        novelty = int(novelty)
    except (TypeError, ValueError):
        novelty = 0
    if novelty > NOVELTY_CAP:
        result["novelty_score"] = NOVELTY_CAP
        changed = True

    cls = (result.get("classification") or "").upper()
    if cls in ("SUSPICIOUS", "CRITICAL"):
        result["classification"] = "NOISE"
        changed = True

    if changed:
        note = f"[guard: {reason}]"
        existing = (result.get("reasoning") or "").strip()
        result["reasoning"] = f"{note} {existing}".strip()
        result["guarded"] = True

    return result
