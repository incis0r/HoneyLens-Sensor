"""Guardrails for AI-generated detection rules.

Stops "fantasy" rules — over-broad, benign-matching, or protocol-inconsistent
regexes — from ever reaching ``ai_custom_rules``. Root cause of the 2026-07-23
false-ICS incident: an AI Modbus rule ``FC=90|\\x5a`` whose ``\\x5a`` byte
matched the 'z' in a Mozilla User-Agent under IGNORECASE, plus a trailing-``|``
catch-all that matched everything, tagging plain HTTP GET / requests as
Modbus/MQTT/ICS attacks.

The classifier compiles custom rules with ``re.IGNORECASE | re.DOTALL`` (see
``classification.custom_rules_loader``); this validator uses the SAME flags so
its benign-corpus test reflects live matching behaviour exactly.
"""

from __future__ import annotations

import logging
import re

# Compile flags MUST match custom_rules_loader so validation == runtime.
logger = logging.getLogger(__name__)

_FLAGS = re.IGNORECASE | re.DOTALL

# Benign payloads a well-formed detection rule must NEVER match. A proposal that
# fires on any of these is too broad / not grounded in a real protocol anomaly.
# Includes 'Z'/'z'-bearing strings so a raw ``\x5a`` byte token is caught.
BENIGN_CORPUS = [
    "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n",
    'POST /api/v1/login HTTP/1.1\r\nUser-Agent: curl/8.4.0\r\nContent-Type: application/json\r\n\r\n{"a":1}',
    "HEAD / HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\r\n\r\n",
    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n",
    "EHLO mail.example.com\r\n",
    "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03",  # TLS ClientHello prefix
    "220 (vsFTPd 3.0.5)\r\n",
    "GET /zabbix/api_jsonrpc.php HTTP/1.1\r\nUser-Agent: Zabbix\r\n\r\n",  # 'Z' words
    "",  # empty
    "   ",  # whitespace
    "the quick brown fox jumps over the lazy dog 0123456789",
]

# Printable-ASCII raw-byte escapes (\x20-\x7e). In a binary/ICS rule these are
# the classic false-positive trap: honeypot payloads are rendered as text, so
# the byte only ever collides with plaintext (e.g. \x5a == 'Z').
_PRINTABLE_HEX = re.compile(r"\\x([2-7][0-9a-fA-F])")


def _matches_empty(rx: re.Pattern) -> bool:
    try:
        return rx.search("") is not None
    except Exception:
        return False


def _literal_core(pattern: str) -> str:
    """Rough specificity measure: strip regex metacharacters and escaped char
    classes, return the remaining literal text (anchors, quantifiers and class
    shorthands removed)."""
    core = re.sub(r"\\x[0-9a-fA-F]{2}", "", pattern)  # hex escapes -> counted elsewhere
    core = re.sub(r"\\[dDwWsSbBAZ]", "", core)  # class shorthands
    core = re.sub(r"\{\d+(,\d*)?\}", "", core)  # quantifier bodies
    core = re.sub(r"[.^$*+?()|\[\]\\]", "", core)  # bare metachars
    core = re.sub(r"\s+", "", core)
    return core


# Degeneracy is a *relative* property, not an absolute one. A pattern is suspect
# when it looks specific but nearly all of that specificity sits in parts that do
# not have to match. Measuring absolute literal length instead would reject the
# rules this platform depends on most: binary/ICS signatures (\x16\x03\x01) carry
# no literal text at all, and well-anchored ones (^EHLO\s+(?:\d{1,3}\.){3}...$)
# get their precision from structure rather than words.
DEGENERACY_MIN_APPARENT = 8  # below this there is no inflation to detect
DEGENERACY_RATIO = 0.4  # mandatory core must be >=40% of apparent core

# A rule satisfied by one or two characters matches essentially everything.
_TINY_SAMPLES = [c for c in "abcxyzABCXYZ0189 \t/.:-_\x00\xff"] + [
    "ab",
    "xy",
    "01",
    "//",
    "..",
    "GE",
    "\x00\x00",
    "\xff\xff",
]

_INLINE_FLAGS = re.compile(r"\(\?[aiLmsux]+\)")

_INLINE_FLAGS = re.compile(r"\(\?[aiLmsux]+\)")


def _strip_optional(pattern: str) -> str:
    """Remove the parts of a regex that do not have to match anything.

    Groups and classes quantified by ``?``/``*``/``{0,n}`` are dropped entirely,
    innermost-first so nested optional groups collapse too. What remains is the
    *mandatory* skeleton — the only part that actually constrains a match.
    """
    out = _INLINE_FLAGS.sub("", pattern)

    # Innermost optional groups: (...)? (?:...)? — repeat until stable so that
    # nesting like ((a)?b)? collapses rather than leaving a fragment behind.
    group = re.compile(r"\((?:\?[:=!]|\?<[=!]|\?P<\w+>)?[^()]*\)(?:[?*]|\{0(?:,\d*)?\})")
    for _ in range(12):  # bounded: attacker-supplied input
        new = group.sub("", out)
        if new == out:
            break
        out = new

    # Optional character classes and single optional atoms, including escapes.
    out = re.sub(r"\[[^\]]*\](?:[?*]|\{0(?:,\d*)?\})", "", out)
    out = re.sub(r"\\.(?:[?*]|\{0(?:,\d*)?\})", "", out)
    out = re.sub(r"[^\\](?:[?*]|\{0(?:,\d*)?\})", "", out)
    return out


def _mandatory_core(pattern: str) -> str:
    """Literal text that every match is guaranteed to contain."""
    return _literal_core(_strip_optional(pattern))


def _looks_binary_proto(rule_name: str, attack_type: str) -> bool:
    """Reuse the classifier's own binary/ICS keyword detection (lazy import to
    avoid a classification<->analysis import cycle)."""
    try:
        from honeylens.classification.attack_classifier import _rule_targets_binary_proto

        return _rule_targets_binary_proto(rule_name, attack_type)
    except Exception:
        s = ((rule_name or "") + " " + (attack_type or "")).lower()
        return any(
            k in s
            for k in (
                "modbus",
                "s7comm",
                "s7",
                "mqtt",
                "bacnet",
                "dnp3",
                "enip",
                "opcua",
                "iec104",
                "profinet",
                "fox",
                "coap",
                "fins",
                "cip",
            )
        )


def validate_rule(rule_name, attack_type, pattern, is_binary_proto=None):
    """Validate a proposed detection rule.

    Returns ``(ok: bool, reason: str)``. ``ok=True`` means safe to store.
    """
    name = rule_name or ""
    atype = attack_type or ""

    if not pattern or not str(pattern).strip():
        return False, "empty pattern"
    pattern = str(pattern)

    # 1. must compile (with the runtime flags)
    try:
        rx = re.compile(pattern, _FLAGS)
    except re.error as e:
        return False, f"regex does not compile: {str(e)[:80]}"

    # 2. must not match the empty string — catches trailing '|', '.*', 'a?'
    if _matches_empty(rx):
        return False, "matches the empty string (catch-all / trailing '|')"

    # 3. must have a literal core — reject structureless wildcard soup.
    #
    # Raw-byte escapes count toward specificity. They are the entire substance of
    # a binary/ICS signature (\xFF[\xFE\xFF]{2,} is a real Telnet IAC probe), and
    # measuring literal text alone scored every such rule at zero — which would
    # have rejected the detections this platform exists for. A lone printable
    # byte is still caught, by its own count below and by check 5.
    core = _literal_core(pattern)
    hex_bytes = len(re.findall(r"\\x[0-9a-fA-F]{2}", pattern))
    if len(core) + hex_bytes < 3:
        return False, (
            f"insufficient specificity (literal core {core!r} plus {hex_bytes} raw bytes < 3)"
        )

    # 3b. the MANDATORY part must carry the specificity, not the optional part.
    #
    # This is what `claude_redis_info_enumeration` exploited in production:
    #     (?i)\bINFO\b\s*(all|server|clients|memory|stats|replication|...)?
    # The alternation is optional, so the rule reduces to "the word INFO anywhere"
    # while the long list made its literal core look highly specific. It matched
    # the bytes of SSH key exchange and produced 11,610 events across 460 sources
    # in 30 days, 11,303 of them on port 22, every one of them labelled Redis
    # reconnaissance. Measure what must match, not what may.
    mandatory = _mandatory_core(pattern)
    if len(core) >= DEGENERACY_MIN_APPARENT and len(mandatory) < max(
        3, int(len(core) * DEGENERACY_RATIO)
    ):
        return False, (
            f"degenerate: looks specific ({len(core)} literal chars) but strip the "
            f"optional parts and only {mandatory!r} ({len(mandatory)}) has to match. "
            f"Put the specificity in the mandatory part — anchor to the protocol "
            f"framing instead of a long optional alternation"
        )

    # 3c. a rule one or two characters can satisfy matches essentially everything.
    # `^[a-z]$` (claude_ethernet_ip_minimal_payload_scan) produced 1,246 events
    # across 728 sources before it was disabled.
    for tiny in _TINY_SAMPLES:
        try:
            if rx.search(tiny):
                return False, (
                    f"matches the {len(tiny)}-character sample {tiny!r} — "
                    f"far too broad to identify anything"
                )
        except Exception as exc:
            logger.debug("probe skipped: %s", exc)

    # 4. must not fire on benign traffic
    for sample in BENIGN_CORPUS:
        try:
            if rx.search(sample):
                label = repr(sample[:28]) if sample.strip() else "empty/whitespace"
                return False, f"matches benign sample {label} — too broad"
        except Exception as exc:
            logger.debug("probe skipped: %s", exc)

    # 5. binary/ICS discipline: no printable-ASCII raw bytes (the \x5a='Z' trap)
    if is_binary_proto is None:
        is_binary_proto = _looks_binary_proto(name, atype)
    if is_binary_proto:
        m = _PRINTABLE_HEX.search(pattern)
        if m:
            ch = chr(int(m.group(1), 16))
            return False, (
                f"binary/ICS rule uses printable-ASCII byte \\x{m.group(1)} "
                f"('{ch}') — collides with plaintext; use anchored hex/text"
            )

    return True, "ok"
