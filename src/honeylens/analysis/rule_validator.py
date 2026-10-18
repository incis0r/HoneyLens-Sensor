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
import os
import re
import time
from collections.abc import Callable

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

# ─── Runtime cost (check 6) ───────────────────────────────────────────────
# Checks 1-5 all ask whether a rule matches the right things. None asked what it costs
# to find out, and that turned out to matter: the shipped `graphql_alias_dos` rule was
# quadratic on a near-match — 59.6 s for a 3.2 KB payload — and every rule runs against
# attacker-chosen bytes on every event. A rule like
# `Authorization:\s*Bearer\s+(?:[A-Za-z0-9]+_?)+$` passed all five checks and doubles its
# run time for each added character: 0.7 ms at 14 characters, 5.6 s at 27.
#
# This is deliberately a measurement and not a structural test. The obvious structural
# rule — reject a quantified group containing an unbounded quantifier — would also reject
# `graphql_deep_nesting` (`(\{\s*\w+\s*\{){5,}`), which is measurably linear (0.65 ms over
# 20 KB) because two literal braces per repetition leave nothing to redistribute. Shape is
# a hint; time is the fact.
_REDOS_BUDGET_MS = float(os.environ.get("RULE_REDOS_BUDGET_MS", "120"))

# What is measured is the *growth rate*, not the absolute time, and that choice is what
# makes this safe to run. An exponential pattern costs about 2x per added character, so
# doubling a tiny probe multiplies its cost by a thousand — unmistakable at a size that
# cannot hurt. Checking only a total elapsed budget, as the first version of this did,
# bounds nothing: the budget is tested *after* a probe returns, and a candidate such as
# `(a+){40,}` would have been handed a 64-character run and never come back. Python's `re`
# holds the GIL and cannot be interrupted, so there is no timeout to fall back on; the only
# real defence is to never build a probe big enough to matter.
# Pressure levels. Each step roughly doubles the work a blow-up has to do, and the ladder
# stops at the first step that is already slow — so the cost of finding out is bounded by
# `_REDOS_ESCALATE_STOP_MS` times a small constant, no matter how pathological the
# candidate. Measuring at one fixed size cannot work: clamp it small enough to be safe and
# it misses patterns that need many repetitions to blow up; make it big enough to catch
# those and the validator hangs on the first bad rule it is asked about.
# The steps are additive, not doublings. With exponential backtracking, doubling the input
# multiplies the cost by 2^(added characters): a ladder of 8, 16, 32 looks cheap at 16 and
# then takes 168 s at 32, which is how the first version of this hung. A +2 step can cost
# at most ~4x the step before it, so a measured-cheap step bounds the next one.
_REDOS_PRESSURE = tuple(range(8, 25, 2))
# ⚠️ What this check does NOT catch, measured rather than assumed.
#
# The ladder stops at 24 characters, and that ceiling is not timidity — extending it
# re-opens the hole it exists to close. The +2 step bounds the next step only while cost
# grows smoothly. `(a+){40,}` is a counter-example: under 40 characters it fails instantly
# because the repetition count cannot be met, and at 40 it becomes 2^40. There is no
# gradual signal to stop on, so a longer ladder walks straight into it — tried it, it hung.
#
# The consequence is a real gap: a pattern needing many repetitions of a long body cannot
# blow up inside 24 characters, so it is not reached. The original `graphql_alias_dos`
# (ten repetitions of an eight-character body, so eighty characters before anything
# happens) is exactly that shape and this check would have let it through. What is caught
# is the `(X+)+` family, where ambiguity shows up immediately.
#
# Closing the gap means probing out of process with a hard kill, since an in-process `re`
# call cannot be interrupted. Until then this is a filter, not a guarantee, and the
# classifier's length cap is what actually bounds the damage of a rule that slips past.
# A probe this slow at these sizes is itself the answer, so it is a rejection and not just
# a reason to stop climbing. Healthy patterns run in microseconds here. The value was tuned
# against the whole shipped rule set and a bench of known-bad patterns: at 20 ms two of
# seven bad patterns slipped through, at 10 ms six of seven are caught with no shipped rule
# rejected, and at 5 ms real rules (`prompt_roleplay`) start being refused. 10 keeps a 2x
# margin to the first false positive.
_REDOS_SLOW_MS = float(os.environ.get("RULE_REDOS_SLOW_MS", "10"))
# Doubling the pressure may not multiply the cost by more than this.
_REDOS_GROWTH_LIMIT = float(os.environ.get("RULE_REDOS_GROWTH_LIMIT", "50"))
# Below this the numbers are scheduler noise, not signal.
_REDOS_FLOOR_MS = 1.0
_REDOS_SEED_CHARS = re.compile(r"[A-Za-z0-9_:/@.\-]")

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


def _has_nested_quantifier(pattern: str) -> bool:
    """True when a quantified group itself contains an unbounded quantifier.

    The shape that makes blow-ups possible. Not sufficient on its own — see the note on
    ``_REDOS_BUDGET_MS`` — so it is only used to enrich the rejection message.
    """
    for m in re.finditer(r"\((?:\?[:=!][^()]*|[^()]*)\)\s*(?:[+*]|\{\d+,\d*\})", pattern):
        body = m.group(0)
        inner = body[1 : body.rindex(")")]
        if re.search(r"(?<!\\)[+*]|\{\d+,\}", inner):
            return True
    return False


_QUANTIFIED_GROUP = re.compile(r"\((?:\?[:=!])?([^()]*)\)\s*(?:([+*])|\{(\d+),\d*\})")


def _sample_of(fragment: str) -> str:
    """A short string a backtracking engine would accept for this pattern fragment.

    Crude on purpose — it only has to get the engine *past* the literals and into the
    ambiguous part, not to produce a true match. Stops at the first alternation so the
    sample stays one concrete branch.
    """
    out: list[str] = []
    i, n = 0, len(fragment)

    def drop_if_optional(index: int) -> int:
        """Remove the token just emitted when the pattern marks it optional.

        Optional elements have to be left out, not filled in. The expensive input is the
        one that exercises the ambiguity, and an optional literal filled in becomes a
        separator that destroys it: sampling `(?:[A-Za-z0-9]+_?)` as `a_` yields
        `a_a_a_...`, which the engine parses one way and finishes instantly, while the
        homogeneous run `aaaa...` it should have produced costs 759 ms at 24 characters.
        """
        if index < n and fragment[index] == "?" and out:
            out.pop()
            return index + 1
        if index < n and fragment[index] == "{":
            close = fragment.find("}", index)
            if close != -1 and fragment[index + 1 : close].startswith("0") and out:
                out.pop()
                return close + 1
        return index

    while i < n and len(out) < 48:
        c = fragment[i]
        if c == "\\" and i + 1 < n:
            out.append(
                {"s": " ", "w": "a", "d": "0", "S": "a", "W": " ", "D": "a"}.get(
                    fragment[i + 1], fragment[i + 1]
                )
            )
            i = drop_if_optional(i + 2)
        elif c == "[":
            close = fragment.find("]", i)
            if close == -1:
                break
            body = fragment[i + 1 : close]
            # A letter satisfies most classes; use a digit when the class only takes those.
            out.append("0" if re.fullmatch(r"\^?[0-9\-]+", body) else "a")
            i = drop_if_optional(close + 1)
        elif c == "(":
            i += 3 if fragment.startswith(("(?:", "(?i", "(?=", "(?!"), i) else 1
        elif c == ")":
            i += 1
        elif c == "|":
            break
        elif c in "^$":
            i += 1
        elif c in "*+?":
            i += 1
        elif c == "{":
            close = fragment.find("}", i)
            i = close + 1 if close != -1 else n
        elif c == ".":
            out.append("a")
            i = drop_if_optional(i + 1)
        else:
            out.append(c)
            i = drop_if_optional(i + 1)
    return "".join(out)


def _targeted_shape(prefix: str, sample: str, _wanted: int = 0) -> Callable[[int], str]:
    """Probe builder aimed at one quantified group: a run built from its own body.

    `pressure` is a length in **characters**, not a repetition count, and that distinction
    is the whole bound. Repeating the body `pressure` times grows the run by
    `2 * len(sample)` per step, so with an eight-character body a +2 step added eighteen
    characters — and against an exponential pattern eighteen characters is a factor of
    260,000, which puts the expensive step right after a cheap one with nothing in between
    to warn us. Truncating to `pressure` makes every step exactly two characters, so a step
    measured cheap really does bound the next.
    """

    def build(pressure: int) -> str:
        # Repeat the body as many times as it takes to fill `pressure` characters, then
        # truncate. Capping the repetitions instead (at the group's own minimum) limits the
        # run to that many characters and the probe never gets long enough to show anything.
        repeats = -(-pressure // max(1, len(sample)))
        run = (sample * repeats)[:pressure]
        return prefix + run + "\x00"

    return build


def _run_shape(char: str) -> Callable[[int], str]:
    """Probe builder for a homogeneous run, for patterns with no literal prefix."""

    def build(pressure: int) -> str:
        return char * pressure + "\x00"

    return build


def _redos_probe_shapes(pattern: str) -> list[Callable[[int], str]]:
    """Inputs that make backtracking visible at small sizes.

    Two kinds. The targeted ones aim at an actual quantified group whose body itself
    repeats — the only shape that can blow up — by repeating a sample of that body one
    short of the required count and following it with filler, which is what forces the
    engine to try every redistribution. Generic homogeneous runs come second, for
    anchored patterns with no literal prefix to get past.

    Every probe ends in a NUL so the overall match fails. That is the expensive case: a
    backtracking engine is quick when it succeeds and slow when it has to prove there is
    no match, which is why this class survives testing — people test patterns on input
    that matches.
    """
    shapes: list[Callable[[int], str]] = []
    for m in _QUANTIFIED_GROUP.finditer(pattern):
        body, min_count = m.group(1), m.group(3)
        if not re.search(r"(?<!\\)[+*]|\{\d+,\}", body):
            continue
        sample = _sample_of(body) or "a"
        prefix = _sample_of(pattern[: m.start()])
        wanted = max(1, int(min_count) - 1) if min_count else 9
        # Pressure drives both the repetition count and the filler, so a pattern that only
        # blows up after many repetitions is still reached — but only while it stays cheap.
        shapes.append(_targeted_shape(prefix, sample, wanted))
    seeds = ["a", "0", " "]
    for ch in _REDOS_SEED_CHARS.findall(pattern):
        if ch not in seeds:
            seeds.append(ch)
        if len(seeds) >= 6:
            break
    for ch in seeds:
        shapes.append(_run_shape(ch))
    return shapes


def _redos_probes(pattern: str) -> list[str]:
    """The concrete probe strings, for tests and for explaining a rejection."""
    return [shape(k) for shape in _redos_probe_shapes(pattern) for k in _REDOS_PRESSURE]


def _time_search(rx, probe: str) -> float:
    """Seconds for one search. Repeats only when the result is too small to trust."""
    start = time.perf_counter()
    try:
        rx.search(probe)
    except Exception as exc:  # a probe must never break validation
        logger.debug("redos probe skipped: %s", exc)
    best = time.perf_counter() - start
    if best * 1000.0 >= _REDOS_FLOOR_MS:
        return best  # already meaningful; repeating an expensive probe is how you hang
    for _ in range(2):
        start = time.perf_counter()
        try:
            rx.search(probe)
        except Exception:
            break
        best = min(best, time.perf_counter() - start)
    return best


def _redos_cost(rx) -> tuple[float, str | None]:
    """Measure how the cost *grows*, and return (seconds spent, offending probe or None).

    Each shape is pushed up an additive ladder of pressure. A candidate is rejected when a
    probe is outright slow at these tiny sizes, or when one step multiplies the previous
    step's cost by more than `_REDOS_GROWTH_LIMIT` — the signature of super-polynomial
    backtracking, visible long before the input is big enough to hurt.

    The bound on asking is structural, which it has to be: Python's `re` holds the GIL and
    cannot be interrupted, so there is no timeout to fall back on. Because a +2 step costs
    at most about 4x the step before it and we stop at the first step over
    `_REDOS_SLOW_MS`, no probe here can cost more than a fraction of a second.
    """
    budget = _REDOS_BUDGET_MS / 1000.0
    floor = _REDOS_FLOOR_MS / 1000.0
    slow = _REDOS_SLOW_MS / 1000.0
    spent = 0.0
    for shape in _redos_probe_shapes(rx.pattern):
        previous = None
        for pressure in _REDOS_PRESSURE:
            probe = shape(pressure)
            elapsed = _time_search(rx, probe)
            spent += elapsed
            if elapsed > slow or elapsed > budget:
                return spent, probe
            if (
                previous is not None
                and previous > floor
                and elapsed / previous > _REDOS_GROWTH_LIMIT
            ):
                return spent, probe
            previous = elapsed
    return spent, None


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

    # 6. must be cheap to evaluate. A rule runs against attacker-chosen bytes on every
    # event, so a pattern that backtracks is a denial of service with extra steps.
    spent, culprit = _redos_cost(rx)
    if culprit is not None:
        hint = (
            " A quantified group here contains an unbounded quantifier, which is the shape "
            "that allows it: express a repetition count as a count (see _CountingPattern) "
            "or make each repetition unambiguous."
            if _has_nested_quantifier(pattern)
            else " Anchor the quantifiers so the engine cannot re-split the same input."
        )
        return False, (
            f"too slow to evaluate: {spent * 1000:.0f} ms on a {len(culprit)}-character "
            f"probe (budget {_REDOS_BUDGET_MS:.0f} ms). Cost grows with payload length and "
            f"the attacker picks the payload.{hint}"
        )

    return True, "ok"
