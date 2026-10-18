"""Bounds on what classification can cost, and the rule that had none.

Three things are pinned here, all of them measured rather than reasoned about:

1. Every target handed to the rules is length-capped, not only the body pulled out of
   metadata. `payload` and `text` were passed in whole, so the cap that existed did not
   apply where the work actually happens.
2. `graphql_alias_dos` counts alias constructs instead of matching a repeated group. As
   `(\\w+\\s*:\\s*\\w+\\s*\\{.*?){10,}` it was O(n²) on a near-match — 59.6 s for a 3.2 KB
   payload, with the attacker choosing the length.
3. `validate_rule` now times a candidate before accepting it. Checks 1-5 all ask whether a
   rule matches the right things; none asked what finding out costs.

The timing assertions are deliberately loose. They exist to catch a return to quadratic or
exponential behaviour, which shows up as orders of magnitude, not as percentages — so a
slow machine will not trip them.
"""

from __future__ import annotations

import re
import time

import pytest

ADVERSARIAL_PREFIX = "a:a{" * 9  # one repetition short of the rule's threshold


def _adversarial(total: int) -> str:
    return ADVERSARIAL_PREFIX + "X" * max(0, total - len(ADVERSARIAL_PREFIX))


# ── 1. the classification cap ────────────────────────────────────────────────────────────


def _detects(payload: str) -> bool:
    from honeylens.classification.attack_classifier import _classify_rules

    return bool({r for _, r, _ in _classify_rules(payload, "HTTP", {"dst_port": 80})})


def test_a_signature_is_found_in_the_head_and_in_the_tail():
    """The cap bounds cost, and the tail scan pays back the obvious half of the blind spot.

    Without it, "send the cap's worth of padding, then the exploit" is a one-line evasion,
    and on a sensor a missed detection is the expensive kind of failure.
    """
    from honeylens.classification import attack_classifier as ac

    cap = ac._BODY_CLASSIFY_BYTES
    marker = "/etc/passwd"
    assert _detects("GET /?x=" + marker + " HTTP/1.1\r\n" + "A" * (cap * 2)), "head"
    assert _detects("GET /?x=" + "A" * (cap + 500) + " HTTP/1.1 " + marker), "tail"


def test_the_remaining_blind_spot_is_the_middle_and_that_is_on_purpose():
    """Capping at all means something is unscanned; this pins where, so it is a decision.

    Closing it needs a per-event "partially classified" marker on ingest, not a bigger cap
    — a bigger cap just moves the boundary and brings back the cost it was there to bound.
    """
    from honeylens.classification import attack_classifier as ac

    cap = ac._BODY_CLASSIFY_BYTES
    buried = "GET /?x=" + "A" * (cap + 200) + "/etc/passwd" + "B" * (cap + 200)
    assert not _detects(buried), (
        "the middle is now scanned — good, but then this test and the cap's comment are "
        "both stale and the cost bound needs re-measuring"
    )


def test_classification_cost_does_not_grow_with_payload_length():
    """Past the cap, a bigger payload must not cost more. This is the DoS bound."""
    from honeylens.classification.attack_classifier import _classify_rules

    def cost(n: int) -> float:
        payload = _adversarial(n)
        start = time.perf_counter()
        _classify_rules(payload, "HTTP", {"dst_port": 80})
        return time.perf_counter() - start

    small = cost(16_384)
    large = cost(1_048_576)  # 64x the bytes
    assert large < small * 4 + 1.0, (
        f"cost still tracks payload length: {small:.2f}s at 16 KB vs {large:.2f}s at 1 MB"
    )


# ── 2. the counting rule ─────────────────────────────────────────────────────────────────


def _alias_rule():
    from honeylens.classification import text_rules as tr

    return next(rx for _, name, rx in tr._RULES if name == "graphql_alias_dos")


def test_alias_rule_is_a_counting_rule_not_a_repeated_group():
    from honeylens.classification.text_rules import _CountingPattern

    rule = _alias_rule()
    assert isinstance(rule, _CountingPattern)
    assert ".*?" not in rule.pattern, "the ambiguous tail is what made this quadratic"
    assert rule.pattern.startswith("\\b"), (
        "without the word boundary the engine restarts inside long word runs and the "
        "sub-pattern itself goes quadratic (491 ms at 8 KB, >30 s at 64 KB)"
    )


@pytest.mark.parametrize(("aliases", "expected"), [(12, True), (10, True), (9, False)])
def test_alias_rule_threshold_is_unchanged(aliases, expected):
    query = "query{" + "".join(f"a{i}:user{{name}}" for i in range(aliases)) + "}"
    assert bool(_alias_rule().search(query)) is expected


def test_alias_rule_is_linear_on_the_input_that_used_to_hang_it():
    rule = _alias_rule()
    start = time.perf_counter()
    rule.search(_adversarial(65_536))
    elapsed = time.perf_counter() - start
    # The old pattern needed ~59 s for 3.2 KB and this is 20x that size.
    assert elapsed < 2.0, f"{elapsed:.2f}s on 64 KB — the blow-up is back"


# ── 3. the validator's cost check ────────────────────────────────────────────────────────

KNOWN_BAD = [
    r"Authorization:\s*Bearer\s+(?:[A-Za-z0-9]+_?)+$",
    r"User-Agent:\s*(?:[A-Za-z0-9]+-?)+\s*$",
    r"(\w+\s*:\s*\w+\s*\{.*?){10,}",
]


@pytest.mark.parametrize("pattern", KNOWN_BAD)
def test_validator_rejects_every_known_bad_pattern(pattern):
    """Rejected for some reason — two of these are too broad and never reach check 6."""
    from honeylens.analysis.rule_validator import validate_rule

    ok, _reason = validate_rule("claude_probe_rule", "RECON", pattern)
    assert not ok, "a pattern that blows up on a near-match was accepted"


@pytest.mark.parametrize("pattern", KNOWN_BAD[:2])
def test_the_cost_check_sees_the_immediate_blow_ups(pattern):
    """The `(X+)+` family: ambiguity that shows up within a couple of dozen characters."""
    from honeylens.analysis.rule_validator import _redos_cost

    _spent, culprit = _redos_cost(re.compile(pattern, re.IGNORECASE | re.DOTALL))
    assert culprit is not None, "the timing probe missed a pattern that blows up"


def test_the_cost_check_cannot_see_high_threshold_patterns_and_says_so():
    """The documented gap, pinned so it is a known limit rather than a surprise.

    The original `graphql_alias_dos` needs ten repetitions of an eight-character body —
    eighty characters before anything happens — and the probe ladder stops at 24. It stops
    there because a longer ladder is unsafe: `(a+){40,}` costs nothing at 38 characters and
    2^40 at 40, so there is no gradual signal to stop on and the probe itself hangs.
    Verified by trying it.

    This pattern is still refused, by the specificity check rather than the cost check, and
    the classifier's length cap is what bounds a rule that slips past both.
    """
    from honeylens.analysis.rule_validator import _redos_cost, validate_rule

    pattern = r"(\w+\s*:\s*\w+\s*\{.*?){10,}"
    _spent, culprit = _redos_cost(re.compile(pattern, re.IGNORECASE | re.DOTALL))
    assert culprit is None, (
        "the cost check now reaches high-threshold patterns — good, but then the comment "
        "on _REDOS_PRESSURE is stale and the ladder's safety needs re-measuring"
    )
    ok, _reason = validate_rule("claude_probe_rule", "RECON", pattern)
    assert not ok, "nothing rejects it any more"


def test_asking_is_cheap_even_for_a_pathological_candidate():
    """The bound that matters: a bad rule must not take the validator down with it.

    `(a+){40,}` is the shape that broke the first two attempts at this check — once by
    building a 64-character run from the candidate's own repetition count, once by
    climbing a doubling ladder into it (168 seconds).
    """
    from honeylens.analysis.rule_validator import _redos_cost

    for pattern in (r"(a+){40,}$", r"^(a+)+$", r"^(a|aa)+$", *KNOWN_BAD):
        start = time.perf_counter()
        _redos_cost(re.compile(pattern, re.IGNORECASE | re.DOTALL))
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"{pattern!r} cost {elapsed:.1f}s to evaluate"


def test_the_cost_check_is_what_catches_the_one_the_others_miss():
    """This is the case that justifies check 6 existing at all.

    `Authorization:\\s*Bearer\\s+(?:[A-Za-z0-9]+_?)+$` is specific, does not match the
    empty string, is not degenerate and does not fire on the benign corpus — it passes all
    five precision checks. It also doubles its run time per added character: 0.7 ms at 14
    characters, 5.6 s at 27.
    """
    from honeylens.analysis.rule_validator import validate_rule

    ok, reason = validate_rule(
        "claude_bearer_rule", "RECON", r"Authorization:\s*Bearer\s+(?:[A-Za-z0-9]+_?)+$"
    )
    assert not ok
    assert "too slow" in reason, f"checks 1-5 caught it instead, on: {reason}"


def test_every_shipped_rule_passes_the_cost_check():
    """The check has to be free for healthy patterns or it cannot stay switched on."""
    from honeylens.analysis.rule_validator import _redos_cost
    from honeylens.classification import text_rules as tr

    offenders = []
    start = time.perf_counter()
    for _atype, name, rule in tr._RULES:
        _spent, culprit = _redos_cost(rule)
        if culprit is not None:
            offenders.append(name)
    elapsed = time.perf_counter() - start
    assert not offenders, f"the cost check rejects shipped rules: {offenders}"
    assert elapsed < 10.0, f"sweeping {len(tr._RULES)} rules took {elapsed:.1f}s"


def test_a_healthy_specific_pattern_is_still_accepted():
    from honeylens.analysis.rule_validator import validate_rule

    ok, reason = validate_rule(
        "probe_log4shell", "RCE", r"\$\{jndi:(ldap|rmi|dns):/[^}]{4,}\}", None
    )
    assert ok, f"a normal signature was rejected: {reason}"


def test_the_nesting_hint_is_only_a_hint():
    """A quantified group containing a quantifier is not by itself a defect.

    `graphql_deep_nesting` has that shape and is linear, because two literal braces per
    repetition leave nothing to redistribute. If the check ever rejects on shape alone,
    this is the rule it would wrongly kill.
    """
    from honeylens.analysis.rule_validator import _has_nested_quantifier, _redos_cost
    from honeylens.classification import text_rules as tr

    rule = next(rx for _, name, rx in tr._RULES if name == "graphql_deep_nesting")
    assert _has_nested_quantifier(rule.pattern), "expected this rule to have the shape"
    _spent, culprit = _redos_cost(rule)
    assert culprit is None, "shape alone must not condemn a pattern that is fast"
    start = time.perf_counter()
    rule.search("{a{" * 4 + "X" * 20_000)
    assert time.perf_counter() - start < 1.0


def test_probe_generation_targets_the_quantified_group():
    """The generic homogeneous runs never got past a literal prefix; these do."""
    from honeylens.analysis.rule_validator import _redos_probes

    probes = _redos_probes(r"Authorization:\s*Bearer\s+(?:[A-Za-z0-9]+_?)+$")
    assert any("Authorization" in p for p in probes), (
        "no probe reaches past the pattern's literals, so the ambiguity is never exercised"
    )
    assert all(p.endswith("\x00") for p in probes[: len(probes)]), (
        "probes must force a failed match — that is the expensive direction"
    )


def test_counting_pattern_quacks_like_a_compiled_pattern():
    """The scoring helpers and the golden snapshot read .pattern and .flags."""
    from honeylens.classification.text_rules import _CountingPattern

    rule = _CountingPattern(r"\bx\s*:", 3, re.IGNORECASE)
    assert isinstance(rule.pattern, str)
    assert isinstance(rule.flags, int)
    assert rule.search("x: x: ") is None
    match = rule.search("x: x: x: ")
    assert match is not None and match.group(0)
