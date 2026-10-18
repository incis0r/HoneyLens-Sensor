"""The intent funnel reads what the decoder saw (ics_events.semantics), not how
loud the event was."""

from __future__ import annotations

import inspect
import re

import honeylens.routes.ics as ics_routes
from honeylens.ics import SEMANTICS
from honeylens.routes.ics import _INTENT_CASE, _SUMMARY_SQL, _derive_intent


def _sql_bucket_for(sem):
    """Evaluate _INTENT_CASE for a row whose only populated column is semantics.

    Parses the WHEN/THEN branches out of the SQL text itself, so a change to the
    SQL that is not mirrored in Python makes the agreement test fail.
    """
    case = _INTENT_CASE.replace("%%", "%")
    for cond, bucket in re.findall(r"WHEN (.+?) THEN '(\w+)'", case):
        if cond == "semantics IS NULL":
            hit = sem is None
        else:
            m = re.fullmatch(r"semantics IN \(([^)]*)\)", cond)
            assert m, f"unrecognised CASE condition: {cond!r}"
            hit = sem in re.findall(r"'(\w+)'", m.group(1))
        if hit:
            return bucket
    m = re.search(r"ELSE '(\w+)'", case)
    assert m, "CASE has no ELSE"
    return m.group(1)


def test_severity_no_longer_decides_intent():
    """The old funnel bucketed anything MEDIUM as recon — that is how loud an event
    was, not what happened. Severity is no longer a parameter at all."""
    assert "severity" not in inspect.signature(_derive_intent).parameters
    assert "severity" not in _INTENT_CASE
    assert _derive_intent("command") == "command"


def test_null_semantics_is_its_own_bucket_not_enumeration():
    """Every pre-cutover row has NULL semantics; the old ELSE branch would have
    called all 2964 of them 'enumeration'."""
    assert _derive_intent(None) == "unknown"


# Written out by hand, independent of both implementations.
_EXPECTED = {
    "read": "recon",
    "discovery": "recon",
    "enumerate": "enumeration",
    "write": "write",
    "command": "command",
    "control": "command",
    "anomaly": "anomaly",
    None: "unknown",
}


def test_the_sql_case_and_the_python_agree_on_every_bucket():
    """A SQL CASE edited without its Python twin (or vice versa) shows different
    numbers in the funnel and in the event rows. Both are checked against a
    hand-written table, and against each other, for all seven values plus NULL."""
    assert set(_EXPECTED) == {*SEMANTICS, None}
    for sem in (*SEMANTICS, None):
        assert _derive_intent(sem) == _sql_bucket_for(sem) == _EXPECTED[sem], sem


def test_anomaly_is_not_unknown():
    """NULL says "we do not know what these bytes were"; anomaly says "the function
    code is outside the specification" - a positive finding. Folding one into the
    other destroys the distinction the semantics column exists to express."""
    assert _derive_intent("anomaly") != _derive_intent(None)


def test_intent_takes_no_attack_type():
    """An ignored parameter let a stale test look plausible; semantics already
    carries everything the rule name would have."""
    assert list(inspect.signature(_derive_intent).parameters) == ["semantics"]
    assert "LIKE" not in _INTENT_CASE


def test_writes_controls_counts_semantics_not_flags():
    """Two headlines reading different columns disagree; both read semantics."""
    assert "semantics IN ('write','command','control')" in _SUMMARY_SQL
    assert "is_write OR is_control" not in _SUMMARY_SQL
    src = inspect.getsource(ics_routes.ics_ip_profile)
    assert "semantics IN ('write','command','control')" in src
    assert "COUNT(*) FILTER (WHERE is_write OR is_control)" not in src
