"""A captured NUL must not be able to stop an ingest.

Measured on `sensor-e`: `honeylens-ingest-fortigate.service` failed every 30 seconds from
2026-11-13 06:11 until it was found on 2026-11-14, with one line in the journal —
``Error: A string literal cannot contain NUL (0x00) characters.`` No FortiGate event
reached the database in that time and the backlog grew to 3 814 lines / 7 MB.

There is no NUL byte in the log file. The decoy serialises a captured path with
``json.dumps``, which writes NUL as the six characters ``\\u0000``; that is valid JSON, it
survives the file, and ``json.loads`` in the ingest turns it back into a real NUL. 67 of
3 816 lines carried it, in ``path`` on ``UNKNOWN_PATH`` events — ordinary ``%00`` URL
evasion, which an attacker can send to any vendor decoy at will.

Every column of `sensor_events` was safe: ``payload`` goes through ``json.dumps`` and
``metadata`` through ``safe_json_dumps``, which drops NUL from the structure before
serialising. The one value bound raw is ``attack_patterns.matched_text``, which takes the
captured path verbatim — in `ingest/fortigate.py`, and the same way in `ingest/paloalto.py`
and `ingest/honeypot.py`. `sanitise.py`'s own docstring states the contract those three
break: "EVERYTHING that comes from packets, honeypot logs or external sources passes
through here before ``cur.execute()``".

**Why one bad line ended the whole run instead of one event.** psycopg2 raises
``ValueError``, not a ``psycopg2.Error``, because adaptation fails client-side before any
statement is sent. So ``except psycopg2.Error`` does not catch it — not around that insert
and not in ``process_log_file`` — and by construction neither a savepoint nor
``ON CONFLICT DO NOTHING`` can, because there is no server round trip to guard. The
exception escaped, ``save_position()`` was never reached, the consumed-prefix trim never
ran, and the timer re-read from byte 0 and died on the same line forever.

These tests pin both halves: the value is scrubbed before it is bound, and a record that
still cannot be written is skipped and counted rather than ending the run.
"""

from __future__ import annotations

import json
import pathlib
import re

import psycopg2.extensions
import pytest

from honeylens.ingest import fortigate as fg
from honeylens.ingest import state

POISON = "/api/v2/cmdb\x00/system/admin"
CLEAN = "/remote/login"


class _AdaptingCursor:
    """A cursor that adapts its string parameters the way psycopg2 does.

    This is the whole point of the fake. The failure is a client-side adaptation error, so
    a cursor that merely records its parameters cannot see it — which is why no existing
    test caught this. ``adapt(...).getquoted()`` is the real psycopg2 code path and needs
    no connection: it returns bytes for an ordinary string and raises ``ValueError`` for
    one containing NUL.
    """

    def __init__(self, fail_on: str | None = None):
        self.statements: list[tuple[str, tuple | None]] = []
        self._last = ""
        # A value that fails to adapt for a reason we did not anticipate, so the
        # skip-and-count guard is tested on something other than NUL.
        self._fail_on = fail_on

    def execute(self, sql, params=None):
        for p in params or ():
            if isinstance(p, str):
                if self._fail_on is not None and self._fail_on in p:
                    raise ValueError("unsupported value for this column")
                psycopg2.extensions.adapt(p).getquoted()
        self.statements.append((sql, params))
        self._last = sql

    def fetchone(self):
        low = self._last.lower()
        if "information_schema.columns" in low:
            return (1,) if "source_class" in low else (2,)
        # event_exists(): nothing is in the table yet.
        return None

    def fetchall(self):
        return []

    def close(self):
        pass

    def _of(self, table: str) -> list[tuple[str, tuple | None]]:
        return [(s, p) for s, p in self.statements if f"INSERT INTO {table}" in s]

    def events(self):
        return self._of("sensor_events")

    def patterns(self):
        return self._of("attack_patterns")


class _Conn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self, *a, **kw):
        return self._cur

    def commit(self):
        pass

    def rollback(self):
        pass


def _event(path: str, event_type: str = "UNKNOWN_PATH") -> dict:
    """An event in the shape the decoy writes, UNKNOWN_PATH being the measured case."""
    return {
        "timestamp": "2026-11-13T05:11:56.865942+00:00",
        "event_type": event_type,
        "src_ip": "91.92.40.12",
        "src_port": 44321,
        "path": path,
        "method": "GET",
        "query": "",
        "user_agent": "",
        "data": {"path": path},
    }


@pytest.fixture(autouse=True)
def _schema_probe_forgotten():
    """`source_class_supported` caches per process; these tests present one schema."""
    from honeylens.ingest import _schema

    _schema.reset_capability_cache()
    yield
    _schema.reset_capability_cache()


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    """Keep the offset file out of the real state directory."""
    monkeypatch.setattr(state, "STATE_DIR", tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# The value, before it is bound
# ---------------------------------------------------------------------------


def test_a_nul_in_the_captured_path_does_not_raise_when_the_event_is_written():
    """The production failure, at the bind site, with nothing mocked but the cursor."""
    cur = _AdaptingCursor()
    fg.insert_event(_Conn(cur), _event(POISON), "evt-poison")

    assert cur.events(), "the event row was not written at all"
    assert cur.patterns(), "no attack_patterns row, so the bind site was not exercised"


def test_the_matched_text_that_is_bound_carries_no_nul():
    """Postgres rejects 0x00 in text/varchar/jsonb; this is the column that got it raw."""
    cur = _AdaptingCursor()
    fg.insert_event(_Conn(cur), _event(POISON), "evt-poison")

    _sql, params = cur.patterns()[0]
    matched_text = params[3]
    assert matched_text is not None, "the evidence was dropped rather than cleaned"
    assert "\x00" not in matched_text


def test_the_scrub_is_the_one_the_other_ingests_already_use():
    """`ingest/honeypot.py` and `ingest/ebpf.py` have bound this column through
    ``strip_nul`` all along — this defect is three writers out of five, not a missing
    helper. So the fix uses the same function rather than a new one, and that function's
    contract is NUL plus the C0 control characters, keeping ``\t``, ``\n`` and ``\r``.

    Consistency decides this, not taste: two writers already store evidence this way, and
    a second scrubbing rule would mean the same captured path reads differently depending
    on which decoy saw it.
    """
    cur = _AdaptingCursor()
    path = "/a\x00b\tc\x1fd"
    fg.insert_event(_Conn(cur), _event(path), "evt-mixed")

    _sql, params = cur.patterns()[0]
    assert params[3] == "/ab\tcd", f"not strip_nul's contract: {params[3]!r}"


def test_a_clean_path_is_still_stored_verbatim():
    """A fix that quietly rewrites ordinary paths would be worse than the defect."""
    cur = _AdaptingCursor()
    fg.insert_event(_Conn(cur), _event(CLEAN), "evt-clean")

    _sql, params = cur.patterns()[0]
    assert params[3] == CLEAN


# ---------------------------------------------------------------------------
# The consequence: the run must finish and the offset must move
# ---------------------------------------------------------------------------


def _log_with(tmp_path, *events) -> str:
    log = tmp_path / "honeypot_fortigate.json"
    log.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return str(log)


def test_a_poisoned_line_does_not_pin_the_offset_at_zero(state_dir, tmp_path):
    """The measured symptom: `.pos` reading 0 with a current mtime, forever.

    `process_all=True` so the consumed-prefix trim is not exercised here — this test is
    about the offset, and the trim has tests of its own.
    """
    cur = _AdaptingCursor()
    log = _log_with(tmp_path, _event(POISON), _event(CLEAN))

    processed, inserted = fg.process_log_file(log, _Conn(cur), process_all=True)

    assert processed == 2, f"the run stopped early: processed={processed}"
    assert inserted == 2, f"an event was lost: inserted={inserted}"
    assert state.read_position("fortigate", log) > 0, "the offset never advanced"


def test_a_record_that_cannot_be_adapted_is_skipped_not_fatal(state_dir, tmp_path):
    """Scrubbing NUL fixes the case we found; the guard covers the one we have not.

    Any client-side adaptation failure lands in the same place, so the per-event guard has
    to survive a `ValueError` as well as a `psycopg2.Error`.
    """
    cur = _AdaptingCursor(fail_on="unadaptable")
    log = _log_with(tmp_path, _event("/x/unadaptable/y"), _event(CLEAN))

    processed, inserted = fg.process_log_file(log, _Conn(cur), process_all=True)

    assert processed == 2, "the bad record ended the run"
    assert inserted == 1, f"expected the good record only, inserted={inserted}"
    assert state.read_position("fortigate", log) > 0, "the offset never advanced"


# ---------------------------------------------------------------------------
# No writer of this column is left out
# ---------------------------------------------------------------------------

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "honeylens"
# A writer that uses COPY instead of INSERT is still a writer. `backfill_attacks` has
# both, and it was the COPY path that Postgres refused on sensor-e -- an INSERT-only
# detector would have let a COPY-only writer through unchecked.
# `sanitise` owns this function. A writer that defines its own `strip_nul` passes a bare
# substring check while diverging from it: `backfill_k8s_patterns.py` carried a local copy
# that removed NUL but not the other C0 control bytes, and left `bytes` unconverted.
_IMPORTS_STRIP_NUL = re.compile(r"^from [\w.]*sanitise import [^\n]*\bstrip_nul\b", re.MULTILINE)

_PATTERN_INSERT_RE = re.compile(
    r"INSERT INTO attack_patterns|copy_from\([^)]*?\"attack_patterns\"", re.IGNORECASE | re.DOTALL
)


def _pattern_writers() -> list[str]:
    return sorted(
        str(p.relative_to(_SRC))
        for p in _SRC.rglob("*.py")
        if _PATTERN_INSERT_RE.search(p.read_text(encoding="utf-8"))
    )


# Until 2026-11-19 this list held only the five ingests, on the argument that the seven tools
# read `payload`, `metadata` or a path column back out of `sensor_events`, "where it was
# scrubbed on the way in", and so could not meet a NUL.
#
# `sensor-e` falsified that argument. Its nightly authoritative pass, 2026-11-19 01:00-01:18,
# found 16,838 attacks and lost four batches of them to exactly this error:
#
#     COPY failed, using batch insert: invalid byte sequence for encoding "UTF8": 0x00
#     [ERROR] Error writing patterns: A string literal cannot contain NUL (0x00) characters.
#
# `tools/backfill_attacks.py` was in the exempt category. One NUL per batch cost up to
# `--batch-size` events their labels, because the caller had already dropped the central rows
# and then rebuilt each summary from the patterns present -- none.
#
# **The exemption's premise is still not disproved, and that is the point.** `payload` is
# `text` and `metadata` is `jsonb`; neither column can hold a raw NUL, and a probe over
# sensor-e's 378 rows carrying an ESCAPED NUL (`\u0000` as six characters, 344 rows, plus 44
# `\x00`) produced zero snippets containing a real 0x00 under today's rules. So the reasoning
# that exempted these tools looks sound and the incident happened anyway.
#
# That is the whole argument for collapsing the categories. The split asked every future
# reader to re-derive, per writer, whether a NUL can reach it -- and the one time that
# derivation was made it was made confidently, on correct premises, and was wrong in a way
# that silently destroyed labels on a production sensor. `strip_nul` on a value that cannot
# contain NUL costs one function call. Requiring it everywhere costs nothing and removes the
# judgement call that failed.
_MUST_SCRUB = [
    "ingest/ebpf.py",
    "ingest/fortigate.py",
    "ingest/honeypot.py",
    "ingest/paloalto.py",
    "ingest/suricata.py",
    "tools/backfill_attacks.py",
    "tools/backfill_k8s_patterns.py",
    "tools/backfill_rule_profile.py",
    "tools/cleanup_false_positives.py",
    "tools/repair_netscaler_tags.py",
    "tools/repair_suricata_tags.py",
]

# The one writer that binds no `matched_text` at all, so there is no value to scrub. Verified
# by the test below rather than taken on trust -- if it ever starts binding the column, the
# exemption fails loudly.
_BINDS_NO_MATCHED_TEXT = ["tools/repair_decoy_verdicts.py"]


def test_the_tree_has_the_pattern_writers_this_fix_reasoned_about():
    """A thirteenth writer fails here, in review, rather than on a sensor at 03:31.

    Two categories, and the split is what bounds the fix. The five in `_EXTERNAL_SOURCED`
    read text nothing has scrubbed. The seven tools read `payload`, `metadata` or a path
    column back out of `sensor_events`, where it was scrubbed on the way in — and
    `tools/repair_decoy_verdicts.py` does not bind `matched_text` at all, which is why
    demanding the call in every writer would be demanding it on a value that is not there.
    """
    assert _pattern_writers() == [
        "ingest/ebpf.py",
        "ingest/fortigate.py",
        "ingest/honeypot.py",
        "ingest/paloalto.py",
        "ingest/suricata.py",
        "tools/backfill_attacks.py",
        "tools/backfill_k8s_patterns.py",
        "tools/backfill_rule_profile.py",
        "tools/cleanup_false_positives.py",
        "tools/repair_decoy_verdicts.py",
        "tools/repair_netscaler_tags.py",
        "tools/repair_suricata_tags.py",
    ]


@pytest.mark.parametrize("path", _MUST_SCRUB)
def test_every_pattern_writer_scrubs_the_text_it_binds(path):
    """`sanitise` is the single place that does this, per its own docstring: "EVERYTHING
    that comes from packets, honeypot logs or external sources passes through here before
    ``cur.execute()``"."""
    text = (_SRC / path).read_text(encoding="utf-8")
    assert "strip_nul" in text, f"{path} binds matched_text without strip_nul()"
    # Mentioning the name is not calling it. Writing this sweep on 2026-11-19 I added the
    # call to four files and the import to one; the text check stayed green on all four and
    # only `ruff` caught the three undefined names. A grep-based guard has to check the
    # import, or it certifies code that cannot run.
    assert _IMPORTS_STRIP_NUL.search(text), (
        f"{path} names strip_nul without importing it from sanitise -- either it is undefined "
        f"or it is a local copy, and sanitise.py's docstring says this lives in one place"
    )


@pytest.mark.parametrize("path", _BINDS_NO_MATCHED_TEXT)
def test_the_one_exemption_really_binds_no_matched_text(path):
    """The exemption is a fact about the file, not a decision. Pin the fact."""
    text = (_SRC / path).read_text(encoding="utf-8")
    assert "matched_text" not in text, f"{path} now binds matched_text and must scrub it"


def test_the_scrub_list_covers_every_writer_the_tree_has():
    """The two lists together must exhaust `_pattern_writers()`. A new writer that is on
    neither list fails here instead of on a sensor at 01:00."""
    assert sorted(_MUST_SCRUB + _BINDS_NO_MATCHED_TEXT) == _pattern_writers()
