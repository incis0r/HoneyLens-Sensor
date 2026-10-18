"""The point corrections re-run the writer's own decision, not a second opinion.

Phase Z, step 8. The authoritative reprocess owns only the rows whose `rule_name` is in the
central registry; a decoy's or a vendor ingest's row is preserved by design, because the central
classifier cannot reproduce it. So three verdicts corrected in code this week are still wrong in
the store, and this tool corrects them — by calling the same function the fixed writer now calls.

That constraint is the thing worth testing. A repair that re-derives a verdict differently from
its writer is how two subsystems start disagreeing, which is the defect the whole plan is about.
"""

from __future__ import annotations

import inspect

import pytest

from honeylens.tools import repair_decoy_verdicts as rd


def test_each_repair_calls_the_writer_s_own_decision_function():
    """`hp_smb.smb1_verdict` for the SMB frame, `paloalto.decide_attack_types` for the captive
    catch-all. Neither judgement is restated here."""
    assert "smb1_verdict" in inspect.getsource(rd.repair_smb)
    assert "decide_attack_types" in inspect.getsource(rd.repair_panos_captive)


def test_writing_is_opt_in():
    """The class of job whose first unattended run wiped decoy tags."""
    src = inspect.getsource(rd.main)

    assert '"--apply", action="store_true"' in src
    assert "if args.apply" in src


@pytest.mark.parametrize("name", ["smb", "panos", "sharepoint"])
def test_every_repair_is_reachable_from_the_cli(name):
    assert name in rd._REPAIRS


def test_the_swap_is_a_delete_and_an_insert_not_an_update():
    """Migration 0012's unique index is on `(event_id, attack_type, rule_name)`, so an UPDATE
    into a pair that already exists fails the statement. `ON CONFLICT DO NOTHING` also makes a
    second run of this tool a no-op."""
    src = inspect.getsource(rd._replace_pattern)

    assert "DELETE FROM attack_patterns" in src
    assert "INSERT INTO attack_patterns" in src
    assert "ON CONFLICT DO NOTHING" in src
    assert "UPDATE attack_patterns" not in src


def test_the_severity_comes_from_the_scoring_table():
    """Not hardcoded: `SMB_SCAN` is low and `SMB_EXPLOIT_PROBE` is high because `scoring.py`
    says so, and a repair that pins its own number would drift from the live classifier."""
    src = inspect.getsource(rd._replace_pattern)

    assert "get_severity(attack_type, rule_name)" in src


def test_the_summaries_are_rebuilt_after_the_swap():
    """An event's `attack_types` is the union of its remaining pattern rows. Swapping a row
    without rebuilding leaves the event claiming a verdict no row supports — which is the
    defect migration 0012 exists for, from the other direction."""
    src = inspect.getsource(rd.main)

    assert "rebuild_attack_types" in src


def test_only_the_events_this_run_changed_are_rebuilt():
    """An earlier draft selected every event carrying one of the new verdict types, which on
    sensor-a is millions of rows of work for a few hundred thousand swaps — and rebuilding an event
    this tool never touched is a chance to get it wrong for no reason."""
    src = inspect.getsource(rd.main)

    assert "ids = sorted(touched)" in src
    assert "attack_type IN" not in src, "the rebuild must not re-select by verdict type"


@pytest.mark.parametrize("fn", [rd.repair_smb, rd.repair_panos_captive, rd.repair_sharepoint])
def test_each_repair_records_what_it_touched(fn):
    """So the rebuild above has something exact to work from."""
    assert "touched" in inspect.signature(fn).parameters
    assert "touched.add(event_id)" in inspect.getsource(fn)


def test_an_unreadable_frame_is_counted_and_skipped():
    """347,045 rows carry the frame today, but a repair must not abort a 347,000-row run on one
    bad hex string."""
    src = inspect.getsource(rd.repair_smb)

    assert "unreadable_frame" in src
    assert "except (ValueError, TypeError)" in src


def test_a_payload_that_is_not_json_is_counted_and_skipped():
    """The PAN-OS rows have NULL metadata, so the decoy's JSON payload is the only source. One
    truncated payload must not stop the run."""
    src = inspect.getsource(rd.repair_panos_captive)

    assert "payload_not_json" in src


def test_the_real_captive_paths_keep_their_verdict():
    """60 of 400 sampled rows on sensor-a re-decide to `PANOS_CAPTIVE` — the three paths the portal
    actually registers — and the repair must leave those alone rather than demoting everything
    that carries the label."""
    src = inspect.getsource(rd.repair_panos_captive)

    assert 'if any(t[0] == "PANOS_CAPTIVE" for t in types):' in src
    assert 'stats["already_correct"] += 1' in src


def test_a_posted_webshell_with_a_body_is_left_alone():
    """The drop is the event the HIGH verdict was written for. Nothing on the fleet has sent
    one — all 110 stored rows are bare GETs — but the repair must not demote one if it has."""
    src = inspect.getsource(rd.repair_sharepoint)

    assert 'if method in ("POST", "PUT") and body_len:' in src


def test_the_smb_repair_reads_the_frame_from_metadata():
    """Measured before writing the tool: 347,045 of 347,045 rows still carry
    `metadata->>'hex'`, which is what makes this correction possible at all."""
    src = inspect.getsource(rd.repair_smb)

    assert "e.metadata->>'hex'" in src
    assert "e.metadata ? 'hex'" in src
