"""The Suricata label repair, and the exclusion that stops a reprocess erasing it again.

Background, measured on sensor-a 2026-11-01: a Suricata detection lived only in
``sensor_events.attack_types`` because the ingest's companion ``attack_patterns`` insert named a
conflict target no unique index covered. ``rebuild_attack_types`` replaces the label with the
union of an event's ``attack_patterns``, so every nightly pass deleted labels with no row behind
them -- 1,991,772 of them on sensor-a, 49,772 on sensor-b, with a clean cut at the pass boundary.
"""

from __future__ import annotations

import json

import pytest

from honeylens.tools.repair_suricata_tags import decide, derive_label

_HUNT = "ET HUNTING PHP Generic Upload Progress Session Manipulation"
_EXPLOIT = "ET EXPLOIT PHP php2shell Code Injection in Filename (CVE-2026-109619)"


def _payload(signature: str, cve: str = "", severity: int = 2, hunting: bool = False) -> str:
    return json.dumps(
        {
            "suricata_sid": 2072555,
            "signature": signature,
            "category": "Misc Attack",
            "severity": severity,
            "cve": cve,
            "cve_declared": ["CVE_2026_109619"],
            "hunting": hunting,
        }
    )


def test_the_label_is_rederived_from_the_stored_alert():
    """Nothing was lost that cannot be recomputed: sid, signature and the alert JSON survive."""
    types, rule_name, severity = derive_label(
        2072554, _EXPLOIT, _payload(_EXPLOIT, "CVE-2026-109619")
    )
    assert types == "EXPLOIT,CVE_2026_109619", types
    assert rule_name == "suricata_sid_2072554"
    assert severity == "HIGH"


def test_a_hunting_rows_promoted_cve_is_withheld_on_repair():
    """Rows written before 2026-10-30 stored the promoted CVE in `cve`. A repair that trusted
    the payload would restore the wrong verdict on the six census rows, so the hunting rule is
    re-applied here rather than read back."""
    types, _rule, _sev = derive_label(2072555, _HUNT, _payload(_HUNT, "CVE-2026-109619"))
    assert "CVE_2026_109619" not in types, types
    assert types, "the attack_type itself must still come back"


def test_the_signature_wins_over_the_category_exactly_as_the_ingest_does():
    sig = "ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack"
    types, _rule, _sev = derive_label(2001, sig, _payload(sig))
    assert types == "BRUTE_FORCE", types


def test_a_signature_only_in_the_payload_is_still_usable():
    """suricata_signature is truncated to 500 chars at ingest; the payload copy is the fallback."""
    types, _rule, _sev = derive_label(2072555, None, _payload(_HUNT))
    assert types, types


@pytest.mark.parametrize(
    "sid,signature,payload", [(None, _EXPLOIT, _payload(_EXPLOIT)), (1, "", None)]
)
def test_an_undecidable_row_is_skipped_not_guessed(sid, signature, payload):
    assert derive_label(sid, signature, payload) is None


def test_a_broken_payload_degrades_to_the_generic_type_rather_than_raising():
    """The category lives only in the payload, so an unreadable payload leaves the signature
    alone to decide. This signature is not in SIGNATURE_RULES, so the honest answer is the
    generic label -- and `test_the_generic_type_never_overwrites_a_real_label` is what stops
    that answer being written over something better."""
    types, _rule, severity = derive_label(2072554, _EXPLOIT, "{not json")
    assert types == "SURICATA_ALERT", types
    assert severity == "MEDIUM", "an unreadable severity must fall back, not raise"


@pytest.mark.parametrize(
    "current,derived,expected",
    [
        # the damage this tool exists for: the label was deleted, the alert still describes it
        (None, "EXPLOIT,CVE_2026_109619", "restore"),
        ("", "BRUTE_FORCE", "restore"),
        # the one correction this tool makes: a wrongly promoted CVE comes off, base type intact
        ("EXPLOIT,CVE_2026_109619", "EXPLOIT", "correct"),
        ("SCANNER,CVE_2026_109619", "SCANNER", "correct"),
        # idempotence: a second run must write nothing
        ("EXPLOIT,CVE_2026_109619", "EXPLOIT,CVE_2026_109619", "ok"),
        ("BRUTE_FORCE", "BRUTE_FORCE", "ok"),
        # a repair that downgrades is not a repair
        ("BRUTE_FORCE", "SURICATA_ALERT", "keep"),
        ("EXPLOIT,CVE_2026_109619", "SURICATA_ALERT", "keep"),
        # rule drift is a reclassification, not a repair -- reported, never written
        ("SCANNER", "ANOMALY", "drift"),
        ("RCE", "WEB_EXPLOIT", "drift"),
        ("LFI", "INFO_DISCLOSURE", "drift"),
        ("RCE,CVE_2025_30208", "WEB_EXPLOIT,CVE_2025_30208", "drift"),
        # but an untagged row may take the generic label -- it beats nothing
        (None, "SURICATA_ALERT", "restore"),
        ("", "SURICATA_ALERT", "restore"),
    ],
)
def test_the_generic_type_never_overwrites_a_real_label(current, derived, expected):
    """The guard that makes this a repair and not a rewrite, over ~2M rows."""
    assert decide(current, derived) == expected


# ---------------------------------------------------------------------------
# The exclusion


class _SqlCapturingConn:
    def __init__(self):
        self.sql: list[tuple[str, object]] = []

    def cursor(self):
        return self

    def execute(self, sql, params=None):
        self.sql.append((sql, params))

    def fetchall(self):
        return []

    def fetchone(self):
        return (0,)


@pytest.fixture
def captured(monkeypatch):
    from honeylens.tools import backfill_attacks

    conn = _SqlCapturingConn()
    monkeypatch.setattr(backfill_attacks, "get_connection", lambda: conn)
    monkeypatch.setattr(backfill_attacks, "put_connection", lambda c: None)
    return conn


@pytest.mark.parametrize("reprocess_all", [True, False])
@pytest.mark.parametrize("last_event_id", [None, "evt-123"])
def test_the_reprocess_never_selects_suricata_rows(captured, reprocess_all, last_event_id):
    """A Suricata row's payload is our own alert JSON, so attacker-input text rules match the
    wrapper. On sensor-a that produced 9,213 pattern rows, 6,699 of them Custom_Exploit -- and
    reprocessing them is what deleted the real labels."""
    from honeylens.tools.backfill_attacks import fetch_event_batch_cursor

    fetch_event_batch_cursor(last_event_id, 100, reprocess_all=reprocess_all)
    sql, params = captured.sql[-1]
    assert "excluded_sources" in sql, sql
    assert params["excluded_sources"] == ["suricata"], params


@pytest.mark.parametrize("reprocess_all", [True, False])
def test_the_total_count_matches_what_the_reprocess_will_actually_fetch(captured, reprocess_all):
    """A count that includes rows the fetch excludes reports a pass that never ends."""
    from honeylens.tools.backfill_attacks import get_total_count

    get_total_count(reprocess_all=reprocess_all)
    counting = [(s, p) for s, p in captured.sql if "COUNT(*)" in s]
    assert counting, captured.sql
    sql, params = counting[-1]
    assert "excluded_sources" in sql, sql
    assert params["excluded_sources"] == ["suricata"], params


# ---------------------------------------------------------------------------
# Applying rule drift


def test_drift_is_opt_in_and_separate_from_the_repair():
    """`--apply` repairs; re-labelling rows whose label was never broken needs its own consent,
    because a relabel nobody asked for is indistinguishable from a bug."""
    from honeylens.tools.repair_suricata_tags import _parse_args

    assert _parse_args([]).apply_drift is False
    assert _parse_args(["--apply"]).apply_drift is False
    assert _parse_args(["--apply", "--apply-drift"]).apply_drift is True
    # permitted to parse on its own, so the tool can say it will do nothing rather than crash
    assert _parse_args(["--apply-drift"]).apply is False


class _CapturingBatchConn:
    def __init__(self):
        self.statements: list[tuple[str, list]] = []
        self.committed = False

    def cursor(self):
        return self

    def commit(self):
        self.committed = True

    def rollback(self):
        pass


def test_moving_a_pattern_row_renames_that_events_own_row_only(monkeypatch):
    """rebuild_attack_types composes the label from the pattern rows, so a relabel that leaves
    the OLD attack_type in the row is undone by the next reprocess. The move must be scoped to
    the one event and its own suricata_sid_* row -- never to a rule_name across events."""
    import psycopg2.extras

    from honeylens.tools import repair_suricata_tags as mod

    conn = _CapturingBatchConn()
    monkeypatch.setattr(mod, "get_connection", lambda: conn)
    monkeypatch.setattr(mod, "put_connection", lambda c: None)
    recorded: dict = {}

    def _fake_batch(cur, sql, rows, page_size=None):
        recorded["sql"] = sql
        recorded["rows"] = list(rows)

    monkeypatch.setattr(psycopg2.extras, "execute_batch", _fake_batch)

    moved = mod._replace_pattern_types(
        [("PROTO_ABUSE", "evt-1", "suricata_sid_2001"), ("SCANNER", "evt-2", "suricata_sid_2002")]
    )

    assert moved == 2
    assert conn.committed
    sql = " ".join(recorded["sql"].split())
    assert "UPDATE attack_patterns SET attack_type = %s" in sql
    assert "WHERE event_id = %s AND rule_name = %s" in sql
    # A second run must be a no-op rather than a unique-index violation (0012 is on
    # (event_id, attack_type, rule_name)).
    assert "NOT EXISTS" in sql
    assert recorded["rows"][0] == ("PROTO_ABUSE", "evt-1", "suricata_sid_2001", "PROTO_ABUSE")


def test_a_failed_pattern_move_reports_zero_rather_than_claiming_success(monkeypatch):
    """If the move fails the label must not be reported as relabelled, or the next reprocess
    silently reverts rows the operator was told were done."""
    import psycopg2
    import psycopg2.extras

    from honeylens.tools import repair_suricata_tags as mod

    conn = _CapturingBatchConn()
    monkeypatch.setattr(mod, "get_connection", lambda: conn)
    monkeypatch.setattr(mod, "put_connection", lambda c: None)

    def _boom(*_a, **_k):
        raise psycopg2.ProgrammingError("nope")

    monkeypatch.setattr(psycopg2.extras, "execute_batch", _boom)
    assert mod._replace_pattern_types([("X", "evt-1", "suricata_sid_1")]) == 0
    assert not conn.committed


def test_no_moves_means_no_statement(monkeypatch):
    from honeylens.tools import repair_suricata_tags as mod

    monkeypatch.setattr(mod, "get_connection", lambda: (_ for _ in ()).throw(AssertionError("!")))
    assert mod._replace_pattern_types([]) == 0


# ---------------------------------------------------------------------------
# Every action's bookkeeping, exhaustively.
#
# This exists because an edit to the branch chain in main() once dropped the restore/correct
# body entirely: the tool then reported *nothing at all* rather than failing, and it only showed
# up because a report that should have listed 444 drift rows came back empty. A loop that cannot
# be unit-tested hides that; a pure function does not.


@pytest.mark.parametrize(
    "action,current,derived,relabel,expect",
    [
        # the repair this tool is for
        ("restore", None, "EXPLOIT", False, ("restored", True, "EXPLOIT", None, False)),
        ("restore", "", "SCANNER", False, ("restored", True, "SCANNER", None, False)),
        # a hunting CVE comes off: same base type, so the pattern row already agrees
        (
            "correct",
            "EXPLOIT,CVE_2026_109619",
            "EXPLOIT",
            False,
            ("corrected", True, "EXPLOIT", None, False),
        ),
        # declined drift: label stays, pattern row must keep agreeing with the label that stays
        ("drift", "RCE", "PROTO_ABUSE", False, ("rule_drift", False, "RCE", None, True)),
        # accepted drift: label moves AND the pattern row moves with it
        (
            "drift",
            "RCE",
            "PROTO_ABUSE",
            True,
            ("drift_relabelled", True, "PROTO_ABUSE", "PROTO_ABUSE", True),
        ),
        # accepted drift where only the CVE part differs: base types match, no row to move
        ("drift", "RCE", "RCE", True, ("drift_relabelled", True, "RCE", None, True)),
        # the no-downgrade guard and the no-op
        (
            "keep",
            "BRUTE_FORCE",
            "SURICATA_ALERT",
            False,
            ("kept_generic", False, "BRUTE_FORCE", None, False),
        ),
        ("ok", "SCANNER", "SCANNER", False, ("label_ok", False, "SCANNER", None, False)),
    ],
)
def test_each_action_writes_and_counts_exactly_what_it_should(
    action, current, derived, relabel, expect
):
    from honeylens.tools.repair_suricata_tags import plan_row

    plan = plan_row(action, current, derived, relabel_drift=relabel)
    assert tuple(plan) == expect, plan


def test_declining_drift_never_writes_anything():
    """The default must be inert: reported, not written."""
    from honeylens.tools.repair_suricata_tags import plan_row

    plan = plan_row("drift", "RCE", "PROTO_ABUSE", relabel_drift=False)
    assert plan.write_label is False
    assert plan.move_pattern_to is None
    assert plan.record_as_drift is True


def test_every_decide_outcome_has_a_plan():
    """A new action with no branch would fall through to the label_ok default and silently do
    nothing -- which is exactly the failure this section was written after."""
    from honeylens.tools.repair_suricata_tags import decide, plan_row

    outcomes = {
        decide(None, "EXPLOIT"),
        decide("EXPLOIT,CVE_2026_109619", "EXPLOIT"),
        decide("RCE", "PROTO_ABUSE"),
        decide("BRUTE_FORCE", "SURICATA_ALERT"),
        decide("SCANNER", "SCANNER"),
    }
    assert outcomes == {"restore", "correct", "drift", "keep", "ok"}
    counters = {plan_row(a, "RCE", "PROTO_ABUSE", relabel_drift=False).counter for a in outcomes}
    assert len(counters) == len(outcomes), counters


def test_a_written_label_always_agrees_with_the_pattern_row():
    """The invariant the whole fix rests on: if the label moves to a new base type, the row must
    move too, or rebuild_attack_types puts the old label back."""
    from honeylens.tools.repair_suricata_tags import plan_row

    for action, relabel in (("restore", False), ("correct", False), ("drift", True)):
        plan = plan_row(action, "RCE", "PROTO_ABUSE", relabel_drift=relabel)
        if plan.write_label:
            assert plan.pattern_type == "PROTO_ABUSE"
            assert plan.move_pattern_to == "PROTO_ABUSE"


# ---------------------------------------------------------------------------
# The service gate, re-applied over stored rows (2026-11-04).
#
# The tool mirrors the ingest rather than calling it, so a gate added to process_alert does not
# reach a single stored row until it is added here too. Measured fleet-wide, the rows this
# corrects are our nginx rule 9026731 (402 rows, three of them on the nginx decoy), our Apache
# rule 9026500 (575 rows over 28 ports) and ET sid 2019526's phpinfo access (393 rows).
# ---------------------------------------------------------------------------

_NGINX = "HONEYLENS CVE-2026-42533 NGINX script-engine — over-long POST body capture"
_PHPINFO = "ET WEB_SERVER WEB-PHP phpinfo access"


def _cve_payload(signature: str, cve: str) -> str:
    return json.dumps(
        {"signature": signature, "category": "Misc Attack", "severity": 2, "cve": cve}
    )


def test_a_stored_nginx_cve_row_on_etcd_loses_the_cve():
    types, _rule, _sev = derive_label(9026731, _NGINX, _cve_payload(_NGINX, "CVE_2026_42533"), 2379)
    assert "CVE_2026_42533" not in types, types
    assert types, "the base attack_type must survive"


def test_the_same_row_on_the_nginx_decoy_keeps_the_cve():
    types, _rule, _sev = derive_label(9026731, _NGINX, _cve_payload(_NGINX, "CVE_2026_42533"), 8000)
    assert "CVE_2026_42533" in types, types


def test_a_stored_phpinfo_row_loses_the_cve_on_every_port():
    for port in (80, 8080, 9200):
        types, _rule, _sev = derive_label(
            2019526, _PHPINFO, _cve_payload(_PHPINFO, "CVE_2002_1149"), port
        )
        assert "CVE_2002_1149" not in types, (port, types)


def test_dropping_only_the_cve_is_a_correction_not_a_drift():
    """decide() must route this to `correct`, which is written by default, because the base
    attack_type is unchanged and a drift would need --apply-drift nobody has agreed to."""
    assert decide("RCE,CVE_2026_42533", "RCE") == "correct"


def test_a_caller_without_a_port_keeps_the_old_behaviour():
    """dst_port defaults to None so an old call site degrades to pre-gate behaviour rather than
    silently stripping every CVE on the fleet."""
    types, _rule, _sev = derive_label(9026731, _NGINX, _cve_payload(_NGINX, "CVE_2026_42533"))
    assert "CVE_2026_42533" in types, types


def test_a_withheld_cve_on_a_generic_base_type_is_still_corrected():
    """SURICATA_ALERT is both the generic fallback and the real label of the phpinfo rows, so the
    generic guard used to hide all 393 of them from the repair. It is narrowed to a differing
    base type: when the base agrees there is nothing to destroy."""
    assert decide("SURICATA_ALERT,CVE_2002_1149", "SURICATA_ALERT") == "correct"


def test_the_generic_guard_still_protects_a_specific_label():
    assert decide("RCE", "SURICATA_ALERT") == "keep"
    assert decide("BRUTE_FORCE,CVE_2026_1", "SURICATA_ALERT") == "keep"
