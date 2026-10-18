"""The corrective ICS backfill: a wrong stored value is cleared, never preserved.

The defect: ``ics_events`` held rows written by logic that has since been deleted -- 15 rows
with ``T0801`` (a read technique) on a function code the Modbus specification does not
define, 2 with an enterprise technique (``T1046``), ~2,960 pre-cutover rows with NULL
``semantics`` and ``is_read`` set by a substring match on the rule name, and no ``T0855`` on
any sensor although genuine IEC-104 commands were stored. The backfill's own private copy
of the MITRE dispatcher also lacked the ``anomaly`` fix, so re-running it would have
reproduced the defect. These tests run the whole pass against an in-memory fake of the
table: no PostgreSQL is involved.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from honeylens.tools import backfill_ics as bf

FLAGS = ("is_read", "is_write", "is_control", "is_discovery", "is_anomaly")


def make_row(event_id="e1", **kw: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "event_id": event_id,
        "protocol": "modbus",
        "function_code": None,
        "attack_type": "ICS_ATTACK",
        "rule_name": "modbus_event",
        "semantics": None,
        "is_read": False,
        "is_write": False,
        "is_control": False,
        "is_discovery": False,
        "is_anomaly": False,
        "mitre_technique": None,
        "mitre_tactic": None,
        "ie_metadata": None,
        "se_metadata": None,
    }
    row.update(kw)
    return row


class FakeCursor:
    def __init__(self, store: dict[str, dict[str, Any]], log: list[str], ro: list[bool]):
        self.store, self.log, self._rows, self.store_readonly = store, log, [], ro

    def execute(self, sql, params=None):
        self.log.append(" ".join(sql.split()))
        s = " ".join(sql.split())
        if s.upper().startswith("SET TRANSACTION READ ONLY"):
            self.read_only = True
            self.store_readonly[0] = True
        elif s.upper().startswith("UPDATE") and self.store_readonly[0]:
            raise RuntimeError("cannot execute UPDATE in a read-only transaction")
        elif s.upper().startswith("SELECT"):
            self._rows = [tuple(r[c] for c in bf.SELECT_COLUMNS) for r in self.store.values()]
        elif s.upper().startswith("UPDATE ICS_EVENTS"):
            sem, rd, wr, ct, di, an, tactic, tech, eid = params
            self.store[eid].update(
                semantics=sem,
                is_read=rd,
                is_write=wr,
                is_control=ct,
                is_discovery=di,
                is_anomaly=an,
                mitre_tactic=tactic,
                mitre_technique=tech,
            )

    def fetchmany(self, n):
        out, self._rows = self._rows[:n], self._rows[n:]
        return out

    def fetchall(self):
        out, self._rows = self._rows, []
        return out

    def close(self):
        pass


class FakeConn:
    def __init__(self, rows):
        self.store = {r["event_id"]: dict(r) for r in rows}
        self.log: list[str] = []
        self.commits = 0
        self.ro = [False]

    def cursor(self, *a, **k):
        return FakeCursor(self.store, self.log, self.ro)

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass

    def close(self):
        pass


@pytest.fixture(autouse=True)
def _journal_in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def run(monkeypatch, rows, dry_run=False, conn=None):
    conn = conn or FakeConn(rows)
    monkeypatch.setattr(bf, "legacy_get_db", lambda: conn)
    stats = bf.correct(dry_run=dry_run)
    return conn, stats


def _backfilled(monkeypatch, row):
    conn, _ = run(monkeypatch, [row])
    return conn.store[row["event_id"]]


# --- the five brief tests ----------------------------------------------------------


def test_a_wrong_technique_is_cleared_not_preserved(monkeypatch):
    """15 rows carry T0801 on an undefined function code (hex ``5a`` = FC 90);
    'never downgrade a row that already has facts' does not protect a wrong value."""
    row = make_row(
        function_code=90,
        is_read=True,
        mitre_technique="T0801",
        mitre_tactic="collection-ics",
        ie_metadata={"pdu_hex": "5a0000"},
    )
    out = _backfilled(monkeypatch, row)
    assert out["mitre_technique"] is None and out["mitre_tactic"] is None
    assert out["semantics"] == "anomaly" and out["is_anomaly"] and not out["is_read"]


def test_a_wrong_technique_with_no_hex_is_cleared_from_the_function_code(monkeypatch):
    """Same 15 rows when the hex was never stored: FC 90 alone shows it is undefined."""
    row = make_row(function_code=90, mitre_technique="T0801", mitre_tactic="collection-ics")
    assert _backfilled(monkeypatch, row)["mitre_technique"] is None


def test_an_enterprise_technique_is_removed_from_an_ics_row(monkeypatch):
    row = make_row(
        protocol="mqtt",
        attack_type="MQTT_PROBE",
        mitre_technique="T1046",
        mitre_tactic="discovery",
    )
    out = _backfilled(monkeypatch, row)
    assert out["mitre_technique"] != "T1046"
    assert out["mitre_technique"] == "T0861"  # the verdict says enumerate: all that is known


def test_a_pre_cutover_row_with_no_hex_gets_what_its_columns_support_and_no_more(monkeypatch):
    """is_read came from a substring match on the rule name; nothing supports 'read'."""
    row = make_row(
        protocol="s7comm",
        attack_type="ICS_RECON",
        rule_name="s7comm_read_szl_probe",
        is_read=True,
        mitre_technique="T0801",
        mitre_tactic="collection-ics",
    )
    r = _backfilled(monkeypatch, row)
    assert r["semantics"] in ("enumerate", "discovery", None)
    assert r["mitre_technique"] != "T0801" and not r["is_read"]


def test_a_row_nothing_supports_stays_null_and_is_counted(monkeypatch):
    """ICS_ATTACK says 'hostile', not what it did: no semantics is invented for it."""
    row = make_row(
        protocol="enip",
        attack_type="ICS_ATTACK",
        is_read=True,
        mitre_technique="T0801",
        mitre_tactic="collection-ics",
    )
    conn, stats = run(monkeypatch, [row])
    out = conn.store["e1"]
    assert out["semantics"] is None and out["mitre_technique"] is None
    assert stats.unresolved == 1


def test_running_it_twice_changes_nothing_the_second_time(monkeypatch):
    rows = [
        make_row("a", function_code=90, mitre_technique="T0801", ie_metadata={"pdu_hex": "5a"}),
        make_row("b", protocol="mqtt", attack_type="MQTT_PROBE", mitre_technique="T1046"),
        make_row("c", protocol="iec104", function_code=45, is_read=True),
        make_row("d", function_code=3),
        make_row("e", protocol="enip", is_read=True, mitre_technique="T0801"),
    ]
    conn, first = run(monkeypatch, rows)
    assert first.changed >= 4
    snapshot = {k: dict(v) for k, v in conn.store.items()}
    conn.log.clear()
    _, second = run(monkeypatch, [], conn=conn)
    assert not any(s.upper().startswith("UPDATE") for s in conn.log)
    assert second.changed == 0
    assert conn.store == snapshot


def test_it_touches_only_ics_events(monkeypatch):
    rows = [make_row("a", function_code=90, mitre_technique="T0801"), make_row("b")]
    conn, _ = run(monkeypatch, rows)
    written = set()
    for s in conn.log:
        m = re.match(r"(?:UPDATE|INSERT INTO|DELETE FROM)\s+(\w+)", s, re.I)
        if m:
            written.add(m.group(1))
    assert written == {"ics_events"}


# --- dry-run -----------------------------------------------------------------------


def test_dry_run_writes_nothing_and_counts_what_it_would_change(monkeypatch):
    rows = [
        make_row("a", function_code=90, mitre_technique="T0801", ie_metadata={"pdu_hex": "5a"}),
        make_row("b", protocol="mqtt", attack_type="MQTT_PROBE", mitre_technique="T1046"),
        make_row("c", protocol="iec104", function_code=45),
    ]
    conn, stats = run(monkeypatch, rows, dry_run=True)
    assert stats.changed == 3
    assert conn.commits == 0
    assert conn.log[0] == "SET TRANSACTION READ ONLY"
    assert all(s.upper().startswith(("SELECT", "SET TRANSACTION READ ONLY")) for s in conn.log)
    assert conn.store == {r["event_id"]: r for r in rows}
    assert stats.cleared_anomaly == 1 and stats.cleared_enterprise == 0
    assert stats.assigned >= 1


def test_the_dry_run_report_breaks_the_change_down(monkeypatch):
    rows = [make_row("a", function_code=90, mitre_technique="T0801")]
    _, stats = run(monkeypatch, rows, dry_run=True)
    text = bf.format_report(stats, dry_run=True)
    assert "DRY RUN" in text and "nothing was written" in text
    assert (
        "1 rows scanned" in text
        and "cleared, total" in text
        and re.search(r"out-of-spec frame\s+1\b", text)
    )


# --- the corrections the plan counts on --------------------------------------------


def test_iec104_commands_get_command_semantics_and_t0855(monkeypatch):
    """T0855 had never been assigned although 40 genuine commands were stored."""
    row = make_row(
        protocol="iec104", function_code=45, ie_metadata={"asdu_hex": "2d01060001000100000001"}
    )
    out = _backfilled(monkeypatch, row)
    assert out["semantics"] == "command" and out["mitre_technique"] == "T0855"
    assert out["is_control"]


def test_hex_is_found_in_the_ingests_own_precedence_order(monkeypatch):
    """pdu_hex outranks payload_hex, as in the live ingest (one list, not two)."""
    row = make_row(ie_metadata={"payload_hex": "5a", "pdu_hex": "03000000 01".replace(" ", "")})
    assert _backfilled(monkeypatch, row)["semantics"] == "read"


def test_hex_is_read_from_sensor_events_metadata_when_ics_metadata_is_empty(monkeypatch):
    """Pre-cutover rows keep the frame only on the sensor_events row."""
    row = make_row(se_metadata='{"pdu_hex": "5a00"}')
    assert _backfilled(monkeypatch, row)["semantics"] == "anomaly"


def test_the_decoys_own_boolean_outranks_the_decoder_as_in_the_live_ingest(monkeypatch):
    row = make_row(ie_metadata={"pdu_hex": "03000000 01".replace(" ", ""), "is_write": True})
    out = _backfilled(monkeypatch, row)
    assert out["is_write"] is True and out["semantics"] == "read"


def test_the_private_dispatcher_copy_is_gone():
    """Two implementations of one rule is what the plan was unpicking."""
    assert not hasattr(bf, "_pick_ics_mitre")


def test_unusable_metadata_does_not_stop_the_pass(monkeypatch):
    row = make_row("a", ie_metadata="not json", se_metadata=["x"], function_code=3)
    assert _backfilled(monkeypatch, row)["semantics"] == "read"


def test_a_mode_must_be_chosen_explicitly(monkeypatch):
    monkeypatch.setattr("sys.argv", ["backfill_ics", "--dry-run"])
    with pytest.raises(SystemExit):
        bf.main()


def test_limit_with_correct_is_rejected_not_ignored(monkeypatch):
    """--correct --limit 100 silently meaning 'every row' is the wrong failure direction
    for an irreversible pass."""
    monkeypatch.setattr("sys.argv", ["backfill_ics", "--correct", "--limit", "100"])
    with pytest.raises(SystemExit):
        bf.main()


def test_the_database_refuses_a_write_in_a_dry_run(monkeypatch):
    """The dry-run guarantee is held by the engine (SET TRANSACTION READ ONLY), not only by
    an ``if not dry_run`` in the loop."""
    conn = FakeConn([make_row(function_code=90, mitre_technique="T0801")])
    monkeypatch.setattr(bf, "legacy_get_db", lambda: conn)
    bf.correct(dry_run=True)
    assert conn.ro[0] is True
    with pytest.raises(RuntimeError, match="read-only"):
        conn.cursor().execute("UPDATE ics_events SET semantics = %s", ("x",))


def test_every_clear_is_journaled_with_its_old_values(monkeypatch, tmp_path):
    """The pass is irreversible; the old tuple of each rewritten row is the only record."""
    import json

    path = tmp_path / "j.jsonl"
    rows = [
        make_row(
            "a",
            function_code=90,
            is_read=True,
            mitre_technique="T0801",
            mitre_tactic="collection-ics",
        ),
        make_row("b", function_code=3),
    ]
    conn = FakeConn(rows)
    monkeypatch.setattr(bf, "legacy_get_db", lambda: conn)
    stats = bf.correct(journal_path=str(path))
    lines = [json.loads(x) for x in path.read_text().splitlines()]
    a = next(x for x in lines if x["event_id"] == "a")
    assert a["mitre_technique"] == "T0801" and a["is_read"] is True and a["semantics"] is None
    assert set(a) == set(bf.JOURNAL_KEYS)
    assert len(lines) == stats.changed
    assert str(path) in bf.format_report(stats, dry_run=False)


def test_a_dry_run_creates_no_journal(monkeypatch, tmp_path):
    run(monkeypatch, [make_row(function_code=90, mitre_technique="T0801")], dry_run=True)
    assert list(tmp_path.iterdir()) == []


def test_a_cleared_tactic_is_not_reported_as_cosmetic(monkeypatch):
    """technique NULL, tactic 'collection-ics', nothing resolvable: the tactic is cleared, and
    the counter that authorises the run must not call that 'respelled only'."""
    row = make_row(protocol="enip", mitre_technique=None, mitre_tactic="collection-ics")
    _, stats = run(monkeypatch, [row], dry_run=True)
    assert stats.tactic_cleared == 1 and stats.tactic_only == 0
    assert "tactic only (technique already NULL)" in bf.format_report(stats, dry_run=True)


def test_no_bytes_and_bytes_that_would_not_decode_are_counted_apart(monkeypatch):
    rows = [
        make_row("a", protocol="enip"),
        make_row("b", protocol="enip", ie_metadata={"data_hex": "zzzz"}),
    ]
    _, stats = run(monkeypatch, rows, dry_run=True)
    assert stats.evidence["none"] == 1 and stats.evidence["bytes_undecoded"] == 1
    assert stats.unresolved == 2


def test_a_code_rebuilt_from_the_rule_name_is_not_called_stored(monkeypatch):
    rows = [
        make_row("a", function_code=3),
        make_row("b", function_code=None, rule_name="modbus_read_coils"),
    ]
    _, stats = run(monkeypatch, rows, dry_run=True)
    assert stats.evidence["function_code"] == 1 and stats.evidence["rule_name"] == 1


def test_the_ingest_and_the_correction_agree_on_a_row_with_only_a_function_code():
    """A modbus row with no hex, function_code=3 and verdict ICS_ATTACK: the ingest used to
    write NULL while --correct wrote 'read', so a later run kept 'correcting' fresh rows.
    Both now call ics_helpers.resolve_semantics."""
    from honeylens.ingest.ics_helpers import resolve_semantics

    live = resolve_semantics("modbus", {"fc": 3}, 3, "ICS_ATTACK")
    res = bf.resolve("modbus", 3, "ICS_ATTACK", "modbus_event")
    assert live[0] == res.semantics == "read" and res.evidence == "function_code"
    assert resolve_semantics("enip", {}, 0x65, "ICS_ATTACK")[0] is None


def test_the_evidence_helpers_are_public_in_honeylens_ics():
    import honeylens.ics as ics
    from honeylens.ingest import honeypot
    from honeylens.routes import ics as ics_route

    # One tuple, owned by honeylens.ics and imported by the API; no private alias in the ingest.
    assert ics_route.ICS_HEX_KEYS is ics.ICS_HEX_KEYS
    assert not hasattr(honeypot, "_ICS_HEX_KEYS")
    assert callable(ics.ics_frame_hex) and callable(ics.ics_flag)
    assert not hasattr(honeypot, "_ics_frame_hex") and not hasattr(honeypot, "_ics_flag")
