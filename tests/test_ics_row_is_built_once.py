"""One ``ics_events`` row builder on the honeypot ingest, carrying what the decoy sent.

``ingest/honeypot.py`` had two builders for one table. The live one
(``_ics_verdict_row``, 17 columns) wrote every row on the fleet and filled none of the
register-level or MITRE columns. The rich one (``_build_ics_row``, 23 columns) sat in an
``else`` branch reachable only by an event with no decoy name *and* an attack type of
exactly ``MODBUS`` or ``ICS_ATTACK``: ``ics_events.source`` holds twelve distinct values
on the fleet and every one of them is ``honeypot-*``, so that branch never ran. The
result on disk was ``unit_id``, ``register_start``, ``register_count``, ``data_value``
and both MITRE columns NULL on every row, while ``iec104``'s ``type_id`` /
``common_address`` / ``ioa`` and ``mqtt``'s ``topic`` never left the decoy.

The dead builder also passed ``pick_ics_mitre(...)[0]`` — the technique — into the
``mitre_tactic`` slot and ``[1]`` — the tactic — into ``mitre_technique``, which is
``VARCHAR(16)``. A tactic slug there overflows, aborts the INSERT, and the savepoint
rolls the whole ICS row back: reviving that builder as it stood would have lost rows
rather than mislabelled them, which is why the slot order is pinned here.

What these tests hold the merged builder to: one INSERT statement for the table, the
mapped columns filled, the decoy's whole event in ``metadata``, the MITRE values each in
their own slot, the write gate (and therefore the row count) unchanged, and — the
anti-goal of the whole phase — no ICS failure, in the INSERT *or* in the row building,
ever costing the ``sensor_events`` row.
"""

from __future__ import annotations

import inspect
import json
import logging

from honeylens.honeypots import sink
from honeylens.ingest import honeypot, ics_helpers

# --------------------------------------------------------------- the recording cursor


class _Cursor:
    """Records every ``execute()``; ``fail_on`` makes one statement raise as PostgreSQL would."""

    def __init__(self, fail_on: str | None = None):
        self.calls: list[tuple[str, tuple | None]] = []
        self.rowcount = 1
        self._fail_on = fail_on

    def execute(self, sql, params=None):
        flat = " ".join(sql.split())
        self.calls.append((flat, params))
        if self._fail_on and self._fail_on in flat:
            raise RuntimeError("value too long for type character varying(16)")

    def fetchone(self):
        return None

    def fetchall(self):
        return []


def ingest_one(line: dict, fail_on: str | None = None) -> _Cursor:
    """One decoy line through the real ingest."""
    cur = _Cursor(fail_on=fail_on)
    honeypot.process_record(cur, line)
    return cur


def find_insert(cur: _Cursor, needle: str) -> tuple[str, tuple | None] | None:
    return next(((sql, params) for sql, params in cur.calls if needle in sql), None)


def find_ics_insert(cur: _Cursor) -> tuple[str, tuple | None] | None:
    return find_insert(cur, "INSERT INTO ics_events")


def _listed(sql: str, after: str) -> list[str]:
    """The comma-separated names (or placeholders) of the group following ``after``."""
    group = sql.split(after, 1)[1].split("(", 1)[1].split(")", 1)[0]
    return [item.strip() for item in group.split(",")]


def ics_params(cur: _Cursor) -> dict:
    """The ICS INSERT resolved to ``{column: value}``.

    Resolving by name rather than by position is the point: a reviewer reading
    ``row["mitre_technique"]`` is reading the column the value actually lands in.
    """
    found = find_ics_insert(cur)
    assert found is not None, "no ics_events INSERT was issued"
    sql, params = found
    columns = _listed(sql, "INSERT INTO ics_events")
    values = _listed(sql, " VALUES ")
    assert all(v == "%s" for v in values), f"a literal in the VALUES clause: {values}"
    assert len(values) == len(columns), f"{len(values)} values for {len(columns)} columns"
    assert params is not None and len(params) == len(columns), (
        f"{len(params or ())} parameters for {len(columns)} columns: the tuple and the "
        "column list have drifted apart"
    )
    return dict(zip(columns, params, strict=True))


# ------------------------------------------------------------------- the decoy events


def _record(honeypot_name: str, event: dict, *, attack_type: str | None, rules=None, dst_port: int):
    """A ``honeylens-event/1`` line exactly as ``_base.log_event`` builds it."""
    rule = event.get("rule") or event.get("phase") or f"{honeypot_name}_event"
    return sink.build_record(
        source=f"honeypot-{honeypot_name}",
        honeypot=honeypot_name,
        protocol=honeypot_name.upper(),
        peer=("203.0.113.9", 51344),
        event=event,
        payload=event.get("payload") or "",
        dst_port=dst_port,
        attack_type=attack_type,
        severity="HIGH",
        rules=[rule] if rules is None else rules,
    )


def modbus_event(
    fc: int = 3,
    rule: str = "Read Holding Registers",
    is_write: bool = False,
    attack_type: str | None = "ICS_ATTACK",
    verdict_rules=None,
    **extra,
):
    """What ``hp_modbus`` sends: ``fc``/``unit_id``/``address``/``quantity``/``pdu_hex``."""
    event = {
        "dst_port": 502,
        "phase": "modbus_request",
        "rule": rule,
        "payload": f"FC={fc} unit=1 addr=0 qty=4",
        "txn_id": 23111,
        "unit_id": 1,
        "fc": fc,
        "fc_name": rule,
        "pdu_hex": f"{fc:02x}00000004",  # the PDU of the fc it claims
        "is_write": is_write,
        "address": 0,
        "quantity": 4,
    }
    event.update(extra)
    return _record("modbus", event, attack_type=attack_type, rules=verdict_rules, dst_port=502)


def s7comm_event(**extra):
    """``s7comm`` parses no protocol fields and has no field-map entry by design."""
    event = {
        "dst_port": 102,
        "phase": "cotp_connect",
        "route": "s7",
        "bytes": 22,
        "payload": "COTP Connection Request received",
    }
    event.update(extra)
    return _record("s7comm", event, attack_type="ICS_ATTACK", dst_port=102)


def iec104_event(**extra):
    """What ``hp_iec104`` sends — its own vocabulary, and nulls on real rows."""
    event = {
        "dst_port": 2404,
        "phase": "asdu",
        "rule": "C_SC_NA_1 Single Command",
        "payload": "C_SC_NA_1 ioa=0",
        "type_id": 45,
        "type_name": "C_SC_NA_1",
        "common_address": 65535,
        "ioa": 0,
        "cot": 6,
        "asdu_hex": "2d01",
        "frame_type": "I",
    }
    event.update(extra)
    return _record("iec104", event, attack_type="ICS_ATTACK", dst_port=2404)


def mqtt_event(**extra):
    """What ``hp_mqtt`` sends. ``topic`` is attacker-chosen and credentials ride along."""
    event = {
        "dst_port": 1883,
        "phase": "publish",
        "payload": "PUBLISH plant/line1/setpoint",
        "pkt_type": 3,
        "topic": "plant/line1/setpoint",
        "qos": 0,
        "client_id": "mosqsub|1-probe",
        "message": "42",
    }
    event.update(extra)
    return _record("mqtt", event, attack_type="MQTT_ATTACK", dst_port=1883)


def profinet_event():
    event = {"dst_port": 34964, "phase": "dcp_identify", "route": "profinet", "bytes": 60}
    return _record("profinet", event, attack_type="ICS_ATTACK", dst_port=34964)


def http_event():
    event = {"dst_port": 8080, "method": "GET", "path": "/", "payload": "GET /"}
    return _record("nginx", event, attack_type="SCANNER", dst_port=8080)


# ------------------------------------------------------------------- one builder only


def test_only_one_ics_insert_statement_exists():
    """Two write paths with different column lists is the drift this task removes."""
    src = inspect.getsource(honeypot)
    assert src.count("INSERT INTO ics_events") == 1
    assert "INSERT_ICS_VERDICT_SQL" not in src and "_build_ics_row" not in src


def test_the_function_code_table_exists_once():
    """honeypot._ICS_FC and ics_helpers.ICS_FC held 45 identical keys each."""
    assert not hasattr(honeypot, "_ICS_FC")
    assert len(ics_helpers.ICS_FC) == 45


def test_the_shared_dead_builder_is_gone_too():
    """``ics_helpers.build_ics_row`` was a third copy of the same tuple, with no callers."""
    assert not hasattr(ics_helpers, "build_ics_row")


def test_the_dead_ics_context_guard_is_gone_with_its_tables():
    """Deleting ``_build_ics_row`` took ``ics_context``'s last caller with it, and a
    comment in the shared module went on saying "the honeypot ingest path keeps using
    ics_context()". That is the same false-comment defect the phase was written around,
    so the symbols go rather than the comment being patched again. ``ICS_VALID_PROTOCOLS``
    was read only by ``ics_context``; ``CALDERA_RULES`` had no reader at all here
    (``tools/cleanup_ics_fp.py`` defines its own list)."""
    for name in ("ics_context", "ICS_VALID_PROTOCOLS", "CALDERA_RULES"):
        assert not hasattr(ics_helpers, name), name
    assert "ics_context" not in (ics_helpers.__doc__ or "")


def test_the_port_table_the_passive_path_still_needs_stays():
    """``ICS_VALID_PORTS`` did not die with ``ics_context``: ``ics_port_consistent``
    reads it for the generic-ICS case, and ``ingest/ebpf.py`` calls that."""
    assert ics_helpers.ICS_VALID_PORTS
    assert "ICS_VALID_PORTS" in inspect.getsource(ics_helpers.ics_port_consistent)


# -------------------------------------------------------------- what reaches the row


def test_the_decoys_whole_event_lands_in_metadata():
    row = ics_params(ingest_one(modbus_event()))
    assert json.loads(row["metadata"])["txn_id"] == 23111, "fields with no column must survive"


def test_the_mapped_columns_are_filled():
    row = ics_params(ingest_one(modbus_event()))
    assert row["function_code"] == 3 and row["unit_id"] == 1
    assert row["register_start"] == 0 and row["register_count"] == 4
    assert row["data_value"] == "0300000004"


def test_a_non_modbus_decoy_fills_the_columns_in_its_own_vocabulary():
    """The point of the phase: iec104's type_id is the function code, its ioa the register.
    Every one of these was NULL on all 97 iec104 rows the fleet had."""
    row = ics_params(ingest_one(iec104_event()))
    assert row["function_code"] == 45 and row["function_name"] == "C_SC_NA_1"
    assert row["register_start"] == 0 and row["data_value"] == "2d01"
    assert row["device_address"] == "65535", "common_address is the device"
    assert json.loads(row["metadata"])["cot"] == 6, "cot has no column and must survive"


def test_the_device_address_column_is_written():
    """It has its own column and the field map fills it for three decoys, so leaving it
    out of the INSERT would keep it 100% NULL — the shape of the defect this phase came
    from. mqtt's topic is the one an operator actually hunts on."""
    assert ics_params(ingest_one(mqtt_event()))["device_address"] == "plant/line1/setpoint"
    assert ics_params(ingest_one(iec104_event()))["device_address"] == "65535"


def test_an_over_long_device_address_is_truncated_to_its_column():
    """VARCHAR(64), and the topic is attacker-chosen: the untruncated value is in metadata."""
    topic = "plant/" + "a" * 200
    row = ics_params(ingest_one(mqtt_event(topic=topic)))
    assert len(row["device_address"]) == 64
    assert json.loads(row["metadata"])["topic"] == topic


def test_a_null_protocol_field_leaves_its_column_null():
    """iec104 sends null type_id/common_address/ioa on real rows; absent is not zero."""
    row = ics_params(ingest_one(iec104_event(type_id=None, ioa=None)))
    assert row["function_code"] is None and row["register_start"] is None
    assert row["data_value"] == "2d01", "the rest of the row is unaffected"


def test_the_field_map_is_read_with_the_same_name_the_gate_matched():
    """ICS_FIELD_MAP is keyed by lowercase decoy name and the gate lowercases, so a decoy
    whose name arrives capitalised passes the gate; it must not then miss the map."""
    line = modbus_event()
    line["honeypot"] = "MODBUS"
    row = ics_params(ingest_one(line))
    assert row["function_code"] == 3, "the map was consulted with the raw name"
    assert row["protocol"] == "MODBUS", "the decoy's own name still goes to the column"


def test_the_identity_columns_are_what_the_live_path_wrote():
    """`source` carries the decoy name (12 distinct `honeypot-*` values on the fleet) and
    `dst_ip` keeps its placeholder, so the API's COUNT(DISTINCT dst_ip) keeps its meaning."""
    row = ics_params(ingest_one(modbus_event()))
    assert row["protocol"] == "modbus"
    assert row["source"] == "honeypot-modbus"
    assert row["src_ip"] == "203.0.113.9" and row["dst_port"] == 502
    assert row["dst_ip"] == "0.0.0.0"
    assert row["severity"] == "HIGH"


def test_the_function_name_falls_back_to_the_rule():
    """mqtt sends `rule` on 1 of 714 rows and `phase` on all of them, so the fallback is
    what gives those rows a readable function name at all."""
    row = ics_params(ingest_one(s7comm_event()))
    assert row["function_name"] == "Cotp Connect"


def test_every_text_column_fits_its_column():
    """An over-long value aborts the INSERT and the savepoint drops the whole ICS row.

    This test used to assert ``function_name`` alone and its docstring said the row was
    handled. It was not: the very same row carried a 200-character ``rule_name`` into
    ``VARCHAR(128)``, so it was still dropped, one column over, and ``attack_type``
    (``VARCHAR(64)``) was uncapped as well. Not reachable from the twelve ICS decoys
    today -- every ``rule`` and ``phase`` comes from a lookup table keyed by a parsed
    integer -- which is exactly why a test asserting one of four columns was worse than
    no test: it taught the reader the class was covered.

    ``device_address`` is the fourth, truncated inside ``map_protocol_fields``
    (``tests/test_ics_field_map.py``) because the MQTT topic is attacker-chosen.
    """
    row = ics_params(ingest_one(s7comm_event(phase="p" * 200)))
    assert len(row["function_name"]) == 64, "function_name VARCHAR(64)"
    assert len(row["rule_name"]) == 128, "rule_name VARCHAR(128)"

    row = ics_params(ingest_one(modbus_event(attack_type="A" * 200)))
    assert len(row["attack_type"]) == 64, "attack_type VARCHAR(64)"


def test_the_truncated_rule_is_the_one_the_flags_and_the_lookup_saw():
    """Truncating at the slot instead of at the source would have the heuristics read a
    different string from the one stored, so a flag could disagree with its own row."""
    row = ics_params(ingest_one(modbus_event(rule="Read Holding Registers " + "x" * 200)))
    assert row["rule_name"] == ("Read Holding Registers " + "x" * 200)[:128]
    assert row["is_read"] is True


# ------------------------------------------------------------------------- the flags


def test_the_decoys_own_is_write_wins():
    """hp_modbus computes is_write from the function code; a substring match over a
    human-readable rule name is the weaker signal and must not override it."""
    row = ics_params(ingest_one(modbus_event(fc=6, is_write=True, rule="Write Single Register")))
    assert row["is_write"] is True


def test_the_decoys_own_false_wins_over_the_rule_name():
    """The other direction: a read rule whose name happens to contain a flag word."""
    row = ics_params(ingest_one(modbus_event(fc=3, is_write=False, rule="Read Write Multiple")))
    assert row["is_write"] is False


def test_a_flag_the_decoy_does_not_send_still_comes_from_the_rule_name():
    row = ics_params(ingest_one(modbus_event(rule="Read Holding Registers")))
    assert row["is_read"] is True and row["is_control"] is False


def test_no_flag_is_ever_null():
    """The columns are BOOLEAN DEFAULT FALSE; NULL would make `WHERE is_write` ambiguous."""
    row = ics_params(ingest_one(s7comm_event()))
    for column in ("is_read", "is_write", "is_control", "is_discovery"):
        assert isinstance(row[column], bool), f"{column} is not a boolean"


# -------------------------------------------------------------------------- the MITRE


def test_mitre_lands_in_the_right_columns():
    """mitre_technique is VARCHAR(16): a tactic slug there aborts the insert and the
    savepoint drops the whole ICS row, so this is a lost row, not a wrong label."""
    row = ics_params(ingest_one(modbus_event(fc=6, is_write=True, rule="Write Single Register")))
    assert row["mitre_technique"] is not None, "a write on an ICS decoy maps to a technique"
    assert row["mitre_technique"].startswith("T") and len(row["mitre_technique"]) <= 16
    assert row["mitre_tactic"] and not row["mitre_tactic"].startswith("T")
    assert len(row["mitre_tactic"]) > 16, "the slug would not have fitted the other column"


def test_the_summary_goes_to_the_attack_type_column_while_mitre_follows_the_bytes():
    """The comma-joined summary is stored verbatim; MITRE is chosen from what the captured
    bytes mean, so a summary no ATTACK_TO_MITRE key matches ("RECON,ICS_ATTACK") neither
    helps nor hurts. Called directly: through a decoy verdict the summary is one type."""
    rec = honeypot._normalise(modbus_event())
    row = dict(
        zip(
            _listed(honeypot.INSERT_ICS_SQL, "INSERT INTO ics_events"),
            honeypot._ics_row(rec, "e" * 64, "RECON,ICS_ATTACK"),
            strict=True,
        )
    )
    assert row["mitre_technique"] == "T0801"
    assert row["attack_type"] == "RECON,ICS_ATTACK", "the summary still goes to the column"


def test_no_attack_rows_does_not_raise_and_mitre_still_follows_the_bytes():
    """A verdict with an empty rules list: no hit to map, and no exception either. MITRE
    comes from what the captured bytes mean, so a decodable read keeps its technique; it
    used to be NULL here only because MITRE was chosen from the hits."""
    row = ics_params(ingest_one(modbus_event(verdict_rules=[])))
    assert row["mitre_technique"] == "T0801" and row["mitre_tactic"] == "collection-ics"


# -------------------------------------------------------------------------- the gate


def test_a_decoy_without_a_map_entry_still_gets_a_row():
    """s7comm, mms, profinet and fox parse nothing protocol-level; they still get the row,
    with the protocol columns NULL and the whole event in metadata."""
    row = ics_params(ingest_one(s7comm_event()))
    assert row["protocol"] == "s7comm" and row["function_code"] is None
    assert json.loads(row["metadata"])["route"] == "s7"


def test_profinet_is_still_written():
    """ics_helpers.ICS_VALID_PORTS has no 34964, so a port guard would drop it; the
    honeypot.py copy of that table went with the dead builder that used it."""
    assert ics_params(ingest_one(profinet_event()))["protocol"] == "profinet"


def test_a_non_ics_decoy_writes_no_ics_row():
    assert find_ics_insert(ingest_one(http_event())) is None


def test_an_unclassified_ics_event_writes_no_ics_row():
    """The gate is `attack_types`, unchanged. Widening it to the decoy's verdict would take
    iec104 from 97 rows to ~1238: this task changes row quality, not row count."""
    quiet = s7comm_event()
    quiet.pop("attack_type", None)
    cur = ingest_one(quiet)
    assert find_insert(cur, "INSERT INTO sensor_events") is not None
    assert find_ics_insert(cur) is None


# ----------------------------------------------------- the event row is never the cost


def test_the_sensor_event_survives_a_failing_ics_insert():
    """The ICS write is secondary and stays inside its savepoint."""
    cur = ingest_one(modbus_event(), fail_on="INSERT INTO ics_events")
    assert find_insert(cur, "INSERT INTO sensor_events") is not None


def test_the_sensor_event_survives_a_failing_ics_row_build():
    """Building the row must be guarded too, not only the INSERT.

    `_savepoint(cur, ..., _ics_row(...), ...)` evaluates its arguments *before* the
    savepoint exists, so an exception raised while building the row escapes
    `process_record` entirely and the event row is lost with it. A decoy that sends a
    non-string `phase` reaches that (`rule.lower()` on an int) — and `_normalise` cannot
    rule it out, because the event dict is whatever JSON the decoy wrote.
    """
    cur = ingest_one(s7comm_event(phase=7))
    assert find_insert(cur, "INSERT INTO sensor_events") is not None, (
        "the ICS row builder raised and took the event row with it"
    )
    assert find_ics_insert(cur) is None


def test_a_lost_ics_row_says_so_in_the_journal(caplog):
    """A warning, not debug — the rule `_guarded` states in the same module: nobody reads
    debug in a daemon unit, and a decoy whose events systematically fail to build would
    stop appearing in ics_events with nothing anywhere to say why."""
    with caplog.at_level(logging.WARNING, logger="honeylens.ingest.honeypot"):
        ingest_one(s7comm_event(phase=7))
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("ICS row skipped" in m for m in warnings), f"nothing logged: {warnings}"
    assert any("s7comm" in m for m in warnings), "the message must name what was lost"


def test_a_failing_ics_row_build_is_still_a_processed_record():
    """`process_record` returns False only when the *event* row was skipped; the ingest
    truncates the log on that signal."""
    assert honeypot.process_record(_Cursor(), s7comm_event(phase=7)) is not False
