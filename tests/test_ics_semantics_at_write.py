"""The ingest writes what the frame means, not what the rule name sounds like."""

import dataclasses

import pytest

from honeylens.ics import SEMANTICS, decode_hex, flags_for
from honeylens.ics.flags import FLAG_FOR_SEMANTICS
from honeylens.ingest.honeypot import INSERT_ICS_SQL, _ics_row
from tests.ics_fakes import (
    col,
    rec_iec104_single_command,
    rec_modbus,
    rec_modbus_fc90,
    rec_with,
)


def test_a_single_command_record_is_flagged_and_gets_semantics():
    row = _ics_row(rec_iec104_single_command(), "e" * 32, "ICS_ATTACK")
    assert col(row, "semantics") == "command" and col(row, "is_control") is True
    assert col(row, "function_code") == 45
    rec = rec_iec104_single_command()
    assert decode_hex("iec104", rec["metadata"]["apdu_hex"]).code == 45, (
        "the decoder skipped the APCI prefix: type 45, not 104 (test command, also 'command')"
    )


def test_function_code_90_sets_is_anomaly_which_nothing_wrote_before():
    row = _ics_row(rec_modbus_fc90(), "e" * 32, "ICS_ATTACK")
    assert col(row, "semantics") == "anomaly" and col(row, "is_anomaly") is True


def test_the_substring_heuristic_is_gone():
    """A rule name containing the word 'write' no longer sets is_write; 1539 rows
    were flagged is_read by this tier, including rows that were not reads."""
    rec = rec_with(honeypot="profinet", rule="pretend write request", metadata={})
    assert col(_ics_row(rec, "e" * 32, "ICS_RECON"), "is_write") is False


def test_a_record_with_no_hex_still_produces_a_row():
    """No frame bytes is not a reason to lose the row; the verdict fills the semantics
    (test_ics_mitre_from_semantics pins the values)."""
    row = _ics_row(
        rec_with(honeypot="s7comm", metadata={"phase": "cotp102"}), "e" * 32, "ICS_RECON"
    )
    assert col(row, "semantics") == "enumerate"
    assert len(row) == INSERT_ICS_SQL.count("%s")


def test_the_decoy_boolean_still_outranks_the_decoder():
    """hp_modbus derives is_write from the function code itself."""
    rec = rec_modbus(metadata={"fc": 6, "is_write": False, "pdu_hex": "060001000a"})
    assert col(_ics_row(rec, "e" * 32, "ICS_ATTACK"), "is_write") is False


def test_insert_column_order_matches_the_builder():
    assert len(_ics_row(rec_modbus(), "e" * 32, "X")) == INSERT_ICS_SQL.count("%s")


def test_a_set_point_is_a_write_although_its_semantics_is_command():
    """C_SE_NA_1/NB_1/NC_1 (types 48-50) carry semantics 'command' yet change a value."""
    for type_id in (48, 49, 50, 51):
        frame = decode_hex("iec104", f"{type_id:02x}0106000100640000" + "0a00" + "00")
        assert frame.semantics == "command" and frame.code == type_id
        assert flags_for(frame)["is_write"] is True and flags_for(frame)["is_control"] is True
    single = flags_for(decode_hex("iec104", "2d0106000100640000" + "01"))
    assert single["is_write"] is False


@pytest.mark.parametrize("semantics,flag", sorted(FLAG_FOR_SEMANTICS.items()))
def test_every_semantics_sets_exactly_one_flag(semantics, flag):
    """enumerate sets is_discovery and NOT is_read: calling enumeration a read is the
    defect that put 1539 non-read rows under is_read."""
    frame = dataclasses.replace(decode_hex("modbus", "0300000004"), semantics=semantics, code=None)
    got = flags_for(frame)
    assert {k for k, v in got.items() if v} == {flag}
    if semantics == "enumerate":
        assert got["is_read"] is False and got["is_discovery"] is True


def test_the_seven_semantics_are_all_mapped():
    assert set(FLAG_FOR_SEMANTICS) == set(SEMANTICS)


def test_each_semantics_sets_exactly_its_own_flag():
    frame = decode_hex("modbus", "0300000004")
    assert frame.semantics == "read"
    assert flags_for(frame) == {
        "is_read": True,
        "is_write": False,
        "is_control": False,
        "is_discovery": False,
        "is_anomaly": False,
    }


def test_hex_is_found_under_the_first_key_present():
    rec = rec_modbus(metadata={"pdu_hex": "5a00", "payload_hex": "0300000004"})
    assert col(_ics_row(rec, "e" * 32, "X"), "semantics") == "anomaly"


def test_migration_0011_is_one_guarded_additive_column():
    """db/migrate.py never deletes or rewrites: the migration may only add a nullable column."""
    from pathlib import Path

    import honeylens

    sql = (
        Path(honeylens.__file__).parent / "db/migrations/0011_ics_events_semantics.sql"
    ).read_text()
    body = "\n".join(
        line for line in sql.splitlines() if not line.lstrip().startswith("--")
    ).upper()
    assert "TO_REGCLASS('PUBLIC.ICS_EVENTS') IS NULL" in body, "the ics_events-absent skip"
    assert "ADD COLUMN IF NOT EXISTS SEMANTICS VARCHAR(16)" in body
    # The ingest INSERT also writes is_anomaly; the migration restates the column (idempotent,
    # a no-op where 0001 already made it) so it does not rely on another file.
    assert "ADD COLUMN IF NOT EXISTS IS_ANOMALY BOOLEAN DEFAULT FALSE" in body
    for forbidden in ("DROP ", "DELETE ", "UPDATE ", "TRUNCATE ", "NOT NULL"):
        assert forbidden not in body
    assert body.count("DEFAULT") == 1
