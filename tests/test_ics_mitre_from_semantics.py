"""MITRE for an ICS row follows what the frame means, from one table."""

from honeylens.classification.mitre_mapping import _ICS_ENTRY_META, ATTACK_TO_MITRE
from honeylens.ics import SEMANTICS
from honeylens.ingest.honeypot import _ics_row
from honeylens.ingest.ics_helpers import (
    SEMANTICS_TO_MITRE,
    pick_ics_mitre,
    semantics_to_mitre,
    verdict_to_semantics,
)
from tests.ics_fakes import col, rec_iec104_single_command, rec_modbus, rec_modbus_fc90, rec_with


def test_an_anomaly_asserts_no_technique():
    """15 rows carry T0801 — a *read* technique — on an undefined function code."""
    assert semantics_to_mitre("anomaly") == (None, None)


def test_a_command_resolves_T0855_which_has_never_been_assigned_on_any_sensor():
    assert semantics_to_mitre("command") == ("T0855", "execution-ics")


def test_a_write_is_modify_parameter_not_modify_controller_tasking():
    assert semantics_to_mitre("write")[0] == "T0836"


def test_ics_attack_has_no_verdict_fallback():
    assert verdict_to_semantics("ICS_ATTACK") is None
    assert verdict_to_semantics("CREDENTIAL_CAPTURE") is None


def test_the_matrix_and_the_ingest_cannot_disagree():
    """ATTACK_TO_MITRE['ICS_ATTACK'] is derived from SEMANTICS_TO_MITRE, so the
    coverage matrix renders exactly the techniques the ingest can assign."""
    derived = {m["technique"] for m in ATTACK_TO_MITRE["ICS_ATTACK"]}
    assert derived == {v[0] for v in SEMANTICS_TO_MITRE.values() if v}
    assert "T0814" not in derived and "T0836" in derived


def test_every_semantics_value_has_a_row_in_the_table():
    """A semantics the table lacks would silently get no technique."""
    assert set(SEMANTICS_TO_MITRE) == set(SEMANTICS)


def test_the_ebpf_path_still_selects_by_operation_for_the_modbus_key():
    """ebpf.py has no decoy metadata and no codes. pick_ics_mitre is untouched; the MODBUS
    key it reads for modbus detections keeps its own techniques."""
    assert pick_ics_mitre("MODBUS", "modbus_write_register", {"is_write": True}) == (
        "T0821",
        "impair-process-control",
    )


def test_the_fallback_maps_the_verdicts_the_store_writes():
    expected = {
        "ICS_RECON": "enumerate",
        "MODBUS_RECON": "enumerate",
        "MQTT_PROBE": "enumerate",
        "MQTT_ENUMERATION": "enumerate",
        "ics_enumeration": "enumerate",
        "SCANNER": "discovery",
        "ics_recon_function_code": "discovery",
        "MQTT_INJECT": "write",
    }
    assert {v: verdict_to_semantics(v) for v in expected} == expected
    assert verdict_to_semantics(None) is None and verdict_to_semantics("SQLI") is None


# --- through the row builder ---------------------------------------------------------


def test_a_single_command_row_carries_T0855():
    """The 40 genuine IEC-104 commands in the store had no technique at all."""
    row = _ics_row(rec_iec104_single_command(), "e" * 32, "ICS_ATTACK")
    assert (col(row, "mitre_technique"), col(row, "mitre_tactic")) == ("T0855", "execution-ics")


def test_a_modbus_read_row_carries_T0801_whatever_the_verdict_is_called():
    """The verdict name used to decide whether MITRE was assigned at all."""
    for verdict in ("ICS_ATTACK", "ICS_RECON", "SOMETHING_NEW"):
        row = _ics_row(rec_modbus(), "e" * 32, verdict)
        assert col(row, "mitre_technique") == "T0801", verdict


def test_an_undefined_function_code_row_gets_no_technique():
    row = _ics_row(rec_modbus_fc90(), "e" * 32, "ICS_ATTACK")
    assert col(row, "mitre_technique") is None and col(row, "mitre_tactic") is None


def test_a_record_with_no_hex_still_produces_a_row():
    row = _ics_row(
        rec_with(honeypot="s7comm", metadata={"phase": "cotp102"}), "e" * 32, "ICS_RECON"
    )
    assert col(row, "semantics") == "enumerate"  # from the verdict fallback


def test_the_verdict_fallback_sets_the_booleans_to_agree_with_semantics():
    """Semantics 'enumerate' next to five Falses would make the dashboard's counters
    disagree with its own semantics column."""
    rec = rec_with(honeypot="s7comm", metadata={"phase": "cotp102"})
    row = _ics_row(rec, "e" * 32, "ICS_RECON")
    assert col(row, "is_discovery") is True
    assert not any(col(row, f) for f in ("is_read", "is_write", "is_control", "is_anomaly"))
    assert (col(row, "mitre_technique"), col(row, "mitre_tactic")) == (
        "T0861",
        "collection-ics",
    )


def test_a_hostile_verdict_with_no_bytes_stays_unlabelled():
    rec = rec_with(honeypot="s7comm", metadata={"phase": "cotp102"})
    row = _ics_row(rec, "e" * 32, "ICS_ATTACK")
    assert col(row, "semantics") is None and col(row, "mitre_technique") is None
    assert not any(col(row, f) for f in ("is_read", "is_write", "is_control", "is_discovery"))


def test_a_comma_joined_summary_uses_the_first_verdict_that_has_a_meaning():
    rec = rec_with(honeypot="s7comm", metadata={"phase": "cotp102"})
    row = _ics_row(rec, "e" * 32, "ICS_ATTACK,SCANNER")
    assert col(row, "semantics") == "discovery" and col(row, "mitre_technique") == "T0846"


def test_a_decoded_frame_outranks_the_verdict():
    row = _ics_row(rec_modbus(), "e" * 32, "SCANNER")
    assert col(row, "semantics") == "read" and col(row, "is_discovery") is False


# --- the passive eBPF path reads the same derived list --------------------------------


def test_both_paths_agree_on_a_write():
    assert (
        pick_ics_mitre("ICS_ATTACK", "x", {"is_write": True})[0] == semantics_to_mitre("write")[0]
    )


def test_ebpf_resolves_every_operation_but_anomaly_to_a_technique():
    """ebpf must not regress to NULL for the five is_* ops."""
    for flag in ("is_read", "is_write", "is_control", "is_discovery"):
        assert pick_ics_mitre("ICS_ATTACK", "x", {flag: True})[0] is not None, flag
    assert pick_ics_mitre("ICS_ATTACK", "modbus_scan_devices", {})[0] is not None


def test_an_ebpf_anomaly_asserts_no_technique():
    """is_anomaly fell through onto control's T0816 and reported an undefined function
    code as Device Restart/Shutdown."""
    assert pick_ics_mitre("ICS_ATTACK", "modbus_user_defined_fc", {"is_anomaly": True}) == (
        None,
        None,
    )


def test_the_display_metadata_covers_exactly_the_semantics_the_table_assigns():
    """A semantics added to SEMANTICS_TO_MITRE without display metadata would otherwise
    fail as a KeyError at import of a module the API routes load."""
    assert set(_ICS_ENTRY_META) == {k for k, v in SEMANTICS_TO_MITRE.items() if v}
