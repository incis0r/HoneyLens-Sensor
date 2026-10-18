#!/usr/bin/env python3
"""
backfill_ics.py - Populate ics_events from existing attack_patterns
=====================================================================
Scans attack_patterns table for MODBUS and ICS_ATTACK entries
and creates corresponding ics_events records with MITRE mappings.

Usage (a mode is required):
    python -m honeylens.tools.backfill_ics --correct --dry-run   # count what would change
    python -m honeylens.tools.backfill_ics --correct             # rewrite those rows
    python -m honeylens.tools.backfill_ics --insert-missing      # create missing ics_events rows
    python -m honeylens.tools.backfill_ics --fix-registers       # fill NULL register columns

--correct recomputes semantics, the five is_* flags and the MITRE pair on every existing
ics_events row, from the stored frame where there is one and from function_code / the
classifier verdict where there is not. It writes to ics_events and to nothing else.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from psycopg2.extras import execute_batch

from honeylens.database import legacy_get_db
from honeylens.ics import ics_flag
from honeylens.ingest.ics_helpers import ICS_FC, resolve_semantics, semantics_to_mitre

FLAGS = ("is_read", "is_write", "is_control", "is_discovery", "is_anomaly")

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
)
logger = logging.getLogger("backfill_ics")

# ICS function code classifications (same as ingest.py)
ICS_FUNCTION_CLASSES = {
    # text-rule names
    "modbus_read_coils": {"fc": 1, "is_read": True, "is_write": False, "severity": "LOW"},
    "modbus_read_discrete": {"fc": 2, "is_read": True, "is_write": False, "severity": "LOW"},
    "modbus_read_holding": {"fc": 3, "is_read": True, "is_write": False, "severity": "LOW"},
    "modbus_read_input": {"fc": 4, "is_read": True, "is_write": False, "severity": "LOW"},
    "modbus_write_single_coil": {"fc": 5, "is_read": False, "is_write": True, "severity": "HIGH"},
    "modbus_write_single_register": {
        "fc": 6,
        "is_read": False,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_write_multiple_coils": {
        "fc": 15,
        "is_read": False,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_write_multiple_registers": {
        "fc": 16,
        "is_read": False,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_mask_write_register": {
        "fc": 22,
        "is_read": False,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_read_write_registers": {
        "fc": 23,
        "is_read": True,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_read_device_id": {
        "fc": 43,
        "is_read": True,
        "is_write": False,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_report_slave_id": {
        "fc": 17,
        "is_read": True,
        "is_write": False,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_diagnostics": {
        "fc": 8,
        "is_read": False,
        "is_write": False,
        "is_control": True,
        "severity": "HIGH",
    },
    "modbus_restart_comm": {
        "fc": 8,
        "is_read": False,
        "is_write": False,
        "is_control": True,
        "severity": "CRITICAL",
    },
    # binary-detector names (ICS_ATTACK)
    "modbus_fc01_read_coils": {"fc": 1, "is_read": True, "severity": "LOW"},
    "modbus_fc02_read_discrete_inputs": {"fc": 2, "is_read": True, "severity": "LOW"},
    "modbus_fc03_read_holding_registers": {"fc": 3, "is_read": True, "severity": "LOW"},
    "modbus_fc04_read_input_registers": {"fc": 4, "is_read": True, "severity": "LOW"},
    "modbus_fc05_write_single_coil": {"fc": 5, "is_write": True, "severity": "HIGH"},
    "modbus_fc06_write_single_register": {"fc": 6, "is_write": True, "severity": "HIGH"},
    "modbus_fc08_diagnostics": {"fc": 8, "is_control": True, "severity": "HIGH"},
    "modbus_fc15_write_multiple_coils": {"fc": 15, "is_write": True, "severity": "HIGH"},
    "modbus_fc16_write_multiple_registers": {"fc": 16, "is_write": True, "severity": "HIGH"},
    "modbus_fc17_report_slave_id": {
        "fc": 17,
        "is_read": True,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_fc22_mask_write_register": {"fc": 22, "is_write": True, "severity": "HIGH"},
    "modbus_fc23_read_write_registers": {
        "fc": 23,
        "is_read": True,
        "is_write": True,
        "severity": "HIGH",
    },
    "modbus_fc43_read_device_id": {
        "fc": 43,
        "is_read": True,
        "is_discovery": True,
        "severity": "MEDIUM",
    },
    "modbus_illegal_fc": {"is_anomaly": True, "severity": "HIGH"},
    "modbus_user_defined_fc": {"is_anomaly": True, "severity": "MEDIUM"},
    "modbus_reserved_fc": {"is_anomaly": True, "severity": "MEDIUM"},
    # S7comm
    "s7comm_stop_cpu": {"is_control": True, "severity": "CRITICAL"},
    "s7comm_plc_stop": {"is_control": True, "severity": "CRITICAL"},
    "s7comm_write_var": {"is_write": True, "severity": "HIGH"},
    "s7comm_download_block": {"is_write": True, "severity": "CRITICAL"},
    # DNP3
    "dnp3_cold_restart": {"is_control": True, "severity": "CRITICAL"},
    "dnp3_warm_restart": {"is_control": True, "severity": "HIGH"},
    "dnp3_direct_operate": {"is_write": True, "severity": "HIGH"},
    "dnp3_direct_operate_noack": {"is_write": True, "severity": "HIGH"},
    "dnp3_select": {"is_write": True, "severity": "MEDIUM"},
    "dnp3_operate": {"is_write": True, "severity": "HIGH"},
    "dnp3_write_request": {"is_write": True, "severity": "HIGH"},
    # BACnet
    "bacnet_write_property": {"is_write": True, "severity": "HIGH"},
    "bacnet_write_property_multiple": {"is_write": True, "severity": "HIGH"},
    "bacnet_reinitialize": {"is_control": True, "severity": "CRITICAL"},
    "bacnet_reinitialize_device": {"is_control": True, "severity": "CRITICAL"},
    # OPC-UA
    "opcua_write": {"is_write": True, "severity": "HIGH"},
    "opcua_call_method": {"is_control": True, "severity": "HIGH"},
    # IEC-104
    "iec104_single_command": {"is_write": True, "severity": "HIGH"},
    "iec104_single_command_time": {"is_write": True, "severity": "HIGH"},
    "iec104_double_command": {"is_write": True, "severity": "HIGH"},
    "iec104_setpoint": {"is_write": True, "severity": "HIGH"},
    "iec104_setpoint_command": {"is_write": True, "severity": "HIGH"},
    "iec104_reset_process": {"is_control": True, "severity": "CRITICAL"},
    "iec104_regulating_step": {"is_write": True, "severity": "HIGH"},
    "iec104_parameter_change": {"is_write": True, "severity": "MEDIUM"},
    "iec104_parameter_activation": {"is_control": True, "severity": "HIGH"},
}


def get_connection():
    return legacy_get_db()


def check_tables():
    """Check required tables exist."""
    conn = get_connection()
    cur = conn.cursor()

    # Check attack_patterns
    cur.execute("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_name = 'attack_patterns'
        )
    """)
    has_patterns = cur.fetchone()[0]

    # Check ics_events
    cur.execute("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_name = 'ics_events'
        )
    """)
    has_ics = cur.fetchone()[0]

    conn.close()
    return has_patterns, has_ics


def get_ics_pattern_count():
    """Count ICS patterns to process."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT COUNT(*) FROM attack_patterns
        WHERE attack_type IN ('MODBUS', 'ICS_ATTACK')
          AND event_id NOT IN (SELECT event_id FROM ics_events)
    """)
    count = cur.fetchone()[0]
    conn.close()
    return count


# ---------------------------------------------------------------------------
# What a stored row means -- one decision, shared with the live ingest
# ---------------------------------------------------------------------------
# Until 2026-10-26 this file held its own copy of the MITRE dispatcher (`_pick_ics_mitre`)
# plus the rule-name substring tables behind it. The copy lacked the `anomaly` fix, so
# running it would have re-written the defect it was meant to correct. It is gone: the
# technique now comes from `semantics_to_mitre`, the same table the ingest uses, and the
# frame hex is found with the ingest's own `ICS_HEX_KEYS` order.


@dataclass(frozen=True)
class Resolution:
    """What the evidence on one row supports. ``evidence`` says which tier answered."""

    semantics: str | None
    flags: dict[str, bool]
    technique: str | None
    tactic: str | None
    evidence: str  # bytes | function_code | rule_name | verdict | bytes_undecoded | none


def _as_dict(value: Any) -> dict:
    """A JSONB column as a dict; anything unusable is an empty dict."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def resolve(
    protocol: str | None,
    function_code: int | None,
    attack_type: str | None,
    rule_name: str | None,
    ics_metadata: Any = None,
    event_metadata: Any = None,
) -> Resolution:
    """Recompute semantics, the five flags and the MITRE pair from the evidence on a row.

    The decision is ``ics_helpers.resolve_semantics`` -- the same call the live ingest
    makes -- so a correction run never "corrects" a row the ingest has just written. The
    one addition is here: a modbus row with no stored code may recover it from the rule
    name as an exact key into ``ICS_FC`` (never a substring), and says so in ``evidence``.
    """
    proto = str(protocol or "").lower()
    meta = {**_as_dict(event_metadata), **_as_dict(ics_metadata)}  # ics_events wins
    code: Any = function_code
    recovered = False
    if code is None and proto == "modbus":
        code = ICS_FC.get(rule_name or "", {}).get("fc")
        recovered = code is not None
    semantics, flags, evidence = resolve_semantics(proto, meta, code, attack_type)
    if evidence == "function_code" and recovered:
        evidence = "rule_name"  # the code was rebuilt from the rule name, not stored on the row
    technique, tactic = semantics_to_mitre(semantics)
    return Resolution(
        semantics,
        {name: ics_flag(name, meta, flags) for name in FLAGS},
        technique,
        tactic,
        evidence,
    )


def parse_ics_event(row):
    """
    Parse attack_patterns row into ics_events record.

    row: (event_id, attack_type, rule_name, matched_text, timestamp,
          src_ip, src_port, dst_ip, dst_port)
    """
    (
        event_id,
        attack_type,
        rule_name,
        _matched_text,
        timestamp,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    ) = row

    # Determine protocol from rule name
    protocol = "ics-generic"
    if rule_name.startswith("modbus_"):
        protocol = "modbus"
    elif rule_name.startswith("dnp3_"):
        protocol = "dnp3"
    elif rule_name.startswith("s7comm_"):
        protocol = "s7comm"
    elif rule_name.startswith("enip_") or rule_name.startswith("cip_"):
        protocol = "enip"
    elif rule_name.startswith("bacnet_"):
        protocol = "bacnet"
    elif rule_name.startswith("opcua_"):
        protocol = "opcua"
    elif rule_name.startswith("iec104_"):
        protocol = "iec104"
    elif rule_name.startswith("caldera_"):
        protocol = "caldera"
    elif dst_port:
        # Detect from port
        port_map = {
            502: "modbus",
            102: "s7comm",
            20000: "dnp3",
            44818: "enip",
            47808: "bacnet",
            4840: "opcua",
            2404: "iec104",
        }
        protocol = port_map.get(dst_port, "ics-generic")

    # Get classification
    fc_info = ICS_FUNCTION_CLASSES.get(rule_name, {})

    # semantics, flags and MITRE: the one decision the corrective pass and the ingest share.
    # No frame exists on this path, so it rests on the function code and the verdict.
    res = resolve(protocol, fc_info.get("fc"), attack_type, rule_name)

    # Severity
    severity = fc_info.get("severity", "MEDIUM")
    if "scanner" in rule_name or "probe" in rule_name:
        severity = "LOW"
    elif "restart" in rule_name or "stop" in rule_name or "crash" in rule_name:
        severity = "CRITICAL"
    elif "write" in rule_name or "download" in rule_name:
        severity = "HIGH"

    function_name = rule_name.replace("modbus_", "").replace("dnp3_", "").replace("s7comm_", "")
    function_name = function_name.replace("_", " ").title()

    return (
        event_id,
        timestamp,
        protocol,
        fc_info.get("fc"),
        function_name[:64] if function_name else None,
        str(src_ip) if src_ip else None,
        src_port,
        str(dst_ip) if dst_ip else None,
        dst_port,
        *(res.flags[f] for f in FLAGS),
        res.tactic,
        res.technique,
        attack_type,
        rule_name,
        "backfill",
        severity,
        res.semantics,
    )


def backfill(dry_run=False, limit=None):
    """Run backfill."""
    has_patterns, has_ics = check_tables()

    if not has_patterns:
        logger.error("attack_patterns table not found")
        return

    if not has_ics:
        logger.error("ics_events table not found - run setup_db.py first")
        return

    total = get_ics_pattern_count()
    if limit:
        total = min(total, limit)

    if total == 0:
        logger.info("No ICS patterns to process")
        return

    logger.info("Processing %s ICS patterns%s", total, " (dry run)" if dry_run else "")

    conn = get_connection()
    cur = conn.cursor()

    # Fetch patterns with event metadata
    query = """
        SELECT ap.event_id, ap.attack_type, ap.rule_name, ap.matched_text,
               se.timestamp, se.src_ip, se.src_port, se.dst_ip, se.dst_port
        FROM attack_patterns ap
        JOIN sensor_events se ON ap.event_id = se.event_id
        WHERE ap.attack_type IN ('MODBUS', 'ICS_ATTACK')
          AND ap.event_id NOT IN (SELECT event_id FROM ics_events)
    """
    if limit:
        query += f" LIMIT {limit}"

    cur.execute(query)
    rows = cur.fetchall()

    start_time = time.time()
    processed = 0
    errors = 0

    insert_sql = """
        INSERT INTO ics_events (
            event_id, timestamp, protocol, function_code, function_name,
            src_ip, src_port, dst_ip, dst_port,
            is_read, is_write, is_control, is_discovery, is_anomaly,
            mitre_tactic, mitre_technique, attack_type, rule_name,
            source, severity, semantics
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (event_id) DO NOTHING
    """

    batch = []
    batch_size = 1000

    for row in rows:
        try:
            ics_record = parse_ics_event(row)
            batch.append(ics_record)

            if len(batch) >= batch_size:
                if not dry_run:
                    execute_batch(cur, insert_sql, batch, page_size=500)
                    conn.commit()
                processed += len(batch)
                batch = []

                elapsed = time.time() - start_time
                rate = processed / elapsed if elapsed > 0 else 0
                logger.info(
                    "Progress: %s/%s (%s%%) - %s/sec",
                    f"{processed:,}",
                    f"{total:,}",
                    f"{100 * processed / total:.1f}",
                    f"{rate:.0f}",
                )

        except Exception as e:
            errors += 1
            logger.debug("Error processing %s: %s", row[0], e)

    # Final batch
    if batch:
        if not dry_run:
            execute_batch(cur, insert_sql, batch, page_size=500)
            conn.commit()
        processed += len(batch)

    conn.close()

    elapsed = time.time() - start_time
    rate = processed / elapsed if elapsed > 0 else 0

    logger.info("=" * 60)
    logger.info("Backfill complete%s", " (dry run)" if dry_run else "")
    logger.info("  Processed: %s", processed)
    logger.info("  Errors: %s", errors)
    logger.info("  Time: %ss | Rate: %s/sec", elapsed, rate)


def fix_registers(dry_run=False):
    """UPDATE ics_events rows with NULL register fields from sensor_events.metadata."""
    import json as _json

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT ie.event_id, se.metadata
        FROM ics_events ie
        JOIN sensor_events se ON ie.event_id = se.event_id
        WHERE ie.protocol = 'modbus'
          AND (ie.unit_id IS NULL OR ie.register_start IS NULL
               OR ie.register_count IS NULL OR ie.data_value IS NULL)
          AND se.metadata IS NOT NULL
    """)
    rows = cur.fetchall()
    if not rows:
        logger.info("No ics_events rows with missing register fields")
        conn.close()
        return
    logger.info("Fixing register fields on %s rows", len(rows))
    updated = 0
    for event_id, metadata_raw in rows:
        try:
            meta = (
                _json.loads(metadata_raw) if isinstance(metadata_raw, str) else (metadata_raw or {})
            )
        except Exception as _exc:
            logging.getLogger(__name__).debug("skipping row with bad metadata: %s", _exc)
            continue
        unit_id = meta.get("unit_id")
        register_start = meta.get("address")
        register_count = meta.get("quantity")
        _dv = meta.get("value")
        if _dv is None and meta.get("pdu_hex"):
            _dv = meta["pdu_hex"]
        data_value = str(_dv) if _dv is not None else None
        if all(v is None for v in (unit_id, register_start, register_count, data_value)):
            continue
        if not dry_run:
            cur.execute(
                """
                UPDATE ics_events
                SET unit_id        = COALESCE(unit_id,        %s),
                    register_start = COALESCE(register_start, %s),
                    register_count = COALESCE(register_count, %s),
                    data_value     = COALESCE(data_value,     %s)
                WHERE event_id = %s
            """,
                (unit_id, register_start, register_count, data_value, event_id),
            )
        updated += 1
    if not dry_run:
        conn.commit()
        logger.info("Fixed register fields on %s rows", updated)
    else:
        logger.info("[dry-run] Would fix %s rows", updated)
    conn.close()


# ---------------------------------------------------------------------------
# The corrective pass
# ---------------------------------------------------------------------------
SELECT_COLUMNS = (
    "event_id",
    "protocol",
    "function_code",
    "attack_type",
    "rule_name",
    "semantics",
    *FLAGS,
    "mitre_technique",
    "mitre_tactic",
    "ie_metadata",
    "se_metadata",
)

# LEFT JOIN: the frame of a pre-cutover row lives only on its sensor_events row.
_SELECT_SQL = """
    SELECT ie.event_id, ie.protocol, ie.function_code, ie.attack_type, ie.rule_name,
           ie.semantics, ie.is_read, ie.is_write, ie.is_control, ie.is_discovery,
           ie.is_anomaly, ie.mitre_technique, ie.mitre_tactic,
           ie.metadata, se.metadata
    FROM ics_events ie
    LEFT JOIN sensor_events se ON se.event_id = ie.event_id
    ORDER BY ie.id
"""

# The only write this tool's corrective mode makes, and to the only table it touches.
_UPDATE_SQL = """
    UPDATE ics_events
    SET semantics = %s, is_read = %s, is_write = %s, is_control = %s,
        is_discovery = %s, is_anomaly = %s, mitre_tactic = %s, mitre_technique = %s
    WHERE event_id = %s
"""


@dataclass
class CorrectionStats:
    """Counts only; nothing here holds a row."""

    scanned: int = 0
    changed: int = 0
    evidence: Counter = field(default_factory=Counter)  # tier that answered, all rows
    semantics_set: int = 0  # NULL -> a value
    semantics_changed: int = 0  # one value -> another
    semantics_cleared: int = 0  # a value -> NULL
    flags_changed: int = 0
    flags_lost: int = 0  # a True flag that ends False with no semantics behind it
    assigned: int = 0  # technique NULL -> a value
    replaced: int = 0  # technique one -> another
    cleared_anomaly: int = 0  # wrong: a technique on an out-of-spec frame
    cleared_enterprise: int = 0  # wrong: a T1xxx technique on an ICS row
    cleared_no_basis: int = 0  # technique the evidence no longer supports
    tactic_cleared: int = 0  # technique already NULL, a stored tactic the evidence drops
    tactic_only: int = 0  # same technique, tactic respelled
    unresolved: int = 0  # no bytes captured and nothing else: left NULL, cannot be corrected
    journal_path: str | None = None


def _technique_effect(old: str | None, new: str | None, semantics: str | None) -> str | None:
    if old == new:
        return None
    if old is None:
        return "assigned"
    if new is not None:
        return "replaced"
    if semantics == "anomaly":
        return "cleared_anomaly"
    if old.startswith("T1"):
        return "cleared_enterprise"
    return "cleared_no_basis"


def default_journal_path() -> str:
    return time.strftime("backfill_ics_journal-%Y%m%dT%H%M%SZ.jsonl", time.gmtime())


JOURNAL_KEYS = ("event_id", "semantics", *FLAGS, "mitre_technique", "mitre_tactic")


def correct(
    dry_run: bool = False, batch_size: int = 500, journal_path: str | None = None
) -> CorrectionStats:
    """Recompute semantics, the five flags and the MITRE pair on every ``ics_events`` row.

    A row is rewritten only when the recomputed values differ from what it holds, and the
    recomputation reads nothing the pass writes (protocol, function_code, attack_type,
    rule_name and the metadata are inputs only), so a second run changes nothing. A wrong
    value is replaced by what the evidence supports, which may be NULL: there is no
    "keep what is there" tier. ``dry_run`` issues the SELECT and nothing else, inside a
    transaction the database itself holds read-only.

    Before each UPDATE the row's old values (``JOURNAL_KEYS``) are appended to a JSON-lines
    journal at ``journal_path`` (default: a timestamped file in the working directory), so
    a clear that later proves wrong is recoverable without a restore. The journal is
    flushed and fsynced before each commit. Progress is logged per committed batch, and a
    failure logs the counters so far (the committed batches stay applied).
    """
    stats = CorrectionStats()
    conn = get_connection()
    journal = None
    try:
        read = conn.cursor()
        write = conn.cursor()
        if dry_run:
            read.execute("SET TRANSACTION READ ONLY")  # the engine refuses any write
        else:
            journal_path = journal_path or default_journal_path()
            journal = open(journal_path, "a", encoding="utf-8")
            logger.info("journaling old values to %s", journal_path)
            stats.journal_path = journal_path
        read.execute(_SELECT_SQL)
        pending = 0
        while True:
            rows = read.fetchmany(1000)
            if not rows:
                break
            for raw in rows:
                row = dict(zip(SELECT_COLUMNS, raw, strict=True))
                stats.scanned += 1
                res = resolve(
                    row["protocol"],
                    row["function_code"],
                    row["attack_type"],
                    row["rule_name"],
                    row["ie_metadata"],
                    row["se_metadata"],
                )
                stats.evidence[res.evidence] += 1
                if res.evidence in ("none", "bytes_undecoded"):
                    stats.unresolved += 1
                new_flags = [res.flags[f] for f in FLAGS]
                old_flags = [row[f] for f in FLAGS]
                old = (row["semantics"], *old_flags, row["mitre_technique"], row["mitre_tactic"])
                new = (res.semantics, *new_flags, res.technique, res.tactic)
                if old == new:
                    continue
                stats.changed += 1
                if row["semantics"] is None and res.semantics is not None:
                    stats.semantics_set += 1
                elif row["semantics"] is not None and res.semantics is None:
                    stats.semantics_cleared += 1
                elif row["semantics"] != res.semantics:
                    stats.semantics_changed += 1
                if old_flags != new_flags:
                    stats.flags_changed += 1
                    if res.semantics is None and any(
                        o and not n for o, n in zip(old_flags, new_flags, strict=True)
                    ):
                        stats.flags_lost += 1
                effect = _technique_effect(row["mitre_technique"], res.technique, res.semantics)
                if effect:
                    setattr(stats, effect, getattr(stats, effect) + 1)
                elif row["mitre_tactic"] != res.tactic:
                    if res.tactic is None:
                        stats.tactic_cleared += 1
                    else:
                        stats.tactic_only += 1
                if not dry_run and journal is not None:
                    journal.write(json.dumps({k: row[k] for k in JOURNAL_KEYS}) + "\n")
                    write.execute(
                        _UPDATE_SQL,
                        (res.semantics, *new_flags, res.tactic, res.technique, row["event_id"]),
                    )
                    pending += 1
                    if pending >= batch_size:
                        _flush(journal)
                        conn.commit()
                        pending = 0
                        logger.info(
                            "progress: %s scanned, %s changed",
                            f"{stats.scanned:,}",
                            f"{stats.changed:,}",
                        )
        if not dry_run and pending:
            _flush(journal)
            conn.commit()
    except BaseException:
        conn.rollback()
        logger.error(
            "failed part-way; batches already committed stay applied:\n%s",
            format_report(stats, dry_run),
        )
        raise
    finally:
        if journal is not None:
            journal.close()
        conn.close()
    return stats


def _flush(journal) -> None:
    journal.flush()
    os.fsync(journal.fileno())


def format_report(stats: CorrectionStats, dry_run: bool) -> str:
    """The report a person reads before authorising the real run."""
    s = stats
    cleared = s.cleared_anomaly + s.cleared_enterprise + s.cleared_no_basis + s.tactic_cleared
    head = "DRY RUN - nothing was written" if dry_run else "CORRECTED - rows were rewritten"
    verb = "would change" if dry_run else "changed"
    lines = [
        head,
        f"{s.scanned:,} rows scanned, {s.changed:,} {verb}, {s.scanned - s.changed:,} already right",
        "",
        "evidence the new value rests on (all rows scanned):",
        f"  captured bytes decoded     {s.evidence['bytes']:>8,}",
        f"  stored function code       {s.evidence['function_code']:>8,}",
        f"  code rebuilt from rule name{s.evidence['rule_name']:>8,}  (exact ICS_FC key; not stored on the row)",
        f"  classifier verdict only    {s.evidence['verdict']:>8,}",
        f"  no bytes were captured     {s.evidence['none']:>8,}  (left NULL: cannot be corrected)",
        f"  bytes would not decode     {s.evidence['bytes_undecoded']:>8,}  (left NULL: cannot be corrected)",
        "",
        f"semantics ({verb}):",
        f"  NULL -> a value            {s.semantics_set:>8,}",
        f"  one value -> another       {s.semantics_changed:>8,}",
        f"  a value -> NULL            {s.semantics_cleared:>8,}",
        f"is_* flags rewritten         {s.flags_changed:>8,}",
        f"  of which a True flag lost with no semantics behind it  {s.flags_lost:,}",
        "",
        f"MITRE technique ({verb}):",
        f"  assigned (was NULL)        {s.assigned:>8,}",
        f"  replaced by another        {s.replaced:>8,}",
        f"  cleared, total             {cleared:>8,}",
        f"    on an out-of-spec frame  {s.cleared_anomaly:>8,}  (e.g. T0801 on an undefined code)",
        f"    enterprise technique     {s.cleared_enterprise:>8,}  (T1xxx on an ICS row)",
        f"    evidence no longer there {s.cleared_no_basis:>8,}  (set by the deleted verdict logic)",
        f"    tactic only (technique already NULL) {s.tactic_cleared:>3,}",
        f"  tactic respelled only      {s.tactic_only:>8,}",
    ]
    if s.journal_path:
        lines += ["", f"old values journaled to: {s.journal_path}"]
    elif not dry_run:
        lines += ["", "old values journaled to: (none)"]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Backfill and correct ics_events")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Report; write nothing")
    parser.add_argument("--limit", "-l", type=int, help="Max records (--insert-missing only)")
    parser.add_argument(
        "--journal", help="--correct: JSON-lines file for the old values (default: timestamped)"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--correct",
        action="store_true",
        help="Recompute semantics, the is_* flags and MITRE on every row; clears wrong values",
    )
    mode.add_argument(
        "--insert-missing",
        action="store_true",
        help="Create ics_events rows for MODBUS/ICS_ATTACK patterns that have none",
    )
    mode.add_argument(
        "--fix-registers",
        action="store_true",
        help="UPDATE existing ics_events rows that have NULL unit_id/register fields",
    )
    args = parser.parse_args()
    if args.limit is not None and not args.insert_missing:
        parser.error("--limit applies to --insert-missing only; --correct always covers every row")
    if args.journal and not args.correct:
        parser.error("--journal applies to --correct only")

    try:
        if args.correct:
            stats = correct(dry_run=args.dry_run, journal_path=args.journal)
            print(format_report(stats, dry_run=args.dry_run))
        elif args.fix_registers:
            fix_registers(dry_run=args.dry_run)
        else:
            backfill(dry_run=args.dry_run, limit=args.limit)
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error("Error: %s", e)
        raise


if __name__ == "__main__":
    main()
