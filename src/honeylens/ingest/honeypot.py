"""
ingest_honeypot.py — HoneypotNG Log Ingestion Pipeline (Enhanced)

==================================================================
Reads all *.json log files written by the honeypots, normalises and sanitises each
record, then upserts into sensor_events. Log files are truncated only after a
successful database commit.

Port 1.0: two line formats arrive here. The legacy one (monolith, K8s, FortiGate,
PAN-OS) is unchanged. The new one, ``schema: honeylens-event/1`` from
``honeypots/sink.py``, is what every honeypot that used to write to the database
itself now emits — a container never holds database credentials. For those lines
this module also does what ``honeypots/_base.log_event`` did in 0.9: honours the
honeypot's own verdict instead of re-classifying, writes ``attack_patterns`` rows
with severity and confidence, ``ics_events`` for ICS decoys, ``full_payload`` from
the raw bytes, the LLM decoy's own table, canary registration and SIEM fan-out.
``_normalise()`` is where the two formats meet; everything after it is one path.

The schema (``attack_types`` column, ``attack_patterns``, ``ics_events``) is
guaranteed by ``honeylens-migrate``, which runs before any service starts. The 0.9
import-time probes — three connections per process start, a silent downgrade when
the database was unreachable — are gone with it.

Requires: Python >= 3.9 (Rocky Linux 9 default)

Run manually or from cron:
    python ingest_honeypot.py
"""

from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.scoring import classify_attack_summary, get_severity
from honeylens.config import (
    HONEYPOT_LOG_GLOBS,
    HONEYPOTNG_GLOB,
    HONEYPOTNG_PATTERNS_FILE,
    K8S_HONEYPOT_LOG_FILE,
)
from honeylens.database import legacy_get_db
from honeylens.eventlog_lock import log_lock
from honeylens.honeypots.body_capture import payload_with_body, raw_from_fields
from honeylens.honeypots.sink import LLM_COLUMNS
from honeylens.honeypots.sink import SCHEMA as HONEYPOT_SCHEMA
from honeylens.ics import ics_flag
from honeylens.ingest import logcleanup
from honeylens.ingest.ics_helpers import (
    map_protocol_fields,
    resolve_semantics,
    semantics_to_mitre,
)
from honeylens.intelligence import canary_store
from honeylens.sanitise import safe_json_dumps, sanitize_payload, strip_nul

logger = logging.getLogger("honeylens.ingest.honeypot")

# honeypotng keeps its auto-detection dedup memory in the same directory, so it matches the
# log glob. It is STATE, not an event log — never parse or truncate it.
NON_EVENT_FILES = {Path(HONEYPOTNG_PATTERNS_FILE).name}

# ---------------------------------------------------------------------------
# NUL byte sanitisation — PostgreSQL text columns cannot contain 0x00
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def get_db():
    return legacy_get_db()


INSERT_SQL = """
    INSERT INTO sensor_events (
        event_id, timestamp, source, protocol,
        src_ip, src_port, dst_ip, dst_port,
        payload, payload_hash,
        scan_score, port_entropy,
        ja3, metadata, attack_types
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON CONFLICT (event_id) DO NOTHING
"""

# severity/confidence: columns from migrations 0001/0002 with defaults 'medium'/'high'.
# Rows from the legacy format get explicitly the same values the defaults used to give them.
INSERT_ATTACK_SQL = """
    INSERT INTO attack_patterns (
        event_id, attack_type, rule_name, matched_text, severity, confidence
    )
    VALUES (%s, %s, %s, %s, %s, %s)
    ON CONFLICT DO NOTHING
"""

# Request bytes, when the honeypot sent them (``raw_hex``). A separate UPDATE, not columns
# in the INSERT: the event row must go in even when this write fails.
UPDATE_RAW_SQL = """
    UPDATE sensor_events
       SET full_payload = %s, full_payload_hash = %s
     WHERE event_id = %s AND full_payload IS NULL
"""

# LLM honeypot table (migration 0008); columns from the contract in honeypots/sink.py.
_LLM_VALUES = ", ".join("%s::inet" if c == "src_ip" else "%s" for c in LLM_COLUMNS)
INSERT_LLM_SQL = (
    f"INSERT INTO llm_honeypot_events ({', '.join(LLM_COLUMNS)}) "  # noqa: S608 # nosec B608 — columns from the constant contract tuple
    f"VALUES ({_LLM_VALUES}) ON CONFLICT (event_id) DO NOTHING"
)

# Honeypots whose verdict also goes to ics_events (list from ``_base.log_event`` in 0.9).
_ICS_HONEYPOTS = frozenset(
    {
        "modbus",
        "s7comm",
        "dnp3",
        "iec104",
        "bacnet",
        "enip",
        "opcua",
        "fins",
        "mqtt",
        "profinet",
        "melsec",
        "coap",
        "mms",
        "fox",
    }
)

# The one ics_events row per ICS decoy event. ``metadata`` carries the decoy's whole event:
# it is what makes the fields with no column of their own (``cot``, ``invoke_id``,
# ``endpoint_url``, ``txn_id``) survive, and what makes truncating the text columns
# (``function_name``, ``device_address``, ``rule_name``, ``attack_type``) to their widths
# acceptable. Column order is what ``_ics_row`` matches, position by position.
INSERT_ICS_SQL = """
    INSERT INTO ics_events (
        event_id, timestamp, protocol, function_code, function_name,
        src_ip, src_port, dst_ip, dst_port,
        unit_id, device_address, register_start, register_count, data_value,
        is_read, is_write, is_control, is_discovery, is_anomaly,
        mitre_tactic, mitre_technique, attack_type, rule_name,
        source, severity, metadata, semantics
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ON CONFLICT (event_id) DO NOTHING
"""


def safe_insert(cur, row):
    """
    Insert one row using a savepoint so a single bad row cannot abort the
    surrounding transaction.  On failure the savepoint is rolled back and
    the error is logged; the caller can continue with the next row.
    """
    cur.execute("SAVEPOINT sp_row")
    try:
        cur.execute(INSERT_SQL, row)
        cur.execute("RELEASE SAVEPOINT sp_row")
    except Exception as exc:
        cur.execute("ROLLBACK TO SAVEPOINT sp_row")
        cur.execute("RELEASE SAVEPOINT sp_row")
        logger.error("Insert failed: %s — event_id=%s", exc, row[0][:16] if row else "?")
        raise


# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------


def _canary_register(cur, data, event_id, ts):
    """Register an AI canary, or correlate a callback with the artefact that carried it.

    Mutates `data` on a callback so the recovered origin is stored with the event —
    the honeypot could only fill those fields in when it had issued the canary itself.
    """
    if canary_store is None:
        return
    nonce = data.get("canary_nonce")
    src_ip = data.get("peer_ip") or data.get("src_ip")

    if data.get("action") != "ai_canary_callback":
        canary_store.record_issue(
            cur,
            nonce,
            canary_type=data.get("canary_type") or "prompt_injection_header",
            carrier=data.get("carrier") or "http_response_header",
            origin_event_id=event_id,
            origin_protocol=data.get("origin_protocol") or data.get("protocol"),
            origin_path=data.get("path"),
            origin_src_ip=src_ip,
            issued_at=ts,
        )
        return

    origin = canary_store.record_callback(
        cur,
        nonce,
        callback_at=ts,
        src_ip=src_ip,
        user_agent=data.get("user_agent"),
        headers=data.get("callback_headers"),
        body_sample=data.get("callback_body_sample"),
    )
    if not origin:
        return

    data["canary_correlated"] = True
    for field in ("origin_protocol", "origin_path", "origin_src_ip"):
        if origin.get(field) and not data.get(field):
            data[field] = origin[field]
    if data.get("callback_delay_ms") is None:
        delay = canary_store.callback_delay_ms(origin.get("issued_at"), _as_dt(ts))
        if delay is not None:
            data["callback_delay_ms"] = delay


def _as_dt(ts):
    """Honeypot logs carry ISO timestamps; the store needs a datetime to subtract."""
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _normalise(data: dict) -> dict:
    """One shape for both line formats; from here on there is a single path.

    The ``honeylens-event/1`` format (``honeypots/sink.py``) carries an envelope and a
    separate ``event``; the legacy format (monolith, K8s, FortiGate, PAN-OS) is flat and
    ``metadata`` is the whole line. Result: a dict with the column fields, ``metadata``
    (for the column and the classifier), ``verdict`` (the honeypot's verdict or None),
    ``raw`` (bytes or None), ``llm``, ``canary`` (dict to register or None),
    ``forward_siem`` and ``honeypot`` (honeypot name, for ics_events).
    """
    if data.get("schema") == HONEYPOT_SCHEMA:
        event: dict = data["event"] if isinstance(data.get("event"), dict) else {}
        src_ip = data.get("peer_ip")
        proto = data.get("protocol") or "unknown"
        verdict = None
        if data.get("attack_type"):
            verdict = {
                "attack_type": data["attack_type"],
                "severity": (data.get("severity") or "MEDIUM").upper(),
                "confidence": data.get("confidence") or "high",
                "rules": [r for r in (data.get("rules") or []) if r],
            }
        raw = None
        if data.get("raw_hex"):
            try:
                raw = bytes.fromhex(data["raw_hex"])
            except ValueError as exc:
                logger.warning("raw_hex not decodable, stored without raw bytes: %s", exc)
        canary = None
        if event.get("canary_nonce"):
            canary = {**event, "peer_ip": src_ip, "protocol": proto}
        return {
            "ts": data.get("timestamp"),
            "proto": proto,
            "src_ip": src_ip,
            "src_port": data.get("peer_port"),
            "dst_ip": data.get("dst_ip"),
            "dst_port": data.get("dst_port") or data.get("port"),
            "payload": sanitize_payload(data.get("payload")),
            "source": data.get("source") or "honeypotng",
            "honeypot": data.get("honeypot"),
            "event_id": data.get("event_id"),
            "metadata": event,
            "verdict": verdict,
            "raw": raw,
            "llm": data.get("llm") if isinstance(data.get("llm"), dict) else None,
            "canary": canary,
            "forward_siem": True,
        }

    # --- legacy format, unchanged from 0.9 ---
    proto = data.get("protocol", "unknown")
    # Handle both old format (peer=[ip,port]) and new format (peer_ip, peer_port)
    peer = data.get("peer", [None, None])
    src_ip = data.get("peer_ip") or (peer[0] if isinstance(peer, list) and peer else None)
    src_port = data.get("peer_port") or (
        peer[1] if isinstance(peer, list) and len(peer) > 1 else None
    )
    # Extract payload from various possible fields
    # K8s honeypot uses: path, method, user_agent
    # NG honeypot uses: data, hex, raw
    payload = sanitize_payload(
        # An explicit `payload` field is the honeypot's own summary of the
        # request and outranks anything we could reassemble here. It was
        # missing from this chain, so a honeypot that filled in the one
        # field named after the column got NULL in it.
        data.get("payload")
        or data.get("data")
        or data.get("hex")
        or data.get("raw")
        or data.get("path")
        or data.get("request_line")
    )
    # For K8s/HTTP logs, construct a more complete payload representation
    if data.get("method") and data.get("path"):
        request_line = f"{data.get('method')} {data.get('path')}"
        if data.get("user_agent"):
            request_line += f" User-Agent: {data.get('user_agent')}"
        if not payload or payload == data.get("path"):
            payload = sanitize_payload(request_line)

    # The body the decoy captured, into the two places a hunt actually looks.
    #
    # Until 2026-10-25 this branch set `raw` to None unconditionally and left `payload`
    # at the request line, so a decoy that had captured the body into its event — the
    # Kubernetes decoy does, the WAGO one now does — stored `POST /index.php` and
    # nothing else. Measured cost on one sensor: 133 052 rows with no `full_payload`,
    # of which 435 POSTs had the body sitting in `metadata.body_sample` the whole time.
    # It hid seven PHP2Shell exploitation requests and mislabelled three of them.
    legacy_raw = None
    if data.get("raw_hex"):
        # The whole request, headers included, as the decoy received it. Strictly more
        # evidence than the body on its own, so it outranks the capture fields below.
        try:
            legacy_raw = bytes.fromhex(data["raw_hex"]) or None
        except ValueError as exc:
            logger.warning("raw_hex not decodable, stored without raw bytes: %s", exc)
    if legacy_raw is None:
        legacy_raw = raw_from_fields(data)
    if data.get("body_sample") or data.get("body_sample_b64"):
        payload = sanitize_payload(payload_with_body(payload or "", data))
    proto_lower = (proto or "").lower()
    if any(x in proto_lower for x in ("k8s_", "kubernetes", "kubelet", "etcd", "kubectl")):
        source = "honeypot_k8s"
    else:
        source = "honeypotng"
    return {
        "ts": data.get("timestamp"),
        "proto": proto,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": None,
        "dst_port": data.get("port") or data.get("dst_port"),
        "payload": payload,
        "source": source,
        "honeypot": None,
        "event_id": None,
        "metadata": data,
        "verdict": None,
        "raw": legacy_raw,
        "llm": None,
        "canary": data if data.get("canary_nonce") else None,
        "forward_siem": False,
    }


def _attack_hits(rec: dict, payload: str | None) -> tuple[str | None, list[tuple]]:
    """``(attack_types, [(atype, rule, matched, severity, confidence)])`` for an event.

    The honeypot's verdict (1.0 format) stands alone: it is higher fidelity than a regex
    and is neither overridden nor supplemented — that is what ``_base.log_event`` did.
    Without a verdict we ask the central rule set; for legacy lines as in 0.9: the
    honeypot's own classification (``attack_type`` + ``rule_name``) as the first hit,
    the rest from the classifier.
    """
    verdict = rec["verdict"]
    if verdict:
        rows = [
            (verdict["attack_type"], rule, None, verdict["severity"], verdict["confidence"])
            for rule in verdict["rules"]
        ]
        return strip_nul(verdict["attack_type"]), rows

    data = rec["metadata"]
    hits: list[tuple] = []
    if rec["source"] in ("honeypotng", "honeypot_k8s") and not rec["honeypot"]:
        pre_atype = data.get("attack_type")
        pre_rule = data.get("rule_name")
        if pre_atype and pre_rule:
            pre_matched = f"{data.get('method', '')} {data.get('path', '')}".strip() or pre_rule
            hits.append((strip_nul(pre_atype), strip_nul(pre_rule), strip_nul(pre_matched[:500])))
    try:
        seen = {(h[0], h[1]) for h in hits}
        for h in classify_event_row(payload=payload, protocol=rec["proto"], metadata=data):
            if (h[0], h[1]) not in seen:
                hits.append(h)
                seen.add((h[0], h[1]))
    except Exception as e:
        logger.warning("attack classifier failed, event stored unclassified: %s", e)
    attack_types = classify_attack_summary(hits)
    if rec["honeypot"]:
        # Regex hits on a 1.0 honeypot event: confidence "medium", severity from the taxonomy —
        # a regex is weaker evidence than a honeypot recognising its own protocol.
        rows = [(a, r, m, (get_severity(a, r) or "medium").upper(), "medium") for a, r, m in hits]
    else:
        rows = [(a, r, m, "medium", "high") for a, r, m in hits]
    return (strip_nul(attack_types) if attack_types else None), rows


# The hex keys, the frame lookup and the own-boolean rule live in honeylens.ics.evidence.


def _writes_ics_row(rec: dict, attack_types: str | None) -> bool:
    """The ICS write gate. A decoy that says ``ics: false`` has told us the exchange was
    not ICS (Fox answering an HTTP scanner); one that says nothing keeps its row. Not a
    verdict blacklist: SCANNER is a legitimate ICS verdict on mqtt."""
    return bool(
        rec["honeypot"]
        and rec["honeypot"].lower() in _ICS_HONEYPOTS
        and attack_types
        and (rec.get("metadata") or {}).get("ics") is not False
    )


def _ics_row(rec: dict, event_id: str, attack_types: str) -> tuple:
    """The 27 values of one ``ics_events`` row, in ``INSERT_ICS_SQL`` column order.

    The single builder for this table: until 2026-10-25 there were two, and the one that
    ran wrote 17 columns and left the register-level and MITRE ones NULL on every row the
    fleet has. The protocol detail comes from ``map_protocol_fields`` — each decoy's own
    vocabulary onto the Modbus-shaped columns — and everything with no column of its own
    stays readable because the whole event goes to ``metadata``.
    """
    data = rec["metadata"]
    hp = rec["honeypot"]
    # ``rule`` as ``_base.log_event`` derives it, so ics_events.rule_name and
    # attack_patterns.rule_name stay the same string. mqtt sends ``rule`` on 1 of 714 rows
    # and ``phase`` on all of them, which is why the fallback matters.
    #
    # Truncated to rule_name's VARCHAR(128) here rather than at the slot, so the string
    # that goes to the column is the one every later step
    # sees. Not reachable today -- every rule and phase in the twelve ICS decoys comes from
    # a lookup table keyed by a parsed integer -- but ``function_name`` was capped and
    # these were not, which taught the reader that over-long decoy fields are handled
    # when they were handled for one column out of four. An over-long value aborts the
    # INSERT and the savepoint drops the whole ICS row.
    rule = (data.get("rule") or data.get("phase") or f"{hp}_event")[:128]
    verdict = rec["verdict"] or {}
    # ICS_FIELD_MAP is keyed by lowercase decoy name, and so is the write gate in
    # `process_record`: a capitalised name that passes the gate must not then miss the map.
    mapped = map_protocol_fields(str(hp).lower(), data)
    # What the row means: bytes, then the decoy's own function code, then the verdict --
    # the same decision the corrective backfill makes (ics_helpers.resolve_semantics).
    semantics, flags, _tier = resolve_semantics(
        str(hp).lower(), data, mapped.get("function_code"), attack_types
    )
    # MITRE follows semantics, never the verdict: nine verdict names met three ICS keys.
    mitre_technique, mitre_tactic = semantics_to_mitre(semantics)

    return (
        event_id,
        rec["ts"],
        hp,
        mapped.get("function_code"),
        mapped.get("function_name") or rule.replace("_", " ").title()[:64],
        rec["src_ip"],
        rec["src_port"],
        rec["dst_ip"] or "0.0.0.0",  # noqa: S104 — unknown destination address, not a bind
        rec["dst_port"] or 0,
        mapped.get("unit_id"),
        # iec104's common_address, dnp3's station_address, mqtt's attacker-chosen topic.
        mapped.get("device_address"),
        mapped.get("register_start"),
        mapped.get("register_count"),
        mapped.get("data_value"),
        ics_flag("is_read", data, flags),
        ics_flag("is_write", data, flags),
        ics_flag("is_control", data, flags),
        ics_flag("is_discovery", data, flags),
        ics_flag("is_anomaly", data, flags),
        mitre_tactic,
        mitre_technique,
        # attack_type is VARCHAR(64) and this is a comma-joined summary of every type the
        # classifier produced, so its length is not bounded by any single verdict.
        attack_types[:64],
        rule,
        rec["source"],
        verdict.get("severity") or "MEDIUM",
        safe_json_dumps(data),
        semantics,
    )


def _guarded(cur, name: str, what: str, fn) -> bool:
    """``fn(cur)`` inside a savepoint: a failure does not break the file's transaction.

    A failure is a warning, not debug: in a daemon unit nobody sees debug, and a permanent
    schema error would silently zero out a whole table. The ``RELEASE`` after ``fn`` also
    detects an error that ``fn`` itself swallowed — PostgreSQL holds the transaction in the
    "aborted" state and ``RELEASE`` then fails, so we roll back to the savepoint instead of
    dragging a broken transaction through the rest of the file (and through ``commit``,
    which in that state is a silent rollback).
    """
    try:
        cur.execute(f"SAVEPOINT {name}")
        fn(cur)
        cur.execute(f"RELEASE SAVEPOINT {name}")
        return True
    except Exception as exc:
        try:
            cur.execute(f"ROLLBACK TO SAVEPOINT {name}")
            cur.execute(f"RELEASE SAVEPOINT {name}")
        except Exception as e2:
            logger.warning("%s: savepoint rollback failed: %s", what, e2)
        logger.warning("%s write skipped: %s", what, exc)
        return False


def _savepoint(cur, name: str, sql: str, params: tuple, what: str) -> bool:
    """A single statement inside a savepoint (see ``_guarded``)."""
    return _guarded(cur, name, what, lambda c: c.execute(sql, params))


def process_record(cur, data: dict) -> bool:
    """One (already parsed) event into the database. ``False`` when the row was skipped."""
    data = strip_nul(data)
    rec = _normalise(data)
    ts, proto, src_ip, src_port = rec["ts"], rec["proto"], rec["src_ip"], rec["src_port"]
    dst_port, payload = rec["dst_port"], rec["payload"]

    payload_hash = hashlib.sha256((payload or "").encode(errors="ignore")).hexdigest()
    event_id = (
        rec["event_id"]
        or hashlib.sha256(
            (f"{ts}:{src_ip}:{src_port}:{dst_port}:{payload_hash}").encode()
        ).hexdigest()
    )

    # AI canary registry (Idea 52). The K8s honeypot holds no DB credentials
    # by design, so its canaries reach the durable store here, on their way
    # through the log. Callbacks are correlated here too, not in the honeypot:
    # the canary may have been issued by a different process (the LLM
    # honeypot), which in-memory correlation can never see. Runs before the
    # metadata is serialised so the correlation it recovers is stored with
    # the event.
    if rec["canary"]:
        # canary_store swallows its own exceptions but does not undo the transaction's
        # "aborted" state — without a savepoint one bad canary lost every event in the file
        # (in 0.9 as well).
        canary = rec["canary"]
        _guarded(cur, "sp_canary", "canary", lambda c: _canary_register(c, canary, event_id, ts))

    metadata_json = safe_json_dumps(rec["metadata"])
    attack_types, attack_rows = _attack_hits(rec, payload)

    row: tuple[Any, ...] = (
        strip_nul(event_id),
        strip_nul(ts),
        rec["source"],
        strip_nul(proto),
        strip_nul(src_ip),
        src_port,
        rec["dst_ip"],
        dst_port,
        payload,  # already sanitised
        strip_nul(payload_hash),
        None,
        None,
        None,
        metadata_json,  # already sanitised
        attack_types,
    )
    try:
        safe_insert(cur, row)
    except Exception as exc:
        # Row-level savepoint already rolled back inside safe_insert.
        # Skip this row and continue — do NOT raise so the file keeps
        # processing and the transaction stays healthy.
        logger.debug("row skipped: %s", exc)
        return False

    # The bytes exactly as they arrived. The hash is over precisely what we store, so anyone
    # can recompute it against the column and see that nothing changed between capture
    # and disk.
    if rec["raw"]:
        raw_hash = hashlib.sha256(rec["raw"]).hexdigest()
        _savepoint(cur, "sp_raw", UPDATE_RAW_SQL, (rec["raw"], raw_hash, event_id), "raw capture")

    if rec["llm"]:
        llm = rec["llm"]
        params = tuple(
            json.dumps(llm.get(c)) if c == "headers" else llm.get(c) for c in LLM_COLUMNS
        )
        _savepoint(cur, "sp_llm", INSERT_LLM_SQL, params, "llm_honeypot_events")

    # Insert individual attack pattern rows.
    # INSERT_ATTACK_SQL uses ON CONFLICT DO NOTHING so this is safe even
    # when the sensor_events row already existed (re-ingest scenario).
    for atype, rule, matched, severity, confidence in attack_rows:
        _savepoint(
            cur,
            "sp_atk",
            INSERT_ATTACK_SQL,
            (
                strip_nul(event_id),
                strip_nul(atype),
                strip_nul(rule),
                strip_nul(matched[:500]) if matched else None,
                severity,
                confidence,
            ),
            "Attack pattern",
        )

    # ICS/OT events. One row for any ICS decoy event that carries an attack type — the
    # decoy's own verdict or the classifier's. The gate is `attack_types`, not
    # `rec["verdict"]`: the comment here used to claim otherwise, and widening it to the
    # verdict would take iec104 from 97 rows to ~1238. There is no port guard, because
    # `ics_helpers.ICS_VALID_PORTS` has no 34964 and would silently drop profinet; the
    # decoy name is already the ICS test.
    #
    # The row is built inside the guard, not passed into `_savepoint` as an argument:
    # arguments are evaluated before the call, so a builder that raises on a malformed
    # metadata field would escape `process_record` and cost the `sensor_events` row
    # inserted above. The ICS write is secondary and a failure costs the ICS row only.
    if attack_types and _writes_ics_row(rec, attack_types):
        try:
            ics_row = _ics_row(rec, event_id, attack_types)
        except Exception as exc:
            # A warning, not debug, for the reason `_guarded` gives below: nobody reads
            # debug in a daemon unit, and a decoy whose events systematically fail to
            # build would stop appearing in ics_events with nothing in the journal.
            logger.warning("ICS row skipped for %s event %s: %s", rec["honeypot"], event_id, exc)
        else:
            _savepoint(cur, "sp_ics", INSERT_ICS_SQL, ics_row, "ICS")

    # Fan-out to configured SIEM forwarders (no-op if none configured). Only for
    # events that reached SIEM in 0.9, i.e. the honeypots that wrote to the database
    # themselves; legacy lines never did and that is a separate decision.
    if rec["forward_siem"]:
        try:
            from honeylens.siem import forward_event_dict

            forward_event_dict(
                {
                    "event_id": event_id,
                    "source": rec["source"],
                    "protocol": proto,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_port": dst_port or 0,
                    "payload": payload or "",
                    "attack_types": attack_types or "",
                }
            )
        except Exception as exc:
            logger.debug("SIEM forward skipped: %s", exc)
    return True


def process_file(cur, path, limit_bytes=None):
    """Parse one log file and insert all valid records. Returns count inserted."""
    logger.info("Processing %s", path)
    inserted = 0

    with open(path, "rb") as fh:
        line_no = 0
        while limit_bytes is None or fh.tell() < limit_bytes:
            remaining = -1 if limit_bytes is None else limit_bytes - fh.tell()
            raw_line = fh.readline(remaining)
            if not raw_line:
                break
            line_no += 1
            if not raw_line.endswith(b"\n"):
                raise ValueError(f"Incomplete event at {path}:{line_no}; keeping log for retry")
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                data = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at {path}:{line_no}; keeping log for inspection"
                ) from exc
            if not isinstance(data, dict):
                raise ValueError(
                    f"Non-object event at {path}:{line_no}; keeping log for inspection"
                )

            if not process_record(cur, data):
                raise ValueError(f"Event not persisted at {path}:{line_no}; keeping log for retry")
            inserted += 1

    logger.info("Inserted %d records from %s", inserted, path)
    return inserted


# ---------------------------------------------------------------------------
# Post-ingest cleanup
# ---------------------------------------------------------------------------


def _allowed_cleanup_dirs():
    """Directories we may clean up in — derived from the configured log sources.

    Anything outside these is refused: cleanup deletes data, so the path must
    provably come from a directory an operator configured.
    """
    dirs = set()
    for pattern in [*list(HONEYPOT_LOG_GLOBS), HONEYPOTNG_GLOB, K8S_HONEYPOT_LOG_FILE]:
        dirs.add(os.path.realpath(os.path.dirname(pattern) or "."))
    return dirs


# The truncate/replace mechanics moved to ingest/logcleanup.py when fortigate.py and
# paloalto.py needed the same thing — a fourth copy of this was not worth having.
_is_within = logcleanup.is_within
_drop_consumed_prefix = logcleanup.drop_consumed_prefix


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def ingest():
    files = []
    for pattern in HONEYPOT_LOG_GLOBS:
        if "*" in pattern:
            files.extend(glob.glob(pattern))
        elif os.path.isfile(pattern):
            files.append(pattern)
    files = list(dict.fromkeys(f for f in files if os.path.basename(f) not in NON_EVENT_FILES))
    if not files:
        logger.info("No honeypot log files found — nothing to do.")
        return

    total = errors = 0
    allowed = _allowed_cleanup_dirs()
    for path in files:
        db = None
        try:
            # Serialize consumers through commit AND cleanup. Writers only wait for
            # the size snapshot and cleanup, never for database work or SIEM calls.
            with log_lock(path, consumer=True):
                with log_lock(path):
                    consumed = os.path.getsize(path)
                if not consumed:
                    continue
                db = get_db()
                cur = db.cursor()
                count = process_file(cur, path, limit_bytes=consumed)
                db.commit()
                cur.close()
                total += count
                resolved = os.path.realpath(path)
                if not any(_is_within(resolved, d) for d in allowed):
                    logger.error("Cleanup refused — %s outside configured directories", path)
                    continue
                _drop_consumed_prefix(path, consumed)
        except Exception as exc:
            logger.error("Error processing %s: %s", path, exc)
            if db:
                try:
                    db.rollback()
                except Exception as e2:
                    logger.debug("DB rollback error: %s", e2)
            errors += 1
        finally:
            if db:
                db.close()
    logger.info("Honeypot ingestion complete — %d records, %d errors.", total, errors)


POLL_INTERVAL = 30  # seconds between passes; keeps systemd and the logs quiet


def main() -> int:
    """Entry point for ``honeylens-ingest-honeypot`` (systemd unit sensor-ingest-honeypot).

    An unhandled exception in one pass is logged and the loop carries on — a process that
    dies once a day and silently restarts is a class of failure we do not want here.
    """
    from honeylens.logging_setup import setup_logging

    setup_logging()
    logger.info("ingest_honeypot starting — polling every %ds", POLL_INTERVAL)
    while True:
        try:
            ingest()
        except Exception:
            logger.exception("Unhandled error in ingest()")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
