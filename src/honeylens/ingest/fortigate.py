#!/usr/bin/env python3
"""
ingest_fortigate.py — FortiGate Honeypot Log Ingestion
=======================================================
Reads honeypot_fortigate.json logs and inserts events into PostgreSQL.
Applies attack classification for CVE detection and credential harvesting.

Usage:
    python ingest_fortigate.py              # Process new events
    python ingest_fortigate.py --all        # Reprocess all events
    python ingest_fortigate.py --dry-run    # Test without inserting

Cron:
    * * * * * cd /opt/sensor && /opt/sensor/venv/bin/python ingest_fortigate.py >> /var/log/ingest_fortigate.log 2>&1
"""

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import UTC, datetime

import psycopg2

from honeylens.config import FORTIGATE_LOG_FILE
from honeylens.database import legacy_get_db
from honeylens.ingest import foreign_path, logcleanup, state

logger = logging.getLogger("ingest-fortigate")

# =============================================================================
# Configuration
# =============================================================================

LOG_FILE = FORTIGATE_LOG_FILE

# Position file to track last read position
# See ingest/state.py — the old /var/run path was unwritable for this user.
_POS_NAME = "fortigate"

# Attack type mappings for FortiGate events
EVENT_TYPE_TO_ATTACK = {
    "CREDENTIAL_CAPTURE": "FORTI_CRED",
    "SSLVPN_LOGIN_ATTEMPT": "FORTI_SSLVPN",
    "CVE_ATTEMPT": "FORTI_CVE",
    "ADMIN_ENUMERATION": "FORTI_ENUM",
    "ADMIN_LOOKUP": "FORTI_ENUM",
    "CONFIG_BACKUP_ATTEMPT": "FORTI_CONFIG",
    "API_PROBE": "FORTI_API",
    "EXPLOIT_PROBE": "FORTI_EXPLOIT",
    "LOGIN_PAGE": "FORTI_RECON",
    "DASHBOARD_ACCESS": "FORTI_ACCESS",
    "UNKNOWN_PATH": "FORTI_PROBE",
}


# =============================================================================
# Database Functions
# =============================================================================


def get_connection():
    """Get database connection."""
    return legacy_get_db()


def ensure_tables(conn):
    """Ensure required tables exist."""
    cur = conn.cursor()

    # Check if sensor_events has fortigate-compatible columns
    cur.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'sensor_events'
    """)
    existing_cols = {row[0] for row in cur.fetchall()}

    # sensor_events should already exist from main ingest.py
    if "sensor_events" not in existing_cols:
        logger.info("sensor_events table exists, using existing schema")

    conn.commit()


def generate_event_id(event: dict) -> str:
    """Generate unique event ID from event data."""
    unique_str = f"{event.get('timestamp', '')}-{event.get('src_ip', '')}-{event.get('path', '')}-{event.get('event_type', '')}"
    return hashlib.sha256(unique_str.encode()).hexdigest()[:32]


def event_exists(conn, event_id: str) -> bool:
    """Check if event already exists."""
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM sensor_events WHERE event_id = %s LIMIT 1", (event_id,))
    return cur.fetchone() is not None


def insert_event(conn, event: dict, event_id: str):
    """Insert FortiGate honeypot event into database."""
    cur = conn.cursor()

    # Parse timestamp - keep as string for PostgreSQL to handle
    # This matches how ingest_honeypot.py works
    ts = event.get("timestamp", "")

    # PostgreSQL TIMESTAMPTZ will handle the conversion correctly
    # Just pass the ISO string directly
    if not ts:
        ts = datetime.now(UTC).isoformat()

    # Determine attack types
    event_type = event.get("event_type", "")
    attack_types = []

    if event_type in EVENT_TYPE_TO_ATTACK:
        attack_types.append(EVENT_TYPE_TO_ATTACK[event_type])

    # Check for specific CVE in data
    data = event.get("data", {})

    # UNKNOWN_PATH is the decoy saying it does not recognise the path — the one moment it
    # has nothing to say about the vendor. Ask the text rules instead; keep FORTI_PROBE
    # only when nothing else identifies the request. See ingest/foreign_path.py.
    rule_for_type = {}
    if event_type == "UNKNOWN_PATH" and isinstance(data, dict):
        identified = foreign_path.classify(data)
        if identified:
            attack_types = [a for a in attack_types if a != "FORTI_PROBE"]
            for atype, _sev, rule in identified:
                attack_types.append(atype)
                rule_for_type[atype] = rule

    if isinstance(data, dict):
        cve = data.get("cve", "")
        if cve:
            attack_types.append(f"FORTI_{cve.replace('-', '_')}")

        # Credential capture is high priority
        if data.get("username") or data.get("password"):
            if "FORTI_CRED" not in attack_types:
                attack_types.append("FORTI_CRED")

    attack_types_str = ",".join(attack_types) if attack_types else None

    # Build payload for storage.
    #
    # `headers` is included because the on-disk log is about to be trimmed after
    # ingestion and this was the only field of forensic value that lived outside `data`
    # — bodies and credentials (body_sample, body_len, username, password, credential)
    # are already inside it, so they were never at risk.
    payload_parts = {
        "event_type": event_type,
        "path": event.get("path", ""),
        "method": event.get("method", ""),
        "query": event.get("query", ""),
        "user_agent": event.get("user_agent", ""),
        "data": data,
    }
    headers = event.get("headers")
    if headers:
        payload_parts["headers"] = headers
    payload = json.dumps(payload_parts)

    # Extract port from path or default
    dst_port = 443

    # Insert into sensor_events
    cur.execute(
        """
        INSERT INTO sensor_events (
            event_id, timestamp, src_ip, src_port, dst_port,
            protocol, source, payload, attack_types
        ) VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s
        )
        ON CONFLICT (event_id) DO NOTHING
    """,
        (
            event_id,
            ts,
            event.get("src_ip", "0.0.0.0"),  # noqa: S104 # nosec B104 — field default value, not a bind address
            event.get("src_port", 0),
            dst_port,
            "https",
            "fortigate-honeypot",
            payload,
            attack_types_str,
        ),
    )

    # Insert into attack_patterns if attack detected
    if attack_types:
        for attack_type in attack_types:
            try:
                cur.execute(
                    """
                    INSERT INTO attack_patterns (event_id, attack_type, rule_name, matched_text)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """,
                    (
                        event_id,
                        attack_type,
                        rule_for_type.get(attack_type, f"fortigate_{event_type.lower()}"),
                        event.get("path", "")[:500],
                    ),
                )
            except psycopg2.Error as e:
                logger.debug("Attack pattern insert error: %s", e)

    conn.commit()
    return True


# =============================================================================
# Log Processing
# =============================================================================


def get_last_position(log_file: str | None = None) -> int:
    """Get last read position from position file."""
    return state.read_position(_POS_NAME, log_file)


def save_position(pos: int):
    state.save_position(_POS_NAME, pos)


def process_log_file(log_file: str, conn, process_all: bool = False, dry_run: bool = False):
    """Process FortiGate honeypot log file."""
    if not os.path.exists(log_file):
        logger.warning("Log file not found: %s", log_file)
        return 0, 0

    # Get starting position
    if process_all:
        start_pos = 0
    else:
        start_pos = get_last_position(log_file)

    processed = 0
    inserted = 0

    with open(log_file) as f:
        # Seek to last position
        f.seek(start_pos)

        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning("Invalid JSON: %s", e)
                continue

            processed += 1
            event_id = generate_event_id(event)

            if dry_run:
                logger.info(
                    "[DRY-RUN] Would insert: %s %s %s",
                    event.get("src_ip"),
                    event.get("event_type"),
                    event.get("path"),
                )
                inserted += 1
                continue

            # Check if already exists
            if event_exists(conn, event_id):
                continue

            try:
                if insert_event(conn, event, event_id):
                    inserted += 1
                    logger.debug("Inserted: %s", event_id)
            except psycopg2.Error as e:
                logger.error("Insert error: %s", e)
                conn.rollback()

        # Save position
        if not dry_run:
            consumed = f.tell()
            save_position(consumed)

    # Drop what we have consumed. Nothing else reads this file — the only other
    # references anywhere are the honeypot that writes it and this ingest — but it was
    # never trimmed, so it held every event since March: 9.4 MB on one sensor. That is not
    # merely untidy. When the stored offset was lost (first run after the offsets moved
    # to /var/lib/honeylens) the ingest replayed all six months, putting 12,812 rows
    # that retention had already archived back into the live table and wedging the Loki
    # exporter, which rejects anything older than a week.
    #
    # Safe to discard only because insert_event() now carries `headers` into the payload
    # as well as `data`; before that the file was the sole copy of the request headers.
    if not dry_run and not process_all and consumed > 0:
        if logcleanup.refuse_outside(log_file, [os.path.dirname(os.path.realpath(log_file))]):
            try:
                logcleanup.drop_consumed_prefix(log_file, consumed)
                # The bytes are gone, so the offset must go with them — leaving it set
                # would seek past the end of the trimmed file and read nothing at all.
                save_position(0)
            except OSError as exc:
                logger.warning("Could not clean up %s: %s", log_file, exc)

    return processed, inserted


# =============================================================================
# Main
# =============================================================================


def main():
    from honeylens.logging_setup import setup_logging

    setup_logging()
    parser = argparse.ArgumentParser(description="Ingest FortiGate honeypot logs")
    parser.add_argument(
        "--all", "-a", action="store_true", help="Process all events from beginning"
    )
    parser.add_argument("--dry-run", "-n", action="store_true", help="Test without inserting")
    parser.add_argument("--log-file", default=LOG_FILE, help=f"Log file path (default: {LOG_FILE})")

    args = parser.parse_args()

    logger.info("FortiGate honeypot log ingestion starting")
    logger.info("Log file: %s", args.log_file)

    if args.dry_run:
        logger.info("DRY RUN - no changes will be made")

    try:
        conn = get_connection()
        ensure_tables(conn)

        processed, inserted = process_log_file(
            args.log_file, conn, process_all=args.all, dry_run=args.dry_run
        )

        logger.info("Processed: %d events, Inserted: %d new", processed, inserted)

        conn.close()

    except psycopg2.Error as e:
        logger.error("Database error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
