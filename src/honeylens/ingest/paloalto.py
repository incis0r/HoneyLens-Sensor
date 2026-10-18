#!/usr/bin/env python3
"""
ingest_paloalto.py — PAN-OS Honeypot Log Ingestion
=====================================================
Reads honeypot_paloalto.json and honeypot_paloalto_ssh.json logs,
inserts events into PostgreSQL sensor_events + attack_patterns tables.

Applies attack classification for:
- CVE detection (CVE-2024-0012, CVE-2024-9474, CVE-2025-0108,
  CVE-2024-3400, CVE-2021-3064)
- Credential harvesting (WebUI, GlobalProtect, API, SSH, Captive Portal)
- Configuration modification attempts (API set/delete/commit, SSH set/commit)
- Reconnaissance (prelogin enumeration, show commands, API probes)

Usage:
    python -m ingest.paloalto              # Process new events
    python -m ingest.paloalto --all        # Reprocess all events
    python -m ingest.paloalto --dry-run    # Test without inserting
    python -m ingest.paloalto --stats      # Show event statistics

Cron:
    * * * * * cd /opt/sensor && /opt/sensor/venv/bin/python -m ingest.paloalto >> /var/log/ingest_paloalto.log 2>&1
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import sys
from datetime import UTC, datetime

import psycopg2

from honeylens.database import legacy_get_db
from honeylens.env import env
from honeylens.ingest import foreign_path, logcleanup, state

logger = logging.getLogger("ingest-paloalto")

# =============================================================================
# Configuration
# =============================================================================

LOG_FILE_WEB = env("PALOALTO_LOG_FILE", "/var/log/honeypot_paloalto.json")
LOG_FILE_SSH = env("PALOALTO_SSH_LOG_FILE", "/var/log/honeypot_paloalto_ssh.json")

# Offsets moved out of /var/run — root-owned, and this runs as `sensor`, so the
# save silently failed and every run re-read the whole log. See ingest/state.py.
POSITION_FILE_WEB = "paloalto_web"
POSITION_FILE_SSH = "paloalto_ssh"

# =============================================================================
# Attack Type Mappings
# =============================================================================

# Web/API honeypot event types -> attack classification
WEB_EVENT_TO_ATTACK = {
    # Phase A: Management WebUI
    "CREDENTIAL_CAPTURE": ("PANOS_CRED", "MEDIUM"),
    "DEFAULT_CREDENTIAL_ATTEMPT": ("PANOS_DEFAULT_CRED", "HIGH"),
    "LOGIN_PAGE": ("PANOS_RECON", "LOW"),
    "ROOT_ACCESS": ("PANOS_RECON", "LOW"),
    "DASHBOARD_ACCESS": ("PANOS_ACCESS", "LOW"),
    "UNAUTH_ACCESS": ("PANOS_PROBE", "MEDIUM"),
    "CREATE_REMOTE_SESSION": ("PANOS_EXPLOIT", "HIGH"),
    # Phase B: GlobalProtect
    "GP_PRELOGIN": ("PANOS_GP_ENUM", "LOW"),
    "GP_LOGIN": ("PANOS_GP_CRED", "MEDIUM"),
    "GP_PORTAL_PAGE": ("PANOS_GP_RECON", "LOW"),
    "GP_GETCONFIG": ("PANOS_GP_CONFIG", "MEDIUM"),
    "GP_HIPREPORT": ("PANOS_GP_PROBE", "MEDIUM"),
    "GP_LOGOUT": ("PANOS_GP_ACCESS", "LOW"),
    # Phase C: XML API
    "API_KEYGEN": ("PANOS_API_CRED", "HIGH"),
    "API_KEYGEN_INVALID": ("PANOS_API_PROBE", "MEDIUM"),
    "API_OP": ("PANOS_API_OP", "MEDIUM"),
    "API_CONFIG": ("PANOS_API_CONFIG", "MEDIUM"),
    "API_CONFIG_WRITE": ("PANOS_API_WRITE", "CRITICAL"),
    "API_COMMIT": ("PANOS_API_COMMIT", "CRITICAL"),
    "API_UNKNOWN": ("PANOS_API_PROBE", "LOW"),
    # Phase E: Captive Portal
    "CAPTIVE_REDIRECT": ("PANOS_CAPTIVE", "LOW"),
    "CAPTIVE_AUTH_PAGE": ("PANOS_CAPTIVE", "LOW"),
    "CAPTIVE_LOGIN": ("PANOS_CAPTIVE_CRED", "MEDIUM"),
    "CAPTIVE_CP_PAGE": ("PANOS_CAPTIVE", "LOW"),
    # CVE detection
    "CVE_ATTEMPT": ("PANOS_CVE", "CRITICAL"),
    # Generic
    "UNKNOWN_PATH": ("PANOS_PROBE", "LOW"),
}

# SSH honeypot event types
SSH_EVENT_TO_ATTACK = {
    "SSH_LOGIN": ("PANOS_SSH_CRED", "MEDIUM"),
    "SSH_SESSION_START": ("PANOS_SSH_ACCESS", "LOW"),
    "SSH_SESSION_END": ("PANOS_SSH_ACCESS", "LOW"),
    "SSH_SHOW_SYSINFO": ("PANOS_SSH_RECON", "LOW"),
    "SSH_SHOW_POLICY": ("PANOS_SSH_RECON", "MEDIUM"),
    "SSH_SHOW_NAT": ("PANOS_SSH_RECON", "MEDIUM"),
    "SSH_SHOW_SESSION_INFO": ("PANOS_SSH_RECON", "LOW"),
    "SSH_SHOW_SESSION_ALL": ("PANOS_SSH_RECON", "MEDIUM"),
    "SSH_SHOW_INTERFACE": ("PANOS_SSH_RECON", "LOW"),
    "SSH_SHOW_DISK": ("PANOS_SSH_RECON", "LOW"),
    "SSH_SHOW_RESOURCES": ("PANOS_SSH_RECON", "LOW"),
    "SSH_SHOW_CMD": ("PANOS_SSH_RECON", "LOW"),
    "SSH_CONFIG_ENTER": ("PANOS_SSH_CONFIG", "HIGH"),
    "SSH_CONFIG_EXIT": ("PANOS_SSH_CONFIG", "LOW"),
    "SSH_CONFIG_SET": ("PANOS_SSH_WRITE", "CRITICAL"),
    "SSH_CONFIG_DELETE": ("PANOS_SSH_WRITE", "CRITICAL"),
    "SSH_CONFIG_EDIT": ("PANOS_SSH_WRITE", "HIGH"),
    "SSH_CONFIG_CMD": ("PANOS_SSH_CONFIG", "MEDIUM"),
    "SSH_COMMIT": ("PANOS_SSH_COMMIT", "CRITICAL"),
    "SSH_REBOOT_ATTEMPT": ("PANOS_SSH_REBOOT", "CRITICAL"),
    "SSH_REQUEST_CMD": ("PANOS_SSH_REQUEST", "HIGH"),
    "SSH_DEBUG_CMD": ("PANOS_SSH_DEBUG", "HIGH"),
    "SSH_UNKNOWN_CMD": ("PANOS_SSH_CMD", "LOW"),
}

# CVE-specific attack types
CVE_ATTACK_TYPES = {
    "CVE-2024-0012": "PANOS_CVE_2024_0012",
    "CVE-2024-9474": "PANOS_CVE_2024_9474",
    "CVE-2025-0108": "PANOS_CVE_2025_0108",
    "CVE-2024-3400": "PANOS_CVE_2024_3400",
    "CVE-2021-3064": "PANOS_CVE_2021_3064",
    # The decoy has detected these three for a while; the mapping had not caught up, so they
    # were ingested under a generic attack type and were invisible to any per-CVE query.
    "CVE-2026-0257": "PANOS_CVE_2026_0257",
    "CVE-2026-0300": "PANOS_CVE_2026_0300",
    "CVE-2026-0322": "PANOS_CVE_2026_0322",
}


# =============================================================================
# Database Functions
# =============================================================================


def get_connection():
    conn = legacy_get_db()
    conn.autocommit = True
    return conn


def generate_event_id(event: dict) -> str:
    unique_str = (
        f"{event.get('timestamp', '')}-{event.get('src_ip', '')}-"
        f"{event.get('event_type', '')}-{event.get('path', event.get('data', {}).get('command', ''))}"
    )
    return hashlib.sha256(unique_str.encode()).hexdigest()[:32]


def event_exists(conn, event_id: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM sensor_events WHERE event_id = %s LIMIT 1", (event_id,))
    return cur.fetchone() is not None


def insert_event(conn, event: dict, event_id: str, source_type: str = "web"):
    """Insert PAN-OS honeypot event into database."""
    cur = conn.cursor()

    ts = event.get("timestamp", "")
    if not ts:
        ts = datetime.now(UTC).isoformat()

    event_type = event.get("event_type", "")
    data = event.get("data", {})
    if not isinstance(data, dict):
        data = {}

    # --- Determine attack types ---
    attack_types = []
    mapping = WEB_EVENT_TO_ATTACK if source_type == "web" else SSH_EVENT_TO_ATTACK

    if event_type in mapping:
        attack_type, severity = mapping[event_type]
        attack_types.append((attack_type, severity))

    # UNKNOWN_PATH means the decoy did not recognise the path — which is precisely when
    # it has nothing to say about the vendor. Mapping it straight to PANOS_PROBE turned
    # "I don't know" into an assertion, and the assertion was often wrong: Cisco
    # AnyConnect probes (`/+CSCOE+/logon.html`, `/+CSCOT+/oem-customization`) arriving on
    # :4443 were filed as Palo Alto reconnaissance. Ask the text classifier what the path
    # actually is; keep PANOS_PROBE only when nothing else identifies it.
    rule_for_type = {}
    if event_type == "UNKNOWN_PATH":
        identified = foreign_path.classify(data)
        if identified:
            attack_types = [at for at in attack_types if at[0] != "PANOS_PROBE"]
            for atype, sev, rule in identified:
                attack_types.append((atype, sev))
                rule_for_type[atype] = rule

    # Override severity from event data if present

    # CVE-specific classification
    cve = data.get("cve", "")
    if cve and cve in CVE_ATTACK_TYPES:
        attack_types.append((CVE_ATTACK_TYPES[cve], "CRITICAL"))

    # Credential capture — always add PANOS_CRED if username present
    if data.get("username") and event_type not in ("SSH_SESSION_START", "SSH_SESSION_END"):
        base_cred = "PANOS_SSH_CRED" if source_type == "ssh" else "PANOS_CRED"
        if not any(at[0] == base_cred for at in attack_types):
            sev = "HIGH" if data.get("default_creds") else "MEDIUM"
            attack_types.append((base_cred, sev))

    # Default credentials escalation
    if data.get("default_creds"):
        if not any(at[0] == "PANOS_DEFAULT_CRED" for at in attack_types):
            attack_types.append(("PANOS_DEFAULT_CRED", "HIGH"))

    attack_types_str = ",".join(at[0] for at in attack_types) if attack_types else None

    # --- Build payload ---
    if source_type == "ssh":
        payload_parts = {
            "event_type": event_type,
            "data": data,
        }
        # Include command history for session end events
        cmd_history = data.get("command_history")
        if cmd_history:
            payload_parts["command_history"] = cmd_history[:50]
    else:
        payload_parts = {
            "event_type": event_type,
            "path": event.get("path", ""),
            "method": event.get("method", ""),
            "query": event.get("query", ""),
            "user_agent": event.get("user_agent", ""),
            "data": data,
        }
        # The last field of value that lived outside `data`, and so the last one the
        # on-disk log was the sole copy of. Bodies, passwords and the portal auth cookies
        # are inside `data` and were never at risk; raw_body_b64 goes to full_payload.
        headers = event.get("headers")
        if headers:
            payload_parts["headers"] = headers
        raw_len = event.get("raw_body_len")
        if raw_len is not None:
            payload_parts["raw_body_len"] = raw_len

    # 4 KB is generous here rather than tight: across 555,336 events on PROD and DEV the
    # longest payload this produces is 2,120 characters, so nothing is actually being
    # cut. Measured before trimming the log, because a cap that silently truncated would
    # have destroyed evidence the moment the file stopped being the backup.
    payload = json.dumps(payload_parts)[:4000]

    # --- Determine dst_port ---
    honeypot_name = event.get("honeypot", "")
    if honeypot_name == "paloalto_ssh":
        dst_port = 2200
        protocol = "ssh"
        source = "paloalto-ssh-honeypot"
    elif event_type.startswith("CAPTIVE_"):
        dst_port = 6082
        protocol = "https"
        source = "paloalto-captive-honeypot"
    else:
        dst_port = 4443
        protocol = "https"
        source = "paloalto-honeypot"

    # --- Insert sensor_events ---
    #
    # raw_body_b64 goes into full_payload rather than into `payload`. It is the verbatim
    # POST body the decoy received, capped at 8 KB by the honeypot, so base64 of it can
    # reach ~11 KB — well past the 4 KB cap on the text column, and a base64 string cut
    # in half is not a partial body, it is a corrupt one. full_payload is bytea and was
    # sitting unused by this ingest.
    #
    # This has to work before the on-disk log may be trimmed: until now the file was the
    # only copy of the raw body anywhere. The 2026-05 PAN-OS review recorded exactly that
    # ("on disk but not in the DB") and it stayed true for four months.
    raw_body = None
    b64 = event.get("raw_body_b64")
    if b64:
        try:
            raw_body = base64.b64decode(b64, validate=True)
        except (ValueError, TypeError) as exc:
            logger.warning(
                "raw_body_b64 on %s is not valid base64 (%s) — keeping the "
                "encoded form in the payload instead",
                event_id,
                exc,
            )
    try:
        if raw_body is not None and _full_payload_supported(cur):
            cur.execute(
                """
                INSERT INTO sensor_events (
                    event_id, timestamp, src_ip, src_port, dst_port,
                    protocol, source, payload, attack_types,
                    full_payload, full_payload_hash
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s
                )
                ON CONFLICT (event_id) DO NOTHING
            """,
                (
                    event_id,
                    ts,
                    event.get("src_ip", "0.0.0.0"),  # noqa: S104 # nosec B104 — field default value, not a bind address
                    event.get("src_port", 0),
                    dst_port,
                    protocol,
                    source,
                    payload,
                    attack_types_str,
                    psycopg2.Binary(raw_body),
                    hashlib.sha256(raw_body).hexdigest(),
                ),
            )
        else:
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
                    protocol,
                    source,
                    payload,
                    attack_types_str,
                ),
            )
    except psycopg2.Error as e:
        logger.error("Insert sensor_events error: %s", e)
        return False

    # --- Insert attack_patterns ---
    for attack_type, severity in attack_types:
        rule_name = rule_for_type.get(attack_type, f"paloalto_{event_type.lower()}")
        matched_text = ""
        if cve:
            matched_text = f"{cve}: {data.get('detail', '')}"[:500]
        elif data.get("username"):
            matched_text = f"user={data['username']}"[:500]
        elif data.get("command"):
            matched_text = data["command"][:500]
        elif event.get("path"):
            matched_text = event["path"][:500]

        try:
            cur.execute(
                """
                INSERT INTO attack_patterns (
                    event_id, attack_type, rule_name, matched_text, severity, confidence
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """,
                (
                    event_id,
                    attack_type,
                    rule_name,
                    matched_text,
                    severity,
                    "high",
                ),
            )
        except psycopg2.Error as e:
            logger.debug("Attack pattern insert error: %s", e)

    return True


_FULL_PAYLOAD_OK = None


def _full_payload_supported(cur):
    """Whether sensor_events has the bytea columns, probed once per process.

    An install from before the Idea 30 Phase 0 migration does not have them. Failing the
    insert there would lose the whole event, so we fall back to the narrow statement and
    keep the raw body out of the database — which is also why cleanup must not run on
    such a host without the operator knowing.
    """
    global _FULL_PAYLOAD_OK
    if _FULL_PAYLOAD_OK is None:
        try:
            cur.execute("""
                SELECT count(*) FROM information_schema.columns
                WHERE table_name = 'sensor_events'
                  AND column_name IN ('full_payload', 'full_payload_hash')
            """)
            _FULL_PAYLOAD_OK = cur.fetchone()[0] == 2
            if not _FULL_PAYLOAD_OK:
                logger.warning(
                    "sensor_events has no full_payload column — raw POST "
                    "bodies will not be stored; run the migrations before "
                    "letting the ingest trim its input log"
                )
        except psycopg2.Error:
            _FULL_PAYLOAD_OK = False
    return _FULL_PAYLOAD_OK


# =============================================================================
# Log Processing
# =============================================================================


def get_last_position(pos_file: str, log_file: str | None = None) -> int:
    # `pos_file` is now the ingest's short name ("paloalto_web"), not a path.
    return state.read_position(pos_file, log_file)


def save_position(pos_file: str, pos: int):
    state.save_position(pos_file, pos)


def process_log_file(
    log_file: str,
    pos_file: str,
    conn,
    source_type: str = "web",
    process_all: bool = False,
    dry_run: bool = False,
):
    """Process a PAN-OS honeypot log file."""
    if not os.path.exists(log_file):
        return 0, 0

    start_pos = 0 if process_all else get_last_position(pos_file, log_file)
    processed = 0
    inserted = 0

    with open(log_file) as f:
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
                et = event.get("event_type", "?")
                ip = event.get("src_ip", "?")
                logger.info(
                    "[DRY-RUN] %s %s %s",
                    ip,
                    et,
                    event.get("path", event.get("data", {}).get("command", ""))[:80],
                )
                inserted += 1
                continue

            if event_exists(conn, event_id):
                continue

            try:
                if insert_event(conn, event, event_id, source_type):
                    inserted += 1
            except psycopg2.Error as e:
                logger.error("Insert error: %s", e)

        consumed = 0
        if not dry_run:
            consumed = f.tell()
            save_position(pos_file, consumed)

    # Trim what we have consumed. Nothing outside this ingest reads the file — the
    # honeypot writes it, we read it, and every other reference in the tree is prose —
    # but it was never trimmed, so honeypot_paloalto_ssh.json on DEV had grown to 107 MB
    # and 470,007 events. An untrimmed log is also a loaded gun: lose the offset and the
    # whole history replays into a table retention has already cleaned out.
    #
    # Only safe now that insert_event() carries `headers`, `raw_body_len` and the decoded
    # raw_body_b64 into the database. Until this release the file was the sole copy of
    # the verbatim POST bodies.
    if not dry_run and not process_all and consumed > 0:
        if logcleanup.refuse_outside(log_file, [os.path.dirname(os.path.realpath(log_file))]):
            try:
                logcleanup.drop_consumed_prefix(log_file, consumed)
                # Offset and file must move together: a stale offset would seek past the
                # end of the trimmed file, and the ingest would read nothing and say
                # nothing about it.
                save_position(pos_file, 0)
            except OSError as exc:
                logger.warning("Could not clean up %s: %s", log_file, exc)

    return processed, inserted


# =============================================================================
# Statistics
# =============================================================================


def show_stats(conn):
    """Show PAN-OS honeypot event statistics from database."""
    cur = conn.cursor()

    print("\n=== PAN-OS Honeypot Event Statistics ===\n")

    # Total events by source
    cur.execute("""
        SELECT source, COUNT(*) FROM sensor_events
        WHERE source LIKE 'paloalto%%'
        GROUP BY source ORDER BY COUNT(*) DESC
    """)
    rows = cur.fetchall()
    if rows:
        print("Events by source:")
        for source, count in rows:
            print(f"  {source:35s} {count:>6}")
    else:
        print("  No PAN-OS events in database yet.")
        return

    # Events by attack type
    print("\nEvents by attack type:")
    cur.execute("""
        SELECT attack_type, severity, COUNT(*) FROM attack_patterns
        WHERE attack_type LIKE 'PANOS%%'
        GROUP BY attack_type, severity ORDER BY COUNT(*) DESC
    """)
    for atype, severity, count in cur.fetchall():
        print(f"  {atype:35s} {severity:10s} {count:>6}")

    # Top source IPs
    print("\nTop 10 source IPs:")
    cur.execute("""
        SELECT src_ip, COUNT(*) FROM sensor_events
        WHERE source LIKE 'paloalto%%'
        GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 10
    """)
    for ip, count in cur.fetchall():
        print(f"  {ip!s:20s} {count:>6}")

    # Credential captures
    print("\nCredential captures:")
    cur.execute("""
        SELECT COUNT(*) FROM attack_patterns
        WHERE attack_type IN ('PANOS_CRED', 'PANOS_SSH_CRED', 'PANOS_GP_CRED',
                              'PANOS_API_CRED', 'PANOS_CAPTIVE_CRED', 'PANOS_DEFAULT_CRED')
    """)
    cred_count = cur.fetchone()[0]
    print(f"  Total: {cred_count}")

    # CVE detections
    print("\nCVE detections:")
    cur.execute("""
        SELECT attack_type, COUNT(*) FROM attack_patterns
        WHERE attack_type LIKE 'PANOS_CVE_%%'
        GROUP BY attack_type ORDER BY COUNT(*) DESC
    """)
    cve_rows = cur.fetchall()
    if cve_rows:
        for atype, count in cve_rows:
            cve_id = atype.replace("PANOS_", "").replace("_", "-")
            print(f"  {cve_id:20s} {count:>6}")
    else:
        print("  None detected yet.")

    # CRITICAL events
    print("\nCRITICAL severity events:")
    cur.execute("""
        SELECT attack_type, COUNT(*) FROM attack_patterns
        WHERE attack_type LIKE 'PANOS%%' AND severity = 'CRITICAL'
        GROUP BY attack_type ORDER BY COUNT(*) DESC
    """)
    for atype, count in cur.fetchall():
        print(f"  {atype:35s} {count:>6}")

    print()


# =============================================================================
# Main
# =============================================================================


def main():
    from honeylens.logging_setup import setup_logging

    setup_logging()
    parser = argparse.ArgumentParser(description="Ingest PAN-OS honeypot logs into sensor database")
    parser.add_argument(
        "--all", "-a", action="store_true", help="Process all events from beginning"
    )
    parser.add_argument("--dry-run", "-n", action="store_true", help="Test without inserting")
    parser.add_argument("--stats", action="store_true", help="Show event statistics and exit")
    parser.add_argument(
        "--web-log", default=LOG_FILE_WEB, help=f"Web honeypot log (default: {LOG_FILE_WEB})"
    )
    parser.add_argument(
        "--ssh-log", default=LOG_FILE_SSH, help=f"SSH honeypot log (default: {LOG_FILE_SSH})"
    )

    args = parser.parse_args()

    try:
        conn = get_connection()
    except psycopg2.Error as e:
        logger.error("Database connection failed: %s", e)
        sys.exit(1)

    if args.stats:
        show_stats(conn)
        conn.close()
        sys.exit(0)

    logger.info("PAN-OS honeypot log ingestion starting")

    if args.dry_run:
        logger.info("DRY RUN — no changes will be made")

    total_processed = 0
    total_inserted = 0

    # Process web honeypot log (Phases A-C, E)
    if os.path.exists(args.web_log):
        logger.info("Processing web log: %s", args.web_log)
        p, i = process_log_file(
            args.web_log,
            POSITION_FILE_WEB,
            conn,
            source_type="web",
            process_all=args.all,
            dry_run=args.dry_run,
        )
        logger.info("  Web: %d processed, %d inserted", p, i)
        total_processed += p
        total_inserted += i
    else:
        logger.info("Web log not found: %s (skipping)", args.web_log)

    # Process SSH honeypot log (Phase D)
    if os.path.exists(args.ssh_log):
        logger.info("Processing SSH log: %s", args.ssh_log)
        p, i = process_log_file(
            args.ssh_log,
            POSITION_FILE_SSH,
            conn,
            source_type="ssh",
            process_all=args.all,
            dry_run=args.dry_run,
        )
        logger.info("  SSH: %d processed, %d inserted", p, i)
        total_processed += p
        total_inserted += i
    else:
        logger.info("SSH log not found: %s (skipping)", args.ssh_log)

    logger.info("Total: %d processed, %d inserted", total_processed, total_inserted)
    conn.close()


if __name__ == "__main__":
    main()
