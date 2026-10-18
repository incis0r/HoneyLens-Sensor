"""Transactional hand-off of qualified sensor PCAPs to the exporter spool."""

import json
import os
import re
import shutil
from pathlib import Path

EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SPOOL_ROOT = Path(os.environ.get("PCAP_EXPORT_SPOOL", "/var/spool/honeylens-pcap-exporter/pending"))


def queue_export_candidate(
    cursor,
    pcap_path,
    event_id,
    severity,
    captured_at,
    protocol,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    metadata,
):
    """Copy a HIGH/CRITICAL PCAP before purge and insert its outbox row."""
    severity = str(severity or "").upper()
    if severity not in {"HIGH", "CRITICAL"}:
        return False
    if not EVENT_ID_RE.fullmatch(str(event_id)):
        raise ValueError("invalid event_id for PCAP export")
    source = Path(pcap_path)
    if not source.is_file():
        raise FileNotFoundError(str(source))
    SPOOL_ROOT.mkdir(parents=True, exist_ok=True, mode=0o750)
    destination = SPOOL_ROOT / (str(event_id) + ".pcap")
    created = False
    if not destination.exists():
        temporary = destination.with_name(destination.name + f".tmp.{os.getpid()}")
        try:
            with source.open("rb") as input_handle, temporary.open("xb") as output_handle:
                shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
                output_handle.flush()
                os.fsync(output_handle.fileno())
            temporary.replace(destination)
            created = True
        finally:
            temporary.unlink(missing_ok=True)
    try:
        cursor.execute(
            """INSERT INTO pcap_export_outbox (
                   event_id, spool_path, severity, captured_at, source, protocol,
                   src_ip, src_port, dst_ip, dst_port, metadata, eligible_at
               ) VALUES (%s, %s, %s, %s, 'sensor', %s, %s, %s, %s, %s, %s::jsonb,
                         %s::timestamptz + interval '60 seconds')
               ON CONFLICT (event_id) DO NOTHING""",
            (
                event_id,
                str(destination),
                severity,
                captured_at,
                protocol,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                json.dumps(metadata or {}, separators=(",", ":"), default=str),
                captured_at,
            ),
        )
    except Exception:
        if created:
            destination.unlink(missing_ok=True)
        raise
    return True
