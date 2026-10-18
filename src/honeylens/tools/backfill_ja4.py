#!/usr/bin/env python3
"""
backfill_ja4.py — Retroactively extract JA4 fingerprints from existing events
==============================================================================

This script processes existing sensor_events that have JA3 fingerprints
(indicating TLS ClientHello was captured) and extracts JA4 fingerprints
from the stored PCAP files.

Usage:
    python backfill_ja4.py                    # Process all events with JA3
    python backfill_ja4.py --limit 1000       # Process up to 1000 events
    python backfill_ja4.py --dry-run          # Show what would be processed
    python backfill_ja4.py --from-metadata    # Extract from metadata (no PCAP needed)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any

# Add parent directory to path for imports
from honeylens.config import PCAP_DIR
from honeylens.database import legacy_get_db

try:
    from classification.ja4 import parse_tls_client_hello_ja4

    HAS_JA4 = True
except ImportError:
    HAS_JA4 = False
    print("ERROR: ja4.py not found. Please ensure ja4.py is in the same directory.")
    sys.exit(1)

try:
    from scapy.all import TCP, rdpcap

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("backfill_ja4")


def strip_nul(value):
    """Remove NUL bytes from strings."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.replace("\x00", "")
    return value


def extract_ja4_from_pcap(pcap_path: str) -> dict[str, Any] | None:
    """Extract JA4 fingerprint from PCAP file."""
    if not HAS_SCAPY:
        return None

    if not os.path.exists(pcap_path):
        return None

    try:
        packets = rdpcap(pcap_path)
        for pkt in packets:
            if not pkt.haslayer(TCP):
                continue

            # Use TCP.payload (same as JA3 extraction)
            payload = bytes(pkt[TCP].payload)

            # Check for TLS Handshake (0x16) + ClientHello (0x01 at offset 5)
            if len(payload) >= 6 and payload[0] == 0x16 and payload[5] == 0x01:
                ja4_info = parse_tls_client_hello_ja4(payload)
                if ja4_info:
                    return ja4_info
    except Exception as e:
        logger.debug("PCAP extraction error for %s: %s", pcap_path, e)

    return None


def backfill(limit: int | None = None, dry_run: bool = False, from_metadata: bool = False):
    """Backfill JA4 fingerprints for existing events."""

    conn = legacy_get_db()
    cur = conn.cursor()

    # Check if ja4_fingerprints table exists
    cur.execute("""
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'ja4_fingerprints'
    """)
    if not cur.fetchone():
        logger.error("ja4_fingerprints table does not exist. Run setup_db.py first.")
        conn.close()
        return

    # Find events that have JA3 but no JA4
    query = """
        SELECT se.event_id, se.ja3, se.metadata
        FROM sensor_events se
        LEFT JOIN ja4_fingerprints j4 ON se.event_id = j4.event_id
        WHERE se.ja3 IS NOT NULL
          AND j4.id IS NULL
        ORDER BY se.timestamp DESC
    """
    if limit:
        query += f" LIMIT {limit}"

    cur.execute(query)
    events = cur.fetchall()

    logger.info("Found %d events with JA3 but no JA4", len(events))

    if dry_run:
        logger.info("Dry run - would process %d events", len(events))
        for event_id, ja3, _metadata in events[:10]:
            pcap_path = os.path.join(PCAP_DIR, f"{event_id}.pcap")
            exists = os.path.exists(pcap_path)
            logger.info(
                "  %s... JA3=%s PCAP=%s",
                event_id[:16],
                ja3[:16] if ja3 else "None",
                "exists" if exists else "missing",
            )
        conn.close()
        return

    # Process events
    processed = 0
    extracted = 0

    insert_sql = """
        INSERT INTO ja4_fingerprints (
            event_id, fingerprint_type, fingerprint,
            fingerprint_a, fingerprint_b, fingerprint_c,
            fingerprint_raw, tls_version, sni, alpn,
            cipher_count, extension_count, identified, metadata
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
    """

    for event_id, _ja3, metadata in events:
        processed += 1

        ja4_info = None

        # Try to extract from PCAP first
        if HAS_SCAPY:
            pcap_path = os.path.join(PCAP_DIR, f"{event_id}.pcap")
            ja4_info = extract_ja4_from_pcap(pcap_path)

        # If PCAP extraction failed and from_metadata is enabled, try metadata
        if not ja4_info and from_metadata and metadata:
            try:
                meta = metadata if isinstance(metadata, dict) else json.loads(metadata)
                if meta.get("analysis", {}).get("ja4"):
                    ja4_data = meta["analysis"]["ja4"]
                    if ja4_data.get("fingerprint"):
                        ja4_info = {
                            "ja4": ja4_data.get("fingerprint"),
                            "ja4_a": ja4_data.get("fingerprint_a"),
                            "ja4_b": ja4_data.get("fingerprint_b"),
                            "ja4_c": ja4_data.get("fingerprint_c"),
                            "ja4_r": None,
                            "tls_version_str": ja4_data.get("tls_version"),
                            "sni": ja4_data.get("sni"),
                            "alpn": ja4_data.get("alpn"),
                            "cipher_count": None,
                            "extension_count": None,
                            "identified": ja4_data.get("identified"),
                        }
            except Exception as _exc:  # silent: best effort metadata JA4 parse, skip on error
                logging.getLogger(__name__).debug("ignored: %s", _exc)

        if ja4_info and ja4_info.get("ja4"):
            try:
                cur.execute(
                    insert_sql,
                    (
                        event_id,
                        "ja4",
                        strip_nul(ja4_info.get("ja4", "")),
                        strip_nul(ja4_info.get("ja4_a")),
                        strip_nul(ja4_info.get("ja4_b")),
                        strip_nul(ja4_info.get("ja4_c")),
                        strip_nul(ja4_info.get("ja4_r")),
                        strip_nul(ja4_info.get("tls_version_str")),
                        strip_nul(ja4_info.get("sni")),
                        strip_nul(ja4_info.get("alpn")),
                        ja4_info.get("cipher_count"),
                        ja4_info.get("extension_count"),
                        strip_nul(ja4_info.get("identified")),
                        json.dumps(
                            {
                                "cipher_suites": ja4_info.get("cipher_suites", []),
                                "extensions": ja4_info.get("extensions", []),
                            }
                        )
                        if ja4_info.get("cipher_suites")
                        else None,
                    ),
                )
                extracted += 1

                if ja4_info.get("identified"):
                    logger.info(
                        "Extracted JA4: %s -> %s (%s)",
                        event_id[:16],
                        ja4_info.get("ja4"),
                        ja4_info.get("identified"),
                    )
            except Exception as e:
                logger.debug("Insert failed for %s: %s", event_id[:16], e)

        if processed % 100 == 0:
            conn.commit()
            logger.info(
                "Progress: %d/%d processed, %d extracted", processed, len(events), extracted
            )

    conn.commit()
    cur.close()
    conn.close()

    logger.info(
        "Backfill complete: %d processed, %d JA4 fingerprints extracted", processed, extracted
    )


def main():
    parser = argparse.ArgumentParser(description="Backfill JA4 fingerprints for existing events")
    parser.add_argument(
        "--limit", type=int, default=None, help="Maximum number of events to process"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be processed without making changes"
    )
    parser.add_argument(
        "--from-metadata", action="store_true", help="Also try to extract JA4 from event metadata"
    )

    args = parser.parse_args()

    if not HAS_SCAPY:
        logger.warning("Scapy not available - PCAP extraction disabled")
        if not args.from_metadata:
            logger.error("Use --from-metadata to extract from stored metadata instead")
            return

    backfill(limit=args.limit, dry_run=args.dry_run, from_metadata=args.from_metadata)


if __name__ == "__main__":
    main()
