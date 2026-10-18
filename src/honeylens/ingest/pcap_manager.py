#!/usr/bin/env python3
"""
pcap_manager.py — PCAP Lifecycle Management Daemon (Idea 23)
Hybrid Intelligence Sensor

AI-driven PCAP retention: triage → compress → purge.
Designed for high volume (2M+ files, streaming scandir, batch SQL).

Pipeline:
  1. TRIAGE  — stream scandir, batch SQL lookup, classify KEEP/CONDITIONAL/PURGE
  2. COMPRESS — zstd level 3 (multiprocessing pool), archive to date-partitioned dirs
  3. PURGE   — delete raw noise PCAPs + expired archive entries
  4. STATS   — log metrics to pcap_stats table

Run:
    python pcap_manager.py              # daemon (every 5 min)
    python pcap_manager.py --once       # single cycle
    python pcap_manager.py --once --dry-run
    python pcap_manager.py --stats      # show archive stats
    python pcap_manager.py --purge-archive --older-than 30

Compatible with Python 3.9+.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg2
import psycopg2.extras

# zstandard is a hard dependency of the package; the gzip branch from 0.9 was dead code.
import zstandard as zstd

from honeylens.config import PCAP_DIR, PCAP_MANAGEMENT
from honeylens.database import legacy_get_db

logger = logging.getLogger("honeylens.ingest.pcap")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


# Merge defaults with config
_DEFAULTS = {
    "enabled": True,
    "daemon_interval_sec": 300,
    "cooldown_sec": 600,  # 10 min — let AI process events first
    "default_retention_hours": 24,
    "keep_retention_days": 30,
    "conditional_retention_days": 7,
    "compression": "zstd",
    "zstd_level": 3,
    "compress_workers": 4,
    # 0.9 had "./pcaps" here and relied on the /opt/sensor working directory — the same class
    # of failure as the sys.path bootstrap. The path comes from the configuration, not the cwd.
    "raw_dir": str(PCAP_DIR),
    "archive_dir": str(PCAP_DIR / "archive"),
    "large_pcap_bytes": 10240,  # 10KB
    "tiny_pcap_bytes": 100,
    "max_files_per_cycle": 100000,
    "batch_sql_size": 5000,  # SQL IN clause batch size
    "keep_verdicts": ["CRITICAL", "SUSPICIOUS"],
    "purge_verdicts": ["NOISE"],
    "threat_score_keep": 70,
    "zero_day_score_keep": 40,
    "rare_protocol_threshold": 100,  # events in 24h
}
CFG: dict[str, Any] = {**_DEFAULTS, **PCAP_MANAGEMENT}

# Event ID regex — SHA-256 = 64 hex chars
_EID_LEN = 64

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def get_db():
    """Get a psycopg2 connection."""
    return legacy_get_db()


def ensure_tables(conn) -> None:
    """Create pcap_index and pcap_stats tables if they don't exist."""
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pcap_index (
                id              BIGSERIAL       PRIMARY KEY,
                event_id        VARCHAR(64)     NOT NULL UNIQUE,
                filepath        TEXT            NOT NULL,
                original_size   INTEGER         NOT NULL,
                compressed_size INTEGER,
                compression     VARCHAR(8)      DEFAULT 'zstd',
                verdict         VARCHAR(16)     NOT NULL,
                retention_rule  VARCHAR(64),
                retention_days  INTEGER         DEFAULT 30,
                protocol        VARCHAR(32),
                src_ip          INET,
                dst_port        INTEGER,
                attack_types    TEXT,
                ai_class        VARCHAR(16),
                threat_score    INTEGER,
                captured_at     TIMESTAMPTZ,
                archived_at     TIMESTAMPTZ     DEFAULT NOW(),
                expires_at      TIMESTAMPTZ,
                created_at      TIMESTAMPTZ     DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_pcap_event    ON pcap_index (event_id);
            CREATE INDEX IF NOT EXISTS idx_pcap_verdict  ON pcap_index (verdict);
            CREATE INDEX IF NOT EXISTS idx_pcap_ai       ON pcap_index (ai_class);
            CREATE INDEX IF NOT EXISTS idx_pcap_protocol ON pcap_index (protocol);
            CREATE INDEX IF NOT EXISTS idx_pcap_src      ON pcap_index (src_ip);
            CREATE INDEX IF NOT EXISTS idx_pcap_expires  ON pcap_index (expires_at)
                WHERE expires_at IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_pcap_captured ON pcap_index (captured_at DESC);

            CREATE TABLE IF NOT EXISTS pcap_stats (
                id              SERIAL          PRIMARY KEY,
                run_at          TIMESTAMPTZ     DEFAULT NOW(),
                total_scanned   INTEGER,
                kept            INTEGER,
                conditional     INTEGER,
                purged          INTEGER,
                compressed      INTEGER,
                skipped         INTEGER,
                already_indexed INTEGER         DEFAULT 0,
                raw_bytes       BIGINT,
                compressed_bytes BIGINT,
                freed_bytes     BIGINT,
                scan_ms         INTEGER,
                query_ms        INTEGER,
                compress_ms     INTEGER,
                purge_ms        INTEGER,
                total_ms        INTEGER,
                archive_files   INTEGER,
                archive_bytes   BIGINT
            );
        """)
    conn.commit()
    logger.info("PCAP tables verified/created.")


# ---------------------------------------------------------------------------
# Phase 1: TRIAGE — streaming scandir + batch SQL
# ---------------------------------------------------------------------------


def scan_pcap_dir(
    raw_dir: str, cooldown_sec: int, max_files: int, already_indexed: set[str]
) -> tuple[list[tuple[str, str, int]], int]:
    """
    Stream-scan the raw PCAP directory.
    Returns: (list of (event_id, filepath, file_size), skipped_count)

    Uses os.scandir() for zero-stat listing, then stat only qualifying files.
    Skips files newer than cooldown_sec (let AI analyzer process first).
    Skips files already in pcap_index.
    """
    cutoff = time.time() - cooldown_sec
    results: list[tuple[str, str, int]] = []
    skipped = 0

    try:
        with os.scandir(raw_dir) as it:
            for entry in it:
                if len(results) >= max_files:
                    break

                # Quick name filter (no I/O)
                name = entry.name
                if not name.endswith(".pcap"):
                    continue
                eid = name[:-5]  # strip .pcap
                if len(eid) != _EID_LEN:
                    continue
                # Validate hex chars
                try:
                    int(eid, 16)
                except ValueError:
                    continue  # silent: filename is not a valid hex event_id

                # Skip already indexed
                if eid in already_indexed:
                    continue

                # Stat for mtime + size (one syscall per file)
                try:
                    stat = entry.stat()
                except OSError:
                    continue  # silent: file disappeared between scandir and stat

                # Skip too new (let AI catch up)
                if stat.st_mtime > cutoff:
                    skipped += 1
                    continue

                results.append((eid, entry.path, stat.st_size))

    except FileNotFoundError:
        logger.error("PCAP directory not found: %s", raw_dir)

    return results, skipped


def get_indexed_event_ids(conn) -> set[str]:
    """Get all event_ids already in pcap_index (fast set lookup)."""
    with conn.cursor() as cur:
        cur.execute("SELECT event_id FROM pcap_index")
        return {row[0] for row in cur.fetchall()}


def batch_lookup_events(conn, event_ids: list[str]) -> dict[str, dict[str, Any]]:
    """
    Batch lookup event metadata + AI verdict + threat scores.
    Single SQL query for the entire batch.
    Returns dict keyed by event_id.
    """
    if not event_ids:
        return {}

    results: dict[str, dict[str, Any]] = {}

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT
                se.event_id,
                se.protocol,
                host(se.src_ip) AS src_ip,
                se.dst_port,
                se.attack_types,
                se.source,
                se.scan_score,
                se.timestamp,
                OCTET_LENGTH(COALESCE(se.payload, '')) AS payload_len,
                ai.triage_class AS ai_class,
                ai.novelty_score,
                ai.zero_day_score,
                ai.known_cve,
                CASE WHEN ai.deep_analysis IS NOT NULL THEN TRUE ELSE FALSE END AS has_deep,
                ts.score AS threat_score,
                ts.chain_detected,
                -- Recent CVE-SID fire from the same source (±15 min).
                -- Catches the lost-body pattern: when an attacker fires
                -- a HONEYLENS captive-portal SID, retain ALL PCAPs in
                -- the flanking window from that source, regardless of
                -- AI verdict. AI runs later than PCAP-retention; without
                -- this, the body-bearing flow gets purged before triage.
                EXISTS (
                    SELECT 1 FROM sensor_events se2
                    WHERE se2.src_ip = se.src_ip
                      AND se2.timestamp BETWEEN se.timestamp - interval '15 minutes'
                                            AND se.timestamp + interval '15 minutes'
                      AND (
                           se2.suricata_sid BETWEEN 9026300 AND 9026314
                        OR se2.suricata_sid BETWEEN 9026420 AND 9026424
                      )
                ) AS recent_cve_sid_fire
            FROM sensor_events se
            LEFT JOIN ai_analysis ai ON se.event_id = ai.event_id
            LEFT JOIN threat_scores ts ON se.event_id = ts.event_id
            WHERE se.event_id = ANY(%s)
        """,
            (event_ids,),
        )

        for row in cur.fetchall():
            results[row["event_id"]] = dict(row)

    return results


def triage_pcap(eid: str, file_size: int, meta: dict[str, Any] | None) -> tuple[str, str, int]:
    """
    Classify a single PCAP: KEEP / CONDITIONAL / PURGE.
    Returns: (verdict, retention_rule, retention_days)
    """
    keep_days = CFG["keep_retention_days"]
    cond_days = CFG["conditional_retention_days"]

    # --- No metadata = no event in DB → PURGE ---
    if meta is None:
        if file_size < CFG["tiny_pcap_bytes"]:
            return ("PURGE", "tiny_no_meta", 0)
        return ("PURGE", "no_event_in_db", 0)

    ai_class = (meta.get("ai_class") or "").upper()
    threat_score = meta.get("threat_score") or 0
    zero_day = meta.get("zero_day_score") or 0
    known_cve = meta.get("known_cve")
    has_deep = meta.get("has_deep", False)
    chain = meta.get("chain_detected")
    protocol = (meta.get("protocol") or "").lower()
    attack_types = (meta.get("attack_types") or "").lower()
    source = (meta.get("source") or "").lower()
    scan_score = meta.get("scan_score") or 0
    payload_len = meta.get("payload_len") or 0

    # === INSTANT KEEP (compress + archive, 30 days) ===

    # Run BEFORE the AI-verdict gates: AI runs after PCAP-retention triage,
    # so a flow that fired a HONEYLENS captive-portal CVE SID won't have
    # ai_class/threat_score yet when this function classifies it. Without
    # this rule the bodies on 2026-05-08/16/21/27 got PURGE'd before AI
    # could promote them. SIDs 9026300-9026314 (CVE-2026-0300) and
    # 9026420-9026424 (CVE-2026-42945) trigger this; ±15-min flanking
    # window covers leak-then-exploit chains and reconnaissance pre-bursts.
    if meta.get("recent_cve_sid_fire"):
        return ("KEEP", "recent_cve_sid_fire", keep_days)

    if ai_class == "CRITICAL":
        return ("KEEP", "ai_critical", keep_days)

    if ai_class == "SUSPICIOUS":
        return ("KEEP", "ai_suspicious", keep_days)

    if zero_day >= CFG["zero_day_score_keep"]:
        return ("KEEP", "zero_day_score", keep_days)

    if known_cve:
        return ("KEEP", "known_cve", keep_days)

    if has_deep:
        return ("KEEP", "deep_analysis", keep_days)

    if threat_score >= CFG["threat_score_keep"]:
        return ("KEEP", "high_threat_score", keep_days)

    if chain:
        return ("KEEP", "attack_chain", keep_days)

    # === CONDITIONAL KEEP (compress, 7 days) ===

    ics_protos = {
        "modbus",
        "s7comm",
        "bacnet",
        "dnp3",
        "iec104",
        "enip",
        "ethernet-ip",
        "opcua",
        "mqtt",
    }
    if protocol in ics_protos:
        return ("CONDITIONAL", "ics_protocol", cond_days)

    cred_patterns = ("ntlm", "brute", "credential", "kerberos", "auth_fail")
    if any(p in attack_types for p in cred_patterns):
        return ("CONDITIONAL", "credential_capture", cond_days)

    exploit_patterns = (
        "rce",
        "sqli",
        "lfi",
        "rfi",
        "log4shell",
        "cve_",
        "cmd_injection",
        "deserialization",
        "ssrf",
        "xxe",
    )
    if any(p in attack_types for p in exploit_patterns):
        return ("CONDITIONAL", "exploit_attempt", cond_days)

    if file_size >= CFG["large_pcap_bytes"]:
        return ("CONDITIONAL", "large_payload", cond_days)

    if source == "honeypotng" and payload_len > 100:
        return ("CONDITIONAL", "honeypot_engagement", cond_days)

    # === PURGE ===

    if ai_class == "NOISE":
        return ("PURGE", "ai_noise", 0)

    if ai_class == "KNOWN" and not attack_types:
        return ("PURGE", "ai_known_no_attacks", 0)

    if file_size < CFG["tiny_pcap_bytes"]:
        return ("PURGE", "tiny_file", 0)

    if scan_score and scan_score > 0.8 and not attack_types:
        return ("PURGE", "port_scan_only", 0)

    # No AI verdict and old enough to be here → PURGE
    if not ai_class:
        return ("PURGE", "no_ai_verdict", 0)

    # Fallback
    return ("PURGE", "fallback_default", 0)


# ---------------------------------------------------------------------------
# Phase 2: COMPRESS — zstd or gzip, multiprocessing
# ---------------------------------------------------------------------------


def _compress_one(args: tuple[str, str, str, int]) -> tuple[str, str, int, int, bool]:
    """
    Compress a single PCAP file. Runs in worker process.
    args: (event_id, src_path, dst_path, zstd_level)
    Returns: (event_id, dst_path, original_size, compressed_size, success)
    """
    eid, src, dst, level = args
    try:
        original_size = os.path.getsize(src)

        # Ensure destination directory exists
        os.makedirs(os.path.dirname(dst), exist_ok=True)

        cctx = zstd.ZstdCompressor(level=level)
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            cctx.copy_stream(fin, fout)

        compressed_size = os.path.getsize(dst)

        # Delete the raw file after successful compression
        os.unlink(src)

        return (eid, dst, original_size, compressed_size, True)

    except Exception:
        # Clean up partial compressed file
        try:
            if os.path.exists(dst):
                os.unlink(dst)
        except OSError:
            pass  # silent: best-effort cleanup of partial compressed file
        return (eid, "", 0, 0, False)


def compress_batch(
    to_compress: list[dict[str, Any]],
    archive_dir: str,
    compression: str,
    zstd_level: int,
    workers: int,
) -> list[dict[str, Any]]:
    """
    Compress a batch of PCAPs using a process pool.
    Returns list of dicts with compression results.
    """
    if not to_compress:
        return []

    if compression != "zstd":
        raise ValueError(f"unsupported archive compression {compression!r}: 1.0 writes zstd only")
    ext = ".pcap.zst"
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    dst_dir = os.path.join(archive_dir, today)

    # Build args for each file
    tasks = []
    for item in to_compress:
        eid = item["event_id"]
        src = item["filepath"]
        dst = os.path.join(dst_dir, f"{eid}{ext}")
        tasks.append((eid, src, dst, zstd_level))

    results = []

    # Use ProcessPoolExecutor for true parallelism (bypasses GIL for I/O)
    actual_workers = min(workers, len(tasks))
    with ProcessPoolExecutor(max_workers=actual_workers) as pool:
        futures = {pool.submit(_compress_one, t): t[0] for t in tasks}
        for future in as_completed(futures):
            eid = futures[future]
            try:
                r = future.result(timeout=60)
                results.append(
                    {
                        "event_id": r[0],
                        "filepath": r[1],
                        "original_size": r[2],
                        "compressed_size": r[3],
                        "success": r[4],
                    }
                )
            except Exception as e:
                logger.warning("Compression failed for %s: %s", eid, e)
                results.append(
                    {
                        "event_id": eid,
                        "filepath": "",
                        "original_size": 0,
                        "compressed_size": 0,
                        "success": False,
                    }
                )

    return results


# ---------------------------------------------------------------------------
# Phase 3: PURGE — delete raw + expired archive
# ---------------------------------------------------------------------------


def purge_raw(to_purge: list[dict[str, Any]]) -> tuple[int, int]:
    """
    Delete raw PCAP files classified as PURGE.
    Returns: (deleted_count, freed_bytes)
    """
    deleted = 0
    freed = 0
    for item in to_purge:
        path = item["filepath"]
        size = item.get("file_size", 0)
        try:
            os.unlink(path)
            deleted += 1
            freed += size
        except FileNotFoundError:
            deleted += 1  # already gone
        except OSError as e:
            logger.debug("Could not delete %s: %s", path, e)
    return deleted, freed


def purge_expired_archive(conn, archive_dir: str) -> tuple[int, int]:
    """
    Delete archived PCAPs that have passed their expires_at date.
    Also removes empty date directories.
    Returns: (deleted_count, freed_bytes)
    """
    deleted = 0
    freed = 0

    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, event_id, filepath, compressed_size
            FROM pcap_index
            WHERE expires_at IS NOT NULL AND expires_at < NOW()
        """)
        expired = cur.fetchall()

        for row in expired:
            pid, _eid, fpath, csize = row
            try:
                if os.path.exists(fpath):
                    os.unlink(fpath)
                    freed += csize or 0
                deleted += 1
                cur.execute("DELETE FROM pcap_index WHERE id = %s", (pid,))
            except OSError as e:
                logger.debug("Could not delete archive %s: %s", fpath, e)

    conn.commit()

    # Clean empty date directories
    try:
        for entry in os.scandir(archive_dir):
            if entry.is_dir():
                try:
                    os.rmdir(entry.path)  # only removes if empty
                except OSError:
                    pass  # silent: directory not empty, expected
    except FileNotFoundError:
        pass  # silent: archive directory does not exist yet

    return deleted, freed


# ---------------------------------------------------------------------------
# Phase 4: INDEX + STATS
# ---------------------------------------------------------------------------


def index_compressed(
    conn,
    compressed: list[dict[str, Any]],
    meta_cache: dict[str, dict[str, Any]],
    verdicts: dict[str, tuple[str, str, int]],
) -> int:
    """
    Bulk insert compressed PCAPs into pcap_index.
    Returns count of indexed entries.
    """
    indexed = 0
    now = datetime.now(UTC)

    with conn.cursor() as cur:
        for item in compressed:
            if not item["success"]:
                continue

            eid = item["event_id"]
            meta = meta_cache.get(eid, {})
            verdict, rule, ret_days = verdicts.get(eid, ("KEEP", "unknown", 30))
            expires = now + timedelta(days=ret_days) if ret_days > 0 else None
            compression = CFG["compression"]

            try:
                cur.execute(
                    """
                    INSERT INTO pcap_index (
                        event_id, filepath, original_size, compressed_size,
                        compression, verdict, retention_rule, retention_days,
                        protocol, src_ip, dst_port, attack_types,
                        ai_class, threat_score, captured_at, expires_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (event_id) DO UPDATE SET
                        filepath = EXCLUDED.filepath,
                        compressed_size = EXCLUDED.compressed_size,
                        verdict = EXCLUDED.verdict,
                        retention_rule = EXCLUDED.retention_rule,
                        expires_at = EXCLUDED.expires_at
                """,
                    (
                        eid,
                        item["filepath"],
                        item["original_size"],
                        item["compressed_size"],
                        compression,
                        verdict,
                        rule,
                        ret_days,
                        meta.get("protocol"),
                        meta.get("src_ip"),
                        meta.get("dst_port"),
                        meta.get("attack_types"),
                        meta.get("ai_class"),
                        meta.get("threat_score"),
                        meta.get("timestamp"),
                        expires,
                    ),
                )
                indexed += 1
            except Exception as e:
                logger.debug("Index insert failed for %s: %s", eid, e)

    conn.commit()
    return indexed


def save_stats(conn, stats: dict[str, Any]) -> None:
    """Save cycle metrics to pcap_stats."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO pcap_stats (
                total_scanned, kept, conditional, purged, compressed,
                skipped, already_indexed,
                raw_bytes, compressed_bytes, freed_bytes,
                scan_ms, query_ms, compress_ms, purge_ms, total_ms,
                archive_files, archive_bytes
            ) VALUES (
                %(total_scanned)s, %(kept)s, %(conditional)s, %(purged)s, %(compressed)s,
                %(skipped)s, %(already_indexed)s,
                %(raw_bytes)s, %(compressed_bytes)s, %(freed_bytes)s,
                %(scan_ms)s, %(query_ms)s, %(compress_ms)s, %(purge_ms)s, %(total_ms)s,
                %(archive_files)s, %(archive_bytes)s
            )
        """,
            stats,
        )
    conn.commit()


def get_archive_stats(conn, archive_dir: str) -> dict[str, Any]:
    """Get current archive state."""
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*), COALESCE(SUM(compressed_size), 0) FROM pcap_index")
        files, size = cur.fetchone()

        cur.execute("""
            SELECT verdict, COUNT(*), COALESCE(SUM(compressed_size), 0)
            FROM pcap_index GROUP BY verdict
        """)
        by_verdict = {r[0]: {"count": r[1], "bytes": r[2]} for r in cur.fetchall()}

        cur.execute("""
            SELECT ai_class, COUNT(*)
            FROM pcap_index WHERE ai_class IS NOT NULL
            GROUP BY ai_class ORDER BY COUNT(*) DESC
        """)
        by_ai = {r[0]: r[1] for r in cur.fetchall()}

    return {
        "archive_files": files,
        "archive_bytes": size,
        "archive_mb": round(size / 1048576, 1) if size else 0,
        "by_verdict": by_verdict,
        "by_ai_class": by_ai,
    }


# ---------------------------------------------------------------------------
# Main cycle
# ---------------------------------------------------------------------------


def run_cycle(conn, dry_run: bool = False) -> dict[str, Any]:
    """
    Run one full triage → compress → purge → stats cycle.
    Returns stats dict.
    """
    t_start = time.monotonic()
    raw_dir = CFG["raw_dir"]
    archive_dir = CFG["archive_dir"]

    stats = {
        "total_scanned": 0,
        "kept": 0,
        "conditional": 0,
        "purged": 0,
        "compressed": 0,
        "skipped": 0,
        "already_indexed": 0,
        "raw_bytes": 0,
        "compressed_bytes": 0,
        "freed_bytes": 0,
        "scan_ms": 0,
        "query_ms": 0,
        "compress_ms": 0,
        "purge_ms": 0,
        "total_ms": 0,
        "archive_files": 0,
        "archive_bytes": 0,
    }

    # --- Get already-indexed event IDs ---
    already_indexed = get_indexed_event_ids(conn)
    stats["already_indexed"] = len(already_indexed)

    # --- Phase 1: SCAN ---
    t_scan = time.monotonic()
    files, skipped = scan_pcap_dir(
        raw_dir, CFG["cooldown_sec"], CFG["max_files_per_cycle"], already_indexed
    )
    stats["scan_ms"] = int((time.monotonic() - t_scan) * 1000)
    stats["skipped"] = skipped
    stats["total_scanned"] = len(files)

    if not files:
        logger.info(
            "No PCAPs to process (skipped=%d, already_indexed=%d)", skipped, len(already_indexed)
        )
        stats["total_ms"] = int((time.monotonic() - t_start) * 1000)
        return stats

    logger.info(
        "Scanned %d PCAPs in %dms (skipped %d new, %d already indexed)",
        len(files),
        stats["scan_ms"],
        skipped,
        len(already_indexed),
    )

    # --- Phase 1b: BATCH SQL LOOKUP ---
    t_query = time.monotonic()
    meta_cache: dict[str, dict[str, Any]] = {}
    event_ids = [f[0] for f in files]

    # Process in batches to avoid huge IN clauses
    batch_size = CFG["batch_sql_size"]
    for i in range(0, len(event_ids), batch_size):
        batch = event_ids[i : i + batch_size]
        batch_meta = batch_lookup_events(conn, batch)
        meta_cache.update(batch_meta)

    stats["query_ms"] = int((time.monotonic() - t_query) * 1000)
    logger.info(
        "Batch SQL lookup: %d/%d events found in %dms",
        len(meta_cache),
        len(event_ids),
        stats["query_ms"],
    )

    # --- Phase 1c: TRIAGE ---
    to_compress: list[dict[str, Any]] = []
    to_purge: list[dict[str, Any]] = []
    verdicts: dict[str, tuple[str, str, int]] = {}

    for eid, filepath, file_size in files:
        meta = meta_cache.get(eid)
        verdict, rule, ret_days = triage_pcap(eid, file_size, meta)
        verdicts[eid] = (verdict, rule, ret_days)
        stats["raw_bytes"] += file_size

        item = {
            "event_id": eid,
            "filepath": filepath,
            "file_size": file_size,
            "verdict": verdict,
            "rule": rule,
        }

        if verdict in ("KEEP", "CONDITIONAL"):
            to_compress.append(item)
            if verdict == "KEEP":
                stats["kept"] += 1
            else:
                stats["conditional"] += 1
        else:
            to_purge.append(item)
            stats["purged"] += 1

    logger.info(
        "Triage: KEEP=%d CONDITIONAL=%d PURGE=%d",
        stats["kept"],
        stats["conditional"],
        stats["purged"],
    )

    if dry_run:
        # Log top rules
        rule_counts: dict[str, int] = {}
        for _, (v, r, _) in verdicts.items():
            key = f"{v}/{r}"
            rule_counts[key] = rule_counts.get(key, 0) + 1
        for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:15]:
            logger.info("  [DRY RUN] %s: %d files", rule, count)
        stats["total_ms"] = int((time.monotonic() - t_start) * 1000)
        return stats

    # --- Phase 2: COMPRESS ---
    t_compress = time.monotonic()
    compressed = compress_batch(
        to_compress, archive_dir, CFG["compression"], CFG["zstd_level"], CFG["compress_workers"]
    )
    stats["compress_ms"] = int((time.monotonic() - t_compress) * 1000)

    success_count = sum(1 for c in compressed if c["success"])
    stats["compressed"] = success_count
    stats["compressed_bytes"] = sum(c["compressed_size"] for c in compressed if c["success"])

    if success_count:
        ratio = stats["raw_bytes"] / max(stats["compressed_bytes"], 1)
        logger.info(
            "Compressed %d files in %dms (%.1fx ratio, %s → %s)",
            success_count,
            stats["compress_ms"],
            ratio,
            _human_bytes(sum(c["original_size"] for c in compressed if c["success"])),
            _human_bytes(stats["compressed_bytes"]),
        )

    # --- Phase 2b: INDEX ---
    indexed = index_compressed(conn, compressed, meta_cache, verdicts)
    logger.info("Indexed %d compressed PCAPs", indexed)

    # --- Phase 3: PURGE RAW ---
    t_purge = time.monotonic()
    deleted, freed = purge_raw(to_purge)
    stats["freed_bytes"] = freed
    logger.info("Purged %d raw PCAPs, freed %s", deleted, _human_bytes(freed))

    # --- Phase 3b: PURGE EXPIRED ARCHIVE ---
    exp_deleted, exp_freed = purge_expired_archive(conn, archive_dir)
    if exp_deleted:
        stats["freed_bytes"] += exp_freed
        logger.info(
            "Purged %d expired archive PCAPs, freed %s", exp_deleted, _human_bytes(exp_freed)
        )
    stats["purge_ms"] = int((time.monotonic() - t_purge) * 1000)

    # --- Phase 4: STATS ---
    archive = get_archive_stats(conn, archive_dir)
    stats["archive_files"] = archive["archive_files"]
    stats["archive_bytes"] = archive["archive_bytes"]
    stats["total_ms"] = int((time.monotonic() - t_start) * 1000)

    save_stats(conn, stats)

    logger.info(
        "Cycle complete in %dms — kept=%d compressed=%d purged=%d freed=%s archive=%d/%s",
        stats["total_ms"],
        stats["kept"],
        stats["compressed"],
        stats["purged"],
        _human_bytes(stats["freed_bytes"]),
        stats["archive_files"],
        _human_bytes(stats["archive_bytes"]),
    )

    return stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _human_bytes(b: int) -> str:
    """Format bytes as human-readable."""
    if b < 1024:
        return f"{b}B"
    elif b < 1048576:
        return f"{b / 1024:.1f}KB"
    elif b < 1073741824:
        return f"{b / 1048576:.1f}MB"
    else:
        return f"{b / 1073741824:.2f}GB"


def print_stats(conn, archive_dir: str) -> None:
    """Print archive statistics."""
    archive = get_archive_stats(conn, archive_dir)

    print(f"\n{'=' * 60}")
    print("  PCAP Archive Statistics")
    print(f"{'=' * 60}\n")
    print(f"  Total archived files:  {archive['archive_files']:,}")
    print(f"  Total archive size:    {_human_bytes(archive['archive_bytes'])}")
    print()
    print("  By verdict:")
    for v, data in archive.get("by_verdict", {}).items():
        print(f"    {v:15s}  {data['count']:>8,} files  ({_human_bytes(data['bytes'])})")
    print()
    print("  By AI class:")
    for cls, count in archive.get("by_ai_class", {}).items():
        print(f"    {cls:15s}  {count:>8,} files")

    # Recent runs
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT run_at, total_scanned, kept, conditional, purged, compressed,
                   freed_bytes, total_ms
            FROM pcap_stats ORDER BY run_at DESC LIMIT 10
        """)
        runs = cur.fetchall()

    if runs:
        print("\n  Recent runs:")
        print(
            f"  {'Timestamp':<22s} {'Scanned':>8s} {'Keep':>6s} {'Cond':>6s} "
            f"{'Purge':>6s} {'Compr':>6s} {'Freed':>10s} {'Time':>8s}"
        )
        print(
            f"  {'-' * 22} {'-' * 8} {'-' * 6} {'-' * 6} {'-' * 6} {'-' * 6} {'-' * 10} {'-' * 8}"
        )
        for r in runs:
            ts = r["run_at"].strftime("%Y-%m-%d %H:%M:%S") if r["run_at"] else ""
            print(
                f"  {ts:<22s} {r['total_scanned'] or 0:>8,} {r['kept'] or 0:>6,} "
                f"{r['conditional'] or 0:>6,} {r['purged'] or 0:>6,} "
                f"{r['compressed'] or 0:>6,} {_human_bytes(r['freed_bytes'] or 0):>10s} "
                f"{r['total_ms'] or 0:>7,}ms"
            )
    print()


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------

_shutdown = False


def _signal_handler(signum, frame):
    global _shutdown
    logger.info("Received signal %d — shutting down", signum)
    _shutdown = True


def run_daemon(dry_run: bool = False, once: bool = False) -> None:
    global _shutdown

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    logger.info("=" * 60)
    logger.info("PCAP Manager Daemon — Idea 23")
    logger.info("=" * 60)
    logger.info("Raw dir: %s", CFG["raw_dir"])
    logger.info("Archive dir: %s", CFG["archive_dir"])
    logger.info(
        "Compression: %s (level %d, %d workers)",
        CFG["compression"],
        CFG["zstd_level"],
        CFG["compress_workers"],
    )
    logger.info(
        "Cooldown: %ds, max files/cycle: %d", CFG["cooldown_sec"], CFG["max_files_per_cycle"]
    )

    conn = get_db()
    ensure_tables(conn)

    interval = CFG["daemon_interval_sec"]

    while not _shutdown:
        try:
            run_cycle(conn, dry_run=dry_run)
        except Exception as e:
            logger.exception("Cycle error: %s", e)
            # Reconnect DB if needed
            try:
                conn.close()
            except Exception as e2:
                logger.debug("DB close error during reconnect: %s", e2)
            try:
                conn = get_db()
            except Exception:
                logger.error("DB reconnect failed — will retry next cycle")

        if once:
            break

        logger.info("Sleeping %ds until next cycle...", interval)
        for _ in range(interval):
            if _shutdown:
                break
            time.sleep(1)

    try:
        conn.close()
    except Exception as e:
        logger.debug("DB close error on shutdown: %s", e)
    logger.info("Daemon shutdown complete.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    from honeylens.logging_setup import setup_logging

    setup_logging()
    parser = argparse.ArgumentParser(description="PCAP Lifecycle Manager — Idea 23")
    parser.add_argument("--once", action="store_true", help="Single cycle then exit")
    parser.add_argument("--dry-run", action="store_true", help="Show triage without changes")
    parser.add_argument("--stats", action="store_true", help="Show archive statistics")
    parser.add_argument("--purge-archive", action="store_true", help="Purge expired archived PCAPs")
    parser.add_argument(
        "--older-than",
        type=int,
        default=None,
        help="Override expiry: purge archive older than N days",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.stats:
        conn = get_db()
        ensure_tables(conn)
        print_stats(conn, CFG["archive_dir"])
        conn.close()
        return

    if args.purge_archive:
        conn = get_db()
        ensure_tables(conn)
        if args.older_than:
            # Override expires_at for manual purge
            with conn.cursor() as cur:
                cutoff = datetime.now(UTC) - timedelta(days=args.older_than)
                cur.execute(
                    """
                    UPDATE pcap_index SET expires_at = %s
                    WHERE archived_at < %s AND (expires_at IS NULL OR expires_at > %s)
                """,
                    (cutoff, cutoff, cutoff),
                )
                updated = cur.rowcount
                conn.commit()
                logger.info(
                    "Marked %d archive entries as expired (older than %d days)",
                    updated,
                    args.older_than,
                )
        deleted, freed = purge_expired_archive(conn, CFG["archive_dir"])
        logger.info("Purged %d expired archive PCAPs, freed %s", deleted, _human_bytes(freed))
        conn.close()
        return

    run_daemon(dry_run=args.dry_run, once=args.once or args.dry_run)


if __name__ == "__main__":
    main()
