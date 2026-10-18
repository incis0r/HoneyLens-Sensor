#!/usr/bin/env python3
"""
import_ja4_db.py — create + populate the ja4_database known-fingerprint reference
=================================================================================
Creates the ``ja4_database`` table (the JA4 known-fingerprint lookup read by
``routes/ja4.py`` + ``api.py:lookup_ja4_fingerprint``) and imports records from the
FoxIO JA4 database (https://ja4db.com), one row per (fingerprint, fingerprint_type).
Idempotent (ON CONFLICT) — run once at install and to refresh.

Usage:
    python -m tools.import_ja4_db                     # download from ja4db.com
    python -m tools.import_ja4_db --file ja4db.json   # import a local JSON file
    python -m tools.import_ja4_db --url <url>         # custom download URL
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import urllib.request

from honeylens.database import legacy_get_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("import-ja4-db")

DEFAULT_URL = "https://ja4db.com/api/download/"

# FoxIO ja4db JSON field -> our fingerprint_type label
FP_FIELDS = [
    ("ja4_fingerprint", "ja4"),
    ("ja4s_fingerprint", "ja4s"),
    ("ja4h_fingerprint", "ja4h"),
    ("ja4x_fingerprint", "ja4x"),
    ("ja4t_fingerprint", "ja4t"),
    ("ja4ts_fingerprint", "ja4ts"),
    ("ja4ssh_fingerprint", "ja4ssh"),
]

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS ja4_database (
    fingerprint           TEXT        NOT NULL,
    fingerprint_type      TEXT        NOT NULL,
    application           TEXT,
    library               TEXT,
    device                TEXT,
    os                    TEXT,
    user_agent            TEXT,
    certificate_authority TEXT,
    verified              BOOLEAN     DEFAULT FALSE,
    notes                 TEXT,
    updated_at            TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (fingerprint, fingerprint_type)
);
"""
INDEX_SQL = "CREATE INDEX IF NOT EXISTS idx_ja4_database_fingerprint ON ja4_database (fingerprint);"

UPSERT_SQL = """
INSERT INTO ja4_database
    (fingerprint, fingerprint_type, application, library, device, os,
     user_agent, certificate_authority, verified, notes, updated_at)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
ON CONFLICT (fingerprint, fingerprint_type) DO UPDATE SET
    application=EXCLUDED.application, library=EXCLUDED.library, device=EXCLUDED.device,
    os=EXCLUDED.os, user_agent=EXCLUDED.user_agent,
    certificate_authority=EXCLUDED.certificate_authority,
    verified=EXCLUDED.verified, notes=EXCLUDED.notes, updated_at=NOW();
"""


def load_from_plugin() -> list:
    """Build records from the enterprise JA4+ plugin's curated KNOWN_JA4 tables.

    These are FoxIO-licensed malware/tooling fingerprints shipped only with the
    honeylens_ja4_plus plugin (not the OSS core). Returns [] if the plugin is absent.
    """
    try:
        from honeylens_ja4_plus.known_tables import KNOWN_JA4H, KNOWN_JA4S, KNOWN_JA4X
    except Exception:
        logger.warning("honeylens_ja4_plus not installed — no plugin known-fingerprints to import")
        return []
    recs = []
    for table, field in (
        (KNOWN_JA4S, "ja4s_fingerprint"),
        (KNOWN_JA4H, "ja4h_fingerprint"),
        (KNOWN_JA4X, "ja4x_fingerprint"),
    ):
        for fp, name in table.items():
            recs.append(
                {
                    "application": name,
                    "verified": True,
                    "notes": "honeylens_ja4_plus curated",
                    field: fp,
                }
            )
    return recs


def load_records(args) -> list:
    if args.from_plugin:
        return load_from_plugin()
    if args.file:
        with open(args.file) as fh:
            data = json.load(fh)
    else:
        logger.info("Downloading JA4 database from %s", args.url)
        req = urllib.request.Request(args.url, headers={"User-Agent": "honeylens-ja4-import"})
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=90) as resp:  # nosec B310
            data = json.load(resp)
    if isinstance(data, list):
        return data
    for key in ("data", "results", "records", "ja4db", "fingerprints"):
        if isinstance(data.get(key), list):
            return data[key]
    raise SystemExit(
        f"Unrecognised JA4 database JSON structure (top-level keys: {list(data.keys())[:10]})"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Create + populate ja4_database from the FoxIO JA4 DB")
    ap.add_argument("--url", default=DEFAULT_URL, help="ja4db download URL")
    ap.add_argument("--file", help="local ja4db JSON file instead of downloading")
    ap.add_argument(
        "--from-plugin",
        action="store_true",
        help="seed from the enterprise honeylens_ja4_plus curated KNOWN_JA4 tables",
    )
    args = ap.parse_args()

    records = load_records(args)
    logger.info("Loaded %d source records", len(records))

    conn = legacy_get_db()
    cur = conn.cursor()
    cur.execute(CREATE_SQL)
    cur.execute(INDEX_SQL)
    conn.commit()

    imported = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        meta = (
            rec.get("application"),
            rec.get("library"),
            rec.get("device"),
            rec.get("os"),
            rec.get("user_agent_string") or rec.get("user_agent"),
            rec.get("certificate_authority"),
            bool(rec.get("verified")),
            rec.get("notes"),
        )
        for field, ftype in FP_FIELDS:
            fp = rec.get(field)
            if not fp:
                continue
            cur.execute(UPSERT_SQL, (fp, ftype, *meta))
            imported += 1
    conn.commit()
    cur.execute("SELECT COUNT(*) FROM ja4_database")
    total = cur.fetchone()[0]
    conn.close()
    logger.info("ja4_database: %d rows imported/updated, %d total", imported, total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
