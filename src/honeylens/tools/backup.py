#!/usr/bin/env python3
"""
backup.py — Hybrid Intelligence Sensor Full System Backup
==========================================================
Creates a password-protected ZIP archive containing:
  1. All system scripts (*.py, *.c, *.sh, *.service, *.txt, *.md)
  2. Configuration files (config.py, certs/, profiles/, Ideas/)
  3. PostgreSQL full database dump (pg_dump)
  4. PostgreSQL schema-only snapshot (for quick restore reference)
  5. Backup metadata (timestamp, version, file manifest)

The output is a single password-protected ZIP file.

Usage:
    python backup.py                          # Use default password from config.py
    python backup.py --password '<YOUR_PASSWORD>'     # Custom password
    python backup.py --output /backups/       # Custom output directory
    python backup.py --no-db                  # Skip database (scripts only)
    python backup.py --db-only                # Database only (no scripts)
    python backup.py --dry-run                # Show what would be backed up
    python backup.py --list-backups           # List existing backups

Requires: zip (with encryption), pg_dump
Platform: Rocky Linux 9 / RHEL 9
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from honeylens.config import BACKUP_PASSWORD

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] backup: %(message)s",
)
logger = logging.getLogger("backup")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Default password — override with --password or BACKUP_PASSWORD env var

try:
    from honeylens.config import DB_CONFIG
except ImportError:
    DB_CONFIG = {
        "dbname": "sensor",
        "user": "sensor_user",
        "password": os.environ.get("DB_PASSWORD", ""),
        "host": "localhost",
        "port": 5432,
    }

# Sensor installation directory
SENSOR_DIR = Path(__file__).parent.resolve()

# Default backup output directory
DEFAULT_BACKUP_DIR = SENSOR_DIR / "backups"

# Files and directories to include in backup
SCRIPT_PATTERNS = [
    "*.py",
    "*.c",
    "*.sh",
    "*.service",
    "*.txt",
    "*.md",
    "*.json",
]

INCLUDE_DIRS = [
    "Ideas",
    "certs",
    "profiles",
]

EXCLUDE_PATTERNS = [
    "__pycache__",
    "*.pyc",
    ".git",
    "node_modules",
    "venv",
    "backups",  # Don't backup backups
    "malware",  # Malware samples backed up separately
    "pcaps",  # Too large — PCAPs not included
    "event_buffer.jsonl",
    "*.log",
    ".npm",
    ".cache",
    ".wget-hsts",
    ".npmrc",
    "._*",  # macOS metadata files
]


# ---------------------------------------------------------------------------
# Helper: Check tool availability
# ---------------------------------------------------------------------------


def check_tool(name: str) -> bool:
    """Check if a command-line tool is available."""
    return shutil.which(name) is not None


def require_tool(name: str, install_hint: str = ""):
    """Require a tool or exit."""
    if not check_tool(name):
        logger.error("Required tool '%s' not found.", name)
        if install_hint:
            logger.error("Install with: %s", install_hint)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Step 1: Collect system scripts
# ---------------------------------------------------------------------------


def collect_scripts(sensor_dir: Path) -> list:
    """Collect all script and config files."""
    files = []

    # Collect by pattern
    for pattern in SCRIPT_PATTERNS:
        for f in sensor_dir.glob(pattern):
            if f.is_file() and not _should_exclude(f, sensor_dir):
                files.append(f)

    # Collect directories
    for dirname in INCLUDE_DIRS:
        dirpath = sensor_dir / dirname
        if dirpath.is_dir():
            for f in dirpath.rglob("*"):
                if f.is_file() and not _should_exclude(f, sensor_dir):
                    files.append(f)

    # Deduplicate and sort
    files = sorted(set(files))
    return files


def _should_exclude(filepath: Path, base_dir: Path) -> bool:
    """Check if a file should be excluded from backup."""
    rel = str(filepath.relative_to(base_dir))
    name = filepath.name

    for pattern in EXCLUDE_PATTERNS:
        if pattern.startswith("*."):
            if name.endswith(pattern[1:]):
                return True
        elif pattern in rel.split(os.sep):
            return True
        elif name == pattern:
            return True
        elif name.startswith("._"):
            return True

    return False


# ---------------------------------------------------------------------------
# Step 2: Database backup
# ---------------------------------------------------------------------------


def pg_dump_full(output_path: Path) -> bool:
    """Create a full PostgreSQL database dump (data + schema)."""
    logger.info("Creating full database dump...")

    env = os.environ.copy()
    env["PGPASSWORD"] = DB_CONFIG.get("password", "")

    cmd = [
        "pg_dump",
        "-h",
        DB_CONFIG.get("host", "localhost"),
        "-p",
        str(DB_CONFIG.get("port", 5432)),
        "-U",
        DB_CONFIG.get("user", "sensor_user"),
        "-d",
        DB_CONFIG.get("dbname", "sensor"),
        "-F",
        "c",  # Custom format (compressed, supports pg_restore)
        "-f",
        str(output_path),
        "-v",  # Verbose
    ]

    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)
        if result.returncode == 0:
            size = output_path.stat().st_size
            logger.info("Full dump: %s (%s MB)", output_path.name, f"{size / 1024 / 1024:.1f}")
            return True
        else:
            logger.error("pg_dump failed: %s", result.stderr[:500])
            return False
    except subprocess.TimeoutExpired:
        logger.error("pg_dump timed out (>600s)")
        return False
    except FileNotFoundError:
        logger.error("pg_dump not found — install postgresql-client")
        return False


def pg_dump_schema(output_path: Path) -> bool:
    """Create a schema-only dump (no data — for reference)."""
    logger.info("Creating schema snapshot...")

    env = os.environ.copy()
    env["PGPASSWORD"] = DB_CONFIG.get("password", "")

    cmd = [
        "pg_dump",
        "-h",
        DB_CONFIG.get("host", "localhost"),
        "-p",
        str(DB_CONFIG.get("port", 5432)),
        "-U",
        DB_CONFIG.get("user", "sensor_user"),
        "-d",
        DB_CONFIG.get("dbname", "sensor"),
        "-s",  # Schema only
        "-f",
        str(output_path),
    ]

    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            size = output_path.stat().st_size
            logger.info("Schema snapshot: %s (%s KB)", output_path.name, f"{size / 1024:.1f}")
            return True
        else:
            logger.error("Schema dump failed: %s", result.stderr[:500])
            return False
    except Exception as e:
        logger.error("Schema dump error: %s", e)
        return False


def pg_table_counts() -> dict:
    """Get row counts for all tables (for metadata)."""
    try:
        from honeylens.database import legacy_get_db

        conn = legacy_get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT schemaname || '.' || relname AS table, n_live_tup
            FROM pg_stat_user_tables ORDER BY n_live_tup DESC
        """)
        counts = {r[0]: r[1] for r in cur.fetchall()}
        conn.close()
        return counts
    except Exception as e:
        logger.warning("Could not get table counts: %s", e)
        return {}


# ---------------------------------------------------------------------------
# Step 3: Build metadata
# ---------------------------------------------------------------------------


def build_metadata(
    files: list, sensor_dir: Path, db_full: bool, db_schema: bool, table_counts: dict
) -> dict:
    """Build backup metadata document."""
    # File manifest with hashes
    manifest = []
    total_size = 0
    for f in files:
        try:
            size = f.stat().st_size
            total_size += size
            sha = hashlib.sha256(f.read_bytes()).hexdigest()[:16]
            manifest.append(
                {
                    "path": str(f.relative_to(sensor_dir)),
                    "size": size,
                    "sha256_prefix": sha,
                }
            )
        except OSError as _exc:  # silent: best effort file manifest, skip unreadable files
            logging.getLogger(__name__).debug("ignored: %s", _exc)

    # Try to get version info
    version = "unknown"
    try:
        with open(sensor_dir / "README.md") as f:
            for line in f:
                if "v2026" in line or "v202" in line:
                    version = line.strip()[:60]
                    break
    except OSError as _exc:  # silent: best effort version read, fallback is "unknown"
        logging.getLogger(__name__).debug("ignored: %s", _exc)

    return {
        "backup_type": "standalone_full",
        "timestamp": datetime.now(UTC).isoformat(),
        "sensor_dir": str(sensor_dir),
        "hostname": os.uname().nodename,
        "version": version,
        "files": {
            "count": len(manifest),
            "total_size_bytes": total_size,
            "manifest": manifest,
        },
        "database": {
            "full_dump": db_full,
            "schema_snapshot": db_schema,
            "config": {
                "host": DB_CONFIG.get("host"),
                "port": DB_CONFIG.get("port"),
                "dbname": DB_CONFIG.get("dbname"),
                "user": DB_CONFIG.get("user"),
            },
            "table_counts": table_counts,
        },
    }


# ---------------------------------------------------------------------------
# Step 4: Create password-protected ZIP
# ---------------------------------------------------------------------------


def create_encrypted_zip(staging_dir: Path, output_zip: Path, password: str) -> bool:
    """Archive the staging dir into ``output_zip``.

    With a password: a plain ZIP encrypted with openssl AES-256 (PBKDF2). The
    passphrase is handed to openssl on a **file descriptor**, never on the command
    line — ``/proc/<pid>/cmdline`` is world-readable, so ``zip -P <pass>`` (the old
    approach, and weak ZipCrypto at that) leaked the backup password to any local
    user during the run. Without a password: a plain ZIP, no encryption.

    The caller decides the filename (``.zip`` vs ``.zip.enc``); this writes exactly
    ``output_zip``.
    """
    logger.info("Creating backup archive: %s", output_zip.name)

    def _build_plain_zip(dest: Path) -> bool:
        try:
            subprocess.run(
                ["zip", "-r", "-9", str(dest), "."],
                cwd=str(staging_dir),
                capture_output=True,
                text=True,
                timeout=600,
                check=True,
            )
            return True
        except subprocess.TimeoutExpired:
            logger.error("ZIP creation timed out")
        except FileNotFoundError:
            logger.error("'zip' command not found — install: dnf install zip")
        except subprocess.CalledProcessError as exc:
            logger.error("zip failed: %s", (exc.stderr or "")[:500])
        return False

    if not password:
        logger.warning("No backup password set — writing an UNENCRYPTED archive")
        return _build_plain_zip(output_zip)

    # 1. Build the unencrypted zip next to the target, then encrypt it away.
    inner = output_zip.with_name(output_zip.name + ".plain")
    if not _build_plain_zip(inner):
        return False

    # 2. openssl AES-256 + PBKDF2; passphrase on an inherited fd, not argv/env.
    r_fd, w_fd = os.pipe()
    try:
        os.write(w_fd, password.encode("utf-8"))
        os.close(w_fd)
        subprocess.run(
            [
                "openssl",
                "enc",
                "-aes-256-cbc",
                "-pbkdf2",
                "-salt",
                "-in",
                str(inner),
                "-out",
                str(output_zip),
                "-pass",
                f"fd:{r_fd}",
            ],
            pass_fds=(r_fd,),
            capture_output=True,
            text=True,
            timeout=600,
            check=True,
        )
    except subprocess.TimeoutExpired:
        logger.error("openssl encryption timed out")
        return False
    except FileNotFoundError:
        logger.error("'openssl' not found — install: dnf install openssl")
        return False
    except subprocess.CalledProcessError as exc:
        logger.error("openssl encryption failed: %s", (exc.stderr or "")[:500])
        return False
    finally:
        try:
            os.close(r_fd)
        except OSError:
            pass
        inner.unlink(missing_ok=True)

    size = output_zip.stat().st_size
    logger.info("Backup created (openssl AES-256): %s (%.1f MB)", output_zip, size / 1024 / 1024)
    return True


# ---------------------------------------------------------------------------
# Main backup flow
# ---------------------------------------------------------------------------


def run_backup(args):
    """Execute the full backup process."""
    sensor_dir = SENSOR_DIR
    password = args.password or os.environ.get("BACKUP_PASSWORD", BACKUP_PASSWORD)
    output_dir = Path(args.output) if args.output else DEFAULT_BACKUP_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    hostname = os.uname().nodename.replace(".", "_")
    encrypted = bool(password)
    zip_name = f"sensor_backup_{hostname}_{timestamp}.zip" + (".enc" if encrypted else "")
    output_zip = output_dir / zip_name

    logger.info("=" * 60)
    logger.info("  Hybrid Intelligence Sensor — Backup")
    logger.info("=" * 60)
    logger.info("  Sensor dir:  %s", sensor_dir)
    logger.info("  Output:      %s", output_zip)
    logger.info("  Database:    %s", "skip" if args.no_db else "include")
    logger.info("  Scripts:     %s", "skip" if args.db_only else "include")
    logger.info("")

    # Collect files
    files = []
    if not args.db_only:
        files = collect_scripts(sensor_dir)
        logger.info("Collected %s files", len(files))
        if args.dry_run:
            for f in files:
                print(f"  {f.relative_to(sensor_dir)}")
            print(f"\nTotal: {len(files)} files")
            if not args.no_db:
                print("Database: full dump + schema snapshot")
            return 0

    # Create staging directory
    with tempfile.TemporaryDirectory(prefix="sensor_backup_") as tmpdir:
        staging = Path(tmpdir) / "sensor_backup"
        staging.mkdir()

        # Copy scripts
        if not args.db_only:
            scripts_dir = staging / "scripts"
            scripts_dir.mkdir()
            for f in files:
                rel = f.relative_to(sensor_dir)
                dest = scripts_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)
            logger.info("Copied %s files to staging", len(files))

        # Database dumps
        db_full_ok = False
        db_schema_ok = False
        table_counts = {}

        if not args.no_db:
            db_dir = staging / "database"
            db_dir.mkdir()

            # Full dump
            db_full_path = db_dir / f"sensor_full_{timestamp}.dump"
            db_full_ok = pg_dump_full(db_full_path)

            # Schema snapshot
            db_schema_path = db_dir / f"sensor_schema_{timestamp}.sql"
            db_schema_ok = pg_dump_schema(db_schema_path)

            # Table counts
            table_counts = pg_table_counts()

            if not db_full_ok and not args.db_only:
                logger.warning("Database dump failed — continuing with scripts only")

        # Metadata
        metadata = build_metadata(files, sensor_dir, db_full_ok, db_schema_ok, table_counts)
        meta_path = staging / "backup_metadata.json"
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2, default=str)

        # Restore instructions
        restore_path = staging / "RESTORE.md"
        with open(restore_path, "w") as f:
            f.write(f"""# Backup Restore Instructions

## Backup Info
- Created: {metadata["timestamp"]}
- Hostname: {metadata["hostname"]}
- Files: {metadata["files"]["count"]}
- Database: {"included" if db_full_ok else "not included"}

## Decrypt and unzip
```bash
# encrypted (.zip.enc) — openssl prompts for the password, nothing on the command line:
openssl enc -d -aes-256-cbc -pbkdf2 -in {zip_name} -out backup.zip && unzip backup.zip
# an unencrypted .zip backup is just: unzip {zip_name}
```

## Restore Scripts
```bash
cp -r scripts/* /opt/sensor/
```

## Restore Database (full)
```bash
pg_restore -h localhost -U sensor_user -d sensor \\
    --clean --if-exists \\
    database/sensor_full_{timestamp}.dump
```

## Restore Database (schema only — empty tables)
```bash
psql -h localhost -U sensor_user -d sensor \\
    -f database/sensor_schema_{timestamp}.sql
```

## Restart Services
```bash
sudo systemctl restart sensor-api sensor-ebpf honeypot
sudo systemctl restart sensor-ai-analyzer sensor-ttl-deception
```
""")

        # Create encrypted ZIP
        if not create_encrypted_zip(staging, output_zip, password):
            logger.error("Backup failed!")
            return 1

    # Summary
    logger.info("")
    logger.info("=" * 60)
    logger.info("  Backup Complete")
    logger.info("=" * 60)
    logger.info("  File:       %s", output_zip)
    logger.info("  Size:       %s MB", output_zip.stat().st_size / 1024 / 1024)
    logger.info("  Scripts:    %s files", len(files))
    logger.info("  DB dump:    %s", "OK" if db_full_ok else "SKIPPED")
    logger.info("  DB schema:  %s", "OK" if db_schema_ok else "SKIPPED")
    if table_counts:
        total_rows = sum(table_counts.values())
        logger.info("  DB rows:    %s across %s tables", total_rows, len(table_counts))
    logger.info("  Encrypted:  %s", "openssl AES-256 (PBKDF2)" if encrypted else "NO (no password)")
    logger.info("")
    if encrypted:
        logger.info(
            "  Restore: openssl enc -d -aes-256-cbc -pbkdf2 -in %s -out b.zip && unzip b.zip",
            zip_name,
        )
    else:
        logger.info("  Restore: unzip %s", zip_name)
    logger.info("")

    return 0


# ---------------------------------------------------------------------------
# List existing backups
# ---------------------------------------------------------------------------


def list_backups(args):
    """List existing backup files."""
    backup_dir = Path(args.output) if args.output else DEFAULT_BACKUP_DIR
    if not backup_dir.exists():
        print(f"No backups directory: {backup_dir}")
        return 0

    zips = sorted(backup_dir.glob("sensor_backup_*.zip*"), reverse=True)
    if not zips:
        print(f"No backups found in {backup_dir}")
        return 0

    print(f"\n  Existing Backups ({backup_dir})")
    print(f"  {'─' * 70}")
    print(f"  {'File':<50s}  {'Size':>8s}  {'Date'}")
    print(f"  {'─' * 70}")

    for z in zips:
        size = z.stat().st_size
        mtime = datetime.fromtimestamp(z.stat().st_mtime, tz=UTC).strftime("%Y-%m-%d %H:%M")
        size_str = f"{size / 1024 / 1024:.1f} MB"
        print(f"  {z.name:<50s}  {size_str:>8s}  {mtime}")

    print(f"  {'─' * 70}")
    print(f"  Total: {len(zips)} backups\n")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Hybrid Intelligence Sensor — Full System Backup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python %(prog)s                             # Default password from config.py
  python %(prog)s --password '<YOUR_PASSWORD>'        # Custom password
  python %(prog)s --output /mnt/backups/      # Custom output directory
  python %(prog)s --no-db                     # Scripts only, skip database
  python %(prog)s --db-only                   # Database only, skip scripts
  python %(prog)s --dry-run                   # Preview what would be backed up
  python %(prog)s --list-backups              # List existing backups

Restore:
  openssl enc -d -aes-256-cbc -pbkdf2 -in sensor_backup_*.zip.enc -out b.zip && unzip b.zip
  pg_restore -h localhost -U sensor_user -d sensor database/sensor_full_*.dump
        """,
    )
    parser.add_argument(
        "--password",
        "-p",
        type=str,
        default=None,
        help="ZIP password (default: from config.py BACKUP_PASSWORD)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help=f"Output directory (default: {DEFAULT_BACKUP_DIR})",
    )
    parser.add_argument("--no-db", action="store_true", help="Skip database dump (scripts only)")
    parser.add_argument("--db-only", action="store_true", help="Database dump only (no scripts)")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Show what would be backed up")
    parser.add_argument(
        "--list-backups", "-l", action="store_true", help="List existing backup files"
    )
    args = parser.parse_args()

    if args.list_backups:
        return list_backups(args)

    # Verify tools
    if not args.no_db and not args.dry_run:
        if not check_tool("pg_dump"):
            logger.warning("pg_dump not found — database backup will be skipped")
            logger.warning("Install: dnf install postgresql")
            args.no_db = True

    if not args.dry_run:
        require_tool("zip", "dnf install zip")

    return run_backup(args)


if __name__ == "__main__":
    sys.exit(main())
