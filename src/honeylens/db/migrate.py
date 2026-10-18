"""Runner for numbered, idempotent PostgreSQL migrations.

The sensor schema lives in ``migrations/NNNN_*.sql`` next to this module (package data, so
an installed sensor needs no checkout). ``apply(conn)`` creates the ``schema_migrations``
table, runs in order every migration whose version is not recorded there, and records it.

Contract (safe for live sensor databases):
  * every migration is **additive and idempotent** (``CREATE TABLE IF NOT EXISTS``,
    ``ADD COLUMN IF NOT EXISTS``, ``CREATE INDEX IF NOT EXISTS``, extending ``ALTER TYPE``);
  * statements run one at a time, with one retry for a missing dependency, and tolerate
    "already exists";
  * an existing, populated database baselines itself: the first pass runs everything as a
    no-op and records the versions.

``apply()`` never deletes or rewrites data. The installer runs it; it does not fire on its
own on any deployed database.
"""

import argparse
import logging
import re
from pathlib import Path
from typing import Any

import psycopg2

logger = logging.getLogger("honeylens.migrate")

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

_VERSION_RE = re.compile(r"^(\d{4})_.*\.sql$")

_SCHEMA_MIGRATIONS_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    VARCHAR(16) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""


def discover_migrations(migrations_dir: Path = MIGRATIONS_DIR) -> list[tuple[str, Path]]:
    """``[(version, path)]`` for ``NNNN_*.sql`` files, ascending by version."""
    found = []
    for path in migrations_dir.glob("*.sql"):
        m = _VERSION_RE.match(path.name)
        if m:
            found.append((m.group(1), path))
    found.sort(key=lambda vp: vp[0])
    return found


def split_statements(sql_blob: str) -> list[str]:
    """Split multi-statement SQL into individual statements.

    Understands semicolons, ``DO $$ ... $$`` blocks, ``--`` comments and blank lines. The
    same logic ``setup_db`` had in 0.9; this is now the single source of truth.
    """
    statements: list[str] = []
    current: list[str] = []
    in_dollar_block = False

    for line in sql_blob.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        if "$$" in stripped and not in_dollar_block:
            in_dollar_block = True
            current.append(line)
            if stripped.count("$$") >= 2:
                in_dollar_block = False
                statements.append("\n".join(current))
                current = []
            continue
        if in_dollar_block:
            current.append(line)
            if "$$" in stripped:
                in_dollar_block = False
                if stripped.endswith(";"):
                    statements.append("\n".join(current))
                    current = []
            continue
        current.append(line)
        if stripped.endswith(";"):
            stmt = "\n".join(current).strip()
            if stmt and stmt != ";":
                statements.append(stmt)
            current = []

    if current:
        stmt = "\n".join(current).strip()
        if stmt and stmt != ";":
            statements.append(stmt)
    return statements


def normalize_ddl(stmt: str) -> str:
    """Canonical form of a statement for comparisons (whitespace collapsed, no ``;``)."""
    return " ".join(stmt.split()).rstrip(";").strip()


def _execute_tolerant(cur: Any, statements: list[str]) -> list[str]:
    """Execute idempotently with one retry for dependencies; return what still did not apply.

    "already exists" is tolerated. A statement that fails on a missing dependency gets a
    second pass. The rest comes back in the list — logged, non-fatal, so an unexpected
    error does not leave a live database halfway through a migration.
    """
    pending = [s for s in statements if s.strip()]
    for _pass in range(2):
        failed = []
        for stmt in pending:
            try:
                cur.execute(stmt)
            except psycopg2.Error as exc:
                if "already exists" in str(exc).lower():
                    continue
                failed.append(stmt)
        pending = failed
        if not pending:
            break
    for stmt in pending:
        logger.warning("migration statement did not apply: %s", normalize_ddl(stmt)[:120])
    return pending


def _set_autocommit(conn: Any) -> None:
    try:
        conn.autocommit = True
    except psycopg2.Error as exc:
        # Some callers set autocommit earlier; inside an open transaction psycopg2 refuses
        # the change, and that is no reason to abort the migration.
        logger.debug("autocommit already set or transaction open: %s", exc)


def baseline(conn: Any, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    """Record every discovered migration as applied WITHOUT running the DDL.

    For a database that already has the current schema (a sensor built by the old
    ``setup_db``): the DDL would be a series of no-ops, but each one queues an ACCESS
    EXCLUSIVE lock on hot tables and stalls the ingest. Returns the recorded versions.
    """
    _set_autocommit(conn)
    cur = conn.cursor()
    cur.execute(_SCHEMA_MIGRATIONS_DDL)
    recorded = []
    for version, _path in discover_migrations(migrations_dir):
        cur.execute(
            "INSERT INTO schema_migrations (version) VALUES (%s) ON CONFLICT DO NOTHING",
            (version,),
        )
        recorded.append(version)
    logger.info("baselined %d migrations (no DDL run): %s", len(recorded), ", ".join(recorded))
    return recorded


def apply(
    conn: Any,
    migrations_dir: Path = MIGRATIONS_DIR,
    force: bool = False,
    lock_timeout_ms: int = 3000,
) -> list[str]:
    """Run every unrecorded migration in order. Returns the applied versions.

    On a busy sensor, DDL on hot tables waits for a lock behind the live ingest;
    ``lock_timeout_ms`` (0 disables) makes such a statement fail fast instead of blocking
    inserts. A statement that did not apply is logged and the migration is recorded anyway
    (so a current schema baselines cleanly); the warning says it may be incomplete — then
    ``force=True`` in a maintenance window.
    """
    _set_autocommit(conn)
    cur = conn.cursor()
    if lock_timeout_ms:
        cur.execute("SET lock_timeout = %s", (f"{int(lock_timeout_ms)}ms",))
    cur.execute(_SCHEMA_MIGRATIONS_DDL)
    cur.execute("SELECT version FROM schema_migrations")
    recorded = {row[0] for row in cur.fetchall()}

    applied = []
    for version, path in discover_migrations(migrations_dir):
        if version in recorded and not force:
            continue
        statements = split_statements(path.read_text())
        pending = _execute_tolerant(cur, statements)
        cur.execute(
            "INSERT INTO schema_migrations (version) VALUES (%s) ON CONFLICT DO NOTHING",
            (version,),
        )
        applied.append(version)
        if pending:
            logger.warning(
                "migration %s: %d/%d statements deferred (lock contention or missing dependency); "
                "recorded anyway. If the schema is not already current, re-run with force=True "
                "in a low-traffic window.",
                version,
                len(pending),
                len(statements),
            )
        else:
            logger.info("migration %s applied cleanly (%d statements)", version, len(statements))
    return applied


def main(argv: list[str] | None = None) -> int:
    """Runner CLI (``honeylens-migrate``).

    In 0.9 ``python -m db.migrate`` for a while did nothing and exited zero — the module had
    no ``__main__`` block — so the fleet reported "migration applied, rc=0" six times
    although nothing had been executed (2026-08-27). A runner that cannot be invoked is a
    runner that silently does not work.
    """
    ap = argparse.ArgumentParser(
        prog="honeylens-migrate", description="Apply pending schema migrations"
    )
    ap.add_argument("--force", action="store_true", help="re-apply migrations already recorded")
    ap.add_argument(
        "--baseline",
        action="store_true",
        help="record every migration as applied WITHOUT running it (database already has the schema)",
    )
    ap.add_argument("--list", action="store_true", help="show discovered migrations and exit")
    args = ap.parse_args(argv)

    if args.list:
        for version, path in discover_migrations():
            print(f"{version}  {path.name}")
        return 0

    from honeylens.database import legacy_get_db

    conn = legacy_get_db()
    try:
        if args.baseline:
            recorded = baseline(conn)
            print("baselined: " + (", ".join(recorded) if recorded else "nothing new"))
        else:
            applied = apply(conn, force=args.force)
            print("applied: " + (", ".join(applied) if applied else "nothing pending"))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
