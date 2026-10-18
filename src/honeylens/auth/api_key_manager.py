"""
honeylens.auth.api_key_manager — Per-Honeypot API Key + Basic Auth Management
=============================================================================
Manages read-only API keys scoped to individual honeypots (or all honeypots).

Security model:
- Dual credential requirement: every API request must provide BOTH:
  1. HTTP Basic Auth (`Authorization: Basic base64(apiaccess<N>:<randompass>)`)
  2. API Key (`X-API-Key: hlk_<token>`)
- Plaintext `randompass` and `api_key` are returned ONLY ONCE at creation time.
- Standard maximum validity is 90 days (`max_age_days <= 90`).
- Extended 365-day validity (`max_age_days == 365` or `91..365`) requires explicit
  operator risk acknowledgment (`acknowledge_risk=True`).
- Keys approaching expiration (`<= 14` days remaining) or expired are flagged
  for rotation in the `/sensor_admin` panel.
- Keys can be revoked immediately by an administrator.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
import string
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg2 import IntegrityError

from honeylens.auth.auth import hash_password, log_admin_action, verify_password
from honeylens.database import db_cursor
from honeylens.honeypots.manifest import BY_NAME as MANIFEST_HONEYPOTS

logger = logging.getLogger(__name__)

# Expiration policy constants
DEFAULT_MAX_AGE_DAYS = 90
STANDARD_MAX_AGE_DAYS = 90
EXTENDED_MAX_AGE_DAYS = 365
EXPIRING_SOON_DAYS = 14

_BASIC_USER_RE = re.compile(r"^apiaccess(\d+)$")

# Safe alphabet for Basic Auth passwords (explicitly excludes ':' to prevent Basic Auth delimiter ambiguity)
_BASIC_PASS_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"

# Every decoy the manifest declares, plus '*' for a key scoped to all of them.
#
# `cms` used to be listed here by hand, because the CMS decoy was planned but not yet in the
# manifest. It landed on 2026-11-08, so the exception is gone: one source of truth for which
# decoys exist, and a key can only ever be scoped to one that does.
VALID_HONEYPOTS: frozenset[str] = frozenset(set(MANIFEST_HONEYPOTS.keys()) | {"*"})


@dataclass
class HoneypotApiKey:
    """Represents a stored Honeypot API key record."""

    id: int
    key_name: str
    honeypot: str
    basic_username: str
    api_key_prefix: str
    max_age_days: int
    risk_acknowledged: bool
    created_by: int | None
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None = None
    last_used_ip: str | None = None
    revoked: bool = False
    revoked_at: datetime | None = None
    revoked_by: int | None = None
    revoked_reason: str | None = None

    @property
    def days_remaining(self) -> int:
        now = datetime.now(UTC)
        exp = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=UTC)
        delta = exp - now
        return int(delta.total_seconds() // 86400)

    @property
    def is_expired(self) -> bool:
        now = datetime.now(UTC)
        exp = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=UTC)
        return now >= exp

    @property
    def status(self) -> str:
        if self.revoked:
            return "revoked"
        if self.is_expired:
            return "expired"
        if self.days_remaining <= EXPIRING_SOON_DAYS:
            return "expiring_soon"
        return "active"

    @property
    def needs_rotation(self) -> bool:
        return self.status in ("expiring_soon", "expired")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key_name": self.key_name,
            "honeypot": self.honeypot,
            "basic_username": self.basic_username,
            "api_key_prefix": self.api_key_prefix,
            "max_age_days": self.max_age_days,
            "risk_acknowledged": self.risk_acknowledged,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "last_used_ip": self.last_used_ip,
            "revoked": self.revoked,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_by": self.revoked_by,
            "revoked_reason": self.revoked_reason,
            "days_remaining": self.days_remaining,
            "status": self.status,
            "needs_rotation": self.needs_rotation,
        }


def assert_api_keys_table() -> None:
    """Fail loudly when migration 0014 has not been applied on this sensor.

    This used to be a ``CREATE TABLE IF NOT EXISTS`` run on every authentication,
    every listing and every revoke. Two things were wrong with that. It is a DDL
    statement per API request, and it was a second copy of the schema that had already
    drifted from ``0014_honeypot_api_keys.sql`` -- the migration creates four indexes
    the inline copy did not. It also hid the failure mode this project has already been
    bitten by: a process started without ``HONEYLENS_ENV_FILE`` talks to the 0.9
    ``sensor`` database, where the table would simply have been created, and everything
    would have looked like it worked.

    A missing table is now an error that names the fix.
    """
    with db_cursor() as cur:
        cur.execute("SELECT to_regclass('public.honeypot_api_keys') IS NOT NULL")
        row = cur.fetchone()
        if not row or not row[0]:
            raise RuntimeError(
                "Table honeypot_api_keys is missing. Apply migration "
                "0014_honeypot_api_keys.sql (honeylens-migrate with HONEYLENS_ENV_FILE set "
                "to this sensor's env file) before using the honeypot read API."
            )


def normalize_honeypot_name(raw_name: str) -> str:
    """Normalize a honeypot identifier and validate against known honeypots."""
    cleaned = (raw_name or "").strip().lower()
    if cleaned in ("*", "all", "global"):
        return "*"
    for prefix in ("honeypot-", "honeypot_", "hp-", "hp_"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
            break
    for suffix in ("-honeypot", "_honeypot"):
        if cleaned.endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            break
    if cleaned in ("honeypotng", "monolith"):
        cleaned = "honeypot"
    if cleaned not in VALID_HONEYPOTS:
        known = ", ".join(sorted(VALID_HONEYPOTS))
        raise ValueError(f"Unknown honeypot '{raw_name}'. Valid honeypots: {known}")
    return cleaned


# `sensor_events.source` shapes, measured 2026-11-07 across three live sensors:
#   honeypot-<name>        the standalone decoys (honeypot-vnc, honeypot-ssh, honeypot-smb, ...)
#   <name>-honeypot        the vendor and LLM decoys (fortigate-honeypot, paloalto-honeypot,
#                          paloalto-ssh-honeypot, llm-honeypot)
#   <name>                 netscaler, sharepoint
#   honeypotng             the monolith, which serves several decoys and distinguishes them
#                          by `protocol` alone
# `suricata` also appears as a source and is not a decoy at all.
_SOURCE_PREFIXES = ("honeypot-", "honeypot_")
_SOURCE_SUFFIXES = ("-honeypot", "_honeypot")

# Sources that do not follow from the decoy's name.
_EXTRA_SOURCES: dict[str, frozenset[str]] = {
    "paloalto": frozenset({"paloalto-captive-honeypot"}),
}

_MONOLITH_SOURCE = "honeypotng"

# The decoys the monolith serves, measured on three sensors: its own web decoy (the
# `honeypot` scope, answering on http and https) and `wago`, from the 0.9 era. The list is
# narrow on purpose. Including the monolith in every scope would make every query walk its
# rows looking for a protocol that is not there -- measured at 1.6 s per page against 0.002
# to 0.185 s without it.
_MONOLITH_SERVES: frozenset[str] = frozenset({"honeypot", "wago"})
_MONOLITH_WEB_PROTOCOLS = frozenset({"http", "https"})


def _source_aliases(hp: str) -> set[str]:
    """Every `sensor_events.source` value that belongs to decoy `hp`."""
    aliases = {hp}
    aliases |= {prefix + hp for prefix in _SOURCE_PREFIXES}
    aliases |= {hp + suffix for suffix in _SOURCE_SUFFIXES}
    aliases |= set(_EXTRA_SOURCES.get(hp, frozenset()))
    return aliases


def _monolith_protocols(hp: str) -> set[str]:
    """Protocols under `source = 'honeypotng'` that belong to decoy `hp`."""
    if hp == "honeypot":
        return set(_MONOLITH_WEB_PROTOCOLS)
    if hp in _MONOLITH_SERVES:
        return {hp}
    return set()


def honeypot_scope_sql(honeypot: str) -> tuple[str, list[Any]]:
    """Return `(sql_predicate, params)` selecting exactly the events of `honeypot`.

    The predicate is an equality test on one column, `source`, so it can use
    `idx_se_source_time` -- and `protocol` narrows it only *within* the monolith's own
    source, never as an alternative to it.

    Both of those are load-bearing.

    **Protocol as an alternative leaks.** The first version of this offered `protocol` as a
    second way to match, and because the vendor and LLM decoys list `http` and `https`
    among their protocols, a key scoped to one of them matched every HTTP event on the
    sensor. Measured on a live sensor, 2026-11-07:

        scope       events that are the decoy's      events the predicate returned
        llm                                   0                            210,194
        paloalto                          1,912                            210,194
        fortigate                        21,374                            210,194

    **One column keeps the query indexable.** With an `OR` across `source`,
    `metadata->>'honeypot'` and `protocol` the planner had no single index to use, so it
    walked the timestamp index and filtered -- which is cheap for a busy decoy and ruinous
    for a quiet one, because it has to walk the whole window to find a handful of rows.
    Measured on the same sensor, one page of 100 events:

        scope                   OR form      this form
        dnp3 (3 rows/30d)        30.34 s        0.002 s
        sharepoint                2.15 s        0.044 s
        ssh (busy)                0.01 s        0.009 s

    `metadata->>'honeypot'` is not consulted because it adds nothing: on both sensors where
    it was measured, every row carrying it sits on a source this table already covers. It
    is the decoy's second way of saying the same thing.

    A decoy whose source shape is not known here returns no rows for its scope. That is the
    safe direction: under-reporting is visible to the operator who expects rows, while
    over-reporting silently hands one key holder another decoy's traffic.
    """
    hp = normalize_honeypot_name(honeypot)

    if hp == "*":
        every_source = {_MONOLITH_SOURCE}
        for name in VALID_HONEYPOTS:
            if name != "*":
                every_source |= _source_aliases(name)
        return "se.source = ANY(%s)", [sorted(every_source)]

    sources = _source_aliases(hp)
    monolith = _monolith_protocols(hp)
    if not monolith:
        return "se.source = ANY(%s)", [sorted(sources)]

    sources.add(_MONOLITH_SOURCE)
    return (
        f"(se.source = ANY(%s) AND (se.source <> '{_MONOLITH_SOURCE}'"
        " OR LOWER(se.protocol) = ANY(%s)))",
        [sorted(sources), sorted(monolith)],
    )


def generate_basic_password(length: int = 24) -> str:
    """Generate a high-entropy random password safe for HTTP Basic Auth (no colon)."""
    while True:
        pwd = "".join(secrets.choice(_BASIC_PASS_ALPHABET) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%^&*()-_=+" for c in pwd)
        ):
            return pwd


def generate_raw_api_key() -> tuple[str, str, str]:
    """Generate `(raw_api_key, api_key_prefix, api_key_hash)`."""
    raw_key = "hlk_" + secrets.token_urlsafe(32)
    prefix = raw_key[:12] + "..."
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return raw_key, prefix, key_hash


def hash_api_key(raw_key: str) -> str:
    """Compute SHA-256 hex digest of an API key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _next_basic_username(cur: Any) -> str:
    """Allocate the next unique `apiaccess<N>` username.

    The number is derived in SQL rather than by reading every row into Python. Two admins
    creating a key at the same moment can still pick the same N; `basic_username` is UNIQUE,
    so one of them loses the INSERT, and `create_api_key` retries. Before that retry existed
    the loser got "Database error while creating API key" and no explanation.
    """
    cur.execute(
        """
        SELECT COALESCE(
                   MAX(CAST(SUBSTRING(basic_username FROM '^apiaccess([0-9]+)$') AS INTEGER)),
                   0
               ) + 1
        FROM honeypot_api_keys
        """
    )
    row = cur.fetchone()
    return f"apiaccess{int(row[0]) if row and row[0] else 1}"


_USERNAME_ALLOCATION_ATTEMPTS = 3


def _insert_api_key(
    *,
    clean_name: str,
    normalized_hp: str,
    pw_hash: str,
    pw_salt: str,
    key_prefix: str,
    key_hash: str,
    max_age_days: int,
    acknowledge_risk: bool,
    created_by: int | None,
    now: datetime,
    expires_at: datetime,
) -> tuple[str, int, datetime, datetime]:
    """Insert the row, retrying the `apiaccess<N>` allocation if another admin won the race.

    Returns `(basic_username, key_id, created_at, expires_at)`.
    """
    last_error: Exception | None = None
    for _attempt in range(_USERNAME_ALLOCATION_ATTEMPTS):
        try:
            with db_cursor() as cur:
                basic_username = _next_basic_username(cur)
                cur.execute(
                    """
                    INSERT INTO honeypot_api_keys (
                        key_name, honeypot, basic_username, basic_password_hash, basic_salt,
                        api_key_prefix, api_key_hash, max_age_days, risk_acknowledged,
                        created_by, created_at, expires_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id, created_at, expires_at
                    """,
                    (
                        clean_name,
                        normalized_hp,
                        basic_username,
                        pw_hash,
                        pw_salt,
                        key_prefix,
                        key_hash,
                        max_age_days,
                        bool(acknowledge_risk),
                        created_by,
                        now,
                        expires_at,
                    ),
                )
                row = cur.fetchone()
                return basic_username, row[0], row[1], row[2]
        except IntegrityError as exc:
            last_error = exc
            logger.info("apiaccess<N> allocation lost a race, retrying: %s", exc)
    raise last_error if last_error else RuntimeError("API key insert failed")


def create_api_key(
    honeypot: str,
    key_name: str = "",
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    acknowledge_risk: bool = False,
    created_by: int | None = None,
    ip_address: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Create a new per-honeypot API key and Basic Auth credential pair.

    Returns:
        `(creation_payload_dict, error_message)`
        `creation_payload_dict` contains the one-time `api_key`, `basic_username`,
        `basic_password`, `basic_auth_pair`, and `basic_auth_header`.
    """
    try:
        normalized_hp = normalize_honeypot_name(honeypot)
    except ValueError as exc:
        return None, str(exc)

    if not isinstance(max_age_days, int) or isinstance(max_age_days, bool):
        return None, "max_age_days must be an integer"

    if max_age_days < 1 or max_age_days > EXTENDED_MAX_AGE_DAYS:
        return (
            None,
            f"max_age_days must be between 1 and {EXTENDED_MAX_AGE_DAYS} days",
        )

    if max_age_days > STANDARD_MAX_AGE_DAYS and not acknowledge_risk:
        return (
            None,
            f"API keys valid for more than {STANDARD_MAX_AGE_DAYS} days (e.g. {EXTENDED_MAX_AGE_DAYS} days) "
            "require explicit confirmation of security risks (acknowledge_risk=True).",
        )

    clean_name = (key_name or "").strip()[:128] or f"{normalized_hp}-read-key"
    basic_password = generate_basic_password(24)
    pw_hash, pw_salt = hash_password(basic_password)
    raw_api_key, key_prefix, key_hash = generate_raw_api_key()

    now = datetime.now(UTC)
    expires_at = now + timedelta(days=max_age_days)

    try:
        assert_api_keys_table()
        basic_username, key_id, db_created_at, db_expires_at = _insert_api_key(
            clean_name=clean_name,
            normalized_hp=normalized_hp,
            pw_hash=pw_hash,
            pw_salt=pw_salt,
            key_prefix=key_prefix,
            key_hash=key_hash,
            max_age_days=max_age_days,
            acknowledge_risk=acknowledge_risk,
            created_by=created_by,
            now=now,
            expires_at=expires_at,
        )

        log_admin_action(
            admin_user_id=created_by,
            action="CREATE_API_KEY",
            details={
                "key_id": key_id,
                "basic_username": basic_username,
                "honeypot": normalized_hp,
                "max_age_days": max_age_days,
                "risk_acknowledged": bool(acknowledge_risk),
            },
            ip_address=ip_address,
        )

        basic_pair = f"{basic_username}:{basic_password}"
        basic_header = "Basic " + base64.b64encode(basic_pair.encode("utf-8")).decode("ascii")

        key_obj = HoneypotApiKey(
            id=key_id,
            key_name=clean_name,
            honeypot=normalized_hp,
            basic_username=basic_username,
            api_key_prefix=key_prefix,
            max_age_days=max_age_days,
            risk_acknowledged=bool(acknowledge_risk),
            created_by=created_by,
            created_at=db_created_at,
            expires_at=db_expires_at,
        )

        result = key_obj.to_dict()
        result.update(
            {
                "api_key": raw_api_key,
                "basic_password": basic_password,
                "basic_auth_pair": basic_pair,
                "basic_auth_header": basic_header,
            }
        )
        return result, None
    except Exception as exc:
        logger.error("Failed to create honeypot API key: %s", exc)
        return None, f"Database error while creating API key: {exc}"


def list_api_keys(include_revoked: bool = True) -> list[HoneypotApiKey]:
    """List all Honeypot API keys ordered by creation time descending."""
    assert_api_keys_table()
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT id, key_name, honeypot, basic_username, api_key_prefix,
                   max_age_days, risk_acknowledged, created_by, created_at,
                   expires_at, last_used_at, last_used_ip::text,
                   revoked, revoked_at, revoked_by, revoked_reason
            FROM honeypot_api_keys
            WHERE (%s OR revoked = FALSE)
            ORDER BY created_at DESC, id DESC
            """,
            (bool(include_revoked),),
        )
        rows = cur.fetchall()

    return [
        HoneypotApiKey(
            id=r[0],
            key_name=r[1],
            honeypot=r[2],
            basic_username=r[3],
            api_key_prefix=r[4],
            max_age_days=r[5],
            risk_acknowledged=bool(r[6]),
            created_by=r[7],
            created_at=r[8],
            expires_at=r[9],
            last_used_at=r[10],
            last_used_ip=r[11],
            revoked=bool(r[12]),
            revoked_at=r[13],
            revoked_by=r[14],
            revoked_reason=r[15],
        )
        for r in rows
    ]


def get_rotation_alerts(keys: list[HoneypotApiKey] | None = None) -> dict[str, Any]:
    """Build summary of keys that are expiring soon or expired and need rotation."""
    if keys is None:
        keys = list_api_keys(include_revoked=False)

    expiring_soon: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []

    for k in keys:
        if k.revoked:
            continue
        if k.status == "expired":
            expired.append(k.to_dict())
        elif k.status == "expiring_soon":
            expiring_soon.append(k.to_dict())

    return {
        "expiring_soon_threshold_days": EXPIRING_SOON_DAYS,
        "expiring_soon_count": len(expiring_soon),
        "expired_count": len(expired),
        "needs_rotation_count": len(expiring_soon) + len(expired),
        "expiring_soon_keys": expiring_soon,
        "expired_keys": expired,
    }


def revoke_api_key(
    key_id: int,
    revoked_by: int | None = None,
    reason: str | None = None,
    ip_address: str | None = None,
) -> tuple[bool, str | None]:
    """Revoke an API key immediately."""
    assert_api_keys_table()
    clean_reason = (reason or "Revoked by administrator").strip()[:500]
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT basic_username, honeypot, revoked
            FROM honeypot_api_keys
            WHERE id = %s
            """,
            (key_id,),
        )
        row = cur.fetchone()
        if not row:
            return False, "API key not found"
        basic_username, honeypot, already_revoked = row
        if already_revoked:
            return False, "API key is already revoked"

        cur.execute(
            """
            UPDATE honeypot_api_keys
               SET revoked = TRUE,
                   revoked_at = NOW(),
                   revoked_by = %s,
                   revoked_reason = %s
             WHERE id = %s
            """,
            (revoked_by, clean_reason, key_id),
        )

    log_admin_action(
        admin_user_id=revoked_by,
        action="REVOKE_API_KEY",
        details={
            "key_id": key_id,
            "basic_username": basic_username,
            "honeypot": honeypot,
            "reason": clean_reason,
        },
        ip_address=ip_address,
    )
    return True, None


def authenticate_api_key(
    basic_username: str,
    basic_password: str,
    raw_api_key: str,
    client_ip: str | None = None,
) -> tuple[HoneypotApiKey | None, str | None]:
    """Verify both Basic Auth (`apiaccessN:randompass`) and `raw_api_key`.

    Returns:
        `(HoneypotApiKey, None)` on success, or `(None, error_reason)` on failure.
    """
    if not basic_username or not basic_password or not raw_api_key:
        return None, "Both Basic Auth (apiaccessN:password) and X-API-Key are required"

    key_hash = hash_api_key(raw_api_key.strip())
    uname = basic_username.strip()

    try:
        assert_api_keys_table()
        with db_cursor() as cur:
            cur.execute(
                """
                SELECT id, key_name, honeypot, basic_username, basic_password_hash,
                       basic_salt, api_key_prefix, max_age_days, risk_acknowledged,
                       created_by, created_at, expires_at, last_used_at,
                       last_used_ip::text, revoked, revoked_at, revoked_by, revoked_reason
                FROM honeypot_api_keys
                WHERE api_key_hash = %s AND basic_username = %s
                """,
                (key_hash, uname),
            )
            row = cur.fetchone()
            if not row:
                return None, "Invalid API key or Basic Auth username"

            pw_hash = row[4]
            pw_salt = row[5]
            if not verify_password(basic_password, pw_hash, pw_salt):
                return None, "Invalid Basic Auth password for API key"

            key_obj = HoneypotApiKey(
                id=row[0],
                key_name=row[1],
                honeypot=row[2],
                basic_username=row[3],
                api_key_prefix=row[6],
                max_age_days=row[7],
                risk_acknowledged=bool(row[8]),
                created_by=row[9],
                created_at=row[10],
                expires_at=row[11],
                last_used_at=row[12],
                last_used_ip=row[13],
                revoked=bool(row[14]),
                revoked_at=row[15],
                revoked_by=row[16],
                revoked_reason=row[17],
            )

            if key_obj.revoked:
                return None, "API key has been revoked"

            if key_obj.is_expired:
                return None, "API key has expired and must be rotated"

            # Record usage timestamp and IP
            now = datetime.now(UTC)
            try:
                cur.execute(
                    """
                    UPDATE honeypot_api_keys
                       SET last_used_at = %s,
                           last_used_ip = %s::inet
                     WHERE id = %s
                    """,
                    (now, client_ip if client_ip else None, key_obj.id),
                )
                key_obj.last_used_at = now
                key_obj.last_used_ip = client_ip
            except Exception as exc:
                logger.debug("Could not update last_used_at for API key %s: %s", key_obj.id, exc)

            return key_obj, None
    except Exception as exc:
        logger.error("API key authentication error: %s", exc)
        return None, "Internal authentication error"
