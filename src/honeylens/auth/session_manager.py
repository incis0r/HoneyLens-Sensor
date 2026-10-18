"""
session_manager.py — Server-Side Session Management
====================================================
Secure session management with opaque tokens stored in PostgreSQL.

Security properties:
  - 512-bit cryptographically random tokens (secrets.token_hex(64))
  - Token hashing in DB (SHA-256) — DB dump does not expose usable tokens
  - Dual expiry: absolute TTL + idle timeout (both server-enforced)
  - Instant server-side revocation (logout, password change, admin kill)
  - Concurrent session limit per user
  - No client-side state — cookie contains only the opaque token

Usage:
    from honeylens.auth.session_manager import (
        create_session, validate_session, revoke_session,
        revoke_all_user_sessions, get_active_sessions, cleanup_expired,
    )

    # Create
    token = create_session(user_id=1, ip="10.0.1.5", user_agent="Mozilla/5.0", persistent=False)

    # Validate (returns user dict or None)
    user = validate_session(token)

    # Revoke
    revoke_session(token, reason="logout")
    revoke_all_user_sessions(user_id=1, reason="password_change")

Requires: psycopg2, config.py (DB_CONFIG)
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg2.extras

from honeylens.config import SESSION as _SESSION_CFG
from honeylens.database import legacy_get_db

logger = logging.getLogger("session_manager")

# =============================================================================
# Configuration (overridden by config.py SESSION dict if present)
# =============================================================================

_DEFAULTS = {
    "lifetime_hours": 8,
    "lifetime_remember_hours": 720,  # 30 days
    "idle_timeout_hours": 2,
    "idle_timeout_remember_hours": 72,  # 3 days
    "max_per_user": 5,
    "cleanup_retain_days": 7,
    "cookie_name": "sensor_sid",
    "token_bytes": 64,  # 512 bits
}


# Merge: config overrides defaults
_CFG: dict[str, Any] = dict(_DEFAULTS)
_CFG.update(_SESSION_CFG)

# Public constants
SESSION_LIFETIME_HOURS = _CFG["lifetime_hours"]
SESSION_LIFETIME_REMEMBER_HOURS = _CFG["lifetime_remember_hours"]
SESSION_IDLE_TIMEOUT_HOURS = _CFG["idle_timeout_hours"]
SESSION_IDLE_TIMEOUT_REMEMBER_HOURS = _CFG["idle_timeout_remember_hours"]
MAX_SESSIONS_PER_USER = _CFG["max_per_user"]
CLEANUP_RETAIN_DAYS = _CFG["cleanup_retain_days"]
SESSION_COOKIE_NAME = _CFG["cookie_name"]
TOKEN_BYTES = _CFG["token_bytes"]


# =============================================================================
# Internal helpers
# =============================================================================


def _get_db():
    """Get a PostgreSQL connection."""
    return legacy_get_db()


def _hash_token(raw_token: str) -> str:
    """
    Hash a session token for DB storage using SHA-256.

    Why SHA-256 and not Argon2id:
    - Session tokens have 512 bits of entropy (not human-chosen passwords).
    - Brute-forcing a 512-bit random token is computationally impossible
      regardless of hash speed.
    - SHA-256 is sufficient and fast — no need for memory-hard hashing.
    - If the DB is compromised, the attacker gets SHA-256(token) which cannot
      be reversed to obtain the raw token.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    """Current UTC timestamp (timezone-aware)."""
    return datetime.now(UTC)


# =============================================================================
# Session CRUD
# =============================================================================


def create_session(
    user_id: int,
    ip: str = "",
    user_agent: str = "",
    persistent: bool = False,
) -> str:
    """
    Create a new session for a user.

    Args:
        user_id: Database user ID
        ip: Client IP address (for audit, not for binding)
        user_agent: Client User-Agent (for audit)
        persistent: True for "remember me" (longer TTL)

    Returns:
        Raw session token (to be placed in cookie).
        The DB stores SHA-256(token), never the raw token.
    """
    raw_token = secrets.token_hex(TOKEN_BYTES)
    token_hash = _hash_token(raw_token)

    now = _utcnow()
    if persistent:
        expires = now + timedelta(hours=SESSION_LIFETIME_REMEMBER_HOURS)
    else:
        expires = now + timedelta(hours=SESSION_LIFETIME_HOURS)

    conn = _get_db()
    try:
        cur = conn.cursor()

        # Enforce concurrent session limit — revoke oldest if over limit
        _enforce_session_limit(cur, user_id)

        cur.execute(
            """
            INSERT INTO user_sessions
                (session_hash, user_id, expires_at, last_active_at,
                 ip_address, user_agent, is_persistent)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
            (
                token_hash,
                user_id,
                expires,
                now,
                ip or None,
                (user_agent or "")[:512],  # truncate long UAs
                persistent,
            ),
        )
        conn.commit()

        logger.info("session: created for user_id=%d ip=%s persistent=%s", user_id, ip, persistent)
        return raw_token

    except Exception as e:
        conn.rollback()
        logger.error("session: create failed: %s", e)
        raise
    finally:
        conn.close()


def validate_session(raw_token: str) -> dict[str, Any] | None:
    """
    Validate a session token and return the associated user.

    Checks:
      1. Token hash exists and is not revoked
      2. Absolute expiry (expires_at) has not passed
      3. Idle timeout (last_active_at + idle_limit) has not passed
      4. User is still active (is_active=True)

    On success: updates last_active_at (sliding window) and returns user dict.
    On failure: returns None.

    Returns:
        Dict with user fields: id, username, name, lastname, email, role,
        is_admin, is_active, session_id (DB row id), auth_method="session"
        — or None if invalid.
    """
    if not raw_token or len(raw_token) < 32:
        return None

    token_hash = _hash_token(raw_token)
    now = _utcnow()

    conn = _get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cur.execute(
            """
            SELECT
                s.id AS session_row_id,
                s.user_id,
                s.expires_at,
                s.last_active_at,
                s.is_persistent,
                s.revoked,
                u.username,
                u.name,
                u.lastname,
                u.email,
                u.role,
                u.is_active
            FROM user_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.session_hash = %s
              AND s.revoked = FALSE
            LIMIT 1
        """,
            (token_hash,),
        )

        row = cur.fetchone()
        if not row:
            return None

        # Check absolute expiry
        if row["expires_at"] and now > row["expires_at"]:
            # Auto-revoke expired session
            cur.execute(
                """
                UPDATE user_sessions
                SET revoked = TRUE, revoked_at = %s, revoked_reason = 'expired'
                WHERE session_hash = %s AND revoked = FALSE
            """,
                (now, token_hash),
            )
            conn.commit()
            logger.debug("session: expired for user_id=%d", row["user_id"])
            return None

        # Check idle timeout
        idle_limit_hours = (
            SESSION_IDLE_TIMEOUT_REMEMBER_HOURS
            if row["is_persistent"]
            else SESSION_IDLE_TIMEOUT_HOURS
        )
        if row["last_active_at"]:
            idle_deadline = row["last_active_at"] + timedelta(hours=idle_limit_hours)
            if now > idle_deadline:
                cur.execute(
                    """
                    UPDATE user_sessions
                    SET revoked = TRUE, revoked_at = %s, revoked_reason = 'idle_timeout'
                    WHERE session_hash = %s AND revoked = FALSE
                """,
                    (now, token_hash),
                )
                conn.commit()
                logger.debug("session: idle timeout for user_id=%d", row["user_id"])
                return None

        # Check user is still active
        if not row["is_active"]:
            cur.execute(
                """
                UPDATE user_sessions
                SET revoked = TRUE, revoked_at = %s, revoked_reason = 'user_deactivated'
                WHERE session_hash = %s AND revoked = FALSE
            """,
                (now, token_hash),
            )
            conn.commit()
            return None

        # Session valid — update last_active_at (sliding window)
        cur.execute(
            """
            UPDATE user_sessions SET last_active_at = %s
            WHERE session_hash = %s AND revoked = FALSE
        """,
            (now, token_hash),
        )
        conn.commit()

        return {
            "id": row["user_id"],
            "username": row["username"],
            "name": row.get("name", ""),
            "lastname": row.get("lastname", ""),
            "email": row["email"],
            "role": row["role"],
            "is_admin": row["role"] == "admin",
            "is_active": row["is_active"],
            "session_row_id": row["session_row_id"],
            "auth_method": "session",
        }

    except Exception as e:
        logger.error("session: validate failed: %s", e)
        return None
    finally:
        conn.close()


def revoke_session(raw_token: str, reason: str = "logout") -> bool:
    """
    Revoke a single session by its raw token.

    Args:
        raw_token: The raw session token from the cookie
        reason: Revocation reason (logout, admin_kill, password_change, etc.)

    Returns:
        True if a session was revoked, False if not found.
    """
    if not raw_token:
        return False

    token_hash = _hash_token(raw_token)
    now = _utcnow()

    conn = _get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE user_sessions
            SET revoked = TRUE, revoked_at = %s, revoked_reason = %s
            WHERE session_hash = %s AND revoked = FALSE
        """,
            (now, reason, token_hash),
        )
        affected = cur.rowcount
        conn.commit()

        if affected:
            logger.info("session: revoked (reason=%s)", reason)
        return affected > 0

    except Exception as e:
        conn.rollback()
        logger.error("session: revoke failed: %s", e)
        return False
    finally:
        conn.close()


def revoke_all_user_sessions(user_id: int, reason: str = "password_change") -> int:
    """
    Revoke ALL active sessions for a user.

    Use cases:
      - Password change (critical: kill all sessions immediately)
      - Account deactivation
      - Admin force-logout

    Returns:
        Number of sessions revoked.
    """
    now = _utcnow()
    conn = _get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE user_sessions
            SET revoked = TRUE, revoked_at = %s, revoked_reason = %s
            WHERE user_id = %s AND revoked = FALSE
        """,
            (now, reason, user_id),
        )
        affected = cur.rowcount
        conn.commit()

        if affected:
            logger.info(
                "session: revoked %d sessions for user_id=%d (reason=%s)", affected, user_id, reason
            )
        return affected

    except Exception as e:
        conn.rollback()
        logger.error("session: revoke_all failed for user_id=%d: %s", user_id, e)
        return 0
    finally:
        conn.close()


# =============================================================================
# Session queries
# =============================================================================


def get_active_sessions(user_id: int) -> list[dict[str, Any]]:
    """Get all active (non-revoked, non-expired) sessions for a user."""
    now = _utcnow()
    conn = _get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            """
            SELECT id, user_id, created_at, expires_at, last_active_at,
                   ip_address, user_agent, is_persistent
            FROM user_sessions
            WHERE user_id = %s AND revoked = FALSE AND expires_at > %s
            ORDER BY last_active_at DESC
        """,
            (user_id, now),
        )
        return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.error("session: get_active failed: %s", e)
        return []
    finally:
        conn.close()


def get_all_active_sessions() -> list[dict[str, Any]]:
    """Get all active sessions across all users (for admin dashboard)."""
    now = _utcnow()
    conn = _get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            """
            SELECT s.id, s.user_id, s.created_at, s.expires_at,
                   s.last_active_at, s.ip_address, s.user_agent,
                   s.is_persistent, u.username, u.role
            FROM user_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.revoked = FALSE AND s.expires_at > %s
            ORDER BY s.last_active_at DESC
        """,
            (now,),
        )
        return [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.error("session: get_all_active failed: %s", e)
        return []
    finally:
        conn.close()


def revoke_session_by_id(session_row_id: int, reason: str = "admin_kill") -> bool:
    """Revoke a session by its database row ID (for admin kill)."""
    now = _utcnow()
    conn = _get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE user_sessions
            SET revoked = TRUE, revoked_at = %s, revoked_reason = %s
            WHERE id = %s AND revoked = FALSE
        """,
            (now, reason, session_row_id),
        )
        affected = cur.rowcount
        conn.commit()
        return affected > 0
    except Exception as e:
        conn.rollback()
        logger.error("session: revoke_by_id failed: %s", e)
        return False
    finally:
        conn.close()


# =============================================================================
# Housekeeping
# =============================================================================


def cleanup_expired() -> dict[str, int]:
    """
    Cleanup expired/revoked sessions:
    1. Auto-revoke sessions past absolute expiry
    2. DELETE sessions revoked more than CLEANUP_RETAIN_DAYS ago

    Returns dict with counts: {"auto_revoked": N, "deleted": N}
    """
    now = _utcnow()
    retain_cutoff = now - timedelta(days=CLEANUP_RETAIN_DAYS)

    conn = _get_db()
    try:
        cur = conn.cursor()

        # 1. Auto-revoke expired sessions that weren't caught by validate_session
        cur.execute(
            """
            UPDATE user_sessions
            SET revoked = TRUE, revoked_at = %s, revoked_reason = 'expired'
            WHERE revoked = FALSE AND expires_at < %s
        """,
            (now, now),
        )
        auto_revoked = cur.rowcount

        # 2. Delete old revoked sessions (keep for audit trail for CLEANUP_RETAIN_DAYS)
        cur.execute(
            """
            DELETE FROM user_sessions
            WHERE revoked = TRUE AND revoked_at < %s
        """,
            (retain_cutoff,),
        )
        deleted = cur.rowcount

        conn.commit()

        if auto_revoked or deleted:
            logger.info("session cleanup: auto_revoked=%d, deleted=%d", auto_revoked, deleted)

        return {"auto_revoked": auto_revoked, "deleted": deleted}

    except Exception as e:
        conn.rollback()
        logger.error("session cleanup failed: %s", e)
        return {"auto_revoked": 0, "deleted": 0}
    finally:
        conn.close()


# =============================================================================
# Concurrent session enforcement
# =============================================================================


def _enforce_session_limit(cur, user_id: int) -> None:
    """
    If user has >= MAX_SESSIONS_PER_USER active sessions, revoke the oldest.
    Called inside create_session() transaction.
    """
    now = _utcnow()
    cur.execute(
        """
        SELECT id FROM user_sessions
        WHERE user_id = %s AND revoked = FALSE AND expires_at > %s
        ORDER BY created_at ASC
    """,
        (user_id, now),
    )
    active = cur.fetchall()

    if len(active) >= MAX_SESSIONS_PER_USER:
        # Revoke oldest sessions to make room
        excess = len(active) - MAX_SESSIONS_PER_USER + 1
        for row in active[:excess]:
            sid = row[0] if isinstance(row, (list, tuple)) else row.get("id", row)
            cur.execute(
                """
                UPDATE user_sessions
                SET revoked = TRUE, revoked_at = %s, revoked_reason = 'session_limit'
                WHERE id = %s AND revoked = FALSE
            """,
                (now, sid),
            )
            logger.info(
                "session: revoked oldest session id=%s for user_id=%d (limit)", sid, user_id
            )


# =============================================================================
# Login rate limiting (in-memory, per-process)
# =============================================================================

_login_attempts: dict[str, list[datetime]] = {}
LOGIN_RATE_LIMIT = 5  # max attempts
LOGIN_RATE_WINDOW_SEC = 60  # per window


def check_login_rate_limit(client_ip: str) -> bool:
    """
    Check if client IP has exceeded login rate limit.
    Returns True if rate-limited (should block), False if OK.
    """
    now = _utcnow()
    cutoff = now - timedelta(seconds=LOGIN_RATE_WINDOW_SEC)

    attempts = _login_attempts.get(client_ip, [])
    # Prune old attempts
    attempts = [t for t in attempts if t > cutoff]
    _login_attempts[client_ip] = attempts

    return len(attempts) >= LOGIN_RATE_LIMIT


def record_login_attempt(client_ip: str) -> None:
    """Record a login attempt for rate limiting."""
    now = _utcnow()
    if client_ip not in _login_attempts:
        _login_attempts[client_ip] = []
    _login_attempts[client_ip].append(now)


# =============================================================================
# Self-test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    print("Session Manager — Config:")
    for k, v in sorted(_CFG.items()):
        print(f"  {k}: {v}")
    print("\nActive sessions:")
    for s in get_all_active_sessions():
        print(
            "  user={} ip={} last_active={}".format(
                s.get("username"), s.get("ip_address"), s.get("last_active_at")
            )
        )
    print("\nCleanup:")
    result = cleanup_expired()
    print(f"  {result}")
