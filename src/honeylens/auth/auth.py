"""
auth.py — User Authentication Module
=====================================
Provides secure password hashing using Argon2id (winner of Password Hashing Competition)
with parameters meeting OWASP recommendations.

Features:
- Argon2id password hashing (memory-hard, timing-attack resistant)
- Per-user salt for additional security
- Password strength validation
- Secure password generation
- Account lockout on failed attempts

Requires: argon2-cffi>=21.3.0
"""

from __future__ import annotations

import logging
import re
import secrets

try:
    from argon2 import PasswordHasher, Type
    from argon2.exceptions import InvalidHash, VerifyMismatchError

    _HAS_ARGON2 = True
except ImportError:
    _HAS_ARGON2 = False

from honeylens.database import db_cursor

logger = logging.getLogger("auth")

# =============================================================================
# Configuration
# =============================================================================

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
MIN_PASSWORD_LENGTH = 12

# Argon2id parameters (OWASP recommended)
# - time_cost: 3 iterations
# - memory_cost: 64 MiB
# - parallelism: 4 threads
# - hash_len: 32 bytes (256-bit)
# - salt_len: 16 bytes (128-bit)

if _HAS_ARGON2:
    _hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,  # 64 MiB
        parallelism=4,
        hash_len=32,
        salt_len=16,
        type=Type.ID,  # Argon2id variant
    )
else:
    _hasher = None  # type: ignore[assignment,unused-ignore]  # PBKDF2 fallback; argon2 optional in the mypy env
    logger.warning("argon2-cffi not installed - using fallback PBKDF2")


# =============================================================================
# Password Hashing
# =============================================================================


def generate_salt() -> str:
    """Generate cryptographically secure random salt."""
    return secrets.token_hex(32)  # 256-bit salt


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """
    Hash password using Argon2id (or PBKDF2 fallback).

    Args:
        password: Plain text password
        salt: Optional per-user salt (generated if not provided)

    Returns:
        Tuple of (password_hash, salt)
    """
    if salt is None:
        salt = generate_salt()

    # Combine password with per-user salt
    salted_password = f"{salt}{password}"

    if _HAS_ARGON2:
        password_hash = _hasher.hash(salted_password)
    else:
        # Fallback to PBKDF2 if argon2 not available
        import hashlib

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            salted_password.encode(),
            salt.encode(),
            iterations=310000,  # OWASP 2023 recommendation
        ).hex()

    return password_hash, salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """
    Verify password against stored hash.

    Args:
        password: Plain text password to verify
        password_hash: Stored hash
        salt: Per-user salt

    Returns:
        True if password matches
    """
    try:
        salted_password = f"{salt}{password}"

        if _HAS_ARGON2:
            _hasher.verify(password_hash, salted_password)
            return True
        else:
            # PBKDF2 fallback verification
            import hashlib

            computed = hashlib.pbkdf2_hmac(
                "sha256", salted_password.encode(), salt.encode(), iterations=310000
            ).hex()
            return secrets.compare_digest(computed, password_hash)

    except (VerifyMismatchError, InvalidHash):
        return False
    except Exception as e:
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure  # the message contains the word "password", not an actual password
        logger.error("Password verification error: %s", e)
        return False


def needs_rehash(password_hash: str) -> bool:
    """Check if password hash needs to be upgraded to new parameters."""
    if _HAS_ARGON2:
        try:
            return _hasher.check_needs_rehash(password_hash)
        except Exception:
            return False
    return False


# =============================================================================
# Password Validation
# =============================================================================


def validate_password(password: str) -> tuple[bool, str | None]:
    """
    Validate password meets security requirements.

    Requirements:
    - At least 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character

    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;\'`~]', password):
        return False, "Password must contain at least one special character"

    # Check for common weak patterns
    weak_patterns = [
        r"(.)\1{3,}",  # 4+ repeated characters
        r"(012|123|234|345|456|567|678|789|890)",  # Sequential numbers
        r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",  # Sequential letters
    ]

    for pattern in weak_patterns:
        if re.search(pattern, password.lower()):
            return False, "Password contains weak patterns"

    return True, None


def generate_secure_password(length: int = 16) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Password length (default 16)

    Returns:
        Random password meeting all requirements
    """
    # Ensure at least one of each required character type
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    special = "!@#$%^&*()-_=+"

    # Start with one of each required type
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special),
    ]

    # Fill remaining length with random from all characters
    all_chars = lowercase + uppercase + digits + special
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))

    # Shuffle to randomize positions
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)

    return "".join(password_list)


# =============================================================================
# Account Lockout
# =============================================================================


def record_failed_login(user_id: int) -> None:
    """
    Record failed login attempt and lock account if threshold exceeded.

    Args:
        user_id: User ID
    """
    try:
        with db_cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET failed_attempts = failed_attempts + 1,
                    locked_until = CASE
                        WHEN failed_attempts + 1 >= %s
                        THEN NOW() + INTERVAL '%s minutes'
                        ELSE locked_until
                    END,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING failed_attempts
            """,
                (MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION_MINUTES, user_id),
            )

            result = cur.fetchone()
            if result and result[0] >= MAX_FAILED_ATTEMPTS:
                logger.warning("Account locked due to failed attempts: user_id=%d", user_id)
    except Exception as e:
        logger.error("Failed to record login failure: %s", e)


def clear_failed_attempts(user_id: int) -> None:
    """
    Clear failed login attempts on successful authentication.

    Args:
        user_id: User ID
    """
    try:
        with db_cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET failed_attempts = 0,
                    locked_until = NULL,
                    last_login = NOW(),
                    updated_at = NOW()
                WHERE id = %s
            """,
                (user_id,),
            )
    except Exception as e:
        logger.error("Failed to clear login failures: %s", e)


def log_admin_action(
    admin_user_id: int,
    action: str,
    target_user_id: int | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """
    Log admin action to audit trail.

    Args:
        admin_user_id: ID of admin performing action
        action: Action type (create_user, delete_user, reset_password, etc.)
        target_user_id: ID of user being acted upon
        details: Additional action details
        ip_address: IP address of admin
    """
    try:
        import json

        with db_cursor() as cur:
            cur.execute(
                """
                INSERT INTO admin_audit_log
                (admin_user_id, action, target_user_id, details, ip_address)
                VALUES (%s, %s, %s, %s, %s)
            """,
                (
                    admin_user_id,
                    action,
                    target_user_id,
                    json.dumps(details) if details else None,
                    ip_address,
                ),
            )

    except Exception as e:
        logger.error("Failed to log admin action: %s", e)


# =============================================================================
# Self-Test
# =============================================================================
