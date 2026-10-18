"""
user_manager.py — User Management Module
=========================================
Handles user CRUD operations, authentication, and role management.

Features:
- User creation with password validation
- User authentication with lockout protection
- Role-based access control (admin/user)
- Password reset functionality
- User listing and management

Requires: psycopg2, auth.py
"""

from __future__ import annotations

import html
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from psycopg2.extras import RealDictCursor

from honeylens.auth.auth import (
    clear_failed_attempts,
    generate_secure_password,
    hash_password,
    log_admin_action,
    record_failed_login,
    validate_password,
    verify_password,
)
from honeylens.auth.ldap_auth import ldap_authenticate, ldap_enabled
from honeylens.database import legacy_get_db

logger = logging.getLogger("user_manager")


# =============================================================================
# User Model
# =============================================================================


class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"


@dataclass
class User:
    """User data model."""

    id: int
    username: str
    name: str
    lastname: str
    email: str
    password_hash: str
    salt: str
    role: UserRole
    created_at: datetime
    updated_at: datetime
    last_login: datetime | None
    is_active: bool
    failed_attempts: int
    locked_until: datetime | None

    @property
    def full_name(self) -> str:
        """Get user's full name."""
        return f"{self.name} {self.lastname}".strip()

    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == UserRole.ADMIN

    @property
    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.locked_until is None:
            return False
        # The timestamp from the database may be naive (column without a timezone) — then we treat it as UTC.
        locked = (
            self.locked_until if self.locked_until.tzinfo else self.locked_until.replace(tzinfo=UTC)
        )
        return datetime.now(UTC) < locked

    def to_dict(self, include_sensitive: bool = False) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {
            "id": self.id,
            "username": self.username,
            "name": self.name,
            "lastname": self.lastname,
            "email": self.email,
            "role": self.role.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "is_active": self.is_active,
            "is_locked": self.is_locked,
        }
        if include_sensitive:
            data["failed_attempts"] = self.failed_attempts
            data["locked_until"] = self.locked_until.isoformat() if self.locked_until else None
        return data

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> User:
        """Create User from database row."""
        return cls(
            id=row["id"],
            username=row["username"],
            name=row["name"] or "",
            lastname=row["lastname"] or "",
            email=row["email"],
            password_hash=row["password_hash"],
            salt=row["salt"],
            role=UserRole(row["role"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_login=row.get("last_login"),
            is_active=row["is_active"],
            failed_attempts=row.get("failed_attempts", 0),
            locked_until=row.get("locked_until"),
        )


# =============================================================================
# Database Connection
# =============================================================================


def get_db():
    """Get database connection."""
    return legacy_get_db()


# =============================================================================
# Input Sanitization (XSS Prevention)
# =============================================================================


# Allowed characters for names (letters, spaces, hyphens, apostrophes)
_NAME_PATTERN = re.compile(
    r"^[a-zA-Z\s\-'\.àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞŸ]{0,128}$"
)

# Allowed characters for username (alphanumeric + underscore)
_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,64}$")

# Basic email pattern
_EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def sanitize_html(value: str) -> str:
    """
    Escape HTML entities to prevent XSS attacks.

    Args:
        value: Input string

    Returns:
        HTML-escaped string
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def validate_name(name: str, field_name: str = "Name") -> tuple[bool, str | None]:
    """
    Validate name field (first name, last name).

    Args:
        name: Name to validate
        field_name: Field name for error messages

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not name:
        return True, None  # Empty names are allowed

    if len(name) > 128:
        return False, f"{field_name} must be 128 characters or less"

    # Check for HTML/script injection attempts
    dangerous_patterns = [
        "<",
        ">",
        "&",
        '"',
        "'",
        "javascript:",
        "onerror",
        "onload",
        "onclick",
        "script",
    ]
    name_lower = name.lower()
    for pattern in dangerous_patterns:
        if pattern in name_lower:
            return False, f"{field_name} contains invalid characters"

    # Validate against allowed pattern
    if not _NAME_PATTERN.match(name):
        return (
            False,
            f"{field_name} contains invalid characters. Only letters, spaces, hyphens, and apostrophes allowed",
        )

    return True, None


def validate_username(username: str) -> tuple[bool, str | None]:
    """
    Validate username.

    Args:
        username: Username to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"

    if len(username) < 3:
        return False, "Username must be at least 3 characters"

    if len(username) > 64:
        return False, "Username must be 64 characters or less"

    if not _USERNAME_PATTERN.match(username):
        return False, "Username can only contain letters, numbers, and underscores"

    return True, None


def validate_email(email: str) -> tuple[bool, str | None]:
    """
    Validate email address.

    Args:
        email: Email to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, "Email is required"

    if len(email) > 256:
        return False, "Email must be 256 characters or less"

    if not _EMAIL_PATTERN.match(email):
        return False, "Invalid email address format"

    return True, None


# =============================================================================
# User CRUD Operations
# =============================================================================


def create_user(
    username: str,
    email: str,
    password: str,
    name: str = "",
    lastname: str = "",
    role: str = "user",
    created_by: int | None = None,
    ip_address: str | None = None,
) -> tuple[User | None, str | None]:
    """
    Create a new user.

    Args:
        username: Unique username
        email: Unique email address
        password: Plain text password (will be hashed)
        name: First name
        lastname: Last name
        role: User role ('admin' or 'user')
        created_by: Admin user ID who created this user
        ip_address: IP address of admin

    Returns:
        Tuple of (User, None) on success or (None, error_message) on failure
    """
    # Validate role
    if role not in ("admin", "user"):
        return None, "Invalid role. Must be 'admin' or 'user'"

    # Validate password
    is_valid, error = validate_password(password)
    if not is_valid:
        return None, error

    # Validate username
    is_valid, error = validate_username(username)
    if not is_valid:
        return None, error

    # Validate email
    is_valid, error = validate_email(email)
    if not is_valid:
        return None, error

    # Validate and sanitize name fields (XSS prevention)
    is_valid, error = validate_name(name, "First name")
    if not is_valid:
        return None, error

    is_valid, error = validate_name(lastname, "Last name")
    if not is_valid:
        return None, error

    # Sanitize all string inputs (defense in depth)
    username = sanitize_html(username.strip())
    email = sanitize_html(email.strip().lower())
    name = sanitize_html(name.strip()) if name else ""
    lastname = sanitize_html(lastname.strip()) if lastname else ""

    # Hash password
    password_hash, salt = hash_password(password)

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Check for existing username/email
        cur.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
        if cur.fetchone():
            conn.close()
            return None, "Username or email already exists"

        # Insert user
        cur.execute(
            """
            INSERT INTO users (username, name, lastname, email, password_hash, salt, role)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """,
            (username, name, lastname, email, password_hash, salt, role),
        )

        row = cur.fetchone()
        conn.commit()

        user = User.from_row(row)

        # Log admin action
        if created_by:
            log_admin_action(
                admin_user_id=created_by,
                action="create_user",
                target_user_id=user.id,
                details={"username": username, "role": role},
                ip_address=ip_address,
            )

        conn.close()
        logger.info("User created: %s (id=%d, role=%s)", username, user.id, role)
        return user, None

    except Exception as e:
        logger.error("Failed to create user: %s", e)
        return None, f"Database error: {e!s}"


def get_user_by_id(user_id: int) -> User | None:
    """Get user by ID."""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        conn.close()

        if row:
            return User.from_row(row)
        return None

    except Exception as e:
        logger.error("Failed to get user by ID: %s", e)
        return None


def get_user_by_username(username: str) -> User | None:
    """Get user by username."""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        conn.close()

        if row:
            return User.from_row(row)
        return None

    except Exception as e:
        logger.error("Failed to get user by username: %s", e)
        return None


def get_user_by_email(email: str) -> User | None:
    """Get user by email."""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        conn.close()

        if row:
            return User.from_row(row)
        return None

    except Exception as e:
        logger.error("Failed to get user by email: %s", e)
        return None


def list_users(include_inactive: bool = False) -> list[User]:
    """List all users."""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        if include_inactive:
            cur.execute("SELECT * FROM users ORDER BY created_at DESC")
        else:
            cur.execute("SELECT * FROM users WHERE is_active = TRUE ORDER BY created_at DESC")

        rows = cur.fetchall()
        conn.close()

        return [User.from_row(row) for row in rows]

    except Exception as e:
        logger.error("Failed to list users: %s", e)
        return []


def update_user(
    user_id: int,
    name: str | None = None,
    lastname: str | None = None,
    email: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    updated_by: int | None = None,
    ip_address: str | None = None,
) -> tuple[User | None, str | None]:
    """
    Update user details.

    Returns:
        Tuple of (User, None) on success or (None, error_message) on failure
    """
    # Validate inputs before database operations
    if name is not None:
        is_valid, error = validate_name(name, "First name")
        if not is_valid:
            return None, error
        name = sanitize_html(name.strip())

    if lastname is not None:
        is_valid, error = validate_name(lastname, "Last name")
        if not is_valid:
            return None, error
        lastname = sanitize_html(lastname.strip())

    if email is not None:
        is_valid, error = validate_email(email)
        if not is_valid:
            return None, error
        email = sanitize_html(email.strip().lower())

    if role is not None and role not in ("admin", "user"):
        return None, "Invalid role. Must be 'admin' or 'user'"

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Build update query dynamically
        updates = []
        values: list[Any] = []

        if name is not None:
            updates.append("name = %s")
            values.append(name)
        if lastname is not None:
            updates.append("lastname = %s")
            values.append(lastname)
        if email is not None:
            # Check email uniqueness
            cur.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, user_id))
            if cur.fetchone():
                conn.close()
                return None, "Email already in use"
            updates.append("email = %s")
            values.append(email)
        if role is not None:
            updates.append("role = %s")
            values.append(role)
        if is_active is not None:
            updates.append("is_active = %s")
            values.append(is_active)

        if not updates:
            conn.close()
            return None, "No fields to update"

        updates.append("updated_at = NOW()")
        values.append(user_id)

        query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s RETURNING *"  # noqa: S608 # nosec B608 — assembled from constants in code, values passed as parameters
        cur.execute(query, values)

        row = cur.fetchone()
        if not row:
            conn.close()
            return None, "User not found"

        conn.commit()
        user = User.from_row(row)

        # Log admin action
        if updated_by:
            log_admin_action(
                admin_user_id=updated_by,
                action="update_user",
                target_user_id=user_id,
                details={
                    "updates": dict(
                        zip(
                            ["name", "lastname", "email", "role", "is_active"],
                            [name, lastname, email, role, is_active],
                            strict=False,
                        )
                    )
                },
                ip_address=ip_address,
            )

        conn.close()
        logger.info("User updated: id=%d", user_id)
        return user, None

    except Exception as e:
        logger.error("Failed to update user: %s", e)
        return None, f"Database error: {e!s}"


def delete_user(
    user_id: int, deleted_by: int | None = None, ip_address: str | None = None
) -> tuple[bool, str | None]:
    """
    Delete a user (soft delete - sets is_active=False).

    Returns:
        Tuple of (success, error_message)
    """
    try:
        # Prevent self-deletion
        if deleted_by == user_id:
            return False, "Cannot delete your own account"

        conn = get_db()
        cur = conn.cursor()

        # Get username for logging
        cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return False, "User not found"

        username = row[0]

        # Soft delete
        cur.execute(
            """
            UPDATE users
            SET is_active = FALSE, updated_at = NOW()
            WHERE id = %s
        """,
            (user_id,),
        )

        conn.commit()

        # Log admin action
        if deleted_by:
            log_admin_action(
                admin_user_id=deleted_by,
                action="delete_user",
                target_user_id=user_id,
                details={"username": username},
                ip_address=ip_address,
            )

        conn.close()
        logger.info("User deleted: %s (id=%d)", username, user_id)
        return True, None

    except Exception as e:
        logger.error("Failed to delete user: %s", e)
        return False, f"Database error: {e!s}"


def reset_password(
    user_id: int,
    new_password: str | None = None,
    reset_by: int | None = None,
    ip_address: str | None = None,
) -> tuple[str | None, str | None]:
    """
    Reset user password.

    Args:
        user_id: User ID
        new_password: New password (generated if not provided)
        reset_by: Admin user ID who reset the password
        ip_address: IP address of admin

    Returns:
        Tuple of (new_password, None) on success or (None, error_message) on failure
    """
    try:
        # Generate password if not provided
        if new_password is None:
            new_password = generate_secure_password(16)
        else:
            # Validate provided password
            is_valid, error = validate_password(new_password)
            if not is_valid:
                return None, error

        # Hash new password
        password_hash, salt = hash_password(new_password)

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            """
            UPDATE users
            SET password_hash = %s, salt = %s,
                failed_attempts = 0, locked_until = NULL,
                updated_at = NOW()
            WHERE id = %s
            RETURNING username
        """,
            (password_hash, salt, user_id),
        )

        row = cur.fetchone()
        if not row:
            conn.close()
            return None, "User not found"

        username = row[0]
        conn.commit()
        conn.close()

        # CRITICAL: Revoke ALL active sessions for this user
        # If password was compromised and changed, attacker must not retain access
        # 0.9 imported `session_manager` by its bare name in try/except ImportError — the import
        # failed, and session invalidation after a password change silently did not work.
        from honeylens.auth.session_manager import revoke_all_user_sessions

        revoked = revoke_all_user_sessions(user_id, reason="password_change")
        if revoked:
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure  # the message contains the word "password", not an actual password
            logger.info("Password reset: revoked %d sessions for %s", revoked, username)

        # Log admin action
        if reset_by:
            log_admin_action(
                admin_user_id=reset_by,
                action="reset_password",
                target_user_id=user_id,
                details={"username": username},
                ip_address=ip_address,
            )

        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure  # the message contains the word "password", not an actual password
        logger.info("Password reset: %s (id=%d)", username, user_id)
        return new_password, None

    except Exception as e:
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure  # the message contains the word "password", not an actual password
        logger.error("Failed to reset password: %s", e)
        return None, f"Database error: {e!s}"


def change_password(
    user_id: int, current_password: str, new_password: str
) -> tuple[bool, str | None]:
    """
    Change user's own password (requires current password).

    Returns:
        Tuple of (success, error_message)
    """
    try:
        # Get user
        user = get_user_by_id(user_id)
        if not user:
            return False, "User not found"

        # Verify current password
        if not verify_password(current_password, user.password_hash, user.salt):
            return False, "Current password is incorrect"

        # Validate new password
        is_valid, error = validate_password(new_password)
        if not is_valid:
            return False, error

        # Check new password is different
        if verify_password(new_password, user.password_hash, user.salt):
            return False, "New password must be different from current password"

        # Hash new password
        password_hash, salt = hash_password(new_password)

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            """
            UPDATE users
            SET password_hash = %s, salt = %s, updated_at = NOW()
            WHERE id = %s
        """,
            (password_hash, salt, user_id),
        )

        conn.commit()
        conn.close()

        # CRITICAL: Revoke ALL active sessions for this user
        from honeylens.auth.session_manager import revoke_all_user_sessions

        revoke_all_user_sessions(user_id, reason="password_change")

        logger.info("Password changed: user_id=%d", user_id)
        return True, None

    except Exception as e:
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure  # the message contains the word "password", not an actual password
        logger.error("Failed to change password: %s", e)
        return False, f"Database error: {e!s}"


# =============================================================================
# Authentication
# =============================================================================


def _safe_username(raw: str) -> str:
    """Derive a valid local username (letters/digits/underscore, 3-64) from an
    AD login, for the mirrored user record."""
    u = re.sub(r"[^a-z0-9_]", "_", (raw or "").strip().lower())
    if len(u) < 3:
        u = (u + "adu")[:3]
    return u[:64]


def _clean_name(s: str) -> str:
    """Reduce an AD name attribute to the WebUI's allowed charset
    (letters/space/hyphen/apostrophe). Empty is allowed by validate_name."""
    return re.sub(r"[^A-Za-z \-']", "", (s or "")).strip()[:64]


def _mirror_ldap_user(info: dict) -> User | None:
    """Upsert an AD-authenticated user into the local `users` table and return
    it, so the session layer (keyed on user_id) works. The role is refreshed
    from AD group membership on every login."""
    email = info["email"]
    role = info["role"]
    existing = get_user_by_email(email)
    if existing:
        if not existing.is_active:
            # Local deactivation must also apply to logins via AD (0.9 skipped this).
            logger.warning("LDAP login refused: local account %s is inactive", existing.username)
            return None
        if existing.role.value != role:
            update_user(existing.id, role=role)
        clear_failed_attempts(existing.id)  # also stamps last_login
        return get_user_by_id(existing.id)
    username = _safe_username(info.get("username") or email.split("@")[0])
    for uname in (
        username,
        _safe_username(username + "_" + __import__("hashlib").sha1(email.encode()).hexdigest()[:6]),
    ):
        user, err = create_user(
            username=uname,
            email=email,
            password=generate_secure_password(24),
            name=_clean_name(info.get("name", "")),
            lastname=_clean_name(info.get("lastname", "")),
            role=role,
        )
        if user:
            logger.info("LDAP: mirrored AD user %s -> local id=%d role=%s", email, user.id, role)
            return user
    logger.error("LDAP: mirror failed for %s: %s", email, err)
    return None


def authenticate_user(username: str, password: str) -> User | None:
    """
    Authenticate user with username and password.

    Handles:
    - AD/LDAP authentication for email/UPN logins (when LDAP_ENABLED)
    - Account lockout checking
    - Failed attempt tracking
    - Password verification

    Returns:
        User object if authenticated, None otherwise
    """
    try:
        # AD/LDAP path: users authenticate by email/UPN (contains '@'). Local
        # accounts (no '@') always take the local path below, so the break-glass
        # admin still works even when AD is unreachable.
        if "@" in username and ldap_enabled():
            info = ldap_authenticate(username, password)
            return _mirror_ldap_user(info) if info else None

        # Get user (local)
        user = get_user_by_username(username)

        if not user:
            # Don't reveal if user exists
            logger.debug("Authentication failed: user not found: %s", username)
            return None

        # Check if account is active
        if not user.is_active:
            logger.warning("Authentication failed: account disabled: %s", username)
            return None

        # Check if account is locked
        if user.is_locked:
            logger.warning("Authentication failed: account locked: %s", username)
            return None

        # Verify password
        if not verify_password(password, user.password_hash, user.salt):
            record_failed_login(user.id)
            # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure  # the message contains the word "password", not an actual password
            logger.warning("Authentication failed: invalid password: %s", username)
            return None

        # Success - clear failed attempts
        clear_failed_attempts(user.id)
        logger.info("Authentication successful: %s", username)

        return user

    except Exception as e:
        logger.error("Authentication error: %s", e)
        return None


# =============================================================================
# Admin Audit Log
# =============================================================================


def get_audit_log(
    limit: int = 100, admin_user_id: int | None = None, action: str | None = None
) -> list[dict[str, Any]]:
    """Get admin audit log entries."""
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        query = """
            SELECT
                a.id, a.action, a.details, a.ip_address, a.timestamp,
                admin.username as admin_username,
                target.username as target_username
            FROM admin_audit_log a
            LEFT JOIN users admin ON a.admin_user_id = admin.id
            LEFT JOIN users target ON a.target_user_id = target.id
            WHERE 1=1
        """
        params: list[Any] = []

        if admin_user_id:
            query += " AND a.admin_user_id = %s"
            params.append(admin_user_id)
        if action:
            query += " AND a.action = %s"
            params.append(action)

        query += " ORDER BY a.timestamp DESC LIMIT %s"
        params.append(limit)

        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    except Exception as e:
        logger.error("Failed to get audit log: %s", e)
        return []


# =============================================================================
# Self-Test
# =============================================================================
