#!/usr/bin/env python3
"""
setup_admin.py — Create Initial Admin User
===========================================
Interactive script to create the first admin user for the sensor system.

Usage:
    python setup_admin.py                    # Interactive mode
    python setup_admin.py --username admin --email admin@example.com  # With args
    python setup_admin.py --generate         # Generate random password

Requires: auth.py, user_manager.py, psycopg2
"""

from __future__ import annotations

import argparse
import getpass
import sys

# Add parent directory to path
from honeylens.database import legacy_get_db

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def ok(msg):
    print(f"  {GREEN}[OK]{RESET}    {msg}")


def fail(msg):
    print(f"  {RED}[FAIL]{RESET}  {msg}")


def warn(msg):
    print(f"  {YELLOW}[WARN]{RESET}  {msg}")


def info(msg):
    print(f"  {CYAN}[INFO]{RESET}  {msg}")


def check_tables_exist() -> bool:
    """Check if users table exists."""
    try:
        conn = legacy_get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT 1 FROM information_schema.tables
            WHERE table_name = 'users'
        """)
        exists = cur.fetchone() is not None
        conn.close()
        return exists
    except Exception as e:
        fail(f"Database error: {e}")
        return False


def check_admin_exists() -> bool:
    """Check if any admin user already exists."""
    try:
        conn = legacy_get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        count = cur.fetchone()[0]
        conn.close()
        return count > 0
    except Exception:
        return False


def create_admin_interactive():
    """Create admin user interactively."""
    from honeylens.auth.auth import generate_secure_password, validate_password
    from honeylens.auth.user_manager import create_user

    print()
    print(f"{BOLD}Create Admin User{RESET}")
    print("=" * 40)

    # Get username
    while True:
        username = input("\nUsername: ").strip()
        if len(username) >= 3:
            break
        warn("Username must be at least 3 characters")

    # Get name
    name = input("First name: ").strip() or "System"
    lastname = input("Last name: ").strip() or "Admin"

    # Get email
    while True:
        email = input("Email: ").strip()
        if "@" in email and "." in email:
            break
        warn("Please enter a valid email address")

    # Get password
    while True:
        print()
        print("Password requirements:")
        print("  - At least 12 characters")
        print("  - At least one uppercase letter")
        print("  - At least one lowercase letter")
        print("  - At least one digit")
        print("  - At least one special character")
        print()

        generate = input("Generate secure password? [y/N]: ").strip().lower()

        if generate == "y":
            password = generate_secure_password(16)
            print(f"\n  Generated password: {BOLD}{password}{RESET}")
            print("  (Save this password - it will not be shown again)")
            confirm = input("\n  Use this password? [Y/n]: ").strip().lower()
            if confirm != "n":
                break
        else:
            password = getpass.getpass("Password: ")
            confirm = getpass.getpass("Confirm password: ")

            if password != confirm:
                warn("Passwords don't match")
                continue

            is_valid, error = validate_password(password)
            if not is_valid:
                warn(error)
                continue
            break

    # Create user
    print()
    info("Creating admin user...")

    user, error = create_user(
        username=username,
        email=email,
        password=password,
        name=name,
        lastname=lastname,
        role="admin",
    )

    if user:
        ok(f"Admin user '{username}' created successfully!")
        print()
        print(f"  Username: {BOLD}{username}{RESET}")
        print(f"  Email:    {email}")
        print("  Role:     admin")
        print()
        return True
    else:
        fail(f"Failed to create admin user: {error}")
        return False


def create_admin_args(
    username: str,
    email: str,
    password: str | None = None,
    name: str = "System",
    lastname: str = "Admin",
):
    """Create admin user with provided arguments."""
    from honeylens.auth.auth import generate_secure_password, validate_password
    from honeylens.auth.user_manager import create_user

    # Generate password if not provided
    if password is None:
        password = generate_secure_password(16)
        print(f"Generated password: {password}")
    else:
        is_valid, error = validate_password(password)
        if not is_valid:
            fail(error)
            return False

    user, error = create_user(
        username=username,
        email=email,
        password=password,
        name=name,
        lastname=lastname,
        role="admin",
    )

    if user:
        ok(f"Admin user '{username}' created!")
        return True
    else:
        fail(f"Failed: {error}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Create initial admin user for the sensor system")
    parser.add_argument("--username", help="Admin username")
    parser.add_argument("--email", help="Admin email")
    parser.add_argument("--password", help="Admin password (or use --generate)")
    parser.add_argument("--name", default="System", help="First name")
    parser.add_argument("--lastname", default="Admin", help="Last name")
    parser.add_argument("--generate", action="store_true", help="Generate random password")
    parser.add_argument("--force", action="store_true", help="Create even if admin already exists")

    args = parser.parse_args()

    print()
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  Sensor System — Admin User Setup{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print()

    # Check if tables exist
    info("Checking database...")
    if not check_tables_exist():
        fail("Users table does not exist!")
        print()
        print("  Run setup_db.py first to create the database tables:")
        print("    python setup_db.py")
        print()
        return 1

    ok("Database tables exist")

    # Check if admin already exists
    if check_admin_exists() and not args.force:
        warn("An admin user already exists")
        print()
        print("  Use --force to create another admin user")
        print()
        return 0

    # Create admin user
    if args.username and args.email:
        # Non-interactive mode
        password = args.password
        if args.generate:
            password = None  # Will be generated

        success = create_admin_args(
            username=args.username,
            email=args.email,
            password=password,
            name=args.name,
            lastname=args.lastname,
        )
    else:
        # Interactive mode
        success = create_admin_interactive()

    print()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
