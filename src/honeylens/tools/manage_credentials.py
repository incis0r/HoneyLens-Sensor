#!/usr/bin/env python3
"""
tools/manage_credentials.py — Credential Vault CLI
====================================================
Manage OSINT API keys stored in the encrypted credential vault.

Usage:
    python -m tools.manage_credentials list
    python -m tools.manage_credentials add abuseipdb YOUR_API_KEY
    python -m tools.manage_credentials add virustotal YOUR_KEY --rate-limit 4
    python -m tools.manage_credentials test abuseipdb
    python -m tools.manage_credentials deactivate abuseipdb
    python -m tools.manage_credentials export-env
"""

from __future__ import annotations

import argparse
import sys


def cmd_list(args):
    from honeylens.intelligence.credential_vault import get_vault

    vault = get_vault()
    providers = vault.list_providers()
    if not providers:
        print("  No credentials stored in vault.")
        print("  Add with: python -m tools.manage_credentials add <provider> <key>")
        return 0
    print()
    print(
        "  %-20s %-8s %-6s %-20s %-10s %s"
        % ("Provider", "Active", "RPM", "Last Used", "Usage", "Notes")
    )
    print("  " + "-" * 80)
    for p in providers:
        active = "YES" if p["is_active"] else "no"
        rpm = str(p["rate_limit_rpm"] or "-")
        last = str(p["last_used"] or "never")[:19]
        usage = str(p["usage_count"])
        notes = (p["notes"] or "")[:30]
        print("  %-20s %-8s %-6s %-20s %-10s %s" % (p["provider"], active, rpm, last, usage, notes))
    print()
    return 0


def cmd_add(args):
    from honeylens.intelligence.credential_vault import get_vault

    vault = get_vault()
    if not vault.enabled:
        print("  ERROR: Vault not enabled. Set VAULT_MASTER_KEY in .env")
        return 1
    ok = vault.store_key(
        args.provider,
        args.key,
        rate_limit_rpm=args.rate_limit,
        notes=args.notes,
    )
    if ok:
        print("  Stored key for '%s'" % args.provider)
        return 0
    else:
        print("  ERROR: Failed to store key")
        return 1


def cmd_test(args):
    from honeylens.intelligence.credential_vault import get_vault

    vault = get_vault()
    key = vault.get_key(args.provider)
    if key:
        masked = key[:4] + "***" + key[-4:] if len(key) > 8 else "***"
        print("  %s: %s (length=%d)" % (args.provider, masked, len(key)))
        return 0
    else:
        print("  %s: NOT FOUND (not in vault or .env)" % args.provider)
        return 1


def cmd_deactivate(args):
    from honeylens.intelligence.credential_vault import get_vault

    vault = get_vault()
    ok = vault.deactivate_key(args.provider)
    if ok:
        print("  Deactivated '%s'" % args.provider)
    else:
        print("  ERROR: Failed to deactivate")
    return 0 if ok else 1


def cmd_export_env(args):
    """Print current vault keys as .env variable format (for backup)."""
    from honeylens.intelligence.credential_vault import get_vault

    vault = get_vault()
    if not vault.enabled:
        print("# Vault not enabled")
        return 1
    for p in vault.list_providers():
        if p["is_active"]:
            key = vault.get_key(p["provider"])
            env_name = "OSINT_%s_KEY" % p["provider"].upper()
            print("%s=%s" % (env_name, key))
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Manage OSINT API keys in the credential vault",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Command")

    sub.add_parser("list", help="List all vault entries")

    p_add = sub.add_parser("add", help="Add or update a provider key")
    p_add.add_argument("provider", help="Provider name (e.g. abuseipdb)")
    p_add.add_argument("key", help="API key")
    p_add.add_argument("--rate-limit", type=int, default=None, help="Rate limit (requests/minute)")
    p_add.add_argument("--notes", default=None, help="Optional notes")

    p_test = sub.add_parser("test", help="Test key retrieval for a provider")
    p_test.add_argument("provider", help="Provider name")

    p_deact = sub.add_parser("deactivate", help="Deactivate a provider key")
    p_deact.add_argument("provider", help="Provider name")

    sub.add_parser("export-env", help="Export vault keys as .env format")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    handlers = {
        "list": cmd_list,
        "add": cmd_add,
        "test": cmd_test,
        "deactivate": cmd_deactivate,
        "export-env": cmd_export_env,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
