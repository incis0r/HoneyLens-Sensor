#!/usr/bin/env python3
"""
patch_k8s_deception_rules.py
============================
Adds the 4 K8s deception / honeytoken rules to an existing attack_classifier.py.

Safe to run multiple times — all three patches are idempotent (skipped if already present).

Usage:
    python patch_k8s_deception_rules.py [path/to/attack_classifier.py]

Default path: attack_classifier.py in the current directory.

What it patches (3 locations):
    1. RULE_SEVERITY_OVERRIDE dict  — 4 new entries
    2. _add() block                 — 4 new K8S_ATTACK registrations after k8s_cve_2021_25741
    3. _detect_k8s_attack()         — 4 new detection blocks before the final `return hits`

After patching, restarts the sensor-api service automatically if systemctl is available.
"""

import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Target file
# ─────────────────────────────────────────────────────────────────────────────

TARGET = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("attack_classifier.py")


def die(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


if not TARGET.exists():
    die(f"{TARGET} not found")

# ─────────────────────────────────────────────────────────────────────────────
# Patch 1 — RULE_SEVERITY_OVERRIDE: add 4 entries before the closing }
# ─────────────────────────────────────────────────────────────────────────────

PATCH1_GUARD = '"k8s_honeytoken_reuse"'

PATCH1_ANCHOR = '"smtp_ehlo": "info",\n}'

PATCH1_NEW = """"smtp_ehlo": "info",

    # K8s deception / honeytoken — added by patch_k8s_deception_rules.py
    "k8s_honeytoken_reuse": "critical",   # Confirmed attacker — zero FP
    "k8s_token_request": "high",
    "k8s_secret_read": "high",
    "k8s_serviceaccount_enum": "medium",
}"""


# ─────────────────────────────────────────────────────────────────────────────
# Patch 2 — _add() registrations: insert after k8s_cve_2021_25741 block
# ─────────────────────────────────────────────────────────────────────────────

PATCH2_GUARD = '_add("K8S_ATTACK", "k8s_serviceaccount_enum"'

PATCH2_ANCHOR = '_add("K8S_ATTACK", "k8s_cve_2021_25741",\n     r"CVE.?2021.?25741", re.IGNORECASE)'

PATCH2_APPEND = """

# Deception / honeytoken detection rules — added by patch_k8s_deception_rules.py
_add("K8S_ATTACK", "k8s_serviceaccount_enum",
     r"/api/v1/(namespaces/[^/]+/)?serviceaccounts", re.IGNORECASE)
_add("K8S_ATTACK", "k8s_token_request",
     r"/api/v1/namespaces/[^/]+/serviceaccounts/[^/]+/token", re.IGNORECASE)
_add("K8S_ATTACK", "k8s_secret_read",
     r"/api/v1/namespaces/[^/]+/secrets/[^/]+$", re.IGNORECASE)
# k8s_honeytoken_reuse is injected directly by the honeypot with attacker_confirmed=True
# and does not rely on pattern matching — listed here for severity reference only.
_add("K8S_ATTACK", "k8s_honeytoken_reuse",
     r"__honeytoken_reuse_sentinel__", re.IGNORECASE)"""


# ─────────────────────────────────────────────────────────────────────────────
# Patch 3 — _detect_k8s_attack(): insert 4 detection blocks before `return hits`
# ─────────────────────────────────────────────────────────────────────────────

PATCH3_GUARD = 'injected_rule == "k8s_honeytoken_reuse"'

# Anchor: the last two lines before return hits
PATCH3_ANCHOR = (
    "    # Kubernetes Dashboard (port 30000)\n"
    "    if dst_port == 30000:\n"
    '        hits.append(("K8S_ATTACK", "k8s_dashboard_access",\n'
    '                    "Kubernetes Dashboard access"))\n'
    "    \n"
    "    return hits"
)

PATCH3_NEW = (
    "    # Kubernetes Dashboard (port 30000)\n"
    "    if dst_port == 30000:\n"
    '        hits.append(("K8S_ATTACK", "k8s_dashboard_access",\n'
    '                    "Kubernetes Dashboard access"))\n'
    "\n"
    "    # ── Deception / honeytoken detection — added by patch_k8s_deception_rules.py ──\n"
    "\n"
    "    # Honeytoken reuse (injected by honeypot with rule_name field set)\n"
    '    injected_rule = metadata.get("rule_name", "") if metadata else ""\n'
    '    if injected_rule == "k8s_honeytoken_reuse":\n'
    '        hits.append(("K8S_ATTACK", "k8s_honeytoken_reuse",\n'
    '                    "CRITICAL: Bearer token reuse from honeytoken — confirmed attacker"))\n'
    "\n"
    "    # ServiceAccount enumeration\n"
    '    if "/serviceaccounts" in payload_lower and "/api/v1" in payload_lower:\n'
    "        if dst_port in (6443, 8001, 8080):\n"
    '            hits.append(("K8S_ATTACK", "k8s_serviceaccount_enum",\n'
    '                        "Kubernetes ServiceAccount enumeration"))\n'
    "\n"
    "    # TokenRequest API\n"
    '    if "/serviceaccounts/" in payload_lower and payload_lower.endswith("/token"):\n'
    "        if dst_port in (6443, 8001, 8080):\n"
    '            hits.append(("K8S_ATTACK", "k8s_token_request",\n'
    '                        "Kubernetes TokenRequest API — service account token theft attempt"))\n'
    "\n"
    "    # Individual secret read\n"
    '    if "/secrets/" in payload_lower and "/namespaces/" in payload_lower:\n'
    "        if dst_port in (6443, 8001, 8080):\n"
    '            hits.append(("K8S_ATTACK", "k8s_secret_read",\n'
    '                        "Kubernetes individual secret read — potential credential theft"))\n'
    "\n"
    "    return hits"
)


# ─────────────────────────────────────────────────────────────────────────────
# Apply patches
# ─────────────────────────────────────────────────────────────────────────────


def apply(src: str, guard: str, anchor: str, replacement: str, label: str) -> tuple[str, bool]:
    if guard in src:
        print(f"  SKIP  {label} (already present)")
        return src, False
    if anchor not in src:
        die(
            f"{label}: anchor text not found in {TARGET}.\n"
            f"  Looking for: {anchor[:80]!r}...\n"
            f"  The file may already be patched differently or be an unexpected version."
        )
    patched = src.replace(anchor, replacement, 1)
    print(f"  APPLY {label}")
    return patched, True


def main():
    src = TARGET.read_text(encoding="utf-8")
    original_lines = src.count("\n") + 1

    # Backup
    backup = TARGET.with_suffix(f".py.bak_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}")
    shutil.copy2(TARGET, backup)
    print(f"\nBacked up {TARGET.name} → {backup.name}")
    print(f"Original: {original_lines} lines\n")

    changed_count = 0
    src, c = apply(
        src, PATCH1_GUARD, PATCH1_ANCHOR, PATCH1_NEW, "Patch 1 — RULE_SEVERITY_OVERRIDE entries"
    )
    changed_count += c

    src, c = apply(
        src,
        PATCH2_GUARD,
        PATCH2_ANCHOR,
        PATCH2_ANCHOR + PATCH2_APPEND,
        "Patch 2 — _add() registrations",
    )
    changed_count += c

    src, c = apply(
        src,
        PATCH3_GUARD,
        PATCH3_ANCHOR,
        PATCH3_NEW,
        "Patch 3 — _detect_k8s_attack() detection blocks",
    )
    changed_count += c

    if changed_count == 0:
        print("\nAll patches already applied — nothing to do.")
        return

    # Syntax check before writing
    try:
        compile(src, str(TARGET), "exec")
    except SyntaxError as e:
        die(f"Syntax error after patching — aborting, original unchanged.\n  {e}")

    TARGET.write_text(src, encoding="utf-8")
    new_lines = src.count("\n") + 1
    print(
        f"\nWrote {TARGET.name}: {original_lines} → {new_lines} lines "
        f"(+{new_lines - original_lines})"
    )

    # Quick self-verification
    print("\nVerifying patched file...")
    for rule, _expected_sev in [
        ("k8s_honeytoken_reuse", "critical"),
        ("k8s_token_request", "high"),
        ("k8s_secret_read", "high"),
        ("k8s_serviceaccount_enum", "medium"),
    ]:
        if f'"{rule}"' in src:
            print(f"  OK  {rule}")
        else:
            print(f"  !! MISSING {rule}")

    # Restart sensor-api if systemctl is available
    print()
    if shutil.which("systemctl"):
        svc = "sensor-api"
        print(f"Restarting {svc}...")
        result = subprocess.run(["systemctl", "restart", svc], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  OK  {svc} restarted")
        else:
            print(f"  WARN  systemctl restart {svc} returned {result.returncode}")
            if result.stderr:
                print(f"       {result.stderr.strip()}")
            print(f"  Run manually: systemctl restart {svc}")
    else:
        print("systemctl not found — restart sensor-api manually:")
        print("  systemctl restart sensor-api")

    print(
        "\nDone. Run the test suite again to verify:\n"
        "  python test_k8s_honeypot.py --host <HOST> "
        "--api-url https://<HOST>:8443 --filter 'B0[0-6]'"
    )


if __name__ == "__main__":
    main()
