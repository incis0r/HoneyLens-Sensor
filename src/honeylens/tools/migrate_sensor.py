#!/usr/bin/env python3
"""
migrate_sensor.py — sensor migrator 0.9 -> 1.0 (Phase 5, skeleton)
=================================================================
**In-place** migration (in-place upgrade): the fleet already runs on these hosts, so
the migrator does not move data between machines — it changes the shape of the
installation alongside live data. Design and rationale: ``docs/decision-migrator.md``.

What this skeleton actually does (under ``--apply``):

* **copies honeypot identities** from the flat 0.9 paths into the 1.0 identity volumes
  (the core of the migration — a changed serial number or certificate fingerprint is a
  ready-made honeypot fingerprint, so we copy bit for bit and verify with a SHA-256
  checksum rather than regenerating).
  Source directories honor the overrides from the 0.9 ``.env`` (``TLS_CERT_DIR``,
  ``WAGO_IDENTITY_DIR``, ``PANOS_DATA_DIR``) — otherwise a honeypot with a non-standard
  path would generate a fresh identity on first start;
* **translates the ``.env``** 0.9 -> 1.0: carries secrets 1:1, forces ``API_PORT=60443``,
  adds new variables, skips honeypot port variables (those come from the manifest) and
  **reports** every decision instead of deleting silently.

What it delegates to existing tools (prints the commands, does not run them):

* schema migration -> ``honeylens-migrate`` (idempotent migrations 0001-0008);
* quadlet generation -> ``honeylens-hp --quadlets``.

What is **out of scope for the skeleton** (to be finished once 1.0 is stable): stopping
the live fleet, switching the systemd units to rootless, and rollback. These steps are only
printed as a plan; the migrator does not perform them. The old units must be stopped
MANUALLY before ``--apply`` — copying an identity while a live 0.9 honeypot is writing to it
would yield an inconsistent file that the SHA-256 verification (which reads the source after
the copy) would not catch.

Usage:
    honeylens-migrate-sensor                 # plan (dry-run) — changes nothing
    honeylens-migrate-sensor --apply         # copies identities and writes .env
    honeylens-migrate-sensor --old-root /opt/sensor --state-dir /var/lib/honeylens
    honeylens-migrate-sensor --apply --force # overwrites existing identity files
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from honeylens.honeypots.manifest import HONEYPOTS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migrate_sensor")

DEFAULT_OLD_ROOT = Path("/opt/sensor")
DEFAULT_STATE_DIR = Path("/var/lib/honeylens")
DEFAULT_NEW_ENV = Path("/opt/honeylens/.env")

# ---------------------------------------------------------------------------
# 1. Honeypot identities — the core of the migration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityMove:
    """Where 0.9 kept a given volume's identity and what we migrate from it.

    ``base`` is the source directory (default, relative to ``--old-root``); ``base_env`` is
    the 0.9 ``.env`` variable that overrides this directory on a given host — we honor it,
    because the operator may have moved the certificates or device data elsewhere. Empty
    ``filenames`` means "the whole directory" (WAGO, PAN-OS: serial, host key, templates);
    a list of names — specific files (certs) copied flat into the volume.
    """

    volume: str  # 1.0 identity volume: <state>/identity/<volume>
    base: str  # source directory relative to old_root (default)
    base_env: str  # 0.9 .env variable overriding `base` (absolute or relative to old_root)
    filenames: tuple[str, ...] = ()  # specific files in `base`; empty = whole directory
    note: str = ""

    @property
    def is_tree(self) -> bool:
        return not self.filenames


# Order as in the decision table. The `honeypot` volume is a monolith (TLS_CERT_DIR),
# `paloalto` is shared by PAN-OS HTTPS and SSH (one device).
# Per-file overrides (LLM_TLS_CERT, FORTIGATE_TLS_CERT, HP_NGINX_CERT) are rarer and
# deliberately unsupported — we honor directory overrides, which covers the typical case
# "the operator moved the whole certs/ or data/".
IDENTITY_MOVES: tuple[IdentityMove, ...] = (
    IdentityMove(
        "nginx", base="certs", base_env="TLS_CERT_DIR", filenames=("nginx.crt", "nginx.key")
    ),
    IdentityMove("llm", base="certs", base_env="TLS_CERT_DIR", filenames=("llm.crt", "llm.key")),
    IdentityMove(
        "fortigate",
        base="certs",
        base_env="TLS_CERT_DIR",
        filenames=("fortigate.crt", "fortigate.key"),
    ),
    IdentityMove(
        "honeypot",
        base="certs",
        base_env="TLS_CERT_DIR",
        filenames=("honey.crt", "honey.key"),
        note="monolith: TLS_CERT_DIR",
    ),
    IdentityMove("wago", base="data/wago", base_env="WAGO_IDENTITY_DIR"),
    IdentityMove(
        "paloalto",
        base="data/paloalto",
        base_env="PANOS_DATA_DIR",
        note="PAN-OS HTTPS+SSH: shared serial and host key",
    ),
)

# Identity volumes native to 1.0: honeypots that did not exist in 0.9, so there is nothing
# to migrate. Their identity (a self-signed certificate) is generated on first start from
# the manifest `certs` field, exactly as on a clean install — so the migrator deliberately
# has no move for them. The parity test allows exactly this gap.
NATIVE_1_0_IDENTITIES: frozenset[str] = frozenset({"netscaler", "sharepoint"})


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class CopyItem:
    """A single file to copy and its status after planning / execution."""

    src: Path
    dst: Path
    # copy | exists | missing-source | irregular | verified | mismatch
    status: str


def _source_base(move: IdentityMove, old_root: Path, overrides: dict[str, str]) -> Path:
    """Identity source directory: override from the 0.9 .env, otherwise default relative to old_root."""
    override = overrides.get(move.base_env, "").strip()
    if override:
        p = Path(override)
        return p if p.is_absolute() else old_root / p
    return old_root / move.base


def _classify(src: Path, dst: Path, force: bool) -> CopyItem:
    """Status of a single source file without touching the disk.

    ``irregular`` is an entry that exists but is not a regular file (broken symlink,
    socket, device) — we show it instead of silently skipping, because that is exactly
    how an identity disappears unnoticed.
    """
    if src.is_symlink() and not src.exists():
        return CopyItem(src, dst, "irregular")  # broken symlink
    if not src.exists():
        return CopyItem(src, dst, "missing-source")
    if not src.is_file():
        return CopyItem(src, dst, "irregular")  # directory symlink, socket, device
    if dst.exists() and not force:
        return CopyItem(src, dst, "exists")
    return CopyItem(src, dst, "copy")


def plan_identity(
    old_root: Path, state_dir: Path, force: bool, overrides: dict[str, str] | None = None
) -> list[CopyItem]:
    """What we will copy from the 0.9 identities into the 1.0 volumes, without disk changes."""
    overrides = overrides or {}
    items: list[CopyItem] = []
    for move in IDENTITY_MOVES:
        target_root = state_dir / "identity" / move.volume
        base = _source_base(move, old_root, overrides)
        if move.is_tree:
            if not base.is_dir():
                items.append(CopyItem(base, target_root, "missing-source"))
                continue
            # Every non-directory entry — including irregular ones — goes into the plan.
            entries = [p for p in sorted(base.rglob("*")) if not p.is_dir()]
            if not entries:
                items.append(CopyItem(base, target_root, "missing-source"))
                continue
            for src in entries:
                items.append(_classify(src, target_root / src.relative_to(base), force))
        else:
            for name in move.filenames:
                items.append(_classify(base / name, target_root / name, force))
    return items


def apply_identity(items: list[CopyItem], force: bool) -> list[CopyItem]:
    """Copies and verifies with a SHA-256 checksum. Returns the list with updated status."""
    for item in items:
        if item.status == "missing-source":
            logger.warning("source missing, skipping: %s", item.src)
            continue
        if item.status == "irregular":
            logger.error("entry is not a regular file, NOT copying: %s", item.src)
            continue
        if item.status == "exists":
            logger.info("target exists (no --force, skipping): %s", item.dst)
            continue
        item.dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item.src, item.dst)
        if _sha256(item.src) == _sha256(item.dst):
            item.status = "verified"
            logger.info("copied and verified: %s -> %s", item.src, item.dst)
        else:
            item.status = "mismatch"
            logger.error("checksum mismatch after copy: %s", item.dst)
    return items


# ---------------------------------------------------------------------------
# 2. .env translation
# ---------------------------------------------------------------------------

# Forced values: the 1.0 WebUI/API listens on 60443 (like the honeypot SSH — a global decision).
FORCED: dict[str, str] = {"API_PORT": "60443"}

# Variables 0.9 did not have; we add them with a default value for the operator to review.
# BACKUP_PASSWORD is a secret — it stays empty and is flagged to be filled in.
NEW_KEYS: dict[str, str] = {
    "WEBUI_NEW_SHELL": "true",
    "LDAP_ALLOW_INSECURE_TLS": "false",
    "DB_ARCHIVE_DIR": "/var/lib/honeylens/archive",
    "DB_ARCHIVE_DAYS": "30",
    "DB_ARCHIVE_EXPORT": "false",
    "DB_ARCHIVE_CLEANUP": "true",
    "BACKUP_PASSWORD": "",
}

# The full surface of 1.0 variables (from .env.example). A key outside this set and outside
# the manifest port variables is carried over, but flagged for review. The
# test_migrate_sensor test guards that this set does not drift from .env.example.
KNOWN_KEYS: frozenset[str] = frozenset(
    {
        "HONEYLENS_ENV_FILE",
        "HONEYLENS_STAMP_DIR",
        "INTERFACE",
        "SENSOR_HOME",
        "SENSOR_HOSTNAME",
        "SENSOR_INTERFACES",
        "SENSOR_SSH_PORT",
        "DB_CONNECT_TIMEOUT",
        "DB_HOST",
        "DB_NAME",
        "DB_PASSWORD",
        "DB_POOL_MAX",
        "DB_POOL_MIN",
        "DB_PORT",
        "DB_USER",
        "API_AUTH_PASSWORD",
        "API_AUTH_USERNAME",
        "API_HOST",
        "API_PCAP_DIR",
        "API_PORT",
        "API_TLS_PORT",
        "TLS_CERT_DIR",
        "TLS_CERT_FILE",
        "TLS_EC_CURVE",
        "TLS_KEY_FILE",
        "TLS_KEY_TYPE",
        "TLS_MIN_VERSION",
        "TLS_RSA_BITS",
        "DECEPTION_ENABLED",
        "DECEPTION_INTERFACE",
        "EBPF_CHECK_STRICT",
        "EBPF_CHECK_TIMEOUT",
        "EBPF_DISSECTION_RECONCILE_SEC",
        "EBPF_FULL_DISSECTION_ENABLED",
        "EBPF_LOG_FILE",
        "EBPF_PERF_BUFFER_PAGES",
        "EVENTS_JSON",
        "PCAP_DIR",
        "IGNORE_DST_PORT_ABOVE",
        "IGNORE_LOCAL_SOURCES",
        "IGNORE_SRC_HOST_PORTS",
        "IGNORE_SRC_PORT_ABOVE",
        "LLM_HONEYPOT_PORT",
        "DASHBOARD_EXCLUDE_SUBNETS",
        "FORTIGATE_BUILD",
        "FORTIGATE_ENABLED",
        "FORTIGATE_HOSTNAME",
        "FORTIGATE_LISTEN_HOST",
        "FORTIGATE_LOG_FILE",
        "FORTIGATE_MODEL",
        "FORTIGATE_PORTS",
        "FORTIGATE_SERIAL",
        "FORTIGATE_TLS_CERT",
        "FORTIGATE_TLS_KEY",
        "FORTIGATE_VERSION",
        "HONEYPOTNG_GLOB",
        "HONEYPOTNG_LOG_DIR",
        "HONEYWEB_HOST",
        "HONEYWEB_LOG_DIR",
        "HONEYWEB_PORT",
        "HONEYWEB_TLS_PORT",
        # The PAN-OS decoy's log paths. Carried through a migration because the ingest
        # silently reads /var/log/... without them and the decoy's events are lost.
        "PALOALTO_LISTEN_HOST",
        "PALOALTO_LOG_FILE",
        "PALOALTO_SSH_LOG_FILE",
        "WEBUI_NEW_SHELL",
        "HONEY_TLS_CIPHERS",
        "K8S_HONEYPOT_ENABLED",
        "K8S_HONEYPOT_LOG_FILE",
        "GEOIP_DB_PATH",
        "TESTER_IPS_FILE",
        "TESTER_IPS_LIST",
        "AI_PROVIDER",
        "AI_ANALYSIS_ENABLED",
        "AI_ANALYZER_LOG_FILE",
        "AI_BATCH_SIZE",
        "AI_CYCLE_INTERVAL",
        "AI_TRIAGE_MIN_SEVERITY",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_DEEP_MODEL",
        "ANTHROPIC_TRIAGE_MODEL",
        "AUTO_EXTERNAL_AI",
        "AI_DEEP_BACKEND",
        "AI_FORCE_CLOUD",
        "DEEP_ANALYSIS_ENGINE",
        "OLLAMA_DEEP_MODEL",
        "OLLAMA_TIMEOUT",
        "OLLAMA_TRIAGE_MODEL",
        "OLLAMA_URL",
        "USE_EXTERNAL_AI",
        "ATTACK_KB_AUTO_GENERATE",
        "ATTACK_KB_CLAUDE_MODEL",
        "ATTACK_KB_ENABLED",
        "ATTACK_KB_ENRICH_PROMPTS",
        "ATTACK_KB_MAX_PAYLOADS",
        "ATTACK_KB_OLLAMA_MODEL",
        "ATTACK_KB_REFRESH_DAYS",
        "ATTACK_KB_SANITIZE",
        "ATTACK_KB_SENSOR_STATS",
        "ATTACK_KB_USE_CLAUDE",
        "CIRCL_ENABLED",
        "FINGERPRINT_ENABLED",
        "FINGERPRINT_INTERVAL_MIN",
        "FINGERPRINT_MAX_IPS",
        "FINGERPRINT_MIN_CLUSTER",
        "FINGERPRINT_MIN_CONFIDENCE",
        "SCANNER_EXCLUSIONS_ENABLED",
        "OSINT_THREATFOX_KEY",
        "OSINT_ABUSEIPDB_KEY",
        "OSINT_CENSYS_ID",
        "OSINT_CENSYS_SECRET",
        "OSINT_GREYNOISE_KEY",
        "OSINT_IPINFO_KEY",
        "OSINT_OTX_KEY",
        "OSINT_PULSEDIVE_KEY",
        "OSINT_SHODAN_KEY",
        "OSINT_VIRUSTOTAL_KEY",
        "NOUS_API_KEY",
        "NOUS_BASE_URL",
        "NOUS_TRIAGE_MODEL",
        "NOUS_DEEP_MODEL",
        "PROFILER_AI_PROVIDER",
        "PROFILER_AI_MAX_TOKENS",
        "PROFILER_NOUS_MODEL",
        "PROFILER_OLLAMA_MODEL",
        "PROFILER_REPROFILE_INTERVAL",
        "PROFILER_AUTO",
        "PROFILER_BATCH_SIZE",
        "PROFILER_INTERVAL",
        "PROFILER_MIN_ATTACKS",
        "PROFILER_MIN_CONNECTIONS",
        "SESSION_CLEANUP_RETAIN_DAYS",
        "SESSION_COOKIE_NAME",
        "SESSION_IDLE_TIMEOUT_HOURS",
        "SESSION_IDLE_TIMEOUT_REMEMBER_HOURS",
        "SESSION_LIFETIME_HOURS",
        "SESSION_LIFETIME_REMEMBER_HOURS",
        "SESSION_MAX_PER_USER",
        "BLOG_API_KEY",
        "BLOG_CA_BUNDLE",
        "BLOG_BASIC_PASS",
        "BLOG_BASIC_USER",
        "BLOG_ENABLED",
        "BLOG_PUBLISH_TIMEOUT",
        "BLOG_URL",
        "BLOG_VERIFY_TLS",
        "MITM_ARP_CHANGE_THRESHOLD",
        "MITM_GATEWAY_IPS",
        "MITM_LLMNR_BROAD_QUERIERS",
        "MITM_LLMNR_COOLDOWN",
        "MITM_LLMNR_MIN_REPLIES",
        "MITM_LOG_FILE",
        "MITM_TRUSTED_DHCP",
        "MITM_TRUSTED_DNS",
        "WHITELIST_FILE",
        "WHITELIST_IPS",
        "ENABLED_PLUGINS",
        "SIEM_FORWARDERS_JSON",
        "VAULT_MASTER_KEY",
        "SENSOR_NAME",
        "SENSOR_SITE",
        "OPENAI_TRIAGE_BASE_URL",
        "OPENAI_TRIAGE_API_KEY",
        "OPENAI_TRIAGE_MODEL",
        "LDAP_ENABLED",
        "LDAP_SERVER",
        "LDAP_BASE_DN",
        "LDAP_BIND_DN",
        "LDAP_BIND_PASSWORD",
        "LDAP_USER_FILTER",
        "LDAP_GROUP_ADMIN",
        "LDAP_GROUP_VIEWER",
        "LDAP_CA_CERT",
        "LDAP_ALLOW_INSECURE_TLS",
        "LDAP_DEFAULT_ROLE",
        "DB_ARCHIVE_DIR",
        "DB_ARCHIVE_DAYS",
        "DB_ARCHIVE_EXPORT",
        "DB_ARCHIVE_CLEANUP",
        "BACKUP_PASSWORD",
    }
)


def _manifest_port_keys() -> frozenset[str]:
    """Port variables that in 1.0 come from the manifest, so they are moot in the .env."""
    keys: set[str] = set()
    for hp in HONEYPOTS:
        for key in hp.runtime_env:
            if key.endswith(("_PORT", "_PORTS", "_PORT_MAP")):
                keys.add(key)
    return frozenset(keys)


def parse_env(text: str) -> dict[str, str]:
    """Simple KEY=VALUE parser: skips comments and blank lines, strips one pair of
    quotes. We do not cut inline comments — a value (e.g. a password) may contain ``#``."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            out[key] = value
    return out


@dataclass
class EnvResult:
    """Result of the .env translation: what we carry, what we skip, what we report."""

    result: dict[str, str] = field(default_factory=dict)  # target .env
    carried: list[str] = field(default_factory=list)  # carried over 1:1
    dropped_ports: list[str] = field(default_factory=list)  # honeypot ports (the manifest has them)
    unknown: list[str] = field(default_factory=list)  # unknown to 1.0 — carried, for review
    added: list[str] = field(default_factory=list)  # newly added variables
    forced: list[str] = field(default_factory=list)  # overridden values

    def render(self) -> str:
        """The target .env file as text. Order: carried over, then added."""
        lines = [
            "# Generated by honeylens-migrate-sensor (Phase 5).",
            "# API/WebUI listens on 60443. Honeypot ports come from the manifest — not here.",
            "# Review the variables flagged as new (especially BACKUP_PASSWORD) before starting.",
            "",
        ]
        for key, value in self.result.items():
            lines.append(f"{key}={value}")
        return "\n".join(lines) + "\n"


def translate_env(old_text: str) -> EnvResult:
    """Translates the 0.9 .env to 1.0 per the decisions: secrets 1:1, API_PORT=60443,
    honeypot ports skipped, unknowns carried and reported, new ones added."""
    old = parse_env(old_text)
    port_keys = _manifest_port_keys()
    res = EnvResult()

    for key, value in old.items():
        if key in FORCED:
            continue  # we set the forced value below
        if key in port_keys:
            res.dropped_ports.append(key)
            continue
        res.result[key] = value
        if key in KNOWN_KEYS:
            res.carried.append(key)
        else:
            res.unknown.append(key)

    for key, default in NEW_KEYS.items():
        if key not in res.result:
            res.result[key] = default
            res.added.append(key)

    for key, value in FORCED.items():
        prev = old.get(key)  # value from the OLD .env, not from the result being built
        res.result[key] = value
        if prev != value:
            res.forced.append(key)  # we report only a real change

    return res


# ---------------------------------------------------------------------------
# Raport / plan
# ---------------------------------------------------------------------------

_STATUS_TAGS = {
    "copy": "will copy",
    "verified": "OK",
    "exists": "exists (no --force)",
    "missing-source": "SOURCE MISSING",
    "irregular": "NOT A FILE (skipping)",
    "mismatch": "CHECKSUM MISMATCH",
}


def _print_identity_plan(items: list[CopyItem]) -> None:
    print("\n== Honeypot identities ==")
    if not items:
        print("  (nothing — no entries)")
        return
    for it in items:
        print(f"  [{_STATUS_TAGS.get(it.status, it.status)}] {it.src}  ->  {it.dst}")


def _print_env_report(res: EnvResult, old_env: Path, new_env: Path) -> None:
    # Note: the report prints only variable NAMES, never values — the .env holds secrets.
    print(f"\n== .env: {old_env}  ->  {new_env} ==")
    print(f"  carried over 1:1 : {len(res.carried)}")
    if res.forced:
        print(f"  forced           : {', '.join(res.forced)} (API/WebUI on 60443)")
    if res.added:
        print(f"  added (new)      : {', '.join(res.added)}")
    if res.dropped_ports:
        print(
            f"  skipped ports    : {', '.join(sorted(res.dropped_ports))} (the manifest has them)"
        )
    if res.unknown:
        print(f"  UNKNOWN to 1.0   : {', '.join(sorted(res.unknown))} (carried over, review)")
    if "BACKUP_PASSWORD" in res.added:
        print("  WARNING: BACKUP_PASSWORD added empty — set the secret manually.")


def _print_stop_units_warning() -> None:
    print("\n== STEP 1 (do this MANUALLY before the copy) ==")
    print("  Stop the old 0.9 units so identities are not copied mid-write:")
    print("    sudo systemctl disable --now 'sensor-hp-*' 'sensor-honeypot*'")


def _print_delegated(state_dir: Path) -> None:
    print("\n== Delegated to existing tools (run separately) ==")
    print("  db schema    : honeylens-migrate")
    print(
        f"  quadlets     : honeylens-hp --quadlets ~/.config/containers/systemd "
        f"--state-dir {state_dir}"
    )
    print("\n== Out of scope for the skeleton (do manually once 1.0 is stable) ==")
    print("  enable linger:  sudo loginctl enable-linger honeylens")
    print("  start 1.0    :  systemctl --user daemon-reload && start hp-*.service")
    print("  Rollback after a failed 1.0 start is NOT automated.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _write_env_600(path: Path, text: str) -> None:
    """Write the .env with 0600 permissions from the start — no window where the secrets file is 0644."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)
    os.chmod(path, 0o600)  # in case the file already existed with looser permissions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="HoneyLens sensor migrator 0.9 -> 1.0 (in-place). Dry-run by default.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--old-root", type=Path, default=DEFAULT_OLD_ROOT, help="root of the 0.9 installation"
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help="1.0 state directory (identity and log volumes)",
    )
    parser.add_argument(
        "--old-env", type=Path, default=None, help="0.9 .env file (default <old-root>/.env)"
    )
    parser.add_argument("--new-env", type=Path, default=DEFAULT_NEW_ENV, help="target 1.0 .env")
    parser.add_argument(
        "--apply", action="store_true", help="perform the changes (plan only by default)"
    )
    parser.add_argument("--force", action="store_true", help="overwrite existing identity files")
    args = parser.parse_args(argv)

    old_env = args.old_env or (args.old_root / ".env")
    old_text = old_env.read_text() if old_env.is_file() else ""
    overrides = parse_env(old_text)  # also identity path overrides

    mode = "APPLY" if args.apply else "PLAN (dry-run)"
    print("=" * 70)
    print(f"  Sensor migrator 0.9 -> 1.0 — mode: {mode}")
    print(f"  0.9: {args.old_root}   ->   1.0 state: {args.state_dir}")
    print("=" * 70)

    # Decision order: first remind to stop the fleet (out of scope, but MUST happen before
    # the copy), then identities, then .env, and delegations last.
    _print_stop_units_warning()

    # 1. Identities
    items = plan_identity(args.old_root, args.state_dir, args.force, overrides)
    if args.apply:
        items = apply_identity(items, args.force)
    _print_identity_plan(items)

    # 2. .env
    if old_text:
        res = translate_env(old_text)
        _print_env_report(res, old_env, args.new_env)
        if args.apply:
            _write_env_600(args.new_env, res.render())
            logger.info("wrote %s (0600)", args.new_env)
    else:
        print(f"\n== .env ==\n  no {old_env} — skipping .env translation")

    # 3-4. Delegated / out of scope
    _print_delegated(args.state_dir)

    # Exit code: an identity checksum mismatch is a hard migration failure.
    mismatches = [it for it in items if it.status == "mismatch"]
    if mismatches:
        logger.error("%d identity files failed verification", len(mismatches))
        return 1

    if not args.apply:
        print("\n(This was a plan. Run with --apply to copy identities and write the .env.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
