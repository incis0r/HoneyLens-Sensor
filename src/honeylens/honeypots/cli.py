"""``honeylens-hp`` — one command for every honeypot, inside a container and outside it.

    honeylens-hp <name>               run a honeypot (this is the image CMD)
    honeylens-hp --list               table from the manifest
    honeylens-hp --quadlets DIR       generate podman quadlets and the firewalld DNAT list

Startup: variables from the manifest go into the environment (``setdefault``, so the operator
can override them), missing self-signed certificates are created in the identity directory,
and then control passes to the class (``BaseHoneypot.run()``) or the module's ``main``
function. Non-zero exit code when the honeypot did not come up — the unit has to see that,
not report ``active`` over a dead process, as in 0.9 with the LLM honeypot.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import logging
import os
import socket
import sys
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from honeylens.honeypots.manifest import (
    BY_NAME,
    CONTAINER_IDENTITY_DIR,
    CONTAINER_LOG_ROOT,
    HONEYPOTS,
    Honeypot,
    get,
)

logger = logging.getLogger("honeylens.honeypots.cli")


# ------------------------------------------------------------------- startup


def _paths() -> tuple[str, str]:
    """(identity directory, log root) — fixed in the container, overridable outside it."""
    return (
        os.environ.get("HONEYLENS_IDENTITY_DIR", CONTAINER_IDENTITY_DIR),
        os.environ.get("HONEYLENS_LOG_ROOT", CONTAINER_LOG_ROOT),
    )


def resolved_env(hp: Honeypot, identity_dir: str, log_root: str) -> dict[str, str]:
    """Manifest variables with the ``{identity}`` and ``{logs}`` placeholders substituted."""
    out = {}
    for key, value in hp.runtime_env.items():
        out[key] = value.replace(CONTAINER_IDENTITY_DIR, identity_dir).replace("{logs}", log_root)
    return out


def ensure_self_signed(cert: Path, key: Path, common_name: str) -> bool:
    """Generate a self-signed pair if it does not exist. ``True`` when something was created.

    The TLS identity is created on first start in the volume, never in the image: the same
    certificate across the whole fleet is a ready-made honeypot fingerprint. Valid 10 years,
    as in 0.9.
    """
    if cert.exists() and key.exists():
        return False
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )
    cert.parent.mkdir(parents=True, exist_ok=True)
    key.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    key.chmod(0o600)
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    logger.info("generated self-signed certificate %s (CN=%s)", cert, common_name)
    return True


def run(name: str) -> int:
    hp = get(name)
    identity_dir, log_root = _paths()
    for key, value in resolved_env(hp, identity_dir, log_root).items():
        os.environ.setdefault(key, value)
    for cert, key, cn in hp.certs:
        if not cn:
            continue  # empty CN: the honeypot generates its own cert (unique per deployment)
        ensure_self_signed(
            Path(cert.replace(CONTAINER_IDENTITY_DIR, identity_dir)),
            Path(key.replace(CONTAINER_IDENTITY_DIR, identity_dir)),
            cn,
        )
    # Vendor-format files live in a subdirectory of the volume; the honeypot opens them in
    # append mode and does not create the directory itself.
    for key in ("FORTIGATE_LOG_FILE", "PALOALTO_LOG_FILE", "PALOALTO_SSH_LOG_FILE"):
        if key in os.environ:
            Path(os.environ[key]).parent.mkdir(parents=True, exist_ok=True)

    # The honeypot takes its configuration from the environment (manifest), not from
    # command-line arguments. But with `honeylens-hp <name>` sys.argv still carries the
    # honeypot name, and more than one main() has its own argparse (paloalto, fortigate) and
    # dies on "unrecognized arguments: <name>". We clear argv so such a parser falls back to
    # its defaults/environment.
    sys.argv = [f"honeylens-hp:{name}"]

    module = importlib.import_module(hp.module)
    target: Any = getattr(module, hp.entry)
    logger.info(
        "starting honeypot %s (%s.%s) on %s/%s",
        hp.name,
        hp.module,
        hp.entry,
        hp.ports,
        hp.transport,
    )
    if inspect.isclass(target):
        instance: Any = target()  # BaseHoneypot subclass; see tests/test_honeypot_manifest.py
        instance.run()
        return 0
    if inspect.iscoroutinefunction(target):
        asyncio.run(target())
        return 0
    result = target()
    return int(result) if isinstance(result, int) else 0


# ------------------------------------------------------------------ quadlets


def quadlet(hp: Honeypot, *, state_dir: str, image_tag: str, registry: str) -> str:
    """Contents of ``hp-<name>.container`` for podman-systemd (rootless, pasta)."""
    lines = [
        "# Generated from honeylens.honeypots.manifest — do not edit by hand, change the manifest.",
        "[Unit]",
        f"Description=HoneyLens honeypot {hp.name} ({hp.transport} {', '.join(map(str, hp.ports))})",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Container]",
        f"Image={registry}/{hp.image}:{image_tag}",
        f"ContainerName={hp.unit}",
        # pasta keeps the source address across the container boundary (measurement 2c on sensor-b).
        "Network=pasta",
        # The process in the container is uid 1000 (the honeylens user from the image) = the
        # host user's uid, so files on the volumes belong to it, not to a sub-uid from
        # /etc/subuid.
        "UserNS=keep-id:uid=1000,gid=1000",
    ]
    for bound, _public in hp.port_map:
        suffix = "/udp" if hp.udp else ""
        lines.append(f"PublishPort={bound}:{bound}{suffix}")
    lines.append("Environment=TZ=UTC")
    for key, value in resolved_env(hp, CONTAINER_IDENTITY_DIR, CONTAINER_LOG_ROOT).items():
        lines.append(f"Environment={key}={value}")
    if hp.waf_canary:
        # Fake-vendor WAF canary. Pin SENSOR_HOSTNAME to this host so every web decoy (whose own
        # container hostname is the container id) derives the SAME invented vendor — one
        # consistent WAF across the host's surfaces. Enable flag + salt come from the generation
        # environment, so the canary is OFF unless the operator sets WAF_CANARY_ENABLED when
        # (re)generating units. See honeypots/deception_waf.py and docs/deception-waf-canary.md.
        host = os.environ.get("SENSOR_HOSTNAME") or socket.gethostname()
        lines.append(f"Environment=SENSOR_HOSTNAME={host}")
        if os.environ.get("WAF_CANARY_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}:
            lines.append("Environment=WAF_CANARY_ENABLED=true")
            salt = os.environ.get("WAF_CANARY_SALT", "").strip()
            if salt:
                lines.append(f"Environment=WAF_CANARY_SALT={salt}")
            vendor = os.environ.get("WAF_CANARY_VENDOR", "").strip()
            if vendor:
                lines.append(f"Environment=WAF_CANARY_VENDOR={vendor}")
    # :z — shared SELinux label (the ingest on the host reads the same files);
    # :Z — private to this honeypot's identity volume.
    lines.append(f"Volume={state_dir}/hp-logs:{CONTAINER_LOG_ROOT}:z")
    if hp.identity:
        lines.append(f"Volume={state_dir}/identity/{hp.identity}:{CONTAINER_IDENTITY_DIR}:Z")
    lines += [
        "ReadOnly=true",
        "Tmpfs=/tmp",
        "NoNewPrivileges=true",
        "DropCapability=ALL",  # without root and without ports < 1024 there is nothing to add
    ]
    lines += [
        "",
        "[Service]",
        "Restart=always",
        "RestartSec=5",
        "TimeoutStartSec=120",
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
    ]
    return "\n".join(lines)


def firewalld_forwards(hps: Iterable[Honeypot]) -> str:
    """firewalld forwards from a protocol port < 1024 to the bound one (30000+port)."""
    out = [
        "# DNAT from the protocol port to the container port — only where they differ (< 1024).",
        "# firewall-cmd --permanent --add-forward-port=... ; firewall-cmd --reload",
    ]
    for hp in hps:
        for bound, public in hp.port_map:
            if bound != public:
                out.append(
                    f"firewall-cmd --permanent --add-forward-port="
                    f"port={public}:proto={hp.transport}:toport={bound}  # {hp.unit}"
                )
    return "\n".join(out) + "\n"


def port_conflicts(hps: Iterable[Honeypot]) -> list[tuple[str, str, str]]:
    """``[(host:port/proto, honeypot A, honeypot B)]`` — units that cannot be enabled together."""
    seen: dict[str, str] = {}
    conflicts = []
    for hp in hps:
        for bound, _public in hp.port_map:
            key = f"{bound}/{hp.transport}"
            if key in seen:
                conflicts.append((key, seen[key], hp.unit))
            else:
                seen[key] = hp.unit
    return conflicts


def write_quadlets(out_dir: Path, *, state_dir: str, image_tag: str, registry: str) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for hp in HONEYPOTS:
        path = out_dir / f"{hp.unit}.container"
        path.write_text(quadlet(hp, state_dir=state_dir, image_tag=image_tag, registry=registry))
        written.append(path)
    fw = out_dir / "firewalld-forwards.sh"
    fw.write_text(firewalld_forwards(HONEYPOTS))
    written.append(fw)
    return written


def _table() -> str:
    rows = [("NAME", "PORTS (protocol)", "BIND", "PROTO", "IDENTITY", "ENTRY")]
    for hp in HONEYPOTS:
        rows.append(
            (
                hp.name,
                ",".join(map(str, hp.ports)),
                ",".join(str(b) for b, _ in hp.port_map),
                hp.transport,
                hp.identity or "-",
                f"{hp.module.rsplit('.', 1)[-1]}.{hp.entry}",
            )
        )
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)) for r in rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="honeylens-hp", description=__doc__.split("\n\n")[0])
    parser.add_argument("name", nargs="?", help="honeypot to run (see --list)")
    parser.add_argument("--list", action="store_true", help="print the manifest and exit")
    parser.add_argument("--quadlets", metavar="DIR", help="write hp-*.container units into DIR")
    parser.add_argument(
        "--state-dir", default="/var/lib/honeylens", help="host dir for logs and identity"
    )
    parser.add_argument("--image-tag", default="latest")
    parser.add_argument("--registry", default="localhost")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )
    if args.list:
        print(_table())
        return 0
    if args.quadlets:
        written = write_quadlets(
            Path(args.quadlets),
            state_dir=args.state_dir,
            image_tag=args.image_tag,
            registry=args.registry,
        )
        print(f"{len(written)} files in {args.quadlets}")
        for key, a, b in port_conflicts(HONEYPOTS):
            print(f"WARNING: {a} and {b} share host port {key} — only one of them can be enabled")
        return 0
    if not args.name:
        parser.error("honeypot name required (or --list / --quadlets)")
    if args.name not in BY_NAME:
        parser.error(f"unknown honeypot {args.name!r}; known: {', '.join(sorted(BY_NAME))}")
    return run(args.name)


if __name__ == "__main__":
    raise SystemExit(main())
