"""Honeypot units on the host: ``hp-<name>`` quadlets of the user that runs the API.

In 0.9 the API and the admin panel kept their own hand-written lists of ``sensor-hp-*``
units (two different ones, both incomplete) and called ``sudo systemctl``. In 1.0 the
honeypots are rootless quadlets from the manifest, so the list comes from it, and
``systemctl --user`` needs no sudo — the API runs as the same user as the containers.
"""

from __future__ import annotations

import logging
import subprocess  # nosec B404 — fixed systemctl commands, arguments as a list
from concurrent.futures import ThreadPoolExecutor

from honeylens.honeypots.manifest import BY_NAME, HONEYPOTS

logger = logging.getLogger(__name__)

_TIMEOUT = 5

# Human-readable names (the "Service" column in the admin panel); no entry = manifest name.
LABELS: dict[str, str] = {
    "honeypot": "Honeypots (NG monolith)",
    "k8s": "K8s API",
    "fortigate": "FortiGate",
    "paloalto": "PAN-OS WebUI/GP/API",
    "paloalto-ssh": "PAN-OS SSH CLI",
    "llm": "LLM Chat (OWASP)",
    "llm-tls": "LLM Chat (TLS)",
    "nginx": "NGINX",
    "wago": "WAGO PLC",
    "s7comm": "S7comm",
    "opcua": "OPC-UA",
    "iec104": "IEC-104",
    "bacnet": "BACnet",
    "dnp3": "DNP3",
    "enip": "EtherNet/IP",
    "fins": "Omron FINS",
    "fox": "Niagara Fox",
    "profinet": "PROFINET",
    "javarmi": "Java RMI",
    "dahua": "Dahua DVR",
    "elasticsearch": "Elasticsearch",
    "memcached": "Memcached",
}


def label(name: str) -> str:
    return LABELS.get(name, name.upper() if len(name) <= 5 else name.capitalize())


def unit_for(name: str) -> str | None:
    hp = BY_NAME.get(name)
    return hp.unit if hp else None


def unit_status(unit: str) -> str:
    """``active``/``inactive``/``failed``… from ``systemctl --user is-active``; ``unknown`` when it cannot be asked."""
    try:
        r = subprocess.run(  # noqa: S603 # nosec B603 B607 — fixed command, unit name from the manifest
            ["systemctl", "--user", "is-active", unit],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
        return r.stdout.strip() or "unknown"
    except Exception as exc:
        logger.debug("systemctl is-active %s failed: %s", unit, exc)
        return "unknown"


def all_status() -> dict[str, str]:
    """``{honeypot name: unit state}`` for the whole manifest, in parallel."""
    with ThreadPoolExecutor(max_workers=16) as pool:
        statuses = pool.map(lambda hp: (hp.name, unit_status(hp.unit)), HONEYPOTS)
    return dict(statuses)


def toggle(unit: str) -> tuple[str, bool]:
    """Stop an active unit or start an inactive one. ``(action, was it active before)``."""
    was_active = unit_status(unit) == "active"
    action = "stop" if was_active else "start"
    subprocess.run(  # noqa: S603 # nosec B603 B607 — fixed command, unit name from the manifest
        ["systemctl", "--user", action, unit],  # noqa: S607
        capture_output=True,
        timeout=10,
        check=True,
    )
    return action, was_active
