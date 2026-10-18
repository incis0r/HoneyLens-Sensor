"""Per-instance device identity for the WAGO decoy (Idea 54).

Every deployment of this honeypot presents its own controller: its own MAC, serial,
hostname, plant addressing and CODESYS task counters. Three separate reasons, and the
first is not about us:

1. The page set this decoy was modelled on came from packet captures of *real, publicly
   exposed* WAGO controllers. Shipping the values that came with those captures would
   mean broadcasting a third party's device fingerprint from our sensors — their MAC,
   their runtime counters — to every scanner that asks. That is someone else's
   equipment and not ours to republish. This module exists so no captured value
   survives into a running decoy; `tests/test_wago_identity.py` enforces it.

2. Identical decoys are trivially fingerprintable. Four sensors answering with one MAC
   and one set of task counters is a single signature; matching it once identifies
   every HoneyLens WAGO at once, and links our sensors to each other.

3. It is what a real fleet looks like. Two genuine PFC200s on two sites do not share a
   serial.

Stability matters as much as uniqueness. The identity is generated once and persisted:
a controller whose MAC changes on restart is not a controller, and an analyst
correlating a slow campaign needs last month's decoy to be the same device as today's.

The seed is `os.urandom`, never anything observable from outside. Deriving it from the
sensor's public address or hostname would let anyone holding this (open-source) file
recompute the identity from a scan result and confirm the host is a HoneyLens decoy —
turning a deception asset into a beacon. The fixed values that remain fixed are the
ones that describe the *model* rather than the unit (order number, firmware, product
string); randomising those would contradict the device we claim to be, and the
detection rules that key on `750-8202`.
"""

from __future__ import annotations

import json
import logging
import os
import random
import string
import tempfile
from typing import Any

# WAGO Kontakttechnik's registered OUI. Fixed on purpose: the vendor prefix is what
# makes the MAC read as a WAGO at all, so only the unit-specific half is generated.
WAGO_OUI = "00:30:DE"

# Site names a water/wastewater PFC200 plausibly carries. The decoy's process model is
# a tank and pump, so the name should agree with what the WebVisu shows.
_SITE_ROLES = ("pump", "tank", "filter", "intake", "booster", "lift", "dose", "well")
_SITE_PREFIX = ("pfc200", "wago", "plc", "rtu")

logger = logging.getLogger("wago_honeypot")

_DEFAULT_FILENAME = "wago_identity.json"

# Keys that must be present; used to backfill an identity written by an older version
# rather than discarding it (which would change a live decoy's MAC on upgrade).
_REQUIRED = (
    "serial",
    "hostname",
    "mac",
    "ip_address",
    "netmask",
    "gateway",
    "ntp_server",
    "snmp_location",
    "task_cycles",
    "rx_packets_base",
    "tx_packets_base",
    "tank_level",
    "temperature",
    "pressure",
    "flow",
)


def _rng(seed: bytes | None = None) -> random.Random:
    """A local PRNG. Seeded from os.urandom unless a test pins it.

    Deliberately a private `random.Random` and not the `random` module globals: this
    runs inside a honeypot process that has its own uses for randomness, and reseeding
    a shared generator from here would be an unpleasant surprise.
    """
    seed = seed if seed is not None else os.urandom(32)
    return random.Random(int.from_bytes(seed, "big"))


def generate(port: int = 8090, seed: bytes | None = None) -> dict[str, Any]:
    """Build a fresh, self-consistent controller identity."""
    r = _rng(seed)

    mac = f"{WAGO_OUI}:{r.randrange(256):02X}:{r.randrange(256):02X}:{r.randrange(256):02X}"

    # Plant addressing. Cosmetic — it is displayed on WBM pages and never used to route
    # anything — but it must not be the sensor's real address, so it is generated inside
    # RFC 1918 rather than read from the host. The third octet varies so two decoys do
    # not claim the same plant segment.
    third = r.randrange(2, 254)
    host_octet = r.randrange(10, 240)
    net = f"192.168.{third}"
    ip_address = f"{net}.{host_octet}"
    gateway = f"{net}.1"
    ntp_server = f"{net}.{r.randrange(2, 9)}"

    # CODESYS task cycle counters. Generated, never copied: the captured values are a
    # real controller's runtime fingerprint. Magnitudes are kept plausible for a device
    # that has been up for a long time, and the pairs stay internally consistent
    # (a fast task accumulates more cycles than a slow one).
    base = r.randrange(20_000_000, 140_000_000)
    task_cycles = [
        base,
        base + r.randrange(1_000_000, 20_000_000),
        r.randrange(9_000, 90_000),
        base + r.randrange(20_000_000, 100_000_000),
        r.randrange(500_000, 3_000_000),
        base + r.randrange(20_000_000, 100_000_000),
    ]

    serial_digits = "".join(r.choice(string.digits) for _ in range(10))
    role = r.choice(_SITE_ROLES)
    hostname = f"{r.choice(_SITE_PREFIX)}-{role}-{r.randrange(1, 24):02d}"

    return {
        "version": 1,
        "port": int(port),
        "serial": serial_digits,
        "hostname": hostname,
        "mac": mac,
        "ip_address": ip_address,
        "netmask": "255.255.255.0",
        "gateway": gateway,
        "ntp_server": ntp_server,
        "snmp_location": f"{role.capitalize()} Station {r.randrange(1, 40):02d}",
        "task_cycles": task_cycles,
        # Interface counters shown on the ethernet page; a fixed pair across the fleet
        # would be as identifying as a fixed MAC.
        "rx_packets_base": r.randrange(200_000, 4_000_000),
        "tx_packets_base": r.randrange(100_000, 2_000_000),
        # Starting process values. Varied so two decoys do not read identically at the
        # same instant, but kept inside the sane operating band the simulation assumes.
        "tank_level": round(r.uniform(35.0, 78.0), 1),
        "temperature": round(r.uniform(17.5, 27.5), 1),
        "pressure": round(r.uniform(1.8, 3.1), 2),
        "flow": round(r.uniform(8.0, 16.0), 1),
    }


def _atomic_write(path: str, data: dict[str, Any]) -> None:
    """Write via a temp file in the same directory, so a crash cannot leave a
    half-written identity that the next start would reject and regenerate."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".wago_identity.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError as exc:
            logging.getLogger(__name__).debug("ignored: %s", exc)
        raise


def load_or_create(
    path: str | None = None, port: int = 8090, seed: bytes | None = None
) -> dict[str, Any]:
    """Return this instance's identity, generating and persisting it on first run.

    An unreadable or corrupt file is replaced rather than fatal: a decoy that refuses
    to start because its cosmetic identity file is damaged would be a worse outcome
    than one that starts as a new unit.
    """
    path = path or default_path(port)
    identity: dict[str, Any] = {}
    try:
        with open(path) as fh:
            loaded = json.load(fh)
        if isinstance(loaded, dict):
            identity = loaded
    except (OSError, ValueError):
        identity = {}

    missing = [k for k in _REQUIRED if k not in identity]
    if missing:
        # Backfill only what is absent, so upgrading the honeypot to a version that
        # adds a field does not silently give a live decoy a new MAC.
        fresh = generate(port, seed)
        for key in missing:
            identity[key] = fresh[key]
        identity.setdefault("version", 1)
        identity["port"] = int(port)
        try:
            _atomic_write(path, identity)
        except OSError as exc:
            # The decoy still runs, but its identity is now in memory only and will be
            # different after the next restart — which is the failure mode this module
            # exists to prevent. Say so loudly rather than degrading quietly.
            logger.warning(
                "Could not persist WAGO identity to %s (%s). The decoy will present a "
                "NEW serial/MAC after every restart until this is fixed; check the "
                "directory is writable by the honeypot user.",
                path,
                exc,
            )
    return identity


def default_path(port: int = 8090) -> str:
    """Identity file location. Per port, so two decoys on one host are two devices."""
    base = (
        os.environ.get("WAGO_IDENTITY_DIR")
        or os.environ.get("HONEYPOT_DATA_DIR")
        or "/opt/sensor/data/wago"
    )
    return os.path.join(base, f"{_DEFAULT_FILENAME[:-5]}_{int(port)}.json")
