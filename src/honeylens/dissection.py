"""Shared eBPF deep-dissection port state (Idea 30, phase 0).

Both the sensor process (BPF map ``monitored_ports``) and the eBPF ingest (writing
``full_payload``) must see the same ports. The state is the union of:

  - ``EBPF_DISSECTION_PORTS`` from the configuration (the operator's baseline),
  - the ``ebpf_dissection_ports`` table in the database (runtime overrides; the DB wins).
"""

import logging
import time
from typing import Any

import psycopg2

from honeylens.database import legacy_get_db

logger = logging.getLogger("honeylens.dissection")


def quantize_depth(depth: int) -> int:
    """Clamp the depth to one of the tiers accepted by ``sensor_tcp.c``: 256, 1024, 4096.

    The same set is enforced by the ``CHECK`` on ``ebpf_dissection_ports.capture_depth``.
    """
    if depth >= 4096:
        return 4096
    if depth >= 1024:
        return 1024
    return 256


def _static_ports() -> dict[int, dict[str, Any]]:
    # 0.9 wrapped this import in try/except ImportError because config.py was a loose file
    # dependent on sys.path. In an installable package a missing honeylens.config is a broken
    # install, not a situation to tolerate silently — the guard was removed on purpose.
    from honeylens.config import EBPF_DISSECTION_PORTS

    return EBPF_DISSECTION_PORTS or {}


def load_dissection_ports_from_db() -> dict[int, int]:
    """``{port: depth}`` from the enabled rows of ``ebpf_dissection_ports``.

    A missing table or database is not an error: the static configuration still applies.
    """
    try:
        conn = legacy_get_db()
    except (psycopg2.Error, OSError, ImportError) as exc:
        logger.debug("ebpf_dissection_ports: no DB connection (%s) — static config only", exc)
        return {}
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "SELECT port, capture_depth FROM ebpf_dissection_ports WHERE enabled = TRUE"
            )
            rows = cur.fetchall()
    except psycopg2.Error as exc:
        logger.debug("ebpf_dissection_ports DB read skipped: %s", exc)
        return {}
    finally:
        conn.close()
    return {int(r[0]): quantize_depth(int(r[1])) for r in rows}


def build_desired_state() -> dict[int, int]:
    """Merge the static configuration with the table; on a port conflict the DB wins."""
    state = {
        int(port): quantize_depth(int(cfg.get("capture_depth", 256)))
        for port, cfg in _static_ports().items()
    }
    state.update(load_dissection_ports_from_db())
    return state


class CachedState:
    """A view of the state refreshed at most every ``refresh_sec`` seconds (minimum 5).

    The default 30 s is the same cadence as the reconciliation loop in the sensor process,
    so both consumers converge on the same state in the same window after a port is added.
    """

    def __init__(self, refresh_sec: int = 30) -> None:
        self.refresh_sec = max(5, int(refresh_sec))
        self._cache: dict[int, int] = {}
        self._last_load: float | None = None

    def get(self) -> dict[int, int]:
        now = time.monotonic()
        if self._last_load is None or now - self._last_load > self.refresh_sec:
            try:
                self._cache = build_desired_state()
            except (psycopg2.Error, OSError) as exc:
                logger.debug("dissection state refresh failed: %s", exc)
            self._last_load = now
        return self._cache

    def is_monitored(self, port: int) -> bool:
        return int(port) in self.get()
