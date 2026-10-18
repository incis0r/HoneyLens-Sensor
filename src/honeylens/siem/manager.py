"""SIEM manager — singleton, queue, worker thread, fan-out.

Hot-path contract:
    forward_event(event_dict)   — non-blocking, drops oldest on overflow.

Design (PAS-engineer perspective):

*   The classifier hot path MUST NOT block on any SIEM. Any forwarder that's
    slow, broken, or has a 30-second TLS timeout cannot be allowed to back-
    pressure ingest. We achieve this with a bounded ``queue.Queue`` plus a
    drop-oldest policy when full.
*   One worker thread drains the queue and fans out to all enabled forwarders.
    Forwarders run sequentially per event — the queue absorbs any pile-up.
    Single-threaded fan-out is intentional: it makes ordering predictable and
    keeps the resource footprint small. If one forwarder is slow it will
    eventually slow the others, but that is preferable to either dropping
    events silently or to a thread-per-forwarder racing for sockets.
*   Each forwarder has its own independent circuit breaker — repeated failure
    on one destination doesn't affect the others.
*   On shutdown, drain with a finite deadline. Don't hang sensor-api stop on
    a stuck SIEM.
"""

import logging
import os
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any

from honeylens.siem.base import SiemError, SiemEvent, SiemForwarder

logger = logging.getLogger("honeylens.siem.manager")


# Forwarder-type → class lookup.  Built lazily so import order doesn't matter.
def _forwarder_registry() -> dict[str, type]:
    from honeylens.siem.elastic import ElasticForwarder
    from honeylens.siem.loki import LokiForwarder
    from honeylens.siem.splunk import SplunkForwarder
    from honeylens.siem.syslog import SyslogForwarder
    from honeylens.siem.wazuh import WazuhForwarder
    from honeylens.siem.webhook import WebhookForwarder

    return {
        SyslogForwarder.TYPE: SyslogForwarder,
        WazuhForwarder.TYPE: WazuhForwarder,
        LokiForwarder.TYPE: LokiForwarder,
        SplunkForwarder.TYPE: SplunkForwarder,
        ElasticForwarder.TYPE: ElasticForwarder,
        WebhookForwarder.TYPE: WebhookForwarder,
    }


@dataclass
class _BreakerState:
    """Per-forwarder circuit breaker."""

    consecutive_failures: int = 0
    open_until: float = 0.0  # epoch seconds; if > now(), forwarder is skipped


class SiemManager:
    """Owns the queue, the worker thread, and the forwarder registry."""

    def __init__(
        self,
        forwarders: list[SiemForwarder] | None = None,
        queue_size: int = 10_000,
        sensor_hostname: str | None = None,
        breaker_threshold: int = 5,
        breaker_cooldown: float = 60.0,
    ):
        self.queue_size = queue_size
        self.sensor_hostname = sensor_hostname or os.uname().nodename
        self._q: queue.Queue[SiemEvent | None] = queue.Queue(maxsize=queue_size)
        self._forwarders: list[SiemForwarder] = list(forwarders or [])
        self._breakers: dict[str, _BreakerState] = {
            f.name: _BreakerState() for f in self._forwarders
        }
        self._breaker_threshold = breaker_threshold
        self._breaker_cooldown = breaker_cooldown
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._dropped_count = 0
        self._dropped_warned = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._run, name="siem-worker", daemon=True)
        self._worker.start()
        logger.info(
            "SIEM manager started — %d forwarders, queue_size=%d",
            len(self._forwarders),
            self.queue_size,
        )

    def stop(self, drain_deadline: float = 2.0) -> None:
        """Stop the worker. Best-effort drain up to ``drain_deadline`` seconds."""
        self._stop.set()
        # Send sentinel so the worker wakes if blocked on get().
        try:
            self._q.put_nowait(None)
        except queue.Full:
            logger.debug("siem: queue full at stop — worker will exit on the stop flag")
        if self._worker is not None:
            self._worker.join(timeout=drain_deadline)
        self._worker = None

    # ------------------------------------------------------------------ #
    # Public API                                                         #
    # ------------------------------------------------------------------ #

    def forward(self, event: SiemEvent) -> bool:
        """Non-blocking enqueue. Returns False if dropped due to overflow."""
        if not self._forwarders:
            return False
        # Stamp sensor hostname if missing
        if not event.sensor_hostname:
            event.sensor_hostname = self.sensor_hostname
        try:
            self._q.put_nowait(event)
            return True
        except queue.Full:
            # Drop-oldest: pop one + retry once. Counter is monotonic.
            try:
                self._q.get_nowait()
                self._dropped_count += 1
                if not self._dropped_warned:
                    logger.warning(
                        "SIEM queue full (size=%d) — dropping oldest events; will warn once",
                        self.queue_size,
                    )
                    self._dropped_warned = True
                self._q.put_nowait(event)
                return True
            except queue.Empty:
                return False

    def add_forwarder(self, fw: SiemForwarder) -> None:
        with self._lock:
            self._forwarders.append(fw)
            self._breakers[fw.name] = _BreakerState()

    def get_forwarders(self) -> list[SiemForwarder]:
        with self._lock:
            return list(self._forwarders)

    def status(self) -> dict[str, Any]:
        return {
            "queue_depth": self._q.qsize(),
            "queue_size": self.queue_size,
            "dropped_count": self._dropped_count,
            "sensor_hostname": self.sensor_hostname,
            "forwarders": [
                {**f.status(), "breaker_open_until": self._breakers[f.name].open_until}
                for f in self._forwarders
            ],
        }

    def test_send(self, forwarder_name: str, event: SiemEvent) -> dict[str, Any]:
        """Synchronous test send to one named forwarder. Used by /admin/siem."""
        fw = next((f for f in self._forwarders if f.name == forwarder_name), None)
        if fw is None:
            return {"ok": False, "error": f"no forwarder named {forwarder_name!r}"}
        try:
            fw.send(event)
            return {"ok": True, "send_count": fw.send_count}
        except SiemError as exc:
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------------ #
    # Worker                                                             #
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            if event is None:
                break
            self._fanout(event)
        # Best-effort drain on stop.
        while True:
            try:
                ev = self._q.get_nowait()
            except queue.Empty:
                break
            if ev is None:
                continue
            self._fanout(ev)

    def _fanout(self, event: SiemEvent) -> None:
        now = time.time()
        for fw in self._forwarders:
            if not fw.enabled:
                continue
            br = self._breakers[fw.name]
            if br.open_until > now:
                continue  # circuit open
            try:
                fw.send(event)
                br.consecutive_failures = 0
            except SiemError:
                br.consecutive_failures += 1
                if br.consecutive_failures >= self._breaker_threshold:
                    br.open_until = now + self._breaker_cooldown
                    logger.error(
                        "SIEM forwarder %r failed %d times — circuit open for %ds",
                        fw.name,
                        br.consecutive_failures,
                        int(self._breaker_cooldown),
                    )
            except Exception:
                # A subclass that raises non-SiemError is a bug; isolate it.
                logger.exception(
                    "SIEM forwarder %r raised non-SiemError — treating as failure",
                    fw.name,
                )
                br.consecutive_failures += 1


# ---------------------------------------------------------------------- #
# Module-level singleton                                                 #
# ---------------------------------------------------------------------- #

_GLOBAL: SiemManager | None = None
_GLOBAL_LOCK = threading.Lock()


def _build_from_config(
    siem_config: list[dict[str, Any]], sensor_hostname: str | None = None
) -> SiemManager:
    """Construct a SiemManager from config dicts.

    Each config dict must have at minimum::

        {"type": "syslog", "name": "central-rsyslog", ...}

    Forwarders that fail to construct (bad config) are logged and skipped —
    misconfiguration of one forwarder must never prevent others from loading.
    """
    registry = _forwarder_registry()
    forwarders: list[SiemForwarder] = []
    for cfg in siem_config or []:
        fw_type = cfg.get("type")
        fw_name = cfg.get("name") or fw_type
        cls = registry.get(fw_type) if isinstance(fw_type, str) else None
        if cls is None:
            logger.error("siem: unknown forwarder type %r — skipping", fw_type)
            continue
        try:
            fw = cls(fw_name, cfg)
            forwarders.append(fw)
            logger.info("siem: loaded forwarder %r (type=%s)", fw_name, fw_type)
        except Exception as exc:
            logger.error("siem: failed to construct %r (type=%s): %s", fw_name, fw_type, exc)
    return SiemManager(forwarders=forwarders, sensor_hostname=sensor_hostname)


def get_manager() -> SiemManager:
    """Get-or-create the singleton, lazily reading config.SIEM_FORWARDERS."""
    global _GLOBAL
    if _GLOBAL is not None:
        return _GLOBAL
    with _GLOBAL_LOCK:
        if _GLOBAL is None:
            try:
                from honeylens import config

                cfgs = getattr(config, "SIEM_FORWARDERS", []) or []
                hostname = getattr(config, "SENSOR_HOSTNAME", None)
            except Exception as exc:
                # values from .env, gethostname); a bad value raises ValueError, not ImportError,
                # and the ingest path must survive here and carry on without forwarders.
                logger.error("siem: config import failed (%s) — no forwarders", exc)
                cfgs, hostname = [], None
            mgr = _build_from_config(cfgs, sensor_hostname=hostname)
            mgr.start()
            _GLOBAL = mgr
    return _GLOBAL


def forward_event(event: SiemEvent) -> bool:
    """Non-blocking entrypoint for ingest hot path. Safe to call when no SIEM is configured."""
    return get_manager().forward(event)


def reset_manager_for_tests() -> None:
    """Test-only: clear the singleton."""
    global _GLOBAL
    with _GLOBAL_LOCK:
        if _GLOBAL is not None:
            _GLOBAL.stop()
        _GLOBAL = None
