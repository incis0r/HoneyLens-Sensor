"""SIEM forwarder base interface + canonical event shape.

Design notes (PAS-engineer perspective):

*   ``SiemEvent`` is the canonical wire-format. Forwarders translate this into
    their target's expected shape (RFC 5424 line, Wazuh JSON, Loki stream entry,
    Splunk HEC body, etc.).
*   The conversion happens at send time, in the worker thread — never on the
    classifier hot path.
*   ``SiemForwarder.send()`` MUST be reentrant-safe for the worker thread. It
    raises ``SiemError`` on any unrecoverable problem; the manager's circuit
    breaker decides whether to retry or open.
*   No forwarder ever logs credentials. The base class provides a redacted
    ``__repr__`` so accidental logging of a forwarder instance is safe.
"""

import abc
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

import requests


class SiemError(Exception):
    """Raised by forwarders when a send fails irrecoverably for the current event.

    The manager catches this and increments the failure counter; consecutive
    failures trip the circuit breaker for that forwarder (the queue keeps
    accepting events, but stops attempting that destination for ``cooldown``
    seconds).
    """


@dataclass
class SiemEvent:
    """Canonical event shape for SIEM forwarding.

    Built from a classified ``sensor_events`` row. Derived fields like
    ``severity`` are set by the manager before fan-out so each forwarder sees
    the same view.

    Field choices follow common SIEM conventions:
      - ``timestamp`` is RFC 3339 UTC.
      - ``severity`` maps to syslog severities (0..7) with a string label.
      - ``attack_types`` is a comma-separated list (already the DB shape).
      - ``payload`` is truncated to 4 KiB before forwarding (full payload
        stays in the local DB; SIEMs hate megabyte log lines).
    """

    event_id: str
    timestamp: str  # RFC 3339, UTC
    source: str  # honeypot module / sensor / suricata / ...
    protocol: str = ""
    src_ip: str = ""
    src_port: int | None = None
    dst_ip: str = ""
    dst_port: int | None = None
    attack_types: str = ""
    severity: str = "informational"  # informational|low|medium|high|critical
    severity_num: int = 6  # syslog 0..7 (0=emerg, 7=debug)
    sensor_hostname: str = ""
    payload: str = ""
    payload_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    PAYLOAD_MAX_BYTES = 4 * 1024

    def truncated_payload(self) -> str:
        if not self.payload:
            return ""
        if len(self.payload.encode("utf-8", "replace")) <= self.PAYLOAD_MAX_BYTES:
            return self.payload
        return self.payload[: self.PAYLOAD_MAX_BYTES] + "...<truncated>"

    def to_json(self, *, redact_payload: bool = False) -> str:
        d = asdict(self)
        d["payload"] = "" if redact_payload else self.truncated_payload()
        return json.dumps(d, default=str, separators=(",", ":"))

    def to_cef(
        self, vendor: str = "HoneyLens", product: str = "Sensor", product_version: str = "1.0"
    ) -> str:
        """ArcSight CEF representation — for syslog forwarders that need it."""
        sig = (self.attack_types.split(",", 1)[0] or self.source or "event").strip()
        name = sig
        sev_map = {"informational": 0, "low": 3, "medium": 5, "high": 7, "critical": 10}
        sev = sev_map.get(self.severity, 5)

        # CEF extension fields — escape pipes/equals
        def _esc(v):
            return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")

        ext = " ".join(
            f"{k}={_esc(v)}"
            for k, v in {
                "rt": self.timestamp,
                "src": self.src_ip,
                "spt": self.src_port or "",
                "dst": self.dst_ip,
                "dpt": self.dst_port or "",
                "proto": self.protocol,
                "cs1Label": "attack_types",
                "cs1": self.attack_types,
                "msg": self.truncated_payload()[:512],
            }.items()
            if v not in ("", None)
        )
        return f"CEF:0|{vendor}|{product}|{product_version}|{sig}|{name}|{sev}|{ext}"


class SiemForwarder(abc.ABC):
    """Base class. Subclasses implement ``_send_one(event)``.

    Concrete forwarders should NEVER log raw credentials, NEVER include the
    full payload in error messages (use ``event.event_id`` for correlation),
    and MUST raise ``SiemError`` (not arbitrary exceptions) on failure.
    """

    #: forwarder type slug, used in config + logs. Override in subclass.
    TYPE: str = "base"

    def __init__(self, name: str, config: dict[str, Any]):
        self.name = name
        self._config = dict(config)
        self.enabled = bool(config.get("enabled", True))
        self.timeout_seconds = float(config.get("timeout_seconds", 5))
        self.retries = int(config.get("retries", 1))
        # Each forwarder has its own logger so operators can adjust levels.
        self.logger = logging.getLogger(f"honeylens.siem.{self.TYPE}.{self.name}")
        # State the manager updates.
        self.last_send_ts: float = 0.0
        self.last_error: str = ""
        self.send_count: int = 0
        self.fail_count: int = 0

    # ------------------------------------------------------------------ #
    # Public surface                                                     #
    # ------------------------------------------------------------------ #

    def send(self, event: SiemEvent) -> None:
        """Forward one event with retries. Raises SiemError on final failure."""
        last_exc: Exception | None = None
        for attempt in range(1 + self.retries):
            try:
                self._send_one(event)
                self.send_count += 1
                self.last_send_ts = time.time()
                self.last_error = ""
                return
            except SiemError as exc:
                last_exc = exc
                # Log without payload to keep the SIEM error log readable.
                self.logger.warning(
                    "send attempt %d/%d failed for event %s: %s",
                    attempt + 1,
                    1 + self.retries,
                    event.event_id,
                    exc,
                )
                if attempt < self.retries:
                    time.sleep(0.2 * (1 + attempt))  # tiny backoff
        self.fail_count += 1
        self.last_error = str(last_exc) if last_exc else "unknown"
        raise SiemError(self.last_error)

    @abc.abstractmethod
    def _send_one(self, event: SiemEvent) -> None:
        """Subclass: serialise + transmit one event. Raise SiemError on failure."""

    # ------------------------------------------------------------------ #
    # Introspection (Settings UI)                                        #
    # ------------------------------------------------------------------ #

    def status(self) -> dict[str, Any]:
        return {
            "type": self.TYPE,
            "name": self.name,
            "enabled": self.enabled,
            "send_count": self.send_count,
            "fail_count": self.fail_count,
            "last_send_ts": self.last_send_ts,
            "last_error": self.last_error,
        }

    def __repr__(self) -> str:
        # Redacted — credentials never make it into logs.
        return f"<{self.__class__.__name__} name={self.name!r} enabled={self.enabled}>"


def http_request(
    session: requests.Session,
    kind: str,
    method: str,
    url: str,
    *,
    timeout: float,
    verify: bool,
    **kwargs: Any,
) -> requests.Response:
    """One HTTP request with error mapping to ``SiemError``.

    A transport error and a response ≥ 300 are the same from the point of view of the
    circuit breaker in the manager; the response body is truncated, because Splunk can
    echo back a huge JSON.
    """
    try:
        resp = session.request(method, url, timeout=timeout, verify=verify, **kwargs)
    except requests.RequestException as exc:
        raise SiemError(f"{kind} request: {exc}") from exc
    if resp.status_code >= 300:
        raise SiemError(f"{kind} HTTP {resp.status_code}: {resp.text[:200]}")
    return resp


class HttpForwarder(SiemForwarder):
    """Shared part of the ``base_url`` forwarders: session, TLS verification, address validation.

    In 0.9 loki, splunk and elastic repeated the same thing word for word, including the dead
    guard ``try: import requests`` — ``requests`` is a hard dependency of the package.
    """

    def __init__(self, name: str, config: dict[str, Any]):
        super().__init__(name, config)
        self.base_url = str(config.get("base_url") or "").rstrip("/")
        self.tls_verify = bool(config.get("tls_verify", True))
        if not self.base_url:
            raise ValueError(f"{self.TYPE} forwarder requires 'base_url'")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError(f"{self.TYPE}: base_url must use http/https, got {self.base_url!r}")
        self._session = requests.Session()

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        return http_request(
            self._session,
            self.TYPE,
            method,
            url,
            timeout=self.timeout_seconds,
            verify=self.tls_verify,
            **kwargs,
        )


def make_test_event(sensor_hostname: str = "honeylens-test") -> SiemEvent:
    """Synthetic event for the 'Test Send' button. Never contains real data."""
    return SiemEvent(
        event_id=str(uuid.uuid4()),
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        source="siem-test",
        protocol="tcp",
        src_ip="203.0.113.42",  # TEST-NET-3 (RFC 5737)
        src_port=12345,
        dst_ip="198.51.100.1",  # TEST-NET-2
        dst_port=22,
        attack_types="SIEM_TEST",
        severity="informational",
        severity_num=6,
        sensor_hostname=sensor_hostname,
        payload="HoneyLens SIEM forwarder test event — not a real attack.",
        payload_hash="0" * 64,
        metadata={"test": True, "issued_by": "admin/siem test-send"},
    )
