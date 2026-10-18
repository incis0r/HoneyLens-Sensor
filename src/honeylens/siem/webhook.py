"""Generic webhook forwarder — POST JSON to an arbitrary URL.

Escape-hatch for any SIEM not directly supported (Sentinel, Datadog, Sumo,
custom internal aggregator, etc.). Keep configuration explicit and lock down
the obvious SSRF traps.

Config shape::

    {
      "type": "webhook",
      "name": "datadog-logs",
      "url": "https://http-intake.logs.datadoghq.com/api/v2/logs",
      "method": "POST",                 # default POST
      "headers": {                      # static headers — values may reference env vars via $VAR
        "DD-API-KEY": "$DATADOG_API_KEY",
        "Content-Type": "application/json"
      },
      "tls_verify": true,
      "allow_private_targets": false,   # default: refuse RFC1918/loopback URLs
      "extra_payload": {"ddsource": "honeylens"}    # optional fields merged into the body
    }

SSRF defence: by default we refuse to send to URLs whose hostname resolves to
private/loopback/link-local space (RFC 1918, 127.0.0.0/8, 169.254.0.0/16,
::1, fc00::/7, fe80::/10, etc.). Operators with internal aggregators must
opt in by setting ``allow_private_targets: true`` — which is itself a
visible signal in the Settings UI.
"""

import ipaddress
import os
import socket
from typing import Any
from urllib.parse import urlparse

import requests

from honeylens.siem.base import SiemEvent, SiemForwarder, http_request


class WebhookForwarder(SiemForwarder):
    TYPE = "webhook"

    def __init__(self, name: str, config: dict[str, Any]):
        super().__init__(name, config)
        self.url = str(config.get("url") or "")
        self.method = (config.get("method") or "POST").upper()
        self.headers_template = dict(config.get("headers") or {})
        self.tls_verify = bool(config.get("tls_verify", True))
        self.allow_private = bool(config.get("allow_private_targets", False))
        self.extra_payload = dict(config.get("extra_payload") or {})
        if not self.url:
            raise ValueError("webhook forwarder requires 'url'")
        parsed = urlparse(self.url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"webhook: scheme must be http/https, got {parsed.scheme!r}")
        if self.method not in ("POST", "PUT"):
            raise ValueError(f"webhook: method must be POST or PUT, got {self.method!r}")
        if not self.allow_private:
            self._ssrf_check(parsed.hostname or "")
        self._session = requests.Session()

    @staticmethod
    def _ssrf_check(hostname: str) -> None:
        """Refuse private / loopback / link-local destinations.

        Resolves hostname → all addresses; rejects if ANY resolved address is
        in a disallowed range. Operators who need internal targets opt in via
        ``allow_private_targets``.
        """
        if not hostname:
            raise ValueError("webhook: URL has no hostname")
        try:
            addrinfo = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            raise ValueError(f"webhook: cannot resolve {hostname!r}: {exc}") from exc
        for ai in addrinfo:
            ip = str(ai[4][0]).split("%", 1)[0]  # strip IPv6 zone id
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_multicast
                or addr.is_unspecified
            ):
                raise ValueError(
                    f"webhook: {hostname!r} resolves to {ip} (private/loopback) — "
                    f"set allow_private_targets=true if intentional"
                )

    @staticmethod
    def _resolve_header_value(value: str) -> str:
        """Expand $VAR references in header values from the environment."""
        if isinstance(value, str) and value.startswith("$"):
            env_name = value[1:]
            return os.environ.get(env_name, "")
        return str(value)

    def _send_one(self, event: SiemEvent) -> None:
        body: dict[str, Any] = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "source": event.source,
            "src_ip": event.src_ip,
            "src_port": event.src_port,
            "dst_ip": event.dst_ip,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "attack_types": event.attack_types,
            "severity": event.severity,
            "sensor_hostname": event.sensor_hostname,
            "payload": event.truncated_payload(),
            "metadata": event.metadata,
        }
        if self.extra_payload:
            body.update(self.extra_payload)
        headers = {k: self._resolve_header_value(v) for k, v in self.headers_template.items()}
        headers.setdefault("Content-Type", "application/json")
        http_request(
            self._session,
            self.TYPE,
            self.method,
            self.url,
            timeout=self.timeout_seconds,
            verify=self.tls_verify,
            json=body,
            headers=headers,
        )

    def status(self) -> dict[str, Any]:
        s = super().status()
        s.update(
            {
                "url": self.url,
                "method": self.method,
                "tls_verify": self.tls_verify,
                "allow_private_targets": self.allow_private,
            }
        )
        return s
