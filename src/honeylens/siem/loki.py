"""Loki / Grafana Cloud Logs — HTTP push API.

Endpoint: ``POST <base_url>/loki/api/v1/push``, body::

    {"streams": [{"stream": {"app": "honeylens", "source": "...", "severity": "..."},
                  "values": [["<ns since epoch>", "<json line>"]]}]}

Configuration::

    {"type": "loki", "name": "loki-prod", "base_url": "https://loki.internal",
     "tenant": "honeylens",            # X-Scope-OrgID for multi-tenant Loki
     "username": "honeylens",          # optional basic auth (Grafana Cloud)
     "password_env": "LOKI_PASSWORD",  # NAME of the variable with the password / token
     "tls_verify": true, "enabled": true}
"""

import os
import time
from typing import Any

from honeylens.siem.base import HttpForwarder, SiemEvent


class LokiForwarder(HttpForwarder):
    TYPE = "loki"

    def __init__(self, name: str, config: dict[str, Any]):
        super().__init__(name, config)
        self.tenant = config.get("tenant") or None
        self.username = config.get("username") or None
        env_name = config.get("password_env")
        self.password = (os.environ.get(str(env_name)) or None) if env_name else None

    def _send_one(self, event: SiemEvent) -> None:
        # The Loki timestamp is nanoseconds since epoch as a string; system time, because
        # parsing event.timestamp is only a cost here (best effort, as in 0.9).
        ns = str(time.time_ns())
        labels = {
            "app": "honeylens",
            "source": event.source or "unknown",
            "severity": event.severity or "informational",
            "sensor": event.sensor_hostname or "unknown",
        }
        labels = {k: v for k, v in labels.items() if v}  # Loki dislikes empty labels
        body: dict[str, Any] = {"streams": [{"stream": labels, "values": [[ns, event.to_json()]]}]}
        headers = {"Content-Type": "application/json"}
        if self.tenant:
            headers["X-Scope-OrgID"] = str(self.tenant)
        auth = (self.username, self.password) if self.username and self.password else None
        self._request(
            "POST", f"{self.base_url}/loki/api/v1/push", json=body, headers=headers, auth=auth
        )

    def status(self) -> dict[str, Any]:
        s = super().status()
        s.update(
            {
                "base_url": self.base_url,
                "tenant": self.tenant,
                "auth": "basic" if self.username else "none",
                "tls_verify": self.tls_verify,
            }
        )
        return s
