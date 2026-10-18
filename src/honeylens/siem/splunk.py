"""Splunk HEC (HTTP Event Collector).

Endpoint: ``POST <base_url>/services/collector/event``, header ``Authorization: Splunk <token>``.

Configuration::

    {"type": "splunk", "name": "splunk-cloud",
     "base_url": "https://http-inputs.splunkcloud.com:443",
     "token_env": "SPLUNK_HEC_TOKEN",   # NAME of the variable with the token
     "index": "honeylens",              # optional
     "sourcetype": "honeylens:event",   # default
     "host_field": "sensor_hostname",   # which event field goes as the Splunk host
     "tls_verify": true, "enabled": true}
"""

import os
import time
from typing import Any

from honeylens.siem.base import HttpForwarder, SiemEvent


class SplunkForwarder(HttpForwarder):
    TYPE = "splunk"

    def __init__(self, name: str, config: dict[str, Any]):
        super().__init__(name, config)
        self.token = os.environ.get(str(config.get("token_env") or "")) or None
        self.index = config.get("index") or None
        self.sourcetype = str(config.get("sourcetype") or "honeylens:event")
        self.host_field = str(config.get("host_field") or "sensor_hostname")
        if not self.token:
            raise ValueError(
                f"splunk forwarder requires token_env to point at an env var (got: {config.get('token_env')!r})"
            )

    def _send_one(self, event: SiemEvent) -> None:
        body: dict[str, Any] = {
            "time": time.time(),
            "host": getattr(event, self.host_field, "") or "honeylens",
            "source": event.source or "honeylens",
            "sourcetype": self.sourcetype,
            "event": {
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "src_ip": event.src_ip,
                "src_port": event.src_port,
                "dst_ip": event.dst_ip,
                "dst_port": event.dst_port,
                "protocol": event.protocol,
                "attack_types": event.attack_types,
                "severity": event.severity,
                "payload": event.truncated_payload(),
                "metadata": event.metadata,
            },
        }
        if self.index:
            body["index"] = self.index
        headers = {"Authorization": f"Splunk {self.token}", "Content-Type": "application/json"}
        self._request(
            "POST", f"{self.base_url}/services/collector/event", json=body, headers=headers
        )

    def status(self) -> dict[str, Any]:
        s = super().status()
        s.update(
            {
                "base_url": self.base_url,
                "index": self.index,
                "sourcetype": self.sourcetype,
                "auth": "token" if self.token else "missing",
                "tls_verify": self.tls_verify,
            }
        )
        return s
