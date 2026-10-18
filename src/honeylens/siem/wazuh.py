"""Wazuh manager forwarder — JSON-over-TCP to wazuh-manager port 1514.

Wazuh accepts events on its remote-syslog port (default 1514/udp or 1514/tcp)
in either plain syslog or JSON form. We send JSON because Wazuh's decoders
have native JSON support and operators get richer fields than syslog can carry.

Config shape::

    {
      "type": "wazuh",
      "name": "wazuh-manager",
      "host": "wazuh.internal",
      "port": 1514,
      "transport": "tcp",        # tcp|udp   (default: tcp)
      "agent_name": "honeylens", # tag injected into the event
      "enabled": true
    }

Wazuh "agentless" ingestion via the manager listener is the simplest path —
no agent install on the sensor. For sites that want full agent integration,
configure a Wazuh agent on the sensor host pointing at the same manager and
use ``agent`` mode in this forwarder (TODO: future).
"""

import socket
from typing import Any

from honeylens.siem.base import SiemError, SiemEvent, SiemForwarder


class WazuhForwarder(SiemForwarder):
    TYPE = "wazuh"

    def __init__(self, name: str, config: dict[str, Any]):
        super().__init__(name, config)
        self.host = str(config.get("host") or "")
        self.port = int(config.get("port") or 1514)
        self.transport = (config.get("transport") or "tcp").lower()
        self.agent_name = str(config.get("agent_name") or "honeylens")[:64]
        if not self.host:
            raise ValueError("wazuh forwarder requires 'host'")
        if self.transport not in ("tcp", "udp"):
            raise ValueError(f"wazuh: invalid transport {self.transport!r}")
        self._sock: socket.socket | None = None

    def _send_one(self, event: SiemEvent) -> None:
        # Wazuh's JSON decoder expects a single JSON object per line, terminated
        # by \n. We prepend a small "honeylens:" tag the operator can match
        # against in their ruleset (rule.decoded_as).
        body = event.to_json()
        line = f"honeylens-{self.agent_name}:{body}\n".encode("utf-8", "replace")
        try:
            if self.transport == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout_seconds)
                    s.sendto(line, (self.host, self.port))
            else:
                if self._sock is None:
                    self._sock = socket.create_connection(
                        (self.host, self.port), timeout=self.timeout_seconds
                    )
                try:
                    self._sock.sendall(line)
                except OSError:
                    self._close_sock()
                    self._sock = socket.create_connection(
                        (self.host, self.port), timeout=self.timeout_seconds
                    )
                    self._sock.sendall(line)
        except OSError as exc:
            self._close_sock()
            raise SiemError(f"wazuh send: {exc}") from exc

    def _close_sock(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError as close_exc:
                self.logger.debug("closing wazuh socket: %s", close_exc)
        self._sock = None

    def status(self) -> dict[str, Any]:
        s = super().status()
        s.update(
            {
                "host": self.host,
                "port": self.port,
                "transport": self.transport,
                "agent_name": self.agent_name,
            }
        )
        return s
