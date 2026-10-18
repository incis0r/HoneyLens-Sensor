"""Syslog forwarder — RFC 5424 over TCP / UDP / TCP+TLS.

Config shape::

    {
      "type": "syslog",
      "name": "central-rsyslog",
      "host": "logs.internal",
      "port": 6514,
      "transport": "tls",            # tcp|udp|tls   (default: udp)
      "tls_verify": true,            # default true; never set false in prod
      "tls_ca_file": "/etc/ssl/certs/internal-ca.pem",  # optional
      "facility": "local6",          # default local6
      "format": "rfc5424",           # rfc5424|cef    (default: rfc5424)
      "app_name": "honeylens",       # default honeylens
      "enabled": true,
      "timeout_seconds": 5
    }

Notes:
    - RFC 5424 framing for TCP / TLS uses the "octet-counting" prefix
      (RFC 6587 §3.4.1) — that's what rsyslog/syslog-ng expect by default.
    - We never log credentials. Syslog itself is unauthenticated; TLS is
      the security boundary, so ``tls_verify`` is ON by default.
"""

import socket
import ssl
import time
from typing import Any

from honeylens.siem.base import SiemError, SiemEvent, SiemForwarder

_FACILITY_MAP = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}


class SyslogForwarder(SiemForwarder):
    TYPE = "syslog"

    def __init__(self, name: str, config: dict[str, Any]):
        super().__init__(name, config)
        self.host = str(config.get("host") or "")
        self.port = int(config.get("port") or 514)
        self.transport = (config.get("transport") or "udp").lower()
        self.tls_verify = bool(config.get("tls_verify", True))
        self.tls_ca_file = config.get("tls_ca_file") or None
        self.app_name = (config.get("app_name") or "honeylens")[:48]
        self.format = (config.get("format") or "rfc5424").lower()
        facility_name = (config.get("facility") or "local6").lower()
        self.facility = _FACILITY_MAP.get(facility_name, 22)
        if not self.host:
            raise ValueError("syslog forwarder requires 'host'")
        if self.transport not in ("tcp", "udp", "tls"):
            raise ValueError(f"syslog: invalid transport {self.transport!r}")
        if self.format not in ("rfc5424", "cef"):
            raise ValueError(f"syslog: invalid format {self.format!r}")
        # Cached TCP/TLS socket — re-opened on send failure.
        self._sock: socket.socket | None = None

    # ------------------------------------------------------------------ #
    def _send_one(self, event: SiemEvent) -> None:
        line = self._frame(event)
        try:
            if self.transport == "udp":
                self._send_udp(line)
            else:
                self._send_stream(line)
        except (OSError, ssl.SSLError) as exc:
            self._close_sock()
            raise SiemError(f"{self.transport}: {exc}") from exc

    # ------------------------------------------------------------------ #
    def _frame(self, event: SiemEvent) -> bytes:
        prival = self.facility * 8 + self._severity_to_syslog(event.severity_num)
        ts = event.timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        host = event.sensor_hostname or "-"
        msgid = (event.attack_types.split(",", 1)[0] or "event")[:32] or "-"

        if self.format == "cef":
            body = event.to_cef()
        else:
            body = event.to_json()

        # RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        line = f"<{prival}>1 {ts} {host} {self.app_name} - {msgid} - {body}\n"
        return line.encode("utf-8", "replace")

    @staticmethod
    def _severity_to_syslog(sev_num: int) -> int:
        # SiemEvent.severity_num already follows syslog scale (0..7), clamp.
        return max(0, min(7, int(sev_num)))

    # ------------------------------------------------------------------ #
    def _send_udp(self, line: bytes) -> None:
        # UDP has a 64 KB datagram limit — payload is already capped at 4 KiB
        # plus envelope, so we're safely under.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout_seconds)
            s.sendto(line, (self.host, self.port))

    def _send_stream(self, line: bytes) -> None:
        if self._sock is None:
            self._sock = self._open_sock()
        # RFC 6587 octet-counting framing: "<length> <message>"
        framed = f"{len(line)} ".encode("ascii") + line
        try:
            self._sock.sendall(framed)
        except (OSError, ssl.SSLError):
            self._close_sock()
            # one reconnect attempt
            self._sock = self._open_sock()
            self._sock.sendall(framed)

    def _open_sock(self) -> socket.socket:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout_seconds)
        if self.transport == "tls":
            ctx = ssl.create_default_context(cafile=self.tls_ca_file)
            if not self.tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                self.logger.warning(
                    "syslog: TLS verification DISABLED for %s — set tls_verify=true in production",
                    self.name,
                )
            return ctx.wrap_socket(raw, server_hostname=self.host)
        return raw

    def _close_sock(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError as exc:
                self.logger.debug("closing syslog socket: %s", exc)
        self._sock = None

    # ------------------------------------------------------------------ #
    def status(self) -> dict[str, Any]:
        s = super().status()
        s.update(
            {
                "host": self.host,
                "port": self.port,
                "transport": self.transport,
                "format": self.format,
                "tls_verify": self.tls_verify,
            }
        )
        return s
