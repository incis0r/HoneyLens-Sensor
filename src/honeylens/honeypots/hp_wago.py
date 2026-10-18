#!/usr/bin/env python3
"""WAGO PFC200 RTU honeypot — service wrapper and HoneyLens log bridge (Idea 54).

Presents the Web-Based Management, CODESYS and WebVisu surfaces of a WAGO 750-8202
pump-station controller. It never executes submitted input, discards uploads after
hashing, makes no outbound connections, and runs no Modbus listener — the sensor
already has one, and two decoys answering for the same protocol would tell an
attacker two different stories.

**This honeypot holds no database credentials.** It writes HoneyLens-shaped JSON
lines into the honeypotng log directory and `ingest/honeypot.py` picks them up, the
same arrangement as the Kubernetes honeypot. That keeps the internet-facing surface
free of secrets and keeps the service ready for containerisation (Idea 53).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import threading
from datetime import UTC, datetime
from typing import Any

from honeylens.config import HONEYPOTNG_LOG_DIR
from honeylens.eventlog_lock import append_line

# Launched as a script, so sys.path[0] is honeypots/ and the sensor packages are
# invisible without help (the trap that silently disabled the AI canary once).
from honeylens.honeypots.wago import identity as wago_identity
from honeylens.honeypots.wago.server import WBMServer
from honeylens.honeypots.wago.state import DeviceState

_LOG = "wago_honeypot"
logger = logging.getLogger(_LOG)

# Native event_type -> (HoneyLens attack_type, rule_name). Events with no mapping are
# still logged: they are the reconnaissance context that makes the mapped ones
# readable, and dropping them would leave an attack with no approach recorded.
EVENT_MAP = {
    "credential_attempt": ("WAGO_CREDENTIAL_CAPTURE", "wago_wbm_login_attempt"),
    "webvisu_control": ("WAGO_CONTROL_WRITE", "wago_webvisu_process_write"),
    "wbm_action": ("WAGO_CONTROL_WRITE", "wago_plc_state_command"),
    "firmware_upload_attempt": ("WAGO_FIRMWARE_UPLOAD", "wago_firmware_upload"),
    "configuration_download": ("WAGO_IO_DISCLOSURE", "wago_config_backup_download"),
    "network_configuration_attempt": ("WAGO_CONTROL_WRITE", "wago_network_reconfigure"),
    "modbus_configuration": ("WAGO_CONTROL_WRITE", "wago_modbus_reconfigure"),
    "webserver_restart_attempt": ("WAGO_CONTROL_WRITE", "wago_webserver_restart"),
    "hmi_configuration": ("WAGO_RECON", "wago_hmi_setting_change"),
    "invalid_configuration": ("WAGO_RECON", "wago_invalid_parameter"),
}

# Paths whose retrieval is worth a type of its own: the I/O map is what an attacker
# reads before touching a process.
IO_DISCLOSURE_PATHS = ("/wbm/io_config.xml", "/wbm/plc_backup.cfg")

SEVERITY_FALLBACK = {
    "WAGO_CREDENTIAL_CAPTURE": "HIGH",
    "WAGO_CONTROL_WRITE": "CRITICAL",
    "WAGO_FIRMWARE_UPLOAD": "CRITICAL",
    "WAGO_IO_DISCLOSURE": "HIGH",
    "WAGO_RECON": "MEDIUM",
}


class HoneyLensEventSink:
    """Translate the decoy's native events into the HoneyLens honeypot log contract.

    The ingest reads `timestamp`, `protocol`, `peer_ip`/`peer_port`, `dst_port` and
    `payload`, and trusts `attack_type` + `rule_name` when the honeypot sets them —
    higher fidelity than re-deriving intent from a request line downstream.
    """

    PROTOCOL = "wago"

    def __init__(self, path: str, dst_port: int):
        self.path = path
        self.dst_port = int(dst_port)
        self._lock = threading.Lock()

    def emit(
        self,
        service: str,
        event_type: str,
        peer: tuple[str, int] | None = None,
        severity: str = "INFO",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        details = dict(details or {})
        src_ip = peer[0] if peer else "0.0.0.0"
        src_port = int(peer[1]) if peer and len(peer) > 1 else 0
        path = str(details.get("path") or "")

        attack_type, rule_name = EVENT_MAP.get(event_type, (None, None))
        if attack_type is None and path in IO_DISCLOSURE_PATHS:
            attack_type, rule_name = "WAGO_IO_DISCLOSURE", "wago_io_map_read"

        event: dict[str, Any] = {
            # Local time, matching the rest of the fleet — the sensors' PostgreSQL
            # and the honeypot logs agreed on this after the timezone normalisation.
            "timestamp": datetime.now(UTC).isoformat(),
            "protocol": self.PROTOCOL,
            "peer_ip": src_ip,
            "peer_port": src_port,
            "dst_port": self.dst_port,
            "action": event_type,
            "service": service,
            "severity": severity or SEVERITY_FALLBACK.get(attack_type or "", "INFO"),
            "payload": self._payload(event_type, details),
        }
        if attack_type:
            event["attack_type"] = attack_type
            event["rule_name"] = rule_name
        event.update(details)

        line = json.dumps(event, separators=(",", ":"), default=str)
        try:
            with self._lock:
                append_line(self.path, line)
        except OSError as exc:
            # Answering the attacker matters more than logging; a lost line is
            # better than a decoy that stops responding and identifies itself.
            logger.error("Failed to write event log: %s", exc)
        if attack_type:
            logger.info("[WAGO] %s -> %s %s", src_ip, attack_type, path or event_type)
        return event

    @staticmethod
    def _payload(event_type: str, details: dict[str, Any]) -> str:
        """A one-line, greppable summary — this is what the classifier and the
        reports show, so it has to carry the substance of the request."""
        method = details.get("method") or ""
        path = details.get("path") or ""
        head = (f"{method} {path}").strip() or event_type
        if event_type == "credential_attempt":
            return "{} username={} password={}".format(
                head,
                details.get("username", ""),
                details.get("password", ""),
            )
        if event_type == "webvisu_control":
            return "{} pump={} auto={} setpoint={} valve={}".format(
                head,
                details.get("pump"),
                details.get("automatic"),
                details.get("setpoint"),
                details.get("valve"),
            )
        if event_type == "wbm_action":
            return "{} {}".format(head, details.get("action", ""))
        if event_type == "firmware_upload_attempt":
            return "{} bytes={} truncated={}".format(
                head,
                details.get("content_length"),
                details.get("truncated"),
            )
        query = details.get("query")
        return f"{head}?{query}" if query else head


def build_log_path(port: int) -> str:
    """One file per listener inside the ingested glob, so no config change is needed."""
    directory = os.environ.get("HP_WAGO_LOG_DIR", HONEYPOTNG_LOG_DIR)
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, f"wago_{int(port)}.json")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="WAGO PFC200 RTU honeypot")
    # 8081 is the NGINX honeypot's cleartext port on some sensors; defaulting there
    # would recreate the collision that left a honeypot crash-looping on PROD.
    ap.add_argument("--port", type=int, default=int(os.environ.get("HP_WAGO_PORT", "8090")))
    ap.add_argument("--bind", default=os.environ.get("HP_WAGO_BIND", "0.0.0.0"))
    ap.add_argument("--unit-id", type=int, default=int(os.environ.get("HP_WAGO_UNIT_ID", "1")))
    ap.add_argument("--log-file", default=None)
    ap.add_argument(
        "--identity-file",
        default=None,
        help="controller identity; generated on first run if absent",
    )
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    log_path = args.log_file or build_log_path(args.port)
    # Unique per deployment and stable across restarts. Generated on first start rather
    # than shipped, so no value from the source captures — which came from real,
    # third-party controllers — is ever served from one of our sensors.
    ident = wago_identity.load_or_create(args.identity_file, args.port)
    state = DeviceState(unit_id=args.unit_id, identity=ident)
    sink = HoneyLensEventSink(log_path, args.port)

    server = WBMServer((args.bind, args.port), state, sink)
    logger.info(
        "WAGO WBM honeypot on %s:%d (%s), events -> %s",
        args.bind,
        args.port,
        state.product,
        log_path,
    )
    # Logged so an analyst reading an alert can tie it to the decoy that raised it.
    logger.info(
        "  identity: host=%s serial=%s mac=%s plant-ip=%s",
        state.hostname,
        state.serial,
        state.mac,
        state.ip_address,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt as exc:
        logging.getLogger(__name__).debug("ignored: %s", exc)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
