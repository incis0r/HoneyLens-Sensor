"""JSON-lines event sink for the NGINX Rift honeypot. See LOG_SCHEMA.md.

One JSON object per line. The schema is intentionally flat and stable so it can
be ingested unchanged by an external honeypot framework.
"""

from __future__ import annotations

import json
import sys
import threading
from datetime import UTC, datetime

from honeylens.eventlog_lock import append_line
from honeylens.honeypots.body_capture import capture as _capture_body


class EventLog:
    """Thread-safe JSON-lines sink. Writes to a file and/or stdout."""

    def __init__(self, path: str | None = None, also_stdout: bool = True):
        self._path = path
        self._stdout = also_stdout
        self._lock = threading.Lock()

    @staticmethod
    def serialisable(event: dict) -> dict:
        """The JSON view of an event: keys starting with `_` are in-process only.

        `_raw` carries the request's raw bytes to the sensor-side sink, which
        stores them in a bytea column. They are not JSON, and base64-ing them into
        this file would roughly double its size to duplicate what the sink already
        holds. Dropping them here keeps LOG_SCHEMA.md exactly as documented, so an
        external framework ingesting these lines sees no change.
        """
        return {k: v for k, v in event.items() if not k.startswith("_")}

    def emit(self, event: dict) -> None:
        line = json.dumps(self.serialisable(event), separators=(",", ":"), sort_keys=True)
        with self._lock:
            if self._path:
                append_line(self._path, line)
            if self._stdout:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()


def build_event(src_ip, method, raw_path, headers, body, detection, attack_class) -> dict:
    """Assemble one honeypot event from a request and its classification."""
    return {
        "ts": datetime.now(UTC).isoformat(),
        "sensor": "nginx-honeypot",
        "cve": getattr(detection, "cve_id", "") or "",
        "src_ip": src_ip,
        "http": {
            "method": method,
            "path": raw_path.decode("latin-1"),
            "headers": dict(headers),
            # Length for everything; the body itself only where it carries meaning
            # (JSON-RPC on the MCP paths). See honeypots/body_capture.py.
            **_capture_body(
                body,
                raw_path.decode("latin-1"),
                headers.get("Content-Type", "") or headers.get("content-type", ""),
            ),
        },
        "detection": {
            "matched": detection.matched,
            "attack_class": attack_class,
            "attack_type": getattr(detection, "attack_type", "") or "",
            "cve_id": getattr(detection, "cve_id", "") or "",
            "confidence": detection.confidence,
            "is_overflow": getattr(detection, "is_overflow", False),
            "indicators": detection.indicators,
        },
    }
