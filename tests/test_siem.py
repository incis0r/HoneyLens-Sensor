"""core.siem — forwardery, manager, kolejka, bezpiecznik. Port 1:1 z 0.9 tests/test_siem.py."""

from __future__ import annotations

import json
import socket
import threading
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from honeylens.siem.base import SiemError, SiemEvent, SiemForwarder, make_test_event
from honeylens.siem.manager import SiemManager
from honeylens.siem.syslog import SyslogForwarder
from honeylens.siem.webhook import WebhookForwarder

# ---------------------------------------------------------------------------
# SiemEvent serialisation
# ---------------------------------------------------------------------------


class TestSiemEvent:
    def test_to_json_truncates_payload(self):
        big_payload = "X" * (8 * 1024)  # 8 KiB
        ev = SiemEvent(event_id="e1", timestamp="t", source="s", payload=big_payload)
        body = ev.to_json()
        d = json.loads(body)
        # 4 KiB cap + truncation marker
        assert len(d["payload"]) <= 4 * 1024 + len("...<truncated>")
        assert d["payload"].endswith("<truncated>")

    def test_to_json_redact_payload(self):
        ev = SiemEvent(event_id="e1", timestamp="t", source="s", payload="secret")
        d = json.loads(ev.to_json(redact_payload=True))
        assert d["payload"] == ""

    def test_to_cef_escapes_pipes_and_equals(self):
        ev = SiemEvent(
            event_id="e1",
            timestamp="t",
            source="s",
            attack_types="X|Y",
            src_ip="1.1.1.1",
            payload="msg with | and = chars",
        )
        line = ev.to_cef()
        assert line.startswith("CEF:0|HoneyLens|Sensor|1.0|")
        # The pipe and equals in fields must be escaped (\\| and \\=)
        assert "\\|" in line or "\\=" in line


# ---------------------------------------------------------------------------
# Manager + queue + circuit breaker
# ---------------------------------------------------------------------------


class _RecordingForwarder(SiemForwarder):
    """In-memory forwarder for testing the manager."""

    TYPE = "recording"

    def __init__(self, name: str, fail_first_n: int = 0, fail_forever: bool = False):
        super().__init__(name, {"enabled": True, "timeout_seconds": 1, "retries": 0})
        self.received: list[SiemEvent] = []
        self.fail_first_n = fail_first_n
        self.fail_forever = fail_forever

    def _send_one(self, event: SiemEvent) -> None:
        if self.fail_forever:
            raise SiemError("permanent failure")
        if self.fail_first_n > 0:
            self.fail_first_n -= 1
            raise SiemError("transient failure")
        self.received.append(event)


class TestManager:
    def test_fanout_to_multiple_forwarders(self):
        a = _RecordingForwarder("a")
        b = _RecordingForwarder("b")
        mgr = SiemManager(forwarders=[a, b])
        mgr.start()
        try:
            ev = make_test_event()
            assert mgr.forward(ev) is True
            time.sleep(0.2)
            assert len(a.received) == 1
            assert len(b.received) == 1
        finally:
            mgr.stop()

    def test_no_forwarders_is_no_op(self):
        mgr = SiemManager(forwarders=[])
        mgr.start()
        try:
            assert mgr.forward(make_test_event()) is False
        finally:
            mgr.stop()

    def test_circuit_breaker_opens_after_threshold(self):
        bad = _RecordingForwarder("bad", fail_forever=True)
        mgr = SiemManager(forwarders=[bad], breaker_threshold=3, breaker_cooldown=60.0)
        mgr.start()
        try:
            for _ in range(5):
                mgr.forward(make_test_event())
            time.sleep(0.5)
            # After 3+ failures, the breaker should be open — additional events
            # don't even attempt the forwarder.
            calls_before = bad.fail_count
            assert calls_before >= 3
            mgr.forward(make_test_event())
            time.sleep(0.2)
            # No new fail because the breaker is open
            assert bad.fail_count == calls_before
        finally:
            mgr.stop()

    def test_one_forwarder_failure_does_not_affect_others(self):
        bad = _RecordingForwarder("bad", fail_forever=True)
        good = _RecordingForwarder("good")
        mgr = SiemManager(forwarders=[bad, good], breaker_threshold=100)
        mgr.start()
        try:
            for _ in range(3):
                mgr.forward(make_test_event())
            time.sleep(0.3)
            assert len(good.received) == 3
            assert bad.fail_count >= 3
        finally:
            mgr.stop()

    def test_queue_overflow_drop_oldest(self):
        slow = _RecordingForwarder("slow")
        mgr = SiemManager(forwarders=[slow], queue_size=4)
        # Don't start the worker — queue piles up.
        for i in range(10):
            mgr.forward(SiemEvent(event_id=f"e{i}", timestamp="t", source="s"))
        # Queue is bounded; drop_count records the overflow.
        assert mgr._dropped_count >= 6
        assert mgr._q.qsize() <= mgr.queue_size

    def test_test_send_unknown_forwarder(self):
        mgr = SiemManager(forwarders=[])
        result = mgr.test_send("nope", make_test_event())
        assert result["ok"] is False
        assert "no forwarder" in result["error"]


# ---------------------------------------------------------------------------
# Syslog forwarder over UDP — round-trip with a real socket
# ---------------------------------------------------------------------------


def _free_udp_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestSyslogForwarder:
    def test_udp_roundtrip(self):
        port = _free_udp_port()
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as listener:
            listener.bind(("127.0.0.1", port))
            listener.settimeout(2)

            fw = SyslogForwarder(
                "test",
                {
                    "host": "127.0.0.1",
                    "port": port,
                    "transport": "udp",
                    "facility": "local6",
                    "format": "rfc5424",
                    "app_name": "honeylens",
                },
            )
            ev = SiemEvent(
                event_id="e1",
                timestamp="2026-05-03T12:00:00Z",
                source="test",
                src_ip="1.2.3.4",
                attack_types="SSH_BRUTE",
                sensor_hostname="sensor4",
                severity_num=4,
            )
            fw.send(ev)

            data, _ = listener.recvfrom(8192)
            line = data.decode("utf-8", "replace")
        # PRI = facility * 8 + severity = 22*8 + 4 = 180
        assert line.startswith("<180>1 2026-05-03T12:00:00Z sensor4 honeylens - SSH_BRUTE - ")
        # RFC 5424 layout: <PRI>1 TS HOST APP PROCID MSGID STRUCTURED-DATA MSG
        # Body (JSON) starts after the 7th space-separated header element.
        parts = line.split(" ", 7)
        body = parts[7].rstrip("\n")
        assert json.loads(body)["event_id"] == "e1"

    def test_invalid_transport_rejected(self):
        with pytest.raises(ValueError, match="invalid transport"):
            SyslogForwarder("bad", {"host": "1.1.1.1", "transport": "tcpx"})

    def test_missing_host_rejected(self):
        with pytest.raises(ValueError, match="requires 'host'"):
            SyslogForwarder("bad", {"transport": "udp"})


# ---------------------------------------------------------------------------
# Webhook forwarder — SSRF guard + happy path
# ---------------------------------------------------------------------------


class _CapturingHandler(BaseHTTPRequestHandler):
    received: ClassVar[list[bytes]] = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        type(self).received.append(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        pass  # silence


class TestWebhookForwarder:
    def test_ssrf_guard_blocks_loopback(self):
        with pytest.raises(ValueError, match="private/loopback"):
            WebhookForwarder("loopback", {"url": "http://127.0.0.1:1234/x"})

    def test_ssrf_guard_blocks_rfc1918(self):
        with pytest.raises(ValueError, match="private/loopback"):
            WebhookForwarder("rfc1918", {"url": "http://10.0.0.1/x"})

    def test_ssrf_opt_in_allows_loopback(self):
        # Just constructing — no actual request.
        fw = WebhookForwarder(
            "ok",
            {
                "url": "http://127.0.0.1:9/test",
                "allow_private_targets": True,
            },
        )
        assert fw.allow_private is True

    def test_invalid_scheme_rejected(self):
        with pytest.raises(ValueError, match="scheme must be http"):
            WebhookForwarder("bad", {"url": "file:///etc/passwd", "allow_private_targets": True})

    def test_post_roundtrip_with_local_http(self):
        # Spin up a real HTTPServer on a free port for the round-trip.
        srv = HTTPServer(("127.0.0.1", 0), _CapturingHandler)
        port = srv.server_port
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            fw = WebhookForwarder(
                "local",
                {
                    "url": f"http://127.0.0.1:{port}/ingest",
                    "allow_private_targets": True,
                    "headers": {"X-Test": "1"},
                },
            )
            ev = make_test_event()
            fw.send(ev)
            time.sleep(0.05)
            assert _CapturingHandler.received, "webhook did not deliver"
            body = json.loads(_CapturingHandler.received[-1])
            assert body["event_id"] == ev.event_id
            assert body["attack_types"] == "SIEM_TEST"
        finally:
            srv.shutdown()
            srv.server_close()
