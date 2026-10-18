"""WAGO PFC200 RTU honeypot — Phase 1 (Idea 54).

Two things are pinned here: the behaviour an attacker can observe (a decoy that
crashes or answers unlike a real device announces itself), and the log contract the
ingest depends on.
"""

import json
import os
import sys
import threading
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from honeylens.honeypots.hp_wago import HoneyLensEventSink, build_log_path
from honeylens.honeypots.wago.server import MAX_BODY, MAX_SECRET, WBMServer
from honeylens.honeypots.wago.state import DeviceState


class StubSink:
    """Duck-typed event sink — the reason server.py imports no sensor packages."""

    def __init__(self):
        self.events = []

    def emit(self, service, event_type, peer=None, severity="INFO", details=None):
        rec = {
            "service": service,
            "event_type": event_type,
            "severity": severity,
            "details": dict(details or {}),
        }
        self.events.append(rec)
        return rec


@pytest.fixture
def server():
    sink = StubSink()
    srv = WBMServer(("127.0.0.1", 0), DeviceState(), sink)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    srv.sink = sink
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield srv
    srv.shutdown()
    srv.server_close()


def get(srv, path):
    with urllib.request.urlopen(srv.base + path, timeout=5) as r:
        return r.status, r.read(), dict(r.headers)


def post(
    srv, path, body: bytes, content_type="application/x-www-form-urlencoded", extra_headers=None
):
    req = urllib.request.Request(srv.base + path, data=body, method="POST")
    req.add_header("Content-Type", content_type)
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:  # 4xx is a valid decoy answer
        return e.code, e.read()


# --- attacker-visible behaviour --------------------------------------------


def test_presents_a_wago_wbm_surface(server):
    status, body, headers = get(server, "/wbm/state.php")
    assert status == 200
    assert b"Web-Based Management" in body
    assert b"750-8202" in body
    # Header signature copied from the real captures — a scanner fingerprints on these.
    assert headers.get("Server", "").startswith("lighttpd")
    assert headers.get("X-Powered-By") == "PHP/5.2.9"


def test_root_redirects_like_the_real_device(server):
    with urllib.request.urlopen(server.base + "/", timeout=5) as r:
        assert r.status == 200 and b"Status Information" in r.read()


def test_io_map_is_served_as_xml(server):
    """The file an attacker reads before touching a process."""
    status, body, headers = get(server, "/wbm/io_config.xml")
    assert status == 200 and b"<WAGO>" in body and b"750-455" in body
    assert "xml" in headers.get("Content-Type", "")


def _raw(srv, request: bytes) -> bytes:
    """urllib rewrites Content-Length, so malformed headers need a raw socket."""
    import socket

    s = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=5)
    try:
        s.sendall(request)
        return s.recv(4096)
    finally:
        s.close()


@pytest.mark.parametrize("value", [b"not-a-number", b"-5", b""])
def test_malformed_content_length_does_not_crash_the_handler(server, value):
    """Regression: _read_form runs before do_POST's try/except, so a junk header
    raised straight out of the handler and returned 500 with a traceback. A real WBM
    answers with a page, so the crash was a honeypot fingerprint."""
    resp = _raw(
        server,
        b"POST /wbm/users.ssi HTTP/1.1\r\nHost: x\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + value + b"\r\n\r\n",
    )
    first = resp.split(b"\r\n")[0]
    assert b"500" not in first, first
    assert first.startswith(b"HTTP/1.1"), first


def test_a_lying_content_length_cannot_park_a_worker_thread(server):
    """Declare a huge body, send none. Without a read timeout the handler waits
    forever and a handful of these exhausts the thread pool — cheap slowloris
    against our own sensor. A bounded wait is also what a real embedded server does."""
    import socket

    from honeylens.honeypots.wago.server import WBMHandler

    assert WBMHandler.timeout and WBMHandler.timeout <= 10, "handler needs a read timeout"

    s = socket.create_connection(
        ("127.0.0.1", server.server_address[1]), timeout=WBMHandler.timeout + 5
    )
    try:
        s.sendall(
            b"POST /wbm/users.ssi HTTP/1.1\r\nHost: x\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 999999999999999999999\r\n\r\n"
        )
        # Either an answer or a close is fine; hanging past the timeout is not.
        s.recv(4096)
    finally:
        s.close()


def test_answers_http_1_1_like_the_real_device(server):
    """The capture shows `HTTP/1.1 200 OK`; the handler default is 1.0 and the
    difference shows in the first line of every response."""
    resp = _raw(server, b"GET /wbm/state.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert resp.split(b"\r\n")[0].startswith(b"HTTP/1.1 200")


def test_junk_numeric_field_answers_with_a_page_not_a_traceback(server):
    status, body = post(server, "/webvisu.htm", b"pump=on&setpoint=abc&valve=xyz")
    assert status in (200, 400)
    assert b"<html" in body.lower()


def test_unknown_path_is_a_404_page(server):
    try:
        get(server, "/nope")
        raise AssertionError("expected 404")
    except urllib.error.HTTPError as e:
        assert e.code == 404


# --- credential capture (the operator's ask) --------------------------------


def test_login_captures_the_full_pair(server):
    post(server, "/wbm/users.ssi", b"username=admin&password=wago")
    ev = next(e for e in server.sink.events if e["event_type"] == "credential_attempt")
    d = ev["details"]
    assert d["username"] == "admin"
    assert d["password"] == "wago"  # the pair IS the intelligence
    assert d["password_length"] == 4
    assert len(d["password_sha256_prefix"]) == 16  # correlation key across sensors


def test_captured_password_is_bounded(server):
    post(server, "/wbm/users.ssi", b"username=u&password=" + b"A" * 5000)
    d = next(e for e in server.sink.events if e["event_type"] == "credential_attempt")["details"]
    assert len(d["password"]) == MAX_SECRET
    assert d["password_length"] > MAX_SECRET  # true length still recorded


def test_login_always_fails(server):
    """No credential may ever succeed — the decoy has nothing behind it."""
    status, body = post(server, "/wbm/users.ssi", b"username=admin&password=admin")
    assert status == 200 and b"Authentication failed" in body


# --- control surface --------------------------------------------------------


def test_process_write_is_recorded(server):
    post(server, "/webvisu.htm", b"pump=on&automatic=off&setpoint=80&valve=10")
    ev = next(e for e in server.sink.events if e["event_type"] == "webvisu_control")
    assert ev["details"]["pump"] is True and ev["details"]["setpoint"] == 80.0


def test_plc_stop_is_recorded_as_critical(server):
    post(server, "/wbm/administration.php", b"plc-action=stop")
    ev = next(e for e in server.sink.events if e["event_type"] == "wbm_action")
    assert ev["severity"] == "CRITICAL" and ev["details"]["action"] == "plc_stop"


def test_firmware_digest_is_labelled_as_truncated(server):
    """The body is capped, so a field called `sha256` would misdescribe the sample."""
    post(
        server,
        "/wbm/firmware_update.php",
        b"MZ" + b"\x00" * (MAX_BODY + 10),
        content_type="multipart/form-data; boundary=x",
    )
    d = next(e for e in server.sink.events if e["event_type"] == "firmware_upload_attempt")[
        "details"
    ]
    assert "sha256" not in d
    assert any(k.startswith("sha256_first_") for k in d)
    assert d["truncated"] is True and d["stored"] is False


# --- HoneyLens log contract -------------------------------------------------


def test_sink_emits_the_fields_the_ingest_reads(tmp_path):
    sink = HoneyLensEventSink(str(tmp_path / "wago.json"), 8090)
    sink.emit(
        "http",
        "credential_attempt",
        ("8.8.8.8", 4444),
        "HIGH",
        {"username": "admin", "password": "wago", "path": "/wbm/users.ssi", "method": "POST"},
    )
    rec = json.loads((tmp_path / "wago.json").read_text().strip())
    for field in ("timestamp", "protocol", "peer_ip", "peer_port", "dst_port", "payload"):
        assert field in rec, field
    assert rec["attack_type"] == "WAGO_CREDENTIAL_CAPTURE"
    assert rec["rule_name"] == "wago_wbm_login_attempt"
    assert "admin" in rec["payload"] and "wago" in rec["payload"]


def test_io_map_read_is_typed_even_without_an_event_mapping(tmp_path):
    sink = HoneyLensEventSink(str(tmp_path / "w.json"), 8090)
    rec = sink.emit(
        "http",
        "http_request",
        ("8.8.8.8", 1),
        "INFO",
        {"method": "GET", "path": "/wbm/io_config.xml"},
    )
    assert rec["attack_type"] == "WAGO_IO_DISCLOSURE"


def test_plain_recon_is_logged_without_an_attack_type(tmp_path):
    """Context must survive: an attack with no approach recorded is half a story."""
    sink = HoneyLensEventSink(str(tmp_path / "w.json"), 8090)
    rec = sink.emit(
        "http", "http_request", ("8.8.8.8", 1), "INFO", {"method": "GET", "path": "/wbm/state.php"}
    )
    assert "attack_type" not in rec and rec["payload"] == "GET /wbm/state.php"


def test_sink_survives_an_unwritable_log(tmp_path):
    """A decoy that stops answering because logging failed identifies itself."""
    sink = HoneyLensEventSink(str(tmp_path / "nodir" / "x" / "w.json"), 8090)
    assert sink.emit("http", "http_request", ("8.8.8.8", 1)) is not None


def test_attack_types_have_severities():
    from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY as S

    assert S["WAGO_CONTROL_WRITE"] == "critical"  # someone moving a valve
    assert S["WAGO_CREDENTIAL_CAPTURE"] == "high"
    assert S["WAGO_RECON"] == "medium"


def test_log_path_lands_in_the_ingested_glob(monkeypatch, tmp_path):
    monkeypatch.setenv("HP_WAGO_LOG_DIR", str(tmp_path))
    assert build_log_path(8090) == str(tmp_path / "wago_8090.json")


def test_account_admin_post_is_not_reported_as_a_plc_command(server):
    """administration.php carries account administration as well as PLC commands.

    Emitting `wbm_action` for every POST to it meant a user-creation attempt was also
    recorded as wago_plc_state_command — on a plant, the difference between someone
    adding an account and someone stopping the controller. Caught during a
    rollout, where the probe logged `plc_` with no command in it.
    """
    post(server, "/wbm/administration.php", b"new-user=hacker&user-role=admin&new-password=x")
    assert not [e for e in server.sink.events if e["event_type"] == "wbm_action"]


def test_a_real_plc_command_is_still_recorded(server):
    """The guard must not silence the event it exists to preserve."""
    post(server, "/wbm/administration.php", b"plc-action=reset")
    ev = next(e for e in server.sink.events if e["event_type"] == "wbm_action")
    assert ev["details"]["action"] == "plc_reset" and ev["severity"] == "CRITICAL"
