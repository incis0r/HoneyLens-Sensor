#!/usr/bin/env python3
"""Characterization / parity tests for the legacy honeypot monolith responders
(Phase 2 / T11).

`honeypots/honeypot.py` is still live (sensor-honeypot.service serves the IT
protocols in config.HONEYPOTNG_SERVICES). Before any extraction/retirement of its
BaseResponder classes, these tests pin the attacker-visible behaviour — banners,
handshakes, and canonical exchanges — so a future refactor can be proven equivalent.

Each responder is driven with a real asyncio.StreamReader (fed the client bytes
then EOF) and a capturing writer; _log_event is stubbed to avoid disk I/O.
"""

import asyncio

import pytest

from honeylens.honeypots import honeypot as H
from honeylens.honeypots.honeypots_config import get_profile


class _CapWriter:
    def __init__(self):
        self.buf = bytearray()

    def write(self, data):
        self.buf += data

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass

    def is_closing(self):
        return False

    def get_extra_info(self, *a, **k):
        return ("1.2.3.4", 12345)


@pytest.fixture(autouse=True)
def _no_log_io(monkeypatch):
    """Keep responders from writing JSON event logs during tests."""
    monkeypatch.setattr(H, "_log_event", lambda *a, **k: None)


def drive(responder, client_bytes=b"", port=80):
    """Run responder.handle against a real reader (client_bytes then EOF)."""

    async def _run():
        reader = asyncio.StreamReader()
        reader.feed_data(client_bytes)
        reader.feed_eof()
        writer = _CapWriter()
        try:
            await asyncio.wait_for(
                responder.handle(reader, writer, port, ("1.2.3.4", 12345)), timeout=5
            )
        except (TimeoutError, ConnectionError):
            pass
        return bytes(writer.buf)

    return asyncio.run(_run())


def _resp(cls_name):
    for r in H._RESPONDER_MAP.values():
        if r.__class__.__name__ == cls_name:
            return r
    raise AssertionError(f"{cls_name} not in _RESPONDER_MAP")


# --------------------------- text / handshake protocols ---------------------------


def test_ssh_banner_matches_profile():
    out = drive(_resp("SSHResponder"))
    assert out.startswith(b"SSH-2.0-OpenSSH")
    # legacy responder must present the same banner as the ssh profile / hp_ssh.py
    assert out.rstrip(b"\r\n") == get_profile("ssh")["banner"].encode()


def test_telnet_negotiation_and_login_prompt():
    out = drive(_resp("TelnetResponder"), b"root\r\nadmin\r\n")
    assert out.startswith(b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03")  # IAC DO/WILL
    assert b"login: " in out and b"Password: " in out
    assert b"Login incorrect" in out


def test_ftp_banner_and_auth_exchange():
    out = drive(_resp("FTPResponder"), b"USER a\r\nPASS b\r\nQUIT\r\n")
    assert out.startswith(b"220 ")
    assert b"331 Password required." in out
    assert b"530 Login incorrect." in out
    assert b"221 Goodbye." in out


def test_smtp_banner_and_ehlo():
    out = drive(_resp("SMTPResponder"), b"EHLO x\r\nQUIT\r\n")
    assert out.startswith(b"220 ") and b"ESMTP" in out
    assert b"250" in out and b"221" in out


def test_mysql_greeting_fingerprint():
    out = drive(_resp("MySQLResponder"))
    assert out[4:5] == b"\n"  # protocol version 10
    assert b"mysql_native_password" in out  # auth plugin advertised
    assert b"5.7" in out  # server version string


def test_http_serves_apache_response():
    out = drive(_resp("HTTPResponder"), b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 200 OK")
    assert b"Server:" in out


# --------------------------- binary protocols ---------------------------


def test_mqtt_connack():
    connect = bytes.fromhex("101300044d5154540402003c000774657374636c69")
    out = drive(_resp("MQTTResponder"), connect)
    assert out.startswith(b"\x20\x02")  # CONNACK fixed header


def test_modbus_read_holding_registers_reply():
    # MBAP txn=0001 proto=0000 len=0006 unit=01 FC=03 addr=0000 qty=0001
    req = bytes.fromhex("000100000006010300000001")
    out = drive(_resp("ModbusResponder"), req)
    assert out[:4] == b"\x00\x01\x00\x00"  # echoes txn + proto id
    assert out[6] == 0x01 and out[7] == 0x03  # unit id + function code 0x03


def test_postgres_declines_ssl():
    ssl_request = bytes.fromhex("0000000804d2162f")
    out = drive(_resp("PostgresResponder"), ssl_request)
    assert out == b"N"  # 'N' = SSL not supported


def test_rdp_x224_connection_confirm():
    x224_cr = bytes.fromhex("030000132ee00000000000")
    out = drive(_resp("RDPResponder"), x224_cr)
    assert out.startswith(b"\x03\x00")  # TPKT version 3 header


def test_javarmi_protocol_ack():
    out = drive(_resp("JavaRMIResponder"), b"JRMI\x00\x02\x4b")
    assert out.startswith(b"N")  # RMI ProtocolAck


# --------------------------- structural invariants (all responders) ---------------------------


def test_responder_map_covers_expected_protocols():
    expected = {
        "ssh",
        "ftp",
        "telnet",
        "smtp",
        "http",
        "https",
        "smb",
        "mysql",
        "mssql",
        "oracle",
        "rdp",
        "modbus",
        "mqtt",
        "java-rmi",
        "auto",
    }
    assert expected <= set(H._RESPONDER_MAP)


def test_all_responders_wellformed():
    for key, resp in H._RESPONDER_MAP.items():
        assert isinstance(resp, H.BaseResponder), f"{key} not a BaseResponder"
        assert asyncio.iscoroutinefunction(resp.handle), f"{key}.handle not async"
        assert isinstance(resp.protocol, str) and resp.protocol


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ---------------------------------------------------------------------------
# Auto-detect dedup memory (known_patterns.json) must never block startup
# ---------------------------------------------------------------------------


def test_load_patterns_missing_file(tmp_path):
    assert H._load_patterns(tmp_path / "nope.json") == {}


def test_load_patterns_empty_file_does_not_raise(tmp_path):
    """An operator truncating logs in the honeypotng dir left this file at 0 bytes,
    which used to raise JSONDecodeError at import and stop the honeypot starting."""
    f = tmp_path / "known_patterns.json"
    f.write_text("")
    assert H._load_patterns(f) == {}


def test_load_patterns_corrupt_file_does_not_raise(tmp_path):
    f = tmp_path / "known_patterns.json"
    f.write_text("{not json")
    assert H._load_patterns(f) == {}


def test_load_patterns_wrong_toplevel_type(tmp_path):
    f = tmp_path / "known_patterns.json"
    f.write_text('["a", "b"]')
    assert H._load_patterns(f) == {}


def test_load_patterns_reads_valid_memory(tmp_path):
    f = tmp_path / "known_patterns.json"
    f.write_text('{"tag1": {"first_seen": "x"}}')
    assert H._load_patterns(f) == {"tag1": {"first_seen": "x"}}
