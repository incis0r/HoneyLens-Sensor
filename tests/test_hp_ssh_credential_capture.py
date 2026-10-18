"""The SSH decoy has to finish the handshake, or it never sees a password.

Until 2026-11-09 ``hp_ssh`` answered with a banner and read raw bytes, so the client
stopped at ``SSH_MSG_KEXINIT``: 122,015 banner rows across the fleet's history and not one
credential. These tests pin the three things that make the new decoy answer the question
CVE-2026-123158 asks — is anyone sending a password longer than 256 bytes?

1. the length is recorded as measured, before any truncation (the PAN-OS decoy stores
   ``password[:200]``, which turns a 300-byte password into an indistinguishable 200);
2. several attempts on ONE connection are each captured, because that CVE needs two and
   a decoy that accepts the first password never sees the second;
3. the banner names a version the CVE applies to, with no glibc distro suffix.
"""

import asyncio
import json
import re
from pathlib import Path

import asyncssh
import pytest

from honeylens.honeypots import hp_ssh, sink


@pytest.fixture()
def events(monkeypatch, tmp_path):
    """Point the sink at a temp dir; returns a reader over what the decoy wrote."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setattr(sink, "HONEYPOTNG_LOG_DIR", log_dir)

    def read(phase=None):
        path = Path(log_dir) / "honeypot-ssh.json"
        if not path.exists():
            return []
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        if phase is None:
            return rows
        return [r for r in rows if (r.get("event") or {}).get("phase") == phase]

    return read


async def _probe(key_dir, **connect_kwargs):
    """Run one client connection against the decoy; auth is expected to fail."""
    honeypot = hp_ssh.SSHHoneypot()
    server = await asyncssh.create_server(
        lambda: hp_ssh._CaptureServer(honeypot),
        "127.0.0.1",
        0,
        server_host_keys=hp_ssh._host_keys(str(key_dir)),
        server_version=hp_ssh._server_version(honeypot.profile["banner"]),
    )
    try:
        # agent_path=None: without it asyncssh also offers whatever keys the developer's
        # ssh-agent holds, and the test would be asserting on their keyring.
        kwargs = {
            "known_hosts": None,
            "client_keys": [],
            "username": "root",
            "agent_path": None,
        }
        kwargs.update(connect_kwargs)
        with pytest.raises(asyncssh.Error):
            conn = await asyncssh.connect("127.0.0.1", server.get_port(), **kwargs)
            conn.close()
    finally:
        server.close()
        await server.wait_closed()
        # connection_lost runs on the next loop pass; the banner event is written there.
        await asyncio.sleep(0.05)


def test_a_password_over_256_bytes_is_captured_with_its_true_length(events, tmp_path):
    password = "A" * 300
    asyncio.run(_probe(tmp_path / "keys", password=password, preferred_auth=("password",)))

    rows = events("auth_password")
    assert rows, "no credential event was written"
    event = rows[0]["event"]
    assert event["password_len"] == 300
    assert event["password"] == password  # under the 1024-byte capture ceiling: stored whole
    assert event["password_truncated"] is False
    assert rows[0]["attack_type"] == "SSH_LONG_PASSWORD"
    assert rows[0]["severity"] == "HIGH"


def test_an_ordinary_password_is_captured_verbatim_and_not_flagged_long(events, tmp_path):
    asyncio.run(_probe(tmp_path / "keys", password="admin123", preferred_auth=("password",)))

    event = events("auth_password")[0]
    assert event["event"]["password"] == "admin123"
    assert event["event"]["password_len"] == 8
    assert event["attack_type"] == "SSH_CREDENTIAL_CAPTURE"
    assert event["severity"] == "MEDIUM"


def test_the_length_survives_a_password_past_the_capture_ceiling(events, tmp_path):
    password = "B" * 2000
    asyncio.run(_probe(tmp_path / "keys", password=password, preferred_auth=("password",)))

    event = events("auth_password")[0]["event"]
    # The bytes are capped, the measurement is not: ">256" stays decidable from the store.
    assert event["password_len"] == 2000
    assert event["password_truncated"] is True
    assert len(event["password"]) == hp_ssh.MAX_PASSWORD_CAPTURE


def test_every_attempt_on_one_connection_is_captured(events):
    """The CVE needs two attempts inside one connection — both have to be recorded.

    Driven against the server object rather than through a client, because asyncssh's own
    client stops after its first method is refused: a client-driven test would be asserting
    the client's manners, not the decoy's. The decoy's side is what matters here — asyncssh
    puts no server-side cap on attempts, so every one of them has to land as its own event,
    numbered, with the connection's peer attached.
    """
    server = hp_ssh._CaptureServer(hp_ssh.SSHHoneypot())

    assert server.validate_password("root", "first") is False
    assert server.validate_password("root", "C" * 300) is False
    assert server.validate_kbdint_response("root", ["third"]) is False

    rows = events("auth_password")
    assert [r["event"]["attempt"] for r in rows] == [1, 2, 3]
    assert [r["event"]["auth_method"] for r in rows] == [
        "password",
        "password",
        "keyboard-interactive",
    ]
    assert [r["attack_type"] for r in rows] == [
        "SSH_CREDENTIAL_CAPTURE",
        "SSH_LONG_PASSWORD",
        "SSH_CREDENTIAL_CAPTURE",
    ]
    # One connection: one peer for all of them, and exactly one banner event.
    assert len({r["peer_port"] for r in rows}) == 1
    assert len(events("banner_exchange")) == 1


def test_a_keyboard_interactive_answer_is_captured_like_a_password(events, tmp_path):
    """A stock sshd offers kbdint too, and some bots use only that method."""
    asyncio.run(
        _probe(
            tmp_path / "keys",
            password="D" * 300,
            preferred_auth=("keyboard-interactive",),
        )
    )

    rows = events("auth_password")
    assert len(rows) == 1
    assert rows[0]["event"]["auth_method"] == "keyboard-interactive"
    assert rows[0]["event"]["password_len"] == 300
    assert rows[0]["attack_type"] == "SSH_LONG_PASSWORD"


def test_an_offered_public_key_is_logged_as_an_indicator(events, tmp_path):
    key = asyncssh.generate_private_key("ssh-ed25519")
    asyncio.run(_probe(tmp_path / "keys", client_keys=[key], preferred_auth=("publickey",)))

    rows = events("auth_publickey")
    assert len(rows) == 1
    assert rows[0]["event"]["key_algorithm"] == "ssh-ed25519"
    assert rows[0]["event"]["key_fingerprint"] == key.get_fingerprint()


def test_the_banner_exchange_event_survives_the_rewrite(events, tmp_path):
    """60k rows a month of scan telemetry hang off this event; it must still be written."""
    asyncio.run(_probe(tmp_path / "keys", password="x", preferred_auth=("password",)))

    rows = events("banner_exchange")
    assert len(rows) == 1
    event = rows[0]["event"]
    assert event["server_banner"].startswith("SSH-2.0-")
    assert "AsyncSSH" in event["client_banner"]  # the client's own version, as it sent it
    assert rows[0]["attack_type"] == "SSH_SCAN"


def test_the_default_banner_names_a_version_the_cve_applies_to():
    """CVE-2026-123158 is fixed in 10.6p2, and only bites musl — so no glibc distro suffix."""
    banner = hp_ssh.SSHHoneypot().profile["banner"]
    match = re.fullmatch(r"SSH-2\.0-OpenSSH_(\d+)\.(\d+)(?:p(\d+))?", banner)
    assert match, f"{banner!r} is not a bare OpenSSH identification string"
    version = (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))
    assert version < (10, 6, 2), f"{banner} is already patched against CVE-2026-123158"


def test_a_broken_banner_override_cannot_stop_the_decoy_from_starting():
    assert hp_ssh._server_version("SSH-2.0-OpenSSH_9.9p2") == "OpenSSH_9.9p2"
    assert hp_ssh._server_version("  OpenSSH_9.9p2  ") == "OpenSSH_9.9p2"
    # A non-ASCII or empty override would make asyncssh refuse to listen at all.
    assert hp_ssh._server_version("OpenSSH_⑨") == "OpenSSH_9.9p2"
    assert hp_ssh._server_version("") == "OpenSSH_9.9p2"


def test_host_keys_are_generated_once_and_then_reused(tmp_path):
    """A host key that changes on every restart is a honeypot fingerprint."""
    first = hp_ssh._host_keys(str(tmp_path / "keys"))
    assert [Path(p).name for p in first] == ["ssh_host_ed25519_key", "ssh_host_rsa_key"]
    before = [Path(p).read_bytes() for p in first]

    second = hp_ssh._host_keys(str(tmp_path / "keys"))
    assert second == first
    assert [Path(p).read_bytes() for p in second] == before


def test_an_unwritable_key_dir_falls_back_to_an_ephemeral_key(tmp_path):
    """Losing restart-persistence beats losing every event on port 22."""
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")

    keys = hp_ssh._host_keys(str(blocker / "keys"))
    assert len(keys) == 2
    assert all(not isinstance(k, str) for k in keys)  # in-memory keys, not paths
