"""The two asyncssh decoys sit outside the accept-path limits every other decoy has.

`BaseHoneypot._handler` has enforced ``MAX_CONNECTIONS = 200`` and
``CONNECTION_TIMEOUT = 60`` since the first decoy shipped. Both SSH decoys hand the
socket to ``asyncssh.create_server`` instead, so that handler never runs and neither
limit applies to them: asyncssh's own ``_DEFAULT_LOGIN_TIMEOUT`` is 120 — twice our
own ceiling — and it caps nothing at all on concurrent connections.

**The cost is log and database amplification, not CPU.** Every password attempt writes
an event carrying up to ``MAX_PASSWORD_CAPTURE`` bytes, and nothing bounded how many
connections did that at once; the PAN-OS decoy accepts the password and starts a shell
session per connection on top of it. A fleet with a disk-pressure history pays for that
in the event store.

**What is deliberately NOT limited here:** attempts per connection. Refusing every
password so a client burns its whole list into one connection is the behaviour
CVE-2026-123158 detection is built on — see
`test_hp_ssh_credential_capture.test_every_attempt_on_one_connection_is_captured`. The
bound belongs on concurrency, which costs nothing to observe, not on the attempts,
which are the evidence.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

asyncssh = pytest.importorskip("asyncssh")

from honeylens.honeypots import honeypot_paloalto_ssh, hp_ssh, sink, ssh_accept  # noqa: E402
from honeylens.honeypots._base import BaseHoneypot  # noqa: E402


class _FakeConn:
    """Only what the accept path touches: a peer name and a transport to abort."""

    def __init__(self, peer=("203.0.113.9", 55000)):
        self._peer = peer
        self.aborted = 0

    def get_extra_info(self, name, default=None):
        if name == "peername":
            return self._peer
        if name == "client_version":
            return "SSH-2.0-TestClient"
        return default

    def abort(self):
        self.aborted += 1


@pytest.fixture()
def events(monkeypatch, tmp_path):
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


# ---- the shared limit itself -------------------------------------------------


def test_the_shared_limit_mirrors_the_cap_every_other_decoy_already_has():
    """Two constants, one contract. If the base moves, this test says the SSH path drifted."""
    assert ssh_accept.MAX_SSH_CONNECTIONS == BaseHoneypot.MAX_CONNECTIONS
    assert ssh_accept.SSH_LOGIN_TIMEOUT == BaseHoneypot.CONNECTION_TIMEOUT


def test_a_connection_under_the_cap_is_admitted_untouched():
    limit = ssh_accept.SSHAcceptLimit(max_connections=2)
    conn = _FakeConn()
    assert limit.admit(conn) is True
    assert conn.aborted == 0
    assert limit.live == 1


def test_the_connection_past_the_cap_is_refused_and_its_transport_aborted():
    limit = ssh_accept.SSHAcceptLimit(max_connections=2)
    assert limit.admit(_FakeConn()) is True
    assert limit.admit(_FakeConn()) is True

    third = _FakeConn()
    assert limit.admit(third) is False
    # Aborted by the limit itself, not by each caller: one shared accept path means the
    # two decoys cannot disagree about what refusing looks like.
    assert third.aborted == 1
    assert limit.live == 2
    assert limit.refused == 1


def test_a_closed_connection_frees_its_slot():
    limit = ssh_accept.SSHAcceptLimit(max_connections=1)
    assert limit.admit(_FakeConn()) is True
    assert limit.admit(_FakeConn()) is False
    limit.release()
    assert limit.live == 0
    assert limit.admit(_FakeConn()) is True


def test_a_release_that_was_never_admitted_cannot_drive_the_counter_negative():
    """A refused connection's `connection_lost` still fires. If that released a slot the
    cap would leak upward one refusal at a time, which is the opposite of a limit."""
    limit = ssh_accept.SSHAcceptLimit(max_connections=1)
    limit.release()
    limit.release()
    assert limit.live == 0
    assert limit.admit(_FakeConn()) is True
    assert limit.admit(_FakeConn()) is False


# ---- hp_ssh ------------------------------------------------------------------


def test_the_ssh_decoy_records_nothing_for_a_connection_it_refused(events):
    honeypot = hp_ssh.SSHHoneypot()
    honeypot.accept_limit = ssh_accept.SSHAcceptLimit(max_connections=1)
    admitted = hp_ssh._CaptureServer(honeypot)
    admitted.connection_made(_FakeConn())

    refused = hp_ssh._CaptureServer(honeypot)
    conn = _FakeConn(peer=("198.51.100.4", 44000))
    refused.connection_made(conn)
    assert conn.aborted == 1

    # Writing an event per refused connection would rebuild the amplification the cap
    # exists to stop: a flood would simply trade credential rows for refusal rows.
    assert refused.validate_password("root", "hunter2") is False
    refused.connection_lost(None)
    assert events() == []

    # And the slot the refused connection never held is not handed back on its close.
    assert honeypot.accept_limit.live == 1


def test_an_admitted_ssh_connection_still_captures_every_attempt(events):
    honeypot = hp_ssh.SSHHoneypot()
    honeypot.accept_limit = ssh_accept.SSHAcceptLimit(max_connections=1)
    server = hp_ssh._CaptureServer(honeypot)
    server.connection_made(_FakeConn())

    assert server.validate_password("root", "first") is False
    assert server.validate_password("root", "second") is False

    rows = events("auth_password")
    assert [r["event"]["attempt"] for r in rows] == [1, 2]
    server.connection_lost(None)
    assert honeypot.accept_limit.live == 0


def test_the_ssh_decoy_hands_asyncssh_an_explicit_login_timeout(monkeypatch):
    seen = {}

    async def fake_create_server(*args, **kwargs):
        seen.update(kwargs)
        raise _Stop

    monkeypatch.setattr(asyncssh, "create_server", fake_create_server)
    monkeypatch.setenv("HP_SSH_HOST_KEY_DIR", "/nonexistent-on-purpose")
    monkeypatch.setattr(hp_ssh, "_host_keys", lambda _d: [])

    with pytest.raises(_Stop):
        asyncio.run(hp_ssh.SSHHoneypot().serve())

    assert seen["login_timeout"] == ssh_accept.SSH_LOGIN_TIMEOUT


def test_publickey_fingerprints_are_bounded_on_one_connection(events):
    """`_seen_keys` grew one entry per distinct key offered, with nothing to stop it, and
    each entry also bought an event. A client offering thousands of keys on one
    connection is the same amplification as the password path."""
    honeypot = hp_ssh.SSHHoneypot()
    server = hp_ssh._CaptureServer(honeypot)
    server.connection_made(_FakeConn())

    class _Key:
        def __init__(self, n):
            self._n = n

        def get_fingerprint(self):
            return f"SHA256:key{self._n}"

        def get_algorithm(self):
            return "ssh-ed25519"

    for n in range(hp_ssh.MAX_KEY_FINGERPRINTS + 50):
        assert server.validate_public_key("root", _Key(n)) is False

    assert len(server._seen_keys) <= hp_ssh.MAX_KEY_FINGERPRINTS
    assert len(events("auth_publickey")) == hp_ssh.MAX_KEY_FINGERPRINTS


# ---- the PAN-OS decoy --------------------------------------------------------


class _Stop(Exception):
    """Ends `serve()` where the test has what it came for, before its forever-wait."""


def test_the_panos_decoy_hands_asyncssh_an_explicit_login_timeout(monkeypatch):
    seen = {}

    async def fake_create_server(*args, **kwargs):
        seen.update(kwargs)
        raise _Stop

    monkeypatch.setattr(asyncssh, "create_server", fake_create_server)
    monkeypatch.setattr(honeypot_paloalto_ssh.os.path, "exists", lambda _p: True)

    with pytest.raises(_Stop):
        asyncio.run(honeypot_paloalto_ssh.start_server("127.0.0.1", 0))

    assert seen["login_timeout"] == ssh_accept.SSH_LOGIN_TIMEOUT


def test_the_panos_decoy_refuses_past_the_cap_and_logs_no_credential(monkeypatch):
    """This decoy accepts the password and starts a shell session, so an unbounded accept
    path costs a session per connection on top of the event."""
    logged = []
    monkeypatch.setattr(
        honeypot_paloalto_ssh,
        "log_event",
        lambda *a, **k: logged.append((a, k)),
    )
    monkeypatch.setattr(
        honeypot_paloalto_ssh,
        "ACCEPT_LIMIT",
        ssh_accept.SSHAcceptLimit(max_connections=1),
    )

    first = honeypot_paloalto_ssh.PanosSSHServer()
    first.connection_made(_FakeConn())

    second = honeypot_paloalto_ssh.PanosSSHServer()
    conn = _FakeConn(peer=("198.51.100.7", 41000))
    second.connection_made(conn)
    assert conn.aborted == 1

    assert second.validate_password("admin", "admin") is False
    second.connection_lost(None)
    assert logged == []

    assert first.validate_password("admin", "admin") is True
    assert len(logged) == 1


# ---- on the wire -------------------------------------------------------------


def test_the_cap_holds_against_real_sockets(events, tmp_path):
    """The unit tests above drive a fake connection, so they cannot say whether asyncssh
    tolerates ``abort()`` from inside ``connection_made``. This one opens real sockets
    against a real listener: the second peer must be cut off and leave no row behind."""

    async def run():
        honeypot = hp_ssh.SSHHoneypot()
        honeypot.accept_limit = ssh_accept.SSHAcceptLimit(max_connections=1)
        server = await asyncssh.create_server(
            lambda: hp_ssh._CaptureServer(honeypot),
            "127.0.0.1",
            0,
            server_host_keys=hp_ssh._host_keys(str(tmp_path / "keys")),
            server_version="OpenSSH_9.9p2",
            login_timeout=ssh_accept.SSH_LOGIN_TIMEOUT,
        )
        port = next(iter(server.sockets)).getsockname()[1]

        # Slot taken, and held open: a raw socket that sends an identification string and
        # then says nothing is exactly the banner grab that dominates port 22.
        _held_r, held_w = await asyncio.open_connection("127.0.0.1", port)
        held_w.write(b"SSH-2.0-HeldOpen\r\n")
        await held_w.drain()
        await asyncio.sleep(0.1)
        assert honeypot.accept_limit.live == 1

        # Over the cap: the listener accepts the TCP connection and then drops it.
        refused_r, _refused_w = await asyncio.open_connection("127.0.0.1", port)
        assert await asyncio.wait_for(refused_r.read(), timeout=5) == b""
        assert honeypot.accept_limit.refused == 1
        assert honeypot.accept_limit.live == 1

        # And once the held connection closes, the next peer is served again.
        held_w.close()
        await asyncio.sleep(0.1)
        assert honeypot.accept_limit.live == 0

        after_r, after_w = await asyncio.open_connection("127.0.0.1", port)
        assert await asyncio.wait_for(after_r.read(len(b"SSH-2.0-OpenSSH_9.9p2")), timeout=5)
        after_w.close()
        await asyncio.sleep(0.1)

        server.close()
        return honeypot

    honeypot = asyncio.run(run())
    peers = {row["peer_ip"] for row in events()}
    assert peers <= {"127.0.0.1"}
    # The refused peer never reached begin_auth, so it owes exactly nothing; the held and
    # the later connection each owe one banner row.
    assert len(events("banner_exchange")) == 2
    assert honeypot.accept_limit.refused == 1
