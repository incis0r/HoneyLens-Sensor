"""
honeypots/hp_ssh.py — SSH honeypot: full transport, credential capture
=======================================================================
Completes the SSH handshake (asyncssh), advertises publickey/password/
keyboard-interactive the way a stock sshd does, logs every credential the client
offers — and refuses all of them.

Why a real transport, 2026-11-09: until now this decoy answered with a banner and
nothing else, so the client never got past ``SSH_MSG_KEXINIT`` and a password was
never sent to it. Measured over the whole fleet history: 122,015 ``banner_exchange``
rows and 114,320 raw ``data`` rows, of which 95.8-99.95% are SSH binary packets
(KEXINIT and its continuation reads) — and not one captured credential. The only
decoy that has ever seen a cleartext SSH password is the PAN-OS one on 2200.

Why it refuses every password: asyncssh puts no server-side cap on authentication
attempts, so a rejected client burns its whole list into the event store on one
connection. The PAN-OS decoy accepts the first password and the cost is visible in
its data — all 4,949 credential connections on sensor-a carry exactly one attempt.
CVE-2026-123158 (OpenSSH before 10.6p2 on musl libc without PAM) needs *two*
attempts inside one connection, so accepting the first one is precisely the
behaviour that would hide the shape this decoy now exists to see. Refusing also
means no session is ever established: there is no shell behind this.

What this gives up: the raw-bytes path (``phase=data``) also caught whatever a
non-SSH client sent to port 22 — HTTP and TLS probes, a few hundred rows per sensor
per month (prod: 23 rows of 42,131) — and the verbatim KEXINIT algorithm list, which
nothing reads today (HASSH is an idea in ``docs/ja3-ja4-fingerprinting.md``, not an
implementation). asyncssh owns the socket now, so both are gone; the client's own
version string survives as ``client_banner``.

Run standalone:
    python -m honeylens.honeypots.hp_ssh
    HP_SSH_PORT=2222 python -m honeylens.honeypots.hp_ssh
"""

from __future__ import annotations

import asyncio
import logging
import os
import re

import asyncssh

from honeylens.honeypots import ssh_accept
from honeylens.honeypots._base import BaseHoneypot, log_event

logger = logging.getLogger("hp_ssh")

# The banner this decoy presents when nothing overrides it. An affected version is the
# whole point of the persona — see the comment on the "ssh" profile in honeypots_config.
DEFAULT_BANNER = "SSH-2.0-OpenSSH_9.9p2"

# CVE-2026-123158 fires on a password of 257-1024 bytes, so the LENGTH is the evidence.
# The PAN-OS decoy stores password[:200]: a 300-byte password lands there as exactly 200
# characters, with the true length unrecoverable, and ">256" becomes undecidable from the
# store. Keep the bytes up to the CVE's own ceiling, and always store the length as
# measured before any truncation.
MAX_PASSWORD_CAPTURE = 1024
LONG_PASSWORD_BYTES = 256

MAX_USERNAME_CAPTURE = 256

# Distinct public keys recorded on ONE connection. Public-key auth has no server-side
# attempt cap either, and unlike a password attempt each new key also grew `_seen_keys`,
# so a client offering keys in a loop bought unbounded memory AND an event apiece. 64 is
# far above any real client: OpenSSH offers what the agent holds, and a keyring that size
# is itself the finding. Past it the connection is still served and still refused — only
# its key offers stop being recorded, and the attempt counter already says how many came.
MAX_KEY_FINGERPRINTS = 64

# Host keys live on the identity volume: a host key that changes on every restart is a
# ready-made honeypot fingerprint, the same reason the PAN-OS serial number is kept there.
DEFAULT_HOST_KEY_DIR = "/var/lib/honeylens/identity/hostkeys"
_HOST_KEY_SPECS: tuple[tuple[str, str], ...] = (
    ("ssh_host_ed25519_key", "ssh-ed25519"),
    ("ssh_host_rsa_key", "ssh-rsa"),
)
_RSA_KEY_SIZE = 3072  # what a current sshd has; asyncssh would default to 2048


def _generate_key(alg: str):
    """One host key of the given algorithm."""
    if alg == "ssh-rsa":
        return asyncssh.generate_private_key(alg, key_size=_RSA_KEY_SIZE)
    return asyncssh.generate_private_key(alg)


def _sanitize(text: str) -> str:
    """Strip control characters and null bytes from decoded text."""
    text = text.replace("\x00", "").replace("\u0000", "")
    return re.sub(r"[\x00-\x1F\x7F]", "", text).strip()


def _server_version(raw: str) -> str:
    """The ``server_version`` to hand asyncssh: no ``SSH-2.0-`` prefix, ASCII only."""
    raw = (raw or "").strip()
    if raw.upper().startswith("SSH-2.0-"):
        raw = raw[len("SSH-2.0-") :]
    # A non-ASCII or control character here makes asyncssh refuse to start, which would turn
    # a cosmetic setting into a crash loop on the busiest port the sensor exposes.
    if not raw or not all(32 <= ord(c) < 127 for c in raw):
        logger.warning("HP_SSH_BANNER is not printable ASCII — using the default")
        return DEFAULT_BANNER[len("SSH-2.0-") :]
    return raw


def _host_keys(key_dir: str) -> list:
    """Persistent host keys, generated on first start.

    Falls back to an in-memory key per algorithm when the directory cannot be written:
    a decoy that refuses to start loses every event on port 22, which is a worse trade
    than a host key that does not survive a restart.
    """
    keys: list = []
    for filename, alg in _HOST_KEY_SPECS:
        path = os.path.join(key_dir, filename)
        try:
            if not os.path.exists(path):
                os.makedirs(key_dir, exist_ok=True)
                generated = _generate_key(alg)
                generated.write_private_key(path)
                os.chmod(path, 0o600)
                logger.info("generated %s host key: %s", alg, path)
            keys.append(path)
        except (OSError, ValueError) as exc:
            logger.warning(
                "cannot persist %s host key in %s (%s) — using an ephemeral one", alg, key_dir, exc
            )
            keys.append(_generate_key(alg))
    return keys


class _CaptureServer(asyncssh.SSHServer):
    """One connection: logs the banner exchange, then every credential offered."""

    def __init__(self, honeypot: SSHHoneypot):
        self._hp = honeypot
        self._conn: asyncssh.SSHServerConnection | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._attempts = 0
        self._banner_logged = False
        self._seen_keys: set[str] = set()
        # True until the accept limit says otherwise. Defaults to admitted because a
        # server object built directly — as the credential tests build one — was never
        # offered to the limit and must behave exactly as it always has.
        self._admitted = True
        self._keys_capped = False

    # ---- connection lifecycle ---------------------------------------------

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername")
        if peer:
            self._peer = (peer[0], peer[1] if len(peer) > 1 else 0)
        # Before anything is logged: a refused connection must cost one abort and no row.
        self._admitted = self._hp.accept_limit.admit(conn)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self._admitted:
            # Releasing here would hand back a slot this connection never held, and the
            # cap would climb by one for every refusal.
            return
        self._hp.accept_limit.release()
        # A bare banner grab never reaches begin_auth, and that is most of the traffic on
        # 22, so the scan event is logged from whichever hook fires first.
        self._log_banner()

    def _client_banner(self) -> str:
        if self._conn is None:
            return ""
        return _sanitize(self._conn.get_extra_info("client_version", "") or "")

    def _log_banner(self) -> None:
        if not self._admitted or self._banner_logged:
            return
        self._banner_logged = True
        client_banner = self._client_banner()
        log_event(
            self._hp.PROTOCOL,
            self._peer,
            {
                "phase": "banner_exchange",
                "client_banner": client_banner,
                "server_banner": self._hp.server_banner,
                "dst_port": self._hp.port,
            },
            attack_type="SSH_SCAN",
            severity="LOW",
        )
        self._hp.logger.info(
            "[SSH] %s:%d banner: %s", self._peer[0], self._peer[1], client_banner[:120]
        )

    # ---- authentication: everything is logged, nothing is accepted --------

    def begin_auth(self, username: str) -> bool:
        self._log_banner()
        return True  # auth required: never let "none" through as a free pass

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        self._record_credential(username, password, "password")
        return False

    def kbdint_auth_supported(self) -> bool:
        # A stock sshd with PasswordAuthentication on also offers keyboard-interactive, and
        # some bots use only that method; without it they would authenticate against nothing.
        return True

    def get_kbdint_challenge(self, username: str, lang: str, submethods: str):
        return "", "", "", (("Password: ", False),)

    def validate_kbdint_response(self, username: str, responses) -> bool:
        for response in responses:
            self._record_credential(username, response, "keyboard-interactive")
        return False

    def public_key_auth_supported(self) -> bool:
        # Advertised because a real sshd advertises it, and the offered key's fingerprint is
        # an indicator in its own right. Never accepted: there are no authorized keys here.
        return True

    def validate_public_key(self, username: str, key) -> bool:
        if not self._admitted:
            return False
        try:
            fingerprint = key.get_fingerprint()
            algorithm = key.get_algorithm()
        except (AttributeError, ValueError):  # silent: a key asyncssh parsed but cannot describe
            fingerprint, algorithm = "", ""
        # Public-key auth is two-phase: the client first asks whether the key would be
        # accepted (no signature), then offers it for real. Both arrive here, and the same
        # key logged twice would double-count one indicator.
        if fingerprint and fingerprint in self._seen_keys:
            return False
        if len(self._seen_keys) >= MAX_KEY_FINGERPRINTS:
            if not self._keys_capped:
                self._keys_capped = True
                self._hp.logger.warning(
                    "[SSH] %s:%d offered more than %d distinct keys; no longer recording them",
                    self._peer[0],
                    self._peer[1],
                    MAX_KEY_FINGERPRINTS,
                )
            return False
        self._seen_keys.add(fingerprint)
        self._attempts += 1
        log_event(
            self._hp.PROTOCOL,
            self._peer,
            {
                "phase": "auth_publickey",
                "username": username[:MAX_USERNAME_CAPTURE],
                "key_algorithm": algorithm,
                "key_fingerprint": fingerprint,
                "auth_method": "publickey",
                "attempt": self._attempts,
                "client_banner": self._client_banner(),
                "dst_port": self._hp.port,
            },
            attack_type="SSH_CREDENTIAL_CAPTURE",
            severity="MEDIUM",
        )
        return False

    def _record_credential(self, username: str, password: str, method: str) -> None:
        if not self._admitted:
            return
        self._log_banner()
        self._attempts += 1
        password = password or ""
        length = len(password)
        is_long = length > LONG_PASSWORD_BYTES
        log_event(
            self._hp.PROTOCOL,
            self._peer,
            {
                "phase": "auth_password",
                "username": username[:MAX_USERNAME_CAPTURE],
                # password_len comes BEFORE the password: json.dumps keeps insertion order and
                # payload is capped, so the one field that cannot be reconstructed is written
                # where no truncation can reach it. The password itself is stored verbatim —
                # not run through _sanitize — because a control character in it is evidence;
                # NUL stripping happens once, in the ingest.
                "password_len": length,
                "password_truncated": length > MAX_PASSWORD_CAPTURE,
                "password": password[:MAX_PASSWORD_CAPTURE],
                "auth_method": method,
                "attempt": self._attempts,
                "client_banner": self._client_banner(),
                "dst_port": self._hp.port,
            },
            # The decoy knows the length exactly, so it states the shape and not a CVE: a
            # 257-1024 byte password is what CVE-2026-123158 needs, but a long password on
            # its own is not proof that anyone exploited it. Binding the CVE wants the
            # second attempt in the same connection too, and that correlation is the
            # analyst's job, not this decoy's.
            attack_type="SSH_LONG_PASSWORD" if is_long else "SSH_CREDENTIAL_CAPTURE",
            severity="HIGH" if is_long else "MEDIUM",
        )
        self._hp.logger.info(
            "[SSH] %s:%d %s attempt %d user=%s pwlen=%d",
            self._peer[0],
            self._peer[1],
            method,
            self._attempts,
            username[:64],
            length,
        )


class SSHHoneypot(BaseHoneypot):
    """SSH honeypot that finishes the handshake and captures credentials."""

    PROTOCOL = "ssh"
    DEFAULT_PORT = 22
    TTL_PROFILE = "linux"

    def __init__(self):
        super().__init__()
        # `BaseHoneypot._handler` enforces MAX_CONNECTIONS for every other decoy; asyncssh
        # owns this socket, so the same cap is applied on its accept path instead.
        self.accept_limit = ssh_accept.SSHAcceptLimit(name=self.PROTOCOL)

    @property
    def server_banner(self) -> str:
        """The identification string as it goes on the wire, with the SSH-2.0- prefix."""
        return f"SSH-2.0-{_server_version(self.profile.get('banner', DEFAULT_BANNER))}"

    # BaseHoneypot's plain TCP path is unused: asyncssh owns the socket, because the
    # handshake cannot be resumed from bytes already read out of the kernel buffer.
    async def handle_connection(self, reader, writer, peer):  # pragma: no cover - not reachable
        raise NotImplementedError("hp_ssh serves SSH through asyncssh, not raw TCP")

    async def serve(self) -> None:
        version = _server_version(self.profile.get("banner", DEFAULT_BANNER))
        key_dir = os.environ.get("HP_SSH_HOST_KEY_DIR", DEFAULT_HOST_KEY_DIR)
        await asyncssh.create_server(
            lambda: _CaptureServer(self),
            "0.0.0.0",
            self.port,
            server_host_keys=_host_keys(key_dir),
            server_version=version,
            # Chosen, not inherited: asyncssh would grant 120 s of pre-auth grace, and
            # every connection here spends all of it, because no password is ever accepted.
            login_timeout=ssh_accept.SSH_LOGIN_TIMEOUT,
        )
        self.logger.info("SSH honeypot listening on 0.0.0.0:%d as SSH-2.0-%s", self.port, version)
        await asyncio.Event().wait()

    def run(self) -> None:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
        self.logger.info(
            "Starting ssh honeypot on port %d (profile: %s)",
            self.port,
            self.TTL_PROFILE,
        )
        try:
            asyncio.run(self.serve())
        except KeyboardInterrupt:
            self.logger.info("Shutting down ssh honeypot")


if __name__ == "__main__":
    SSHHoneypot().run()
