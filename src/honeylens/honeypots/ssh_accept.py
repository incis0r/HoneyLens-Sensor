"""honeypots/ssh_accept.py — the accept-path limits the two asyncssh decoys were missing
=======================================================================================
``hp_ssh`` and ``honeypot_paloalto_ssh`` are the only two decoys that do not serve their
socket through `BaseHoneypot._handler`: ``asyncssh.create_server`` owns it instead,
because an SSH handshake cannot be resumed from bytes already read out of the kernel
buffer. Both limits that handler has applied since the first decoy shipped were lost with
it, silently, on the two decoys whose business is collecting attacker input:

| limit                | every other decoy          | the asyncssh decoys, before this |
|----------------------|----------------------------|----------------------------------|
| concurrent sockets   | ``MAX_CONNECTIONS = 200``  | unbounded                        |
| seconds before auth  | ``CONNECTION_TIMEOUT = 60``| asyncssh's own default, **120**  |

The timeout was never absent, which is why it did not look like anything: asyncssh 2.24.0
resolves an unset ``login_timeout`` to ``_DEFAULT_LOGIN_TIMEOUT`` (120 s, as
``LoginGraceTime``). It is simply *unchosen*, and twice our own ceiling — and on
``hp_ssh`` every connection spends that whole grace period pre-auth, because
`validate_password` refuses every credential by design, so authentication never completes
and nothing else ends the connection early.

**What this bounds is the event store, not the CPU.** Each password attempt writes a row
carrying up to ``MAX_PASSWORD_CAPTURE`` bytes, each offered key writes another, and
nothing limited how many connections were doing that at the same time; the PAN-OS decoy
accepts the password and starts a shell session per connection on top of it. On a fleet
whose retention has already failed on disk pressure, log and database amplification is
the consequence that costs something.

**What is deliberately not limited is attempts per connection.** ``hp_ssh`` refuses every
password precisely so that a client burns its whole list into one connection:
CVE-2026-123158 needs *two* attempts inside one connection, and a decoy that disconnects
after N — or stops logging after N — would throw away the shape the decoy was built to
see. That requirement is pinned by
``test_hp_ssh_credential_capture.test_every_attempt_on_one_connection_is_captured``.
asyncssh offers no ``max_auth_attempts`` to reach for either (zero occurrences in 2.24.0).
The bound belongs on concurrency, which is free to observe, and not on the evidence.
"""

from __future__ import annotations

import logging

from honeylens.honeypots._base import BaseHoneypot

logger = logging.getLogger("ssh_accept")

# Deliberately the base class's own numbers rather than new ones: the asyncssh path is
# meant to be under the same contract as the other 43 decoys, not under a second opinion
# about what that contract should be. `test_ssh_accept_limits` fails if they drift.
MAX_SSH_CONNECTIONS = BaseHoneypot.MAX_CONNECTIONS
SSH_LOGIN_TIMEOUT = BaseHoneypot.CONNECTION_TIMEOUT


class SSHAcceptLimit:
    """How many SSH connections may be live at once, counted across one decoy.

    One object per decoy, consulted from ``connection_made`` and released from
    ``connection_lost``. It aborts the refused connection itself rather than returning a
    verdict for each caller to act on: two decoys deciding separately what "refused" means
    is how one of them ends up logging a flood it believes it rejected.
    """

    def __init__(self, max_connections: int = MAX_SSH_CONNECTIONS, *, name: str = "ssh"):
        self._max = max_connections
        self._name = name
        self._live = 0
        self._refused = 0
        self._warned = False

    @property
    def live(self) -> int:
        return self._live

    @property
    def refused(self) -> int:
        """Lifetime count of refused connections. Read by tests and by nothing else yet."""
        return self._refused

    def admit(self, conn) -> bool:
        """Count this connection in, or abort it and return False.

        The caller must log nothing for a refused connection. An event per refusal would
        rebuild the amplification this cap exists to stop — refusals arrive exactly when
        the decoy is saturated — so saturation is reported to the process log once per
        episode and to the counter always.
        """
        if self._live >= self._max:
            self._refused += 1
            if not self._warned:
                self._warned = True
                logger.warning(
                    "%s: %d concurrent connections reached, refusing until one closes",
                    self._name,
                    self._max,
                )
            try:
                conn.abort()
            except Exception as exc:  # silent: the peer may already be gone
                logging.getLogger(__name__).debug("ignored: %s", exc)
            return False
        self._live += 1
        return True

    def release(self) -> None:
        """Give back a slot taken by `admit`.

        ``connection_lost`` fires for a refused connection too, so this must never go
        below zero: a release the limit never granted would raise the effective cap by one
        per refusal, turning the limit into a counter that loosens under load. Callers
        pair this with their own admitted flag; the floor here is the backstop.
        """
        if self._live > 0:
            self._live -= 1
        if self._live < self._max:
            self._warned = False
