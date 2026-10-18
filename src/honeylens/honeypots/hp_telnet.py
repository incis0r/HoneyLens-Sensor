"""
honeypots/hp_telnet.py — Modular Telnet honeypot service
=========================================================
Captures login credentials from Telnet connections. Sends IAC
negotiation bytes, presents a login prompt, and allows up to
3 authentication attempts before closing.

Run standalone:
    python -m honeypots.hp_telnet
    HP_TELNET_PORT=2323 python -m honeypots.hp_telnet
"""

from __future__ import annotations

import asyncio
import logging
import re

from honeylens.honeypots._base import BaseHoneypot, log_event


def _sanitize(text: str) -> str:
    """Strip control characters, null bytes, and IAC sequences."""
    text = text.replace("\x00", "").replace("\u0000", "")
    return re.sub(r"[\x00-\x1F\x7F]", "", text).strip()


class TelnetHoneypot(BaseHoneypot):
    """Low-interaction Telnet honeypot.

    Performs minimal IAC negotiation, presents a login banner, and
    captures username/password pairs across multiple retry attempts.
    """

    PROTOCOL = "telnet"
    DEFAULT_PORT = 23
    TTL_PROFILE = "linux"

    # ---- connection handler ------------------------------------------------

    async def handle_connection(self, reader, writer, peer):
        banner = self.profile.get("banner", "SwiftTrans Gateway")
        self.profile.get("hostname", "gateway")
        login_prompt = self.profile.get("login_prompt", "login: ")

        # Minimal IAC negotiation
        writer.write(
            b"\xff\xfd\x01"  # IAC DO ECHO
            b"\xff\xfd\x1f"  # IAC DO NAWS
            b"\xff\xfb\x01"  # IAC WILL ECHO
            b"\xff\xfb\x03"  # IAC WILL SGA
        )
        await writer.drain()

        writer.write(f"\r\n{banner}\r\n{login_prompt}".encode())
        await writer.drain()

        max_attempts = 3
        try:
            for attempt in range(max_attempts):
                username_raw = await asyncio.wait_for(reader.readline(), timeout=60)
                username = _sanitize(username_raw.decode(errors="ignore"))

                writer.write(b"Password: ")
                await writer.drain()

                password_raw = await asyncio.wait_for(reader.readline(), timeout=60)
                password = _sanitize(password_raw.decode(errors="ignore"))

                phase = "auth" if attempt == 0 else "auth_retry"
                log_event(
                    self.PROTOCOL,
                    peer,
                    {
                        "phase": phase,
                        "username": username,
                        "password": password,
                        "attempt": attempt + 1,
                        "dst_port": self.port,
                    },
                    attack_type="CREDENTIAL_CAPTURE",
                    severity="MEDIUM",
                )

                self.logger.info(
                    "[Telnet] %s:%d auth(%d): %s / %s",
                    peer[0],
                    peer[1],
                    attempt + 1,
                    username,
                    password,
                )

                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()

                if attempt < max_attempts - 1:
                    writer.write(login_prompt.encode())
                    await writer.drain()

        except (TimeoutError, ConnectionError) as exc:  # silent: expected normal client disconnect
            logging.getLogger(__name__).debug("ignored: %s", exc)


if __name__ == "__main__":
    TelnetHoneypot().run()
