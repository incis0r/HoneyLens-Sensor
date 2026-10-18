"""
honeypots/hp_ssh.py — Modular SSH honeypot service
====================================================
Captures SSH banner exchanges, key-exchange data, and any raw bytes
sent by attackers. Logs everything via log_event() to the database.

Run standalone:
    python -m honeypots.hp_ssh
    HP_SSH_PORT=2222 python -m honeypots.hp_ssh
"""

from __future__ import annotations

import asyncio
import logging
import re

from honeylens.honeypots._base import BaseHoneypot, log_event


def _sanitize(text: str) -> str:
    """Strip control characters and null bytes from decoded text."""
    text = text.replace("\x00", "").replace("\u0000", "")
    return re.sub(r"[\x00-\x1F\x7F]", "", text).strip()


class SSHHoneypot(BaseHoneypot):
    """Low-interaction SSH honeypot.

    Performs a banner exchange, captures the client banner and any
    subsequent key-exchange / authentication bytes the attacker sends.
    """

    PROTOCOL = "ssh"
    DEFAULT_PORT = 22
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 120  # SSH scanners can be slow

    # ---- connection handler ------------------------------------------------

    async def handle_connection(self, reader, writer, peer):
        # Build the server banner from config (must end with \r\n)
        banner_text = self.profile.get("banner", "SSH-2.0-OpenSSH_8.2p1")
        if not banner_text.startswith("SSH-"):
            banner_text = f"SSH-2.0-{banner_text}"
        banner = f"{banner_text}\r\n".encode()

        # 1. Send server banner
        writer.write(banner)
        await writer.drain()

        # 2. Read client banner (first line the client sends)
        try:
            client_banner_raw = await asyncio.wait_for(
                reader.readline(),
                timeout=30,
            )
        except (TimeoutError, ConnectionError):
            return

        client_banner = _sanitize(client_banner_raw.decode(errors="ignore"))

        log_event(
            self.PROTOCOL,
            peer,
            {
                "phase": "banner_exchange",
                "client_banner": client_banner,
                "server_banner": banner_text,
                "dst_port": self.port,
            },
            attack_type="SSH_SCAN",
            severity="LOW",
        )

        self.logger.info(
            "[SSH] %s:%d banner: %s",
            peer[0],
            peer[1],
            client_banner[:120],
        )

        # 3. Continue reading key-exchange / auth data until the client
        #    disconnects or we hit the timeout set by BaseHoneypot._handler.
        try:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=60)
                if not data:
                    break

                log_event(
                    self.PROTOCOL,
                    peer,
                    {
                        "phase": "data",
                        "hex": data[:256].hex(),
                        "size": len(data),
                        "dst_port": self.port,
                    },
                )
        except (TimeoutError, ConnectionError) as exc:  # silent: expected normal client disconnect
            logging.getLogger(__name__).debug("ignored: %s", exc)


if __name__ == "__main__":
    SSHHoneypot().run()
