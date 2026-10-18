"""
honeypots/hp_ftp.py — Modular FTP honeypot service
====================================================
Emulates an FTP server, captures credentials and commands sent by
attackers. Handles USER, PASS, SYST, FEAT, QUIT, and logs everything.

Run standalone:
    python -m honeypots.hp_ftp
    HP_FTP_PORT=2121 python -m honeypots.hp_ftp
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


class FTPHoneypot(BaseHoneypot):
    """Low-interaction FTP honeypot.

    Sends an FTP banner, processes standard FTP commands, and captures
    credentials from USER/PASS exchanges.
    """

    PROTOCOL = "ftp"
    DEFAULT_PORT = 21
    TTL_PROFILE = "linux"

    # ---- connection handler ------------------------------------------------

    async def handle_connection(self, reader, writer, peer):
        banner = self.profile.get("banner", "FTP server ready.")
        self.profile.get("hostname", "ftp.swifttrans.local")

        writer.write(f"220 {banner}\r\n".encode())
        await writer.drain()

        current_user = None

        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=60)
                if not line:
                    break

                raw = _sanitize(line.decode(errors="ignore"))
                upper = raw.upper()

                log_event(
                    self.PROTOCOL,
                    peer,
                    {
                        "phase": "command",
                        "command": raw,
                        "dst_port": self.port,
                    },
                )

                if upper.startswith("USER"):
                    current_user = raw[5:].strip() if len(raw) > 5 else ""
                    self.logger.info("[FTP] %s:%d USER %s", peer[0], peer[1], current_user)
                    writer.write(b"331 Password required.\r\n")

                elif upper.startswith("PASS"):
                    password = raw[5:].strip() if len(raw) > 5 else ""
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "auth",
                            "username": current_user or "",
                            "password": password,
                            "dst_port": self.port,
                        },
                        attack_type="CREDENTIAL_CAPTURE",
                        severity="MEDIUM",
                    )
                    self.logger.info(
                        "[FTP] %s:%d auth: %s / %s",
                        peer[0],
                        peer[1],
                        current_user,
                        password,
                    )
                    writer.write(b"530 Login incorrect.\r\n")

                elif upper.startswith("QUIT"):
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break

                elif upper.startswith("SYST"):
                    writer.write(b"215 UNIX Type: L8\r\n")

                elif upper.startswith("FEAT"):
                    writer.write(b"211-Features:\r\n UTF8\r\n211 End\r\n")

                else:
                    writer.write(b"500 Unknown command.\r\n")

                await writer.drain()

        except (TimeoutError, ConnectionError) as exc:  # silent: expected normal client disconnect
            logging.getLogger(__name__).debug("ignored: %s", exc)


if __name__ == "__main__":
    FTPHoneypot().run()
