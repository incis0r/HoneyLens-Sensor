"""
honeypots/hp_vnc.py — Modular VNC honeypot service
====================================================
Performs the RFB (Remote Framebuffer) handshake: version exchange,
VNC authentication with a random challenge, and captures the
client's encrypted auth response. Logs via log_event().

Run standalone:
    python -m honeypots.hp_vnc
    HP_VNC_PORT=5900 python -m honeypots.hp_vnc
"""

from __future__ import annotations

import asyncio
import os
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event


class VNCHoneypot(BaseHoneypot):
    """Low-interaction VNC (RFB) honeypot.

    Sends an RFB version string, negotiates VNC authentication,
    issues a random 16-byte challenge, and captures the DES-encrypted
    response (which can be cracked offline to recover the password).
    """

    PROTOCOL = "vnc"
    DEFAULT_PORT = 5900
    TTL_PROFILE = "linux"

    # RFB security types
    SEC_VNC_AUTH = 2

    async def handle_connection(self, reader, writer, peer):
        version = self.profile.get("version", "3.8")
        self.profile.get("desktop_name", "honeypot:0")

        try:
            # 1. Send RFB server version
            server_version = f"RFB 00{version[0]}.00{version[2]}\n".encode()
            writer.write(server_version)
            await writer.drain()

            # 2. Read client version (12 bytes: "RFB 003.008\n")
            client_ver_raw = await asyncio.wait_for(
                reader.readexactly(12),
                timeout=30,
            )
            client_ver = client_ver_raw.decode(errors="ignore").strip()

            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "version_exchange",
                    "client_version": client_ver,
                    "server_version": server_version.decode().strip(),
                    "dst_port": self.port,
                },
                attack_type="VNC_SCAN",
                severity="LOW",
            )

            self.logger.info(
                "[VNC] %s:%d version: %s",
                peer[0],
                peer[1],
                client_ver,
            )

            # 3. Send security types: count=1, type=VNC_AUTH (2)
            writer.write(struct.pack("B", 1) + struct.pack("B", self.SEC_VNC_AUTH))
            await writer.drain()

            # 4. Read client security type selection (1 byte)
            sec_choice = await asyncio.wait_for(
                reader.readexactly(1),
                timeout=30,
            )

            # 5. Send random 16-byte VNC auth challenge
            challenge = os.urandom(16)
            writer.write(challenge)
            await writer.drain()

            # 6. Read 16-byte DES-encrypted response
            response = await asyncio.wait_for(
                reader.readexactly(16),
                timeout=30,
            )

            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "vnc_auth",
                    "challenge_hex": challenge.hex(),
                    "response_hex": response.hex(),
                    "security_type": sec_choice[0],
                    "dst_port": self.port,
                },
                attack_type="VNC_AUTH_ATTEMPT",
                severity="HIGH",
            )

            self.logger.info(
                "[VNC] %s:%d auth attempt captured (challenge=%s)",
                peer[0],
                peer[1],
                challenge.hex()[:16] + "...",
            )

            # 7. Send SecurityResult: auth failed (uint32 = 1)
            writer.write(struct.pack(">I", 1))
            await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError) as exc:
            self.logger.debug("ignored: %s", exc)


if __name__ == "__main__":
    VNCHoneypot().run()
