"""
honeypots/hp_rsync.py — Modular rsync daemon honeypot service
==============================================================
Emulates an rsync daemon, captures module enumeration and auth
attempts from attackers probing for exposed rsync shares.

Run standalone:
    python -m honeypots.hp_rsync
    HP_RSYNC_PORT=873 python -m honeypots.hp_rsync
"""

from __future__ import annotations

import asyncio
import os
import re

from honeylens.honeypots._base import BaseHoneypot, log_event


def _sanitize(text: str) -> str:
    """Strip control characters and null bytes from decoded text."""
    text = text.replace("\x00", "").replace("\u0000", "")
    return re.sub(r"[\x00-\x1F\x7F]", "", text).strip()


class RsyncHoneypot(BaseHoneypot):
    """Low-interaction rsync daemon honeypot.

    Sends the rsyncd banner, handles module listing requests, and
    captures authentication attempts against advertised modules.
    """

    PROTOCOL = "rsync"
    DEFAULT_PORT = 873
    TTL_PROFILE = "linux"

    async def handle_connection(self, reader, writer, peer):
        version = self.profile.get("version", "31.0")
        modules = self.profile.get("modules", ["backup", "www", "etc"])
        motd = self.profile.get("motd", "")

        # Send server banner
        writer.write(f"@RSYNCD: {version}\n".encode())
        await writer.drain()

        # Read client version line
        line = await asyncio.wait_for(reader.readline(), timeout=30)
        if not line:
            return
        client_version = _sanitize(line.decode(errors="ignore"))
        self.logger.info("[RSYNC] %s:%d client version: %s", peer[0], peer[1], client_version)

        # Read the request (module name or #list)
        line = await asyncio.wait_for(reader.readline(), timeout=30)
        if not line:
            return
        request = _sanitize(line.decode(errors="ignore"))

        # Module listing
        if request == "" or request == "#list":
            self.logger.info("[RSYNC] %s:%d module listing request", peer[0], peer[1])
            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "module_list",
                    "message": "Client requested module listing",
                    "dst_port": self.port,
                },
                attack_type="RSYNC_RECON",
                severity="LOW",
            )

            if motd:
                writer.write(f"{motd}\n".encode())
            for mod in modules:
                writer.write(f"{mod}\n".encode())
            writer.write(b"@RSYNCD: EXIT\n")
            await writer.drain()
            return

        # Client sent a module name — require auth
        module_name = request
        self.logger.info("[RSYNC] %s:%d requesting module: %s", peer[0], peer[1], module_name)

        challenge = os.urandom(16).hex()
        writer.write(f"@RSYNCD: AUTHREQD {challenge}\n".encode())
        await writer.drain()

        # Read auth response: "user hash"
        line = await asyncio.wait_for(reader.readline(), timeout=30)
        if not line:
            return
        auth_line = _sanitize(line.decode(errors="ignore"))

        parts = auth_line.split(" ", 1)
        username = parts[0] if parts else ""
        auth_hash = parts[1] if len(parts) > 1 else ""

        self.logger.info(
            "[RSYNC] %s:%d auth attempt: user=%s hash=%s module=%s",
            peer[0],
            peer[1],
            username,
            auth_hash,
            module_name,
        )
        log_event(
            self.PROTOCOL,
            peer,
            {
                "phase": "auth",
                "username": username,
                "auth_hash": auth_hash,
                "module": module_name,
                "challenge": challenge,
                "dst_port": self.port,
            },
            attack_type="RSYNC_ATTACK",
            severity="MEDIUM",
        )

        writer.write(f"@ERROR: auth failed on module {module_name}\n".encode())
        await writer.drain()


if __name__ == "__main__":
    RsyncHoneypot().run()
