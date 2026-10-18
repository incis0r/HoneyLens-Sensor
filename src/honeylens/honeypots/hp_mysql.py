#!/usr/bin/env python3
"""
honeypots/hp_mysql.py — MySQL Honeypot
=======================================
Simulates a MySQL server. Sends a greeting packet with server version
and auth challenge, captures the client handshake (username + auth hash),
then replies with Access Denied.

Run: python -m honeypots.hp_mysql
Service: sensor-hp-mysql (port 3306)
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event


class MySQLHoneypot(BaseHoneypot):
    PROTOCOL = "mysql"
    DEFAULT_PORT = 3306
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 60

    def __init__(self):
        super().__init__()
        p = self.profile
        self.version = p.get("version", "5.7.99")
        self.server_id = p.get("server_id", 1)

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[MySQL] Connection from %s:%d", peer[0], peer[1])

        # Build greeting packet
        version = self.version.encode() + b"\x00"
        thread_id = struct.pack("<I", self.server_id)
        salt1 = b"\x41\x42\x43\x44\x45\x46\x47\x48"  # 8-byte scramble part 1
        cap_low = struct.pack("<H", 0xF7FF)
        charset = b"\x21"  # utf8
        status = struct.pack("<H", 0x0002)
        cap_high = struct.pack("<H", 0x0081)
        auth_len = b"\x15"  # 21 bytes total scramble
        reserved = b"\x00" * 10
        salt2 = b"\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x00"
        auth_plugin = b"mysql_native_password\x00"

        payload = (
            b"\x0a"
            + version
            + thread_id
            + salt1
            + b"\x00"
            + cap_low
            + charset
            + status
            + cap_high
            + auth_len
            + reserved
            + salt2
            + auth_plugin
        )

        pkt_len = struct.pack("<I", len(payload))[:3]
        writer.write(pkt_len + b"\x00" + payload)
        await writer.drain()

        try:
            # Read client handshake response
            hdr = await asyncio.wait_for(reader.readexactly(4), timeout=30)
            length = struct.unpack("<I", hdr[:3] + b"\x00")[0]
            body = await asyncio.wait_for(reader.readexactly(length), timeout=30)

            # Extract username: skip capabilities(4) + max_packet(4) + charset(1) + reserved(23)
            idx = 32
            username_end = body.find(b"\x00", idx)
            username = (
                body[idx:username_end].decode(errors="ignore") if username_end > idx else "unknown"
            )

            log_event(
                self.PROTOCOL,
                peer,
                {
                    "dst_port": self.port,
                    "phase": "auth",
                    "rule": "mysql_auth",
                    "username": username,
                    "client_hex": body[:64].hex(),
                },
                attack_type="CREDENTIAL_CAPTURE",
                severity="HIGH",
            )
            self.logger.info("[MySQL] %s auth user: %s", peer[0], username)

            # Send ERR packet — access denied
            err_payload = (
                b"\xff"
                + struct.pack("<H", 1045)
                + b"#28000"
                + f"Access denied for user '{username}'".encode()
                + b"\x00"
            )
            err_len = struct.pack("<I", len(err_payload))[:3]
            writer.write(err_len + b"\x02" + err_payload)
            await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    MySQLHoneypot().run()
