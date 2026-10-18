#!/usr/bin/env python3
"""
honeypots/hp_postgres.py — PostgreSQL Honeypot
================================================
Simulates a PostgreSQL server. Handles the startup message (including
SSL negotiation), captures username/database, requests MD5 password
authentication, logs the hash, then sends an auth-failed error.

Run: python -m honeypots.hp_postgres
Service: sensor-hp-postgres (port 5432)
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event


class PostgresHoneypot(BaseHoneypot):
    PROTOCOL = "postgres"
    DEFAULT_PORT = 5432
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 60

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[PG] Connection from %s:%d", peer[0], peer[1])

        try:
            # Read startup message
            hdr = await asyncio.wait_for(reader.readexactly(4), timeout=30)
            msg_len = struct.unpack(">I", hdr)[0]
            body = await asyncio.wait_for(reader.readexactly(msg_len - 4), timeout=30)

            # Handle SSLRequest (magic 80877103)
            if msg_len == 8 and struct.unpack(">I", body)[0] == 80877103:
                writer.write(b"N")  # refuse SSL
                await writer.drain()
                # Read actual startup message
                hdr = await asyncio.wait_for(reader.readexactly(4), timeout=30)
                msg_len = struct.unpack(">I", hdr)[0]
                body = await asyncio.wait_for(reader.readexactly(msg_len - 4), timeout=30)

            # Parse startup parameters (key\x00value\x00 pairs after 4-byte version)
            params = {}
            parts = body[4:].split(b"\x00")
            for i in range(0, len(parts) - 1, 2):
                k = parts[i].decode(errors="ignore")
                v = parts[i + 1].decode(errors="ignore") if i + 1 < len(parts) else ""
                if k:
                    params[k] = v

            username = params.get("user", "unknown")
            database = params.get("database", "unknown")

            log_event(
                self.PROTOCOL,
                peer,
                {
                    "dst_port": self.port,
                    "phase": "startup",
                    "rule": "pg_startup",
                    "username": username,
                    "database": database,
                    "params": params,
                    "payload": f"user={username} db={database}",
                },
            )
            self.logger.info("[PG] %s user=%s db=%s", peer[0], username, database)

            # Send AuthenticationMD5Password (type R, method=5, 4-byte salt)
            salt = b"\x01\x02\x03\x04"
            auth_msg = b"R" + struct.pack(">I", 12) + struct.pack(">I", 5) + salt
            writer.write(auth_msg)
            await writer.drain()

            # Read password message (tag 'p')
            await asyncio.wait_for(reader.readexactly(1), timeout=30)
            pw_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=30)
            pw_len = struct.unpack(">I", pw_hdr)[0]
            pw_body = await asyncio.wait_for(reader.readexactly(pw_len - 4), timeout=30)

            log_event(
                self.PROTOCOL,
                peer,
                {
                    "dst_port": self.port,
                    "phase": "auth",
                    "rule": "pg_auth",
                    "username": username,
                    "password_hash": pw_body.hex(),
                },
                attack_type="CREDENTIAL_CAPTURE",
                severity="HIGH",
            )

            # Send ErrorResponse — authentication failed
            err = b"SFATAL\x00VFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00"
            writer.write(b"E" + struct.pack(">I", len(err) + 4) + err)
            await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    PostgresHoneypot().run()
