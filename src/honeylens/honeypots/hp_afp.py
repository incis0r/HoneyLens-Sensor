#!/usr/bin/env python3
"""
honeypots/hp_afp.py — Apple Filing Protocol (AFP) Honeypot
===========================================================
Simulates an AFP file server at the DSI (Data Stream Interface) layer.
Captures login credentials and responds to GetSrvrInfo requests with
fake server identity.

Run: python -m honeypots.hp_afp
Service: sensor-hp-afp (port 548)
"""

from __future__ import annotations

import asyncio
import logging
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event

# DSI command codes
DSI_CLOSE_SESSION = 0x01
DSI_COMMAND = 0x02
DSI_OPEN_SESSION = 0x04

# AFP command codes (inside DSI_COMMAND payload)
AFP_GET_SRVR_INFO = 15
AFP_LOGIN = 18

DSI_HEADER_SIZE = 16


class AFPHoneypot(BaseHoneypot):
    PROTOCOL = "afp"
    DEFAULT_PORT = 548
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 60

    def __init__(self):
        super().__init__()
        p = self.profile
        self.server_name = p.get("server_name", "NAS-Backup-01")
        self.machine_type = p.get("machine_type", "Synology DS920+")
        self.shares = p.get("shares", ["backup", "photos", "documents", "media"])

    # ── DSI helpers ──────────────────────────────────────────────

    @staticmethod
    def _parse_dsi_header(data: bytes):
        """Parse 16-byte DSI header → (flags, command, requestID, errCode, totalDataLength, reserved)."""
        flags, command, request_id, err_code, total_len, reserved = struct.unpack(
            ">BBHIII", data[:DSI_HEADER_SIZE]
        )
        return flags, command, request_id, err_code, total_len, reserved

    @staticmethod
    def _build_dsi_reply(command: int, request_id: int, payload: bytes, err_code: int = 0) -> bytes:
        """Build a DSI reply frame (flags=0x01 for reply)."""
        header = struct.pack(">BBHIII", 0x01, command, request_id, err_code, len(payload), 0)
        return header + payload

    # ── AFP response builders ────────────────────────────────────

    def _build_srvr_info(self) -> bytes:
        """Minimal AFP GetSrvrInfo reply with server name, machine type, and AFP versions."""
        name_bytes = self.server_name.encode("utf-8")
        machine_bytes = self.machine_type.encode("utf-8")
        versions = [b"AFP3.4", b"AFP3.3", b"AFP3.2"]
        # Pascal-style: length-prefixed strings
        body = struct.pack("B", len(name_bytes)) + name_bytes
        body += struct.pack("B", len(machine_bytes)) + machine_bytes
        body += struct.pack("B", len(versions))
        for v in versions:
            body += struct.pack("B", len(v)) + v
        return body

    # ── Connection handler ───────────────────────────────────────

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[AFP] Connection from %s:%d", peer[0], peer[1])

        try:
            while True:
                raw_hdr = await asyncio.wait_for(reader.readexactly(DSI_HEADER_SIZE), timeout=30)
                _flags, command, req_id, _err_code, total_len, _ = self._parse_dsi_header(raw_hdr)

                payload = b""
                if total_len > 0:
                    payload = await asyncio.wait_for(reader.readexactly(total_len), timeout=30)

                if command == DSI_OPEN_SESSION:
                    reply = self._build_dsi_reply(DSI_OPEN_SESSION, req_id, b"\x00")
                    writer.write(reply)
                    await writer.drain()

                elif command == DSI_COMMAND and len(payload) >= 1:
                    afp_cmd = payload[0]

                    if afp_cmd == AFP_LOGIN:
                        # Payload after command byte: AFP version (pascal) then UAM + username
                        username, afp_version = "unknown", "unknown"
                        try:
                            idx = 1
                            ver_len = payload[idx]
                            idx += 1
                            afp_version = payload[idx : idx + ver_len].decode(errors="ignore")
                            idx += ver_len
                            uam_len = payload[idx]
                            idx += 1
                            idx += uam_len  # skip UAM name
                            user_len = payload[idx]
                            idx += 1
                            username = payload[idx : idx + user_len].decode(errors="ignore")
                        except (
                            IndexError,
                            ValueError,
                        ) as exc:  # silent: expected from malformed AFP login frame
                            logging.getLogger(__name__).debug("ignored: %s", exc)

                        self.logger.info(
                            "[AFP] Login attempt from %s — user: %s, version: %s",
                            peer[0],
                            username,
                            afp_version,
                        )
                        log_event(
                            self.PROTOCOL,
                            peer,
                            {
                                "dst_port": self.port,
                                "phase": "auth",
                                "rule": "afp_login",
                                "username": username,
                                "afp_version": afp_version,
                                "payload": payload[:128].hex(),
                            },
                            attack_type="AFP_ATTACK",
                            severity="HIGH",
                        )

                        # Reply: UserNotAuth error (-5023 → 0xFFFFEC81)
                        err_reply = self._build_dsi_reply(
                            DSI_COMMAND, req_id, b"", err_code=0xFFFFEC81
                        )
                        writer.write(err_reply)
                        await writer.drain()

                    elif afp_cmd == AFP_GET_SRVR_INFO:
                        info = self._build_srvr_info()
                        writer.write(self._build_dsi_reply(DSI_COMMAND, req_id, info))
                        await writer.drain()

                    else:
                        # Unknown AFP command — close gracefully
                        writer.write(
                            self._build_dsi_reply(DSI_COMMAND, req_id, b"", err_code=0xFFFFFFFF)
                        )
                        await writer.drain()

                elif command == DSI_CLOSE_SESSION:
                    break
                else:
                    break

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    AFPHoneypot().run()
