"""
honeypots/hp_dahua.py — Modular Dahua DVR honeypot service
============================================================
Emulates a Dahua DVR/XVR on port 37777, captures login attempts
from scanners and exploits targeting surveillance equipment.

Run standalone:
    python -m honeypots.hp_dahua
    HP_DAHUA_PORT=37777 python -m honeypots.hp_dahua
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event

# Dahua binary protocol constants
DAHUA_MAGIC = b"\xa0\x00\x00\x60"
HEADER_SIZE = 32
LOGIN_TYPE = 0x000000A0
DEVICE_INFO_TYPE = 0x000000A3


def _parse_header(data: bytes):
    """Parse a 32-byte Dahua protocol header.

    Returns (magic, msg_type, session, sequence, total_len, body_len) or None.
    """
    if len(data) < HEADER_SIZE:
        return None
    magic = data[0:4]
    msg_type, session, sequence, total_len, body_len = struct.unpack_from("<IIIII", data, 4)
    return magic, msg_type, session, sequence, total_len, body_len


def _build_response(msg_type: int, session: int, sequence: int, body: bytes) -> bytes:
    """Build a Dahua protocol response packet."""
    header = (
        DAHUA_MAGIC
        + struct.pack("<IIIII", msg_type, session, sequence, len(body), len(body))
        + b"\x00" * 8
    )
    return header + body


class DahuaHoneypot(BaseHoneypot):
    """Low-interaction Dahua DVR binary protocol honeypot.

    Parses the Dahua binary header, handles login and device-info
    packets, and captures credentials from authentication attempts.
    """

    PROTOCOL = "dahua"
    DEFAULT_PORT = 37777
    TTL_PROFILE = "linux"

    async def handle_connection(self, reader, writer, peer):
        model = self.profile.get("model", "DH-XVR5108HS-I3")
        firmware = self.profile.get("firmware", "4.003.0000000.1")
        serial = self.profile.get("serial", "6L08B6DPAZ12345")
        device_type = self.profile.get("device_type", "XVR")

        self.logger.info("[DAHUA] %s:%d connected", peer[0], peer[1])

        try:
            while True:
                header_data = await asyncio.wait_for(reader.readexactly(HEADER_SIZE), timeout=30)
                parsed = _parse_header(header_data)
                if parsed is None or parsed[0] != DAHUA_MAGIC:
                    self.logger.debug("[DAHUA] %s:%d bad magic", peer[0], peer[1])
                    break

                _magic, msg_type, session, sequence, _total_len, body_len = parsed

                body = b""
                if body_len > 0:
                    body = await asyncio.wait_for(
                        reader.readexactly(min(body_len, 8192)), timeout=10
                    )

                if msg_type == LOGIN_TYPE:
                    # Extract username from body (null-terminated string at offset 0)
                    username = body.split(b"\x00", 1)[0].decode(errors="ignore") if body else ""
                    password_hash = body[32:96].hex() if len(body) >= 96 else body.hex()

                    self.logger.info(
                        "[DAHUA] %s:%d login attempt: user=%s",
                        peer[0],
                        peer[1],
                        username,
                    )
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "auth",
                            "username": username,
                            "password_hash": password_hash,
                            "device_model": model,
                            "dst_port": self.port,
                        },
                        attack_type="DVR_ATTACK",
                        severity="HIGH",
                    )

                    # Login failure response
                    fail_body = b"\x01" + b"\x00" * 15  # error code 1 = auth failed
                    resp = _build_response(LOGIN_TYPE + 1, session, sequence, fail_body)
                    writer.write(resp)
                    await writer.drain()

                elif msg_type == DEVICE_INFO_TYPE:
                    self.logger.info("[DAHUA] %s:%d device info request", peer[0], peer[1])
                    info = (
                        f'{{"model":"{model}","firmware":"{firmware}",'
                        f'"serial":"{serial}","type":"{device_type}"}}'
                    ).encode()
                    resp = _build_response(DEVICE_INFO_TYPE + 1, session, sequence, info)
                    writer.write(resp)
                    await writer.drain()

                else:
                    self.logger.debug(
                        "[DAHUA] %s:%d unknown type 0x%08x", peer[0], peer[1], msg_type
                    )
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "unknown_packet",
                            "msg_type": f"0x{msg_type:08x}",
                            "body_len": body_len,
                            "dst_port": self.port,
                        },
                        attack_type="DVR_ATTACK",
                        severity="HIGH",
                    )
                    break

        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    DahuaHoneypot().run()
