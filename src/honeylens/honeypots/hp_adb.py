"""
honeypots/hp_adb.py — Modular ADB (Android Debug Bridge) honeypot service
==========================================================================
Emulates an exposed ADB daemon to capture shell commands, miner payloads,
and C2 connections from IoT botnets targeting open ADB ports.

Run standalone:
    python -m honeypots.hp_adb
    HP_ADB_PORT=5555 python -m honeypots.hp_adb
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event


class ADBHoneypot(BaseHoneypot):
    """Low-interaction ADB honeypot for capturing botnet shell commands."""

    PROTOCOL = "adb"
    DEFAULT_PORT = 5555
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 90

    # ADB protocol constants (little-endian uint32)
    CMD_CNXN = 0x4E584E43  # "CNXN"
    CMD_OPEN = 0x4E45504F  # "OPEN"
    CMD_WRTE = 0x45545257  # "WRTE"
    CMD_OKAY = 0x59414B4F  # "OKAY"
    CMD_CLSE = 0x45534C43  # "CLSE"
    CMD_AUTH = 0x48545541  # "AUTH"

    ADB_VERSION = 0x01000000
    MAX_PAYLOAD = 4096
    HEADER_SIZE = 24

    def __init__(self):
        super().__init__()
        self._device_model = self.profile.get("device_model", "Pixel 6")
        self._android_ver = self.profile.get("android_ver", "13")
        self._api_level = self.profile.get("api_level", "33")
        self._build = self.profile.get("build", "TQ3A.230901.001")
        self._serial = self.profile.get("serial", "emulator-5554")
        self._local_id = 1

    # ---- ADB protocol helpers -----------------------------------------------

    @staticmethod
    def _adb_header(command: int, arg0: int, arg1: int, data: bytes) -> bytes:
        """Build a 24-byte ADB message header + data payload."""
        data_len = len(data)
        data_checksum = sum(data) & 0xFFFFFFFF
        magic = command ^ 0xFFFFFFFF
        hdr = struct.pack("<IIIIII", command, arg0, arg1, data_len, data_checksum, magic)
        return hdr + data

    @staticmethod
    def _parse_adb_header(data: bytes) -> dict | None:
        """Parse a 24-byte ADB header. Returns None if invalid."""
        if len(data) < 24:
            return None
        cmd, arg0, arg1, data_len, data_csum, magic = struct.unpack("<IIIIII", data[:24])
        if magic != (cmd ^ 0xFFFFFFFF):
            return None
        return {
            "command": cmd,
            "arg0": arg0,
            "arg1": arg1,
            "data_length": data_len,
            "data_checksum": data_csum,
        }

    def _device_banner(self) -> bytes:
        """Build the device banner string for CNXN response."""
        banner = (
            f"device::ro.product.model={self._device_model};"
            f"ro.product.device={self._serial};"
            f"ro.build.display.id={self._build};"
            f"ro.build.version.release={self._android_ver};"
            f"ro.build.version.sdk={self._api_level}"
        )
        return banner.encode("utf-8")

    def _cnxn_response(self) -> bytes:
        """Build a CNXN reply with device banner."""
        banner = self._device_banner()
        return self._adb_header(self.CMD_CNXN, self.ADB_VERSION, self.MAX_PAYLOAD, banner)

    def _okay_response(self, local_id: int, remote_id: int) -> bytes:
        return self._adb_header(self.CMD_OKAY, local_id, remote_id, b"")

    def _clse_response(self, local_id: int, remote_id: int) -> bytes:
        return self._adb_header(self.CMD_CLSE, local_id, remote_id, b"")

    # ---- connection handler -------------------------------------------------

    async def handle_connection(self, reader, writer, peer):
        msg_count = 0
        try:
            while msg_count < 100:
                raw_hdr = await asyncio.wait_for(reader.readexactly(self.HEADER_SIZE), timeout=30)
                hdr = self._parse_adb_header(raw_hdr)
                if hdr is None:
                    break

                # Read data payload if present
                payload = b""
                if hdr["data_length"] > 0:
                    read_len = min(hdr["data_length"], self.MAX_PAYLOAD)
                    payload = await asyncio.wait_for(reader.readexactly(read_len), timeout=15)
                    # Discard excess
                    excess = hdr["data_length"] - read_len
                    if excess > 0:
                        await reader.readexactly(excess)

                cmd = hdr["command"]

                if cmd == self.CMD_CNXN:
                    banner_str = payload.decode("utf-8", errors="replace")
                    self.logger.info("[ADB] %s CNXN: %s", peer[0], banner_str[:120])
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "connect",
                            "client_banner": banner_str[:500],
                            "dst_port": self.port,
                            "rule": "adb_connect",
                        },
                        attack_type="ADB_ATTACK",
                        severity="MEDIUM",
                    )
                    writer.write(self._cnxn_response())
                    await writer.drain()

                elif cmd == self.CMD_OPEN:
                    self._local_id += 1
                    remote_id = hdr["arg0"]
                    destination = payload.rstrip(b"\x00").decode("utf-8", errors="replace")
                    self.logger.warning("[ADB] %s OPEN: %s", peer[0], destination)
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "open",
                            "destination": destination,
                            "dst_port": self.port,
                            "rule": "adb_shell",
                        },
                        attack_type="ADB_ATTACK",
                        severity="HIGH",
                    )
                    writer.write(self._okay_response(self._local_id, remote_id))
                    await writer.drain()

                elif cmd == self.CMD_WRTE:
                    remote_id = hdr["arg0"]
                    local_id = hdr["arg1"]
                    cmd_text = payload.decode("utf-8", errors="replace").strip()
                    self.logger.warning("[ADB] %s WRTE: %s", peer[0], cmd_text[:200])
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "phase": "shell_command",
                            "payload": cmd_text[:2000],
                            "dst_port": self.port,
                            "rule": "adb_command",
                        },
                        attack_type="ADB_ATTACK",
                        severity="HIGH",
                    )
                    writer.write(self._okay_response(local_id, remote_id))
                    await writer.drain()

                elif cmd == self.CMD_CLSE:
                    self.logger.debug("[ADB] %s CLSE", peer[0])
                    writer.write(self._clse_response(hdr["arg1"], hdr["arg0"]))
                    await writer.drain()
                    break

                elif cmd == self.CMD_AUTH:
                    self.logger.info("[ADB] %s AUTH (ignored)", peer[0])

                else:
                    self.logger.debug("[ADB] %s Unknown cmd 0x%08X", peer[0], cmd)
                    break

                msg_count += 1

        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    ADBHoneypot().run()
