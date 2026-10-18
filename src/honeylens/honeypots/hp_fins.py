#!/usr/bin/env python3
"""
honeypots/hp_fins.py — Omron FINS Honeypot
============================================
Simulates an Omron FINS/TCP PLC (CJ2M series). Responds to node address
negotiation and FINS frame commands, logging all ICS-relevant events.

Run: python -m honeypots.hp_fins
Service: sensor-hp-fins (port 9600)
"""

from __future__ import annotations

import asyncio
import struct
import time

from honeylens.honeypots._base import BaseHoneypot, log_event

# FINS TCP header constants
FINS_MAGIC = b"FINS"  # 0x46494E53
CMD_NODE_ADDR_REQ = 0x00000000
CMD_NODE_ADDR_RESP = 0x00000001
CMD_FRAME_SEND = 0x00000002
CMD_FRAME_RESP = 0x00000003

# MRC/SRC command definitions: (mrc, src) -> (name, attack_type, severity)
FINS_COMMANDS = {
    (0x01, 0x01): ("Memory Area Read", "ICS_RECON", "LOW"),
    (0x01, 0x02): ("Memory Area Write", "ICS_ATTACK", "HIGH"),
    (0x01, 0x03): ("Memory Area Fill", "ICS_ATTACK", "HIGH"),
    (0x02, 0x01): ("Parameter Area Read", "ICS_RECON", "MEDIUM"),
    (0x02, 0x02): ("Parameter Area Write", "ICS_ATTACK", "HIGH"),
    (0x03, 0x06): ("CPU Unit Status Read", "ICS_RECON", "MEDIUM"),
    (0x04, 0x01): ("Run", "ICS_ATTACK", "CRITICAL"),
    (0x04, 0x02): ("Stop", "ICS_ATTACK", "CRITICAL"),
    (0x05, 0x01): ("Controller Data Read", "ICS_RECON", "MEDIUM"),
    (0x06, 0x01): ("Status Read", "ICS_RECON", "MEDIUM"),
    (0x07, 0x01): ("Clock Read", "ICS_RECON", "LOW"),
    (0x07, 0x02): ("Clock Write", "ICS_ATTACK", "MEDIUM"),
    (0x26, 0x01): ("Program Area Read", "ICS_RECON", "HIGH"),
    (0x26, 0x02): ("Program Area Write", "ICS_ATTACK", "CRITICAL"),
}

FINS_TCP_HEADER_LEN = 16
FINS_FRAME_HEADER_LEN = 10  # ICF..SID (before MRC/SRC)


class FinsHoneypot(BaseHoneypot):
    PROTOCOL = "fins"
    DEFAULT_PORT = 9600
    TTL_PROFILE = "plc"
    CONNECTION_TIMEOUT = 120

    def __init__(self):
        super().__init__()
        p = self.profile
        self.plc_model = p.get("plc_model", "CJ2M-CPU33")
        self.vendor = p.get("vendor", "Omron Corporation")
        self.cpu_unit = p.get("cpu_unit", "CJ2M")
        self.firmware = p.get("firmware", "V2.1")

    # ── helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_tcp_header(command: int, payload: bytes, error: int = 0) -> bytes:
        """Build a 16-byte FINS/TCP header + payload."""
        length = len(payload) + 8  # length field counts from command onward
        return FINS_MAGIC + struct.pack(">III", length, command, error) + payload

    def _build_fins_response(
        self, req_frame: bytes, resp_data: bytes, end_code: int = 0x0000
    ) -> bytes:
        """Build a FINS frame response from a request frame.

        Flips ICF to response (0xC0), keeps MRC/SRC, prepends 2-byte end code.
        """
        if len(req_frame) < FINS_FRAME_HEADER_LEN + 2:
            return b""

        # Response ICF: set bit 6 (response) — 0xC0
        icf = 0xC0 | (req_frame[0] & 0x3F)
        # Swap source/dest in header
        rsv = req_frame[1]
        gct = req_frame[2]
        dna = req_frame[6]  # original SNA → now DNA
        da1 = req_frame[7]  # original SA1 → now DA1
        da2 = req_frame[8]  # original SA2 → now DA2
        sna = req_frame[3]  # original DNA → now SNA
        sa1 = req_frame[4]  # original DA1 → now SA1
        sa2 = req_frame[5]  # original DA2 → now SA2
        sid = req_frame[9]
        mrc = req_frame[10]
        src = req_frame[11]

        header = bytes([icf, rsv, gct, dna, da1, da2, sna, sa1, sa2, sid, mrc, src])
        end_code_bytes = struct.pack(">H", end_code)
        return header + end_code_bytes + resp_data

    def _controller_data(self) -> bytes:
        """Build controller data response for MRC=05 SRC=01."""
        model = self.plc_model.encode("ascii")[:20].ljust(20, b"\x00")
        version = self.firmware.encode("ascii")[:20].ljust(20, b"\x00")
        return model + version

    def _cpu_status_data(self) -> bytes:
        """Build CPU unit status response (RUN mode)."""
        # Status: 0x01 = RUN, Mode: 0x02 = RUN
        return struct.pack(">BB", 0x01, 0x02) + b"\x00" * 24

    def _clock_data(self) -> bytes:
        """Build clock read response with current time (BCD-encoded)."""
        t = time.localtime()

        def bcd(val: int) -> int:
            return ((val // 10) << 4) | (val % 10)

        return bytes(
            [
                bcd(t.tm_year % 100),
                bcd(t.tm_mon),
                bcd(t.tm_mday),
                bcd(t.tm_hour),
                bcd(t.tm_min),
                bcd(t.tm_sec),
                bcd(t.tm_wday),
            ]
        )

    # ── connection handler ───────────────────────────────────────────

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[FINS] Connection from %s:%d", peer[0], peer[1])

        client_node = 1
        server_node = 0

        try:
            while True:
                # Read FINS/TCP header (16 bytes)
                raw_header = await asyncio.wait_for(
                    reader.readexactly(FINS_TCP_HEADER_LEN),
                    timeout=60,
                )

                magic = raw_header[0:4]
                if magic != FINS_MAGIC:
                    self.logger.debug("[FINS] Invalid magic from %s", peer[0])
                    break

                length, command, _error_code = struct.unpack(">III", raw_header[4:16])

                # Payload length = length - 8 (command + error fields already counted)
                payload_len = length - 8
                payload = b""
                if payload_len > 0:
                    if payload_len > 65535:
                        break
                    payload = await asyncio.wait_for(
                        reader.readexactly(payload_len),
                        timeout=30,
                    )

                # ── Node Address Request ─────────────────────────────
                if command == CMD_NODE_ADDR_REQ:
                    self.logger.info("[FINS] %s Node Address Request", peer[0])

                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "dst_port": self.port,
                            "phase": "fins_node_request",
                            "rule": "Node Address Request",
                            "payload": "FINS node address negotiation",
                        },
                        None,
                        None,
                    )

                    # Response: 4 bytes client node + 4 bytes server node
                    resp_payload = struct.pack(">II", client_node, server_node)
                    resp = self._build_tcp_header(CMD_NODE_ADDR_RESP, resp_payload)
                    writer.write(resp)
                    await writer.drain()

                # ── FINS Frame Send ──────────────────────────────────
                elif command == CMD_FRAME_SEND:
                    if len(payload) < FINS_FRAME_HEADER_LEN + 2:
                        self.logger.debug("[FINS] Frame too short from %s", peer[0])
                        break

                    fins_frame = payload
                    mrc = fins_frame[10]
                    src = fins_frame[11]
                    frame_data = fins_frame[12:] if len(fins_frame) > 12 else b""

                    cmd_key = (mrc, src)
                    cmd_info = FINS_COMMANDS.get(cmd_key)
                    cmd_name = cmd_info[0] if cmd_info else f"Unknown_{mrc:02X}_{src:02X}"
                    attack_type = cmd_info[1] if cmd_info else "ICS_RECON"
                    severity = cmd_info[2] if cmd_info else "MEDIUM"

                    event_data = {
                        "dst_port": self.port,
                        "phase": "fins_request",
                        "rule": cmd_name,
                        "payload": f"MRC={mrc:02X} SRC={src:02X} data_len={len(frame_data)}",
                        "mrc": mrc,
                        "src": src,
                        "mrc_src_name": cmd_name,
                        "frame_hex": fins_frame.hex(),
                    }
                    log_event(self.PROTOCOL, peer, event_data, attack_type, severity)

                    if attack_type == "ICS_ATTACK":
                        self.logger.warning(
                            "[FINS] %s %s MRC=%02X SRC=%02X (ATTACK/%s)",
                            peer[0],
                            cmd_name,
                            mrc,
                            src,
                            severity,
                        )
                    else:
                        self.logger.info(
                            "[FINS] %s %s MRC=%02X SRC=%02X",
                            peer[0],
                            cmd_name,
                            mrc,
                            src,
                        )

                    # Build response data based on command
                    resp_data = self._build_command_response(mrc, src, frame_data)

                    # Build full FINS frame response
                    fins_resp = self._build_fins_response(fins_frame, resp_data)
                    resp = self._build_tcp_header(CMD_FRAME_RESP, fins_resp)
                    writer.write(resp)
                    await writer.drain()

                else:
                    self.logger.debug(
                        "[FINS] Unknown TCP command 0x%08X from %s",
                        command,
                        peer[0],
                    )
                    break

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect

    def _build_command_response(self, mrc: int, src: int, data: bytes) -> bytes:
        """Return response payload bytes for a given MRC/SRC command."""

        # Memory Area Read → fake register data (zeros)
        if (mrc, src) == (0x01, 0x01):
            # data starts with area code (1) + start address (3) + count (2)
            count = 1
            if len(data) >= 6:
                count = struct.unpack(">H", data[4:6])[0]
            return b"\x00\x00" * max(count, 1)

        # Memory Area Write / Fill → success (empty data)
        if (mrc, src) in ((0x01, 0x02), (0x01, 0x03)):
            return b""

        # Parameter Area Read → fake empty params
        if (mrc, src) == (0x02, 0x01):
            return b"\x00" * 10

        # Parameter Area Write → success
        if (mrc, src) == (0x02, 0x02):
            return b""

        # CPU Unit Status Read → RUN status
        if (mrc, src) == (0x03, 0x06):
            return self._cpu_status_data()

        # Run / Stop → success
        if (mrc, src) in ((0x04, 0x01), (0x04, 0x02)):
            return b""

        # Controller Data Read → model + firmware info
        if (mrc, src) == (0x05, 0x01):
            return self._controller_data()

        # Status Read → basic status
        if (mrc, src) == (0x06, 0x01):
            return b"\x00" * 8

        # Clock Read → current time
        if (mrc, src) == (0x07, 0x01):
            return self._clock_data()

        # Clock Write → success
        if (mrc, src) == (0x07, 0x02):
            return b""

        # Program Area Read → small fake chunk
        if (mrc, src) == (0x26, 0x01):
            return b"\x00" * 16

        # Program Area Write → success
        if (mrc, src) == (0x26, 0x02):
            return b""

        # Unknown command → empty success
        return b""


if __name__ == "__main__":
    FinsHoneypot().run()
