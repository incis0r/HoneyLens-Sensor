#!/usr/bin/env python3
"""
honeypots/hp_dnp3.py — DNP3 (Distributed Network Protocol 3) Honeypot
======================================================================
Simulates a DNP3 outstation (RTU/RTAC). Responds to application-layer
requests and logs all ICS-relevant events.

Run: python -m honeypots.hp_dnp3
Service: sensor-hp-dnp3 (port 20000)
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event

# ---------------------------------------------------------------------------
# DNP3 constants
# ---------------------------------------------------------------------------
DNP3_START = b"\x05\x64"
DL_HEADER_SIZE = 10  # start(2) + length(1) + control(1) + dst(2) + src(2) + crc(2)

# Function code names
DNP3_FC_NAMES = {
    0x00: "Confirm",
    0x01: "Read",
    0x02: "Write",
    0x03: "Select",
    0x04: "Operate",
    0x05: "Direct Operate",
    0x06: "Direct Operate No Ack",
    0x0D: "Cold Restart",
    0x0E: "Warm Restart",
    0x15: "Disable Unsolicited",
    0x18: "Record Current Time",
    0x19: "Open File",
}

# Attack classification per function code
FC_CLASSIFICATION = {
    0x01: ("ICS_RECON", "MEDIUM"),  # Read
    0x02: ("ICS_ATTACK", "HIGH"),  # Write
    0x03: ("ICS_ATTACK", "CRITICAL"),  # Select
    0x04: ("ICS_ATTACK", "CRITICAL"),  # Operate
    0x05: ("ICS_ATTACK", "CRITICAL"),  # Direct Operate
    0x06: ("ICS_ATTACK", "CRITICAL"),  # Direct Operate No Ack
    0x0D: ("ICS_ATTACK", "CRITICAL"),  # Cold Restart
    0x0E: ("ICS_ATTACK", "CRITICAL"),  # Warm Restart
    0x15: ("ICS_ATTACK", "HIGH"),  # Disable Unsolicited
    0x18: ("ICS_RECON", "LOW"),  # Record Current Time
    0x19: ("ICS_ATTACK", "HIGH"),  # Open File
}

# CRC-16/DNP lookup table (polynomial 0x3D65, reflected)
_CRC_TABLE: list[int] = []


def _init_crc_table():
    poly = 0xA6BC  # reflected 0x3D65
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        _CRC_TABLE.append(crc & 0xFFFF)


_init_crc_table()


def _crc16_dnp(data: bytes) -> int:
    """Compute CRC-16/DNP over *data*."""
    crc = 0x0000
    for b in data:
        crc = (_CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)) & 0xFFFF
    return crc ^ 0xFFFF


def _build_dl_frame(length: int, control: int, dst: int, src: int, payload: bytes) -> bytes:
    """Build a complete Data Link Layer frame with CRC blocks."""
    header = struct.pack("<BBBhh", 0x05, 0x64, length, dst, src)
    # Replace control byte (header[3])
    header = header[:3] + bytes([control]) + header[4:]
    # Repack properly: start(2) + length(1) + control(1) + dst(2 LE) + src(2 LE)
    header = struct.pack("<2sBBHH", DNP3_START, length, control, dst, src)
    hdr_crc = _crc16_dnp(header)
    frame = header + struct.pack("<H", hdr_crc)

    # Payload is split into 16-byte blocks, each followed by a 2-byte CRC
    offset = 0
    while offset < len(payload):
        block = payload[offset : offset + 16]
        block_crc = _crc16_dnp(block)
        frame += block + struct.pack("<H", block_crc)
        offset += 16

    return frame


class DNP3Honeypot(BaseHoneypot):
    PROTOCOL = "dnp3"
    DEFAULT_PORT = 20000
    TTL_PROFILE = "plc"
    CONNECTION_TIMEOUT = 120

    def __init__(self):
        super().__init__()
        p = self.profile
        self.device_name = p.get("device_name", "SEL-3530 RTAC")
        self.vendor = p.get("vendor", "Schweitzer Engineering")
        self.firmware = p.get("firmware", "R136-V0")
        self.station_address = p.get("station_address", 10)

    # ------------------------------------------------------------------
    # Application-layer response builders
    # ------------------------------------------------------------------

    @staticmethod
    def _app_response(
        fc: int, seq: int, iin1: int = 0x80, iin2: int = 0x00, objects: bytes = b""
    ) -> bytes:
        """Build an application-layer response.

        *iin1* defaults to 0x80 (device restart bit set).
        """
        # Application control: FIR=1 FIN=1 CON=0 UNS=0 SEQ=seq
        app_ctrl = 0xC0 | (seq & 0x0F)
        # Response function code = 0x81
        return bytes([app_ctrl, 0x81, iin1, iin2]) + objects

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[DNP3] Connection from %s:%d", peer[0], peer[1])

        try:
            while True:
                # ---- Read Data Link Layer header (10 bytes) ----
                header = await asyncio.wait_for(reader.readexactly(DL_HEADER_SIZE), timeout=60)

                # Validate start bytes
                if header[0:2] != DNP3_START:
                    self.logger.debug("[DNP3] Invalid start bytes from %s", peer[0])
                    break

                dl_length = header[2]
                dl_control = header[3]
                dl_dst = struct.unpack("<H", header[4:6])[0]
                dl_src = struct.unpack("<H", header[6:8])[0]
                # header[8:10] = CRC (skip validation — scanners may send bad CRC)

                # Payload length: dl_length includes control + dst(2) + src(2) = 5
                payload_len = dl_length - 5
                if payload_len < 0 or payload_len > 250:
                    self.logger.debug("[DNP3] Bad DL length %d from %s", dl_length, peer[0])
                    break

                # Read payload blocks: each 16-byte block has 2-byte CRC appended
                raw_payload = b""
                remaining = payload_len
                while remaining > 0:
                    block_size = min(remaining, 16)
                    # Read block data + 2-byte CRC
                    block_data = await asyncio.wait_for(
                        reader.readexactly(block_size + 2), timeout=30
                    )
                    raw_payload += block_data[:block_size]  # strip CRC
                    remaining -= block_size

                if len(raw_payload) < 2:
                    break

                # ---- Transport Layer ----
                transport_hdr = raw_payload[0]
                # FIN bit = 0x80, FIR bit = 0x40, sequence = 0x3F
                tp_seq = transport_hdr & 0x3F

                # ---- Application Layer ----
                app_data = raw_payload[1:]
                if len(app_data) < 2:
                    break

                app_ctrl = app_data[0]
                app_seq = app_ctrl & 0x0F
                fc = app_data[1]
                app_objects = app_data[2:]

                fc_name = DNP3_FC_NAMES.get(fc, f"FC_{fc}")
                classification = FC_CLASSIFICATION.get(fc)
                attack_type = classification[0] if classification else None
                severity = classification[1] if classification else None

                # For unknown/unexpected function codes, flag as suspicious
                if classification is None and fc != 0x00:
                    attack_type = "ICS_ATTACK"
                    severity = "MEDIUM"

                event_data = {
                    "dst_port": self.port,
                    "phase": "dnp3_request",
                    "rule": fc_name,
                    "payload": (f"FC=0x{fc:02X} ({fc_name}) dst_addr={dl_dst} src_addr={dl_src}"),
                    "dl_dst": dl_dst,
                    "dl_src": dl_src,
                    "dl_control": dl_control,
                    "fc": fc,
                    "fc_name": fc_name,
                    "app_objects_hex": app_objects.hex() if app_objects else "",
                    "station_address": self.station_address,
                }

                log_event(self.PROTOCOL, peer, event_data, attack_type, severity)

                if severity in ("CRITICAL", "HIGH"):
                    self.logger.warning(
                        "[DNP3] %s %s FC=0x%02X (%s) dst=%d src=%d",
                        peer[0],
                        severity,
                        fc,
                        fc_name,
                        dl_dst,
                        dl_src,
                    )
                else:
                    self.logger.info(
                        "[DNP3] %s FC=0x%02X (%s) dst=%d src=%d",
                        peer[0],
                        fc,
                        fc_name,
                        dl_dst,
                        dl_src,
                    )

                # ---- Build response ----
                if fc == 0x00:
                    # Confirm — no response needed
                    continue

                resp_objects = b""
                iin1 = 0x80  # restart bit
                iin2 = 0x00

                if fc in (0x0D, 0x0E):
                    # Cold/Warm restart — respond with time delay object
                    # g51v1: Time Delay Fine — Object header + 2-byte ms value
                    resp_objects = bytes(
                        [
                            0x34,
                            0x02,  # group 52, variation 2 (Time Delay Fine)
                            0x07,
                            0x01,  # qualifier 0x07 (1-byte count), count 1
                            0xE8,
                            0x03,  # 1000 ms delay (little-endian)
                        ]
                    )

                app_resp = self._app_response(fc, app_seq, iin1, iin2, resp_objects)

                # Transport layer: FIN=1 FIR=1 SEQ=tp_seq
                transport_byte = 0xC0 | (tp_seq & 0x3F)
                tp_payload = bytes([transport_byte]) + app_resp

                # Data link: respond with src/dst swapped
                # DL length = 5 (ctrl+dst+src) + len(tp_payload)
                resp_dl_length = 5 + len(tp_payload)
                # Control: DIR=0 PRM=0 — response from outstation
                resp_dl_control = 0x00

                frame = _build_dl_frame(
                    resp_dl_length,
                    resp_dl_control,
                    dl_src,
                    self.station_address,
                    tp_payload,
                )
                writer.write(frame)
                await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    DNP3Honeypot().run()
