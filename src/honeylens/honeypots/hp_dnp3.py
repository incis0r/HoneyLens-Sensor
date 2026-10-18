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
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.ics.base import frame_hex
from honeylens.honeypots.ics.foreign import (
    DESYNC_VERDICT,
    FOREIGN_VERDICT,
    desync_event,
    foreign_event,
    read_rest,
)
from honeylens.honeypots.ics.verdict import verdict_for
from honeylens.ics import decode
from honeylens.ics.dnp3 import function_name, header_crc_ok, link_function_name

# ---------------------------------------------------------------------------
# DNP3 constants
# ---------------------------------------------------------------------------
DNP3_START = b"\x05\x64"
DL_HEADER_SIZE = 10  # start(2) + length(1) + control(1) + dst(2) + src(2) + crc(2)
# The length field counts control + destination + source (5) and the user data (0..250).
MIN_DL_LENGTH = 5


def check_link(header: bytes) -> str | None:
    """Why these ten bytes are not a DNP3 data link header, or ``None`` when they are one.

    The header CRC is deliberately not part of the answer: scanners send bad CRCs, the
    decoder reports rather than enforces it, and the decoy records it as ``header_crc_ok``.
    """
    if len(header) < DL_HEADER_SIZE:
        return f"{len(header)} byte(s) is not a data link header"
    if header[0:2] != DNP3_START:
        return f"the start bytes are 0x{header[0:2].hex()}, not 0x0564"
    if header[2] < MIN_DL_LENGTH:
        return f"length {header[2]} is below {MIN_DL_LENGTH}, the control and address bytes"
    return None


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
    # start(2) + length(1) + control(1) + dst(2 LE) + src(2 LE); addresses are unsigned.
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

    async def _read(self, reader, n: int, wait: float) -> tuple[bytes, bool]:
        """``n`` bytes and True, or what arrived before the stream ended and False. On a
        timeout the bytes stay in the reader, where ``read_rest`` finds them."""
        try:
            return await asyncio.wait_for(reader.readexactly(n), timeout=wait), True
        except asyncio.IncompleteReadError as exc:
            return bytes(exc.partial), False
        except TimeoutError:
            return b"", False

    async def _not_dnp3(self, reader, peer, consumed: bytes, defect: str, frames: int):
        """One event for a stream that is not (or is no longer) DNP3, then nothing more."""
        data = await read_rest(reader, consumed)
        if not data:
            return  # the peer connected and left, or an idle session timed out
        if frames == 0:
            event, verdict = foreign_event(self.port, data, "DNP3", defect), FOREIGN_VERDICT
        else:
            event, verdict = desync_event(self.port, data, "DNP3", defect, frames), DESYNC_VERDICT
        log_event(self.PROTOCOL, peer, event, *verdict, raw=data[:MAX_RAW_EVENT_BYTES])
        self.logger.info("[DNP3] %s not DNP3 (%s): %s", peer[0], event["foreign_protocol"], defect)

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[DNP3] Connection from %s:%d", peer[0], peer[1])

        frames = 0
        try:
            while True:
                # ---- Read Data Link Layer header (10 bytes) ----
                header, whole = await self._read(reader, DL_HEADER_SIZE, 60)
                if not whole:
                    await self._not_dnp3(
                        reader, peer, header, "the stream ended inside the data link header", frames
                    )
                    return
                defect = check_link(header)
                if defect:
                    await self._not_dnp3(reader, peer, header, defect, frames)
                    return

                dl_length = header[2]
                dl_control = header[3]
                dl_dst = struct.unpack("<H", header[4:6])[0]
                dl_src = struct.unpack("<H", header[6:8])[0]

                # Payload length: dl_length includes control + dst(2) + src(2) = 5
                payload_len = dl_length - MIN_DL_LENGTH

                # Read payload blocks: each 16-byte block has 2-byte CRC appended
                raw_payload = b""
                wire = bytes(header)  # the frame as it arrived, block CRCs included
                remaining = payload_len
                while remaining > 0:
                    block_size = min(remaining, 16)
                    # Read block data + 2-byte CRC
                    block_data, whole = await self._read(reader, block_size + 2, 30)
                    wire += block_data
                    if not whole:
                        cut = f"the stream ended inside {payload_len} byte(s) of user data"
                        await self._not_dnp3(reader, peer, wire, cut, frames)
                        return
                    raw_payload += block_data[:block_size]  # strip CRC
                    remaining -= block_size
                frames += 1

                # What the frame means, and so how it is judged, comes from the decoder:
                # this decoy keeps no function-code table.
                decoded = decode(self.PROTOCOL, wire)
                attack_type, severity = verdict_for(decoded)
                link = {
                    "dst_port": self.port,
                    "dl_dst": dl_dst,
                    "dl_src": dl_src,
                    "dl_control": dl_control,
                    "header_crc_ok": header_crc_ok(header),
                    "frame_hex": frame_hex(wire),
                    "station_address": self.station_address,
                }

                # ---- A frame with no application layer ----
                # No user data (link status, reset link, test link), or user data too short
                # to hold an application header. It is DNP3 and it is evidence, so it is a
                # row; the decoy has no reply for it yet and the session goes on.
                if len(raw_payload) < 3:
                    link_name = link_function_name(dl_control)
                    event_data = {
                        **link,
                        "phase": "dnp3_link",
                        "rule": link_name,
                        "payload": (
                            f"link control=0x{dl_control:02X} ({link_name}) "
                            f"dst_addr={dl_dst} src_addr={dl_src} user_data={len(raw_payload)}"
                        ),
                    }
                    log_event(self.PROTOCOL, peer, event_data, attack_type, severity)
                    self.logger.info(
                        "[DNP3] %s link %s dst=%d src=%d", peer[0], link_name, dl_dst, dl_src
                    )
                    continue

                # ---- Transport Layer ----
                transport_hdr = raw_payload[0]
                # FIN bit = 0x80, FIR bit = 0x40, sequence = 0x3F
                tp_seq = transport_hdr & 0x3F

                # ---- Application Layer ----
                app_data = raw_payload[1:]
                app_ctrl = app_data[0]
                app_seq = app_ctrl & 0x0F
                fc = app_data[1]
                app_objects = app_data[2:]

                fc_name = function_name(fc) or f"FC_{fc}"

                event_data = {
                    **link,
                    "phase": "dnp3_request",
                    "rule": fc_name,
                    "payload": (f"FC=0x{fc:02X} ({fc_name}) dst_addr={dl_dst} src_addr={dl_src}"),
                    "fc": fc,
                    "fc_name": fc_name,
                    # app_objects_hex starts after the function code; frame_hex is the frame
                    # the decoder reads (data link header, then CRC-interleaved blocks).
                    "app_objects_hex": app_objects.hex() if app_objects else "",
                }
                if decoded.code is None and decoded.tail_reason:
                    # The decoder did not place an application layer (a continuation
                    # segment, a secondary frame): the byte in ``fc`` is not a function code.
                    event_data["decode_note"] = decoded.tail_reason

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

        except (TimeoutError, ConnectionError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    DNP3Honeypot().run()
