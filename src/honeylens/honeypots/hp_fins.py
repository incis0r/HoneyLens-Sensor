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
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.ics.base import frame_hex
from honeylens.honeypots.ics.foreign import (
    DESYNC_VERDICT,
    FOREIGN_VERDICT,
    desync_event,
    foreign_event,
    read_rest,
)
from honeylens.honeypots.ics.verdict import verdict_for, verdict_for_semantics
from honeylens.ics import decode
from honeylens.ics.fins import command_name

# FINS TCP header constants
FINS_MAGIC = b"FINS"  # 0x46494E53
CMD_NODE_ADDR_REQ = 0x00000000
CMD_NODE_ADDR_RESP = 0x00000001
CMD_FRAME_SEND = 0x00000002
CMD_FRAME_RESP = 0x00000003
# FINS/TCP commands that exist. A client sends 0 and 2; the rest are the server's side of
# the exchange (1 node address reply, 3 frame send error, 6 connection confirmation).
FINS_TCP_COMMANDS = frozenset({0, 1, 2, 3, 6})
_TCP_COMMAND_NAMES = {
    1: "Node Address Response",
    3: "Frame Send Error Notification",
    6: "Connection Confirmation",
}

# The length field counts the command and error code (8) and the payload. A FINS frame is at
# most 2,012 bytes; 2,048 leaves room for a client that rounds up.
MIN_TCP_LENGTH = 8
MAX_TCP_LENGTH = 8 + 2048

FINS_TCP_HEADER_LEN = 16
FINS_FRAME_HEADER_LEN = 10  # ICF..SID (before MRC/SRC)


def check_fins_tcp(header: bytes) -> str | None:
    """Why these sixteen bytes are not a FINS/TCP header from a client, or ``None``."""
    if len(header) < FINS_TCP_HEADER_LEN:
        return f"{len(header)} byte(s) is not a FINS/TCP header"
    if header[0:4] != FINS_MAGIC:
        return f"the magic is 0x{header[0:4].hex()}, not 'FINS'"
    length, command, error = struct.unpack(">III", header[4:16])
    if not MIN_TCP_LENGTH <= length <= MAX_TCP_LENGTH:
        return f"length {length} is outside {MIN_TCP_LENGTH}..{MAX_TCP_LENGTH}"
    if command not in FINS_TCP_COMMANDS:
        return f"0x{command:08x} is not a FINS/TCP command"
    if error != 0 and command in (CMD_NODE_ADDR_REQ, CMD_FRAME_SEND):
        return f"error code 0x{error:08x} in a request"
    return None


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

    async def _read(self, reader, n: int, wait: float) -> tuple[bytes, bool]:
        """``n`` bytes and True, or what arrived before the stream ended and False. On a
        timeout the bytes stay in the reader, where ``read_rest`` finds them."""
        try:
            return await asyncio.wait_for(reader.readexactly(n), timeout=wait), True
        except asyncio.IncompleteReadError as exc:
            return bytes(exc.partial), False
        except TimeoutError:
            return b"", False

    async def _not_fins(self, reader, peer, consumed: bytes, defect: str, frames: int):
        """One event for a stream that is not (or is no longer) FINS/TCP, then nothing more."""
        data = await read_rest(reader, consumed)
        if not data:
            return  # the peer connected and left, or an idle session timed out
        if frames == 0:
            event, verdict = foreign_event(self.port, data, "FINS", defect), FOREIGN_VERDICT
        else:
            event, verdict = desync_event(self.port, data, "FINS", defect, frames), DESYNC_VERDICT
        log_event(self.PROTOCOL, peer, event, *verdict, raw=data[:MAX_RAW_EVENT_BYTES])
        self.logger.info("[FINS] %s not FINS (%s): %s", peer[0], event["foreign_protocol"], defect)

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[FINS] Connection from %s:%d", peer[0], peer[1])

        client_node = 1
        server_node = 0
        frames = 0

        try:
            while True:
                # Read FINS/TCP header (16 bytes)
                raw_header, whole = await self._read(reader, FINS_TCP_HEADER_LEN, 60)
                if not whole:
                    await self._not_fins(
                        reader,
                        peer,
                        raw_header,
                        "the stream ended inside the FINS/TCP header",
                        frames,
                    )
                    return
                bad_header = check_fins_tcp(raw_header)
                if bad_header:
                    await self._not_fins(reader, peer, raw_header, bad_header, frames)
                    return

                length, command, _error_code = struct.unpack(">III", raw_header[4:16])

                # Payload length = length - 8 (command + error fields already counted)
                payload_len = length - MIN_TCP_LENGTH
                payload, whole = await self._read(reader, payload_len, 30)
                if not whole:
                    defect = f"the stream ended inside a payload declared as {payload_len} byte(s)"
                    await self._not_fins(reader, peer, raw_header + payload, defect, frames)
                    return
                if command == CMD_NODE_ADDR_REQ and payload_len != 4:
                    defect = f"a node address request carries 4 bytes, got {payload_len}"
                    await self._not_fins(reader, peer, raw_header + payload, defect, frames)
                    return
                if command == CMD_FRAME_SEND and payload_len < FINS_FRAME_HEADER_LEN + 2:
                    defect = f"a FINS frame of {payload_len} byte(s) has no command code"
                    await self._not_fins(reader, peer, raw_header + payload, defect, frames)
                    return
                frames += 1

                # ── Node Address Request ─────────────────────────────
                if command == CMD_NODE_ADDR_REQ:
                    self.logger.info("[FINS] %s Node Address Request", peer[0])

                    # The opening negotiation carries no FINS frame for the decoder; it is
                    # how a client finds out there is a FINS node here.
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "dst_port": self.port,
                            "phase": "fins_node_request",
                            "rule": "Node Address Request",
                            "payload": "FINS node address negotiation",
                        },
                        *verdict_for_semantics("discovery", self.PROTOCOL),
                    )

                    # Response: 4 bytes client node + 4 bytes server node
                    resp_payload = struct.pack(">II", client_node, server_node)
                    resp = self._build_tcp_header(CMD_NODE_ADDR_RESP, resp_payload)
                    writer.write(resp)
                    await writer.drain()

                # ── FINS Frame Send ──────────────────────────────────
                elif command == CMD_FRAME_SEND:
                    fins_frame = payload
                    mrc = fins_frame[10]
                    src = fins_frame[11]
                    frame_data = fins_frame[12:] if len(fins_frame) > 12 else b""

                    # The command's name and verdict come from the decoder: this decoy
                    # keeps no (MRC, SRC) table of its own.
                    cmd_name = command_name(mrc, src) or f"Unknown_{mrc:02X}_{src:02X}"
                    attack_type, severity = verdict_for(decode(self.PROTOCOL, fins_frame))

                    event_data = {
                        "dst_port": self.port,
                        "phase": "fins_request",
                        "rule": cmd_name,
                        "payload": f"MRC={mrc:02X} SRC={src:02X} data_len={len(frame_data)}",
                        "mrc": mrc,
                        "src": src,
                        "mrc_src_name": cmd_name,
                        "frame_hex": frame_hex(fins_frame),
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
                    # A FINS/TCP command only a server sends. It is FINS, so it is a row;
                    # there is nothing to answer and the session ends.
                    name = _TCP_COMMAND_NAMES.get(command, f"TCP command {command}")
                    log_event(
                        self.PROTOCOL,
                        peer,
                        {
                            "dst_port": self.port,
                            "phase": "fins_tcp_command",
                            "rule": f"{name} sent by a client",
                            "payload": f"FINS/TCP command {command} ({name}) from a client",
                            "tcp_command": command,
                            "tcp_hex": frame_hex(raw_header + payload),
                        },
                        *verdict_for_semantics("anomaly", self.PROTOCOL),
                    )
                    self.logger.info("[FINS] %s server-side TCP command %d", peer[0], command)
                    return

        except (TimeoutError, ConnectionError):
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
