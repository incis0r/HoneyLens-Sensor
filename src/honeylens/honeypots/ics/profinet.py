# honeypots/ics/profinet.py
"""PROFINET honeypot — UDP 34964 (PN-IO context manager / DCE-RPC).
Identify-depth: answer an implicit read with an I&M0 Siemens identity."""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Any

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.ics.base import classify, frame_hex
from honeylens.honeypots.ics.foreign import FOREIGN_VERDICT, foreign_event
from honeylens.honeypots.ics.verdict import kind_for
from honeylens.ics import decode

# A connectionless DCE/RPC PDU (DCE 1.1 RPC, chapter 12): an 80-byte header whose first byte is
# the RPC version 4, whose second is the packet type, whose fifth carries the integer byte
# order, and whose bytes 74-75 give the length of the body that follows.
RPC_HEADER = 80
_RPC_VERSION = 4
_PACKET_TYPES = range(11)  # request .. cancel_ack; 11-19 are connection-oriented
_REQUEST = 0


def check_rpc(data: bytes) -> str | None:
    """Why a datagram is not a connectionless DCE/RPC PDU, or ``None`` when it is one."""
    if len(data) < RPC_HEADER:
        return f"{len(data)} byte(s) are shorter than the 80-byte DCE/RPC header"
    if data[0] != _RPC_VERSION:
        return f"RPC version is {data[0]}, not the connectionless version 4"
    if data[1] not in _PACKET_TYPES:
        return f"packet type {data[1]} is not a connectionless DCE/RPC packet type"
    body = int.from_bytes(data[74:76], "little" if data[4] & 0x10 else "big")
    if RPC_HEADER + body > len(data):
        return f"the header declares a {body}-byte body and {len(data) - RPC_HEADER} follow"
    return None


def build_im0(profile: dict) -> bytes:
    """Minimal I&M0 identity block (not a full DCE/RPC PDU — identity bytes
    a fingerprinting tool reads: VendorID + OrderID + Serial + revisions +
    NameOfStation). Enough to land in scanner result sets."""
    p = profile
    vendor = int(p.get("vendor_id", "0x002A"), 16)
    order = p.get("order_id", "6ES7 515-2AM01-0AB0").encode().ljust(20, b"\x20")
    serial = p.get("serial", "S C-X1V234567").encode().ljust(16, b"\x20")
    hw = int(p.get("hw_rev", "5"))
    sw = p.get("sw_rev", "V2.9.2").encode()[:4].ljust(4, b"\x00")
    station = p.get("station_name", "plcxb1d0ed").encode()
    blk = struct.pack(">H", vendor) + order + serial + struct.pack(">H", hw) + sw
    blk += struct.pack(">H", len(station)) + station
    return blk


class ProfinetDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, profile: dict, port: int = 34964):
        self.profile = profile
        self.port = port
        self.transport: Any = None
        self.log = logging.getLogger("hp_profinet")

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        defect = check_rpc(data)
        if defect:
            # Not DCE/RPC: recorded, never answered. A reply to an unvalidated datagram is a
            # reply to whatever source address the sender chose to write.
            log_event(
                "profinet",
                addr,
                foreign_event(self.port, data, "PROFINET", defect),
                *FOREIGN_VERDICT,
                raw=data[:MAX_RAW_EVENT_BYTES] or None,
            )
            return
        # The opnum that tells an identification read from a write sits at byte 68; the
        # decoder reads it, and the kind is the decoder's.
        kind = kind_for(decode("profinet", data))
        if data[1] == _REQUEST:
            try:
                self.transport.sendto(build_im0(self.profile), addr)
            except Exception as exc:
                logging.getLogger(__name__).debug("ignored: %s", exc)
        atk, sev = classify(kind)
        log_event(
            "profinet",
            addr,
            {"phase": "pnio_dgram", "bytes": len(data), "frame_hex": frame_hex(data)},
            attack_type=atk,
            severity=sev,
        )


class ProfinetHoneypot(BaseHoneypot):
    PROTOCOL = "profinet"
    DEFAULT_PORT = 34964
    TTL_PROFILE = "plc"  # embedded device fingerprint; one source with manifest.ttl_profile

    def run(self):
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        self.logger.info("Starting PROFINET honeypot on UDP %d", self.port)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        transport, _ = loop.run_until_complete(
            loop.create_datagram_endpoint(
                lambda: ProfinetDatagramProtocol(self.profile, self.port),
                local_addr=("0.0.0.0", self.port),
            )
        )
        self.logger.info("PROFINET honeypot listening on 0.0.0.0:%d (UDP)", self.port)
        try:
            loop.run_forever()
        except KeyboardInterrupt as exc:
            logging.getLogger(__name__).debug("ignored: %s", exc)
        finally:
            transport.close()
            loop.close()


if __name__ == "__main__":
    ProfinetHoneypot().run()
