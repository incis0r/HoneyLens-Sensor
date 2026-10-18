# honeypots/ics/profinet.py
"""PROFINET honeypot — UDP 34964 (PN-IO context manager / DCE-RPC).
Identify-depth: answer an implicit read with an I&M0 Siemens identity."""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Any

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.ics.base import classify


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
    def __init__(self, profile: dict):
        self.profile = profile
        self.transport: Any = None
        self.log = logging.getLogger("hp_profinet")

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        kind = "recon"  # a DCE/RPC datagram on 34964 implies a tool, not noise
        # DCE/RPC opnum at byte 2 in our test shape; treat write opnums as write.
        # NOTE: byte offset 2 is an identify-depth simplification, NOT a wire-accurate
        # DCE/RPC opnum offset — a future deepening must not trust this offset.
        if len(data) >= 3 and data[2] in (0x06,):  # 6 = Write
            kind = "write"
        if len(data) < 3:
            kind = "enumeration"
        if kind != "enumeration":
            try:
                self.transport.sendto(build_im0(self.profile), addr)
            except Exception as exc:
                logging.getLogger(__name__).debug("ignored: %s", exc)
        atk, sev = classify(kind)
        log_event(
            "profinet",
            addr,
            {"phase": "pnio_dgram", "bytes": len(data)},
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
                lambda: ProfinetDatagramProtocol(self.profile), local_addr=("0.0.0.0", self.port)
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
