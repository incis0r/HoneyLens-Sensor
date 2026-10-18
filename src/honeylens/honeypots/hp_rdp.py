"""
honeypots/hp_rdp.py — Modular RDP honeypot service
====================================================
Captures X.224 Connection Requests, extracts cookie/credential info,
and sends a valid Connection Confirm. Logs via log_event().

Run standalone:
    python -m honeypots.hp_rdp
    HP_RDP_PORT=3389 python -m honeypots.hp_rdp
"""

from __future__ import annotations

import asyncio
import logging
import re
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event


class RDPHoneypot(BaseHoneypot):
    """Low-interaction RDP honeypot.

    Handles the X.224 Connection Request, extracts any mstshash cookie
    or credential hints, responds with a Connection Confirm, and logs
    all subsequent MCS / TLS data the attacker sends.
    """

    PROTOCOL = "rdp"
    DEFAULT_PORT = 3389
    TTL_PROFILE = "windows"

    async def handle_connection(self, reader, writer, peer):
        self.profile.get("hostname", "WIN-PC01")
        self.profile.get("os_version", "10.0.19041")
        self.profile.get("domain", "WORKGROUP")

        try:
            # 1. Read X.224 Connection Request
            data = await asyncio.wait_for(reader.read(4096), timeout=30)
            if not data:
                return

            # Extract mstshash cookie (contains username hint)
            cookie = ""
            decoded = data.decode(errors="ignore")
            m = re.search(r"mstshash=([^\r\n]+)", decoded)
            if m:
                cookie = m.group(1).strip()

            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "x224_request",
                    "hex": data[:256].hex(),
                    "size": len(data),
                    "cookie": cookie,
                    "dst_port": self.port,
                },
                attack_type="RDP_SCAN",
                severity="MEDIUM",
            )

            self.logger.info(
                "[RDP] %s:%d request (%d bytes) cookie=%s",
                peer[0],
                peer[1],
                len(data),
                cookie or "(none)",
            )

            # 2. Build X.224 Connection Confirm (TPKT + X224 CC)
            x224_cc = bytearray()
            x224_cc += b"\x0e"  # length indicator
            x224_cc += b"\xd0"  # CC code (1101 0000)
            x224_cc += b"\x00\x00"  # DST-REF
            # Echo back SRC-REF from request
            x224_cc += data[7:9] if len(data) > 8 else b"\x00\x00"
            x224_cc += b"\x00"  # class option
            # RDP Negotiation Response: TYPE_RDP_NEG_RSP, protocol 0
            x224_cc += b"\x02\x00\x08\x00\x00\x00\x00\x00"

            total_len = 4 + len(x224_cc)
            tpkt = b"\x03\x00" + struct.pack(">H", total_len)

            writer.write(tpkt + bytes(x224_cc))
            await writer.drain()

            # 3. Read MCS Connect Initial / further handshake data
            while True:
                more = await asyncio.wait_for(reader.read(8192), timeout=60)
                if not more:
                    break
                log_event(
                    self.PROTOCOL,
                    peer,
                    {
                        "phase": "data",
                        "hex": more[:512].hex(),
                        "size": len(more),
                        "dst_port": self.port,
                    },
                )

        except (TimeoutError, ConnectionError) as exc:  # silent: expected normal client disconnect
            logging.getLogger(__name__).debug("ignored: %s", exc)


if __name__ == "__main__":
    RDPHoneypot().run()
