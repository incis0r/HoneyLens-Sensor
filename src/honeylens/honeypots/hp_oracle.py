"""
honeypots/hp_oracle.py — Modular Oracle TNS honeypot service
=============================================================
Captures TNS connect packets, extracts service names, and sends
a TNS refuse response. Logs everything via log_event() to the database.

Run standalone:
    python -m honeypots.hp_oracle
    HP_ORACLE_PORT=1521 python -m honeypots.hp_oracle
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event


class OracleHoneypot(BaseHoneypot):
    """Low-interaction Oracle TNS honeypot.

    Reads a TNS connect packet, extracts the service name from the
    connect data, then sends a TNS REFUSE with error 12505 (unknown SID).
    """

    PROTOCOL = "oracle"
    DEFAULT_PORT = 1521
    TTL_PROFILE = "linux"

    # VSNNUM is the listener's version, packed into 32 bits as
    # (major << 24) | (minor << 20) | (patch << 12) | (port_release << 8) | port_update.
    # Scanners decode and print it, so VSNNUM=0 rendered as "Oracle TNS listener
    # 0.0.0.0.0" — a version that has never shipped, and therefore a reliable tell that
    # the listener is not Oracle. 0x13300000 is 19.3.0.0.0, a long-term-support release
    # still widely deployed.
    VSNNUM = (19 << 24) | (3 << 20)  # 19.3.0.0.0 -> 321912832

    # Shape of a real 19c listener's refusal: TMP is present and empty, VSNNUM carries
    # the version, and the error appears both as ERR and inside ERROR_STACK.
    @property
    def refuse_data(self) -> bytes:
        return (
            b"(DESCRIPTION=(TMP=)(VSNNUM=%d)(ERR=12505)"
            b"(ERROR_STACK=(ERROR=(CODE=12505)(EMFI=4))))" % self.VSNNUM
        )

    async def handle_connection(self, reader, writer, peer):
        try:
            # Read TNS packet header (8 bytes minimum)
            hdr = await asyncio.wait_for(reader.readexactly(8), timeout=30)
            pkt_len = struct.unpack(">H", hdr[0:2])[0]
            pkt_type = hdr[4]  # 1=connect, 2=accept, 4=refuse

            # Read the rest of the packet body
            remaining = pkt_len - 8
            if 0 < remaining < 8192:
                body = await asyncio.wait_for(
                    reader.readexactly(remaining),
                    timeout=30,
                )
            else:
                body = b""

            # Try to extract service name from connect data
            connect_data = body.decode(errors="ignore")[:512]
            service_name = ""
            if "SERVICE_NAME=" in connect_data.upper():
                start = connect_data.upper().index("SERVICE_NAME=") + 13
                end = connect_data.find(")", start)
                service_name = connect_data[start:end] if end > start else ""

            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "connect",
                    "tns_type": pkt_type,
                    "service_name": service_name,
                    "connect_data": connect_data,
                    "body_hex": body[:256].hex(),
                    "dst_port": self.port,
                },
                attack_type="ORACLE_SCAN",
                severity="MEDIUM",
            )

            self.logger.info(
                "[Oracle] %s:%d TNS type=%d len=%d service=%s",
                peer[0],
                peer[1],
                pkt_type,
                pkt_len,
                service_name or "(none)",
            )

            # Send TNS REFUSE. A real listener refuses an unknown service the same way,
            # so the refusal itself is not the tell — the version inside it was.
            payload = self.refuse_data
            refuse_len = 8 + len(payload)
            refuse_hdr = (
                struct.pack(">H", refuse_len)
                + b"\x00\x00"  # packet checksum
                + b"\x04"  # type = refuse
                + b"\x00\x00\x00"  # reserved / flags
            )
            writer.write(refuse_hdr + payload)
            await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError) as exc:
            self.logger.debug("ignored: %s", exc)


if __name__ == "__main__":
    OracleHoneypot().run()
