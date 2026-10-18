"""
honeypots/hp_javarmi.py — Modular Java RMI honeypot service
=============================================================
Captures Java RMI handshake attempts and subsequent class/method
invocation data from attackers probing RMI registries.

Run standalone:
    python -m honeypots.hp_javarmi
    HP_JAVARMI_PORT=1099 python -m honeypots.hp_javarmi
"""

from __future__ import annotations

import asyncio
import logging

from honeylens.honeypots._base import BaseHoneypot, log_event


class JavaRMIHoneypot(BaseHoneypot):
    """Low-interaction Java RMI honeypot.

    Accepts RMI connections, identifies valid JRMI handshakes, sends a
    protocol-ack response, and logs all subsequent data for analysis.
    """

    PROTOCOL = "javarmi"
    DEFAULT_PORT = 1099
    TTL_PROFILE = "linux"
    CONNECTION_TIMEOUT = 120

    # RMI protocol magic bytes
    RMI_MAGIC = b"JRMI"

    # Endpoint response: protocol-not-supported (0x4E) + dummy endpoint
    RMI_ACK = b"\x4e\x00\x0elocalhost\x00\x00\x00\x00\x00\x00\xc4\x12"

    async def handle_connection(self, reader, writer, peer):
        # 1. Read initial data from the client
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=30)
        except (TimeoutError, ConnectionError):
            return
        if not data:
            return

        is_rmi = data[:4] == self.RMI_MAGIC

        log_event(
            self.PROTOCOL,
            peer,
            {
                "phase": "initial",
                "hex": data[:256].hex(),
                "is_rmi": is_rmi,
                "size": len(data),
                "dst_port": self.port,
            },
            attack_type="RMI_SCAN",
            severity="LOW",
        )

        self.logger.info(
            "[RMI] %s:%d initial %d bytes (valid_rmi=%s)",
            peer[0],
            peer[1],
            len(data),
            is_rmi,
        )

        # 2. Respond based on handshake type
        if is_rmi:
            writer.write(self.RMI_ACK)
        else:
            # Echo back a small portion for unknown sub-protocols
            writer.write(data[:64])
        await writer.drain()

        # 3. Keep reading follow-up data (method calls, serialized objects)
        try:
            while True:
                more = await asyncio.wait_for(reader.read(4096), timeout=60)
                if not more:
                    break

                log_event(
                    self.PROTOCOL,
                    peer,
                    {
                        "phase": "data",
                        "hex": more[:256].hex(),
                        "size": len(more),
                        "dst_port": self.port,
                    },
                )
                self.logger.info(
                    "[RMI] %s:%d data %d bytes",
                    peer[0],
                    peer[1],
                    len(more),
                )
        except (TimeoutError, ConnectionError) as exc:  # silent: expected normal client disconnect
            logging.getLogger(__name__).debug("ignored: %s", exc)


if __name__ == "__main__":
    JavaRMIHoneypot().run()
