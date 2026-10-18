"""
honeypots/_base.py — Base class for all modular honeypot services
==================================================================
Idea 21 v2: Each protocol is a separate systemd service running as
sensor user. This base class provides the common foundation.

Usage:
    class SSHHoneypot(BaseHoneypot):
        PROTOCOL = "ssh"
        DEFAULT_PORT = 22
        async def handle_connection(self, reader, writer, peer):
            ...

    if __name__ == "__main__":
        SSHHoneypot().run()

Port to 1.0: the honeypot knows nothing about the database. ``log_event`` writes a JSON
line (``honeypots/sink.py``); classification, ``attack_patterns``, ``ics_events``, canaries
and SIEM are done by ``ingest/honeypot.py`` on the host side — from the same fields it used
here in 0.9. Equivalence test: ``tests/test_honeypot_event_metadata.py``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

from honeylens.honeypots.sink import MAX_RAW_CAPTURE, build_record, public_port, write_record


class BaseHoneypot:
    """Base class for all protocol honeypots."""

    PROTOCOL = "unknown"
    DEFAULT_PORT = 0
    TTL_PROFILE = "linux"
    MAX_CONNECTIONS = 200
    CONNECTION_TIMEOUT = 60

    def __init__(self):
        env_key = f"HP_{self.PROTOCOL.upper()}_PORT"
        self.port = int(os.environ.get(env_key, self.DEFAULT_PORT))
        self.logger = logging.getLogger(f"hp_{self.PROTOCOL}")
        self._active_connections = 0

        # Load protocol profile
        try:
            from honeylens.honeypots.honeypots_config import get_profile

            self.profile = get_profile(self.PROTOCOL)
        except ImportError:
            self.profile = {}

    async def handle_connection(self, reader, writer, peer):
        """Override in subclass — handle a single client connection."""
        raise NotImplementedError

    async def _handler(self, reader, writer):
        """Wrapper with timeout, connection limit, and error handling."""
        if self._active_connections >= self.MAX_CONNECTIONS:
            writer.close()
            return

        self._active_connections += 1
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        try:
            await asyncio.wait_for(
                self.handle_connection(reader, writer, peer),
                timeout=self.CONNECTION_TIMEOUT,
            )
        except TimeoutError:
            self.logger.debug("Timeout from %s:%d", peer[0], peer[1])
        except (
            ConnectionResetError,
            BrokenPipeError,
            OSError,
        ) as exc:  # silent: connection cleanup
            logging.getLogger(__name__).debug("ignored: %s", exc)
        except Exception as e:
            self.logger.debug("Error handling %s:%d: %s", peer[0], peer[1], e)
        finally:
            self._active_connections -= 1
            try:
                writer.close()
            except Exception as exc:
                logging.getLogger(__name__).debug("ignored: %s", exc)

    def run(self):
        """Start the honeypot server. Called from __main__."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
        self.logger.info(
            "Starting %s honeypot on port %d (profile: %s)",
            self.PROTOCOL,
            self.port,
            self.TTL_PROFILE,
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        server = loop.run_until_complete(asyncio.start_server(self._handler, "0.0.0.0", self.port))
        self.logger.info("%s honeypot listening on 0.0.0.0:%d", self.PROTOCOL.upper(), self.port)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            self.logger.info("Shutting down %s honeypot", self.PROTOCOL)
        finally:
            server.close()
            loop.run_until_complete(server.wait_closed())
            loop.close()


def log_event(
    protocol: str,
    peer: tuple,
    data: dict,
    attack_type: str | None = None,
    severity: str | None = None,
    proto: str | None = None,
    raw: bytes | None = None,
) -> dict:
    """Write a honeypot event to the JSON sink; returns the written envelope.

    `protocol` names the honeypot *identity* and drives the ``source`` column
    (``honeypot-<protocol>``). The ``protocol`` column defaults to the same
    value, but a honeypot whose identity is not a wire protocol (e.g. the
    ``nginx`` decoy actually speaks HTTPS/HTTP)
    can pass ``proto`` to record the real wire protocol without changing its
    source identity.

    The full event dict travels as ``event`` and lands in ``metadata``; ``payload``
    keeps the short summary. Before 2026-08-20 only the flat columns were written,
    so a honeypot could capture a POST body and still store nothing but its length.

    ``raw`` is the bytes as they arrived. Pass it when the payload rides in the
    body — a loader, a web shell, an exploit chain — and the request as parsed is
    a reconstruction rather than the thing itself. Truncated to ``MAX_RAW_CAPTURE``
    here; the ingest stores it in ``full_payload`` with a SHA-256 over exactly the
    stored bytes, so the hash stays checkable against the column.

    A honeypot that worked out its own ``attack_type`` knows better than a regex,
    so its verdict travels with the event and the ingest does not run the
    classifier over it. When it has none, the ingest asks the central rule set —
    until 2026-08-22 nobody did, and every DB-direct honeypot simply stored a blank
    attack type no matter what the request said.
    """
    src_ip = peer[0] if peer else "0.0.0.0"
    src_port = peer[1] if peer and len(peer) > 1 else 0
    wire_proto = (proto or protocol).upper()
    if "dst_port" in data and public_port(data["dst_port"]) != data["dst_port"]:
        # Metadata carries the protocol port too: the classifier reads dst_port from it.
        data = {**data, "dst_port": public_port(data["dst_port"])}
    payload = data.get("payload") or data.get("message") or json.dumps(data, default=str)[:2000]
    rule_name = data.get("rule") or data.get("phase") or f"{protocol}_event"

    record = build_record(
        source=f"honeypot-{protocol}",
        honeypot=protocol,
        protocol=wire_proto,
        peer=(src_ip, src_port),
        event=data,
        payload=payload,
        dst_port=data.get("dst_port", 0),
        dst_ip=data.get("dst_ip"),
        attack_type=attack_type,
        severity=severity,
        rules=[rule_name] if attack_type else None,
        raw=raw[:MAX_RAW_CAPTURE] if raw else None,
    )
    write_record(record)
    return record
