# honeypots/ics/fox.py
"""Niagara Fox (Tridium) honeypot — TCP 1911. Identify-depth: emit the
station `fox hello` identity block scanners fingerprint on, classify."""

from __future__ import annotations

import asyncio
import re

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.ics.base import classify

# A request-line: method token, a path, and HTTP/1.x, at the very start of the frame. A bare
# "HTTP" anywhere in the bytes is not enough — a Fox frame can legitimately contain it.
_HTTP_REQUEST_LINE = re.compile(rb"[a-z]{3,10} \S+ http/1\.[01](?:\r?\n|\Z)", re.IGNORECASE)


def is_http_request_line(data: bytes) -> bool:
    return _HTTP_REQUEST_LINE.match(data) is not None


def build_fox_hello(profile: dict, peer_ip: str) -> bytes:
    p = profile
    lines = [
        "fox a 0 -1 fox hello",
        "{",
        "fox.version=s:1.0.1",
        "id=i:1",
        f"hostName=s:{p.get('hostname', 'jace')}",
        f"hostAddress=s:{peer_ip}",
        "app.name=s:Station",
        f"app.version=s:{p.get('niagara_version', '4.10.3.36')}",
        "vm.name=s:Java HotSpot(TM) Server VM",
        "vm.version=s:25.281-b09",
        "os.name=s:QNX",
        f"station.name=s:{p.get('station_name', 'Station1')}",
        "lang=s:en",
        f"timeZone=s:{p.get('timezone', 'America/New_York')}",
        f"hostId=s:{p.get('host_id', 'Qnx-0000')}",
        f"vmUuid=s:{p.get('vm_uuid', '00000000')}",
        f"brandId=s:{p.get('brand_id', 'vykon')}",
        "}",
        ";;",
        "",
    ]
    return ("\n".join(lines)).encode()


class FoxHoneypot(BaseHoneypot):
    PROTOCOL = "fox"
    DEFAULT_PORT = 1911
    TTL_PROFILE = "plc"  # embedded device fingerprint; one source with manifest.ttl_profile
    CONNECTION_TIMEOUT = 30

    async def handle_connection(self, reader, writer, peer):
        writer.write(build_fox_hello(self.profile, peer[0]))
        await writer.drain()
        # read at most one client frame to learn intent (bounded)
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
        except TimeoutError:
            data = b""
        if is_http_request_line(data):
            # A web scanner on a high port is not an ICS exchange. `ics=False` tells the
            # ingest not to write an ics_events row; dst_port rides along because that
            # row was the only place the port survived.
            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "http_on_ics_port",
                    "ics": False,
                    "dst_port": self.port,
                    "client_bytes": len(data),
                    "preview": data.decode("latin-1", "ignore").lower()[:200],
                },
                attack_type="SCANNER",
                severity="LOW",
                raw=data[:MAX_RAW_EVENT_BYTES] or None,
            )
            return
        kind = "enumeration"
        text = data.decode("latin-1", "ignore").lower()
        if any(k in text for k in ("file:", "config", "/auth", "ord ")):
            kind = "recon"
        if any(k in text for k in ("write", "invoke", "set ", "save")):
            kind = "write"
        atk, sev = classify(kind)
        log_event(
            self.PROTOCOL,
            peer,
            {"phase": "fox_session", "client_bytes": len(data), "preview": text[:200]},
            attack_type=atk,
            severity=sev,
        )


if __name__ == "__main__":
    FoxHoneypot().run()
