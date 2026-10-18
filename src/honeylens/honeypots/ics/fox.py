# honeypots/ics/fox.py
"""Niagara Fox (Tridium) honeypot — TCP 1911. Identify-depth: emit the
station `fox hello` identity block scanners fingerprint on, classify."""

from __future__ import annotations

import asyncio
import re

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.ics.base import classify
from honeylens.honeypots.ics.foreign import FOREIGN_VERDICT, foreign_event

# A request-line: method token, a path, and HTTP/1.x, at the very start of the frame. A bare
# "HTTP" anywhere in the bytes is not enough — a Fox frame can legitimately contain it.
_HTTP_REQUEST_LINE = re.compile(rb"[a-z]{3,10} \S+ http/1\.[01](?:\r?\n|\Z)", re.IGNORECASE)


def is_http_request_line(data: bytes) -> bool:
    return _HTTP_REQUEST_LINE.match(data) is not None


# Every Fox message opens with the protocol name and the channel letter: "fox a <seq> ...".
_FOX_PREFIX = b"fox a "


def is_fox_frame(data: bytes) -> bool:
    return data.startswith(_FOX_PREFIX)


def fox_kind(text: str) -> str:
    """The taxonomy kind of a Fox frame, from its lowercased text. There is no Fox decoder;
    this keyword map is the whole of it and must only ever be handed a recognised frame."""
    if any(k in text for k in ("write", "invoke", "set ", "save")):
        return "write"
    if any(k in text for k in ("file:", "config", "/auth", "ord ")):
        return "recon"
    return "enumeration"


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
        except (TimeoutError, ConnectionError, OSError):
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
        if not is_fox_frame(data):
            # RDP, SMB, SIP, TLS, a connect that sends nothing: whatever it is, it is not a
            # Fox session, and its bytes are not searched for Fox intent.
            log_event(
                self.PROTOCOL,
                peer,
                foreign_event(self.port, data, "Fox", "the stream does not start with 'fox a '"),
                *FOREIGN_VERDICT,
                raw=data[:MAX_RAW_EVENT_BYTES] or None,
            )
            return
        text = data.decode("latin-1", "ignore").lower()
        atk, sev = classify(fox_kind(text))
        log_event(
            self.PROTOCOL,
            peer,
            {"phase": "fox_session", "client_bytes": len(data), "preview": text[:200]},
            attack_type=atk,
            severity=sev,
        )


if __name__ == "__main__":
    FoxHoneypot().run()
