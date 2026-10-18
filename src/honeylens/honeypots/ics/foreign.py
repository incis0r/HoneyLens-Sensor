"""What an industrial decoy does with a stream that is not its protocol.

One rule for the whole family: a stream that fails the decoy's own recognition is recorded
once, as ``foreign_on_ics_port`` with ``ics: False`` (so it stays out of ``ics_events``) and the
verdict ``SCANNER``/LOW, and is never parsed. A public port collects HTTP, TLS, RDP and SMB
whatever service it claims; a decoy that parses those as frames invents industrial events, and
one that drops them keeps no evidence that anything arrived.

The helpers build the event and leave the write to the caller, so each decoy logs under its
own name through its own ``log_event``.
"""

from __future__ import annotations

import asyncio
import re

FOREIGN_VERDICT = ("SCANNER", "LOW")
DESYNC_VERDICT = ("ICS_RECON", "LOW")

# How much of a foreign stream is read after the bytes that failed recognition, and how long
# the decoy waits for it. Enough for a request line and headers or a ClientHello.
FOREIGN_READ = 4096
FOREIGN_WAIT = 2.0

_PREVIEW_CHARS = 200
_FIRST_BYTES = 64

_HTTP_START = re.compile(rb"[A-Za-z]{3,10} \S+ HTTP/\d", re.DOTALL)


def guess_foreign(data: bytes) -> str:
    """Name what a stream most likely is, from its first bytes. A label for the analyst, not
    a parser: ``text``, ``binary`` and ``empty`` are honest answers."""
    if not data:
        return "empty"
    if len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03:
        return "tls"
    if _HTTP_START.match(data) or data.startswith(b"PRI * HTTP/2"):
        return "http"
    if data.startswith(b"SSH-"):
        return "ssh"
    if data.startswith(b"fox ") or b"fox.version" in data[:256]:
        return "fox"
    if data[4:8] in (b"\xffSMB", b"\xfeSMB"):
        return "smb"
    if data[:2] == b"\x03\x00":
        # TPKT carries both ISO transport (S7, MMS) and RDP. An RDP client says so in the
        # connection request: a routing cookie, or an RDP negotiation request (type 1,
        # length 8) as the last eight bytes.
        if b"Cookie: mstshash=" in data[:128] or (
            len(data) >= 19 and data[5] == 0xE0 and data[-8] == 0x01 and data[-6:-4] == b"\x08\x00"
        ):
            return "rdp"
        return "tpkt"
    head = data[:256]
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    return "text" if printable / len(head) > 0.9 else "binary"


def preview(data: bytes) -> str:
    """The first bytes as text, every non-printable byte a dot."""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:_PREVIEW_CHARS])


async def read_rest(reader, consumed: bytes) -> bytes:
    """``consumed`` plus whatever the peer has already sent; never raises."""
    try:
        rest = await asyncio.wait_for(reader.read(FOREIGN_READ), timeout=FOREIGN_WAIT)
    except (TimeoutError, ConnectionError, OSError):
        rest = b""
    return consumed + rest


def _evidence(port: int, data: bytes, defect: str) -> dict:
    return {
        "dst_port": port,
        "defect": defect,
        "foreign_protocol": guess_foreign(data),
        "client_bytes": len(data),
        "preview": preview(data),
        "first_bytes_hex": data[:_FIRST_BYTES].hex(),
    }


def foreign_event(port: int, data: bytes, label: str, defect: str) -> dict:
    """The event for a stream that never was ``label``. Log it with ``FOREIGN_VERDICT``."""
    event = _evidence(port, data, defect)
    guess = event["foreign_protocol"]
    event.update(
        phase="foreign_on_ics_port",
        ics=False,
        rule=f"not {label}: {guess}",
        payload=f"non-{label} traffic on port {port}: {guess}, {len(data)} bytes",
    )
    return event


def desync_event(
    port: int, data: bytes, label: str, defect: str, frames: int, phase: str = "ics_desync"
) -> dict:
    """The event for a peer that framed ``label`` correctly ``frames`` times and then stopped:
    a fuzzer or a broken client. Log it with ``DESYNC_VERDICT``."""
    event = _evidence(port, data, defect)
    event.update(
        phase=phase,
        frames_before=frames,
        rule="malformed frame after a valid session",
        payload=f"{label} framing lost after {frames} frame(s): {defect}",
    )
    return event
