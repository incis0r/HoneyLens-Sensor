# honeypots/ics/cotp102.py
"""Port-102 dispatcher: TPKT/COTP front-end that routes the first DT payload
to S7comm or IEC 61850 MMS, so both coexist on the ISO-TSAP port.

The port is public, so most of what connects is not ISO transport at all, and an RDP client's
connection request *is* a TPKT + COTP CR. Three gates, in order:

1. the first packet must be a TPKT carrying a COTP Connection Request that is not RDP's —
   otherwise one ``foreign_on_ics_port`` event and no reply;
2. the first data TPDU must open with S7 (0x32) or an ISO session SPDU — otherwise the same;
3. once a session is S7 or MMS, a packet that is no longer that is one desync event and the
   end of the session.

The kind of every recognised request comes from ``honeylens.ics`` (the decoder), not from a
table kept here.
"""

from __future__ import annotations

import asyncio

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.honeypots_config import get_profile
from honeylens.honeypots.hp_s7comm import handle_s7_dt, s7_job_function
from honeylens.honeypots.ics.base import (
    check_tpkt,
    classify,
    cotp_connection_confirm,
    cotp_data,
    cotp_dt_payload,
    frame_hex,
    pack_tpkt,
)
from honeylens.honeypots.ics.foreign import (
    DESYNC_VERDICT,
    FOREIGN_VERDICT,
    desync_event,
    foreign_event,
    guess_foreign,
    read_rest,
)
from honeylens.honeypots.ics.mms import MmsHandler

__all__ = ["Cotp102Honeypot", "check_tpkt", "route_dt_payload"]

_LABEL = "S7comm/MMS"
_FIRST_WAIT = 30
_NEXT_WAIT = 60
_BODY_WAIT = 30
# ISO 8327 session SPDU identifiers that can open a COTP data TPDU on an MMS association:
# give-tokens (0x01, followed by data-transfer), CONNECT, ACCEPT, FINISH, DISCONNECT, ABORT.
_SESSION_SPDUS = frozenset({0x01, 0x0D, 0x0E, 0x09, 0x0A, 0x19})
_COTP_CR = 0xE0


def route_dt_payload(payload: bytes):
    """Return (kind, who) where who in {'s7','mms','unknown'}."""
    if not payload:
        return "enumeration", "unknown"
    if payload[0] == 0x32:
        return "recon", "s7"
    if payload[0] in (0x0D, 0x0E):  # ISO 8327 session CONNECT/ACCEPT SPDU
        return "recon", "mms"
    return "enumeration", "unknown"


def _belongs(who: str, payload: bytes) -> bool:
    """Whether a data TPDU's payload is still the protocol the session was routed to."""
    if not payload:
        return False
    return payload[0] == 0x32 if who == "s7" else payload[0] in _SESSION_SPDUS


class _NotTpkt(Exception):
    """The stream stopped being TPKT. ``consumed`` is what was read of the bad packet."""

    def __init__(self, consumed: bytes, defect: str) -> None:
        super().__init__(defect)
        self.consumed = consumed
        self.defect = defect


class Cotp102Honeypot(BaseHoneypot):
    PROTOCOL = "s7comm"  # keeps the HP_S7COMM_PORT env + sensor-hp-s7comm unit
    DEFAULT_PORT = 102
    TTL_PROFILE = "plc"  # embedded device fingerprint; one source with manifest.ttl_profile
    CONNECTION_TIMEOUT = 120

    async def _read_tpkt(self, reader, wait: float) -> bytes | None:
        """One whole TPKT (header included), ``None`` on a clean end of stream.

        Raises ``_NotTpkt`` when what arrived is not a TPKT or is shorter than it declares;
        bytes a timeout left unread stay in the stream for ``read_rest``.
        """
        try:
            head = await asyncio.wait_for(reader.readexactly(4), timeout=wait)
        except asyncio.IncompleteReadError as exc:
            if not exc.partial:
                return None
            raise _NotTpkt(bytes(exc.partial), "the stream ends inside a TPKT header") from None
        except (TimeoutError, ConnectionError, OSError):
            raise _NotTpkt(b"", "no TPKT header arrived") from None
        defect = check_tpkt(head)
        if defect:
            raise _NotTpkt(head, defect)
        total = (head[2] << 8) | head[3]
        try:
            body = await asyncio.wait_for(reader.readexactly(total - 4), timeout=_BODY_WAIT)
        except asyncio.IncompleteReadError as exc:
            raise _NotTpkt(
                head + bytes(exc.partial),
                f"the TPKT declares {total} bytes and the stream ends after {4 + len(exc.partial)}",
            ) from None
        except (TimeoutError, ConnectionError, OSError):
            raise _NotTpkt(head, f"the TPKT declares {total} bytes that never arrived") from None
        return head + body

    def _foreign(self, peer, data: bytes, defect: str) -> None:
        log_event(
            self.PROTOCOL,
            peer,
            foreign_event(self.port, data, _LABEL, defect),
            *FOREIGN_VERDICT,
            raw=data[:MAX_RAW_EVENT_BYTES] or None,
        )

    def _desync(self, peer, data: bytes, defect: str, frames: int) -> None:
        log_event(
            self.PROTOCOL,
            peer,
            desync_event(self.port, data, _LABEL, defect, frames),
            *DESYNC_VERDICT,
            raw=data[:MAX_RAW_EVENT_BYTES] or None,
        )

    async def handle_connection(self, reader, writer, peer):
        # --- gate 1: TPKT + COTP Connection Request, and not RDP's ---
        try:
            first = await self._read_tpkt(reader, _FIRST_WAIT)
        except _NotTpkt as bad:
            self._foreign(peer, await read_rest(reader, bad.consumed), bad.defect)
            return
        if first is None:
            self._foreign(peer, b"", "the peer connected and sent nothing")
            return
        cr = first[4:]
        if len(cr) < 7 or cr[1] & 0xF0 != _COTP_CR:
            seen = f"0x{cr[1]:02x}" if len(cr) > 1 else "missing"
            defect = f"the first TPDU type is {seen}, not a COTP Connection Request (0xe0)"
            self._foreign(peer, await read_rest(reader, first), defect)
            return
        if guess_foreign(first) == "rdp":
            # An RDP client waits for our confirm before it sends anything else; it gets none.
            self._foreign(peer, first, "the COTP Connection Request carries RDP negotiation")
            return
        writer.write(pack_tpkt(cotp_connection_confirm(cr)))
        await writer.drain()

        s7_prof, mms = get_profile("s7comm"), MmsHandler(get_profile("mms"))
        who = None
        frames = 0
        while True:
            try:
                packet = await self._read_tpkt(reader, _NEXT_WAIT)
            except _NotTpkt as bad:
                if bad.consumed:
                    data = await read_rest(reader, bad.consumed)
                    if frames:
                        self._desync(peer, data, bad.defect, frames)
                    else:
                        self._foreign(peer, data, bad.defect)
                break
            if packet is None:
                break
            payload = cotp_dt_payload(packet[4:])
            if payload is None:
                continue
            if who is None:
                _k, routed = route_dt_payload(payload)
                who = routed if routed != "unknown" else None
            if who is None or not _belongs(who, payload):
                seen = f"0x{payload[0]:02x}" if payload else "nothing"
                defect = f"the COTP data starts with {seen}, not S7 (0x32) or an ISO session SPDU"
                if frames:
                    self._desync(peer, payload, defect, frames)
                else:
                    self._foreign(peer, payload, defect)
                return
            if who == "s7":
                resp, kind = handle_s7_dt(payload, s7_prof)
                proto = "s7comm"
            else:
                resp, kind = mms.handle_mms(payload), mms.last_kind
                proto = "mms"
            if resp:
                writer.write(pack_tpkt(cotp_data(resp)))
                await writer.drain()
            atk, sev = classify(kind)
            md = {
                "phase": "cotp102",
                "route": who,
                "bytes": len(payload),
                # The COTP data as received: a bare S7 PDU or the ISO session payload, the
                # two shapes the s7comm and mms decoders take.
                "frame_hex": frame_hex(payload),
            }
            if who == "s7" and (func_code := s7_job_function(payload)) is not None:
                md["func_code"] = func_code
            log_event(proto, peer, md, attack_type=atk, severity=sev)
            frames += 1
        if frames == 0 and who is None:
            # A connect-only scan: the peer completed the COTP handshake and asked nothing.
            atk, sev = classify("enumeration")
            log_event(
                self.PROTOCOL,
                peer,
                {
                    "phase": "cotp_connect",
                    "route": "unknown",
                    "dst_port": self.port,
                    "bytes": len(cr),
                    "frame_hex": frame_hex(cr),
                },
                attack_type=atk,
                severity=sev,
            )


if __name__ == "__main__":
    Cotp102Honeypot().run()
