# honeypots/ics/cotp102.py
"""Port-102 dispatcher: TPKT/COTP front-end that routes the first DT payload
to S7comm or IEC 61850 MMS, so both coexist on the ISO-TSAP port."""

from __future__ import annotations

import asyncio

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.honeypots_config import get_profile
from honeylens.honeypots.hp_s7comm import handle_s7_dt, s7_job_function
from honeylens.honeypots.ics.base import (
    classify,
    cotp_connection_confirm,
    cotp_data,
    cotp_dt_payload,
    frame_hex,
    pack_tpkt,
    parse_tpkt,
)
from honeylens.honeypots.ics.mms import MmsHandler


def route_dt_payload(payload: bytes):
    """Return (kind, who) where who in {'s7','mms','unknown'}."""
    if not payload:
        return "enumeration", "unknown"
    if payload[0] == 0x32:
        return "recon", "s7"
    if payload[0] in (0x0D, 0x0E):  # ISO 8327 session CONNECT/ACCEPT SPDU
        return "recon", "mms"
    return "enumeration", "unknown"


class Cotp102Honeypot(BaseHoneypot):
    PROTOCOL = "s7comm"  # keeps the HP_S7COMM_PORT env + sensor-hp-s7comm unit
    DEFAULT_PORT = 102
    TTL_PROFILE = "plc"  # embedded device fingerprint; one source with manifest.ttl_profile
    CONNECTION_TIMEOUT = 120

    async def _read_tpkt(self, reader):
        head = await asyncio.wait_for(reader.readexactly(4), timeout=30)
        total = (head[2] << 8) | head[3]
        body = await asyncio.wait_for(reader.readexactly(total - 4), timeout=30)
        return parse_tpkt(head + body)[0]

    async def handle_connection(self, reader, writer, peer):
        try:
            cr = await self._read_tpkt(reader)  # COTP CR
        except Exception:
            return
        writer.write(pack_tpkt(cotp_connection_confirm(cr)))
        await writer.drain()
        s7_prof, mms = get_profile("s7comm"), MmsHandler(get_profile("mms"))
        who = None
        while True:
            try:
                tpdu = await asyncio.wait_for(self._read_tpkt(reader), timeout=60)
            except Exception:
                break
            payload = cotp_dt_payload(tpdu)
            if payload is None:
                continue
            if who is None:
                _k, who = route_dt_payload(payload)
            if who == "s7":
                resp, kind = handle_s7_dt(payload, s7_prof)
                proto = "s7comm"
            elif who == "mms":
                resp, kind = mms.handle_mms(payload), mms.last_kind
                proto = "mms"
            else:
                resp, kind, proto = None, "enumeration", "s7comm"
            if resp:
                writer.write(pack_tpkt(cotp_data(resp)))
                await writer.drain()
            atk, sev = classify(kind)
            md = {
                "phase": "cotp102",
                "route": who or "unknown",
                "bytes": len(payload),
                # The COTP data as received: a bare S7 PDU or the ISO session payload, the
                # two shapes the s7comm and mms decoders take.
                "frame_hex": frame_hex(payload),
            }
            if who == "s7" and (func_code := s7_job_function(payload)) is not None:
                md["func_code"] = func_code
            log_event(proto, peer, md, attack_type=atk, severity=sev)


if __name__ == "__main__":
    Cotp102Honeypot().run()
