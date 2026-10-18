#!/usr/bin/env python3
"""
honeypots/hp_modbus.py — Modbus TCP Honeypot
==============================================
Simulates a Modbus TCP device (PLC/RTU). Responds to read/write
function codes and logs all ICS-relevant events.

Run: honeylens-hp modbus
Service: hp-modbus (quadlet). Protocol port 502 is < 1024, so the container binds 30502 and
the host firewall DNATs 502 to it -- still no root and no CAP_NET_BIND_SERVICE anywhere.
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.ics.foreign import (
    DESYNC_VERDICT,
    FOREIGN_VERDICT,
    desync_event,
    foreign_event,
    read_rest,
)
from honeylens.honeypots.ics.verdict import verdict_for
from honeylens.ics import decode, flags_for
from honeylens.ics.modbus import request_name

MBAP_LEN = 7
# The MBAP length field counts the unit identifier and the PDU; a PDU is at most 253 bytes.
MIN_ADU_LENGTH = 2
MAX_ADU_LENGTH = 254

# Request PDU lengths the specification fixes. Function codes outside this table are not
# length-checked: a vendor code (UMAS, FC 90) has whatever layout the vendor gave it.
_FIXED_REQUEST_LEN = {1: 5, 2: 5, 3: 5, 4: 5, 5: 5, 6: 5, 7: 1, 11: 1, 12: 1, 17: 1, 22: 7}
# function code -> (offset of the byte count, bytes before the data it counts)
_COUNTED_REQUEST = {15: (5, 6), 16: (5, 6), 23: (9, 10)}

# The most a read may ask for (Modbus Application Protocol 1.1b3, 6.1-6.4).
_MAX_BITS = 2000
_MAX_REGISTERS = 125


def check_mbap(header: bytes) -> str | None:
    """Why these seven bytes are not an MBAP header, or ``None`` when they are one."""
    if len(header) < MBAP_LEN:
        return f"{len(header)} byte(s) is not an MBAP header"
    protocol_id = int.from_bytes(header[2:4], "big")
    if protocol_id != 0:
        return f"protocol identifier 0x{protocol_id:04x} is not 0 (Modbus)"
    length = int.from_bytes(header[4:6], "big")
    if not MIN_ADU_LENGTH <= length <= MAX_ADU_LENGTH:
        return f"length {length} is outside {MIN_ADU_LENGTH}..{MAX_ADU_LENGTH}"
    return None


def check_pdu(pdu: bytes) -> str | None:
    """Why this is not a request PDU, or ``None``. Checks only what the specification fixes:
    a function code that exists, and the length it gives the fixed-layout requests. That is
    what tells a DICOM association (protocol identifier bytes 00 00, "function code" 1,
    204 bytes) from a Read Coils, which is five."""
    if not pdu:
        return "the PDU is empty"
    fc = pdu[0]
    if fc == 0:
        return "function code 0 does not exist"
    want = _FIXED_REQUEST_LEN.get(fc)
    if want is not None and len(pdu) != want:
        return f"function code {fc} is a {want}-byte request, got {len(pdu)}"
    counted = _COUNTED_REQUEST.get(fc)
    if counted is not None:
        at, before = counted
        if len(pdu) < before:
            return f"function code {fc} needs at least {before} bytes, got {len(pdu)}"
        if len(pdu) != before + pdu[at]:
            return (
                f"function code {fc} declares {pdu[at]} data byte(s), carries {len(pdu) - before}"
            )
    if fc == 8 and len(pdu) < 3:
        return f"function code 8 needs a sub-function, got {len(pdu)} byte(s)"
    if fc == 43 and len(pdu) < 2:
        return "function code 43 needs an MEI type"
    return None


class ModbusHoneypot(BaseHoneypot):
    PROTOCOL = "modbus"
    DEFAULT_PORT = 502
    TTL_PROFILE = "plc"
    CONNECTION_TIMEOUT = 120

    def __init__(self):
        super().__init__()
        p = self.profile
        self.device_id = p.get("device_id", "Schneider Electric PM5560")
        self.vendor = p.get("vendor", "Schneider Electric")
        self.product = p.get("product_code", "PM5560")
        self.firmware = p.get("firmware", "3.4.2")
        self.unit_id = p.get("unit_id", 1)

    async def _read(self, reader, n: int, wait: float) -> tuple[bytes, bool]:
        """``n`` bytes and True, or what arrived before the stream ended and False. On a
        timeout the bytes stay in the reader, where ``read_rest`` finds them."""
        try:
            return await asyncio.wait_for(reader.readexactly(n), timeout=wait), True
        except asyncio.IncompleteReadError as exc:
            return bytes(exc.partial), False
        except TimeoutError:
            return b"", False

    async def _not_modbus(self, reader, peer, consumed: bytes, defect: str, frames: int):
        """One event for a stream that is not (or is no longer) Modbus, then nothing more."""
        data = await read_rest(reader, consumed)
        if not data:
            return  # the peer connected and left, or an idle session timed out
        if frames == 0:
            event, verdict = foreign_event(self.port, data, "Modbus", defect), FOREIGN_VERDICT
        else:
            event, verdict = desync_event(self.port, data, "Modbus", defect, frames), DESYNC_VERDICT
        log_event(self.PROTOCOL, peer, event, *verdict, raw=data[:MAX_RAW_EVENT_BYTES])
        self.logger.info(
            "[Modbus] %s not Modbus (%s): %s", peer[0], event["foreign_protocol"], defect
        )

    def _response(self, pdu: bytes) -> bytes:
        """The response PDU. Replies are unchanged from before the recognition gate, except
        that a read quantity outside the specification is answered with exception 3 (illegal
        data value), where building the reply used to raise."""
        fc = pdu[0]
        if fc in (0x01, 0x02, 0x03, 0x04):
            qty = struct.unpack(">H", pdu[3:5])[0]
            if not 1 <= qty <= (_MAX_BITS if fc in (0x01, 0x02) else _MAX_REGISTERS):
                return bytes([fc | 0x80, 0x03])
            if fc in (0x01, 0x02):
                byte_count = (qty + 7) // 8
                return bytes([fc, byte_count]) + b"\x00" * byte_count
            return bytes([fc, qty * 2]) + b"\x00" * (qty * 2)
        if fc in (0x05, 0x06):
            return pdu  # Echo back
        if fc == 0x2B:
            # Device Identification — return vendor/product/firmware
            objects = [
                (0x00, self.vendor.encode()[:255]),
                (0x01, self.product.encode()[:255]),
                (0x02, self.firmware.encode()[:255]),
            ]
            obj_data = b""
            for oid, oval in objects:
                obj_data += bytes([oid, len(oval)]) + oval
            return bytes([fc, 0x0E, 0x01, 0x01, 0x00, 0x00, len(objects)]) + obj_data
        if fc == 0x11:
            # Report Slave ID
            slave_data = self.device_id.encode()[:32]
            return bytes([fc, len(slave_data) + 1, 0xFF]) + slave_data
        # Exception response
        return bytes([(fc | 0x80) & 0xFF, 0x01])

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[Modbus] Connection from %s:%d", peer[0], peer[1])

        frames = 0
        try:
            while True:
                header, whole = await self._read(reader, MBAP_LEN, 60)
                if not whole:
                    await self._not_modbus(
                        reader, peer, header, "the stream ended inside the MBAP header", frames
                    )
                    return
                defect = check_mbap(header)
                if defect:
                    await self._not_modbus(reader, peer, header, defect, frames)
                    return
                txn_id = struct.unpack(">H", header[0:2])[0]
                length = struct.unpack(">H", header[4:6])[0]
                unit_id = header[6]

                pdu, whole = await self._read(reader, length - 1, 30)
                if not whole:
                    defect = f"the stream ended inside a PDU declared as {length - 1} byte(s)"
                    await self._not_modbus(reader, peer, header + pdu, defect, frames)
                    return
                defect = check_pdu(pdu)
                if defect:
                    await self._not_modbus(reader, peer, header + pdu, defect, frames)
                    return
                frames += 1
                fc = pdu[0]

                # Parse address/value
                address = value = quantity = None
                if fc in (0x01, 0x02, 0x03, 0x04) and len(pdu) >= 5:
                    address = struct.unpack(">H", pdu[1:3])[0]
                    quantity = struct.unpack(">H", pdu[3:5])[0]
                elif fc in (0x05, 0x06) and len(pdu) >= 5:
                    address = struct.unpack(">H", pdu[1:3])[0]
                    value = struct.unpack(">H", pdu[3:5])[0]
                elif fc in (0x0F, 0x10) and len(pdu) >= 6:
                    address = struct.unpack(">H", pdu[1:3])[0]
                    quantity = struct.unpack(">H", pdu[3:5])[0]

                # What the request means, and so what it is called and how it is judged,
                # comes from the decoder: this decoy keeps no function-code table.
                frame = decode(self.PROTOCOL, pdu)
                attack_type, severity = verdict_for(frame)
                is_write = flags_for(frame)["is_write"]
                name = request_name(pdu)

                event_data = {
                    "dst_port": self.port,
                    "phase": "modbus_request",
                    "rule": name,
                    "payload": f"FC={fc} unit={unit_id} addr={address} val={value} qty={quantity}",
                    "txn_id": txn_id,
                    "unit_id": unit_id,
                    "fc": fc,
                    "fc_name": name,
                    "pdu_hex": pdu.hex(),
                    "is_write": is_write,
                }
                if address is not None:
                    event_data["address"] = address
                if value is not None:
                    event_data["value"] = value
                if quantity is not None:
                    event_data["quantity"] = quantity

                log_event(self.PROTOCOL, peer, event_data, attack_type, severity)

                if attack_type == "ICS_ATTACK":
                    self.logger.warning(
                        "[Modbus] %s %s FC=%d (%s) unit=%d addr=%s val=%s",
                        peer[0],
                        severity,
                        fc,
                        name,
                        unit_id,
                        address,
                        value,
                    )
                else:
                    self.logger.info("[Modbus] %s FC=%d (%s) unit=%d", peer[0], fc, name, unit_id)

                resp_pdu = self._response(pdu)
                resp_header = struct.pack(">HHH", txn_id, 0, len(resp_pdu) + 1)
                writer.write(resp_header + bytes([unit_id]) + resp_pdu)
                await writer.drain()

        except (TimeoutError, ConnectionError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    ModbusHoneypot().run()
