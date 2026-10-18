#!/usr/bin/env python3
"""
honeypots/hp_modbus.py — Modbus TCP Honeypot
==============================================
Simulates a Modbus TCP device (PLC/RTU). Responds to read/write
function codes and logs all ICS-relevant events.

Run: python -m honeypots.hp_modbus
Service: sensor-hp-modbus (port 502, needs CAP_NET_BIND_SERVICE)
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event

MODBUS_FC_NAMES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Slave ID",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x2B: "Read Device Identification",
}

WRITE_FCS = {0x05, 0x06, 0x0F, 0x10, 0x16, 0x17}
RECON_FCS = {0x07, 0x08, 0x11, 0x2B}
MAX_PDU = 65535


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

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[Modbus] Connection from %s:%d", peer[0], peer[1])

        try:
            while True:
                header = await asyncio.wait_for(reader.readexactly(7), timeout=60)
                txn_id = struct.unpack(">H", header[0:2])[0]
                struct.unpack(">H", header[2:4])[0]
                length = struct.unpack(">H", header[4:6])[0]
                unit_id = header[6]

                if length < 1 or length > MAX_PDU:
                    break

                pdu = await asyncio.wait_for(reader.readexactly(length - 1), timeout=30)
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

                is_write = fc in WRITE_FCS
                is_recon = fc in RECON_FCS
                is_illegal = fc in range(90, 101) or fc in range(125, 128)

                # Determine attack type
                attack_type = None
                severity = None
                if is_write:
                    attack_type = "ICS_ATTACK"
                    severity = "HIGH"
                elif is_illegal:
                    attack_type = "ICS_ATTACK"
                    severity = "MEDIUM"
                elif is_recon:
                    attack_type = "MODBUS_RECON"
                    severity = "LOW"

                event_data = {
                    "dst_port": self.port,
                    "phase": "modbus_request",
                    "rule": MODBUS_FC_NAMES.get(fc, f"FC_{fc}"),
                    "payload": f"FC={fc} unit={unit_id} addr={address} val={value} qty={quantity}",
                    "txn_id": txn_id,
                    "unit_id": unit_id,
                    "fc": fc,
                    "fc_name": MODBUS_FC_NAMES.get(fc, "unknown"),
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

                if is_write:
                    self.logger.warning(
                        "[Modbus] %s WRITE FC=%d unit=%d addr=%s val=%s",
                        peer[0],
                        fc,
                        unit_id,
                        address,
                        value,
                    )
                elif is_recon:
                    self.logger.info("[Modbus] %s RECON FC=%d unit=%d", peer[0], fc, unit_id)
                else:
                    self.logger.info("[Modbus] %s FC=%d unit=%d", peer[0], fc, unit_id)

                # Build response
                if fc in (0x01, 0x02):
                    qty = quantity or 1
                    byte_count = (qty + 7) // 8
                    resp_pdu = bytes([fc, byte_count]) + b"\x00" * byte_count
                elif fc in (0x03, 0x04):
                    qty = quantity or 1
                    resp_pdu = bytes([fc, qty * 2]) + b"\x00" * (qty * 2)
                elif fc in (0x05, 0x06):
                    resp_pdu = pdu  # Echo back
                elif fc == 0x2B:
                    # Device Identification — return vendor/product/firmware
                    objects = [
                        (0x00, self.vendor.encode()),
                        (0x01, self.product.encode()),
                        (0x02, self.firmware.encode()),
                    ]
                    obj_data = b""
                    for oid, oval in objects:
                        obj_data += bytes([oid, len(oval)]) + oval
                    resp_pdu = bytes([fc, 0x0E, 0x01, 0x01, 0x00, 0x00, len(objects)]) + obj_data
                elif fc == 0x11:
                    # Report Slave ID
                    slave_data = self.device_id.encode()[:32]
                    resp_pdu = bytes([fc, len(slave_data) + 1, 0xFF]) + slave_data
                else:
                    # Exception response
                    resp_pdu = bytes([fc | 0x80, 0x01])

                resp_header = struct.pack(">HHH", txn_id, 0, len(resp_pdu) + 1)
                writer.write(resp_header + bytes([unit_id]) + resp_pdu)
                await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    ModbusHoneypot().run()
