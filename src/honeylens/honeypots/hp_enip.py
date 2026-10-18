#!/usr/bin/env python3
"""
honeypots/hp_enip.py — EtherNet/IP (CIP) Honeypot
====================================================
Simulates an EtherNet/IP device (CompactLogix PLC). Responds to
encapsulation commands and CIP service requests, logs all ICS-relevant events.

Run: python -m honeypots.hp_enip
Service: sensor-hp-enip (port 44818)
"""

from __future__ import annotations

import asyncio
import struct

from honeylens.honeypots._base import BaseHoneypot, log_event

ENIP_CMD_NAMES = {
    0x0001: "NOP",
    0x0004: "ListServices",
    0x0063: "ListIdentity",
    0x0064: "ListInterfaces",
    0x0065: "RegisterSession",
    0x0066: "UnregisterSession",
    0x006F: "SendRRData",
    0x0070: "SendUnitData",
}

CIP_SERVICE_NAMES = {
    0x01: "Get_Attribute_All",
    0x0E: "Get_Attribute_Single",
    0x10: "Set_Attribute_Single",
    0x05: "Reset",
    0x4B: "Execute_PCCC",
    0x52: "Read_Tag",
    0x53: "Write_Tag",
}

ENCAP_HEADER_SIZE = 24


class ENIPHoneypot(BaseHoneypot):
    PROTOCOL = "enip"
    DEFAULT_PORT = 44818
    TTL_PROFILE = "plc"
    CONNECTION_TIMEOUT = 120

    def __init__(self):
        super().__init__()
        p = self.profile
        self.vendor_name = p.get("vendor_name", "Rockwell Automation")
        self.product_name = p.get("product_name", "1769-L33ER CompactLogix")
        self.serial = p.get("serial", "0xABCD1234")
        self.product_code = p.get("product_code", 55)
        self.device_type = p.get("device_type", 14)
        self.firmware = p.get("firmware", "33.011")
        self._next_session = 1

    def _parse_firmware(self):
        """Parse firmware string into major/minor bytes."""
        parts = self.firmware.split(".")
        major = int(parts[0]) if len(parts) > 0 else 33
        minor = int(parts[1]) if len(parts) > 1 else 0
        return major, minor

    def _build_encap_header(
        self, command, length, session_handle, status, sender_context, options=0
    ):
        """Build a 24-byte EtherNet/IP encapsulation header."""
        return struct.pack(
            "<HHI I 8s I", command, length, session_handle, status, sender_context, options
        )

    def _build_list_services_response(self, sender_context):
        """Build ListServices response with Communications service."""
        # Service entry: Type ID (2) + Length (2) + Version (2) +
        # Capability Flags (2) + Service Name (16)
        service_name = b"Communications\x00\x00"  # 16 bytes padded
        service_entry = struct.pack(
            "<HH HH 16s",
            0x0100,  # Type ID: Communications
            20,  # Length of service entry data
            1,  # Version
            0x0120,  # Capability: TCP + UDP
            service_name,
        )
        # Item count
        items_data = struct.pack("<H", 1) + service_entry

        return self._build_encap_header(0x0004, len(items_data), 0, 0, sender_context) + items_data

    def _build_list_identity_response(self, sender_context):
        """Build ListIdentity response with device identity."""
        fw_major, fw_minor = self._parse_firmware()
        serial_int = int(self.serial, 16) if isinstance(self.serial, str) else self.serial
        product_name_bytes = self.product_name.encode("utf-8")[:32]

        # CIP Identity item data:
        # Protocol Version (2) + Socket Address (16) + Vendor ID (2) +
        # Device Type (2) + Product Code (2) + Revision Major (1) +
        # Revision Minor (1) + Status (2) + Serial Number (4) +
        # Product Name Length (1) + Product Name + State (1)

        # Socket address: sin_family(2) + sin_port(2) + sin_addr(4) + sin_zero(8)
        socket_addr = struct.pack(
            ">HH 4s 8s",
            2,  # AF_INET
            44818,  # port (big-endian in sockaddr)
            b"\x00\x00\x00\x00",
            b"\x00" * 8,
        )

        identity_data = struct.pack("<H", 1)  # Protocol version
        identity_data += socket_addr
        identity_data += struct.pack("<H", 1)  # Vendor ID (Rockwell = 1)
        identity_data += struct.pack("<H", self.device_type)
        identity_data += struct.pack("<H", self.product_code)
        identity_data += struct.pack("<BB", fw_major, fw_minor)
        identity_data += struct.pack("<H", 0x0030)  # Status: owned, configured
        identity_data += struct.pack("<I", serial_int & 0xFFFFFFFF)
        identity_data += struct.pack("<B", len(product_name_bytes))
        identity_data += product_name_bytes
        identity_data += struct.pack("<B", 0x03)  # State: Run

        # Wrap in CPF item: Type 0x000C + Length + data
        item = struct.pack("<HH", 0x000C, len(identity_data)) + identity_data
        items_data = struct.pack("<H", 1) + item  # Item count = 1

        return self._build_encap_header(0x0063, len(items_data), 0, 0, sender_context) + items_data

    def _build_list_interfaces_response(self, sender_context):
        """Build ListInterfaces response with empty list."""
        items_data = struct.pack("<H", 0)  # Item count = 0
        return self._build_encap_header(0x0064, len(items_data), 0, 0, sender_context) + items_data

    def _build_register_session_response(self, sender_context, session_handle):
        """Build RegisterSession response."""
        # Data: Protocol Version (2) + Options Flags (2)
        data = struct.pack("<HH", 1, 0)
        return self._build_encap_header(0x0065, len(data), session_handle, 0, sender_context) + data

    def _build_unregister_session_response(self, sender_context, session_handle):
        """Build UnregisterSession response (no data)."""
        return self._build_encap_header(0x0066, 0, session_handle, 0, sender_context)

    def _build_sendrr_response(self, sender_context, session_handle, cip_response):
        """Build SendRRData response wrapping a CIP reply."""
        # Interface Handle (4) + Timeout (2) + CPF (item count + items)
        # CPF: Address Item (null, type=0x0000, len=0) +
        #      Data Item (type=0x00B2, len=N, data=cip_response)
        cpf = struct.pack("<HH", 0x0000, 0)  # Null address item
        cpf += struct.pack("<HH", 0x00B2, len(cip_response)) + cip_response
        data = struct.pack("<IH H", 0, 0, 2) + cpf  # iface=0, timeout=0, count=2

        return self._build_encap_header(0x006F, len(data), session_handle, 0, sender_context) + data

    def _handle_cip_service(self, cip_data, peer):
        """Parse CIP service request, log event, return (cip_response, attack_type, severity)."""
        if len(cip_data) < 2:
            return b"\x80\x01\x00\x08\x00", None, None  # General error

        service_code = cip_data[0] & 0x7F  # Mask request bit
        cip_data[1]  # in words

        attack_type = None
        severity = None

        if service_code == 0x01:  # Get_Attribute_All
            attack_type = "ICS_RECON"
            severity = "LOW"
            # Reply: service | 0x80, reserved, status=0, vendor/product data
            fw_major, fw_minor = self._parse_firmware()
            attr_data = struct.pack("<H", 1)  # Vendor ID
            attr_data += struct.pack("<H", self.device_type)
            attr_data += struct.pack("<H", self.product_code)
            attr_data += struct.pack("<BB", fw_major, fw_minor)
            cip_resp = struct.pack("<BBH", service_code | 0x80, 0, 0) + attr_data

        elif service_code == 0x0E:  # Get_Attribute_Single
            attack_type = "ICS_RECON"
            severity = "LOW"
            cip_resp = struct.pack("<BBH", service_code | 0x80, 0, 0) + b"\x00\x00"

        elif service_code == 0x10:  # Set_Attribute_Single
            attack_type = "ICS_ATTACK"
            severity = "HIGH"
            cip_resp = struct.pack("<BBH", service_code | 0x80, 0, 0)

        elif service_code == 0x05:  # Reset
            attack_type = "ICS_ATTACK"
            severity = "CRITICAL"
            cip_resp = struct.pack("<BBH", service_code | 0x80, 0, 0)

        elif service_code == 0x4B:  # Execute PCCC
            attack_type = "ICS_ATTACK"
            severity = "CRITICAL"
            cip_resp = struct.pack("<BBH", service_code | 0x80, 0, 0)

        elif service_code == 0x52:  # Read Tag Service
            attack_type = "ICS_RECON"
            severity = "MEDIUM"
            # Return dummy tag data
            cip_resp = struct.pack("<BBH", service_code | 0x80, 0, 0)
            cip_resp += struct.pack("<HH", 0x00C1, 0)  # type SINT, value 0

        elif service_code == 0x53:  # Write Tag Service
            attack_type = "ICS_ATTACK"
            severity = "HIGH"
            cip_resp = struct.pack("<BBH", service_code | 0x80, 0, 0)

        else:
            # Unknown CIP service — return general error
            cip_resp = struct.pack("<BBH", service_code | 0x80, 0, 0x0008)

        return cip_resp, attack_type, severity

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[EtherNet/IP] Connection from %s:%d", peer[0], peer[1])
        session_handle = 0

        try:
            while True:
                # Read 24-byte encapsulation header
                header = await asyncio.wait_for(reader.readexactly(ENCAP_HEADER_SIZE), timeout=60)

                command, length, sess, _status, sender_context, _options = struct.unpack(
                    "<HHI I 8s I", header
                )

                # Read command-specific data
                cmd_data = b""
                if length > 0:
                    if length > 65535:
                        break
                    cmd_data = await asyncio.wait_for(reader.readexactly(length), timeout=30)

                cmd_name = ENIP_CMD_NAMES.get(command, f"CMD_0x{command:04X}")
                response = None

                if command == 0x0001:  # NOP
                    event_data = {
                        "dst_port": self.port,
                        "phase": "enip_nop",
                        "rule": "NOP",
                        "payload": f"NOP from {peer[0]}",
                    }
                    log_event(self.PROTOCOL, peer, event_data)
                    continue  # No response

                elif command == 0x0004:  # ListServices
                    event_data = {
                        "dst_port": self.port,
                        "phase": "enip_list_services",
                        "rule": "ListServices",
                        "payload": f"ListServices from {peer[0]}",
                    }
                    log_event(self.PROTOCOL, peer, event_data, "ICS_RECON", "MEDIUM")
                    self.logger.info("[EtherNet/IP] %s ListServices", peer[0])
                    response = self._build_list_services_response(sender_context)

                elif command == 0x0063:  # ListIdentity
                    event_data = {
                        "dst_port": self.port,
                        "phase": "enip_list_identity",
                        "rule": "ListIdentity",
                        "payload": f"ListIdentity from {peer[0]}",
                    }
                    log_event(self.PROTOCOL, peer, event_data, "ICS_RECON", "MEDIUM")
                    self.logger.info("[EtherNet/IP] %s ListIdentity", peer[0])
                    response = self._build_list_identity_response(sender_context)

                elif command == 0x0064:  # ListInterfaces
                    event_data = {
                        "dst_port": self.port,
                        "phase": "enip_list_interfaces",
                        "rule": "ListInterfaces",
                        "payload": f"ListInterfaces from {peer[0]}",
                    }
                    log_event(self.PROTOCOL, peer, event_data, "ICS_RECON", "LOW")
                    self.logger.info("[EtherNet/IP] %s ListInterfaces", peer[0])
                    response = self._build_list_interfaces_response(sender_context)

                elif command == 0x0065:  # RegisterSession
                    session_handle = self._next_session
                    self._next_session += 1
                    event_data = {
                        "dst_port": self.port,
                        "phase": "enip_register_session",
                        "rule": "RegisterSession",
                        "payload": f"RegisterSession from {peer[0]} session={session_handle}",
                        "session_handle": session_handle,
                    }
                    log_event(self.PROTOCOL, peer, event_data)
                    self.logger.info(
                        "[EtherNet/IP] %s RegisterSession handle=%d", peer[0], session_handle
                    )
                    response = self._build_register_session_response(sender_context, session_handle)

                elif command == 0x0066:  # UnregisterSession
                    event_data = {
                        "dst_port": self.port,
                        "phase": "enip_unregister_session",
                        "rule": "UnregisterSession",
                        "payload": f"UnregisterSession from {peer[0]} session={sess}",
                        "session_handle": sess,
                    }
                    log_event(self.PROTOCOL, peer, event_data)
                    self.logger.info("[EtherNet/IP] %s UnregisterSession handle=%d", peer[0], sess)
                    response = self._build_unregister_session_response(sender_context, sess)

                elif command == 0x006F:  # SendRRData
                    # Parse CIP from SendRRData:
                    # Interface Handle (4) + Timeout (2) + CPF items
                    cip_data = b""
                    if len(cmd_data) >= 6:
                        # Skip interface handle (4) + timeout (2)
                        cpf_data = cmd_data[6:]
                        if len(cpf_data) >= 2:
                            item_count = struct.unpack("<H", cpf_data[0:2])[0]
                            offset = 2
                            for _ in range(item_count):
                                if offset + 4 > len(cpf_data):
                                    break
                                item_type, item_len = struct.unpack(
                                    "<HH", cpf_data[offset : offset + 4]
                                )
                                offset += 4
                                if item_type == 0x00B2:  # Unconnected Data Item
                                    cip_data = cpf_data[offset : offset + item_len]
                                offset += item_len

                    service_code = cip_data[0] & 0x7F if cip_data else 0
                    service_name = CIP_SERVICE_NAMES.get(service_code, f"CIP_0x{service_code:02X}")

                    cip_resp, attack_type, severity = self._handle_cip_service(cip_data, peer)

                    event_data = {
                        "dst_port": self.port,
                        "phase": "enip_sendrr_cip",
                        "rule": service_name,
                        "payload": (
                            f"SendRRData CIP service=0x{service_code:02X} "
                            f"({service_name}) from {peer[0]}"
                        ),
                        "session_handle": sess,
                        "cip_service": service_code,
                        "cip_service_name": service_name,
                        "cip_data_hex": cip_data.hex(),
                    }
                    log_event(self.PROTOCOL, peer, event_data, attack_type, severity)

                    if attack_type == "ICS_ATTACK":
                        self.logger.warning(
                            "[EtherNet/IP] %s CIP %s (0x%02X) — %s",
                            peer[0],
                            service_name,
                            service_code,
                            severity,
                        )
                    else:
                        self.logger.info(
                            "[EtherNet/IP] %s CIP %s (0x%02X)", peer[0], service_name, service_code
                        )

                    response = self._build_sendrr_response(sender_context, sess, cip_resp)

                elif command == 0x0070:  # SendUnitData
                    event_data = {
                        "dst_port": self.port,
                        "phase": "enip_send_unit_data",
                        "rule": "SendUnitData",
                        "payload": (f"SendUnitData from {peer[0]} session={sess} len={length}"),
                        "session_handle": sess,
                        "data_hex": cmd_data.hex()[:200],
                    }
                    log_event(self.PROTOCOL, peer, event_data, "ICS_ATTACK", "MEDIUM")
                    self.logger.warning("[EtherNet/IP] %s SendUnitData session=%d", peer[0], sess)
                    # Return success with empty CPF
                    cpf_resp = struct.pack("<IH H", 0, 0, 0)
                    response = (
                        self._build_encap_header(0x0070, len(cpf_resp), sess, 0, sender_context)
                        + cpf_resp
                    )

                else:
                    # Unknown command — log and return invalid command status
                    event_data = {
                        "dst_port": self.port,
                        "phase": "enip_unknown_command",
                        "rule": cmd_name,
                        "payload": (f"Unknown ENIP command 0x{command:04X} from {peer[0]}"),
                        "command": command,
                        "data_hex": cmd_data.hex()[:200],
                    }
                    log_event(self.PROTOCOL, peer, event_data, "ICS_RECON", "LOW")
                    self.logger.info("[EtherNet/IP] %s unknown cmd 0x%04X", peer[0], command)
                    response = self._build_encap_header(command, 0, sess, 0x0001, sender_context)

                if response:
                    writer.write(response)
                    await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    ENIPHoneypot().run()
