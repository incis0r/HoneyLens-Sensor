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
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.ics.base import frame_hex
from honeylens.honeypots.ics.foreign import (
    DESYNC_VERDICT,
    FOREIGN_VERDICT,
    desync_event,
    foreign_event,
    read_rest,
)
from honeylens.honeypots.ics.verdict import verdict_for
from honeylens.ics import decode
from honeylens.ics.enip import COMMAND_NAMES, cip_service_name

ENCAP_HEADER_SIZE = 24
# The specification's ceiling for the command data of one encapsulation message.
MAX_ENCAP_DATA = 65511

# Commands a target answers without a session: a request for one of them carries handle 0.
_SESSIONLESS = frozenset({0x0004, 0x0063, 0x0064, 0x0065})

_PHASES = {
    0x0000: "enip_nop",
    0x0004: "enip_list_services",
    0x0063: "enip_list_identity",
    0x0064: "enip_list_interfaces",
    0x0065: "enip_register_session",
    0x0066: "enip_unregister_session",
    0x006F: "enip_sendrr_cip",
    0x0070: "enip_send_unit_data",
}


def check_encap(header: bytes, first: bool = True) -> str | None:
    """Why these 24 bytes are not an EtherNet/IP encapsulation request, or None when they are.

    A request carries a command the specification defines, status 0 and options 0, and at
    most 65,511 bytes of command data; the session-less commands carry session handle 0.
    ``first`` is False once the peer has sent a valid request: a device answers an unknown
    command inside a session with status 1, so there it is not a reason to doubt the stream.
    """
    if len(header) < ENCAP_HEADER_SIZE:
        return f"{len(header)} byte(s), an encapsulation header is {ENCAP_HEADER_SIZE}"
    command, length, session, status, _context, options = struct.unpack(
        "<HHI I 8s I", header[:ENCAP_HEADER_SIZE]
    )
    if command not in COMMAND_NAMES and first:
        return f"command 0x{command:04x} is not an encapsulation command"
    if options != 0:
        return f"options field is 0x{options:08x}, a request sends 0"
    if status != 0:
        return f"status field is 0x{status:08x}, a request sends 0"
    if length > MAX_ENCAP_DATA:
        return f"length {length} exceeds the {MAX_ENCAP_DATA} bytes an encapsulation carries"
    if command in _SESSIONLESS and session != 0:
        return (
            f"session handle 0x{session:08x} on {COMMAND_NAMES[command]}, "
            "which is sent before a session exists"
        )
    return None


def _unconnected_cip(cmd_data: bytes) -> bytes:
    """The CIP request inside SendRRData command data, or empty when there is none."""
    cpf = cmd_data[6:]  # after the interface handle (4) and the timeout (2)
    if len(cpf) < 2:
        return b""
    offset = 2
    for _ in range(struct.unpack("<H", cpf[0:2])[0]):
        if offset + 4 > len(cpf):
            break
        item_type, item_len = struct.unpack("<HH", cpf[offset : offset + 4])
        offset += 4
        if item_type == 0x00B2:  # unconnected data item
            return cpf[offset : offset + item_len]
        offset += item_len
    return b""


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

    def _cip_reply(self, cip_data: bytes) -> bytes:
        """The CIP reply to an unconnected request. What the request means is not decided
        here: the event takes its name and verdict from ``honeylens.ics.enip``."""
        if len(cip_data) < 2:
            return b"\x80\x01\x00\x08\x00"  # General error

        service_code = cip_data[0] & 0x7F  # Mask request bit
        ok = struct.pack("<BBH", service_code | 0x80, 0, 0)

        if service_code == 0x01:  # Get_Attribute_All
            fw_major, fw_minor = self._parse_firmware()
            attr_data = struct.pack("<H", 1)  # Vendor ID
            attr_data += struct.pack("<H", self.device_type)
            attr_data += struct.pack("<H", self.product_code)
            attr_data += struct.pack("<BB", fw_major, fw_minor)
            return ok + attr_data
        if service_code == 0x0E:  # Get_Attribute_Single
            return ok + b"\x00\x00"
        if service_code in (0x10, 0x05, 0x4B, 0x53):
            return ok
        if service_code == 0x52:
            return ok + struct.pack("<HH", 0x00C1, 0)  # type SINT, value 0
        # A service this device does not implement: general status 0x08.
        return struct.pack("<BBH", service_code | 0x80, 0, 0x0008)

    async def _unframed(self, reader, peer, consumed: bytes, defect: str, frames: int):
        """One event for a stream that is not (or is no longer) EtherNet/IP; no reply."""
        data = await read_rest(reader, consumed)
        if frames == 0:
            event, verdict = foreign_event(self.port, data, "EtherNet/IP", defect), FOREIGN_VERDICT
        else:
            event = desync_event(self.port, data, "EtherNet/IP", defect, frames)
            verdict = DESYNC_VERDICT
        log_event(self.PROTOCOL, peer, event, *verdict, raw=data[:MAX_RAW_EVENT_BYTES])
        self.logger.info("[EtherNet/IP] %s not EtherNet/IP: %s", peer[0], defect)

    async def handle_connection(self, reader, writer, peer):
        self.logger.info("[EtherNet/IP] Connection from %s:%d", peer[0], peer[1])
        frames = 0

        try:
            while True:
                try:
                    header = await asyncio.wait_for(
                        reader.readexactly(ENCAP_HEADER_SIZE), timeout=60
                    )
                except asyncio.IncompleteReadError as cut:
                    if cut.partial:
                        defect = (
                            f"stream ends {len(cut.partial)} byte(s) into a "
                            f"{ENCAP_HEADER_SIZE}-byte encapsulation header"
                        )
                        await self._unframed(reader, peer, bytes(cut.partial), defect, frames)
                    return
                except TimeoutError:
                    stalled = await read_rest(reader, b"")
                    if stalled:
                        defect = f"{len(stalled)} byte(s) and then silence, no encapsulation header"
                        await self._unframed(reader, peer, stalled, defect, frames)
                    return

                refused = check_encap(header, first=frames == 0)
                if refused:
                    await self._unframed(reader, peer, header, refused, frames)
                    return

                command, length, sess, _status, sender_context, _options = struct.unpack(
                    "<HHI I 8s I", header
                )

                cmd_data = b""
                if length > 0:
                    try:
                        cmd_data = await asyncio.wait_for(reader.readexactly(length), timeout=30)
                    except asyncio.IncompleteReadError as cut:
                        got = header + bytes(cut.partial)
                        defect = f"command data cut short: {len(cut.partial)} of {length} byte(s)"
                        event = desync_event(
                            self.port, got, "EtherNet/IP", defect, frames, phase="enip_truncated"
                        )
                        log_event(
                            self.PROTOCOL,
                            peer,
                            event,
                            *DESYNC_VERDICT,
                            raw=got[:MAX_RAW_EVENT_BYTES],
                        )
                        return
                frames += 1

                # One reading of the frame: the decoder names it and says what it does.
                frame = decode("enip", header + cmd_data)
                attack_type, severity = verdict_for(frame)
                cmd_name = COMMAND_NAMES.get(command, f"CMD_0x{command:04X}")
                response = None
                # On every event: the encapsulation frame as received (header and command
                # data) and the command as an integer.
                event_data = {
                    "command": command,
                    "frame_hex": frame_hex(header + cmd_data),
                    "dst_port": self.port,
                    "phase": _PHASES.get(command, "enip_command"),
                    "rule": cmd_name,
                    "payload": f"{cmd_name} from {peer[0]}",
                }

                if command == 0x0004:  # ListServices
                    response = self._build_list_services_response(sender_context)

                elif command == 0x0063:  # ListIdentity
                    response = self._build_list_identity_response(sender_context)

                elif command == 0x0064:  # ListInterfaces
                    response = self._build_list_interfaces_response(sender_context)

                elif command == 0x0065:  # RegisterSession
                    session_handle = self._next_session
                    self._next_session += 1
                    event_data["payload"] += f" session={session_handle}"
                    event_data["session_handle"] = session_handle
                    response = self._build_register_session_response(sender_context, session_handle)

                elif command == 0x0066:  # UnRegisterSession
                    event_data["payload"] += f" session={sess}"
                    event_data["session_handle"] = sess
                    response = self._build_unregister_session_response(sender_context, sess)

                elif command == 0x006F:  # SendRRData
                    cip_data = _unconnected_cip(cmd_data)
                    service_code = cip_data[0] & 0x7F if cip_data else 0
                    service_name = cip_service_name(frame) or f"CIP_0x{service_code:02X}"
                    event_data.update(
                        rule=service_name,
                        payload=(
                            f"SendRRData CIP service=0x{service_code:02X} "
                            f"({service_name}) from {peer[0]}"
                        ),
                        session_handle=sess,
                        cip_service=service_code,
                        cip_service_name=service_name,
                        cip_data_hex=cip_data.hex(),
                    )
                    response = self._build_sendrr_response(
                        sender_context, sess, self._cip_reply(cip_data)
                    )

                elif command == 0x0070:  # SendUnitData
                    event_data["payload"] = (
                        f"SendUnitData from {peer[0]} session={sess} len={length}"
                    )
                    event_data["session_handle"] = sess
                    event_data["data_hex"] = cmd_data.hex()[:200]
                    # Return success with empty CPF
                    cpf_resp = struct.pack("<IH H", 0, 0, 0)
                    response = (
                        self._build_encap_header(0x0070, len(cpf_resp), sess, 0, sender_context)
                        + cpf_resp
                    )

                elif command not in COMMAND_NAMES:
                    # A well-formed header with a command the specification does not define:
                    # a device answers it with status 1 (invalid or unsupported command).
                    event_data.update(
                        phase="enip_unknown_command",
                        payload=f"Unknown ENIP command 0x{command:04X} from {peer[0]}",
                        data_hex=cmd_data.hex()[:200],
                    )
                    response = self._build_encap_header(command, 0, sess, 0x0001, sender_context)

                # NOP, IndicateStatus and Cancel are recorded and not answered.
                log_event(self.PROTOCOL, peer, event_data, attack_type, severity)
                if attack_type == "ICS_ATTACK":
                    self.logger.warning(
                        "[EtherNet/IP] %s %s — %s", peer[0], event_data["rule"], severity
                    )
                else:
                    self.logger.info("[EtherNet/IP] %s %s", peer[0], event_data["rule"])

                if response:
                    writer.write(response)
                    await writer.drain()

        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass  # silent: expected normal client disconnect


if __name__ == "__main__":
    ENIPHoneypot().run()
