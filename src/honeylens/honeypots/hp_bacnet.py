#!/usr/bin/env python3
"""
honeypots/hp_bacnet.py — BACnet/IP Honeypot (UDP)
===================================================
Simulates a BACnet/IP building automation controller. Responds to
Who-Is, ReadProperty, ReadPropertyMultiple and logs write/reinit attacks.

Run: python -m honeypots.hp_bacnet
Service: sensor-hp-bacnet (UDP port 47808)
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Any

from honeylens.honeypots._base import BaseHoneypot, log_event
from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES
from honeylens.honeypots.ics.base import frame_hex
from honeylens.honeypots.ics.foreign import DESYNC_VERDICT, FOREIGN_VERDICT, foreign_event
from honeylens.honeypots.ics.verdict import verdict_for, verdict_for_semantics
from honeylens.ics import decode
from honeylens.ics.bacnet import BVLC_FUNCTIONS, network_message, pdu_type_name, service_name

# ---------------------------------------------------------------------------
# BACnet constants
# ---------------------------------------------------------------------------

# BVLC
BVLC_TYPE = 0x81
BVLC_FORWARDED_NPDU = 0x04
BVLC_DISTRIBUTE_BROADCAST = 0x09
BVLC_ORIGINAL_UNICAST = 0x0A
BVLC_ORIGINAL_BROADCAST = 0x0B
# Where the NPDU starts in each BVLC function that carries one. Forwarded-NPDU puts the
# originating device's address (4 + 2 bytes) in front of it.
_NPDU_START = {
    BVLC_FORWARDED_NPDU: 10,
    BVLC_DISTRIBUTE_BROADCAST: 4,
    BVLC_ORIGINAL_UNICAST: 4,
    BVLC_ORIGINAL_BROADCAST: 4,
}

# APDU PDU type masks (upper nibble)
PDU_CONFIRMED_REQ = 0x00
PDU_UNCONFIRMED_REQ = 0x10
PDU_SIMPLE_ACK = 0x20
PDU_COMPLEX_ACK = 0x30

# Service choices this device answers. What a service is called and what it means is not
# decided here: every event takes both from ``honeylens.ics.bacnet``.
SVC_READ_PROPERTY = 0x0C
SVC_READ_PROPERTY_MULTIPLE = 0x0E
SVC_WHO_IS = 0x08
SVC_I_AM = 0x00
# Confirmed services answered with a Simple-ACK. 4 and 8 are here because the decoy has
# always acknowledged them (it once took them for CreateObject and DeleteObject).
_SIMPLE_ACKED = frozenset({0x0F, 0x14, 0x04, 0x08})

# BACnet object/property identifiers used in responses
OBJ_DEVICE = 8
PROP_OBJECT_ID = 75
PROP_OBJECT_NAME = 77
PROP_VENDOR_NAME = 121
PROP_MODEL_NAME = 70
PROP_DESCRIPTION = 28
PROP_LOCATION = 56
PROP_FIRMWARE_REV = 44
PROP_APP_SW_VER = 12
PROP_SYSTEM_STATUS = 112


# ---------------------------------------------------------------------------
# Helpers — minimal BACnet encoding
# ---------------------------------------------------------------------------


def _encode_context_tag(tag_num: int, data: bytes) -> bytes:
    """Encode a context-tagged value (BACnet encoding rules)."""
    length = len(data)
    if length <= 4:
        header = bytes([(tag_num << 4) | 0x08 | length])
    else:
        header = bytes([(tag_num << 4) | 0x0D, length])
    return header + data


def _encode_app_uint(value: int) -> bytes:
    """Encode an application-tagged unsigned integer."""
    if value <= 0xFF:
        return bytes([0x21, value])
    elif value <= 0xFFFF:
        return bytes([0x22]) + struct.pack(">H", value)
    else:
        return bytes([0x24]) + struct.pack(">I", value)


def _encode_app_charstring(text: str) -> bytes:
    """Encode an application-tagged CharacterString (UTF-8, encoding byte 0)."""
    raw = b"\x00" + text.encode("utf-8")  # 0x00 = UTF-8 charset
    length = len(raw)
    if length <= 4:
        return bytes([0x70 | length]) + raw
    else:
        return bytes([0x75]) + struct.pack(">H", length) + raw


def _encode_object_id(obj_type: int, instance: int) -> bytes:
    """Encode a BACnet ObjectIdentifier (4 bytes: type:10 instance:22)."""
    val = ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)
    return struct.pack(">I", val)


def check_bvlc(data: bytes) -> str | None:
    """Why this datagram is not BACnet/IP, or None when it is.

    BACnet/IP is a four-byte BVLC header — type 0x81, a function Annex J defines, and the
    length of the whole datagram — and, in the functions that carry one, an NPDU of
    protocol version 1.
    """
    if len(data) < 4:
        return f"{len(data)} byte(s), a BVLC header is 4"
    bvlc_type, function, length = struct.unpack(">BBH", data[0:4])
    if bvlc_type != BVLC_TYPE:
        return f"BVLC type 0x{bvlc_type:02x} is not 0x81"
    if function not in BVLC_FUNCTIONS:
        return f"BVLC function 0x{function:02x} is not one the standard defines"
    if length != len(data):
        return f"BVLC length field says {length}, the datagram is {len(data)} byte(s)"
    start = _NPDU_START.get(function)
    if start is not None:
        if len(data) < start + 2:
            return f"{BVLC_FUNCTIONS[function][0]} too short to carry an NPDU"
        if data[start] != 0x01:
            return f"NPDU version {data[start]} is not 1"
    return None


def split_npdu(npdu: bytes) -> dict[str, Any]:
    """Find what an NPDU carries. ``npdu`` starts at the version byte.

    Returns ``defect`` (a reason, or None), ``apdu`` (bytes, or None for a network-layer
    message), ``message_type`` and ``message_body`` (for a network-layer message).

    Layout after version and control: DNET(2) DLEN(1) DADR(DLEN) when the control byte has
    bit 5, then SNET(2) SLEN(1) SADR(SLEN) when it has bit 3, then the hop count, which is
    present exactly when the destination is.
    """
    out: dict[str, Any] = {"defect": None, "apdu": None, "message_type": None, "message_body": b""}
    control = npdu[1]
    offset = 2
    for bit, what in ((0x20, "destination"), (0x08, "source")):
        if control & bit:
            if len(npdu) < offset + 3:
                out["defect"] = f"NPDU ends inside its {what} address"
                return out
            offset += 3 + npdu[offset + 2]
    if control & 0x20:
        offset += 1  # hop count
    if offset > len(npdu):
        out["defect"] = "NPDU ends inside its addresses"
    elif offset == len(npdu):
        out["defect"] = "NPDU carries no APDU and no network message"
    elif control & 0x80:
        out["message_type"] = npdu[offset]
        out["message_body"] = npdu[offset + 1 :]
    else:
        out["apdu"] = npdu[offset:]
    return out


def _build_bvlc(function: int, payload: bytes) -> bytes:
    """Wrap payload in BVLC header."""
    length = 4 + len(payload)
    return struct.pack(">BBH", BVLC_TYPE, function, length) + payload


def _build_npdu_apdu(apdu: bytes) -> bytes:
    """Wrap APDU in a minimal NPDU (version=1, control=0x00 no network layer)."""
    return bytes([0x01, 0x00]) + apdu


# ---------------------------------------------------------------------------
# BACnet UDP protocol handler
# ---------------------------------------------------------------------------


class BACnetProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol that handles BACnet/IP packets."""

    def __init__(self, honeypot: BACnetHoneypot):
        self.hp = honeypot
        self.logger = honeypot.logger
        self.transport: Any = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        try:
            self._handle_packet(data, addr)
        except Exception as e:
            self.logger.debug("Error handling packet from %s:%d: %s", addr[0], addr[1], e)

    def _handle_packet(self, data: bytes, addr: tuple):
        defect = check_bvlc(data)
        if defect:
            # Not BACnet/IP: one row, and nothing is sent back to an address that a UDP
            # sender chose freely.
            event = foreign_event(self.hp.port, data, "BACnet/IP", defect)
            log_event(
                self.hp.PROTOCOL, addr, event, *FOREIGN_VERDICT, raw=data[:MAX_RAW_EVENT_BYTES]
            )
            return

        function = data[1]
        function_name, function_semantics = BVLC_FUNCTIONS[function]
        # On every row: the datagram as it arrived. Not under a key the frame decoder reads,
        # because that decoder takes the APDU (``apdu_hex``), not the BVLC and NPDU around it.
        wire = {
            "dst_port": self.hp.port,
            "bvlc_function": function,
            "datagram_hex": frame_hex(data),
        }

        start = _NPDU_START.get(function)
        if start is None:
            # A BVLC control function: recorded and named, never answered.
            event = {
                **wire,
                "phase": "bacnet_bvlc",
                "rule": function_name,
                "payload": f"BVLC {function_name}(0x{function:02X}) len={len(data)}",
            }
            verdict = verdict_for_semantics(function_semantics, self.hp.PROTOCOL)
            log_event(self.hp.PROTOCOL, addr, event, *verdict)
            self.logger.info("[BACnet] %s BVLC %s", addr[0], function_name)
            return

        npdu = split_npdu(data[start:])
        if npdu["defect"]:
            event = {
                **wire,
                "phase": "bacnet_malformed",
                "rule": "malformed NPDU",
                "defect": npdu["defect"],
                "payload": f"BACnet/IP {function_name}: {npdu['defect']}",
            }
            log_event(self.hp.PROTOCOL, addr, event, *DESYNC_VERDICT)
            return

        if npdu["apdu"] is None:
            name, semantics = network_message(npdu["message_type"], npdu["message_body"])
            event = {
                **wire,
                "phase": "bacnet_network",
                "rule": name,
                "network_message": npdu["message_type"],
                "payload": f"Network message {name}(0x{npdu['message_type']:02X})",
            }
            verdict = verdict_for_semantics(semantics, self.hp.PROTOCOL)
            log_event(self.hp.PROTOCOL, addr, event, *verdict)
            self.logger.info("[BACnet] %s network message %s", addr[0], name)
            return

        apdu = npdu["apdu"]
        pdu_type = apdu[0] & 0xF0
        if pdu_type == PDU_CONFIRMED_REQ:
            self._handle_confirmed(apdu, addr, wire)
        elif pdu_type == PDU_UNCONFIRMED_REQ:
            self._handle_unconfirmed(apdu, addr, wire)
        else:
            # An acknowledgement, error, reject or abort nobody here asked for.
            name = pdu_type_name(apdu[0]) or f"Reserved PDU type {apdu[0] >> 4}"
            event = {
                **wire,
                "phase": "bacnet_pdu",
                "rule": name,
                "payload": f"{name} PDU, {len(apdu)} byte(s)",
                "apdu_hex": apdu.hex(),
            }
            log_event(self.hp.PROTOCOL, addr, event, *verdict_for(decode("bacnet", apdu)))

    # ---- Confirmed requests ----

    def _handle_confirmed(self, apdu: bytes, addr: tuple, wire: dict):
        # One reading of the request: the decoder places the header (a segmented request has
        # two more bytes before the service choice), names the service and says what it does.
        frame = decode("bacnet", apdu)
        attack_type, severity = verdict_for(frame)
        placed = {f.name: f for f in frame.fields}
        service = frame.code if "service_choice" in placed else None
        invoke_id = placed["invoke_id"].value if "invoke_id" in placed else None

        if service is None:
            svc_name = "Confirmed-Request (cut short)"
            payload = f"Confirmed request cut short after {len(apdu)} byte(s)"
        else:
            svc_name = service_name(True, service) or f"Confirmed_0x{service:02X}"
            payload = f"Confirmed service={svc_name}(0x{service:02X}) invoke={invoke_id}"
        event_data = {
            **wire,
            "phase": "bacnet_confirmed",
            "rule": svc_name,
            "payload": payload,
            "service": service,
            "service_name": svc_name,
            "invoke_id": invoke_id,
            "apdu_hex": apdu.hex(),
        }
        log_event(self.hp.PROTOCOL, addr, event_data, attack_type, severity)

        if attack_type == "ICS_ATTACK":
            self.logger.warning("[BACnet] %s ATTACK %s invoke=%s", addr[0], svc_name, invoke_id)
        else:
            self.logger.info("[BACnet] %s Confirmed %s invoke=%s", addr[0], svc_name, invoke_id)

        if service is None or not isinstance(invoke_id, int):
            return  # nothing to address a reply to

        # Build response
        if service == SVC_READ_PROPERTY:
            choice = placed["service_choice"]
            resp_apdu = self._build_read_property_ack(invoke_id, apdu[choice.offset + 1 :])
        elif service == SVC_READ_PROPERTY_MULTIPLE:
            resp_apdu = self._build_read_property_multiple_ack(invoke_id)
        elif service in _SIMPLE_ACKED:
            resp_apdu = bytes([PDU_SIMPLE_ACK, invoke_id, service])
        else:
            # Reject — unrecognized service
            resp_apdu = bytes([0x60, invoke_id, 0x09])  # Reject, reason=unrecognized-service
            self.logger.debug("[BACnet] Rejecting unknown confirmed service 0x%02X", service)

        resp = _build_bvlc(BVLC_ORIGINAL_UNICAST, _build_npdu_apdu(resp_apdu))
        self.transport.sendto(resp, addr)

    def _build_read_property_ack(self, invoke_id: int, service_data: bytes) -> bytes:
        """Build a Complex-ACK for ReadProperty with fake property values."""
        # Try to parse requested object/property from service data
        prop_id = self._parse_property_id(service_data)
        value_data = self._get_property_value(prop_id)

        # Complex-ACK: PDU-type=0x30, invoke-id, service=ReadProperty
        ack = bytes([PDU_COMPLEX_ACK, invoke_id, SVC_READ_PROPERTY])
        # Context 0: objectIdentifier
        ack += _encode_context_tag(0, _encode_object_id(OBJ_DEVICE, self.hp.object_id))
        # Context 1: propertyIdentifier
        ack += _encode_context_tag(1, _encode_app_uint(prop_id)[1:])
        # Context 3: propertyValue (opening tag, value, closing tag)
        ack += bytes([(3 << 4) | 0x0E])  # opening tag 3
        ack += value_data
        ack += bytes([(3 << 4) | 0x0F])  # closing tag 3
        return ack

    def _build_read_property_multiple_ack(self, invoke_id: int) -> bytes:
        """Build a Complex-ACK for ReadPropertyMultiple returning core device info."""
        ack = bytes([PDU_COMPLEX_ACK, invoke_id, SVC_READ_PROPERTY_MULTIPLE])
        # listOfReadAccessResults — one result for Device object
        ack += bytes([(0 << 4) | 0x0E])  # opening tag 0
        # objectIdentifier
        ack += _encode_context_tag(0, _encode_object_id(OBJ_DEVICE, self.hp.object_id))
        # listOfResults opening tag 1
        ack += bytes([(1 << 4) | 0x0E])
        for prop_id in (PROP_OBJECT_NAME, PROP_VENDOR_NAME, PROP_MODEL_NAME, PROP_LOCATION):
            # propertyIdentifier
            ack += _encode_context_tag(2, _encode_app_uint(prop_id)[1:])
            # propertyValue opening tag 4
            ack += bytes([(4 << 4) | 0x0E])
            ack += self._get_property_value(prop_id)
            ack += bytes([(4 << 4) | 0x0F])  # closing tag 4
        ack += bytes([(1 << 4) | 0x0F])  # closing tag 1
        ack += bytes([(0 << 4) | 0x0F])  # closing tag 0
        return ack

    def _parse_property_id(self, service_data: bytes) -> int:
        """Best-effort extraction of propertyIdentifier from ReadProperty request."""
        # The property ID is in context tag 1 after the object identifier (context tag 0).
        # Simple heuristic: scan for context tag 1 (0x19 for 1-byte value).
        try:
            for i in range(len(service_data) - 1):
                if service_data[i] == 0x19:  # context tag 1, length 1
                    return service_data[i + 1]
            # Try 2-byte tag (0x1A)
            for i in range(len(service_data) - 2):
                if service_data[i] == 0x1A:
                    return struct.unpack(">H", service_data[i + 1 : i + 3])[0]
        except (IndexError, struct.error):
            pass  # silent: expected from malformed BACnet property frame
        return PROP_OBJECT_NAME  # default fallback

    def _get_property_value(self, prop_id: int) -> bytes:
        """Return encoded application-tagged value for a BACnet property."""
        if prop_id == PROP_OBJECT_ID:
            return bytes([0xC4]) + _encode_object_id(OBJ_DEVICE, self.hp.object_id)
        elif prop_id == PROP_OBJECT_NAME:
            return _encode_app_charstring(self.hp.device_name)
        elif prop_id == PROP_VENDOR_NAME:
            return _encode_app_charstring(self.hp.vendor)
        elif prop_id == PROP_MODEL_NAME:
            return _encode_app_charstring(self.hp.model)
        elif prop_id == PROP_DESCRIPTION:
            return _encode_app_charstring(f"{self.hp.vendor} {self.hp.model}")
        elif prop_id == PROP_LOCATION:
            return _encode_app_charstring(self.hp.location)
        elif prop_id == PROP_FIRMWARE_REV:
            return _encode_app_charstring("2.1.0")
        elif prop_id == PROP_APP_SW_VER:
            return _encode_app_charstring("1.0.3")
        elif prop_id == PROP_SYSTEM_STATUS:
            return _encode_app_uint(0)  # operational
        else:
            return _encode_app_uint(0)

    # ---- Unconfirmed requests ----

    def _handle_unconfirmed(self, apdu: bytes, addr: tuple, wire: dict):
        frame = decode("bacnet", apdu)
        attack_type, severity = verdict_for(frame)
        service = frame.code if any(f.name == "service_choice" for f in frame.fields) else None

        if service is None:
            svc_name = "Unconfirmed-Request (cut short)"
            payload = f"Unconfirmed request cut short after {len(apdu)} byte(s)"
        else:
            svc_name = service_name(False, service) or f"Unconfirmed_0x{service:02X}"
            payload = f"Unconfirmed service={svc_name}(0x{service:02X})"
        self.logger.info("[BACnet] %s Unconfirmed %s", addr[0], svc_name)

        event_data = {
            **wire,
            "phase": "bacnet_unconfirmed",
            "rule": svc_name,
            "payload": payload,
            "service": service,
            "service_name": svc_name,
            "apdu_hex": apdu.hex(),
        }
        log_event(self.hp.PROTOCOL, addr, event_data, attack_type, severity)

        # Respond to Who-Is with I-Am
        if service == SVC_WHO_IS:
            self._send_i_am(addr)

    def _send_i_am(self, addr: tuple):
        """Send an I-Am unconfirmed response with fake device info."""
        # I-Am APDU: PDU-type=0x10 (unconfirmed), service=0x00 (I-Am)
        # Payload: objectIdentifier, maxAPDUlength, segmentationSupported, vendorID
        apdu = bytes([PDU_UNCONFIRMED_REQ, SVC_I_AM])
        # Object identifier (application tag 0xC4 = object-id, 4 bytes)
        apdu += bytes([0xC4]) + _encode_object_id(OBJ_DEVICE, self.hp.object_id)
        # Max APDU length accepted (application tag unsigned, 1476)
        apdu += bytes([0x22]) + struct.pack(">H", 1476)
        # Segmentation supported: 0x03 = no-segmentation (enumerated, app tag 0x91)
        apdu += bytes([0x91, 0x03])
        # Vendor ID (application tag unsigned)
        apdu += bytes([0x21, 0x05])  # vendor 5 = Johnson Controls

        resp = _build_bvlc(BVLC_ORIGINAL_UNICAST, _build_npdu_apdu(apdu))
        self.transport.sendto(resp, addr)
        self.logger.info(
            "[BACnet] Sent I-Am to %s:%d (device=%d)", addr[0], addr[1], self.hp.object_id
        )


# ---------------------------------------------------------------------------
# Honeypot class
# ---------------------------------------------------------------------------


class BACnetHoneypot(BaseHoneypot):
    PROTOCOL = "bacnet"
    DEFAULT_PORT = 47808
    TTL_PROFILE = "plc"  # embedded device fingerprint; one source with manifest.ttl_profile
    CONNECTION_TIMEOUT = 60

    def __init__(self):
        super().__init__()
        p = self.profile
        self.device_name = p.get("device_name", "HVAC-Controller-01")
        self.vendor = p.get("vendor", "Johnson Controls")
        self.model = p.get("model", "FX-PCG2611")
        self.location = p.get("location", "Building A Floor 3")
        self.object_id = int(p.get("object_id", 12345))

    def run(self):
        """Start the BACnet honeypot on a UDP socket (overrides TCP-based base)."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
        self.logger.info("Starting BACnet honeypot on UDP port %d", self.port)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        transport, _protocol = loop.run_until_complete(
            loop.create_datagram_endpoint(
                lambda: BACnetProtocol(self), local_addr=("0.0.0.0", self.port)
            )
        )
        self.logger.info("BACnet honeypot listening on 0.0.0.0:%d (UDP)", self.port)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            self.logger.info("Shutting down BACnet honeypot")
        finally:
            transport.close()
            loop.close()


if __name__ == "__main__":
    BACnetHoneypot().run()
