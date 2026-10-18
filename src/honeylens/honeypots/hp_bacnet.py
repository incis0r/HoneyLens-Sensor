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

# ---------------------------------------------------------------------------
# BACnet constants
# ---------------------------------------------------------------------------

# BVLC functions
BVLC_TYPE = 0x81
BVLC_FORWARDED_NPDU = 0x04
BVLC_ORIGINAL_UNICAST = 0x0A
BVLC_ORIGINAL_BROADCAST = 0x0B

# APDU PDU type masks (upper nibble)
PDU_CONFIRMED_REQ = 0x00
PDU_UNCONFIRMED_REQ = 0x10
PDU_SIMPLE_ACK = 0x20
PDU_COMPLEX_ACK = 0x30

# Confirmed service choices
SVC_CREATE_OBJECT = 0x04
SVC_DELETE_OBJECT = 0x08
SVC_READ_PROPERTY = 0x0C
SVC_READ_PROPERTY_MULTIPLE = 0x0E
SVC_WRITE_PROPERTY = 0x0F
SVC_REINITIALIZE_DEVICE = 0x14

# Unconfirmed service choices
SVC_I_AM = 0x00
SVC_WHO_IS = 0x08

CONFIRMED_SERVICE_NAMES = {
    SVC_CREATE_OBJECT: "CreateObject",
    SVC_DELETE_OBJECT: "DeleteObject",
    SVC_READ_PROPERTY: "ReadProperty",
    SVC_READ_PROPERTY_MULTIPLE: "ReadPropertyMultiple",
    SVC_WRITE_PROPERTY: "WriteProperty",
    SVC_REINITIALIZE_DEVICE: "ReinitializeDevice",
}

UNCONFIRMED_SERVICE_NAMES = {
    SVC_I_AM: "I-Am",
    SVC_WHO_IS: "Who-Is",
}

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
        if len(data) < 4:
            return

        # --- BVLC header ---
        bvlc_type, bvlc_func, _bvlc_len = struct.unpack(">BBH", data[0:4])
        if bvlc_type != BVLC_TYPE:
            return

        # Determine NPDU start
        if bvlc_func == BVLC_FORWARDED_NPDU:
            # Forwarded-NPDU has 6 extra bytes (IP + port)
            if len(data) < 10:
                return
            npdu_start = 10
        elif bvlc_func in (BVLC_ORIGINAL_UNICAST, BVLC_ORIGINAL_BROADCAST):
            npdu_start = 4
        else:
            # Unsupported BVLC function — log and skip
            self.logger.debug("Unsupported BVLC function 0x%02X from %s", bvlc_func, addr[0])
            return

        if len(data) < npdu_start + 2:
            return

        # --- NPDU ---
        npdu_version = data[npdu_start]
        npdu_control = data[npdu_start + 1]
        if npdu_version != 0x01:
            return

        # Skip network-layer fields if present
        offset = npdu_start + 2
        if npdu_control & 0x20:  # DNET/DLEN/Hop present
            if len(data) < offset + 4:
                return
            dlen = (
                struct.unpack(">H", data[offset + 2 : offset + 4])[0]
                if len(data) > offset + 3
                else 0
            )
            # skip DNET(2) + DLEN(2) + DADR(dlen) + hop_count(1)
            offset += 2 + 2 + dlen + 1
        if npdu_control & 0x08:  # SNET/SLEN present
            if len(data) < offset + 4:
                return
            slen = (
                struct.unpack(">H", data[offset + 2 : offset + 4])[0]
                if len(data) > offset + 3
                else 0
            )
            offset += 2 + 2 + slen

        if offset >= len(data):
            return

        # --- APDU ---
        apdu = data[offset:]
        pdu_type = apdu[0] & 0xF0

        if pdu_type == PDU_CONFIRMED_REQ:
            self._handle_confirmed(apdu, addr)
        elif pdu_type == PDU_UNCONFIRMED_REQ:
            self._handle_unconfirmed(apdu, addr)
        else:
            self.logger.debug("Ignoring PDU type 0x%02X from %s", pdu_type, addr[0])

    # ---- Confirmed requests ----

    def _handle_confirmed(self, apdu: bytes, addr: tuple):
        if len(apdu) < 4:
            return

        # Confirmed-REQ: byte0=PDU type+flags, byte1=max-segs/max-resp,
        #                byte2=invoke-id, byte3=service-choice
        invoke_id = apdu[2]
        service = apdu[3]
        svc_name = CONFIRMED_SERVICE_NAMES.get(service, f"Confirmed_0x{service:02X}")

        # Classify
        if service in (SVC_WRITE_PROPERTY, SVC_REINITIALIZE_DEVICE):
            attack_type, severity = "ICS_ATTACK", "CRITICAL"
        elif service in (SVC_CREATE_OBJECT, SVC_DELETE_OBJECT):
            attack_type, severity = "ICS_ATTACK", "HIGH"
        elif service in (SVC_READ_PROPERTY, SVC_READ_PROPERTY_MULTIPLE):
            attack_type, severity = "ICS_RECON", "LOW"
        else:
            attack_type, severity = None, None

        event_data = {
            "dst_port": self.hp.port,
            "phase": "bacnet_confirmed",
            "rule": svc_name,
            "payload": f"Confirmed service={svc_name}(0x{service:02X}) invoke={invoke_id}",
            "service": service,
            "service_name": svc_name,
            "invoke_id": invoke_id,
            "apdu_hex": apdu.hex(),
        }
        log_event(self.hp.PROTOCOL, addr, event_data, attack_type, severity)

        if service in (SVC_WRITE_PROPERTY, SVC_REINITIALIZE_DEVICE):
            self.logger.warning("[BACnet] %s ATTACK %s invoke=%d", addr[0], svc_name, invoke_id)
        elif service in (SVC_CREATE_OBJECT, SVC_DELETE_OBJECT):
            self.logger.warning("[BACnet] %s ATTACK %s invoke=%d", addr[0], svc_name, invoke_id)
        else:
            self.logger.info("[BACnet] %s Confirmed %s invoke=%d", addr[0], svc_name, invoke_id)

        # Build response
        if service == SVC_READ_PROPERTY:
            resp_apdu = self._build_read_property_ack(invoke_id, apdu[4:])
        elif service == SVC_READ_PROPERTY_MULTIPLE:
            resp_apdu = self._build_read_property_multiple_ack(invoke_id)
        elif service in (
            SVC_WRITE_PROPERTY,
            SVC_CREATE_OBJECT,
            SVC_DELETE_OBJECT,
            SVC_REINITIALIZE_DEVICE,
        ):
            # Simple-ACK
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

    def _handle_unconfirmed(self, apdu: bytes, addr: tuple):
        if len(apdu) < 2:
            return

        service = apdu[1]
        svc_name = UNCONFIRMED_SERVICE_NAMES.get(service, f"Unconfirmed_0x{service:02X}")

        if service == SVC_WHO_IS:
            attack_type, severity = "ICS_RECON", "MEDIUM"
            self.logger.info("[BACnet] %s Who-Is (broadcast discovery)", addr[0])
        elif service == SVC_I_AM:
            attack_type, severity = None, None
            self.logger.info("[BACnet] %s I-Am announcement", addr[0])
        else:
            attack_type, severity = None, None
            self.logger.info("[BACnet] %s Unconfirmed 0x%02X", addr[0], service)

        event_data = {
            "dst_port": self.hp.port,
            "phase": "bacnet_unconfirmed",
            "rule": svc_name,
            "payload": f"Unconfirmed service={svc_name}(0x{service:02X})",
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
