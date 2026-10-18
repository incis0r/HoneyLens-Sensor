# honeypots/ics/mms.py
"""IEC 61850 MMS handler — identify-depth. Recognises Initiate / Identify /
control services in the COTP DT payload and returns templated MMS PDUs."""

from __future__ import annotations

# MMS PDU tags (context tags on the MMSpdu CHOICE)
_INITIATE_REQ = 0xA8
_INITIATE_RSP = 0xA9
_CONFIRMED_REQ = 0xA0
_CONFIRMED_RSP = 0xA1
# confirmed-service tags (inside confirmed-Request)
_SVC_IDENTIFY = 0x82
_SVC_GETNAMELIST = 0xA1  # context
_SVC_READ = 0xA4
_SVC_WRITE = 0xA5


def _str(tag: int, s: bytes) -> bytes:
    return bytes([tag, len(s)]) + s


class MmsHandler:
    def __init__(self, profile: dict):
        self.profile = profile
        self.last_kind = "enumeration"

    def _identify_response(self) -> bytes:
        vendor = self.profile.get("vendor", "SIEMENS").encode()
        model = self.profile.get("model", "SIPROTEC 5").encode()
        rev = self.profile.get("revision", "V09.40").encode()
        # Identify-Response: SEQUENCE { vendorName[0] IA5, modelName[1], revision[2] }
        body = _str(0x80, vendor) + _str(0x81, model) + _str(0x82, rev)
        ident = bytes([0xA0, len(body)]) + body  # identify result
        inner = bytes([0x02, 0x01, 0x01]) + ident  # invokeID 1 + result
        return bytes([_CONFIRMED_RSP, len(inner)]) + inner

    def handle_mms(self, payload: bytes):
        """Return an MMS response (raw, to be COTP-wrapped) or None."""
        if not payload:
            return None
        tag = payload[0]
        if tag == _INITIATE_REQ:
            self.last_kind = "enumeration"
            # Initiate-Response: conservative negotiated params
            body = (
                bytes([0x80, 0x01, 0x05])  # localDetailCalling
                + bytes([0x81, 0x01, 0x05])  # maxServOutstandingCalling
                + bytes([0x82, 0x01, 0x05])  # maxServOutstandingCalled
                + bytes([0x83, 0x01, 0x0A])
            )  # dataStructNestingLevel
            return bytes([_INITIATE_RSP, len(body)]) + body
        if tag == _CONFIRMED_REQ:
            svc = payload.find(bytes([0xA1]))  # locate the service wrapper
            blob = payload[svc:] if svc >= 0 else payload
            if _SVC_WRITE in blob[:8]:
                self.last_kind = "write"
                return bytes([_CONFIRMED_RSP, 0x03, 0x02, 0x01, 0x02])  # bare ack
            if _SVC_IDENTIFY in blob[:8]:
                self.last_kind = "recon"
                return self._identify_response()
            if _SVC_READ in blob[:8] or _SVC_GETNAMELIST in blob[:8]:
                self.last_kind = "recon"
                return bytes([_CONFIRMED_RSP, 0x03, 0x02, 0x01, 0x01])  # empty-ish
            self.last_kind = "recon"
            return bytes([_CONFIRMED_RSP, 0x03, 0x02, 0x01, 0x01])
        self.last_kind = "enumeration"
        return None
