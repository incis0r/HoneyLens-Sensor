# honeypots/ics/mms.py
"""IEC 61850 MMS handler — identify-depth. Returns templated MMS PDUs for Initiate /
Identify / confirmed requests in the COTP DT payload.

What a request *is* — and therefore its kind — is not decided here: ``last_kind`` comes from
``honeylens.ics.mms``, which walks the ISO session and presentation layers a real client
wraps its MMS PDU in. The reply templates below still key on a bare MMS tag.
"""

from __future__ import annotations

from honeylens.honeypots.ics.verdict import kind_for
from honeylens.ics import decode

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
            self.last_kind = "enumeration"
            return None
        self.last_kind = kind_for(decode("mms", payload))
        tag = payload[0]
        if tag == _INITIATE_REQ:
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
                return bytes([_CONFIRMED_RSP, 0x03, 0x02, 0x01, 0x02])  # bare ack
            if _SVC_IDENTIFY in blob[:8]:
                return self._identify_response()
            return bytes([_CONFIRMED_RSP, 0x03, 0x02, 0x01, 0x01])  # empty-ish
        return None
