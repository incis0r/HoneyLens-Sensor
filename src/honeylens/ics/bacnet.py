"""BACnet decoder: the APDU, its service choice, and what the service does.

The input is the APDU as the decoy captures it (``apdu_hex``): byte 0 carries the PDU
type in its high nibble. The BVLC and NPDU layers are not part of the stored bytes.
Only the confirmed-request header and the object and property identifiers of
ReadProperty and WriteProperty are placed further; everything else stays in the tail.

``Frame.code`` is the service choice. Confirmed and unconfirmed services number
separately, so code 8 is AddListElement in a confirmed request and Who-Is in an
unconfirmed one; the semantics and the sentence say which.
"""

from __future__ import annotations

from honeylens.ics.frame import DECODERS, Field, Frame, Semantics, undecodable

_PDU_TYPES = {
    0: "Confirmed-Request",
    1: "Unconfirmed-Request",
    2: "Simple-ACK",
    3: "Complex-ACK",
    4: "Segment-ACK",
    5: "Error",
    6: "Reject",
    7: "Abort",
}

# service choice -> (name, semantics)
_CONFIRMED: dict[int, tuple[str, Semantics | None]] = {
    0: ("AcknowledgeAlarm", None),
    1: ("ConfirmedCOVNotification", None),
    2: ("ConfirmedEventNotification", None),
    3: ("GetAlarmSummary", "enumerate"),
    4: ("GetEnrollmentSummary", "enumerate"),
    5: ("SubscribeCOV", "read"),
    6: ("AtomicReadFile", "read"),
    7: ("AtomicWriteFile", "write"),
    8: ("AddListElement", "write"),
    9: ("RemoveListElement", "write"),
    10: ("CreateObject", "write"),
    11: ("DeleteObject", "write"),
    12: ("ReadProperty", "read"),
    13: ("ReadPropertyConditional", "read"),
    14: ("ReadPropertyMultiple", "read"),
    15: ("WriteProperty", "write"),
    16: ("WritePropertyMultiple", "write"),
    17: ("DeviceCommunicationControl", "control"),
    18: ("ConfirmedPrivateTransfer", None),
    19: ("ConfirmedTextMessage", None),
    20: ("ReinitializeDevice", "control"),
    21: ("VT-Open", None),
    22: ("VT-Close", None),
    23: ("VT-Data", None),
    24: ("Authenticate", None),
    25: ("RequestKey", None),
    26: ("ReadRange", "read"),
    27: ("LifeSafetyOperation", "command"),
    28: ("SubscribeCOVProperty", "read"),
    29: ("GetEventInformation", "enumerate"),
    30: ("SubscribeCOVPropertyMultiple", "read"),
    31: ("ConfirmedCOVNotificationMultiple", None),
    32: ("ConfirmedAuditNotification", None),
    33: ("AuditLogQuery", "read"),
}

_UNCONFIRMED: dict[int, tuple[str, Semantics | None]] = {
    0: ("I-Am", None),
    1: ("I-Have", None),
    2: ("UnconfirmedCOVNotification", None),
    3: ("UnconfirmedEventNotification", None),
    4: ("UnconfirmedPrivateTransfer", None),
    5: ("UnconfirmedTextMessage", None),
    6: ("TimeSynchronization", "command"),
    7: ("Who-Has", "discovery"),
    8: ("Who-Is", "discovery"),
    9: ("UTCTimeSynchronization", "command"),
    10: ("WriteGroup", "write"),
    11: ("UnconfirmedCOVNotificationMultiple", None),
    12: ("UnconfirmedAuditNotification", None),
    13: ("Who-Am-I", None),
    14: ("You-Are", None),
}

_OBJECT_TYPES = {
    0: "analog-input",
    1: "analog-output",
    2: "analog-value",
    3: "binary-input",
    4: "binary-output",
    5: "binary-value",
    6: "calendar",
    7: "command",
    8: "device",
    9: "event-enrollment",
    10: "file",
    11: "group",
    12: "loop",
    13: "multi-state-input",
    14: "multi-state-output",
    15: "notification-class",
    16: "program",
    17: "schedule",
    18: "averaging",
    19: "multi-state-value",
    20: "trend-log",
}

_PROPERTIES = {
    8: "all",
    12: "application-software-version",
    28: "description",
    36: "event-state",
    44: "firmware-revision",
    70: "model-name",
    75: "object-identifier",
    76: "object-list",
    77: "object-name",
    79: "object-type",
    85: "present-value",
    87: "priority-array",
    104: "relinquish-default",
    111: "status-flags",
    112: "system-status",
    117: "units",
    120: "vendor-identifier",
    121: "vendor-name",
}

# Services whose request starts with an object identifier [0] and a property identifier [1].
_PROPERTY_SERVICES = {12, 15}


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("bacnet", 0, "empty frame: no PDU type")
    pdu = raw[0] >> 4
    type_name = _PDU_TYPES.get(pdu)
    fields = [Field("pdu_type", "PDU type", 0, 1, pdu, type_name)]

    if type_name is None:
        why = f"PDU type {pdu} is reserved by the BACnet specification, so the bytes after it are not placed"
        sentence = f"Sends PDU type {pdu}, which the BACnet specification reserves"
        return _frame(raw, fields, "anomaly", None, sentence, _after(raw, 1), why)
    if pdu not in (0, 1):
        why = (
            f"a {type_name} PDU is a response the specification defines, "
            "and its layout is not decoded here"
        )
        return _frame(raw, fields, None, None, f"Sends a {type_name} PDU", _after(raw, 1), why)

    confirmed = pdu == 0
    pos = 1
    layout: list[tuple[str, str, int]] = []
    if confirmed:
        layout.append(("max_response", "Max segments and response size", 1))
        layout.append(("invoke_id", "Invoke ID", 1))
        if raw[0] & 0x08:  # SEG: the request is segmented
            layout.append(("sequence_number", "Sequence number", 1))
            layout.append(("window_size", "Proposed window size", 1))
    layout.append(("service_choice", "Service choice", 1))

    table = _CONFIRMED if confirmed else _UNCONFIRMED
    code: int | None = None
    name = ""
    semantics: Semantics | None = None
    for fname, label, length in layout:
        if pos + length > len(raw):
            return _cut(raw, fields, code, name, semantics, pos, fname, confirmed)
        value = int.from_bytes(raw[pos : pos + length], "big")
        meaning = None
        if fname == "service_choice":
            code = value
            known = table.get(value)
            if known is not None:
                name, semantics = known
                meaning = name
        fields.append(Field(fname, label, pos, length, value, meaning))
        pos += length

    code = 0 if code is None else code  # the loop above always reads the service choice
    kind = "confirmed" if confirmed else "unconfirmed"
    if code not in table:
        why = (
            f"{kind} service choice {code} is not assigned in the BACnet revision "
            "this decoder knows, so the bytes after it are not placed"
        )
        return _frame(raw, fields, None, code, None, _after(raw, pos), why)

    object_text = ""
    if confirmed and code in _PROPERTY_SERVICES and pos < len(raw):
        stop = _property_request(raw, pos, fields)
        if stop is not None:
            return _cut_or_mismatch(raw, fields, code, name, semantics, stop)
        pos = fields[-1].offset + fields[-1].length
        object_text = _object_text(fields)

    sentence = _sentence(confirmed, code, name, object_text)
    if pos < len(raw):
        why = (
            f"{len(raw) - pos} byte(s) after the fields decoded for {kind} service {code} ({name})"
        )
        return _frame(raw, fields, semantics, code, sentence, pos, why)
    return _frame(raw, fields, semantics, code, sentence, None, None)


def _property_request(raw: bytes, pos: int, fields: list[Field]) -> tuple[int, str, bool] | None:
    """Place [0] object identifier and [1] property identifier; None when both fit.

    Otherwise (position of the first unplaced byte, reason, whether the frame ended there).
    """
    if raw[pos] != 0x0C:
        return pos, f"expected the object identifier tag 0x0c, found 0x{raw[pos]:02x}", False
    if pos + 5 > len(raw):
        return pos, "frame ends inside the object_identifier field", True
    packed = int.from_bytes(raw[pos + 1 : pos + 5], "big")
    obj_type, instance = packed >> 22, packed & 0x3FFFFF
    fields.append(
        Field(
            "object_identifier",
            "Object identifier",
            pos,
            5,
            f"{obj_type},{instance}",
            _OBJECT_TYPES.get(obj_type),
        )
    )
    pos += 5
    if pos >= len(raw):
        return pos, "frame ends before the property_identifier field", True
    tag = raw[pos]
    if tag & 0xF8 != 0x18 or not 0x19 <= tag <= 0x1C:
        return pos, f"expected the property identifier tag 0x19-0x1c, found 0x{tag:02x}", False
    length = tag & 0x07
    if pos + 1 + length > len(raw):
        return pos, "frame ends inside the property_identifier field", True
    prop = int.from_bytes(raw[pos + 1 : pos + 1 + length], "big")
    fields.append(
        Field(
            "property_identifier",
            "Property identifier",
            pos,
            1 + length,
            prop,
            _PROPERTIES.get(prop),
        )
    )
    return None


def _object_text(fields: list[Field]) -> str:
    obj = next(f for f in fields if f.name == "object_identifier")
    prop = next(f for f in fields if f.name == "property_identifier")
    obj_type, _, instance = str(obj.value).partition(",")
    type_name = obj.meaning or f"object type {obj_type}"
    prop_name = prop.meaning or f"property {prop.value}"
    return f"{prop_name} of {type_name} {instance}"


def _sentence(confirmed: bool, code: int, name: str, object_text: str) -> str:
    if object_text:
        verb = "Reads" if code == 12 else "Writes"
        return f"{verb} {object_text}"
    if not confirmed and code in (7, 8):
        return (
            "Broadcasts a search for devices" if code == 8 else "Broadcasts a search for an object"
        )
    return f"Requests the {name} service"


def _after(raw: bytes, pos: int) -> int | None:
    return pos if pos < len(raw) else None


def _cut_or_mismatch(
    raw: bytes,
    fields: list[Field],
    code: int,
    name: str,
    semantics: Semantics | None,
    stop: tuple[int, str, bool],
) -> Frame:
    pos, why, ended = stop
    if ended:
        # The tail starts where the field that did not fit would have started.
        return _frame(raw, fields, semantics, code, f"{name} (frame cut short)", pos, why)
    return _frame(raw, fields, semantics, code, f"Requests the {name} service", pos, why)


def _cut(
    raw: bytes,
    fields: list[Field],
    code: int | None,
    name: str,
    semantics: Semantics | None,
    pos: int,
    fname: str,
    confirmed: bool,
) -> Frame:
    where = "before" if pos >= len(raw) else "inside"
    kind = "confirmed" if confirmed else "unconfirmed"
    why = f"frame ends {where} the {fname} field of a {kind} request"
    # A sentence exists only when the service choice was actually read.
    sentence = f"{name} (frame cut short)" if code is not None and name else None
    return _frame(raw, fields, semantics, code, sentence, pos, why)


def _frame(
    raw: bytes,
    fields: list[Field],
    semantics: Semantics | None,
    code: int | None,
    sentence: str | None,
    tail_offset: int | None,
    tail_reason: str | None,
) -> Frame:
    if tail_offset is None:
        tail_reason = None
    return Frame(
        protocol="bacnet",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


DECODERS["bacnet"] = decode
