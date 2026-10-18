"""EtherNet/IP decoder: the 24-byte encapsulation header and the CIP service in SendRRData.

The input is a complete encapsulation frame (header, then ``length`` bytes of command data).
``Frame.code`` is the encapsulation command; for SendRRData (0x6F) the semantics come
from the unconnected CIP request inside, when its layout is confirmed:

* services below 0x32 are common to every CIP object, so they are read from the service code;
* services 0x4b-0x63 are object-specific, so their meaning depends on the target class. The one
  confirmed case is a symbolic request path (segment 0x91), where 0x4c/0x4d/0x52/0x53 are the
  Logix tag read and write services. Anywhere else the service is reported without semantics.
"""

from __future__ import annotations

from honeylens.ics.frame import DECODERS, Field, Frame, Semantics, undecodable

_HEADER: tuple[tuple[str, str, int], ...] = (
    ("command", "Encapsulation command", 2),
    ("length", "Length of command data", 2),
    ("session_handle", "Session handle", 4),
    ("status", "Status", 4),
    ("sender_context", "Sender context", 8),
    ("options", "Options", 4),
)
_HEADER_LEN = 24

# command -> (name, semantics)
_COMMANDS: dict[int, tuple[str, Semantics | None]] = {
    0x0000: ("NOP", None),
    0x0004: ("ListServices", "enumerate"),
    0x0063: ("ListIdentity", "discovery"),
    0x0064: ("ListInterfaces", "enumerate"),
    0x0065: ("RegisterSession", "enumerate"),
    0x0066: ("UnRegisterSession", None),
    0x006F: ("SendRRData", None),
    0x0070: ("SendUnitData", None),
    0x0072: ("IndicateStatus", None),
    0x0073: ("Cancel", None),
}

_SENTENCES = {
    0x0000: "Sends a no-operation keep-alive",
    0x0004: "Asks the device which services it offers",
    0x0063: "Asks the device to identify itself (ListIdentity)",
    0x0064: "Asks the device which interfaces it offers",
    0x0065: "Opens an EtherNet/IP session",
    0x0066: "Closes its EtherNet/IP session",
    0x0070: "Sends connected data on an open CIP connection",
    0x0072: "Sends a status indication",
    0x0073: "Cancels an outstanding request",
}

# Common CIP services (below 0x32): name, semantics.
_CIP_COMMON: dict[int, tuple[str, Semantics | None]] = {
    0x01: ("Get_Attribute_All", "read"),
    0x02: ("Set_Attribute_All", "write"),
    0x03: ("Get_Attribute_List", "read"),
    0x04: ("Set_Attribute_List", "write"),
    0x05: ("Reset", "control"),
    0x06: ("Start", "control"),
    0x07: ("Stop", "control"),
    0x08: ("Create", "write"),
    0x09: ("Delete", "write"),
    0x0A: ("Multiple_Service_Packet", None),
    0x0D: ("Apply_Attributes", None),
    0x0E: ("Get_Attribute_Single", "read"),
    0x10: ("Set_Attribute_Single", "write"),
}
# Logix tag services, valid only on a symbolic request path.
_LOGIX_TAG: dict[int, tuple[str, Semantics]] = {
    0x4C: ("Read Tag", "read"),
    0x4D: ("Write Tag", "write"),
    0x52: ("Read Tag Fragmented", "read"),
    0x53: ("Write Tag Fragmented", "write"),
}
_SYMBOLIC_SEGMENT = 0x91
_LEGACY = range(0x0001, 0x0004)


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("enip", 0, "empty frame: no encapsulation header")
    fields: list[Field] = []
    pos = 0
    command: int | None = None
    values: dict[str, int] = {}
    for name, label, length in _HEADER:
        if pos + length > len(raw):
            return _cut_header(raw, fields, command, pos, name)
        chunk = raw[pos : pos + length]
        value: int | str = (
            chunk.hex() if name == "sender_context" else int.from_bytes(chunk, "little")
        )
        meaning = None
        if name == "command":
            command = int(value)
            known = _COMMANDS.get(command)
            meaning = known[0] if known else None
        if isinstance(value, int):
            values[name] = value
        fields.append(Field(name, label, pos, length, value, meaning))
        pos += length

    command = values["command"]
    end = min(len(raw), _HEADER_LEN + values["length"])
    outer = None
    if end < len(raw):
        outer = (
            end,
            f"{len(raw) - end} byte(s) after the encapsulation length of {values['length']}",
        )

    known = _COMMANDS.get(command)
    if known is None:
        return _unknown_command(raw, fields, command, pos, outer)
    name, semantics = known
    if command == 0x0065:
        return _register_session(raw, fields, command, semantics, pos, end, outer)
    if command == 0x006F:
        return _send_rr_data(raw, fields, pos, end, values["length"], outer)

    sentence = _SENTENCES[command]
    if pos < end:
        why = f"the command data of {name} is not decoded here"
        return _frame(raw, fields, semantics, command, sentence, pos, why)
    return _frame(raw, fields, semantics, command, sentence, None, None, outer)


def _unknown_command(
    raw: bytes, fields: list[Field], command: int, pos: int, outer: tuple[int, str] | None
) -> Frame:
    if command in _LEGACY:
        why = (
            f"command 0x{command:04x} is reserved for legacy use by the EtherNet/IP "
            "specification, so the bytes after the header are not placed"
        )
    else:
        why = (
            f"command 0x{command:04x} is reserved and not defined by the EtherNet/IP "
            "specification, so the bytes after the header are not placed"
        )
    # A reserved-for-legacy code is in the specification, so it is "I do not know this code"
    # (None); only a code the specification leaves undefined is out of specification.
    tail = pos if pos < len(raw) else None
    if command in _LEGACY:
        sentence = f"Sends command 0x{command:04x}, which the EtherNet/IP specification reserves for legacy use"
        return _frame(raw, fields, None, command, sentence, tail, why)
    sentence = f"Sends command 0x{command:04x}, which the EtherNet/IP specification does not define"
    return _frame(raw, fields, "anomaly", command, sentence, tail, why)


def _register_session(
    raw: bytes,
    fields: list[Field],
    command: int,
    semantics: Semantics | None,
    pos: int,
    end: int,
    outer: tuple[int, str] | None,
) -> Frame:
    sentence = _SENTENCES[command]
    for name, label in (
        ("protocol_version", "Protocol version"),
        ("session_options", "Options flags"),
    ):
        if pos + 2 > end:
            where = "before" if pos >= end else "inside"
            return _frame(
                raw, fields, semantics, command, "RegisterSession (frame cut short)", pos,
                f"frame ends {where} the {name} field of RegisterSession",
            )  # fmt: skip
        fields.append(
            Field(name, label, pos, 2, int.from_bytes(raw[pos : pos + 2], "little"), None)
        )
        pos += 2
    if pos < end:
        return _frame(
            raw, fields, semantics, command, sentence, pos, "bytes after the RegisterSession fields"
        )
    return _frame(raw, fields, semantics, command, sentence, None, None, outer)


def _send_rr_data(
    raw: bytes,
    fields: list[Field],
    pos: int,
    end: int,
    declared: int,
    outer: tuple[int, str] | None,
) -> Frame:
    command = 0x006F
    semantics: Semantics | None = None
    sentence = "Sends an unconnected CIP request (SendRRData)"
    stop: tuple[int, str] | None = None

    def cut(name: str, at: int) -> Frame:
        where = "before" if at >= end else "inside"
        why = f"frame ends {where} the {name} field of SendRRData"
        if declared > end - _HEADER_LEN and end == len(raw):
            return _frame(raw, fields, semantics, command, "SendRRData (frame cut short)", at, why)
        return _frame(raw, fields, semantics, command, sentence, at, why)

    layout: tuple[tuple[str, str, int], ...] = (
        ("interface_handle", "Interface handle", 4),
        ("timeout", "Timeout", 2),
        ("item_count", "CPF item count", 2),
        ("address_item_type", "Address item type", 2),
        ("address_item_length", "Address item length", 2),
        ("data_item_type", "Data item type", 2),
        ("data_item_length", "Data item length", 2),
    )
    vals: dict[str, int] = {}
    for name, label, length in layout:
        if pos + length > end:
            return cut(name, pos)
        vals[name] = int.from_bytes(raw[pos : pos + length], "little")
        fields.append(Field(name, label, pos, length, vals[name], None))
        pos += length
        if name == "item_count" and vals[name] != 2:
            stop = (pos, f"the CPF item count is {vals[name]}, not 2, so the items are not placed")
        elif name == "address_item_length" and vals[name] != 0:
            stop = (
                pos,
                f"address item type 0x{vals['address_item_type']:04x} carries data, so the items after it are not placed",
            )
        elif name == "data_item_type" and vals[name] != 0x00B2:
            stop = (
                pos,
                f"data item type 0x{vals[name]:04x} is not the unconnected data item (0x00b2)",
            )
        elif name == "address_item_type" and vals[name] != 0:
            stop = (pos, f"address item type 0x{vals[name]:04x} is not the null address item")
        if stop is not None:
            return _frame(
                raw, fields, None, command, sentence, pos if pos < len(raw) else None, stop[1]
            )

    data_end = min(end, pos + vals["data_item_length"])
    item_limited = pos + vals["data_item_length"] < end

    def short(name: str, at: int) -> Frame | None:
        """The data item's own length, not the capture, is what runs out: say so."""
        if not item_limited:
            return None
        n = vals["data_item_length"]
        why = f"the data item declares {n} byte(s), which leaves no {name} field"
        return _frame(raw, fields, semantics, command, sentence, at, why)

    # The CIP request: service, path size in words, the path, then request data.
    if pos + 1 > data_end:
        return short("cip_service", pos) or cut("cip_service", pos)
    service = raw[pos]
    is_response = bool(service & 0x80)
    base = service & 0x7F
    path_first: int | None = None
    name_of: str | None = None
    if is_response:
        meaning = None
    elif base < 0x32:
        meaning = _CIP_COMMON.get(base, (None, None))[0]
        semantics = _CIP_COMMON[base][1] if base in _CIP_COMMON else None
        name_of = meaning
    else:
        meaning = None
    service_at = len(fields)
    fields.append(Field("cip_service", "CIP service", pos, 1, service, meaning))
    pos += 1
    if pos + 1 > data_end:
        return short("request_path_size", pos) or cut("request_path_size", pos)
    words = raw[pos]
    fields.append(Field("request_path_size", "Request path size (words)", pos, 1, words, None))
    pos += 1
    path_len = words * 2
    if pos + path_len > data_end:
        # a partial path is not placed as a field; its bytes stay in the tail
        if item_limited:
            n = vals["data_item_length"]
            why = f"the data item declares {n} byte(s), which leaves no complete request_path field"
            label = name_of or f"CIP service 0x{base:02x}"
            return _frame(raw, fields, semantics, command, f"{label} (short data item)", pos, why)
        return _cut_path(raw, fields, command, semantics, name_of, pos, base)
    path = raw[pos : pos + path_len]
    if path:
        path_first = path[0]
    fields.append(Field("request_path", "Request path", pos, path_len, path.hex(), None))
    pos += path_len

    if not is_response and base >= 0x32 and path_first == _SYMBOLIC_SEGMENT and base in _LOGIX_TAG:
        name_of, semantics = _LOGIX_TAG[base]
        old = fields[service_at]
        fields[service_at] = Field(old.name, old.label, old.offset, old.length, old.value, name_of)
    if is_response:
        sentence = f"Sends a CIP response (service 0x{service:02x}) in a request frame"
    elif name_of is not None:
        sentence = f"Sends the CIP service {name_of} to the device"
    elif base >= 0x32:
        sentence = (
            f"Sends the CIP service 0x{service:02x} (object-specific; "
            "its meaning depends on the target class)"
        )
    else:
        sentence = f"Sends the CIP service 0x{service:02x}"
    if pos < len(raw):
        why = f"{len(raw) - pos} byte(s) of CIP request data after the request path"
        return _frame(raw, fields, semantics, command, sentence, pos, why)
    return _frame(raw, fields, semantics, command, sentence, None, None, outer)


def _cut_path(
    raw: bytes,
    fields: list[Field],
    command: int,
    semantics: Semantics | None,
    name_of: str | None,
    pos: int,
    base: int,
) -> Frame:
    where = "before" if pos >= len(raw) else "inside"
    why = f"frame ends {where} the request_path field of SendRRData"
    label = name_of or f"CIP service 0x{base:02x}"
    return _frame(raw, fields, semantics, command, f"{label} (frame cut short)", pos, why)


def _cut_header(raw: bytes, fields: list[Field], command: int | None, pos: int, name: str) -> Frame:
    where = "before" if pos >= len(raw) else "inside"
    why = f"frame ends {where} the {name} field of the encapsulation header"
    known = _COMMANDS.get(command) if command is not None else None
    if command is None:
        sentence = None
        semantics: Semantics | None = None
    elif known is not None:
        sentence, semantics = f"{known[0]} (frame cut short)", known[1]
    else:
        sentence, semantics = f"Command 0x{command:04x} (frame cut short)", "anomaly"
    return _frame(raw, fields, semantics, command, sentence, pos, why)


def _frame(
    raw: bytes,
    fields: list[Field],
    semantics: Semantics | None,
    code: int | None,
    sentence: str | None,
    tail_offset: int | None,
    tail_reason: str | None,
    outer: tuple[int, str] | None = None,
) -> Frame:
    if tail_offset is None and outer is not None:
        tail_offset, tail_reason = outer
    if tail_offset is None:
        tail_reason = None
    return Frame(
        protocol="enip",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


DECODERS["enip"] = decode
