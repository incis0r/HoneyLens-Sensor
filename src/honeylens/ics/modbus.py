"""Modbus decoder: the function code and the request fields the specification defines for it.

The input is the PDU as the decoys capture it: the function code is byte 0.
A code the specification does not define is reported as an anomaly and its
remaining bytes stay in the tail, because their layout is unknown. The one exception is
function code 90, Schneider's Unity (UMAS) protocol: see ``_UMAS``.
"""

from __future__ import annotations

from honeylens.ics.frame import DECODERS, Field, Frame, Semantics, undecodable

# code -> (name, semantics, layout). Layout items are (field name, label, length);
# a length of -1 means "the number of bytes given by the preceding byte_count field".
_Layout = tuple[tuple[str, str, int], ...]

_ADDR_QTY: _Layout = (("address", "Starting address", 2), ("quantity", "Quantity", 2))
_ADDR_VAL: _Layout = (("address", "Address", 2), ("value", "Value", 2))
_MULTI: _Layout = (
    ("address", "Starting address", 2),
    ("quantity", "Quantity", 2),
    ("byte_count", "Byte count", 1),
    ("data", "Values", -1),
)

_SPEC: dict[int, tuple[str, Semantics, _Layout]] = {
    1: ("Read Coils", "read", _ADDR_QTY),
    2: ("Read Discrete Inputs", "read", _ADDR_QTY),
    3: ("Read Holding Registers", "read", _ADDR_QTY),
    4: ("Read Input Registers", "read", _ADDR_QTY),
    5: ("Write Single Coil", "write", _ADDR_VAL),
    6: ("Write Single Register", "write", _ADDR_VAL),
    7: ("Read Exception Status", "read", ()),
    # FC7/11/12 read a status register, a counter and a log: nothing is ordered, so they are
    # reads (the decoy files FC7 as recon). FC8 is "control" here because its sub-functions
    # include Restart Communications and Force Listen Only Mode; the sub-functions that only
    # echo or return a counter are narrowed to "read" below (_DIAGNOSTIC_CONTROL). A frame cut
    # before its sub-function keeps "control". Do not "tidy" the whole code to a read.
    8: (
        "Diagnostics",
        "control",
        (("sub_function", "Sub-function", 2), ("diagnostic_data", "Data", 2)),
    ),
    11: ("Get Comm Event Counter", "read", ()),
    12: ("Get Comm Event Log", "read", ()),
    15: ("Write Multiple Coils", "write", _MULTI),
    16: ("Write Multiple Registers", "write", _MULTI),
    17: ("Report Server ID", "enumerate", ()),
    43: (
        "Encapsulated Interface Transport",
        "enumerate",
        (("mei_type", "MEI type", 1),),
    ),
}

# FC8 sub-functions that change how the device behaves: 1 Restart Communications Option,
# 4 Force Listen Only Mode, 10 Clear Counters and Diagnostic Register, 20 Clear Overrun
# Counter and Flag. Every other sub-function echoes the request or returns a counter. The
# decoy's verdict is derived from the semantics, so an echo test must not read as a command.
_DIAGNOSTIC_CONTROL = frozenset({1, 4, 10, 20})

# Function code 90 is not in the Modbus specification: it is Schneider Electric's Unity
# (UMAS) protocol, carried in the user-defined range and spoken by every Modicon PLC. The
# request is ``5a <session key> <UMAS function> <data>``. It is how a Modicon is
# fingerprinted, and it is also how one is stopped or reprogrammed, so the meaning has to
# come from the UMAS function and not from the Modbus code. Names follow the public
# dissectors; the data after the function is not decoded.
UMAS_FUNCTION_CODE = 90
_UMAS: dict[int, tuple[str, Semantics]] = {
    0x01: ("Init Comm", "discovery"),
    0x02: ("Read ID", "enumerate"),
    0x03: ("Read Project Info", "enumerate"),
    0x04: ("Read PLC Info", "enumerate"),
    0x06: ("Read Card Info", "enumerate"),
    0x0A: ("Repeat", "discovery"),
    0x10: ("Take PLC Reservation", "control"),
    0x11: ("Release PLC Reservation", "discovery"),
    0x12: ("Keep Alive", "discovery"),
    0x20: ("Read Memory Block", "read"),
    0x22: ("Read Variables", "read"),
    0x23: ("Write Variables", "write"),
    0x24: ("Read Coils/Registers", "read"),
    0x25: ("Write Coils/Registers", "write"),
    0x30: ("Initialize Upload", "read"),
    0x31: ("Upload Block", "read"),
    0x32: ("End Strategy Upload", "read"),
    0x33: ("Initialize Download", "write"),
    0x34: ("Download Block", "write"),
    0x35: ("End Strategy Download", "write"),
    0x39: ("Read Ethernet Master Data", "enumerate"),
    0x40: ("Start PLC", "control"),
    0x41: ("Stop PLC", "control"),
    0x50: ("Monitor PLC", "read"),
    0x58: ("Check PLC", "enumerate"),
    0x70: ("Read IO Object", "read"),
    0x71: ("Write IO Object", "write"),
    0x73: ("Get Status Module", "enumerate"),
}

# MEI type 14 (Read Device Identification) is the only MEI layout decoded.
_MEI_14: _Layout = (
    ("read_device_id_code", "Read device ID code", 1),
    ("object_id", "Object ID", 1),
)

# Fields shown as hex bytes; every other field is read as a big-endian integer.
_HEX_FIELDS = {"data"}

# Defined by the specification, meaning known, field layout not decoded here. The meaning is
# assigned (semantics=None would say "unknown code", which is false for these); the bytes after
# the function code go to the tail with a reason that says the layout is not decoded.
_SPEC_UNDECODED: dict[int, tuple[str, Semantics, str]] = {
    20: ("Read File Record", "read", "Reads file records"),
    21: ("Write File Record", "write", "Writes file records"),
    22: ("Mask Write Register", "write", "Masks and writes a holding register"),
    23: ("Read/Write Multiple Registers", "write", "Writes and reads holding registers"),
    24: ("Read FIFO Queue", "read", "Reads a FIFO queue"),
}

_SENTENCES = {
    1: "Reads {quantity} coil(s) starting at address {address}",
    2: "Reads {quantity} discrete input(s) starting at address {address}",
    3: "Reads {quantity} holding register(s) starting at address {address}",
    4: "Reads {quantity} input register(s) starting at address {address}",
    5: "Writes coil {address} (value 0x{value:04x})",
    6: "Writes the value {value} to holding register {address}",
    7: "Reads the device's exception status",
    8: "Runs a diagnostic (sub-function {sub_function}) on the device",
    11: "Asks for the device's communication event counter",
    12: "Asks for the device's communication event log",
    15: "Writes {quantity} coil(s) starting at address {address}",
    16: "Writes {quantity} holding register(s) starting at address {address}",
    17: "Asks the device to identify itself",
    43: "Asks the device for its identification objects",
}


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("modbus", 0, "empty frame: no function code")
    code = raw[0]
    fields: list[Field] = [Field("function_code", "Function code", 0, 1, code, None)]
    spec = _SPEC.get(code)

    if code == UMAS_FUNCTION_CODE:
        return _umas(raw, fields)

    if spec is None:
        if code in _SPEC_UNDECODED:
            uname, usem, usentence = _SPEC_UNDECODED[code]
            fields[0] = Field("function_code", "Function code", 0, 1, code, uname)
            why = (
                f"function code {code} ({uname}) is in the specification "
                "but its field layout is not decoded here"
            )
            return _frame(raw, fields, usem, code, usentence, 1 if len(raw) > 1 else None, why)
        if code >= 0x80:
            why = (
                f"function code {code} is an exception-response code, which a client "
                "should not send in a request, so the layout of the bytes after it is unknown"
            )
            sentence = f"Sends {code}, an exception-response code, as a request"
        elif 65 <= code <= 72 or 100 <= code <= 110:
            why = (
                f"function code {code} is a user-defined code, "
                "so the layout of the bytes after it is unknown"
            )
            sentence = f"Uses function code {code}, a user-defined code"
        else:
            why = (
                f"function code {code} is not in the Modbus specification, "
                "so the layout of the bytes after it is unknown"
            )
            sentence = f"Uses function code {code}, which the Modbus specification does not define"
        return _frame(raw, fields, "anomaly", code, sentence, 1 if len(raw) > 1 else None, why)

    name, semantics, layout = spec
    fields[0] = Field("function_code", "Function code", 0, 1, code, name)
    pos = 1
    values: dict[str, int] = {}
    cut_short = False
    pending = list(layout)
    unplaced_reason: str | None = None
    while pending:
        fname, label, length = pending.pop(0)
        if length == -1:
            length = values["byte_count"]
        if pos + length > len(raw):
            cut_short = True
            break
        chunk = raw[pos : pos + length]
        value: int | str = chunk.hex() if fname in _HEX_FIELDS else int.from_bytes(chunk, "big")
        if isinstance(value, int):
            values[fname] = value
        fields.append(Field(fname, label, pos, length, value, None))
        pos += length
        if fname == "mei_type":
            if value == 14:
                pending.extend(_MEI_14)
            else:
                unplaced_reason = (
                    f"MEI type {value} is not decoded here, so the bytes after it are not placed"
                )

    reason: str | None
    tail: int | None
    if cut_short:
        where = "before" if pos >= len(raw) else "inside"
        reason = f"frame ends {where} the {fname} field of function code {code} ({name})"
        tail = pos
    elif pos < len(raw):
        reason = unplaced_reason or (
            f"{len(raw) - pos} byte(s) after the fields defined for function code {code}"
        )
        tail = pos
    else:
        reason = None
        tail = None

    if cut_short:
        sentence = f"{name} (frame cut short)"
    else:
        sentence = _SENTENCES[code].format(**values)
    if code == 8 and "sub_function" in values and values["sub_function"] not in _DIAGNOSTIC_CONTROL:
        semantics = "read"
    return _frame(raw, fields, semantics, code, sentence, tail, reason)


def _umas(raw: bytes, fields: list[Field]) -> Frame:
    """Function code 90: the session key, the UMAS function, and the data left in the tail."""
    code = UMAS_FUNCTION_CODE
    fields[0] = Field("function_code", "Function code", 0, 1, code, "Unity (UMAS)")
    if len(raw) < 3:
        missing = "session_key" if len(raw) < 2 else "umas_function"
        if len(raw) == 2:
            fields.append(Field("session_key", "Session key", 1, 1, raw[1], None))
        why = f"frame ends before the {missing} field of function code 90 (Unity/UMAS)"
        return _frame(raw, fields, "anomaly", code, "Unity (UMAS) (frame cut short)", len(raw), why)
    fields.append(Field("session_key", "Session key", 1, 1, raw[1], None))
    function = raw[2]
    known = _UMAS.get(function)
    fields.append(
        Field("umas_function", "UMAS function", 2, 1, function, known[0] if known else None)
    )
    tail = 3 if len(raw) > 3 else None
    if known is None:
        sentence = f"Sends UMAS function 0x{function:02x}, which is not a known Unity request"
        why = f"UMAS function 0x{function:02x} is not known, so the bytes after it are not placed"
        return _frame(raw, fields, "anomaly", code, sentence, tail, why)
    name, semantics = known
    sentence = f"Sends the Schneider Unity (UMAS) request {name} to a Modicon controller"
    return _frame(
        raw, fields, semantics, code, sentence, tail, f"the data of {name} is not decoded"
    )


def request_name(raw: bytes) -> str:
    """The short name of a request PDU, for a decoy's ``rule``: the specification's name for
    the function code, the UMAS function for code 90, ``FC_<n>`` for a code with no name."""
    if not raw:
        return "empty"
    code = raw[0]
    if code == UMAS_FUNCTION_CODE:
        known = _UMAS.get(raw[2]) if len(raw) >= 3 else None
        return f"UMAS {known[0]}" if known else "UMAS unknown function"
    if code == 43:
        return (
            "Read Device Identification"
            if raw[1:2] == b"\x0e"
            else "Encapsulated Interface Transport"
        )
    if code in _SPEC:
        return _SPEC[code][0]
    if code in _SPEC_UNDECODED:
        return _SPEC_UNDECODED[code][0]
    return f"FC_{code}"


def _frame(
    raw: bytes,
    fields: list[Field],
    semantics: Semantics | None,
    code: int,
    sentence: str | None,
    tail_offset: int | None,
    tail_reason: str | None,
) -> Frame:
    if tail_offset is None:
        tail_reason = None
    return Frame(
        protocol="modbus",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


DECODERS["modbus"] = decode
