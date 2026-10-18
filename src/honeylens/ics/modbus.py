"""Modbus decoder: the function code and the request fields the specification defines for it.

The input is the PDU as the decoys capture it: the function code is byte 0.
A code the specification does not define is reported as an anomaly and its
remaining bytes stay in the tail, because their layout is unknown.
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
    # reads (the decoy files FC7 as recon). FC8 stays "control" on purpose: its sub-functions
    # include Restart Communications and Force Listen Only Mode. Do not "tidy" it to a read.
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
    return _frame(raw, fields, semantics, code, sentence, tail, reason)


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
