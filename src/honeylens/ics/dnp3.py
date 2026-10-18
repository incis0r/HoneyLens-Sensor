"""DNP3 decoder: the data link header, the transport and application control, the function code.

The input is a data link frame as it appears on the wire: ``05 64``, a length, a control
byte, destination and source addresses, a CRC, then user data in blocks of up to 16 bytes
each followed by its own CRC. Only the first block is read; the application layer fields sit
in it. Object headers and everything after them stay in the tail.

The header CRC is reported, not enforced: scanners send bad CRCs and the screen should say so.
"""

from __future__ import annotations

from honeylens.ics.frame import DECODERS, Field, Frame, Semantics, undecodable

# function code -> (name, semantics)
_FUNCTIONS: dict[int, tuple[str, Semantics | None]] = {
    0: ("Confirm", None),
    1: ("Read", "read"),
    2: ("Write", "write"),
    3: ("Select", "command"),
    4: ("Operate", "command"),
    5: ("Direct Operate", "command"),
    6: ("Direct Operate No Ack", "command"),
    7: ("Immediate Freeze", "command"),
    8: ("Immediate Freeze No Ack", "command"),
    9: ("Freeze and Clear", "command"),
    10: ("Freeze and Clear No Ack", "command"),
    11: ("Freeze at Time", "command"),
    12: ("Freeze at Time No Ack", "command"),
    13: ("Cold Restart", "control"),
    14: ("Warm Restart", "control"),
    15: ("Initialize Data", None),
    16: ("Initialize Application", "control"),
    17: ("Start Application", "control"),
    18: ("Stop Application", "control"),
    19: ("Save Configuration", None),
    20: ("Enable Unsolicited", "control"),
    21: ("Disable Unsolicited", "control"),
    22: ("Assign Class", "write"),
    23: ("Delay Measurement", "enumerate"),
    24: ("Record Current Time", "command"),
    25: ("Open File", "read"),
    26: ("Close File", None),
    27: ("Delete File", "write"),
    28: ("Get File Info", "enumerate"),
    29: ("Authenticate File", None),
    30: ("Abort File", None),
    31: ("Activate Config", "command"),
    32: ("Authentication Request", None),
    33: ("Authentication Error", None),
}
_LINK_HEADER_LEN = 10
_BLOCK = 16
_RESPONSES = {129: "Response", 130: "Unsolicited Response", 131: "Authentication Response"}


def _crc(data: bytes) -> int:
    """CRC-16/DNP: reflected polynomial 0xA6BC, final complement."""
    reg = 0
    for byte in data:
        reg ^= byte
        for _ in range(8):
            reg = (reg >> 1) ^ 0xA6BC if reg & 1 else reg >> 1
    return reg ^ 0xFFFF


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("dnp3", 0, "empty frame: no data link start bytes")
    if raw[:2] != b"\x05\x64":
        seen = raw[:2].hex()
        return undecodable(
            "dnp3", len(raw), f"the first bytes are 0x{seen}, not the data link start 0x0564"
        )

    fields: list[Field] = []
    values: dict[str, int] = {}
    pos = 0
    layout = (
        ("start", "Start bytes", 2),
        ("length", "Length", 1),
        ("link_control", "Link control", 1),
        ("destination", "Destination address", 2),
        ("source", "Source address", 2),
        ("header_crc", "Header CRC", 2),
    )
    for name, label, length in layout:
        if pos + length > len(raw):
            return _cut(raw, fields, None, pos, name)
        chunk = raw[pos : pos + length]
        value: int | str = "0564" if name == "start" else int.from_bytes(chunk, "little")
        meaning = None
        if name == "link_control":
            meaning = _link_text(int(value))
        elif name == "header_crc":
            ok = _crc(raw[:8]) == value
            meaning = "CRC valid" if ok else "CRC does not match the header"
        if isinstance(value, int):
            values[name] = value
        fields.append(Field(name, label, pos, length, value, meaning))
        pos += length

    control = values["link_control"]
    user_len = max(values["length"] - 5, 0)
    src, dst = values["source"], values["destination"]
    if user_len == 0:
        extra = f"{len(raw) - pos} byte(s) after a header that declares no user data"
        if control & 0x40 and control & 0x0F == 9:
            sentence = f"Asks station {dst} for its link status"
            return _frame(raw, fields, "discovery", None, sentence, _after(raw, pos), extra)
        return _frame(raw, fields, None, None, None, _after(raw, pos), extra)
    if not (control & 0x40 and control & 0x0F in (3, 4)):
        why = (
            f"link control 0x{control:02x} is not a primary user-data function (3 or 4), "
            "so the user data is not placed"
        )
        return _frame(raw, fields, None, None, None, _after(raw, pos), why)

    app_layout = (
        ("transport_header", "Transport header", "Transport"),
        ("app_control", "Application control", "Application"),
        ("function_code", "Function code", "Function"),
    )
    for idx, (name, label, _) in enumerate(app_layout):
        if idx >= user_len:
            why = f"the length field declares only {user_len} byte(s) of user data, so there is no {name}"
            return _frame(raw, fields, None, None, None, pos, why)
        if pos >= len(raw):
            return _cut(raw, fields, None, pos, name)
        fields.append(Field(name, label, pos, 1, raw[pos], None))
        pos += 1
        if name == "transport_header" and not raw[pos - 1] & 0x40:
            why = "the transport header does not have FIR set, so this is a continuation segment without an application control byte"
            return _frame(raw, fields, None, None, None, _after(raw, pos), why)

    # The loop returns early unless all three application fields were placed.
    return _function(raw, fields, raw[pos - 1], pos, src, dst, user_len)


def _function(
    raw: bytes, fields: list[Field], code: int, pos: int, src: int, dst: int, user_len: int
) -> Frame:
    known = _FUNCTIONS.get(code)
    if known is not None:
        name, semantics = known
        fields[-1] = Field("function_code", "Function code", pos - 1, 1, code, name)
        sentence = f"Sends the DNP3 {name} request to station {dst} from station {src}"
        return _finish(raw, fields, semantics, code, sentence, pos, user_len)
    if code in _RESPONSES:
        why = (
            f"function code {code} is the {_RESPONSES[code]} response, which the specification "
            "defines for an outstation to send, so the bytes after it are not placed"
        )
        sentence = f"Sends {code}, a response code, as a request"
    else:
        why = (
            f"function code {code} is reserved by the DNP3 specification, "
            "so the bytes after it are not placed"
        )
        sentence = f"Uses function code {code}, which the DNP3 specification reserves"
    return _frame(raw, fields, "anomaly", code, sentence, _after(raw, pos), why)


def _finish(
    raw: bytes,
    fields: list[Field],
    semantics: Semantics | None,
    code: int,
    sentence: str,
    pos: int,
    user_len: int,
) -> Frame:
    """Place the first block's CRC when no object bytes precede it; the rest is the tail."""
    block_end = _LINK_HEADER_LEN + min(user_len, _BLOCK)
    if pos < block_end:
        n = min(block_end, len(raw)) - pos
        why = f"{n} byte(s) of object headers and data are not decoded"
        return _frame(raw, fields, semantics, code, sentence, _after(raw, pos), why)
    if pos + 2 > len(raw):
        where = "before" if pos >= len(raw) else "inside"
        why = f"frame ends {where} the block_crc field"
        return _frame(raw, fields, semantics, code, sentence, pos, why)
    ok = _crc(raw[_LINK_HEADER_LEN:pos]) == int.from_bytes(raw[pos : pos + 2], "little")
    meaning = "CRC valid" if ok else "CRC does not match the block"
    fields.append(
        Field(
            "block_crc",
            "Data block CRC",
            pos,
            2,
            int.from_bytes(raw[pos : pos + 2], "little"),
            meaning,
        )
    )
    pos += 2
    why = "later data blocks and their CRCs are not decoded"
    return _frame(raw, fields, semantics, code, sentence, _after(raw, pos), why)


def _link_text(control: int) -> str:
    direction = "from master" if control & 0x80 else "from outstation"
    role = "primary" if control & 0x40 else "secondary"
    return f"{direction}, {role}, link function {control & 0x0F}"


def _after(raw: bytes, pos: int) -> int | None:
    return pos if pos < len(raw) else None


def _cut(raw: bytes, fields: list[Field], code: int | None, pos: int, name: str) -> Frame:
    # `pos` is where the field would start: "before" if no byte of it is present.
    where = "before" if pos >= len(raw) else "inside"
    why = f"frame ends {where} the {name} field"
    # No function code has been read on any path that reaches here.
    return _frame(raw, fields, None, code, None, pos, why)


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
        protocol="dnp3",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


DECODERS["dnp3"] = decode
