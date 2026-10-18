"""IEC 60870-5-104 decoder: the ASDU header, the first information object, and what it commands.

The input is either a bare ASDU or a full APCI frame (0x68, length, four control
bytes, then the ASDU); the store holds both. A type id the standard does not
assign is reported with semantics None, not 'anomaly': unassigned is not illegal.
Only the first information object is decoded; later objects stay in the tail.
"""

from __future__ import annotations

import struct

from honeylens.ics.frame import DECODERS, Field, Frame, Semantics, undecodable

# type id -> (name, semantics, element layout after the IOA)
# Layout items are (field name, label, length, kind); kind: u unsigned, s signed, f float, h hex.
_Elem = tuple[tuple[str, str, int, str], ...]

_SCO: _Elem = (("sco", "Single command qualifier", 1, "u"),)
_DCO: _Elem = (("dco", "Double command qualifier", 1, "u"),)
_RCO: _Elem = (("rco", "Regulating step command qualifier", 1, "u"),)
_QOS: tuple[str, str, int, str] = ("qos", "Set-point qualifier", 1, "u")

_COMMANDS: dict[int, tuple[str, Semantics, _Elem]] = {
    45: ("C_SC_NA_1 Single Command", "command", _SCO),
    46: ("C_DC_NA_1 Double Command", "command", _DCO),
    47: ("C_RC_NA_1 Regulating Step Command", "command", _RCO),
    48: (
        "C_SE_NA_1 Set-point, normalized",
        "command",
        (("value", "Normalized value", 2, "s"), _QOS),
    ),
    49: ("C_SE_NB_1 Set-point, scaled", "command", (("value", "Scaled value", 2, "s"), _QOS)),
    50: ("C_SE_NC_1 Set-point, short float", "command", (("value", "Float value", 4, "f"), _QOS)),
    51: ("C_BO_NA_1 Bitstring command", "command", (("value", "Bitstring", 4, "h"),)),
    100: ("C_IC_NA_1 Interrogation", "enumerate", (("qoi", "Interrogation qualifier", 1, "u"),)),
    101: (
        "C_CI_NA_1 Counter interrogation",
        "enumerate",
        (("qcc", "Counter interrogation qualifier", 1, "u"),),
    ),
    102: ("C_RD_NA_1 Read", "enumerate", ()),
    103: ("C_CS_NA_1 Clock synchronization", "command", (("time", "CP56Time2a", 7, "h"),)),
    105: ("C_RP_NA_1 Reset process", "control", (("qrp", "Reset process qualifier", 1, "u"),)),
}

_MONITOR_NAMES = {
    1: "M_SP_NA_1 Single-point",
    3: "M_DP_NA_1 Double-point",
    5: "M_ST_NA_1 Step position",
    7: "M_BO_NA_1 Bitstring",
    9: "M_ME_NA_1 Measured value, normalized",
    11: "M_ME_NB_1 Measured value, scaled",
    13: "M_ME_NC_1 Measured value, short float",
    15: "M_IT_NA_1 Integrated totals",
}

_CAUSES = {
    1: "Periodic",
    2: "Background scan",
    3: "Spontaneous",
    4: "Initialized",
    5: "Request",
    6: "Activation",
    7: "Activation confirmation",
    8: "Deactivation",
    9: "Deactivation confirmation",
    10: "Activation termination",
    20: "Interrogated by station",
}

_HEADER: tuple[tuple[str, str, int], ...] = (
    ("type_id", "Type identification", 1),
    ("vsq", "Variable structure qualifier", 1),
    ("cot", "Cause of transmission", 1),
    ("originator", "Originator address", 1),
    ("common_address", "Common address", 2),
    ("ioa", "Information object address", 3),
)
_APCI = 6


def _int(chunk: bytes, kind: str) -> int | str:
    if kind == "h":
        return chunk.hex()
    if kind == "f":
        return str(struct.unpack("<f", chunk)[0])
    return int.from_bytes(chunk, "little", signed=(kind == "s"))


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("iec104", 0, "empty frame: no type identification")
    fields: list[Field] = []
    base = 0
    end = len(raw)
    outer_tail: tuple[int, str] | None = None
    # 0x68 with a plausible APCI length byte starts an APCI frame; a bare ASDU of
    # type 104 (test command) has a variable-structure byte below 4 here.
    if raw[0] == 0x68 and len(raw) >= 2 and raw[1] >= 4:
        fields.append(Field("apci_length", "APCI length", 1, 1, raw[1], None))
        if len(raw) < _APCI:
            return _frame(
                raw, fields, None, None, None, 2, "frame ends inside the APCI control field"
            )
        fields.append(Field("control_field", "APCI control field", 2, 4, raw[2:6].hex(), None))
        base = _APCI
        end = min(len(raw), 2 + raw[1])
        if end < len(raw):
            outer_tail = (end, f"{len(raw) - end} byte(s) after the APCI length of {raw[1]}")
        if end == base and raw[1] == 4:
            kind = "U" if raw[2] & 3 == 3 else "S" if raw[2] & 3 == 1 else "I"
            why = f"{kind}-format APCI frame without an ASDU"
            return _frame(raw, fields, None, None, why, None, None)

    pos = base
    values: dict[str, int | str] = {}
    cut_name = ""
    for name, label, length in _HEADER:
        if pos + length > end:
            cut_name = name
            break
        value = int.from_bytes(raw[pos : pos + length], "little")
        meaning = None
        if name == "cot":
            meaning = _CAUSES.get(value & 0x3F)
        fields.append(Field(name, label, pos, length, value, meaning))
        values[name] = value
        pos += length
        if name == "type_id":
            type_id = value
            spec = _COMMANDS.get(type_id)
            if spec is not None:
                fields[-1] = Field(name, label, pos - 1, 1, value, spec[0])
            elif 1 <= type_id <= 40:
                monitor = _MONITOR_NAMES.get(type_id)
                fields[-1] = Field(name, label, pos - 1, 1, value, monitor)
        if name == "common_address" and values["type_id"] not in _COMMANDS:
            # IOA layout is only trusted for the types decoded here.
            if not 1 <= int(values["type_id"]) <= 40:
                break
    code = int(values["type_id"]) if "type_id" in values else None
    if cut_name:
        return _cut(raw, fields, code, pos, f"frame ends before the {cut_name} field", outer_tail)

    type_id = int(values["type_id"])
    spec = _COMMANDS.get(type_id)
    if spec is None and not 1 <= type_id <= 40:
        why = f"type identification {type_id} is not one this decoder knows, so the bytes after the common address are not placed"
        return _frame(raw, fields, None, type_id, None, pos if pos < end else None, why, outer_tail)

    ioa = values["ioa"]
    station = values["common_address"]
    if spec is None:
        mname = _MONITOR_NAMES.get(type_id, f"type {type_id}")
        sentence = f"Monitor-direction data ({mname}) at object {ioa} on station {station}"
        tail = pos if pos < end else None
        undecoded = (
            f"the information element layout of type {type_id} is not decoded here"
            if tail is not None
            else None
        )
        return _frame(raw, fields, "read", type_id, sentence, tail, undecoded, outer_tail)

    title, semantics, layout = spec
    for name, label, length, kind in layout:
        if pos + length > end:
            sentence = f"{title.split(' ', 1)[0]} (frame cut short)"  # same rule as _cut: a type id was read
            where = "before" if pos >= end else "inside"
            return _frame(
                raw, fields, semantics, type_id, sentence, pos,
                f"frame ends {where} the {name} field of type {type_id} ({title})", outer_tail,
            )  # fmt: skip
        element = _int(raw[pos : pos + length], kind)
        fields.append(Field(name, label, pos, length, element, None))
        values[name] = element
        pos += length
    sentence = _sentence(type_id, values)
    if pos < end:
        return _frame(
            raw, fields, semantics, type_id, sentence, pos,
            f"{end - pos} byte(s) after the first information object of type {type_id}", outer_tail,
        )  # fmt: skip
    return _frame(raw, fields, semantics, type_id, sentence, None, None, outer_tail)


def _sentence(type_id: int, v: dict[str, int | str]) -> str:
    ioa, station = v["ioa"], v["common_address"]
    target = f"output {ioa} on station {station}"
    if type_id in (45, 46, 47):
        q = int(v[{45: "sco", 46: "dco", 47: "rco"}[type_id]])
        select = "select (arm, do not execute) " if q & 0x80 else ""
        state = q & 3 if type_id != 45 else q & 1
        if type_id == 45:
            act = "switch on" if state else "switch off"
        elif type_id == 46:
            act = {1: "switch off", 2: "switch on"}.get(state, "send an invalid state to")
        else:
            act = {1: "step down", 2: "step up"}.get(state, "send an invalid step to")
        return f"{select}{act} {target}"
    if type_id in (48, 49, 50):
        return f"set {target} to {v['value']}"
    if type_id == 51:
        return f"write bitstring {v['value']} to {target}"
    if type_id == 100:
        return f"ask station {station} for all its current data (general interrogation)"
    if type_id == 101:
        return f"ask station {station} for its counter values"
    if type_id == 102:
        return f"read object {ioa} on station {station}"
    if type_id == 103:
        return f"set the clock of station {station}"
    return f"reset the process on station {station}"


def _cut(
    raw: bytes,
    fields: list[Field],
    code: int | None,
    pos: int,
    why: str,
    outer: tuple[int, str] | None,
) -> Frame:
    # The type id was read, so what the frame means is known even though it is cut short.
    spec = _COMMANDS.get(code) if code is not None else None
    semantics: Semantics | None = (
        spec[1] if spec else ("read" if code and 1 <= code <= 40 else None)
    )
    # Rule: a cut-short frame carries a sentence if and only if a type id was read
    # from its bytes. Without one nothing true can be said, so the sentence is None
    # (as it is when the cut falls inside the APCI control field).
    if code is None:
        return _frame(raw, fields, semantics, code, None, pos, why, outer)
    label = spec[0].split(" ", 1)[0] if spec else f"type {code}"
    return _frame(raw, fields, semantics, code, f"{label} (frame cut short)", pos, why, outer)


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
        protocol="iec104",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


DECODERS["iec104"] = decode
