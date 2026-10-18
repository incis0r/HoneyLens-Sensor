"""PROFINET decoder: the connectionless DCE/RPC header of a UDP datagram, and the opnum.

PROFINET IO context management runs as DCE/RPC over UDP. The datagram starts with an
80-byte header (version 4); the operation number (opnum) is at byte 68, in the byte order
that the header's data representation (byte 4, bit 4) declares. The opnum only has a PROFINET
meaning on the PROFINET IO device interface (DEA00001-6C97-11D1-8271-00A02442DF7D), so the
interface UUID is read first and any other interface leaves the semantics unset.

The PNIO request body (NDR blocks) is not decoded; it stays in the tail.
"""

from __future__ import annotations

from honeylens.ics.frame import DECODERS, Field, Frame, Semantics, undecodable

_PNIO_DEVICE = "dea00001-6c97-11d1-8271-00a02442df7d"
_INTERFACES = {_PNIO_DEVICE: "PROFINET IO device interface"}

_PACKET_TYPES = {
    0: "request",
    1: "ping",
    2: "response",
    3: "fault",
    4: "working",
    5: "nocall",
    6: "reject",
    7: "ack",
    8: "cancel",
    9: "fack",
    10: "cancel_ack",
}
_CONNECTION_ORIENTED = range(11, 20)

# opnum on the PROFINET IO device interface -> (name, semantics)
_OPNUMS: dict[int, tuple[str, Semantics | None]] = {
    0: ("Connect", None),
    1: ("Release", None),
    2: ("Read", "read"),
    3: ("Write", "write"),
    4: ("Control", "control"),
    5: ("ReadImplicit", "enumerate"),
}
_SENTENCES = {
    0: "Opens a PROFINET IO connection (Connect)",
    1: "Closes a PROFINET IO connection (Release)",
    2: "Sends a PROFINET IO Read request",
    3: "Sends a PROFINET IO Write request",
    4: "Sends a PROFINET IO Control request",
    5: "Reads the device's identity without a connection (ReadImplicit)",
}

# (name, label, length, kind). kind: u integer in the declared byte order, h hex, g uuid.
_HEADER: tuple[tuple[str, str, int, str], ...] = (
    ("rpc_version", "RPC version", 1, "b"),
    ("packet_type", "Packet type", 1, "b"),
    ("flags1", "Flags 1", 1, "b"),
    ("flags2", "Flags 2", 1, "b"),
    ("drep", "Data representation", 3, "h"),
    ("serial_high", "Serial number (high)", 1, "b"),
    ("object_uuid", "Object UUID", 16, "g"),
    ("interface_uuid", "Interface UUID", 16, "g"),
    ("activity_uuid", "Activity UUID", 16, "g"),
    ("server_boot", "Server boot time", 4, "u"),
    ("interface_version", "Interface version", 4, "u"),
    ("sequence_number", "Sequence number", 4, "u"),
    ("opnum", "Operation number", 2, "u"),
    ("interface_hint", "Interface hint", 2, "u"),
    ("activity_hint", "Activity hint", 2, "u"),
    ("body_length", "Body length", 2, "u"),
    ("fragment_number", "Fragment number", 2, "u"),
    ("auth_proto", "Authentication protocol", 1, "b"),
    ("serial_low", "Serial number (low)", 1, "b"),
)


def _uuid(chunk: bytes, little: bool) -> str:
    if little:  # the first three groups are stored in the declared byte order
        chunk = chunk[3::-1] + chunk[5:3:-1] + chunk[7:5:-1] + chunk[8:]
    h = chunk.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("profinet", 0, "empty frame: no DCE/RPC header")
    if raw[0] != 4:
        return undecodable(
            "profinet",
            len(raw),
            f"the first byte is RPC version {raw[0]}, not the connectionless version 4, "
            "so no DCE/RPC header is applied",
        )
    fields: list[Field] = []
    values: dict[str, int | str] = {}
    little = True  # the data representation is byte 4; it is known before any integer is read
    pos = 0
    for name, label, length, kind in _HEADER:
        if pos + length > len(raw):
            return _cut(raw, fields, values, pos, name)
        chunk = raw[pos : pos + length]
        value: int | str
        if kind == "h":
            value = chunk.hex()
            little = bool(chunk[0] & 0x10)
        elif kind == "g":
            value = _uuid(chunk, little)
        elif kind == "u":
            value = int.from_bytes(chunk, "little" if little else "big")
        else:
            value = chunk[0]
        meaning = None
        if name == "packet_type":
            meaning = _PACKET_TYPES.get(int(value))
        elif name == "interface_uuid":
            meaning = _INTERFACES.get(str(value))
        elif name == "opnum" and values.get("interface_uuid") == _PNIO_DEVICE:
            known = _OPNUMS.get(int(value))
            meaning = known[0] if known else None
        fields.append(Field(name, label, pos, length, value, meaning))
        values[name] = value
        pos += length
    return _classify(raw, fields, values, pos)


def _classify(raw: bytes, fields: list[Field], values: dict[str, int | str], pos: int) -> Frame:
    ptype = int(values["packet_type"])
    tail = pos if pos < len(raw) else None
    body = f"{len(raw) - pos} byte(s) of request body are not decoded"
    if ptype in _CONNECTION_ORIENTED:
        why = f"packet type {ptype} is a connection-oriented type, which is not defined for datagram DCE/RPC"
        sentence = f"Sends connection-oriented packet type {ptype} in a datagram"
        return _frame(raw, fields, "anomaly", None, sentence, tail, why)
    if ptype not in _PACKET_TYPES:
        why = f"packet type {ptype} is not defined by DCE/RPC"
        return _frame(
            raw, fields, "anomaly", None, f"Uses undefined packet type {ptype}", tail, why
        )
    if ptype != 0:
        name = _PACKET_TYPES[ptype]
        why = f"a {name} packet is defined by DCE/RPC but its body is not decoded here"
        return _frame(raw, fields, None, None, f"Sends a {name} packet", tail, why)

    interface = str(values["interface_uuid"])
    opnum = int(values["opnum"])
    if interface != _PNIO_DEVICE:
        why = (
            f"interface {interface} is not the PROFINET IO device interface, so opnum {opnum} "
            "has no meaning here and the body is not placed"
        )
        sentence = f"Calls operation {opnum} on interface {interface}"
        return _frame(raw, fields, None, None, sentence, tail, why)
    known = _OPNUMS.get(opnum)
    if known is None:
        why = f"opnum {opnum} is not defined for the PROFINET IO device interface, so the body is not placed"
        sentence = f"Uses opnum {opnum}, which the PROFINET IO device interface does not define"
        return _frame(raw, fields, "anomaly", opnum, sentence, tail, why)
    return _frame(raw, fields, known[1], opnum, _SENTENCES[opnum], tail, body)


def _cut(
    raw: bytes, fields: list[Field], values: dict[str, int | str], pos: int, name: str
) -> Frame:
    where = "before" if pos >= len(raw) else "inside"
    why = f"frame ends {where} the {name} field"
    # The opnum is known once it has been read; its meaning also needs a request on the
    # PNIO interface, both of which precede it in the header.
    if (
        "opnum" in values
        and values.get("packet_type") == 0
        and values.get("interface_uuid") == _PNIO_DEVICE
    ):
        known = _OPNUMS.get(int(values["opnum"]))
        if known is not None:
            return _frame(
                raw,
                fields,
                known[1],
                int(values["opnum"]),
                f"{known[0]} (frame cut short)",
                pos,
                why,
            )
    return _frame(raw, fields, None, None, None, pos, why)


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
        protocol="profinet",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


DECODERS["profinet"] = decode
