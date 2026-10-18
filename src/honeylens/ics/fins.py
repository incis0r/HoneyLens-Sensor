"""FINS decoder: the command header, the MRC/SRC pair, and the memory-area request.

The input is the FINS frame as the decoy captures it (``frame_hex``): the ten header
bytes ICF..SID, the main and sub request codes, then the command data. The FINS/TCP
transport header in front of it is not part of the stored bytes.

``Frame.code`` is the main request code (MRC); the sub request code (SRC) is needed
as well to say what the command does, so the semantics come from the pair. An ICF with
the response bit set is not a request: it is reported as an anomaly with the header
placed and the end code and data left in the tail.
"""

from __future__ import annotations

from honeylens.ics.frame import DECODERS, Field, Frame, Semantics, undecodable

_HEADER: tuple[tuple[str, str], ...] = (
    ("icf", "Information control field"),
    ("rsv", "Reserved"),
    ("gct", "Gateway count"),
    ("dna", "Destination network address"),
    ("da1", "Destination node address"),
    ("da2", "Destination unit address"),
    ("sna", "Source network address"),
    ("sa1", "Source node address"),
    ("sa2", "Source unit address"),
    ("sid", "Service ID"),
)

# (MRC, SRC) -> (name, semantics)
_COMMANDS: dict[tuple[int, int], tuple[str, Semantics]] = {
    (0x01, 0x01): ("Memory Area Read", "read"),
    (0x01, 0x02): ("Memory Area Write", "write"),
    (0x01, 0x03): ("Memory Area Fill", "write"),
    (0x01, 0x04): ("Multiple Memory Area Read", "read"),
    (0x01, 0x05): ("Memory Area Transfer", "write"),
    (0x02, 0x01): ("Parameter Area Read", "read"),
    (0x02, 0x02): ("Parameter Area Write", "write"),
    (0x02, 0x03): ("Parameter Area Clear", "write"),
    (0x03, 0x06): ("Program Area Read", "read"),
    (0x03, 0x07): ("Program Area Write", "write"),
    (0x03, 0x08): ("Program Area Clear", "write"),
    (0x04, 0x01): ("Run", "control"),
    (0x04, 0x02): ("Stop", "control"),
    (0x05, 0x01): ("Controller Data Read", "enumerate"),
    (0x05, 0x02): ("Connection Data Read", "enumerate"),
    (0x06, 0x01): ("Controller Status Read", "read"),
    (0x06, 0x20): ("Cycle Time Read", "read"),
    (0x07, 0x01): ("Clock Read", "read"),
    (0x07, 0x02): ("Clock Write", "command"),
    (0x21, 0x02): ("Error Log Read", "read"),
    (0x21, 0x03): ("Error Log Clear", "write"),
    (0x22, 0x01): ("File Name Read", "enumerate"),
    (0x22, 0x02): ("Single File Read", "read"),
    (0x22, 0x03): ("Single File Write", "write"),
    (0x22, 0x04): ("Memory Card Format", "write"),
    (0x22, 0x05): ("File Delete", "write"),
    (0x22, 0x07): ("File Copy", "write"),
    (0x22, 0x08): ("File Name Change", "write"),
    (0x23, 0x01): ("Forced Set/Reset", "write"),
    (0x23, 0x02): ("Forced Set/Reset Cancel", "write"),
}

# Memory area codes of the CS/CJ series (word designations).
_AREAS = {0x82: "DM word", 0xB0: "CIO word", 0xB1: "WR word", 0xB2: "HR word", 0xB3: "AR word"}

_MEMORY_LAYOUT: tuple[tuple[str, str, int], ...] = (
    ("memory_area", "Memory area code", 1),
    ("address", "Beginning address", 2),
    ("address_bit", "Bit position", 1),
    ("item_count", "Number of items", 2),
)


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("fins", 0, "empty frame: no FINS header")
    fields: list[Field] = []
    pos = 0
    for name, label in _HEADER:
        if pos >= len(raw):
            return _cut(raw, fields, None, None, pos, name)
        fields.append(Field(name, label, pos, 1, raw[pos], None))
        pos += 1
    if pos >= len(raw):
        return _cut(raw, fields, None, None, pos, "mrc")
    mrc = raw[pos]
    fields.append(Field("mrc", "Main request code", pos, 1, mrc, None))
    pos += 1
    if pos >= len(raw):
        return _cut(raw, fields, mrc, None, pos, "src")
    src = raw[pos]
    command = _COMMANDS.get((mrc, src))

    if raw[0] & 0x40:  # ICF bit 6: this frame is a response
        fields.append(Field("src", "Sub request code", pos, 1, src, None))
        why = (
            "the ICF marks this frame as a response, which a client does not send as a "
            "request, so the end code and data after the command codes are not placed"
        )
        sentence = f"Sends a response frame (MRC 0x{mrc:02x} SRC 0x{src:02x}) as a request"
        return _frame(raw, fields, "anomaly", mrc, sentence, _after(raw, pos + 1), why)

    fields.append(Field("src", "Sub request code", pos, 1, src, command[0] if command else None))
    pos += 1
    if command is None:
        why = (
            f"MRC 0x{mrc:02x} SRC 0x{src:02x} is not a command pair this decoder knows, "
            "so the command data is not placed"
        )
        return _frame(raw, fields, None, mrc, None, _after(raw, pos), why)

    name, semantics = command
    if (mrc, src) not in ((0x01, 0x01), (0x01, 0x02)):
        sentence = f"Sends the FINS command {name}"
        why = f"the command data of {name} is not decoded here"
        return _frame(raw, fields, semantics, mrc, sentence, _after(raw, pos), why)

    values: dict[str, int] = {}
    for fname, label, length in _MEMORY_LAYOUT:
        if pos + length > len(raw):
            return _cut(raw, fields, mrc, command, pos, fname)
        value = int.from_bytes(raw[pos : pos + length], "big")
        meaning = _AREAS.get(value) if fname == "memory_area" else None
        fields.append(Field(fname, label, pos, length, value, meaning))
        values[fname] = value
        pos += length
    area = _AREAS.get(values["memory_area"], f"area 0x{values['memory_area']:02x}")
    verb = "Reads" if semantics == "read" else "Writes"
    sentence = (
        f"{verb} {values['item_count']} item(s) "
        f"{'from' if verb == 'Reads' else 'to'} the {area} area starting at address "
        f"{values['address']}"
    )
    if pos < len(raw):
        return _frame(
            raw, fields, semantics, mrc, sentence, pos,
            f"{len(raw) - pos} byte(s) of data after the memory area fields",
        )  # fmt: skip
    return _frame(raw, fields, semantics, mrc, sentence, None, None)


def _after(raw: bytes, pos: int) -> int | None:
    return pos if pos < len(raw) else None


def _cut(
    raw: bytes,
    fields: list[Field],
    mrc: int | None,
    command: tuple[str, Semantics] | None,
    pos: int,
    name: str,
) -> Frame:
    where = "before" if pos >= len(raw) else "inside"
    why = f"frame ends {where} the {name} field"
    if mrc is None:
        return _frame(raw, fields, None, None, None, pos, why)
    if command is None:
        # The MRC was read but the sub request code was not, so the command is not known.
        return _frame(
            raw, fields, None, mrc, f"FINS command 0x{mrc:02x} (frame cut short)", pos, why
        )
    return _frame(raw, fields, command[1], mrc, f"{command[0]} (frame cut short)", pos, why)


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
        protocol="fins",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


DECODERS["fins"] = decode
