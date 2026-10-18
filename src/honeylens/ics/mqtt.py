"""MQTT decoder: the fixed header, CONNECT with its credentials withheld, and PUBLISH's topic.

The input is a complete MQTT control packet: the type and flags byte, the remaining
length, then the variable header and payload.

Credentials: the username and password fields are placed (so their byte ranges can be
masked) but their value is the constant ``"<redacted>"``; the bytes never reach a Field.
A CONNECT whose layout cannot be confirmed (an unknown protocol name or level) leaves
everything after that point in the tail, and the credentials with it; a consumer that
emits the hex must therefore mask from the tail onward for packet type 1; ``mask_hex``
below does exactly that, and is what ``honeylens.ics.mask_hex`` dispatches to.

A packet type that carries a version-dependent layout (SUBSCRIBE filters, the PUBLISH
payload) is placed only as far as the version-independent bytes reach, because those
packets do not carry the protocol version.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from honeylens.ics.frame import DECODERS, MASKERS, Field, Frame, Semantics, undecodable

REDACTED = "<redacted>"
_TEXT_BUDGET = 64


def _clip(text: str) -> str:
    """Attacker-controlled text interpolated into a sentence is cut to a fixed budget."""
    return text if len(text) <= _TEXT_BUDGET else text[:_TEXT_BUDGET] + "..."


_TYPES = {
    0: "Reserved",
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
}
_SEMANTICS: dict[int, Semantics | None] = {1: "enumerate", 3: "write", 8: "read"}
# Packets only a server sends: a client sending one is out of specification.
_SERVER_ONLY = {2, 9, 11, 13}

_SENTENCES = {
    8: "Subscribes to topics",
    10: "Removes topic subscriptions",
    12: "Sends a keep-alive ping",
    14: "Ends its MQTT session",
}
_PROTOCOLS = {(b"MQTT", 4), (b"MQTT", 5), (b"MQIsdp", 3)}


class _Stop(Exception):
    """The packet ends before a field is complete."""

    def __init__(self, name: str, where: str) -> None:
        super().__init__(name)
        self.name = name
        self.where = where


class _Reader:
    def __init__(self, raw: bytes, pos: int, end: int) -> None:
        self.raw, self.pos, self.end = raw, pos, end
        self.fields: list[Field] = []

    def _need(self, n: int, name: str, started: bool = False) -> None:
        if self.pos + n > self.end:
            where = "inside" if started or self.pos < self.end else "before"
            raise _Stop(name, where)

    def peek(self, name: str) -> int:
        self._need(1, name)
        return self.raw[self.pos]

    def uint(self, name: str, label: str, n: int, meaning: str | None = None) -> int:
        self._need(n, name)
        value = int.from_bytes(self.raw[self.pos : self.pos + n], "big")
        self.fields.append(Field(name, label, self.pos, n, value, meaning))
        self.pos += n
        return value

    def varint_bytes(
        self, name: str, label: str, scrub: Callable[[bytes], bytes] | None = None
    ) -> bytes:
        """A variable-length integer followed by that many bytes; one hex-valued field."""
        start, pos, size, shift = self.pos, self.pos, 0, 0
        while True:
            if pos >= self.end:
                raise _Stop(name, "inside" if pos > start else "before")
            byte = self.raw[pos]
            pos += 1
            size |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80 or shift > 21:
                break
        if pos + size > self.end:
            raise _Stop(name, "inside")
        body = self.raw[pos : pos + size]
        shown = scrub(body) if scrub else body
        self.fields.append(Field(name, label, start, pos + size - start, shown.hex(), None))
        self.pos = pos + size
        return body

    def prefixed(self, name: str, label: str, kind: str) -> bytes:
        """A two-byte length then that many bytes. kind: 'str', 'hex' or 'redact'."""
        self._need(2, name)
        length = int.from_bytes(self.raw[self.pos : self.pos + 2], "big")
        self._need(2 + length, name, started=True)
        body = self.raw[self.pos + 2 : self.pos + 2 + length]
        value = {
            "str": body.decode("utf-8", "replace"),
            "hex": body.hex(),
            "redact": REDACTED,
            # Only the two real names are shown: a mis-framed length can swallow credentials.
            "name": body.decode("ascii") if body in (b"MQTT", b"MQIsdp") else REDACTED,
        }
        self.fields.append(Field(name, label, self.pos, 2 + length, value[kind], None))
        self.pos += 2 + length
        return body


def decode(raw: bytes) -> Frame:
    if not raw:
        return undecodable("mqtt", 0, "empty frame: no fixed header")
    ptype, flags = raw[0] >> 4, raw[0] & 0x0F
    name = _TYPES[ptype]
    qos = (flags >> 1) & 3
    meaning = name
    if ptype == 3:
        meaning = f"PUBLISH (QoS {qos}{', retain' if flags & 1 else ''})"
    fields = [Field("packet_type", "Packet type", 0, 1, ptype, meaning)]
    semantics: Semantics | None = _SEMANTICS.get(ptype)
    # Decided from byte 0, before the remaining length: a one-byte probe is still out of spec.
    if ptype == 0 or ptype in _SERVER_ONLY or (ptype == 3 and qos == 3):
        semantics = "anomaly"

    # Remaining length: one to four bytes, seven bits each.
    pos, remaining, shift = 1, 0, 0
    while True:
        if pos >= len(raw):
            where = "inside" if pos > 1 else "before"
            return _cut(raw, fields, ptype, semantics, 1, "remaining_length", where)
        byte = raw[pos]
        remaining |= (byte & 0x7F) << shift
        pos += 1
        shift += 7
        if not byte & 0x80:
            break
        if pos == 5:  # a fourth byte that still asks for more
            fields.append(Field("remaining_length", "Remaining length", 1, 4, remaining, None))
            why = "the remaining length does not end within four bytes, which the specification forbids"
            return _frame(raw, fields, "anomaly", ptype, _sentence(ptype, {}), _after(raw, 5), why)
    fields.append(Field("remaining_length", "Remaining length", 1, pos - 1, remaining, None))
    end = min(len(raw), pos + remaining)
    outer: tuple[int, str] | None = None
    if end < len(raw):
        outer = (end, f"{len(raw) - end} byte(s) after the remaining length of {remaining}")

    if ptype == 0:
        why = "packet type 0 is reserved by the MQTT specification"
        return _frame(
            raw, fields, "anomaly", 0, "Sends the reserved packet type 0", _after(raw, pos), why
        )
    if ptype in _SERVER_ONLY:
        sentence = f"Sends a {name} packet, which only a server sends"
        why = f"{name} is a server-to-client packet, so its layout as a request is not decoded"
        return _frame(raw, fields, "anomaly", ptype, sentence, _after(raw, pos), why)
    if ptype == 3 and qos == 3:
        why = "QoS 3 is not defined by the MQTT specification, so the bytes after it are not placed"
        return _frame(
            raw, fields, "anomaly", 3, "Publishes with the undefined QoS 3", _after(raw, pos), why
        )

    reader = _Reader(raw, pos, end)
    reader.fields = fields
    try:
        if ptype == 1:
            return _connect(raw, reader, semantics, outer)
        if ptype == 3:
            return _publish(raw, reader, semantics, qos, outer)
        if ptype == 8:
            reader.uint("packet_identifier", "Packet identifier", 2)
            why = (
                "the topic filters are not placed: their layout depends on the MQTT version, "
                "which a SUBSCRIBE does not carry"
            )
            return _frame(
                raw, reader.fields, semantics, 8, _SENTENCES[8], _after(raw, reader.pos), why
            )
    except _Stop as stop:
        if ptype == 1:
            _withhold_swallowed(reader.fields)
        return _cut(raw, reader.fields, ptype, semantics, reader.pos, stop.name, stop.where)

    sentence = _SENTENCES.get(ptype) or (
        "Sends an AUTH packet (reserved before MQTT 5)" if ptype == 15 else f"Sends a {name} packet"
    )
    if reader.pos < end:
        why = f"the variable header and payload of {name} are not decoded here"
        return _frame(raw, reader.fields, semantics, ptype, sentence, reader.pos, why)
    return _frame(raw, reader.fields, semantics, ptype, sentence, None, None, outer)


def _connect(
    raw: bytes, r: _Reader, semantics: Semantics | None, outer: tuple[int, str] | None
) -> Frame:
    proto = r.prefixed("protocol_name", "Protocol name", "name")
    level_at = r.pos
    level = r.uint("protocol_level", "Protocol level", 1)
    if (proto, level) not in _PROTOCOLS:
        if proto not in (b"MQTT", b"MQIsdp"):
            r.fields.pop()  # the level byte is not confirmed either
            r.pos = level_at
            why = (
                f"protocol name of {len(proto)} byte(s) is not MQTT or MQIsdp, so the "
                "rest of the CONNECT layout is not applied"
            )
        else:
            why = f"protocol level {level} is not one of 3, 4 or 5 for {proto.decode()}, so the rest of the CONNECT layout is not applied"
        return _frame(raw, r.fields, semantics, 1, "Opens an MQTT session", _after(raw, r.pos), why)
    flags = r.uint("connect_flags", "Connect flags", 1, _flag_text(r.peek("connect_flags")))
    r.uint("keep_alive", "Keep alive (seconds)", 2)
    if level == 5:
        r.varint_bytes("properties", "Properties", _scrub_properties)
    client = r.prefixed("client_id", "Client ID", "str").decode("utf-8", "replace")
    if flags & 0x04:
        if level == 5:
            r.varint_bytes("will_properties", "Will properties", _scrub_properties)
        r.prefixed("will_topic", "Will topic", "str")
        r.prefixed("will_message", "Will message", "hex")
    if flags & 0x80:
        r.prefixed("username", "Username (value withheld)", "redact")
    if flags & 0x40:
        r.prefixed("password", "Password (value withheld)", "redact")
    both = flags & 0xC0 == 0xC0
    sentence = f"Opens an MQTT session as client {_clip(client)!r}"
    if both:
        sentence += " with a username and password"
    elif flags & 0xC0:
        sentence += " with a username" if flags & 0x80 else " with a password"
    if r.pos < r.end:
        why = f"{r.end - r.pos} byte(s) after the CONNECT payload"
        return _frame(raw, r.fields, semantics, 1, sentence, r.pos, why)
    return _frame(raw, r.fields, semantics, 1, sentence, None, None, outer)


def _withhold_swallowed(fields: list[Field]) -> None:
    """A CONNECT cut short may have had a length prefix that swallowed the credentials.

    The client id and will values placed before the cut are then unverified, so their
    values are withheld (offset and length stay).
    """
    for i, f in enumerate(fields):
        if f.name in ("client_id", "will_topic", "will_message"):
            fields[i] = dataclasses.replace(f, value=REDACTED)


def _flag_text(flags: int) -> str:
    parts = []
    if flags & 0x02:
        parts.append("clean session")
    if flags & 0x04:
        parts.append("will")
    if flags & 0x80:
        parts.append("username")
    if flags & 0x40:
        parts.append("password")
    return ", ".join(parts) or "no flags"


def _publish(
    raw: bytes, r: _Reader, semantics: Semantics | None, qos: int, outer: tuple[int, str] | None
) -> Frame:
    topic = r.prefixed("topic", "Topic name", "str").decode("utf-8", "replace")
    if qos:
        r.uint("packet_identifier", "Packet identifier", 2)
    sentence = f"Publishes to topic {_clip(topic)!r}"
    if r.pos < r.end:
        why = (
            "the PUBLISH payload is not placed: it follows MQTT 5 properties on a "
            "version-5 connection, and a PUBLISH does not carry the version"
        )
        return _frame(raw, r.fields, semantics, 3, sentence, r.pos, why)
    return _frame(raw, r.fields, semantics, 3, sentence, None, None, outer)


def _sentence(ptype: int, _: dict[str, int]) -> str:
    return _SENTENCES.get(ptype) or f"Sends a {_TYPES[ptype]} packet"


def _after(raw: bytes, pos: int) -> int | None:
    return pos if pos < len(raw) else None


def _cut(
    raw: bytes,
    fields: list[Field],
    ptype: int,
    semantics: Semantics | None,
    pos: int,
    name: str,
    where: str,
) -> Frame:
    why = f"frame ends {where} the {name} field of a {_TYPES[ptype]} packet"
    # The packet type was read from byte 0, so the sentence can name it.
    return _frame(raw, fields, semantics, ptype, f"{_TYPES[ptype]} (frame cut short)", pos, why)


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
        protocol="mqtt",
        raw_len=len(raw),
        fields=tuple(fields),
        semantics=semantics,
        code=code,
        sentence=sentence,
        tail_offset=tail_offset,
        tail_reason=tail_reason,
        truncated=False,
    )


_PROP_FIXED = {
    **dict.fromkeys((0x01, 0x17, 0x19, 0x24, 0x25, 0x28, 0x29, 0x2A), 1),
    **dict.fromkeys((0x13, 0x21, 0x22, 0x23), 2),
    **dict.fromkeys((0x02, 0x11, 0x18, 0x27), 4),
}
_PROP_STRING = {0x03, 0x08, 0x12, 0x15, 0x1A, 0x1C, 0x1F}
_PROP_BINARY = {0x09, 0x16}
_PROP_KEEP = 0x15  # authentication method: a mechanism name such as PLAIN, not a secret


def _scrub_properties(body: bytes) -> bytes:
    """An MQTT 5 property list with every value zeroed except the authentication method.

    0x16 is Authentication Data, which is the password of the enhanced-authentication flow.
    Anything this parser cannot walk to the end is zeroed whole: fail closed.
    """
    out = bytearray(len(body))
    i = 0
    try:
        while i < len(body):
            pid, start = body[i], i
            i += 1
            if pid in _PROP_FIXED:
                i += _PROP_FIXED[pid]
            elif pid in _PROP_STRING or pid in _PROP_BINARY:
                i += 2 + int.from_bytes(body[i : i + 2], "big")
            elif pid == 0x0B:
                while body[i] & 0x80:
                    i += 1
                i += 1
            elif pid == 0x26:
                for _ in range(2):
                    i += 2 + int.from_bytes(body[i : i + 2], "big")
            else:
                return bytes(len(body))
            if i > len(body):
                return bytes(len(body))
            if pid == _PROP_KEEP:
                out[start:i] = body[start:i]
    except IndexError:
        return bytes(len(body))
    return bytes(out)


def _varint_bytes(n: int) -> bytes:
    out = bytearray()
    while True:
        byte, n = n & 0x7F, n >> 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


_ALWAYS_KEPT = ("packet_type", "remaining_length")
_FRAMING = ("protocol_name", "protocol_level", "connect_flags", "keep_alive")
_AFTER_CLIENT = ("client_id", "will_topic", "will_message")
_PROPERTY_BLOBS = ("properties", "will_properties")


def _varint_header(packet: bytes, start: int, end: int) -> tuple[int, int] | None:
    """Where a varint-prefixed blob's body starts, by exactly the reader's rules.

    The same break condition as ``_Reader.varint_bytes`` (a clear continuation bit, or the
    fourth byte). Returns (body_start, size) only if the prefix stays inside the field and
    ``body_start + size == end``; None on any disagreement, so the caller keeps nothing.
    """
    pos, size, shift = start, 0, 0
    while True:
        if pos >= end:
            return None
        byte = packet[pos]
        pos += 1
        size |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80 or shift > 21:
            break
    if pos + size != end:
        return None
    return pos, size


def _mask_connect(packet: bytes) -> bytes:
    """A full CONNECT packet with everything zeroed except positively identified bytes.

    Kept: the fixed header; and, only when the protocol name is exactly MQTT or MQIsdp, the
    name, level, flags and keep-alive; the property lists with only the authentication
    method left in; and client id and will, only when every credential field the flags
    promise was placed (otherwise a mis-framed length may have swallowed them). Each
    credential keeps its 2-byte length prefix and has its body zeroed, so the masked bytes
    decode to the same layout; anything unplaced and anything after the packet is zeroed.
    """
    try:
        frame = decode(packet)
    except Exception:
        return bytes(len(packet))
    by = {f.name: f for f in frame.fields}
    out = bytearray(len(packet))
    keep: list[tuple[int, int]] = [(0, 1)]
    if "remaining_length" in by:
        rl = by["remaining_length"]
        keep.append((rl.offset, rl.offset + rl.length))
    name = by.get("protocol_name")
    if name is None or packet[name.offset + 2 : name.offset + name.length] not in (
        b"MQTT",
        b"MQIsdp",
    ):
        return _apply(packet, out, keep)
    flags_field = by.get("connect_flags")
    flags = flags_field.value if flags_field and isinstance(flags_field.value, int) else None
    complete = (
        flags is not None
        and (not flags & 0x80 or "username" in by)
        and (not flags & 0x40 or "password" in by)
    )
    for n in _FRAMING + (_AFTER_CLIENT if complete else ()):
        if n in by:
            keep.append((by[n].offset, by[n].offset + by[n].length))
    if complete:
        # The 2-byte length prefix of each credential stays so the masked bytes re-decode to
        # the same layout (a zeroed prefix collapses the field and fabricates a tail). The
        # prefix reveals only how long a credential was, never a byte of it.
        for n in ("username", "password"):
            if n in by:
                keep.append((by[n].offset, by[n].offset + 2))
    _apply(packet, out, keep)
    for n in _PROPERTY_BLOBS:
        f = by.get(n)
        if f is None:
            continue
        end = f.offset + f.length
        header = _varint_header(packet, f.offset, end)
        if header is None:
            continue  # the reader and this walk disagree: the blob stays zeroed
        body_start = header[0]
        out[f.offset : body_start] = packet[f.offset : body_start]
        out[body_start:end] = _scrub_properties(packet[body_start:end])
    return bytes(out)


def _apply(packet: bytes, out: bytearray, keep: list[tuple[int, int]]) -> bytes:
    for start, end in keep:
        out[start:end] = packet[start:end]
    return bytes(out)


def _is_confirmed_other_packet(raw: bytes) -> bool:
    """True only when raw is a whole fixed-header packet, its length exact, positively of a non-CONNECT type."""
    ptype = raw[0] >> 4
    if ptype in (0, 1):
        return False
    try:
        frame = decode(raw)
    except Exception:
        return False
    rl = next((f for f in frame.fields if f.name == "remaining_length"), None)
    if rl is None or frame.code != ptype:
        return False
    return 1 + rl.length + int(rl.value) == len(raw)


def mask_hex(raw: bytes, pkt_type: int | None = None) -> bytes:
    """The bytes with credential bytes zeroed; same length, so offsets still line up.

    Two shapes are stored. The decoy (hp_mqtt) keeps only the *body* after the fixed header,
    so every historical row is headerless and starts with the protocol-name length
    (``00 04 "MQTT"``, ``00 06 "MQIsdp"``); a full packet starts with its type nibble. A
    headerless CONNECT body is wrapped in a synthetic fixed header, masked as a packet, and
    unwrapped. Username and password bodies are zeroed (length prefixes stay); a CONNECT
    that stopped early (unknown protocol, cut short) is zeroed from its tail on.

    Order matters. (1) Bytes shaped like a CONNECT, headerless or full, are masked whatever
    the hint says: credentials live in CONNECT bodies, and the hint is only the wire byte of
    the row. (2) Otherwise a hint naming a packet type 2..15 lets the bytes through (an HTTP
    probe stored under type 4 stays readable). (3) Otherwise fail closed: anything not
    positively a complete packet of another type is zeroed entirely.
    """
    if not raw:
        return raw
    for name in (b"MQTT", b"MQIsdp"):
        if raw[:2] == len(name).to_bytes(2, "big") and raw[2 : 2 + len(name)] == name:
            header = b"\x10" + _varint_bytes(len(raw))
            return _mask_connect(header + raw)[len(header) :]
    if raw[0] >> 4 == 1:
        return _mask_connect(raw)
    if isinstance(pkt_type, int) and not isinstance(pkt_type, bool) and 2 <= pkt_type <= 15:
        return raw
    if _is_confirmed_other_packet(raw):
        return raw
    return bytes(len(raw))


DECODERS["mqtt"] = decode
MASKERS["mqtt"] = mask_hex
