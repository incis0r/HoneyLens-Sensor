"""The frame contract: what a decoder says about captured bytes, and the registry.

Imports nothing from honeylens.ingest, honeylens.routes or honeylens.webui:
the first two import this package.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from honeylens.honeypots.body_capture import MAX_RAW_EVENT_BYTES

Semantics = Literal["read", "enumerate", "discovery", "write", "command", "control", "anomaly"]

# The seven values, in the order the screen shows them.
SEMANTICS: tuple[str, ...] = (
    "read",
    "enumerate",
    "discovery",
    "write",
    "command",
    "control",
    "anomaly",
)

log = logging.getLogger(__name__)
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+")


@dataclass(frozen=True)
class Field:
    name: str  # "type_id"
    label: str  # "Type identification" - what the screen shows
    offset: int
    length: int
    value: int | str
    meaning: str | None  # "C_SC_NA_1 Single Command"; None when the value speaks for itself


@dataclass(frozen=True)
class Frame:
    protocol: str
    raw_len: int
    fields: tuple[Field, ...]
    # None: decodes, but the code is not in the specification.
    # "anomaly": the code is out of specification.
    semantics: Semantics | None
    code: int | None
    sentence: str | None  # one plain-language line for the OT reader
    tail_offset: int | None  # first byte not placed; None when fully placed
    tail_reason: str | None
    truncated: bool


def undecodable(protocol: str, raw_len: int, reason: str) -> Frame:
    """A Frame that places no byte and says why."""
    return Frame(
        protocol=protocol,
        raw_len=raw_len,
        fields=(),
        semantics=None,
        code=None,
        sentence=None,
        tail_offset=0,
        tail_reason=reason,
        truncated=raw_len == MAX_RAW_EVENT_BYTES,
    )


# A decoder module exposes decode(raw) -> Frame and registers here by protocol name.
DECODERS: dict[str, Callable[[bytes], Frame]] = {}
# Optional per-protocol hook: (bytes[, pkt_type]) -> the same bytes, same length, sensitive ranges zeroed.
MASKERS: dict[str, Callable[..., bytes]] = {}


def decode(protocol: str, raw: bytes) -> Frame:
    """Decode raw bytes; never raises."""
    raw_len = len(raw)
    decoder = DECODERS.get(protocol)
    if decoder is None:
        return undecodable(protocol, raw_len, f"no decoder for protocol {protocol!r}")
    try:
        frame = decoder(raw)
        if not isinstance(frame, Frame):
            return undecodable(protocol, raw_len, "decoder returned something that is not a Frame")
    except Exception as exc:  # a decoder must never cost a row or a 500
        return undecodable(protocol, raw_len, f"decoder failed: {exc}")
    truncated = raw_len == MAX_RAW_EVENT_BYTES
    if frame.truncated != truncated:
        frame = dataclasses.replace(frame, truncated=truncated)
    return frame


def decode_hex(protocol: str, hex_str: str | None) -> Frame:
    """Decode stored hex; None, empty, odd-length or non-hex yields an undecodable Frame."""
    if not hex_str or not _HEX_RE.fullmatch(hex_str):
        return undecodable(protocol, 0, "stored bytes are not valid hex")
    return decode(protocol, bytes.fromhex(hex_str))


def mask_hex(protocol: str, hex_str: str | None, *, pkt_type: int | None = None) -> str:
    """Stored hex with any credential byte ranges zeroed; never raises.

    Length and offsets are preserved. A protocol with no hook is returned unchanged. For a
    protocol with a hook, input that is not valid hex is dropped (empty string), because
    echoing a malformed packet back would leak whatever it carries, and a hook that fails
    masks the whole packet: the failure direction is over-masking.

    ``pkt_type`` is an optional hint (the row's own wire-derived packet type). It is passed to
    the hook only when given; a hook may use it to let bytes through, never to skip a mask
    its own content check demands.
    """
    masker = MASKERS.get(protocol)
    if masker is None:
        return hex_str or ""
    if not hex_str or not _HEX_RE.fullmatch(hex_str):
        return ""
    raw = bytes.fromhex(hex_str)
    try:
        out = masker(raw) if pkt_type is None else masker(raw, pkt_type)
        if not isinstance(out, bytes) or len(out) != len(raw):
            raise ValueError("a mask hook must return bytes of the same length")
    except Exception:
        log.warning(
            "mask hook for protocol %r failed; the whole packet is masked", protocol, exc_info=True
        )
        out = bytes(len(raw))
    return out.hex()
