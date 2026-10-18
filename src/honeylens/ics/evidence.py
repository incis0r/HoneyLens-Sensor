"""Where a row's evidence lives, as pure dict operations shared by the ingest and the backfill.

Imports nothing from honeylens.ingest, honeylens.routes or honeylens.webui.
"""

from __future__ import annotations

from typing import Any

from honeylens.ics.flags import flags_for
from honeylens.ics.frame import Frame, decode

# Where a decoy stores the captured frame, strongest first. ``pdu_hex`` leads: hp_modbus
# stores a bare PDU there, which is exactly what the modbus decoder takes.
ICS_HEX_KEYS = (
    "pdu_hex",
    "asdu_hex",
    "apdu_hex",
    "frame_hex",
    "data_hex",
    "body_hex",
    "app_objects_hex",
    "payload_hex",
)

# Protocols whose ``function_code`` column is, by the decoys' own field map, byte 0 of the
# stored frame (modbus ``fc`` = PDU byte 0, iec104 ``type_id`` = ASDU byte 0). Every other
# protocol's code is a different thing (enip ``command`` is 16-bit, bacnet ``service`` sits
# behind an APDU header) and is NOT decoded this way.
CODE_IS_FIRST_BYTE = frozenset({"modbus", "iec104"})


def ics_frame_hex(meta: dict) -> str | None:
    """The captured frame's hex from the first key that holds any, else None."""
    for key in ICS_HEX_KEYS:
        value = meta.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def ics_flag(name: str, meta: dict, flags: dict[str, bool]) -> bool:
    """One ``is_*`` column: the decoy's own boolean, then the decoded frame, then False."""
    own = meta.get(name)
    if isinstance(own, bool):
        return own
    return flags[name]


def frame_for_code(protocol: str, code: Any) -> Frame | None:
    """The one-byte frame a stored function code stands for, or None where the code is not
    byte 0 of the frame (or is not a byte). Its semantics are the specification's reading
    of the code alone."""
    if protocol not in CODE_IS_FIRST_BYTE:
        return None
    if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255:
        return None
    return decode(protocol, bytes([code]))


__all__ = [
    "CODE_IS_FIRST_BYTE",
    "ICS_HEX_KEYS",
    "flags_for",
    "frame_for_code",
    "ics_flag",
    "ics_frame_hex",
]
