"""The five legacy ``ics_events`` booleans, derived from a decoded frame.

``semantics`` is the single truth; the booleans stay so older readers keep working.
Imports nothing from honeylens.ingest, honeylens.routes or honeylens.webui.
"""

from __future__ import annotations

from honeylens.ics.frame import Frame

# semantics -> the flag it sets. "enumerate" and "discovery" both mean the attacker is
# mapping the device, not reading process data.
FLAG_FOR_SEMANTICS = {
    "read": "is_read",
    "enumerate": "is_discovery",
    "discovery": "is_discovery",
    "write": "is_write",
    "command": "is_control",
    "control": "is_control",
    "anomaly": "is_anomaly",
}

# IEC 60870-5-104 commands that put a value into the process: set-points C_SE_NA/NB/NC_1
# (48-50) and the bitstring command C_BO_NA_1 (51). Semantics "command", but is_write too.
_IEC104_SETPOINT_TYPES = frozenset({48, 49, 50, 51})


def flags_for_semantics(semantics: str | None) -> dict[str, bool]:
    """The five booleans for a bare semantics value; all False for ``None``.

    For a row whose semantics came from the verdict rather than from a frame: the five
    booleans must say what the ``semantics`` column says.
    """
    flags = dict.fromkeys(
        ("is_read", "is_write", "is_control", "is_discovery", "is_anomaly"), False
    )
    flag = FLAG_FOR_SEMANTICS.get(semantics or "")
    if flag:
        flags[flag] = True
    return flags


def flags_for(frame: Frame) -> dict[str, bool]:
    """The five booleans for ``frame``; all False when it has no semantics."""
    flags = flags_for_semantics(frame.semantics)
    if frame.protocol == "iec104" and frame.code in _IEC104_SETPOINT_TYPES:
        flags["is_write"] = True
    return flags
