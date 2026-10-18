"""Text sanitisation for PostgreSQL: the single place that strips NUL and control characters.

``text``/``varchar``/``jsonb`` columns reject a string containing 0x00. EVERYTHING that
comes from packets, honeypot logs or external sources passes through here before
``cur.execute()``. In 0.9 this logic was duplicated across three ingests; here it lives once.
"""

import json
import re
from typing import Any

# NUL and all C0/DEL control characters except \n \r \t
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def strip_nul(value: Any) -> Any:
    """Recursively strip NUL and control characters from every string in dict/list/tuple/str.

    Bytes become hex (safe for the database); numbers and ``None`` pass through unchanged.
    """
    if value is None:
        return None
    if isinstance(value, str):
        if "\x00" in value:
            value = value.replace("\x00", "")
        return CTRL_RE.sub("", value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {k: strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_nul(v) for v in value]
    if isinstance(value, tuple):
        return tuple(strip_nul(v) for v in value)
    return value


def safe_str(value: Any) -> str | None:
    """The value as a string without NUL and control characters; ``None`` when empty."""
    if value is None:
        return None
    if isinstance(value, bytes):
        s = value.decode(errors="replace")
    elif not isinstance(value, str):
        s = str(value)
    else:
        s = value
    s = CTRL_RE.sub("", s.replace("\x00", ""))
    return s.strip() or None


def _drop_nul(value: Any) -> Any:
    """NUL only, in strings only; the rest of the structure and characters unchanged."""
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {k: _drop_nul(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_drop_nul(v) for v in value]
    return value


def safe_json_dumps(obj: Any) -> str:
    """JSON without NUL; non-serialisable types via ``str``.

    In 0.9 NUL was removed from the finished JSON text, but ``ensure_ascii=True`` writes it
    as the six characters ``\\u0000``, so ``replace("\\x00", "")`` matched nothing, and jsonb
    rejects ``\\u0000`` anyway. Hence NUL is removed from the structure BEFORE serialisation.
    """
    return json.dumps(_drop_nul(obj), ensure_ascii=True, default=str)


def sanitize_payload(payload: Any) -> str | None:
    """Raw payload text without NUL and control characters; ``None`` when nothing remains."""
    if not payload:
        return None
    if not isinstance(payload, str):
        payload = str(payload)
    result = CTRL_RE.sub("", payload.replace("\x00", "")).strip()
    return result or None
