"""core.sanitise — the only place packet text passes through before cur.execute()."""

from __future__ import annotations

import json

from honeylens.sanitise import safe_json_dumps, safe_str, sanitize_payload, strip_nul


def test_strip_nul_recurses_and_keeps_newlines() -> None:
    value = {"a": "x\x00y\x01z\n", "b": ["p\x7fq", ("t\x00",)], "n": 3, "f": 1.5, "none": None}
    assert strip_nul(value) == {"a": "xyz\n", "b": ["pq", ("t",)], "n": 3, "f": 1.5, "none": None}


def test_strip_nul_turns_bytes_into_hex() -> None:
    assert strip_nul(b"\x00\xff") == "00ff"


def test_safe_str() -> None:
    assert safe_str(None) is None
    assert safe_str("  \x00  ") is None
    assert safe_str(b"ab\x00c\xff") == "abc�"
    assert safe_str(12) == "12"
    assert safe_str("ok\tline\r\n") == "ok\tline"


def test_safe_json_dumps_strips_nul_and_survives_odd_types() -> None:
    out = safe_json_dumps({"k": "a\x00b", "when": object()})
    assert "\x00" not in out
    assert json.loads(out)["k"] == "ab"


def test_sanitize_payload() -> None:
    assert sanitize_payload(None) is None
    assert sanitize_payload("") is None
    assert sanitize_payload("\x00\x01") is None
    assert sanitize_payload("GET / \x00HTTP\x1b") == "GET / HTTP"
    assert sanitize_payload(b"raw") == "b'raw'"  # str() of bytes, as in 0.9
