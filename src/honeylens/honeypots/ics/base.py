"""Shared helpers for the ICS honeypot family — classification taxonomy,
device-profile access, and TPKT/COTP (RFC 1006 / ISO 8073) framing."""

from __future__ import annotations

import struct

# kind -> (attack_type, severity). Mirrors the existing ICS convention.
_TAXONOMY = {
    "enumeration": ("ics_enumeration", "LOW"),
    "recon": ("ics_recon_function_code", "MEDIUM"),
    "write": ("ics_write_attempt", "HIGH"),
    "command": ("ics_command_with_intent", "CRITICAL"),
}


def classify(kind: str):
    """Map an interaction kind to (attack_type, severity)."""
    return _TAXONOMY.get(kind, _TAXONOMY["enumeration"])


# --- TPKT (RFC 1006) ---
def pack_tpkt(payload: bytes) -> bytes:
    return b"\x03\x00" + struct.pack(">H", len(payload) + 4) + payload


def parse_tpkt(buf: bytes):
    """Return (payload, rest). Raises ValueError on a malformed/short header."""
    if len(buf) < 4 or buf[0] != 0x03:
        raise ValueError("not a TPKT")
    total = struct.unpack(">H", buf[2:4])[0]
    if total < 4 or len(buf) < total:
        raise ValueError("short TPKT")
    return buf[4:total], buf[total:]


# --- COTP (ISO 8073) ---
def cotp_connection_confirm(cr: bytes) -> bytes:
    """Build a COTP CC echoing the CR's src-ref as the CC dst-ref."""
    # CR layout after TPKT: len(1), 0xE0, dst-ref(2), src-ref(2), class(1), [params]
    src_ref = cr[4:6] if len(cr) >= 6 else b"\x00\x01"
    body = bytes([0xD0]) + src_ref + b"\x00\x01" + b"\x00"  # CC, dst=src_ref, src=1, class0
    return bytes([len(body)]) + body


def cotp_data(payload: bytes) -> bytes:
    """Wrap payload in a COTP DT TPDU (EOT set)."""
    return bytes([0x02, 0xF0, 0x80]) + payload


def cotp_dt_payload(tpdu: bytes):
    """Return the payload of a COTP DT TPDU, or None if not a DT."""
    if len(tpdu) >= 3 and tpdu[1] == 0xF0:
        return tpdu[3:]
    return None
