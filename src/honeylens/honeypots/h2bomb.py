"""honeypots/h2bomb.py — CVE-2026-49975 "HTTP/2 Bomb" inspector
================================================================
Pure, stdlib-only inspector for the HTTP/2 Bomb (HPACK indexed-reference
bomb + flow-control window stall). Reads HTTP/2 frame *headers* off a
socket-like object, flags the smoking-gun SETTINGS_INITIAL_WINDOW_SIZE=0
plus the WINDOW_UPDATE-drip / HEADERS-flood corroborators, sends a GOAWAY
(ENHANCE_YOUR_CALM) and returns. Used by hp_nginx.py when a client
negotiates ALPN "h2" on the 8443 TLS listener — the path Suricata can't
see (encrypted).

Non-amplification principle: this never decodes HPACK, never builds the
dynamic table, never ACKs SETTINGS, never holds a stream open. It reads
9-byte frame headers, drains payloads under a hard cap, and bails on the
first oversize frame. The honeypot's own memory is safe by construction.
"""

from __future__ import annotations

import logging
import struct
import time
from dataclasses import dataclass, field

# HTTP/2 frame type codes
_T_HEADERS = 0x1
_T_SETTINGS = 0x4
_T_GOAWAY = 0x7
_T_WINDOW_UPDATE = 0x8
_T_CONTINUATION = 0x9

_TYPE_NAMES = {
    0x0: "data",
    0x1: "headers",
    0x2: "priority",
    0x3: "rststream",
    0x4: "settings",
    0x5: "pushpromise",
    0x6: "ping",
    0x7: "goaway",
    0x8: "windowupdate",
    0x9: "continuation",
}

_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_SETTINGS_INITIAL_WINDOW_SIZE = 0x4
_ENHANCE_YOUR_CALM = 0x0B
_MAX_FRAME_SIZE = 16384  # HTTP/2 default SETTINGS_MAX_FRAME_SIZE

# Detection thresholds — mirror the Suricata pack (SIDs 9026702/9026703).
_DRIP_COUNT = 20
_DRIP_MAX_INCREMENT = 256
_FLOOD_COUNT = 50


@dataclass
class H2InspectResult:
    is_bomb: bool = False
    attack_types: list = field(default_factory=list)
    severity: str | None = None
    initial_window_size: int | None = None
    frame_counts: dict = field(default_factory=dict)
    window_update_min_increment: int | None = None


def _recvn(conn, n: int) -> bytes:
    """Read up to n bytes; return fewer on EOF. Errors → b''."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except Exception:
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _send_goaway(conn, last_stream_id: int, error_code: int) -> None:
    payload = struct.pack(">II", last_stream_id & 0x7FFFFFFF, error_code)
    frame = (
        struct.pack(">I", len(payload))[1:] + bytes([_T_GOAWAY, 0]) + struct.pack(">I", 0) + payload
    )
    try:
        conn.sendall(frame)
    except Exception as exc:
        logging.getLogger(__name__).debug("ignored: %s", exc)


def inspect_h2_connection(
    conn,
    addr,
    *,
    max_frames: int = 200,
    max_seconds: float = 2.0,
    max_total_bytes: int = 65536,
    monotonic=time.monotonic,
) -> H2InspectResult:
    """Inspect a freshly-ALPN-negotiated h2 connection for the bomb shape.

    `conn` needs recv(n)->bytes and sendall(bytes). Never raises.
    """
    r = H2InspectResult()
    counts = r.frame_counts
    last_stream_id = 0
    wu_count = 0
    headers_count = 0
    total_bytes = 0

    # 1. connection preface
    preface = _recvn(conn, len(_PREFACE))
    total_bytes += len(preface)
    if preface != _PREFACE:
        counts["preface_bad"] = 1
        _send_goaway(conn, 0, _ENHANCE_YOUR_CALM)
        return r

    # 2. bounded frame loop
    start = monotonic()
    frames = 0
    while frames < max_frames and total_bytes < max_total_bytes:
        if monotonic() - start > max_seconds:
            break
        hdr = _recvn(conn, 9)
        total_bytes += len(hdr)
        if len(hdr) < 9:
            break  # EOF / short
        length = int.from_bytes(hdr[0:3], "big")
        ftype = hdr[3]
        stream_id = int.from_bytes(hdr[5:9], "big") & 0x7FFFFFFF

        if length > _MAX_FRAME_SIZE:
            counts["oversize_frame"] = counts.get("oversize_frame", 0) + 1
            break  # refuse to drain a hostile/giant frame

        payload = _recvn(conn, length) if length else b""
        total_bytes += len(payload)
        frames += 1
        name = _TYPE_NAMES.get(ftype, "other")
        counts[name] = counts.get(name, 0) + 1

        if ftype == _T_SETTINGS:
            for off in range(0, len(payload) - 5, 6):
                ident = int.from_bytes(payload[off : off + 2], "big")
                value = int.from_bytes(payload[off + 2 : off + 6], "big")
                if ident == _SETTINGS_INITIAL_WINDOW_SIZE:
                    r.initial_window_size = value
        elif ftype == _T_WINDOW_UPDATE and len(payload) >= 4:
            inc = int.from_bytes(payload[0:4], "big") & 0x7FFFFFFF
            wu_count += 1
            if r.window_update_min_increment is None or inc < r.window_update_min_increment:
                r.window_update_min_increment = inc
        elif ftype in (_T_HEADERS, _T_CONTINUATION):
            headers_count += 1
            if stream_id > last_stream_id:
                last_stream_id = stream_id

    # 3. evaluate
    if r.initial_window_size == 0:
        r.attack_types.append("cve_2026_49975_zero_window")
    if (
        wu_count >= _DRIP_COUNT
        and r.window_update_min_increment is not None
        and r.window_update_min_increment < _DRIP_MAX_INCREMENT
    ):
        r.attack_types.append("cve_2026_49975_window_drip")
    if headers_count >= _FLOOD_COUNT:
        r.attack_types.append("cve_2026_49975_hpack_bomb")

    r.is_bomb = bool(r.attack_types)
    if "cve_2026_49975_zero_window" in r.attack_types:
        r.severity = "HIGH"
    elif r.attack_types:
        r.severity = "MEDIUM"

    # 4. patched-server response: GOAWAY + ENHANCE_YOUR_CALM
    _send_goaway(conn, last_stream_id, _ENHANCE_YOUR_CALM)
    return r
