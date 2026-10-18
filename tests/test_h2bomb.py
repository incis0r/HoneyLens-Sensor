"""Unit tests for honeypots/h2bomb.py — CVE-2026-49975 HTTP/2 Bomb inspector.

Pure, offline: a FakeSocket feeds crafted HTTP/2 frame bytes and captures
what the inspector sends back. No real sockets, no TLS, no network.
"""

import struct

from honeylens.honeypots.h2bomb import H2InspectResult, inspect_h2_connection

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# HTTP/2 frame type codes
T_DATA, T_HEADERS, T_SETTINGS = 0x0, 0x1, 0x4
T_PING, T_GOAWAY, T_WINDOW_UPDATE = 0x6, 0x7, 0x8
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
ENHANCE_YOUR_CALM = 0x0B


def _frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))[1:]
        + bytes([ftype, flags])
        + struct.pack(">I", stream_id)
        + payload
    )


def settings(window: int) -> bytes:
    return _frame(T_SETTINGS, 0x0, 0, struct.pack(">HI", SETTINGS_INITIAL_WINDOW_SIZE, window))


def winupd(increment: int) -> bytes:
    return _frame(T_WINDOW_UPDATE, 0x0, 0, struct.pack(">I", increment))


def headers(stream_id: int = 1) -> bytes:
    # minimal HEADERS payload — a single HPACK indexed byte; never decoded
    return _frame(T_HEADERS, 0x4, stream_id, b"\x82")


def ping() -> bytes:
    return _frame(T_PING, 0x0, 0, b"\x00" * 8)


class FakeSocket:
    def __init__(self, inbound: bytes):
        self._in = inbound
        self._pos = 0
        self.sent = bytearray()
        self.closed = False

    def recv(self, n: int) -> bytes:
        chunk = self._in[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def selected_alpn_protocol(self):
        return "h2"


def _run(inbound: bytes, **kw) -> tuple[H2InspectResult, FakeSocket]:
    sock = FakeSocket(inbound)
    result = inspect_h2_connection(sock, ("203.0.113.7", 51000), **kw)
    return result, sock


def _parse_goaway(sent: bytes):
    """Return (found, error_code) for a GOAWAY frame in the sent bytes."""
    i = 0
    while i + 9 <= len(sent):
        length = int.from_bytes(sent[i : i + 3], "big")
        ftype = sent[i + 3]
        payload = sent[i + 9 : i + 9 + length]
        if ftype == T_GOAWAY and len(payload) >= 8:
            return True, int.from_bytes(payload[4:8], "big")
        i += 9 + length
    return False, None


# --- case 1: zero-window smoking gun ---------------------------------------
def test_zero_initial_window_is_high_bomb():
    result, sock = _run(PREFACE + settings(0))
    assert result.is_bomb is True
    assert "cve_2026_49975_zero_window" in result.attack_types
    assert result.severity == "HIGH"
    assert result.initial_window_size == 0
    found, err = _parse_goaway(bytes(sock.sent))
    assert found and err == ENHANCE_YOUR_CALM


# --- case 2: window-update drip --------------------------------------------
def test_window_update_drip():
    inbound = PREFACE + settings(65535) + winupd(1) * 25
    result, _ = _run(inbound)
    assert "cve_2026_49975_window_drip" in result.attack_types
    assert result.is_bomb is True
    assert result.severity == "MEDIUM"
    assert result.window_update_min_increment == 1


# --- case 3: HPACK headers flood -------------------------------------------
def test_hpack_headers_flood():
    inbound = PREFACE + settings(65535) + b"".join(headers(i) for i in range(1, 121, 2))
    result, _ = _run(inbound)
    assert "cve_2026_49975_hpack_bomb" in result.attack_types
    assert result.is_bomb is True


# --- case 4: benign h2 client → no tags (no false positive) ----------------
def test_clean_h2_client_no_tags():
    inbound = PREFACE + settings(65535) + ping() + headers(1)
    result, sock = _run(inbound)
    assert result.is_bomb is False
    assert result.attack_types == []
    assert result.severity is None
    # still GOAWAY-and-close (we are a honeypot, not a real service)
    found, _ = _parse_goaway(bytes(sock.sent))
    assert found


# --- case 5: malformed preface → graceful ----------------------------------
def test_bad_preface_graceful():
    result, _ = _run(b"GET / HTTP/1.1\r\n\r\n")  # not an h2 preface
    assert result.is_bomb is False
    assert result.frame_counts.get("preface_bad") == 1


# --- case 6: oversize frame length is not buffered --------------------------
def test_oversize_frame_capped():
    # claim a 5 MB frame but provide no payload — inspector must not block/alloc
    oversize_header = struct.pack(">I", 5_000_000)[1:] + bytes([T_DATA, 0]) + struct.pack(">I", 1)
    result, _ = _run(PREFACE + settings(65535) + oversize_header)
    assert result.frame_counts.get("oversize_frame") == 1
    assert result.is_bomb is False


# --- case 7: GOAWAY structure ----------------------------------------------
def test_goaway_structure():
    _, sock = _run(PREFACE + settings(0))
    sent = bytes(sock.sent)
    # first frame is GOAWAY on stream 0
    assert sent[3] == T_GOAWAY
    assert int.from_bytes(sent[5:9], "big") == 0


# --- case 8: deadline stops the loop ---------------------------------------
def test_deadline_stops_loop():
    # a monotonic that jumps past max_seconds after the first call
    ticks = iter([0.0, 0.1, 99.0, 99.0, 99.0, 99.0])

    def fake_monotonic():
        try:
            return next(ticks)
        except StopIteration:
            return 99.0

    inbound = PREFACE + settings(65535) + winupd(1) * 100
    result, _ = _run(inbound, max_seconds=2.0, monotonic=fake_monotonic)
    # loop bailed on deadline before counting all 100 → not enough for drip
    assert "cve_2026_49975_window_drip" not in result.attack_types
