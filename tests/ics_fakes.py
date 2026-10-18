# tests/ics_fakes.py
"""Async fake StreamReader/StreamWriter for honeypot wire tests (offline)."""

import asyncio


class FakeReader:
    def __init__(self, data: bytes = b""):
        self._buf = bytearray(data)

    def feed(self, data: bytes):
        self._buf.extend(data)

    async def read(self, n: int) -> bytes:
        if not self._buf:
            return b""
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    async def readexactly(self, n: int) -> bytes:
        if len(self._buf) < n:
            chunk = bytes(self._buf)
            self._buf.clear()
            raise asyncio.IncompleteReadError(chunk, n)
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk


class FakeWriter:
    def __init__(self, peer=("203.0.113.9", 40000)):
        self.sent = bytearray()
        self._peer = peer
        self.closed = False

    def write(self, data: bytes):
        self.sent.extend(data)

    async def drain(self):
        pass

    def get_extra_info(self, key, default=None):
        return self._peer if key == "peername" else default

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class FakeDatagramTransport:
    def __init__(self):
        self.sent = []  # list of (data, addr)

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        pass


# ---------------------------------------------------------------------------
# ics_events record helpers: what ``honeypot._ics_row`` receives from ``_normalise``.
# ---------------------------------------------------------------------------

_IEC104_SINGLE_COMMAND = "680e2a0000002d0106000100640000" + "01"


def rec_with(honeypot: str = "modbus", rule: str | None = None, metadata: dict | None = None):
    """A normalised ICS record with only the keys ``_ics_row`` reads."""
    meta = dict(metadata or {})
    if rule is not None:
        meta["rule"] = rule
    return {
        "ts": "2026-10-26T10:00:00",
        "honeypot": honeypot,
        "src_ip": "203.0.113.7",
        "src_port": 40000,
        "dst_ip": "10.0.0.5",
        "dst_port": 502,
        "source": "honeypotng",
        "verdict": {"severity": "HIGH"},
        "metadata": meta,
    }


def rec_modbus(metadata: dict | None = None):
    """A Modbus Read Holding Registers record; ``metadata`` replaces the default wholesale."""
    meta = {"rule": "Read Holding Registers", "fc": 3, "pdu_hex": "0300000004"}
    return rec_with("modbus", metadata=meta if metadata is None else metadata)


def rec_modbus_fc90():
    """Function code 90 is not in the Modbus specification."""
    return rec_with(
        "modbus",
        metadata={"rule": "Unknown FC 90", "fc": 90, "pdu_hex": "5a0020001400000000000002"},
    )


def rec_iec104_single_command():
    """A C_SC_NA_1 Single Command, the frame hex under ``apdu_hex``."""
    return rec_with(
        "iec104",
        metadata={
            "rule": "C_SC_NA_1 Single Command",
            "type_id": 45,
            "apdu_hex": _IEC104_SINGLE_COMMAND,
        },
    )


def col(row: tuple, name: str):
    """The value of column ``name`` in a row built in ``INSERT_ICS_SQL`` order."""
    from honeylens.ingest import honeypot

    group = honeypot.INSERT_ICS_SQL.split("INSERT INTO ics_events", 1)[1].split("(", 1)[1]
    names = [n.strip() for n in group.split(")", 1)[0].split(",")]
    return row[names.index(name)]


def rec_fox_http():
    """What the Fox decoy logs when the first client bytes are an HTTP request-line."""
    rec = rec_with(
        "fox",
        metadata={
            "phase": "http_on_ics_port",
            "ics": False,
            "dst_port": 1911,
            "client_bytes": 40,
            "preview": "get / http/1.1\r\nhost: 203.0.113.9:1911\r\n",
        },
    )
    rec["dst_port"] = 1911
    return rec


def rec_fox_session():
    """A Fox exchange that is not HTTP: the decoy says nothing about ``ics``."""
    rec = rec_with(
        "fox",
        metadata={"phase": "fox_session", "client_bytes": 12, "preview": "fox a 1 -1 fox hello"},
    )
    rec["dst_port"] = None
    return rec
