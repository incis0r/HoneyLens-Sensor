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
