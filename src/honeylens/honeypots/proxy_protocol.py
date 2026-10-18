"""HAProxy PROXY protocol (v1 and v2) support for honeypots behind a reverse proxy.

When a decoy sits behind an L4/L7 proxy (for example nginx ``stream`` with ``ssl_preread`` for
443, nginx ``http`` for 80), the decoy's TCP peer is the proxy, so every event records the
proxy's address instead of the attacker's. With the PROXY protocol the proxy prepends the real
client address as a short preamble on the connection. The preamble rides *below* TLS and below
HTTP, so the attacker never sees it; only the decoy reads it. This module consumes that preamble
and makes the real client address surface as the connection's ``peername`` — so ``request.remote``
and the event's ``peer_ip`` are correct with no change to any handler.

Two properties matter:

* **No over-read before TLS.** The preamble is read with ``MSG_PEEK`` to measure its exact
  length, then exactly that many bytes are consumed. Everything after it (the TLS ClientHello
  on 443, the request line on 80) stays in the socket buffer, so ``connect_accepted_socket``
  does the TLS handshake and HTTP parse normally.
* **The preamble is trusted only from the proxy.** It is parsed only when the connection's real
  TCP peer is in the configured trusted set. A direct attacker (not via the proxy) cannot spoof
  an address: their TCP peer is not trusted, so the preamble is ignored and the connection is
  served as-is.
"""

from __future__ import annotations

import asyncio
import enum
import ipaddress
import logging
import socket
from typing import Any

logger = logging.getLogger("netscaler-honeypot")

_V2_SIG = b"\r\n\r\n\x00\r\nQUIT\n"  # 12-byte PROXY v2 signature
_V1_PREFIX = b"PROXY "
_MAX_PREAMBLE = 536  # v1 is <=107 bytes; v2 header(16)+largest addr block fits well under this


class _Signal(enum.Enum):
    """Parser outcomes that are not an address: wait for more bytes, or not a PROXY preamble."""

    NEED_MORE = "need-more"
    NOT_PROXY = "not-proxy"


NEED_MORE = _Signal.NEED_MORE
NOT_PROXY = _Signal.NOT_PROXY


def parse_preamble(buf: bytes) -> tuple[int, tuple[str, int] | None] | _Signal:
    """Parse a PROXY v1/v2 preamble from the front of ``buf``.

    Returns ``(consumed, (ip, port))`` for a TCP4/TCP6 client, ``(consumed, None)`` for a valid
    preamble that carries no usable address (UNKNOWN / LOCAL), ``NEED_MORE`` if more bytes are
    required, or ``NOT_PROXY`` if the bytes are clearly not a PROXY preamble.
    """
    if buf.startswith(_V2_SIG):
        return _parse_v2(buf)
    if buf.startswith(_V1_PREFIX):
        return _parse_v1(buf)
    # A short prefix that could still become a signature means "wait"; anything else is not PROXY.
    if _V2_SIG.startswith(buf) or _V1_PREFIX.startswith(buf):
        return NEED_MORE
    return NOT_PROXY


def _parse_v1(buf: bytes) -> tuple[int, tuple[str, int] | None] | _Signal:
    end = buf.find(b"\r\n")
    if end == -1:
        return NEED_MORE if len(buf) <= 107 else NOT_PROXY
    line = buf[:end].decode("latin-1")
    consumed = end + 2
    parts = line.split(" ")
    # "PROXY TCP4 src dst sport dport" | "PROXY TCP6 ..." | "PROXY UNKNOWN"
    if len(parts) >= 2 and parts[1] in ("TCP4", "TCP6") and len(parts) == 6:
        try:
            return consumed, (parts[2], int(parts[4]))
        except ValueError:
            return consumed, None
    return consumed, None  # UNKNOWN or malformed address family: valid preamble, no address


def _parse_v2(buf: bytes) -> tuple[int, tuple[str, int] | None] | _Signal:
    if len(buf) < 16:
        return NEED_MORE
    ver_cmd = buf[12]
    fam_proto = buf[13]
    addr_len = int.from_bytes(buf[14:16], "big")
    total = 16 + addr_len
    if len(buf) < total:
        return NEED_MORE
    if ver_cmd >> 4 != 0x2:  # not version 2
        return NOT_PROXY
    if ver_cmd & 0x0F != 0x1:  # LOCAL (health check) — valid preamble, no address
        return total, None
    family = fam_proto >> 4
    addr = buf[16:total]
    if family == 0x1 and addr_len >= 12:  # AF_INET
        ip = socket.inet_ntop(socket.AF_INET, addr[0:4])
        port = int.from_bytes(addr[8:10], "big")
        return total, (ip, port)
    if family == 0x2 and addr_len >= 36:  # AF_INET6
        ip = socket.inet_ntop(socket.AF_INET6, addr[0:16])
        port = int.from_bytes(addr[32:34], "big")
        return total, (ip, port)
    return total, None  # AF_UNIX or unspecified: no usable TCP address


def parse_trusted(value: str) -> list[ipaddress._BaseNetwork] | str:
    """Turn the env value into a trust policy: ``"all"`` to trust any source, or a list of
    networks. Empty means disabled (caller should not start the proxy listener)."""
    v = value.strip().lower()
    if v in ("1", "true", "yes", "all", "any"):
        return "all"
    nets: list[ipaddress._BaseNetwork] = []
    for item in value.split(","):
        item = item.strip()
        if item:
            nets.append(ipaddress.ip_network(item, strict=False))
    return nets


def _is_trusted(ip: str, trusted: list[ipaddress._BaseNetwork] | str) -> bool:
    if trusted == "all":
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in trusted)


def _wake(fut: asyncio.Future[None]) -> None:
    if not fut.done():
        fut.set_result(None)


async def _recv(
    loop: asyncio.AbstractEventLoop, sock: socket.socket, n: int, *, peek: bool
) -> bytes:
    """Read up to ``n`` bytes, waiting for readability on a non-blocking socket. ``peek`` leaves
    the bytes in the socket buffer (MSG_PEEK)."""
    flags = socket.MSG_PEEK if peek else 0
    while True:
        try:
            return sock.recv(n, flags)
        except (BlockingIOError, InterruptedError):
            fut: asyncio.Future[None] = loop.create_future()
            # Wake when the fd is readable. The reader is removed right after, so it fires once.
            loop.add_reader(sock.fileno(), _wake, fut)
            try:
                await fut
            finally:
                loop.remove_reader(sock.fileno())


async def read_client_address(
    loop: asyncio.AbstractEventLoop, sock: socket.socket
) -> tuple[str, int] | None:
    """Peek the PROXY preamble, consume exactly its bytes, and return the real client address
    (or None when there is no preamble or it carries no address). Leaves everything after the
    preamble in the socket buffer."""
    peeked = b""
    while len(peeked) < _MAX_PREAMBLE:
        chunk = await _recv(loop, sock, _MAX_PREAMBLE, peek=True)
        if not chunk:
            return None  # connection closed before a full preamble
        peeked = chunk  # MSG_PEEK returns from the front each time, cumulatively
        result = parse_preamble(peeked)
        if isinstance(result, _Signal):
            if result is NEED_MORE:
                continue
            return None  # NOT_PROXY
        consumed, addr = result
        # Consume exactly the preamble; the rest stays buffered for TLS/HTTP.
        remaining = consumed
        while remaining > 0:
            got = await _recv(loop, sock, remaining, peek=False)
            if not got:
                return None
            remaining -= len(got)
        return addr
    return None


class _TransportView:
    """Delegates everything to the real transport but reports the PROXY-declared peer as the
    connection's peername, so request.remote and peer extraction see the real client."""

    def __init__(self, transport: asyncio.Transport, peer: tuple[str, int]) -> None:
        self._t = transport
        self._peer = peer

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name == "peername":
            return self._peer
        return self._t.get_extra_info(name, default)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._t, name)


class _PeerOverrideProtocol(asyncio.Protocol):
    """Wraps the real handler protocol, swapping in a peer-overriding transport view."""

    def __init__(self, inner: asyncio.Protocol, peer: tuple[str, int]) -> None:
        self._inner = inner
        self._peer = peer

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._inner.connection_made(_TransportView(transport, self._peer))  # type: ignore[arg-type]

    def connection_lost(self, exc: Exception | None) -> None:
        self._inner.connection_lost(exc)

    def data_received(self, data: bytes) -> None:
        self._inner.data_received(data)

    def eof_received(self) -> bool | None:
        return self._inner.eof_received()

    def pause_writing(self) -> None:
        self._inner.pause_writing()

    def resume_writing(self) -> None:
        self._inner.resume_writing()


class ProxyProtocolListener:
    """A listener that strips a trusted PROXY preamble, then hands the connection to the aiohttp
    handler via ``connect_accepted_socket`` (with TLS when a context is given)."""

    def __init__(
        self,
        *,
        server_factory: Any,
        ssl_context: Any,
        trusted: list[ipaddress._BaseNetwork] | str,
    ) -> None:
        self._server_factory = server_factory  # aiohttp web.Server (callable -> RequestHandler)
        self._ssl = ssl_context
        self._trusted = trusted
        self._sock: socket.socket | None = None
        self._task: asyncio.Task[None] | None = None
        self._conns: set[asyncio.Task[None]] = set()  # in-flight handoffs, kept alive

    async def start(self, host: str, port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(128)
        sock.setblocking(False)
        self._sock = sock
        self.sockname: tuple[str, int] = sock.getsockname()  # resolved host/port (port 0 -> real)
        self._task = asyncio.get_event_loop().create_task(self._accept_loop())

    async def _accept_loop(self) -> None:
        loop = asyncio.get_event_loop()
        sock = self._sock
        if sock is None:  # start() always sets it before creating this task
            return
        while True:
            conn, peer = await loop.sock_accept(sock)
            task = loop.create_task(self._handle(conn, peer))
            self._conns.add(task)
            task.add_done_callback(self._conns.discard)

    async def _handle(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        loop = asyncio.get_event_loop()
        conn.setblocking(False)
        real = peer
        try:
            if _is_trusted(peer[0], self._trusted):
                parsed = await read_client_address(loop, conn)
                if parsed is not None:
                    real = parsed
            await loop.connect_accepted_socket(
                lambda: _PeerOverrideProtocol(self._server_factory(), real),
                conn,
                ssl=self._ssl,
            )
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive; one bad peer must not kill the loop
            logger.warning("proxy-protocol handoff failed from %s: %s", peer, exc)
            try:
                conn.close()
            except OSError:
                pass

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None
