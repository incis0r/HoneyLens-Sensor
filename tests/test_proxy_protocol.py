#!/usr/bin/env python3
"""PROXY protocol v1/v2 parsing and the peer-override listener.

The unit tests pin the preamble parser and the trust policy. The integration test proves the
whole point: a connection carrying a PROXY preamble from a trusted source makes the aiohttp
handler see the real client address (not the TCP peer), while an untrusted source is ignored
and the literal bytes reach the handler unchanged.
"""

from __future__ import annotations

import asyncio
import socket

from aiohttp import web

from honeylens.honeypots import proxy_protocol as pp

# --- preamble parser --------------------------------------------------------------------


def test_v1_tcp4_is_parsed():
    buf = b"PROXY TCP4 203.0.113.9 198.51.100.1 51234 443\r\nGET / HTTP/1.1\r\n"
    consumed, addr = pp.parse_preamble(buf)
    assert addr == ("203.0.113.9", 51234)
    assert buf[consumed:].startswith(b"GET / HTTP/1.1")


def test_v1_unknown_is_valid_but_addressless():
    consumed, addr = pp.parse_preamble(b"PROXY UNKNOWN\r\nrest")
    assert addr is None
    assert consumed == len("PROXY UNKNOWN\r\n")


def test_v2_tcp4_is_parsed():
    sig = b"\r\n\r\n\x00\r\nQUIT\n"
    addr_block = (
        socket.inet_aton("203.0.113.9")  # src
        + socket.inet_aton("198.51.100.1")  # dst
        + (51234).to_bytes(2, "big")  # src port
        + (443).to_bytes(2, "big")  # dst port
    )
    header = sig + bytes([0x21, 0x11]) + len(addr_block).to_bytes(2, "big") + addr_block
    consumed, addr = pp.parse_preamble(header + b"\x16\x03\x01")  # trailing TLS record byte
    assert addr == ("203.0.113.9", 51234)
    assert consumed == len(header)


def test_partial_preamble_needs_more():
    assert pp.parse_preamble(b"PROXY TCP4 203.0.113.9 198.51") == pp.NEED_MORE
    assert pp.parse_preamble(b"\r\n\r\n\x00") == pp.NEED_MORE  # partial v2 signature


def test_plain_http_is_not_proxy():
    assert pp.parse_preamble(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == pp.NOT_PROXY


def test_trust_policy():
    assert pp.parse_trusted("1") == "all"
    assert pp.parse_trusted("all") == "all"
    nets = pp.parse_trusted("10.1.5.1, 192.168.0.0/24")
    assert pp._is_trusted("10.1.5.1", nets)
    assert pp._is_trusted("192.168.0.50", nets)
    assert not pp._is_trusted("8.8.8.8", nets)
    assert pp._is_trusted("8.8.8.8", "all")


# --- end-to-end listener ----------------------------------------------------------------


def _run_listener_case(preamble: bytes, trusted) -> str:
    """Start the listener, send `preamble` + a GET, return the request.remote the handler saw."""
    seen: dict[str, str] = {}

    async def handler(request: web.Request) -> web.Response:
        seen["remote"] = request.remote or ""
        return web.Response(text="ok")

    async def _main():
        app = web.Application()
        app.router.add_route("*", "/{t:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        listener = pp.ProxyProtocolListener(
            server_factory=runner.server, ssl_context=None, trusted=trusted
        )
        await listener.start("127.0.0.1", 0)
        host, port = listener.sockname
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(preamble + b"GET /probe HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n")
            await writer.drain()
            await reader.read()  # drain response/EOF so the handler has run
            writer.close()
            await asyncio.sleep(0.02)
        finally:
            await listener.stop()
            await runner.cleanup()
        return seen.get("remote", "")

    return asyncio.run(_main())


def test_trusted_proxy_preamble_sets_real_client():
    # The loopback peer (127.0.0.1) is trusted, so the preamble's address wins.
    remote = _run_listener_case(b"PROXY TCP4 203.0.113.9 198.51.100.1 51234 443\r\n", "all")
    assert remote == "203.0.113.9"


def test_untrusted_source_cannot_spoof():
    # 127.0.0.1 is not in the trusted set, so the preamble is NOT consumed: the spoofed address
    # is never adopted. The literal "PROXY ..." line then reaches the HTTP parser as a malformed
    # request, so the handler does not run at all — the attacker gains nothing.
    remote = _run_listener_case(
        b"PROXY TCP4 203.0.113.9 198.51.100.1 51234 443\r\n", pp.parse_trusted("10.1.5.1")
    )
    assert remote != "203.0.113.9"


def test_no_preamble_from_trusted_source_is_normal():
    # Trusted source but no preamble (a direct GET): the real loopback peer is used.
    remote = _run_listener_case(b"", "all")
    assert remote == "127.0.0.1"
