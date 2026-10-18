"""A stream-based decoy must read the body the headers promised, not one TCP segment.

`honeypot_k8s` learned this on 2026-10-23: dispatching as soon as `\r\n\r\n` appears is
the moment the *headers* are complete, so a 20 KB POST was stored with `body_len=128`
and the decoy's row sat 68 s before Suricata's alert on the same request. That fix was
for an `asyncio.Protocol`. The monolith's `HTTPResponder` and `hp_elasticsearch` use
stream readers and still do a single read — `HTTPResponder`'s even carries the comment
"may need multiple reads for large POSTs" directly above a lone `reader.read(16384)`.

These tests pin the shared stream version of that behaviour.
"""

from __future__ import annotations

import asyncio

from honeylens.honeypots import body_capture as bc


class _Reader:
    """A StreamReader-alike that hands out pre-scripted chunks, one await each."""

    def __init__(self, chunks, stall=False):
        self._chunks = list(chunks)
        self._stall = stall

    async def read(self, n):
        if self._chunks:
            chunk = self._chunks.pop(0)
            return chunk[:n]
        if self._stall:
            await asyncio.sleep(3600)  # never returns; the caller's timeout must win
        return b""


def _run(reader, **kw):
    return asyncio.run(bc.read_http_request(reader, **kw))


# ----------------------------------------------------------------- header parsing


def test_content_length_is_read_case_insensitively():
    assert bc.content_length(b"POST / HTTP/1.1\r\ncontent-length: 42") == 42
    assert bc.content_length(b"POST / HTTP/1.1\r\nContent-Length:  7 ") == 7
    assert bc.content_length(b"GET / HTTP/1.1\r\nHost: x") is None


def test_a_content_length_that_is_not_a_number_is_not_a_length():
    """An attacker-supplied header must not raise inside the read loop."""
    assert bc.content_length(b"POST / HTTP/1.1\r\nContent-Length: ../../etc/passwd") is None
    assert bc.content_length(b"POST / HTTP/1.1\r\nContent-Length: -5") == 0


def test_the_request_line_is_never_mistaken_for_a_header():
    """A path can contain anything, including something header-shaped."""
    assert bc.content_length(b"GET /x?content-length:99 HTTP/1.1\r\nHost: x") is None


def test_chunked_is_detected_only_on_transfer_encoding():
    assert bc.is_chunked(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked")
    assert bc.is_chunked(b"POST / HTTP/1.1\r\ntransfer-encoding: gzip, CHUNKED")
    assert not bc.is_chunked(b"POST / HTTP/1.1\r\nX-Note: chunked")


# ----------------------------------------------------------------- reading


def test_a_body_split_across_segments_is_read_whole():
    """The defect this exists for: headers in one segment, body in the next."""
    body = b"x" * 3000
    reader = _Reader([b"POST /api HTTP/1.1\r\nContent-Length: 3000\r\n\r\n", body])
    got = _run(reader, max_bytes=65536, body_wait=5)
    assert got.endswith(body), "the body that arrived second was dropped"
    assert len(got) == len(body) + len(b"POST /api HTTP/1.1\r\nContent-Length: 3000\r\n\r\n")


def test_a_body_arriving_in_many_small_segments_is_read_whole():
    head = b"POST /api HTTP/1.1\r\nContent-Length: 300\r\n\r\n"
    reader = _Reader([head] + [b"y" * 10] * 30)
    got = _run(reader, max_bytes=65536, body_wait=5)
    assert got == head + b"y" * 300


def test_a_get_returns_as_soon_as_the_headers_are_complete():
    """No Content-Length means no body to wait for; waiting would stall every GET."""
    reader = _Reader([b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"], stall=True)
    got = _run(reader, max_bytes=65536, body_wait=5)
    assert got == b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


def test_a_lying_content_length_does_not_hang_the_decoy():
    """A real server answers. Declared 10000, sent 10 — we answer with what arrived."""
    reader = _Reader([b"POST / HTTP/1.1\r\nContent-Length: 10000\r\n\r\n", b"short"], stall=True)
    got = _run(reader, max_bytes=65536, body_wait=0.3)
    assert got.endswith(b"short")


def test_the_read_is_bounded_so_a_decoy_cannot_be_used_to_fill_memory():
    head = b"POST / HTTP/1.1\r\nContent-Length: 1000000\r\n\r\n"
    reader = _Reader([head] + [b"z" * 5000] * 100)
    got = _run(reader, max_bytes=20000, body_wait=5)
    assert len(got) <= 20000


def test_chunked_reads_until_the_terminator():
    head = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
    reader = _Reader([head, b"5\r\nhello\r\n", b"0\r\n\r\n"], stall=True)
    got = _run(reader, max_bytes=65536, body_wait=5)
    assert b"hello" in got and got.endswith(b"0\r\n\r\n")


def test_a_closed_connection_returns_what_was_received():
    reader = _Reader([b"POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\n", b"partial"])
    got = _run(reader, max_bytes=65536, body_wait=5)
    assert got.endswith(b"partial")


def test_nothing_sent_returns_empty_rather_than_raising():
    assert _run(_Reader([]), max_bytes=65536, body_wait=1) == b""


def test_headers_alone_exceeding_the_bound_still_return():
    """A header flood must not loop forever looking for \\r\\n\\r\\n."""
    reader = _Reader([b"GET /" + b"a" * 9000], stall=True)
    got = _run(reader, max_bytes=4096, body_wait=5)
    assert len(got) <= 4096


# ----------------------------------------------------------------- shared with k8s


def test_k8s_uses_the_same_header_parsers():
    """Two copies of header parsing drift. k8s was first; it now shares these."""
    from honeylens.honeypots import honeypot_k8s as k8s

    assert k8s._content_length is bc.content_length
    assert k8s._is_chunked is bc.is_chunked
