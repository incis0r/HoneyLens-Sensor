"""CVE-2026-119618 shape: END_STREAM, Content-Type present, no Content-Length, not CONNECT.

Every case builds the HEADERS block by hand with ``hpack`` (never ``h2``'s own client, which
picks one encoding for us), puts it on a real connection preface, and decodes it through
``observe()`` -- so the test proves the pipeline sees the shape, not that a predicate reads a
dataclass. Each case also asserts what the *wire* looks like, so a case cannot claim an
encoding it did not produce.

What the library can reach: ``hpack.Encoder`` always references the name ``content-type``
through the static table (index 31), whatever the mode, so it never writes the name as
literal bytes. The two literal-name cases (the reference PoC's plain ASCII, and a
Huffman-coded literal name) are therefore assembled by hand from the RFC 7541 layout, with
``hpack.huffman`` doing the Huffman coding.
"""

from __future__ import annotations

import asyncio

import hpack
import pytest
from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH

from honeylens.honeypots.h2_capture import PREFACE, H2Budgets, H2Stream, is_119618_shape, observe
from tests.ics_fakes import FakeReader, FakeWriter

SHAPE = [
    (":method", "GET"),
    (":path", "/"),
    (":scheme", "http"),
    (":authority", "x"),
    ("content-type", "text/plain"),
]

_HUFFMAN = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)


def _frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([ftype, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


def _string(data: bytes, *, huffman: bool) -> bytes:
    """An RFC 7541 string literal (all test strings are under 127 bytes)."""
    if huffman:
        data = _HUFFMAN.encode(data)
    return bytes([(0x80 if huffman else 0) | len(data)]) + data


def _literal_name_block(headers, *, huffman: bool) -> bytes:
    """Every header as 'literal, never indexed, new name': nothing is table-referenced."""
    block = b""
    for name, value in headers:
        block += b"\x10" + _string(name.encode(), huffman=huffman)
        block += _string(value.encode(), huffman=huffman)
    return block


def _block(headers, encoding: str) -> bytes:
    if encoding == "static_indexed":
        return hpack.Encoder().encode(headers, huffman=False)
    if encoding == "literal_huffman":
        return hpack.Encoder().encode(headers, huffman=True)
    if encoding == "literal_never_indexed_no_huffman":
        never = [hpack.NeverIndexedHeaderTuple(*h) for h in headers]
        return hpack.Encoder().encode(never, huffman=False)
    if encoding == "literal_name_ascii":
        return _literal_name_block(headers, huffman=False)
    if encoding == "literal_name_huffman":
        return _literal_name_block(headers, huffman=True)
    raise AssertionError(encoding)


def _wire(headers, *, encoding: str = "literal_huffman", end_stream: bool = True) -> bytes:
    flags = 0x4 | (0x1 if end_stream else 0)  # END_HEADERS [| END_STREAM]
    return PREFACE + _frame(0x4, 0, 0) + _frame(0x1, flags, 1, _block(headers, encoding))


def _one_stream(headers, *, encoding: str = "literal_huffman", end_stream: bool = True):
    obs = asyncio.run(
        observe(
            FakeReader(_wire(headers, encoding=encoding, end_stream=end_stream)),
            FakeWriter(),
            entry="preface",
        )
    )
    assert obs.h2_error is None
    assert len(obs.streams) == 1
    return obs.streams[0]


ENCODINGS = [
    "literal_never_indexed_no_huffman",
    "literal_huffman",
    "static_indexed",
    "literal_name_ascii",
    "literal_name_huffman",
]


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_the_shape_is_seen_in_every_hpack_encoding(encoding):
    stream = _one_stream(SHAPE, encoding=encoding, end_stream=True)
    assert is_119618_shape(stream) is True


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_the_wire_really_differs_per_encoding(encoding):
    """Guards the guard: the name is readable on the wire only in the PoC's own encoding."""
    wire = _wire(SHAPE, encoding=encoding)
    assert (b"content-type" in wire) is (encoding == "literal_name_ascii")
    if encoding in {"literal_huffman", "literal_name_huffman"}:
        assert b"text/plain" not in wire  # value Huffman-coded too
    if encoding == "static_indexed":
        assert b"text/plain" in wire and b"\x5f\x0atext/plain" in wire  # name by index 31
    if encoding == "literal_never_indexed_no_huffman":
        assert b"\x1f\x10\x0atext/plain" in wire  # never-indexed, name by index 31


def test_no_shape_when_content_length_is_present():
    stream = _one_stream([*SHAPE, ("content-length", "0")], end_stream=True)
    assert is_119618_shape(stream) is False


def test_no_shape_when_content_type_is_absent():
    stream = _one_stream([h for h in SHAPE if h[0] != "content-type"], end_stream=True)
    assert is_119618_shape(stream) is False


def test_no_shape_when_end_stream_is_clear():
    stream = _one_stream(SHAPE, end_stream=False)
    assert is_119618_shape(stream) is False


def test_no_shape_on_connect():
    # RFC 9113 8.5: CONNECT carries :authority and no :path/:scheme (h2 rejects the rest).
    stream = _one_stream(
        [(":method", "CONNECT"), (":authority", "x"), ("content-type", "text/plain")],
        end_stream=True,
    )
    assert stream.method == "CONNECT" and stream.content_type == "text/plain"
    assert is_119618_shape(stream) is False


def test_malformed_pseudo_headers_do_not_raise():
    assert (
        is_119618_shape(
            H2Stream(
                stream_id=1,
                method=None,
                path=None,
                authority=None,
                scheme=None,
                content_type=None,
                has_content_length=False,
                end_stream=True,
                header_count=0,
                ended_by="reset",
            )
        )
        is False
    )


def test_a_stream_with_no_method_does_not_match():
    stream = H2Stream(stream_id=1, content_type="text/plain", end_stream=True)
    assert is_119618_shape(stream) is False


def test_shape_matches_counts_every_stream_beyond_the_kept_records():
    block = _block(SHAPE, "literal_huffman")
    frames = b"".join(_frame(0x1, 0x5, sid, block) for sid in (1, 3, 5, 7))
    obs = asyncio.run(
        observe(
            FakeReader(PREFACE + _frame(0x4, 0, 0) + frames),
            FakeWriter(),
            entry="preface",
            budgets=H2Budgets(keep_streams=2),
        )
    )
    assert len(obs.streams) == 2
    assert obs.shape_matches == 4


@pytest.mark.parametrize("method", ["connect", "Connect", "CoNNect"])
def test_a_case_variant_of_connect_is_an_ordinary_method_and_still_matches(method):
    """Method tokens are case-sensitive and h2 and Apache treat `connect` as ordinary."""
    stream = _one_stream([(":method", method), *SHAPE[1:]], end_stream=True)
    assert stream.method == method
    assert is_119618_shape(stream) is True


def test_real_connect_still_does_not_match():
    assert (
        is_119618_shape(H2Stream(stream_id=1, method="CONNECT", content_type="x", end_stream=True))
        is False
    )
