"""Fox is a Niagara decoy on 1911, and a web scanner hitting that port is not ICS traffic."""

import asyncio

import pytest

from honeylens.honeypots.ics import fox as fox_mod
from honeylens.honeypots.ics.fox import FoxHoneypot, is_http_request_line
from honeylens.ingest import honeypot
from tests.ics_fakes import FakeReader, FakeWriter, rec_fox_http, rec_fox_session, rec_modbus


def _would_write_ics_row(rec) -> bool:
    return honeypot._writes_ics_row(rec, "SCANNER")


def test_http_on_the_fox_port_writes_no_ics_row():
    """Defect: 878 `get / http/1.1` rows (28% of ICS volume on the busiest sensor) were
    ICS events because the gate tested the decoy's name, not what it had seen."""
    assert _would_write_ics_row(rec_fox_http()) is False


def test_real_fox_traffic_still_writes_one():
    assert _would_write_ics_row(rec_fox_session()) is True


def test_the_port_survives_without_the_ics_row(monkeypatch):
    """dst_port is NULL on all 878 fox rows in sensor_events, and fox is the one ICS
    decoy that never sent it — without the ICS row there would be no port at all. Pinned
    end to end: the real decoy, the real log_event envelope, then the ingest's _normalise."""
    from honeylens.honeypots import _base

    written = []
    monkeypatch.setattr(_base, "write_record", written.append)
    hp = FoxHoneypot.__new__(FoxHoneypot)
    hp.profile = {}
    hp.port = 1911
    reader = FakeReader(b"GET / HTTP/1.1\r\nHost: x:1911\r\n\r\n")
    asyncio.run(hp.handle_connection(reader, FakeWriter(), ("203.0.113.9", 4000)))
    assert len(written) == 1
    rec = honeypot._normalise(written[0])
    assert rec["dst_port"] == 1911
    assert rec["metadata"]["ics"] is False
    assert honeypot._writes_ics_row(rec, "SCANNER") is False


def test_a_decoy_that_says_nothing_about_ics_is_still_ics():
    rec = rec_modbus()
    rec["metadata"].pop("ics", None)
    assert _would_write_ics_row(rec) is True


def test_only_an_explicit_false_suppresses_the_ics_row():
    """`is not False`: a truthy or None `ics` must not silence a decoy."""
    for value in (True, None, 0, ""):
        rec = rec_modbus()
        rec["metadata"]["ics"] = value
        assert _would_write_ics_row(rec) is True, value


def _run_fox(data: bytes) -> dict:
    events = []
    orig = fox_mod.log_event
    fox_mod.log_event = lambda proto, peer, d, **kw: events.append((d, kw))
    try:
        hp = FoxHoneypot.__new__(FoxHoneypot)
        hp.profile = {}
        hp.port = 1911
        asyncio.run(hp.handle_connection(FakeReader(data), FakeWriter(), ("203.0.113.9", 4000)))
    finally:
        fox_mod.log_event = orig
    assert len(events) == 1
    return events[0]


def test_the_decoy_flags_http_and_carries_its_port():
    meta, kw = _run_fox(b"GET / HTTP/1.1\r\nHost: x:1911\r\n\r\n")
    assert meta["ics"] is False
    assert meta["phase"] == "http_on_ics_port"
    assert meta["dst_port"] == 1911
    assert kw["attack_type"] == "SCANNER"


def test_non_http_fox_bytes_are_unchanged():
    meta, _ = _run_fox(b"fox a 1 -1 fox hello\n")
    assert meta["phase"] == "fox_session"
    assert "ics" not in meta


def test_a_payload_that_merely_contains_http_is_not_a_request_line():
    """Defect guard: a bare substring search for HTTP would swallow real Fox frames."""
    assert not is_http_request_line(b"fox a 1 -1 fox hello\nnote=s:HTTP/1.1 get / \n")
    assert not is_http_request_line(b"\x00\x01GET / HTTP/1.1\r\n")
    assert not is_http_request_line(b"GET /\r\n")
    assert not is_http_request_line(b"HTTP/1.1 200 OK\r\n")
    assert is_http_request_line(b"POST /a?b=c HTTP/1.0\r\n")
    assert is_http_request_line(b"GET / HTTP/1.1\r\n")


def test_a_lowercase_method_is_still_a_request_line():
    """The original casing is unrecoverable from stored fox rows (no raw bytes kept), so
    the match must not depend on it."""
    assert is_http_request_line(b"get / http/1.1\r\n")
    assert is_http_request_line(b"get / HTTP/1.1\r\nHost: x\r\n")
    assert not is_http_request_line(b"get  / HTTP/1.1\r\n")


def test_the_http_branch_keeps_the_raw_bytes():
    """Defect: fox rows preserved only a lowercased 200-byte preview."""
    data = b"GET / HTTP/1.1\r\nHost: x:1911\r\n\r\n"
    _, kw = _run_fox(data)
    assert kw["raw"] == data


@pytest.mark.parametrize(
    "line",
    [
        b"GET / http/1.1\r\n",
        b"get / HTTP/1.1\r\n",
        b"Get / HtTp/1.0\r\n",
    ],
)
def test_case_is_folded_in_both_the_method_and_the_version(line):
    """Defect: the HTTP/ half silently lost its case-insensitivity between two commits."""
    assert is_http_request_line(line)


@pytest.mark.parametrize(
    "line",
    [
        b"GET / HTTP/2\r\n",
        b"GET / HTTP/2.0\r\n",
        b"GET / HTTP/1.\r\n",
        b"GET / HTTP/1.11\r\n",
        b"GET / HTTP/1.11",
        b"GET  / HTTP/1.1",
    ],
)
def test_other_versions_and_malformed_lines_are_not_request_lines(line):
    assert not is_http_request_line(line)


def test_a_request_line_ended_by_the_close_of_the_connection_is_still_a_request_line():
    """Defect: a request line had to end in a newline, so `GET / HTTP/1.1` followed by a close
    (no CRLF) fell through to the ICS path and wrote an ICS row for a web scanner. The end of
    the buffer terminates the line as a newline does."""
    assert is_http_request_line(b"GET / HTTP/1.1")
    assert is_http_request_line(b"get / http/1.0")
    assert not is_http_request_line(b"GET / HTTP/1.")
    assert not is_http_request_line(b"fox a 1 -1 fox hello GET / HTTP/1.1")
