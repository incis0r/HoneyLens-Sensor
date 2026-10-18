"""`HTTPResponder` and `hp_elasticsearch` must read the body and send it on verbatim.

Measured over 7 days on 2026-10-25, after the ingest side was already fixed: the
`honeypotng` source took 1 612 POSTs across sensor-a, sensor-b, sensor-c and prod and wrote
`full_payload` for **two of them**, while `metadata.body_len` was present on 529. The
body was being captured and then dropped on the floor, which is the same finding that
opened this work for the k8s and FortiGate decoys — and the reason is two defects here:

* a single `reader.read(16384)`, under a comment reading "may need multiple reads for
  large POSTs", so a body in a second TCP segment was never read at all;
* the event carried `raw` — sanitised, decoded, truncated — and never `raw_hex`, which
  is the only field `ingest/honeypot.py` promotes into `full_payload`.

`hp_elasticsearch` read once into 8 KiB and emitted neither.
"""

from __future__ import annotations

import asyncio
import json

import pytest


class _Reader:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def read(self, n):
        return self._chunks.pop(0)[:n] if self._chunks else b""


class _Writer:
    def __init__(self):
        self.written = b""

    def write(self, data):
        self.written += data

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass

    def get_extra_info(self, *_a, **_k):
        return None


def _events(tmp_path, monkeypatch, module, run):
    """Point the decoy's log directory at tmp_path and return the events it wrote."""
    monkeypatch.setattr(module, "HONEYPOTNG_LOG_DIR", str(tmp_path), raising=False)
    asyncio.run(run())
    out = []
    for f in tmp_path.rglob("*.json"):
        out += [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    return out


# ------------------------------------------------------------------ HTTPResponder


@pytest.fixture
def monolith():
    from honeylens.honeypots import honeypot as hp

    return hp


def test_a_post_body_in_a_second_segment_is_captured(monolith, tmp_path, monkeypatch):
    """The defect: headers in one segment, body in the next, body never read."""
    body = b'<?php system($_GET["c"]); ?>' + b"A" * 900
    head = b"POST /upload.php HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body)
    r = _Reader([head, body])

    events = _events(
        tmp_path,
        monkeypatch,
        monolith,
        lambda: monolith.HTTPResponder().handle(r, _Writer(), 8080, ("203.0.113.9", 4444)),
    )
    assert events, "no event written"
    e = events[0]
    assert e.get("method") == "POST"
    assert e.get("body_size") == len(body), f"body_size={e.get('body_size')} of {len(body)}"
    assert "system($_GET" in (e.get("body") or ""), "the body did not reach the event"


def test_the_verbatim_bytes_travel_as_raw_hex(monolith, tmp_path, monkeypatch):
    """`raw_hex` is the only field the ingest turns into `full_payload`."""
    body = b"\x00\x01\xfe\xff" + b"payload-marker"
    head = b"POST /x HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body)
    r = _Reader([head, body])

    events = _events(
        tmp_path,
        monkeypatch,
        monolith,
        lambda: monolith.HTTPResponder().handle(r, _Writer(), 8080, ("203.0.113.9", 4444)),
    )
    raw = [bytes.fromhex(e["raw_hex"]) for e in events if e.get("raw_hex")]
    assert raw, "nothing would reach full_payload"
    assert raw[0] == head + body, "what travels is not what arrived"
    assert b"\x00\x01\xfe\xff" in raw[0], "non-UTF-8 bytes were lost on the way"


def test_a_get_still_answers_without_waiting(monolith, tmp_path, monkeypatch):
    """A GET promises no body; waiting for one would stall every scan."""
    w = _Writer()
    r = _Reader([b"GET /server-status HTTP/1.1\r\nHost: x\r\n\r\n"])
    events = _events(
        tmp_path,
        monkeypatch,
        monolith,
        lambda: monolith.HTTPResponder().handle(r, w, 8080, ("203.0.113.9", 4444)),
    )
    assert events and events[0].get("method") == "GET"
    assert b"HTTP/1.1 200" in w.written, "the decoy went silent on a GET"


def test_the_existing_fields_are_unchanged(monolith, tmp_path, monkeypatch):
    """This fix adds a field; it must not drop what the hunting queries already read."""
    r = _Reader([b"POST /a?b=1 HTTP/1.1\r\nUser-Agent: curl/8\r\nContent-Length: 2\r\n\r\n", b"hi"])
    events = _events(
        tmp_path,
        monkeypatch,
        monolith,
        lambda: monolith.HTTPResponder().handle(r, _Writer(), 8080, ("203.0.113.9", 4444)),
    )
    e = events[0]
    for field in (
        "phase",
        "raw",
        "method",
        "path",
        "query_string",
        "headers",
        "body",
        "body_size",
        "user_agent",
        "content_length",
        "is_encrypted",
    ):
        assert field in e, f"{field} disappeared from the event"
    assert e["user_agent"] == "curl/8"
    assert e["query_string"] == "b=1"


# ------------------------------------------------------------------ elasticsearch


def _es_events(body, path=b"/_search"):
    """Run the elasticsearch decoy over a split request; return its log_event calls."""
    from honeylens.honeypots import hp_elasticsearch as es

    head = (
        b"POST " + path + b" HTTP/1.1\r\nContent-Type: application/json\r\n"
        b"Content-Length: %d\r\n\r\n" % len(body)
    )
    seen = []
    real = es.log_event

    def spy(protocol, peer, data, **kw):
        seen.append({"data": data, "kw": kw})
        return {}

    es.log_event = spy
    try:
        asyncio.run(
            es.ElasticsearchHoneypot().handle_connection(
                _Reader([head, body]), _Writer(), ("203.0.113.9", 5555)
            )
        )
    finally:
        es.log_event = real
    return seen, head + body


def test_elasticsearch_captures_a_search_body():
    """5 POSTs on sensor-a in 7 days, none with a body or even a body length."""
    body = b'{"query":{"script":{"script":"java.lang.Runtime.getRuntime().exec(id)"}}}'
    seen, _whole = _es_events(body)

    assert seen, "no event at all"
    for ev in seen:
        assert ev["data"].get("body_len") == len(body), f"{ev['data'].get('phase')} lost the body"
        assert "getRuntime" in (ev["data"].get("body_sample") or "")


def test_elasticsearch_passes_the_whole_request_as_raw():
    """`raw=` is the documented way in and wins over the body-only bytes log_event would
    otherwise derive, so `full_payload` ends up holding headers plus body."""
    body = b'{"query":{"match_all":{}}}'
    seen, whole = _es_events(body)

    for ev in seen:
        assert ev["kw"].get("raw") == whole, f"{ev['data'].get('phase')} did not pass the request"


def test_elasticsearch_leaves_the_payload_body_to_log_event():
    """log_event appends the body to `payload` itself once capture fields are present.
    Doing it here as well put the body in twice -- measured on sensor-b as payload_len 3187
    with the marker appearing twice for a 1586-byte body."""
    marker = "UNIQUEMARKER12345"
    body = f'{{"q":"{marker}"}}'.encode()
    seen, _whole = _es_events(body)

    for ev in seen:
        payload = ev["data"].get("payload") or ""
        assert marker not in payload, (
            f"{ev['data'].get('phase')}: the decoy must leave the body to log_event, "
            f"got payload={payload!r}"
        )
        assert payload.startswith("POST /"), f"payload should be the bare summary, got {payload!r}"


def test_the_higher_severity_search_event_carries_the_evidence_too():
    """Two events are logged per /_search by design: ES_SCAN (LOW) and ES_DATA_ACCESS
    (MEDIUM). The MEDIUM one is what a hunt looks at, and it used to carry
    request_text[:2000] with no capture fields, so it reached no full_payload."""
    body = b'{"query":{"script":{"script":"exfil"}}}'
    seen, whole = _es_events(body)

    phases = [ev["data"].get("phase") for ev in seen]
    assert "search_query" in phases, f"the MEDIUM event is gone: {phases}"
    medium = next(ev for ev in seen if ev["data"].get("phase") == "search_query")
    assert medium["data"].get("body_len") == len(body)
    assert medium["kw"].get("raw") == whole
    assert medium["kw"].get("severity") == "MEDIUM"
