"""A captured body must reach `payload` and `full_payload`, not only `metadata`.

`ingest/honeypot.py` has two line formats. The `honeylens-event/1` envelope carries
`raw_hex` and the ingest stores it in `full_payload`. The legacy flat format — the
monolith, the Kubernetes decoy, the WAGO decoy, anything writing into the honeypotng log
directory — hardcoded `"raw": None` and left `payload` at the request line.

So a decoy could capture a body into its event and still store nothing a hunt can find.
Measured on one sensor on 2026-10-25: 133 052 rows under `source='honeypotng'` with no
`full_payload` at all, of which 435 POSTs had the body sitting in `metadata.body_sample`
the whole time. Six of those rows contained `PHP_SESSION_UPLOAD_PROGRESS`, which is to
say six requests of a live campaign were in the database and invisible to every query we
ran against it over four sweeps.

The property under test is reachability: given a legacy line that carries a captured
body, the body must appear in `payload` (what the event list, the exports and a SQL grep
read) and the bytes in `raw` (what becomes `full_payload`).
"""

from __future__ import annotations

import base64

from honeylens.ingest.honeypot import _normalise

FIELD = 'name="PHP_SESSION_UPLOAD_PROGRESS"'


def _line(**over) -> dict:
    """A legacy line as the Kubernetes decoy writes it for a POST on :8001."""
    body = f'--P2SB\r\n{FIELD}\r\n\r\n<?php system("id"); ?>\r\n--P2SB--'
    line = {
        "timestamp": "2026-10-23T03:51:30+00:00",
        "protocol": "http",
        "port": 8001,
        "dst_port": 8001,
        "peer_ip": "77.90.185.20",
        "peer_port": 44321,
        "method": "POST",
        "path": "/index.php",
        "user_agent": "Mozilla/5.0",
        "body_len": len(body),
        "body_sample": body,
    }
    line.update(over)
    return line


def test_the_body_reaches_the_payload_column():
    rec = _normalise(_line())
    assert FIELD in rec["payload"], "a hunt over `payload` still cannot find this request"
    assert "<?php" in rec["payload"]


def test_the_summary_line_is_still_first():
    """Reports and greps key on the `METHOD path` shape; it must not be displaced."""
    assert _normalise(_line())["payload"].startswith("POST /index.php")


def test_the_bytes_reach_full_payload():
    rec = _normalise(_line())
    assert rec["raw"] is not None, '"raw": None was the whole defect'
    assert FIELD.encode() in rec["raw"]


def test_a_binary_body_comes_back_unchanged():
    """Text bodies re-encode; binary ones must come back from base64 byte for byte, or
    `full_payload_hash` describes something we never held."""
    blob = bytes(range(256))
    rec = _normalise(
        _line(body_sample=None, body_sample_b64=base64.b64encode(blob).decode(), body_len=256)
    )
    assert rec["raw"] == blob


def test_a_binary_body_is_named_in_the_payload_not_pasted():
    """Base64 in the middle of a payload string reads as corruption; the bytes are in
    `full_payload`, which is where they are useful."""
    rec = _normalise(
        _line(body_sample=None, body_sample_b64=base64.b64encode(b"\x00\x01MZ").decode())
    )
    assert "binary body" in rec["payload"]
    assert "full_payload" in rec["payload"], "the reader must be told where the bytes are"


def test_a_decoy_that_sends_raw_hex_is_honoured():
    """The Kubernetes decoy now sends the whole request, headers included — better
    evidence than the body alone, so it wins."""
    raw = b"POST /index.php HTTP/1.1\r\nHost: x\r\n\r\nbody"
    rec = _normalise(_line(body_sample=None, raw_hex=raw.hex()))
    assert rec["raw"] == raw


def test_raw_hex_wins_when_a_decoy_sends_both():
    """The Kubernetes decoy sends both. `full_payload` should hold the request, not the
    body cut out of it — that is what `netscaler` and `sharepoint` already store, and it
    is what makes `full_payload_hash` worth checking."""
    raw = b"POST /index.php HTTP/1.1\r\nHost: x\r\n\r\nbody"
    rec = _normalise(_line(raw_hex=raw.hex()))
    assert rec["raw"] == raw
    assert rec["raw"].startswith(b"POST /index.php HTTP/1.1"), "the headers were dropped"


def test_a_line_with_no_body_is_unchanged():
    """'no body' and 'an empty body' are different observations, and a GET has neither
    a body nor a reason to grow a payload."""
    rec = _normalise(
        {
            "timestamp": "2026-10-23T03:51:30+00:00",
            "protocol": "http",
            "port": 8001,
            "peer_ip": "77.90.185.20",
            "method": "GET",
            "path": "/index.php",
        }
    )
    assert rec["payload"] == "GET /index.php"
    assert rec["raw"] is None


def test_a_length_alone_is_not_a_body():
    """`body_len` without a sample means the decoy measured the body and dropped it;
    storing an empty `full_payload` would claim we have it."""
    rec = _normalise(_line(body_sample=None, body_len=20000))
    assert rec["raw"] is None
    assert rec["payload"] == "POST /index.php User-Agent: Mozilla/5.0"


def test_undecodable_raw_hex_does_not_lose_the_event():
    """A bad field is a warning, not a dropped event."""
    rec = _normalise(_line(body_sample=None, raw_hex="not-hex"))
    assert rec["raw"] is None
    assert rec["payload"].startswith("POST /index.php")


def test_the_payload_body_is_bounded_and_says_so():
    """`payload` is stored on every event; the body stays whole in metadata."""
    rec = _normalise(_line(body_sample="A" * 40000, body_len=40000))
    assert len(rec["payload"]) < 40000
    assert "truncated" in rec["payload"]
    assert rec["metadata"]["body_sample"] == "A" * 40000, "metadata must keep it whole"


def test_the_source_name_is_unchanged():
    """This fixes what is stored, not where. `honeypotng` remains the catch-all name the
    legacy path assigns — it covers the monolith, the Kubernetes decoy and the WAGO one,
    which is worth knowing before reading per-source numbers as per-decoy ones."""
    assert _normalise(_line())["source"] == "honeypotng"


# ---------------------------------------------- end to end: line -> ingest -> columns


class _FakeCursor:
    """Records every execute() so a test can inspect the statements the ingest issues."""

    def __init__(self):
        self.calls: list = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def statements(self, needle: str) -> list:
        return [(sql, params) for sql, params in self.calls if needle in sql]


def _ingest(line: dict, monkeypatch, tmp_path):
    """Run the real ingest over one legacy log line."""
    import json

    import honeylens.siem as siem
    from honeylens.ingest import honeypot as ih

    monkeypatch.setattr(siem, "forward_event_dict", lambda row: False)
    path = tmp_path / "k8s_8001.json"
    path.write_text(json.dumps(line) + "\n")
    cursor = _FakeCursor()
    ih.process_file(cursor, str(path))
    return cursor


def test_the_ingest_writes_full_payload_for_a_legacy_line(monkeypatch, tmp_path):
    """`_normalise` returning the bytes is only half of it — the UPDATE has to fire."""
    cursor = _ingest(_line(), monkeypatch, tmp_path)

    updates = cursor.statements("SET full_payload")
    assert updates, "no full_payload UPDATE was issued; the bytes went nowhere"
    raw = updates[0][1][0]
    assert FIELD.encode() in bytes(raw)


def test_the_stored_hash_is_over_exactly_what_is_stored(monkeypatch, tmp_path):
    """Anyone must be able to recompute it against the column and see that nothing
    changed between capture and disk."""
    import hashlib

    cursor = _ingest(_line(), monkeypatch, tmp_path)
    raw, digest, _event_id = cursor.statements("SET full_payload")[0][1]
    assert hashlib.sha256(bytes(raw)).hexdigest() == digest


def test_the_inserted_payload_carries_the_body(monkeypatch, tmp_path):
    cursor = _ingest(_line(), monkeypatch, tmp_path)
    inserts = cursor.statements("INSERT INTO sensor_events")
    assert inserts, "the event row itself was not inserted"
    assert any(isinstance(p, str) and FIELD in p for p in inserts[0][1])


def test_a_body_less_line_issues_no_full_payload_update(monkeypatch, tmp_path):
    """Storing an empty `full_payload` would claim we hold a body we never read."""
    cursor = _ingest(_line(body_sample=None), monkeypatch, tmp_path)
    assert not cursor.statements("SET full_payload")
