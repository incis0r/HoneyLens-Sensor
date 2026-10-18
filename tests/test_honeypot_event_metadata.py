"""Honeypot events must keep their structured fields — the POST body above all.

`honeypots/_base.log_event()` is the DB-direct path: every `BaseHoneypot` subclass and
the NGINX decoy write through it. It used to INSERT only the flat columns, so the whole
event dict was collapsed into `payload` (2 000 chars, usually a hand-built one-line
summary) and everything else was dropped on the floor.

The visible symptom was `POST / body_len=705` in `sensor_events.payload` with
`metadata` NULL: the NGINX honeypot had already captured the 705-byte body via
`honeypots/body_capture.py`, and the writer threw it away. A honeypot that records the
length of what an attacker sent, and not the thing itself, has kept the receipt and
binned the evidence.

These tests pin the contract end to end: the capture layer produces the body, the NGINX
event bridge carries it, and the writer persists it in `metadata`.

Port 1.0: `log_event` no longer talks to the database. It writes one JSON line
(`honeypots/sink.py`) and `ingest/honeypot.py` does the INSERTs on the host, so "the
writer" below is the pair of them — every assertion runs honeypot -> line -> ingest.
"""

import json
from pathlib import Path

import pytest

from honeylens.honeypots import sink
from honeylens.ingest import honeypot as ih


class _FakeCursor:
    """Records every execute() so a test can inspect the INSERT and its params.

    Port 1.0: the honeypot writes a line to the sink and the ingest does the INSERTs,
    so ``ingested()`` runs the ingest over whatever the honeypot wrote and returns the
    recorded statements. The assertions below are the 0.9 ones — they now hold across
    the whole path.
    """

    def __init__(self, log_dir: Path):
        self._log_dir = log_dir
        self._calls: list = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        self._calls.append((" ".join(sql.split()), params))

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def ingested(self) -> list:
        """Run the ingest over what the honeypot wrote so far; returns every execute()."""
        for path in sorted(self._log_dir.glob("*.json")):
            ih.process_file(self, str(path))
            path.unlink()
        return self._calls

    def sensor_event_insert(self):
        for sql, params in self.ingested():
            if "INSERT INTO sensor_events" in sql:
                return sql, params
        raise AssertionError("no sensor_events INSERT was issued")


@pytest.fixture()
def cursor(monkeypatch, tmp_path):
    """Point the sink at a temp dir and silence SIEM fan-out."""
    import honeylens.siem as siem

    monkeypatch.setattr(sink, "HONEYPOTNG_LOG_DIR", tmp_path)
    monkeypatch.setattr(siem, "forward_event_dict", lambda row: False)
    return _FakeCursor(tmp_path)


def _split_top_level(text):
    """Split a parenthesised, comma-separated list on its top-level commas.

    `NOW()` and `%s::inet` mean neither a naive `split(",")` nor a naive
    `split(")")` survives contact with this SQL.
    """
    depth, current, out = 0, "", []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        out.append(current.strip())
    return out


def _parenthesised(text):
    """Return the contents of the first balanced (...) group in `text`."""
    start = text.index("(")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
    raise AssertionError(f"unbalanced parentheses in {text!r}")


def _column_value(sql, params, column):
    """Resolve one named column of an INSERT to its value in the params tuple.

    Positions do not line up: the VALUES clause mixes placeholders with literals
    (`NOW()`, `0`), so the Nth column is not the Nth parameter. Count the
    placeholders that precede the column instead.
    """
    cols_part, values_part = sql.split(" VALUES ", 1)
    columns = _split_top_level(_parenthesised(cols_part))
    values = _split_top_level(_parenthesised(values_part))
    assert len(columns) == len(values), f"column/value count mismatch in {sql}"

    pos = columns.index(column)
    assert values[pos].startswith("%s"), (
        f"{column} is a literal in the VALUES clause, not a parameter"
    )
    return params[sum(1 for v in values[:pos] if v.startswith("%s"))]


def _metadata_of(cur):
    """Return the metadata column of the recorded INSERT, parsed."""
    sql, params = cur.sensor_event_insert()
    assert "metadata" in sql, "sensor_events INSERT does not write the metadata column"
    raw = _column_value(sql, params, "metadata")
    assert raw is not None, "metadata was written as NULL"
    return json.loads(raw)


# --------------------------------------------------------------- the writer


def test_log_event_persists_the_post_body(cursor):
    """The body an attacker sent survives into the row, not just its length."""
    from honeylens.honeypots._base import log_event

    body = "username=admin&password=Summer2024!&csrf=" + "a" * 600

    log_event(
        "nginx",
        ("203.0.113.9", 51344),
        {
            "phase": "request",
            "method": "POST",
            "path": "/",
            "body_len": len(body),
            "body_sample": body,
            "payload": f"POST / body_len={len(body)}",
            "dst_port": 8080,
        },
    )

    meta = _metadata_of(cursor)
    assert meta["body_sample"] == body
    assert meta["body_len"] == len(body)
    assert "password=Summer2024!" in meta["body_sample"]


def test_log_event_keeps_every_structured_field(cursor):
    """Not only the body: the fields a honeypot computed are the analysis material."""
    from honeylens.honeypots._base import log_event

    log_event(
        "nginx",
        ("203.0.113.9", 1),
        {
            "phase": "request",
            "method": "POST",
            "path": "/wp-login.php",
            "cve": "CVE-2026-42533",
            "indicators": ["chained_attack:3"],
            "attack_class": "cve-2026-42533",
            "payload": "POST /wp-login.php body_len=0",
            "dst_port": 8080,
        },
        attack_type="NGINX_CVE_2026_42533",
        severity="HIGH",
    )

    meta = _metadata_of(cursor)
    assert meta["cve"] == "CVE-2026-42533"
    assert meta["indicators"] == ["chained_attack:3"]
    assert meta["path"] == "/wp-login.php"


def test_log_event_survives_nul_bytes_in_a_body(cursor):
    """Attacker-supplied text reaches jsonb, where a NUL byte is a hard error."""
    from honeylens.honeypots._base import log_event

    log_event(
        "nginx",
        ("203.0.113.9", 1),
        {
            "method": "POST",
            "path": "/",
            "dst_port": 8080,
            "body_sample": "before\x00after",
            "payload": "POST / body_len=12",
        },
    )

    meta = _metadata_of(cursor)
    assert "\x00" not in json.dumps(meta)
    assert "before" in meta["body_sample"] and "after" in meta["body_sample"]


def test_payload_summary_still_written_for_the_events_list(cursor):
    """metadata is additive — the one-line summary the UI lists stays put."""
    from honeylens.honeypots._base import log_event

    log_event(
        "nginx",
        ("203.0.113.9", 1),
        {
            "method": "POST",
            "path": "/",
            "dst_port": 8080,
            "body_sample": "x=1",
            "payload": "POST / body_len=3",
        },
    )

    _sql, params = cursor.sensor_event_insert()
    assert "POST / body_len=3" in params


def test_a_body_larger_than_the_payload_column_is_not_truncated_to_it(cursor):
    """`payload` is capped at 2 000 chars; the body must not inherit that cap."""
    from honeylens.honeypots._base import log_event

    body = "A" * 9000
    log_event(
        "nginx",
        ("203.0.113.9", 1),
        {
            "method": "POST",
            "path": "/",
            "dst_port": 8080,
            "body_len": len(body),
            "body_sample": body,
            "payload": "POST / body_len=9000",
        },
    )

    assert len(_metadata_of(cursor)["body_sample"]) == 9000


# ------------------------------------------------------- the NGINX bridge


def test_nginx_event_bridge_carries_the_body_through(cursor):
    """hp_nginx read only `body_len` out of the engine event and dropped the rest."""
    from honeylens.honeypots.hp_nginx import HoneyLensEventLog

    body = '{"cmd":"id;cat /etc/passwd"}'
    HoneyLensEventLog(dst_port=8080, wire_protocol="HTTP").emit(
        {
            "src_ip": "203.0.113.9",
            "http": {
                "method": "POST",
                "path": "/",
                "headers": {},
                "body_len": len(body),
                "body_sample": body,
                "body_truncated": False,
            },
            "detection": {
                "attack_class": "none",
                "confidence": "none",
                "indicators": [],
                "matched": False,
            },
        }
    )

    meta = _metadata_of(cursor)
    assert meta["body_sample"] == body
    assert meta["body_len"] == len(body)
    assert meta["body_truncated"] is False


def test_nginx_event_bridge_carries_a_binary_body(cursor):
    """A binary exploit payload arrives base64-encoded; it must survive as such."""
    from honeylens.honeypots.hp_nginx import HoneyLensEventLog

    HoneyLensEventLog(dst_port=8080, wire_protocol="HTTP").emit(
        {
            "src_ip": "203.0.113.9",
            "http": {
                "method": "POST",
                "path": "/",
                "headers": {},
                "body_len": 5,
                "body_sample_b64": "AAEC//4=",
                "body_encoding": "binary",
            },
            "detection": {
                "attack_class": "none",
                "confidence": "none",
                "indicators": [],
                "matched": False,
            },
        }
    )

    meta = _metadata_of(cursor)
    assert meta["body_sample_b64"] == "AAEC//4="
    assert meta["body_encoding"] == "binary"


def test_nginx_bridge_without_a_body_writes_no_body_keys(cursor):
    """A GET must not gain empty body fields — absent and empty differ in analysis."""
    from honeylens.honeypots.hp_nginx import HoneyLensEventLog

    HoneyLensEventLog(dst_port=8080, wire_protocol="HTTP").emit(
        {
            "src_ip": "203.0.113.9",
            "http": {"method": "GET", "path": "/", "headers": {}, "body_len": 0},
            "detection": {
                "attack_class": "none",
                "confidence": "none",
                "indicators": [],
                "matched": False,
            },
        }
    )

    meta = _metadata_of(cursor)
    assert "body_sample" not in meta
    assert meta["body_len"] == 0


# ---------------------------------------------------------- the HTTP decoy


def test_http_honeypot_captures_a_body_beyond_the_old_8k_cap():
    """hp_http truncated at 8 192 chars of its own; body_capture's ceiling governs."""
    from honeylens.honeypots.body_capture import MAX_CAPTURE
    from honeylens.honeypots.hp_http import HTTPHoneypot

    body = "p=" + "B" * 20000
    raw = (
        f"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n\r\n{body}"
    ).encode()

    parsed = HTTPHoneypot._parse_request(HTTPHoneypot.__new__(HTTPHoneypot), raw)
    assert len(parsed["body"]) == len(body)
    assert len(body) < MAX_CAPTURE, "test body must fit under the capture ceiling"


def test_http_honeypot_keeps_credentials_in_the_body():
    """The credential is the evidence — see honeypots/body_capture.py."""
    from honeylens.honeypots.hp_http import HTTPHoneypot

    raw = (
        b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 35\r\n\r\n"
        b"username=admin&password=Summer2024!"
    )
    parsed = HTTPHoneypot._parse_request(HTTPHoneypot.__new__(HTTPHoneypot), raw)
    assert parsed["body"] == "username=admin&password=Summer2024!"


# ------------------------------------------------------------ classification


def test_classifier_reads_the_captured_body():
    """Attacks that live in the body must still be classified.

    The honeypots put the body in `body_sample` (body_capture's field name), while the
    classifier only harvested `body`. Every honeypot on the capture path — nginx, K8s,
    PAN-OS, FortiGate — was therefore handing the rules a body they never looked at.
    """
    from honeylens.classification.attack_classifier import classify_event_row

    hits = classify_event_row(
        payload="POST /upload body_len=42",
        protocol="HTTP",
        metadata={
            "dst_port": 8080,
            "method": "POST",
            "path": "/upload",
            "body_sample": "file=../../../../etc/passwd",
        },
    )
    assert hits, "a traversal in the body produced no classification"
    assert any("../" in h[2] or "etc/passwd" in h[2] for h in hits)


def test_log_event_classifies_when_the_honeypot_did_not(cursor):
    """DB-direct honeypots never reached the central classifier.

    `classify_event_row()` was only ever called from `ingest/honeypot.py` and
    `ingest/ebpf.py`. Everything writing through `log_event` — hp_nginx and every
    `BaseHoneypot` subclass — carried whatever attack_type it worked out for itself,
    and nothing else. A honeypot with no opinion produced a row with no attack type,
    however plainly the request said what it was: an AnyConnect enumeration campaign
    put ~145 000 such events through :8443 over two weeks, every one blank.
    """
    from honeylens.honeypots._base import log_event

    log_event(
        "nginx",
        ("203.0.113.9", 1),
        {
            "method": "POST",
            "path": "/",
            "dst_port": 8443,
            "body_sample": '<config-auth client="vpn" type="init">',
            "payload": "POST / body_len=38",
        },
        proto="HTTPS",
    )  # no attack_type — the honeypot had no opinion

    sql, params = cursor.sensor_event_insert()
    assert _column_value(sql, params, "attack_types") == "VPN_RECON"


def test_log_event_records_the_matching_rule_in_attack_patterns(cursor):
    """The rule name is what makes a hit reviewable; a bare type is not enough."""
    from honeylens.honeypots._base import log_event

    log_event(
        "nginx",
        ("203.0.113.9", 1),
        {
            "method": "POST",
            "path": "/",
            "dst_port": 8443,
            "body_sample": '<config-auth client="vpn" type="init">',
            "payload": "POST / body_len=38",
        },
        proto="HTTPS",
    )

    rules = [p for sql, p in cursor.ingested() if "INSERT INTO attack_patterns" in sql]
    assert rules, "no attack_patterns row was written for a classified event"
    assert any("cisco_anyconnect_auth_init" in str(p) for p in rules)


def test_log_event_leaves_unremarkable_traffic_unclassified(cursor):
    """Classifying everything is the same failure as classifying nothing."""
    from honeylens.honeypots._base import log_event

    log_event(
        "nginx",
        ("203.0.113.9", 1),
        {
            "method": "GET",
            "path": "/",
            "dst_port": 8443,
            "payload": "GET / body_len=0",
        },
        proto="HTTPS",
    )

    sql, params = cursor.sensor_event_insert()
    assert _column_value(sql, params, "attack_types") is None


def test_honeypot_classification_is_not_overridden(cursor):
    """When the honeypot did classify, its verdict is higher-fidelity than a regex
    guess and must survive."""
    from honeylens.honeypots._base import log_event

    log_event(
        "wago",
        ("203.0.113.9", 1),
        {
            "method": "POST",
            "path": "/wbm/tcpip.php",
            "dst_port": 8090,
            "payload": "POST /wbm/tcpip.php",
            "rule": "wago_network_reconfigure",
        },
        attack_type="WAGO_CONTROL_WRITE",
        severity="CRITICAL",
    )

    sql, params = cursor.sensor_event_insert()
    assert "WAGO_CONTROL_WRITE" in _column_value(sql, params, "attack_types")


def test_classifier_body_target_is_bounded():
    """A 64 KB body must not be handed to every rule in full — that is CPU we pay
    on every ingested event, and the exploit shape is at the head."""
    from honeylens.classification.attack_classifier import _BODY_CLASSIFY_BYTES
    from honeylens.honeypots.body_capture import MAX_CAPTURE

    assert _BODY_CLASSIFY_BYTES < MAX_CAPTURE
