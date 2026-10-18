"""The Express decoy and the verdict it is meant to produce.

Bait for NODE2SHELL / CVE-2026-111497. Measured 2026-10-30 and again 2026-11-01: the fleet has
recorded zero Brotli-encoded request bodies against 18,300 / 15,600 / 2,122 rows on
sensor-a / sensor-b / sensor-c that merely declare `Accept-Encoding: ...br`. The query works, so the zero
is real -- but the fleet also offered no Node surface at all, which is the half these tests cover.
"""

from __future__ import annotations

import asyncio

import pytest

from honeylens.classification import text_rules as tr
from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY
from honeylens.honeypots.hp_express import ExpressHoneypot

# --------------------------------------------------------------------------- the header read


@pytest.mark.parametrize(
    "header,expected",
    [
        ("br", ["br"]),
        ("BR", ["br"]),
        ("gzip, br", ["gzip", "br"]),
        ("br, gzip", ["br", "gzip"]),
        (" br ", ["br"]),
        ("gzip", ["gzip"]),
        ("deflate", ["deflate"]),
        ("", []),
        ("identity", []),
        # `brotli` is not a Content-Encoding token, and it is also the string our own ADB decoy
        # puts in its client banner -- a loose match on it returned 4,275 phantom hits on sensor-c.
        ("brotli", []),
        ("snappy", []),
    ],
)
def test_only_a_real_body_encoding_is_read_as_one(header, expected):
    assert ExpressHoneypot.declared_encodings({"content-encoding": header}) == expected


def test_accept_encoding_is_never_mistaken_for_the_bodys_encoding():
    """Accept-Encoding says what the client will take BACK. Thousands of ordinary requests a day
    carry `br` there; reading it as the body's encoding turns the whole fleet into one false
    positive."""
    assert ExpressHoneypot.declared_encodings({"accept-encoding": "gzip, deflate, br"}) == []


# --------------------------------------------------------------------------- the disguise


@pytest.fixture
def hp():
    return ExpressHoneypot()


def test_the_404_is_the_one_express_actually_sends(hp):
    """`Cannot GET /x` in a <pre>, plus the two finalhandler headers. An operator who
    fingerprints before firing checks exactly this."""
    out = hp._not_found("GET", "/admin").decode()
    assert out.startswith("HTTP/1.1 404 Not Found")
    assert "X-Powered-By: Express" in out
    assert "<pre>Cannot GET /admin</pre>" in out
    assert "Content-Security-Policy: default-src 'none'" in out
    assert "X-Content-Type-Options: nosniff" in out


def test_the_404_echoes_the_method_and_escapes_the_path(hp):
    out = hp._not_found("POST", "/<script>").decode()
    assert "Cannot POST /&lt;script&gt;" in out
    assert "<script>" not in out.split("<pre>")[1]


def test_the_index_advertises_that_compressed_bodies_are_accepted(hp):
    """The bait only works if a fingerprinting operator believes a br body would be inflated."""
    out = hp._index().decode()
    assert "HTTP/1.1 200 OK" in out
    assert "X-Powered-By: Express" in out
    assert "application/json" in out
    assert '"content-encoding":["br","gzip","deflate"]' in out
    assert "Vary: Accept-Encoding" in out


def test_a_compressed_body_is_answered_as_inflated_not_rejected(hp):
    """A 415 tells a careful operator the body was never inflated, which is the one thing the
    disguise must not say."""
    out = hp._ack(["br"]).decode()
    assert out.startswith("HTTP/1.1 200 OK")
    assert "415" not in out.splitlines()[0]
    assert '"accepted":true' in out
    assert '"encoding":"br"' in out


def test_responses_carry_a_weak_etag_like_expresss_default(hp):
    for body in (b"", b"{}", b"x" * 5000):
        etag = hp._etag(body)
        assert etag.startswith('W/"')
        assert etag.endswith('"')
    assert hp._etag(b"{}") != hp._etag(b"{ }"), "the etag must depend on the body"


# --------------------------------------------------------------------------- capture


def _run(coro):
    return asyncio.run(coro)


class _Reader:
    def __init__(self, data: bytes):
        self._data = data

    async def read(self, n: int) -> bytes:
        chunk, self._data = self._data[:n], self._data[n:]
        return chunk


class _Writer:
    def __init__(self):
        self.written = b""

    def write(self, data: bytes):
        self.written += data

    async def drain(self):
        pass


_BROTLI_BODY = bytes([0x1B, 0x3F, 0xFF, 0xFF, 0xDB, 0x4F, 0xE2, 0x99, 0x80, 0x00]) * 40


def _request(body: bytes, encoding: str | None = "br") -> bytes:
    headers = [
        "POST /api/v1/import HTTP/1.1",
        "Host: example.test",
        "User-Agent: node-fetch/3.3.2",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
    ]
    if encoding:
        headers.append(f"Content-Encoding: {encoding}")
    return ("\r\n".join(headers) + "\r\n\r\n").encode() + body


def test_the_compressed_bytes_are_captured_verbatim_and_never_decoded(hp, monkeypatch):
    """The bytes are the evidence. Decoding buys nothing -- the verdict comes from the header --
    and running a decoder over a payload crafted to break a decoder is not a thing to do here."""
    import honeylens.honeypots._base as base

    captured: list[dict] = []
    monkeypatch.setattr(base, "write_record", lambda rec: captured.append(rec))

    writer = _Writer()
    _run(hp.handle_connection(_Reader(_request(_BROTLI_BODY)), writer, ("203.0.113.9", 51000)))

    assert len(captured) == 1
    event = captured[0]["event"]
    assert event["body_len"] == len(_BROTLI_BODY)
    assert event["brotli_body"] is True
    assert event["body_encodings"] == ["br"]
    # Binary, so body_capture base64s it rather than mangling it into replacement characters.
    import base64

    assert base64.b64decode(event["body_sample_b64"]) == _BROTLI_BODY
    assert writer.written.startswith(b"HTTP/1.1 200 OK")


def test_the_decoy_emits_no_verdict_of_its_own(hp, monkeypatch):
    """A decoy verdict switches the central classifier OFF for that event -- measured on
    2026-10-26, when twenty PHP2Shell events kept only the nginx decoy's own overflow tag. The
    labelling belongs to node2shell_brotli_request_body in the central registry, so everything
    else in the body still gets classified."""
    import honeylens.honeypots._base as base

    captured: list[dict] = []
    monkeypatch.setattr(base, "write_record", lambda rec: captured.append(rec))
    _run(hp.handle_connection(_Reader(_request(_BROTLI_BODY)), _Writer(), ("203.0.113.9", 51000)))

    rec = captured[0]
    assert not rec.get("attack_type"), rec.get("attack_type")
    assert not rec.get("rules"), rec.get("rules")


def test_a_request_without_a_body_is_not_reported_as_encoded(hp, monkeypatch):
    import honeylens.honeypots._base as base

    captured: list[dict] = []
    monkeypatch.setattr(base, "write_record", lambda rec: captured.append(rec))
    plain = b"GET /api/v1/health HTTP/1.1\r\nHost: example.test\r\n\r\n"
    writer = _Writer()
    _run(hp.handle_connection(_Reader(plain), writer, ("203.0.113.9", 51000)))

    event = captured[0]["event"]
    assert "brotli_body" not in event
    assert "body_encodings" not in event
    assert b'"status":"ok"' in writer.written


def test_a_body_split_across_segments_is_fully_read(hp, monkeypatch):
    """One read() returns one TCP segment. Stopping there is how a decoy records a large POST
    as a small one -- the defect found on the honeypotng family in October."""

    class _Trickle(_Reader):
        async def read(self, n: int) -> bytes:
            chunk, self._data = self._data[: min(n, 64)], self._data[min(n, 64) :]
            return chunk

    import honeylens.honeypots._base as base

    captured: list[dict] = []
    monkeypatch.setattr(base, "write_record", lambda rec: captured.append(rec))
    body = _BROTLI_BODY * 5
    _run(hp.handle_connection(_Trickle(_request(body)), _Writer(), ("203.0.113.9", 51000)))
    assert captured[0]["event"]["body_len"] == len(body)


# --------------------------------------------------------------------------- the verdict


def _verdicts(event: dict) -> set[str]:
    import json

    payload = json.dumps(event, default=str)
    return {h[0] for h in classify_event_row(payload, "http", event)}


def test_the_rule_names_the_vector_and_not_the_cve():
    """A Brotli-encoded body is the precondition, not evidence that the decoder was driven out
    of bounds. Naming CVE-2026-111497 here would repeat the mistake the Suricata hunting fix
    exists to prevent."""
    event = {"headers": {"content-encoding": "br"}, "path": "/api/v1/import", "method": "POST"}
    found = _verdicts(event)
    assert "NODE2SHELL" in found, found
    assert not any("111497" in f for f in found), found


def test_accept_encoding_alone_produces_no_verdict():
    """Otherwise every ordinary browser request on the fleet becomes a NODE2SHELL hit: 18,300
    rows on sensor-a in 14 days declare `Accept-Encoding: ...br`."""
    event = {"headers": {"accept-encoding": "gzip, deflate, br"}, "path": "/", "method": "GET"}
    assert "NODE2SHELL" not in _verdicts(event)


def test_our_own_adb_decoy_banner_does_not_match():
    """`brotli` in the ADB decoy's feature list produced 4,275 phantom hits on sensor-c under a
    loose predicate. The rule requires the token `br`, not the substring."""
    event = {"client_banner": "host::features=shell_v2,cmd,stat_v2,brotli,abb_exec"}
    assert "NODE2SHELL" not in _verdicts(event)


def test_a_gzip_body_is_not_a_node2shell_hit():
    event = {"headers": {"content-encoding": "gzip"}, "path": "/api/v1/import", "method": "POST"}
    assert "NODE2SHELL" not in _verdicts(event)


def test_a_listed_encoding_still_matches():
    event = {"headers": {"content-encoding": "gzip, br"}, "path": "/x", "method": "POST"}
    assert "NODE2SHELL" in _verdicts(event)


def test_the_vector_type_is_scored():
    """An attack_type with no severity scores as unknown on the dashboard -- a verdict nobody
    sees. Medium, for the same reason PHP2SHELL is: it says the vector is present."""
    assert ATTACK_TYPE_SEVERITY["NODE2SHELL"] == "medium"


def test_the_rule_is_registered_once_under_a_stable_name():
    names = [n for _a, n, _p in tr._RULES]
    assert names.count("node2shell_brotli_request_body") == 1


def test_the_decoy_is_in_the_manifest_so_it_actually_gets_deployed():
    """A decoy module that no manifest entry names is a decoy that never runs: the image, the
    quadlet, the firewalld forward and the `honeylens-hp` command all follow from the manifest."""
    from honeylens.honeypots.manifest import HONEYPOTS

    entry = [h for h in HONEYPOTS if h.name == "express"]
    assert len(entry) == 1, "hp_express must be registered exactly once"
    hp_entry = entry[0]
    assert hp_entry.module == "honeylens.honeypots.hp_express"
    assert hp_entry.entry == "ExpressHoneypot"
    assert hp_entry.ports == (3000,)
    # 3000 is Express's own default port, and no other honeypot may bind it.
    others = [h for h in HONEYPOTS if h.name != "express" for b, _p in h.port_map if b == 3000]
    assert not others, others
