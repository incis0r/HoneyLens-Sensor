"""The HTTP/2 cleartext preface gets a verdict that names the behaviour.

Measured 2026-11-04, 30 days. `method='PRI'` rows, every one of them unlabelled:

| sensor | :2379 | :80 | :8001 | :6443 | :8080 | :10250 | :3000 |
|---|---|---|---|---|---|---|---|
| `sensor-a`  | 2,249 | 321 | 68 | 42 | 40 | 34 | 2 |
| `sensor-b` | 2,505 |  -  | 66 | 50 | 39 | 32 |  - |

2,756 rows on `sensor-a` from 33-38 distinct sources, and the single largest block of
unlabelled events in the fleet review. The one exception is :9200, which the Elasticsearch
decoy labels itself.

This is the decoy-side counterpart of Suricata rule 9026706, written in Phase A for exactly
this preface, and it follows that rule's two decisions. The verdict names the **behaviour** --
a client sending `PRI * HTTP/2.0` to a server that never advertised h2 -- and it claims **no
CVE**: the preface is the entry point of CVE-2026-49975's h2c variant, but on its own it is a
client assuming h2, which internet-wide scanners do constantly. When the bomb follows,
`honeypots/h2bomb.py` flags the CVE on its own evidence.

`PRI` is deliberately absent from `_HTTP_METHODS`: it is not an HTTP/1.1 method, and RFC 7540
chose a method name no HTTP/1.1 server would accept precisely so the preface is unmistakable.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.mitre_mapping import get_mitre_mapping
from honeylens.classification.scoring import get_severity

RULE = "http2_h2c_prior_knowledge_preface"
VERDICT = "PROTO_ABUSE"

# The 24-byte preface, then a SETTINGS frame -- copied from a real `sensor-a` row's raw_hex.
PREFACE_HEX = "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a000000040000000000"
PREFACE_TEXT = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# What the decoys actually store: the request line truncated to two tokens, the method and
# path split out into metadata, and the bytes kept in raw_hex.
DECOY_PAYLOAD = "PRI *"
DECOY_METADATA = {
    "path": "*",
    "port": 2379,
    "method": "PRI",
    "peer_ip": "167.94.146.61",
    "raw_hex": PREFACE_HEX,
    "dst_port": 2379,
    "protocol": "http",
}


def _rules(hits):
    return {h[1] for h in hits}


def _verdicts(hits):
    return {h[0] for h in hits}


# ---------------------------------------------------------------------------
# It fires on what the decoys store
# ---------------------------------------------------------------------------


def test_the_row_the_decoys_actually_write_gets_the_verdict():
    hits = classify_event_row(payload=DECOY_PAYLOAD, protocol="http", metadata=DECOY_METADATA)

    assert RULE in _rules(hits)
    assert VERDICT in _verdicts(hits)


def test_the_full_preface_in_the_payload_gets_the_verdict():
    hits = classify_event_row(payload=PREFACE_TEXT, protocol="http", metadata={"dst_port": 80})

    assert RULE in _rules(hits)


def test_the_bytes_are_enough_when_the_request_line_was_truncated():
    """The hex carries the preface even when `payload` kept only a fragment of it."""
    hits = classify_event_row(
        payload="PRI", protocol="http", metadata={"raw_hex": PREFACE_HEX, "dst_port": 8080}
    )

    assert RULE in _rules(hits)


def test_an_empty_payload_classifies_to_nothing_by_design():
    """`classify_event_row` returns early on an empty payload, so the hex is never the only
    evidence available. Measured: no `:2379` row has an empty payload (0 on `sensor-a`, `prod` and
    `sensor-b`), so this costs no coverage -- it is recorded here so the next reader does not
    mistake it for a gap."""
    assert classify_event_row(payload="", protocol="http", metadata={"raw_hex": PREFACE_HEX}) == []


@pytest.mark.parametrize("port", [2379, 80, 8001, 6443, 8080, 10250, 3000, 9200])
def test_it_is_not_gated_on_a_port(port):
    """Measured on seven ports on one sensor. A port list would be wrong by next week."""
    md = dict(DECOY_METADATA, dst_port=port, port=port)

    assert RULE in _rules(classify_event_row(payload=DECOY_PAYLOAD, protocol="http", metadata=md))


def test_it_fires_without_any_metadata_at_all():
    """A backfilled row whose metadata was never stored still has its payload."""
    hits = classify_event_row(payload=PREFACE_TEXT, protocol=None, metadata=None)

    assert RULE in _rules(hits)


# ---------------------------------------------------------------------------
# It does not fire on anything else
# ---------------------------------------------------------------------------


def test_an_ordinary_request_does_not_get_it():
    md = {"method": "GET", "path": "/v3/kv/range", "dst_port": 2379}

    hits = classify_event_row(payload="GET /v3/kv/range HTTP/1.1", protocol="http", metadata=md)

    assert RULE not in _rules(hits)


@pytest.mark.parametrize(
    "payload",
    [
        "GET /PRI HTTP/1.1",
        "POST /api/pri * HTTP/1.1",
        '{"user": "PRI *", "note": "PRI * HTTP/2.0 mentioned in a body"}',
        "PRIORITY * HTTP/2.0",
    ],
)
def test_the_word_pri_in_a_request_is_not_a_preface(payload):
    """The preface is the first thing on the connection, not a substring anywhere in it."""
    hits = classify_event_row(payload=payload, protocol="http", metadata={"dst_port": 80})

    assert RULE not in _rules(hits)


def test_a_tls_client_hello_does_not_get_it():
    """`160301...` is a TLS record. It is a separate defect that the decoy writes a request
    line for one at all (157 rows on `sensor-a`, 210 on `sensor-b`) -- it must not become an h2c
    preface on top of that."""
    hits = classify_event_row(
        payload="",
        protocol="http",
        metadata={"raw_hex": "1603010100010000fc0303", "dst_port": 2379},
    )

    assert RULE not in _rules(hits)


# ---------------------------------------------------------------------------
# The claim it makes, and the claims it does not
# ---------------------------------------------------------------------------


def test_the_verdict_claims_no_cve():
    """Phase A's lesson, in the classifier layer: 9026706 exists because binding the preface
    to a CVE would have deleted a month of real detection. The verdict here keeps the signal
    and drops the claim."""
    hits = classify_event_row(payload=DECOY_PAYLOAD, protocol="http", metadata=DECOY_METADATA)

    for attack_type, rule_name, _snippet in hits:
        assert "CVE" not in attack_type.upper(), attack_type
        assert "49975" not in rule_name, rule_name


def test_the_verdict_names_no_product():
    """`PANOS_CAPTIVE` on WordPress is what happens when a verdict names a product it only
    guessed at (review section 5.5). This one names what arrived."""
    assert "etcd" not in RULE
    assert "k8s" not in RULE
    assert "nginx" not in RULE


def test_it_is_scored_and_mapped():
    """A rule absent from scoring or MITRE shows as unscored and unmapped on the dashboard.
    `RECON` is the cautionary case: exactly one rule emits it, and it is in neither table, so
    a verdict that exists to say "this was only a probe" is scored the same as an attack."""
    severity = get_severity(VERDICT, RULE)

    assert severity in {"info", "low", "medium", "high", "critical"}
    assert severity in {"info", "low"}, (
        f"scanner noise should not outrank a real finding: {severity}"
    )
    assert get_mitre_mapping(VERDICT, RULE), f"{VERDICT} has no MITRE mapping"


def test_it_appears_once():
    hits = classify_event_row(payload=DECOY_PAYLOAD, protocol="http", metadata=DECOY_METADATA)

    assert [h[1] for h in hits].count(RULE) == 1
