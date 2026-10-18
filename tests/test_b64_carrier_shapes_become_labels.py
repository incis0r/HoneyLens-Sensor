"""A recorded shape has to become a label, and it has to do it centrally.

The decoy records evidence; the classifier names the attack. That split is not stylistic — a
1.0 decoy verdict **suppresses** the central classifier rather than being supplemented by it
(`decoy-verdict-suppresses-classifier`), so a shape verdict emitted by `hp_http` would have
silently removed every other label those rows carry. The hook lives here instead.

It also has to run when `payload` is empty. `classify_event_row` returns `[]` on a falsy
payload, which is correct for a text rule and wrong for this: the evidence is in metadata.
Measured on the fleet — `sensor-f` holds 405 pre-parser rows whose payload is empty and whose
`attack_types` is empty for that reason alone.
"""

import base64

from honeylens.b64_shape import b64_shape, carrier_shapes
from honeylens.classification.attack_classifier import classify_event_row

CVE = "CVE_2026_114938"


def _types(hits):
    return {t for t, _r, _s in hits}


def _rules(hits):
    return {r for _t, r, _s in hits}


def _meta(**kw):
    return {"b64_carriers": carrier_shapes(**kw)}


def test_a_percent_encoded_saml_trigger_is_labelled():
    # The carrier a text rule cannot grade: `%3D` is three characters where the token has one.
    meta = _meta(query="SAMLRequest=" + "A" * 64 + "%3D")
    hits = classify_event_row("POST /saml/SSO HTTP/1.1", "HTTP", meta)
    assert CVE in _types(hits)
    assert "java4shell_b64_fires_65" in _rules(hits)


def test_the_label_names_the_carrier_it_came_from():
    meta = _meta(query="SAMLResponse=" + "A" * 64 + "%3D")
    snippets = [s for _t, r, s in classify_event_row("POST / HTTP/1.1", "HTTP", meta) if "b64" in r]
    assert snippets and "saml_response" in snippets[0]


def test_an_empty_payload_no_longer_discards_the_evidence():
    meta = _meta(headers={"authorization": "NTLM " + "A" * 64 + "="})
    assert CVE in _types(classify_event_row("", "HTTP", meta))
    assert CVE in _types(classify_event_row(None, "HTTP", meta))


def test_a_clipped_capture_is_not_labelled_on_length():
    meta = {
        "b64_carriers": carrier_shapes(query="SAMLResponse=" + "A" * 64 + "%3D", truncated=True)
    }
    assert CVE not in _types(classify_event_row("POST / HTTP/1.1", "HTTP", meta))


def test_real_traffic_is_not_labelled():
    ntlm = base64.b64encode(b"NTLMSSP\x00\x01\x00\x00\x00\x07\x82\x08\xa2" + bytes(24)).decode()
    legal = _meta(headers={"authorization": f"NTLM {ntlm}"})
    assert CVE not in _types(classify_event_row("GET / HTTP/1.1", "HTTP", legal))


def test_a_malformed_shape_field_cannot_break_classification():
    # The field arrives from a decoy's JSON and is therefore attacker-adjacent input. A shape
    # the hook cannot read must cost nothing, not raise inside ingest.
    for broken in ["not-a-list", [{"carrier": "x"}], [{"shape": None}], [], None, {"a": 1}]:
        assert classify_event_row("GET / HTTP/1.1", "HTTP", {"b64_carriers": broken}) is not None


def test_the_text_rules_still_run_alongside_the_hook():
    meta = _meta(headers={"authorization": "Basic " + "A" * 64 + "="})
    rules = _rules(
        classify_event_row(
            "GET / HTTP/1.1\r\nAuthorization: Basic " + "A" * 64 + "=\r\n\r\n", "HTTP", meta
        )
    )
    assert "java4shell_basic_auth_fires_65" in rules  # text path
    assert "java4shell_b64_fires_65" in rules  # shape path


def test_one_carrier_is_not_labelled_twice():
    meta = {
        "b64_carriers": [
            {"carrier": "basic", "shape": b64_shape("A" * 64 + "=")},
            {"carrier": "basic", "shape": b64_shape("A" * 64 + "=")},
        ]
    }
    hits = [
        h for h in classify_event_row("GET /", "HTTP", meta) if h[1].startswith("java4shell_b64")
    ]
    assert len(hits) == 1
