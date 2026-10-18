"""The decoy records the shape of every Base64 carrier, through one method, at both sites.

`hp_http` and `honeypot_k8s` each grew their own Basic-auth extractor and they diverged: the
k8s one reduced the value to the word `"present"`, which is why the 14 rows the 2026-11-18
actor left on four decoy surfaces are stored and cannot be labelled. `hp_http` itself builds an
event in two places — the HTTP/1.1 path and `_h2c_request_record` — so the carrier logic is one
static method called twice, not two copies that will drift the same way.
"""

from honeylens.honeypots.hp_http import HTTPHoneypot

TRIGGER = "A" * 64 + "="


def _carriers(records, name):
    return [r for r in records if r["carrier"] == name]


def test_an_ntlm_header_is_recorded():
    records = HTTPHoneypot._b64_carriers({"authorization": f"NTLM {TRIGGER}"})
    assert _carriers(records, "ntlm")[0]["shape"]["len"] == 65


def test_a_percent_encoded_saml_parameter_is_recorded_decoded():
    # The carrier the text rules cannot grade: on the wire this is 67 characters, and the token
    # is 65. Recording the wire length would have been recording the encoding.
    records = HTTPHoneypot._b64_carriers({}, path="/x?SAMLRequest=" + "A" * 64 + "%3D")
    shape = _carriers(records, "saml_request")[0]["shape"]
    assert (shape["len"], shape["mod4"]) == (65, 1)


def test_a_soap_binary_security_token_is_recorded():
    body = f"<wsse:BinarySecurityToken>{TRIGGER}</wsse:BinarySecurityToken>"
    records = HTTPHoneypot._b64_carriers({}, body=body)
    assert _carriers(records, "binary_security_token")[0]["shape"]["len"] == 65


def test_the_body_ceiling_only_discounts_the_token_it_could_have_cut():
    """Narrowed 2026-11-18 (evening): this used to assert that **every** body-derived shape
    inherits `body_truncated`, which was the cheapest bypass in the set — trigger first, then
    padding until the ceiling fires, and a token captured whole had its grading suppressed.

    The ceiling still never touches headers or the query string. Within the body it now applies
    per token: an element that found its closing `<`, or a parameter followed by `&`, is whole
    whatever happened to the rest.
    """
    complete = f"<wsse:BinarySecurityToken>{TRIGGER}</wsse:BinarySecurityToken>"
    records = HTTPHoneypot._b64_carriers(
        {"authorization": f"NTLM {TRIGGER}"}, body=complete, body_truncated=True
    )
    assert _carriers(records, "ntlm")[0]["shape"]["truncated"] is False
    assert _carriers(records, "binary_security_token")[0]["shape"]["truncated"] is False

    # No closing `<`: this one really could have been cut, so its length is discounted.
    cut = f"<wsse:BinarySecurityToken>{TRIGGER}"
    records = HTTPHoneypot._b64_carriers({}, body=cut, body_truncated=True)
    assert _carriers(records, "binary_security_token")[0]["shape"]["truncated"] is True


def test_a_request_with_no_base64_carrier_records_nothing():
    assert (
        HTTPHoneypot._b64_carriers({"user-agent": "curl/8.5.0"}, path="/?a=1", body="b=2") is None
    )


def test_the_h2_record_site_populates_the_field_too():
    record = HTTPHoneypot()._h2c_request_record(
        {
            "method": "GET",
            "path": "/",
            "version": "HTTP/1.1",
            "query_string": None,
            "headers": {"authorization": f"Basic {TRIGGER}"},
            "body": None,
            "body_raw": b"",
        }
    )
    assert _carriers(record["b64_carriers"], "basic")[0]["shape"]["mod4"] == 1


def test_the_two_sources_do_not_record_the_same_token_twice():
    """`hp_http` keeps the query string in `path` as well as in its own field, and
    `body_capture.capture` now reads the path. If this decoy also extracted from
    `query_string`, every SAML parameter on it would be stored twice.

    The split is by source and not by deduplication: `capture` owns the body and the path,
    this decoy owns the headers. Nothing can appear in both.
    """
    from honeylens.honeypots.body_capture import capture

    path = "/saml/login?SAMLRequest=" + "A" * 64 + "%3D"
    body = f"SAMLResponse={TRIGGER}".encode()
    headers = {"authorization": f"Basic {TRIGGER}"}

    from_capture = capture(body, path, "").get("b64_carriers", [])
    from_headers = HTTPHoneypot._b64_carriers(headers) or []
    everything = from_capture + from_headers

    keys = [(r["carrier"], r.get("segment"), tuple(sorted(r["shape"].items()))) for r in everything]
    assert len(keys) == len(set(keys)), "a token was recorded by both sources"
    assert {r["carrier"] for r in everything} == {"saml_request", "saml_response", "basic"}


def test_the_h2_site_still_reads_the_path_because_nothing_captures_a_body_there():
    """`_h2c_request_record` does not call `capture`, so it has to read the path itself — and
    it must record each token once, not once per source."""
    record = HTTPHoneypot()._h2c_request_record(
        {
            "method": "GET",
            "path": "/saml/login?SAMLRequest=" + "A" * 64 + "%3D",
            "version": "HTTP/1.1",
            "query_string": "SAMLRequest=" + "A" * 64 + "%3D",
            "headers": {"authorization": f"Basic {TRIGGER}"},
            "body": None,
            "body_raw": b"",
        }
    )
    carriers = record["b64_carriers"]
    assert {r["carrier"] for r in carriers} == {"saml_request", "basic"}
    assert len(carriers) == 2, "the query string reached the extractor twice"
