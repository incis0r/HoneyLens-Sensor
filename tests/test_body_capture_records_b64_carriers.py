"""SAML lands on the decoys that share the body-capture path, so the shape is measured there.

Measured 30 days to 2026-11-18, own validation sources excluded: **all 100 SAML rows on the
fleet arrive on two decoys** — `netscaler` (95 rows, 67 sources, `/saml/login` POST and
`/cgi/samlauth`) and `fortigate-honeypot` (5). Zero on `hp_http`, which is the decoy that was
instrumented first, and zero on sharepoint, nginx and k8s.

`body_capture.capture` is the one function all of those already call, and it happens to hold
exactly what SAML needs: the **body** (HTTP-POST binding, which is 77 of the 87 SAMLRequest
rows) and the **path** (HTTP-Redirect binding puts the parameter in the query string). It also
already computes `body_truncated`, which is the flag the shape has to carry. One change here
covers every decoy that captures a body instead of nine extractors that will drift.

Headers are deliberately not visible here: Basic, NTLM, Negotiate and Bearer are covered by
the text rules on the verbatim wire form and by `hp_http`, so the two sources stay disjoint and
cannot double-record.
"""

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.honeypots.body_capture import capture

TRIGGER = "A" * 64 + "="
CVE = "CVE_2026_114938"


def _carriers(fields):
    return {r["carrier"] for r in fields.get("b64_carriers", [])}


def test_the_post_binding_is_measured_from_the_body():
    # 77 of 87 SAMLRequest rows on the fleet are a POST, so this is the common case.
    fields = capture(f"SAMLResponse={TRIGGER}".encode(), "/saml/login", "")
    assert "saml_response" in _carriers(fields)
    shape = fields["b64_carriers"][0]["shape"]
    assert (shape["len"], shape["mod4"]) == (65, 1)


def test_the_redirect_binding_is_measured_from_the_path():
    # `=` arrives as `%3D` here, which is the whole reason the grading reads a decoded shape.
    fields = capture(b"", "/cgi/samlauth?SAMLRequest=" + "A" * 64 + "%3D", "")
    assert "saml_request" in _carriers(fields)
    assert fields["b64_carriers"][0]["shape"]["len"] == 65


def test_a_soap_binary_security_token_is_measured():
    body = f"<wsse:BinarySecurityToken>{TRIGGER}</wsse:BinarySecurityToken>".encode()
    assert "binary_security_token" in _carriers(capture(body, "/_vti_bin/webs.asmx", "text/xml"))


def test_the_bodys_own_truncation_reaches_the_shape():
    """`SAMLRequest` reaches 7,660 characters on this fleet and `SAMLResponse` is larger, so
    this ceiling fires on real traffic — and a clipped length is not the sender's."""
    body = f"SAMLResponse={TRIGGER}".encode()
    clipped = capture(body, "/saml/login", "", max_capture=20)
    assert clipped["body_truncated"] is True
    assert all(r["shape"]["truncated"] is True for r in clipped["b64_carriers"])
    whole = capture(body, "/saml/login", "")
    assert all(r["shape"]["truncated"] is False for r in whole["b64_carriers"])


def test_a_path_shape_is_not_marked_truncated_by_the_body_ceiling():
    # The ceiling clips the body. The path arrives whole, and marking it clipped would throw
    # away a sound length.
    path = "/cgi/samlauth?SAMLRequest=" + "A" * 64 + "%3D"
    fields = capture(b"x" * 500, path, "", max_capture=10)
    assert fields["body_truncated"] is True
    assert [r["shape"]["truncated"] for r in fields["b64_carriers"]] == [False]


def test_an_ordinary_request_gains_no_field():
    # This runs on every captured body on every decoy; a key added to every event would be
    # pure weight.
    assert "b64_carriers" not in capture(b"user=admin&pass=hunter2", "/login", "")
    assert "b64_carriers" not in capture(b"", "/", "")
    assert "b64_carriers" not in capture(b"\x89PNG\r\n\x1a\n\xff\xfe", "/upload", "")


def test_a_binary_body_is_not_scanned_and_does_not_raise():
    fields = capture(b"\xff\xfe\x00\x01" * 8, "/", "")
    assert fields.get("body_encoding") == "binary"
    assert "b64_carriers" not in fields


def test_the_netscaler_shaped_request_is_labelled_end_to_end():
    """`/saml/login` POST is where 77 rows from 52 sources already arrive, 58 of them with no
    verdict at all."""
    fields = capture(f"SAMLResponse={TRIGGER}&RelayState=x".encode(), "/saml/login", "")
    hits = classify_event_row("POST /saml/login", "HTTP", fields)
    assert CVE in {t for t, _r, _s in hits}
    assert "java4shell_b64_fires_65" in {r for _t, r, _s in hits}


def test_the_scan_is_bounded_on_a_full_sized_body():
    import time

    body = (b"A" * 64 + b"=") * 1000 + b"SAMLResponse=" + b"A" * 1000
    start = time.perf_counter()
    capture(body, "/saml/login", "")
    assert (time.perf_counter() - start) < 0.25


def test_a_query_string_can_be_passed_separately():
    """aiohttp's `request.path` does **not** carry the query string — `request.path_qs` does —
    and `netscaler` and `fortigate-honeypot` both pass `request.path`. Those are the only two
    decoys that receive SAML, so without this the HTTP-Redirect binding would be invisible on
    exactly the surfaces it arrives at.

    A separate argument rather than asking them for `path_qs`: `path` also feeds
    `is_high_value`, and widening what that sees would change `body_high_value` on every decoy
    for an unrelated reason.
    """
    fields = capture(b"", "/cgi/samlauth", "", query="SAMLRequest=" + "A" * 64 + "%3D")
    assert _carriers(fields) == {"saml_request"}
    assert fields["b64_carriers"][0]["shape"]["len"] == 65


def test_the_query_argument_does_not_change_the_high_value_marker():
    plain = capture(b"x", "/cgi/samlauth", "")
    with_query = capture(b"x", "/cgi/samlauth", "", query="SAMLRequest=QQ%3D%3D")
    assert plain.get("body_high_value") == with_query.get("body_high_value")
