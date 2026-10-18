"""Every carrier that hands attacker Base64 to `java.util.Base64`, through one primitive.

Ranked by what the fleet actually carries over 30 days to 2026-11-18, own validation sources
excluded:

| carrier                 | rows | sources | alphabet    | decoder            |
|-------------------------|-----:|--------:|-------------|--------------------|
| NTLM / Negotiate        |  168 |      68 | std, padded | `getDecoder()`     |
| SAMLRequest             |   87 |     ~58 | std, padded | `getDecoder()`     |
| SAMLResponse            |   13 |      12 | std, padded | `getDecoder()`     |
| Bearer JWT (`eyJ...`)   |   16 |       3 | base64url   | `getUrlDecoder()`  |

NTLM is ten times the JWT traffic and goes straight into the vulnerable decoder; the JWT path
measured safe (F4). That is why Bearer is extracted but graded down, and NTLM is not optional.
"""

import base64

from honeylens.b64_shape import carrier_shapes


def _carriers(records):
    return [r["carrier"] for r in records]


def _one(records, carrier):
    return next(r["shape"] for r in records if r["carrier"] == carrier)


# ------------------------------------------------------------------ headers
def test_basic_is_still_extracted():
    records = carrier_shapes(headers={"authorization": "Basic " + "A" * 64 + "="})
    assert _one(records, "basic")["len"] == 65


def test_ntlm_and_negotiate_are_extracted_from_either_header():
    ntlm = carrier_shapes(headers={"authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAA"})
    assert _one(ntlm, "ntlm")["decodes"] is True
    proxy = carrier_shapes(headers={"proxy-authorization": "Negotiate YIIJvQYGKwYBBQUCoIIJ"})
    assert _carriers(proxy) == ["negotiate"]


def test_a_real_ntlm_token_does_not_look_malformed():
    # All 168 NTLM/Negotiate rows on the fleet are `mod4 == 0`, length 44-56, across 68
    # sources. Not one is 65 characters, which is why carrier + exact length is two gates.
    records = carrier_shapes(headers={"authorization": "NTLM " + "T" * 52})
    shape = _one(records, "ntlm")
    assert (shape["mod4"], shape["pad_interior"]) == (0, False)


def _jwt(*parts: bytes) -> str:
    """A conformant JWT built from its parts: base64url, padding omitted per RFC 7515 §2.

    Built rather than pasted as a literal, for two reasons. A pasted blob reads like a
    captured credential and the secret scanner treats it as one, and spelling out the
    encoding is the point of these tests — the conformance is the thing under test.
    """
    return ".".join(base64.urlsafe_b64encode(part).decode().rstrip("=") for part in parts)


def test_bearer_is_split_into_its_dot_segments():
    token = _jwt(b'{"alg":"HS256"}', b'{"sub":"1"}', b"signature-bytes")
    records = carrier_shapes(headers={"authorization": f"Bearer {token}"})
    assert _carriers(records) == ["bearer", "bearer", "bearer"]
    assert [r["segment"] for r in records] == [0, 1, 2]
    # A conformant segment distinguishes nothing or base64url, never the standard alphabet.
    assert all(r["shape"]["alphabet"] in ("either", "url") for r in records)


def test_a_bearer_segment_using_the_standard_alphabet_is_the_reachable_case():
    # F4: `getUrlDecoder()` does not take the intrinsic. A JWT only reaches the vulnerable
    # decoder when the application hand-rolls `-_`->`+/` and re-pads into `getDecoder()`, and
    # the wire tell for that is a segment carrying `+`, `/` or `=` — non-conformant to
    # RFC 7515 section 2, which requires padding to be omitted.
    header = f"Bearer {_jwt(b'{"alg":"HS256"}')}.a+b/c=.x"
    records = carrier_shapes(headers={"authorization": header})
    assert _one_at(records, 1)["alphabet"] == "std"
    assert _one_at(records, 1)["pad_count"] == 1


def _one_at(records, segment):
    return next(r["shape"] for r in records if r.get("segment") == segment)


# ------------------------------------------------- transport decoding (measured trap)
def test_percent_encoded_padding_is_decoded_before_the_length_is_measured():
    # 52 SAMLRequest rows from 29 fleet sources read `mod4 == 2`, and none of them is
    # malformed: `%3D` is three characters where `=` is one. Measuring the wire form makes the
    # field noise, and worse — an attacker who sends a `%3D` tail reads back as `mod4 == 0`
    # and walks past a length rule.
    records = carrier_shapes(query="SAMLRequest=QQ%3D%3D&RelayState=x")
    shape = _one(records, "saml_request")
    assert (shape["len"], shape["mod4"], shape["decodes"]) == (4, 0, True)


def test_plus_stays_a_base64_character_and_does_not_become_a_space():
    # `+` means space in an HTML form body, but in a Base64-valued parameter it is data. A
    # conformant sender percent-encodes it as `%2B` and both readings agree; translating it
    # would corrupt the token's length and with it `mod4`.
    records = carrier_shapes(body="SAMLResponse=ab%2B/cd12")
    assert _one(records, "saml_response")["len"] == 8
    raw_plus = carrier_shapes(body="SAMLResponse=ab+/cd12")
    assert _one(raw_plus, "saml_response")["len"] == 8
    assert _one(raw_plus, "saml_response")["alphabet"] == "std"


# ------------------------------------------------------------------ SAML + SOAP
def test_saml_signature_is_only_a_carrier_inside_a_saml_exchange():
    # `Signature=` alone is too generic — `X-Amz-Signature=` is a hex SigV4 value. The
    # structural gate is the parameter list, which the extractor has and a regex rule does not:
    # that split is why `Signature` lives here and not in the rule set.
    inside = carrier_shapes(query="SAMLRequest=QQ%3D%3D&SigAlg=rsa-sha256&Signature=QUJD")
    assert "saml_signature" in _carriers(inside)
    outside = carrier_shapes(query="X-Amz-Signature=QUJD&other=1")
    assert _carriers(outside) == []


def test_binary_security_token_is_extracted_from_a_soap_body():
    body = (
        "<soap:Envelope><soap:Header><wsse:Security><wsse:BinarySecurityToken "
        'EncodingType="...#Base64Binary">' + "A" * 64 + "=</wsse:BinarySecurityToken>"
        "</wsse:Security></soap:Header></soap:Envelope>"
    )
    shape = _one(carrier_shapes(body=body), "binary_security_token")
    assert (shape["len"], shape["mod4"]) == (65, 1)


# ------------------------------------------------------------------ bookkeeping
def test_truncation_reaches_every_shape_the_call_produced():
    records = carrier_shapes(body="SAMLResponse=" + "A" * 400, truncated=True)
    assert all(r["shape"]["truncated"] is True for r in records)
    assert records


def test_nothing_in_nothing_out():
    assert carrier_shapes() == []
    assert carrier_shapes(headers={"user-agent": "curl/8.5.0"}, query="a=1", body="b=2") == []


# ------------------------------------------------------- found by adversarial probing, not by
# ------------------------------------------------------- a review: two bypasses and one gap


def test_every_occurrence_of_a_parameter_is_measured():
    """HTTP parameter pollution, and reading only the first value was a bypass.

    `SAMLRequest=QQ%3D%3D&SAMLRequest=<trigger>` missed the trigger entirely. Which value the
    receiving application uses is **not ours to guess** — Tomcat takes the first, other stacks
    take the last, some concatenate — so every occurrence is measured. The one that reaches
    `java.util.Base64` is whichever the server picks, and we cannot know which that is.
    """
    trigger = "A" * 64 + "="
    for query in [
        f"SAMLRequest={trigger}&SAMLRequest=QQ%3D%3D",
        f"SAMLRequest=QQ%3D%3D&SAMLRequest={trigger}",
        "&".join(["SAMLRequest=QQ%3D%3D"] * 50) + f"&SAMLRequest={trigger}",
    ]:
        lens = [r["shape"]["len"] for r in carrier_shapes(query=query)]
        assert 65 in lens, query[:40]


def test_any_whitespace_separates_the_scheme_from_the_token():
    """`Authorization: Basic\\t<blob>` and an obs-folded value both recorded nothing.

    RFC 7235 writes `1*SP`, so a tab is non-conformant — but whether Tomcat's
    `BasicAuthenticator` accepts one is not something this code can know, and the asymmetry is
    not close: being more permissive than the server costs a carrier whose own shape then
    decides whether it means anything, while being less permissive costs a bypass. Obs-folding
    matters for the same reason: the decoy's parser may hand us the continuation intact.
    """
    trigger = "A" * 64 + "="
    for value in [
        f"Basic {trigger}",
        f"Basic  {trigger}",
        f"Basic\t{trigger}",
        f"Basic\r\n {trigger}",
        f"basic \t {trigger}",
    ]:
        records = carrier_shapes(headers={"authorization": value})
        assert [r["shape"]["len"] for r in records] == [65], repr(value)


def test_a_scheme_with_no_token_records_nothing():
    for value in ["Basic", "Basic ", "Basic\t", "Bearer   "]:
        assert carrier_shapes(headers={"authorization": value}) == [], repr(value)


def test_a_parameter_name_needs_its_own_separator():
    trigger = "A" * 64 + "="
    assert carrier_shapes(query=f"xSAMLRequest={trigger}") == []
    assert carrier_shapes(query=f"my_SAMLRequest={trigger}") == []
