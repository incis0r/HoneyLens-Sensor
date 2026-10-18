"""The one Base64 shape primitive every carrier extractor goes through.

Why a primitive and not a third copy: `hp_http` and `honeypot_k8s` each grew their own
Basic-auth extractor, and the k8s one reduced the blob to the word `"present"` before anything
could measure it. That cost the 14 rows the 2026-11-18 actor (`31.76.87.52`) left behind — they
are stored and they cannot be labelled, because the evidence was destroyed at record time.
NTLM, SAML and Bearer must not repeat it.

What the primitive may and may not claim is set by the PoC's measured findings
(recorded in the internal Java4Shell case notes):

* **F4** — only `Base64.getDecoder()` takes the vulnerable intrinsic; `getUrlDecoder()` and
  `getMimeDecoder()` measured `sig9a=0`. So the alphabet a token *distinguishes* is load-bearing
  and the primitive reports it instead of guessing one.
* **F5** — only the exact 64+1 = 65-character shape fires on that build. So `len` is reported
  exactly, never bucketed.
"""

import pytest

from honeylens.b64_shape import b64_shape


def test_absent_token_has_no_shape():
    assert b64_shape(None) is None


def test_the_shape_that_fires_on_the_measured_build():
    # `"A"*64 + "="`: the one rung the actor repeated at 05:05, 05:30, 05:46 and 05:52 after
    # sweeping 5/65/129 once at 05:01 — exactly F5's only-firing shape.
    assert b64_shape("A" * 64 + "=") == {
        "len": 65,
        "mod4": 1,
        "alphabet": "either",
        "pad_count": 1,
        "pad_interior": False,
        "decodes": False,
        "truncated": False,
    }


def test_the_valid_control_the_actor_sent_first_is_not_malformed():
    shape = b64_shape("QQ==")  # decodes to "A"; the calibration request
    assert shape["mod4"] == 0
    assert shape["decodes"] is True
    assert shape["pad_interior"] is False


def test_unpadded_63_character_credential_still_decodes():
    # Two fleet addresses send this shape and it is a real credential. "Not a multiple of
    # four" would have called it an exploit attempt.
    blob = "Y2FsZGF2X3B1YmxpY191c2VyQGxvY2FsaG9zdDpjYWxkYXZfcHVibGljX3VzZXI"
    assert len(blob) % 4 == 3
    assert b64_shape(blob)["decodes"] is True


def test_interior_padding_is_caught_where_mod4_cannot_see_it():
    # `=` before a non-`=` character is illegal in every Base64 variant, and this token's
    # length is a clean multiple of four — so mod4 says nothing and the pad fields say it all.
    # This is the `A=`/`AB=`/`===` gap the Basic-auth rules left open.
    shape = b64_shape("AAA=AAAA")
    assert shape["mod4"] == 0
    assert shape["pad_interior"] is True
    assert shape["decodes"] is False


def test_more_than_two_padding_characters_is_illegal():
    shape = b64_shape("AAAA====")
    assert shape["pad_count"] == 4
    assert shape["pad_interior"] is False
    assert shape["decodes"] is False


@pytest.mark.parametrize(
    "token,alphabet",
    [
        ("ab+/cd12", "std"),  # `+` and `/` exist only in the standard alphabet
        ("ab-_cd12", "url"),  # `-` and `_` exist only in base64url
        ("ab+_cd12", "mixed"),  # both: legal in neither
        ("abcd1234", "either"),  # nothing distinguishes it; claiming "std" would be invention
    ],
)
def test_alphabet_reports_what_the_token_distinguishes(token, alphabet):
    assert b64_shape(token)["alphabet"] == alphabet


def test_a_mixed_alphabet_token_decodes_in_neither_variant():
    assert b64_shape("ab+_cd12")["decodes"] is False


def test_url_alphabet_decodes():
    assert b64_shape("ab-_cd12")["decodes"] is True


def test_truncation_is_the_callers_fact_to_state():
    # Real `SAMLRequest` reaches 7,660 characters on this fleet and `SAMLResponse` is bigger.
    # A capture budget that clips the field makes `len` — and therefore `mod4` — independent of
    # what the sender actually sent, so a clipped field can manufacture `mod4 == 1`. Only the
    # code that did the clipping knows; the primitive records the claim and never infers it.
    assert b64_shape("A" * 64, truncated=True)["truncated"] is True
    assert b64_shape("A" * 64)["truncated"] is False


def test_empty_blob_is_a_shape_not_an_absence():
    # `Authorization: Basic` with nothing after it is a request we saw; a None here would be
    # ambiguous between that and a decoy that predates the field.
    assert b64_shape("")["len"] == 0


# --------------------------------------------------- one answer to "is this Base64", and one
# --------------------------------------------------- piece of code that produces the bytes


def test_decode_b64_agrees_with_the_shape_it_measured():
    """Two implementations of "is this Base64" is the defect this module exists to remove.

    `hp_http._decode_basic_blob` had its own copy and the copies disagreed: for a url-alphabet
    blob the shape said `b64_valid=True` while the decoder returned `None`, so one field in the
    stored row contradicted the next. `decode_b64` is the one that produces the bytes and
    `decodes` is defined as "`decode_b64` returned something".
    """
    from honeylens.b64_shape import decode_b64

    for token in [
        "QQ==",
        "ab-_cd12",
        "ab+/cd12",
        "YWRtaW46YWRtaW4=",
        "Y2FsZGF2X3B1YmxpY191c2VyQGxvY2FsaG9zdDpjYWxkYXZfcHVibGljX3VzZXI",
        "A" * 64 + "=",
        "AAA=AAAA",
        "AAAA====",
        "ab+_cd12",
        "",
    ]:
        assert (decode_b64(token) is not None) is b64_shape(token)["decodes"], token


def test_decode_b64_returns_the_bytes():
    from honeylens.b64_shape import decode_b64

    assert decode_b64("YWRtaW46YWRtaW4=") == b"admin:admin"
    assert decode_b64("QQ==") == b"A"
    assert decode_b64("A" * 64 + "=") is None
