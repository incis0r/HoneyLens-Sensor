"""The three-way grading, in one place, over a measured shape rather than over wire text.

Why this is not a regex. A text rule can count length in an `Authorization` header, because
header values arrive verbatim. It cannot do it for SAML: `SAMLRequest` is percent-encoded on
the wire, so `=` arrives as `%3D` — three characters where the token has one. 52 SAMLRequest
rows from 29 fleet sources read `mod4 == 2` for exactly that reason and not one of them is
malformed, and the inverse is worse: an attacker whose padding is written `%3D` reads back as
`mod4 == 0` and walks past a length rule. `BinarySecurityToken` has the same problem through
XML line folding.

So the transport is undone by the extractor and the grading reads the shape. The gates are:

* ``mod4 == 1 and len == 65`` -> critical. F5 (`AdjProbe8/9`): on the measured build only the
  exact 64+1 shape fires; 129, 193 and 259 with every malformed tail measured zero.
* any other ``mod4 == 1`` -> medium. Impossible Base64 either way, but it is the sweep rather
  than the shape that writes. Our actor sent 5 / 65 / 129 once and then repeated only the 65.
* ``pad_interior`` or ``pad_count >= 3`` -> medium. `=` before a non-`=` character, or more
  than two pad characters, is illegal in every Base64 variant **and invisible to `mod4`** —
  `AAA=AAAA` is a clean multiple of four. This closes the `A=` / `AB=` / `===` gap the
  Basic-auth length rules left open.
"""

import pytest

from honeylens.b64_shape import b64_shape, shape_verdict

FIRES = "java4shell_b64_fires_65"
SWEEP = "java4shell_b64_malformed_length"
PADDING = "java4shell_b64_illegal_padding"


def _verdict(token, **kw):
    return shape_verdict(b64_shape(token, **kw))


def test_the_shape_that_fires_is_graded_apart_from_the_sweep():
    assert _verdict("A" * 64 + "=") == FIRES


@pytest.mark.parametrize("token", ["AAA==", "A" * 128 + "=", "A" * 192 + "="])
def test_every_other_impossible_length_is_the_sweep(token):
    assert len(token) % 4 == 1
    assert _verdict(token) == SWEEP


def test_interior_padding_is_graded_where_mod4_is_blind():
    assert b64_shape("AAA=AAAA")["mod4"] == 0
    assert _verdict("AAA=AAAA") == PADDING


def test_more_than_two_pad_characters_is_graded():
    assert _verdict("AAAA====") == PADDING


@pytest.mark.parametrize(
    "token",
    [
        "QQ==",  # the actor's own valid control
        "Y2FsZGF2X3B1YmxpY191c2VyQGxvY2FsaG9zdDpjYWxkYXZfcHVibGljX3VzZXI",  # unpadded 63
        "dGVzdDp0ZXN0ODU3Ng==",
        "T" * 52,  # a real NTLM token's shape: all 168 fleet rows are mod4 0, length 44-56
        "",
    ],
)
def test_nothing_legal_is_graded(token):
    assert _verdict(token) is None


def test_a_clipped_field_cannot_be_graded_on_length():
    # Truncation makes `len` — and with it `mod4` — independent of what the sender sent, so a
    # capture budget could manufacture this verdict out of a valid 7,660-character SAMLRequest.
    assert _verdict("A" * 64 + "=", truncated=True) is None
    assert _verdict("A" * 128 + "=", truncated=True) is None


def test_a_clipped_field_can_still_be_graded_on_padding():
    # The asymmetry is real and it is why the two gates are separate: clipping removes a tail,
    # so it can lower `pad_count` and can never move a `=` into the interior. An illegal pad
    # survived the clipping, which means the sender sent it.
    assert _verdict("AAA=AAAA", truncated=True) == PADDING
    assert _verdict("AAAA====", truncated=True) == PADDING


def test_absent_shape_is_not_a_verdict():
    assert shape_verdict(None) is None


# ------------------------------------------------------- the grade must reach the score


def test_each_grade_carries_the_severity_the_measurement_supports():
    from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY, get_severity

    assert ATTACK_TYPE_SEVERITY["CVE_2026_114938"] == "critical"
    assert get_severity("CVE_2026_114938", FIRES) == "critical"
    assert get_severity("CVE_2026_114938", SWEEP) == "medium"
    assert get_severity("CVE_2026_114938", PADDING) == "medium"


def test_the_long_basic_auth_rule_is_demoted_to_the_sweep_it_describes():
    """`java4shell_basic_auth_overwrite_length` fires on any `mod4 == 1` blob of 33 characters
    or more, which includes the 129- and 193-character rungs F5 measured as non-firing. Leaving
    it critical makes every rung of a sweep read like the one shape that writes."""
    from honeylens.classification.scoring import get_severity

    assert get_severity("CVE_2026_114938", "java4shell_basic_auth_overwrite_length") == "medium"


# ------------------------------------------------- two false positives, both measured on the
# ------------------------------------------------- real corpus and not predicted by review


def test_a_value_that_is_not_base64_at_all_is_not_graded():
    """Found by running 59 distinct real fleet tokens through full classification.

    A query parameter is percent-decoded before it is measured, and what comes back is not
    guaranteed to be a Base64 token at all — one real SAML-adjacent value decoded to a 19-byte
    string carrying an interior `=` and characters from no Base64 alphabet, and it was graded.
    `mod4` and padding only mean something in a field that is Base64; asking that first is the
    gate that was missing.

    This is not an evasion either: F5 fixes the firing shape at 64 Base64 characters plus `=`,
    so a junk character in the token moves it off that shape rather than hiding it.
    """
    assert _verdict("not a base64 token at all!") is None
    assert _verdict("%3A%2Fabc/def=xyz") is None
    assert b64_shape("abc$def")["alphabet"] == "invalid"


def test_an_opaque_bearer_token_is_never_graded_on_length():
    """Also found end to end: **46 fleet rows** would have been labelled.

    RFC 6750's `b64token` is a syntax for an *opaque* string, not a Base64 encoding — a bearer
    token has no reason for its length to be a multiple of four, and the corpus agrees: among
    non-dotted Bearer values, 163 rows are `mod4 == 0`, **46 are `mod4 == 1`** (25 characters,
    one source), 24 are 2 and 2 are 3. A JWT segment is different: it is base64url by
    definition, and across all 21 segments of the 7 distinct real JWTs on the fleet `mod4` is
    0, 2 or 3 and never 1.
    """
    opaque = b64_shape("A" * 25)
    assert opaque["mod4"] == 1
    assert shape_verdict(opaque, carrier="bearer_opaque") is None
    # The same shape in a field that must be Base64 by specification is still evidence.
    assert shape_verdict(opaque, carrier="ntlm") == SWEEP
    assert shape_verdict(opaque, carrier="bearer") == SWEEP


def test_illegal_padding_is_graded_even_in_an_opaque_field():
    # Padding is not a length claim. `=` before a non-`=` character is illegal wherever the
    # value is meant to be decoded, and no opaque token on the fleet carries `=` at all.
    assert shape_verdict(b64_shape("AAA=AAAA"), carrier="bearer_opaque") == PADDING
