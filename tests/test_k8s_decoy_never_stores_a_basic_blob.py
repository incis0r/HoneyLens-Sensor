"""The decoy on port 8080 records the *shape* of an `Authorization` value, never the value.

History, because this reverses a decision made earlier the same day. The decoy reduced the
header to the literal `"present"`, which is right for a credential and wrong for
CVE-2026-114938, where the blob **is** the exploit and cannot be a credential — measured
2026-11-18, `31.76.87.52` sent the probe ladder to port 8080 on `sensor-c` (05:01, 05:05, 05:30)
and `sensor-h` (05:46), and every row reads `"authorization": "present"`, carries no verdict
and is indistinguishable from a wrong password.

The first fix kept the header verbatim when the blob could not be Base64, so a text rule could
read it. A security review of that change found the hole, and measuring it found a wider one
than the review described:

    'admin:password'   alphabet=invalid  decodes=False  -> KEPT VERBATIM
    'admin'            alphabet=either   decodes=False  -> KEPT VERBATIM   (len % 4 == 1)

A client that sends raw credentials after `Basic` is a real and common misconfiguration, and
the second line went through the *original* `len % 4 == 1` gate too — so this was never purely
a regression in the widened gate. Narrowing the condition would have kept a guess about which
strings are secrets in a decoy whose stated policy is to hold none.

So the blob is not stored at all. `b64_carriers` carries the measurement instead — length,
`mod4`, alphabet, padding — which is everything the grading needs and nothing anybody can
authenticate with, and the labelling happens centrally over that shape. The verbatim request
still survives in the pre-parser's `raw_hex` for anyone who needs the bytes.
"""

from __future__ import annotations

import base64

from honeylens.b64_shape import request_carriers
from honeylens.classification.attack_classifier import classify_event_row
from honeylens.honeypots.honeypot_k8s import describe_authorization

TRIGGER_21 = "A" * 64 + "="
TRIGGER_17 = "A" * 128 + "="
SHORT_MALFORMED = "AAA=="
REAL_CRED = base64.b64encode(b"kube-admin:s3cret-token").decode()
CVE = "CVE_2026_114938"


# ------------------------------------------------------------------ nothing is ever stored
def test_no_authorization_value_is_ever_echoed_into_the_field():
    for blob in [
        TRIGGER_21,
        TRIGGER_17,
        SHORT_MALFORMED,
        REAL_CRED,
        "AAA=AAAA",
        "AAAA====",
        "ab+_cd12",
        "admin",
        "admin:password",
        "s3cret with spaces",
    ]:
        assert describe_authorization(f"Basic {blob}") == "present", blob


def test_a_raw_credential_after_basic_is_not_leaked():
    """The finding. A client that sends `Basic admin:password` literally is a real
    misconfiguration, and the value is a plaintext password."""
    for raw in ["admin:password", "root:toor", "admin", "hunter2"]:
        assert raw not in describe_authorization(f"Basic {raw}")


def test_a_missing_header_is_still_anonymous():
    assert describe_authorization("") == "anonymous"
    assert describe_authorization(None) == "anonymous"


def test_other_schemes_are_unchanged():
    assert describe_authorization("Bearer eyJhbGciOiJub25lIn0") == "present"
    assert describe_authorization(f"Negotiate {TRIGGER_21}") == "present"


# ------------------------------------------------------------------ the shape still labels it
def test_the_shape_carries_what_the_blob_used_to_have_to():
    fields = request_carriers(headers={"authorization": f"Basic {TRIGGER_21}"})
    shape = fields["b64_carriers"][0]["shape"]
    assert (shape["len"], shape["mod4"], shape["decodes"]) == (65, 1, False)


def test_the_ladder_is_labelled_from_the_shape_alone():
    for blob, expected in [
        (TRIGGER_21, "java4shell_b64_fires_65"),
        (TRIGGER_17, "java4shell_b64_malformed_length"),
        (SHORT_MALFORMED, "java4shell_b64_malformed_length"),
        ("AAA=AAAA", "java4shell_b64_illegal_padding"),
    ]:
        fields = request_carriers(headers={"authorization": f"Basic {blob}"})
        hits = classify_event_row("GET /api/v1/pods", "HTTP", fields)
        assert expected in {r for _t, r, _s in hits}, blob
        assert CVE in {t for t, _r, _s in hits}, blob


def test_a_withheld_credential_produces_no_verdict():
    fields = request_carriers(headers={"authorization": f"Basic {REAL_CRED}"})
    hits = classify_event_row("GET /api/v1/pods", "HTTP", fields)
    assert CVE not in {t for t, _r, _s in hits}


def test_the_shape_cannot_be_authenticated_with():
    """A shape is a length and three booleans. Nothing in it reconstructs the secret."""
    fields = request_carriers(headers={"authorization": f"Basic {REAL_CRED}"})
    rendered = repr(fields)
    assert "kube-admin" not in rendered
    assert REAL_CRED not in rendered
