"""Text rules for the carriers whose wire form is verbatim, graded by the same three gates.

The shape path (`honeylens.b64_shape.shape_verdict`) judges a decoded token and is the only
honest way to grade SAML, whose padding arrives as `%3D`. But most rows never reach it: Suricata
rows, decoys that predate the field, and every decoy that is not `hp_http` carry text and
nothing else. Header values *are* verbatim, so for the header carriers a text rule can count
length exactly — and that is where the traffic is.

Measured on the fleet, 30 days to 2026-11-18, own validation sources excluded:

* **NTLM / Negotiate — 168 rows, 68 sources, every one `mod4 == 0`, length 44-56.** Standard
  padded Base64 handed to `Base64.getDecoder()` pre-auth. Ten times the JWT traffic, and not
  one token is 65 characters long.
* **Bearer — 282 rows, 13 sources, and not one carries `=`.** JWT and opaque alike. RFC 7515
  section 2 requires padding to be omitted, so `=` in a Bearer value is both non-conformant and
  unobserved — which makes it the tell for the one reachable JWT path: an application that
  hand-rolls `-_`->`+/` and re-pads into `getDecoder()`. F4 measured `getUrlDecoder()` safe, so
  this is graded medium, not critical.
"""

from __future__ import annotations

import base64
import time

import pytest

import honeylens.classification.text_rules as tr
from honeylens.classification.scoring import get_severity

CVE = "CVE_2026_114938"

TRIGGER = "A" * 64 + "="  # 65 — the only shape F5 measured as firing
SWEEP_129 = "A" * 128 + "="
# Both built from their parts rather than pasted. A pasted blob reads like a captured
# credential and the secret scanner treats it as one, and the encoding is what is under test.
# An NTLM type-1 message: the NTLMSSP signature, message type 1, then the flags and the
# empty domain/workstation fields. Base64 of 36 bytes is 48 characters, `mod4 == 0` — which
# is what all 168 NTLM rows on the fleet look like.
NTLM_REAL = base64.b64encode(b"NTLMSSP\x00\x01\x00\x00\x00\x07\x82\x08\xa2" + bytes(24)).decode()
JWT_CONFORMANT = ".".join(
    base64.urlsafe_b64encode(part).decode().rstrip("=")
    for part in (b'{"alg":"HS256"}', b'{"sub":"1"}', b"signature-bytes-ok")
)


def _hits(text: str) -> set[str]:
    rules = [(n, p) for (at, n, p) in tr._RULES if at == CVE]
    assert rules, "no CVE_2026_114938 rule registered"
    return {n for n, p in rules if p.search(text)}


def _hdr(name: str, value: str) -> str:
    return f"GET / HTTP/1.1\r\nHost: example\r\n{name}: {value}\r\nConnection: close\r\n\r\n"


# ------------------------------------------------------------------ the firing shape
def test_the_firing_basic_blob_is_graded_apart_from_the_sweep():
    fired = _hits(_hdr("Authorization", f"Basic {TRIGGER}"))
    assert "java4shell_basic_auth_fires_65" in fired
    assert get_severity(CVE, "java4shell_basic_auth_fires_65") == "critical"


def test_a_longer_malformed_blob_is_not_the_firing_shape():
    fired = _hits(_hdr("Authorization", f"Basic {SWEEP_129}"))
    assert "java4shell_basic_auth_fires_65" not in fired
    assert "java4shell_basic_auth_overwrite_length" in fired


# ------------------------------------------------------------------ NTLM / Negotiate
@pytest.mark.parametrize("scheme", ["NTLM", "Negotiate"])
def test_the_firing_shape_in_an_ntlm_header(scheme):
    fired = _hits(_hdr("Authorization", f"{scheme} {TRIGGER}"))
    assert "java4shell_ntlm_fires_65" in fired
    assert get_severity(CVE, "java4shell_ntlm_fires_65") == "critical"


def test_an_ntlm_sweep_rung_is_medium():
    fired = _hits(_hdr("Proxy-Authorization", f"NTLM {SWEEP_129}"))
    assert "java4shell_ntlm_malformed_length" in fired
    assert get_severity(CVE, "java4shell_ntlm_malformed_length") == "medium"


def test_a_real_ntlm_handshake_fires_nothing():
    assert _hits(_hdr("Authorization", f"NTLM {NTLM_REAL}")) == set()


# ------------------------------------------------------------------ Bearer
def test_padding_in_a_bearer_value_is_the_hand_rolled_decoder_tell():
    fired = _hits(_hdr("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.a+b/c=.sig"))
    assert "java4shell_bearer_padded_segment" in fired
    assert get_severity(CVE, "java4shell_bearer_padded_segment") == "medium"


def test_a_conformant_jwt_fires_nothing():
    assert _hits(_hdr("Authorization", f"Bearer {JWT_CONFORMANT}")) == set()


# ------------------------------------------------------------------ illegal padding
@pytest.mark.parametrize(
    "blob,why",
    [
        ("AAA=AAAA", "interior pad, and mod4 == 0 so no length rule can see it"),
        ("AAAA====", "four pad characters; two is the legal maximum"),
    ],
)
@pytest.mark.parametrize("scheme", ["Basic", "NTLM", "Negotiate"])
def test_illegal_padding_is_caught_on_every_header_carrier(scheme, blob, why):
    fired = _hits(_hdr("Authorization", f"{scheme} {blob}"))
    assert "java4shell_illegal_padding_header" in fired, why
    assert get_severity(CVE, "java4shell_illegal_padding_header") == "medium"


def test_interior_padding_is_invisible_to_the_length_rules():
    assert len("AAA=AAAA") % 4 == 0
    fired = _hits(_hdr("Authorization", "Basic AAA=AAAA"))
    assert fired == {"java4shell_illegal_padding_header"}


# ------------------------------------------------------------------ negatives
@pytest.mark.parametrize(
    "value",
    [
        "Basic QQ==",
        "Basic Y2FsZGF2X3B1YmxpY191c2VyQGxvY2FsaG9zdDpjYWxkYXZfcHVibGljX3VzZXI",
        "Basic dGVzdDp0ZXN0ODU3Ng==",
        "Basic YWRtaW46YWRtaW4=",
        f"NTLM {NTLM_REAL}",
        f"Negotiate {NTLM_REAL}",
        f"Bearer {JWT_CONFORMANT}",
    ],
)
def test_nothing_legal_fires(value):
    assert _hits(_hdr("Authorization", value)) == set()


# ------------------------------------------------------------------ cost
@pytest.mark.parametrize("n", [200, 1000, 4000])
def test_no_rule_is_superlinear_in_attacker_controlled_whitespace(n):
    """The defect that shipped in the first version of these rules: `"?\\s*:\\s*"?\\s*` let a
    whitespace run split N+1 ways, and the first cost check varied the Base64 run instead —
    0.24 ms at n=200 against 82.6 ms at n=4000."""
    target = "Authorization:" + " " * n + "x"
    rules = [p for (at, _n, p) in tr._RULES if at == CVE]
    start = time.perf_counter()
    for pattern in rules:
        pattern.search(target)
    assert (time.perf_counter() - start) < 0.25, f"n={n}"


@pytest.mark.parametrize("scheme", ["Basic", "NTLM", "Bearer"])
def test_no_rule_is_superlinear_in_an_attacker_controlled_run(scheme):
    target = _hdr("Authorization", f"{scheme} " + "A" * 4096)
    rules = [p for (at, _n, p) in tr._RULES if at == CVE]
    start = time.perf_counter()
    for pattern in rules:
        pattern.search(target)
    assert (time.perf_counter() - start) < 0.25
