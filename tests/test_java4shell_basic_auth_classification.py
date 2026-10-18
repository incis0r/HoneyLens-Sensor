"""CVE-2026-114938 ("Java4Shell") arrives as an `Authorization: Basic` header, and we filed it
as a credential.

Measured on the fleet 2026-11-18: `31.76.87.52` sent the researchers' probe ladder to four
sensors between 05:01 and 05:52 CET — `sensor-c` (05:01, 05:05, 05:30), `sensor-h` (05:46),
`sensor-e` (05:52) — after plain `GET /` + `GET /modern/` reconnaissance from the same address on
11-13 (`curl/8.5.0`). Every row that carried the blob was labelled **`CREDENTIAL`**, because
`cred_basic_auth_header` matches any `Authorization: Basic <blob>` and nothing looked at the
blob itself. The rows on the port-8080 decoy carried no verdict at all.

The bug: `java.util.Base64.Decoder.decode` on a pre-fix HotSpot JDK running on an AVX-512 VBMI
CPU writes 64 bytes past the output buffer while rejecting a malformed Base64 tail, *before*
throwing. Tomcat's `BasicAuthenticator$BasicCredentials.parseBase64()` and Jetty 12's
`BasicAuthenticator` both hand the attacker's blob straight to that decoder **before
authenticating anyone**, so the primitive is pre-auth and the whole trigger fits in one header.
Measured from the internal Java4Shell case notes.

The discriminator pinned here is **blob length modulo 4**, and the capture is what rules out the
obvious alternatives:

* A Base64 blob whose length is ``≡ 1 (mod 4)`` cannot be valid — there is no bit pattern that
  produces one leftover character. No client emits it. All four rungs of the observed ladder
  have it: 5, 65 and 129 characters.
* ``≡ 2`` and ``≡ 3`` are **not** usable as a discriminator, and the same capture proves it:
  `144.24.94.153` and `192.42.116.16` sent a 63-character unpadded blob that decodes cleanly to
  ``caldav_public_user@localhost:caldav_public_user``. A rule keyed on "not a multiple of four"
  would call that an exploit attempt.

So: fire on ``len % 4 == 1``, and split by whether the blob is long enough to reach the VBMI
path at all (31 characters on the 21 line, 128 on the 17 line).
"""

from __future__ import annotations

import base64

import pytest

import honeylens.classification.text_rules as tr
from honeylens.classification.scoring import (
    ATTACK_TYPE_SEVERITY,
    get_severity,
    get_severity_weight,
)

CVE = "CVE_2026_114938"

# --- the ladder, exactly as 31.76.87.52 sent it (sensor-a/sensor-c/sensor-h/sensor-e, 2026-11-18) ---
CONTROL = "QQ=="  # 4 chars, valid, decodes to "A"
SHORT_MALFORMED = "AAA=="  # 5 chars, len%4 == 1
TRIGGER_21 = "A" * 64 + "="  # 65 chars — the canonical 21-line trigger
TRIGGER_17 = "A" * 128 + "="  # 129 chars — the 17-line trigger (its VBMI gate is 128 B)

# --- real credentials from the same 30-day window; none of these may fire ---
CRED_UNPADDED_63 = "Y2FsZGF2X3B1YmxpY191c2VyQGxvY2FsaG9zdDpjYWxkYXZfcHVibGljX3VzZXI"  # len 63
CRED_TEST = "dGVzdDp0ZXN0ODU3Ng=="  # len 20, test:test8576
CRED_ADMIN = "YWRtaW46YWRtaW4="  # len 16, admin:admin
CRED_LONG = "MHg1N2EwN2IwOGYyMjVjYjRmZmE5NDI0NzM4ZDI4YmJkNjk2ZDA4MTE5Ong="  # len 60


def _wire(blob: str, header: str = "Authorization") -> str:
    """The dialect a packet capture gives the classifier."""
    return f"GET / HTTP/1.1\r\nHost: example\r\n{header}: Basic {blob}\r\nConnection: close\r\n\r\n"


def _json(blob: str, header: str = "authorization") -> str:
    """The dialect a decoy's `metadata['headers']` dict gives the classifier."""
    return f'{{"host": "example", "{header}": "Basic {blob}", "connection": "close"}}'


def _rules_for(attack_type: str) -> list[tuple[str, object]]:
    return [(name, pat) for (at, name, pat) in tr._RULES if at == attack_type]


def _worst(rule_names: list[str]) -> str:
    """The heaviest severity among the rules one blob fired — what actually reaches the score."""
    return max(
        (get_severity(CVE, name) for name in rule_names),
        key=get_severity_weight,
    )


def _hits(attack_type: str, text: str) -> list[str]:
    rules = _rules_for(attack_type)
    assert rules, f"no {attack_type} rule registered"
    return [name for name, pat in rules if pat.search(text)]


# --------------------------------------------------------------- the triggers


@pytest.mark.parametrize("blob", [TRIGGER_21, TRIGGER_17], ids=["21-line", "17-line"])
@pytest.mark.parametrize("dialect", [_wire, _json], ids=["wire", "json"])
def test_the_observed_triggers_are_named_as_the_cve(blob, dialect):
    assert _hits(CVE, dialect(blob)), f"len={len(blob)} must be caught in both dialects"


def test_the_short_rung_of_the_ladder_is_also_caught():
    """`AAA==` is 5 characters: invalid Base64, far too short to reach the VBMI path. It is
    evidence of the same probe and must not be silently dropped."""
    assert _hits(CVE, _wire(SHORT_MALFORMED))


def test_a_proxy_authorization_header_counts():
    """Tomcat and Jetty read `Authorization`; a probe through a proxy chain uses the other
    spelling, and `claude_credential_basic_auth_weak_patterns` already accepts both."""
    assert _hits(CVE, _wire(TRIGGER_21, header="Proxy-Authorization"))


# --------------------------------------------------------------- the negatives


@pytest.mark.parametrize(
    "blob",
    [CONTROL, CRED_UNPADDED_63, CRED_TEST, CRED_ADMIN, CRED_LONG],
    ids=["control", "unpadded-63", "test", "admin", "long-token"],
)
@pytest.mark.parametrize("dialect", [_wire, _json], ids=["wire", "json"])
def test_real_credentials_do_not_fire(blob, dialect):
    assert len(blob) % 4 != 1, "test data error: this blob is itself malformed"
    assert not _hits(CVE, dialect(blob))


def test_the_unpadded_credential_decodes_so_the_mod_three_case_is_a_real_credential():
    """Guards the discriminator choice itself: `len % 4 == 3` is legal unpadded Base64 and the
    fleet sees it from real clients, so 'not a multiple of 4' can never be the rule."""
    assert len(CRED_UNPADDED_63) % 4 == 3
    decoded = base64.b64decode(CRED_UNPADDED_63 + "=").decode()
    assert decoded == "caldav_public_user@localhost:caldav_public_user"


def test_a_conformant_bearer_token_does_not_fire():
    """A JWT is dot-separated and each segment is decoded separately, so a `mod4` over the whole
    token means nothing — and **F4** (`AdjProbe16`) measured the decoder it reaches as safe:
    `basic sig9a=32`, `url=0`, `mime=0`. Claiming this CVE on conformant Bearer traffic would be
    the decoy-scope defect in a new place."""
    conformant = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLWhlcmUtb2st"
    assert not _hits(CVE, _wire(conformant).replace("Basic ", "Bearer "))


def test_a_padded_bearer_token_fires_only_the_graded_carrier_rule():
    """Superseded the blanket "Bearer never fires", 2026-11-18, on two measurements.

    F4 leaves exactly one JWT path reachable: an application that hand-rolls `-_`->`+/` and
    re-pads into `getDecoder()`. The wire tell is padding, which RFC 7515 section 2 forbids —
    and the fleet agrees that it does not occur, with **not one of 282 Bearer tokens from 13
    sources carrying `=`**. So a padded Bearer is worth a medium, and it must stay a medium: the
    firing-shape rules are Basic- and NTLM-scoped and may not claim a 65-character JWT segment
    is the shape that writes."""
    fired = _hits(CVE, _wire(TRIGGER_21).replace("Basic ", "Bearer "))
    assert fired == ["java4shell_bearer_padded_segment"]
    assert get_severity(CVE, "java4shell_bearer_padded_segment") == "medium"


# --------------------------------------------------------------- severity + registry


def test_the_type_is_registered_with_a_severity():
    """An unregistered type silently scores `medium`, which puts a pre-auth memory-corruption
    primitive below a WordPress scan."""
    assert ATTACK_TYPE_SEVERITY.get(CVE) == "critical"


def test_the_short_rung_scores_below_the_firing_shape():
    """5 characters cannot reach the intrinsic: the VBMI gate is 31 bytes on the 21 line. Both
    rungs are the same campaign, so they share a type — severity is what separates them."""
    long_rule = _hits(CVE, _wire(TRIGGER_21))
    short_rule = _hits(CVE, _wire(SHORT_MALFORMED))
    assert long_rule and short_rule
    assert set(long_rule) != set(short_rule), "the two rungs must be distinguishable by rule"
    # Compare the worst grade each rung earns, not the first rule that happens to be
    # registered: a blob fires several rules and `calculate_threat_score` scores the heaviest.
    # Reading `[0]` tied this assertion to registration order, and it broke the moment the
    # firing shape got its own rule after the length rule.
    assert _worst(short_rule) == "medium"
    assert _worst(long_rule) == "critical"


def test_the_cve_spelling_matches_the_case_directory():
    """One campaign, one spelling. `CVE-2026-114938` is what the advisory and
    the internal case notes use; a second spelling would split every hunt."""
    assert any(at == CVE for at, _n, _p in tr._RULES)


def test_a_bare_scheme_and_blob_matches_too():
    """The Kubernetes decoy writes the header's VALUE into a flat `authorization` field, with no
    header name in front of it. A rule that required the name labelled nothing on that decoy —
    which is where this probe hit port 8080 on two sensors."""
    assert _hits(CVE, f"Basic {TRIGGER_21}")
    assert _hits(CVE, f'{{"authorization": "Basic {TRIGGER_21}"}}')


def test_prose_mentioning_basic_auth_does_not_fire():
    """The anchor is now the scheme word, so the negative worth pinning is English text."""
    assert not _hits(CVE, "This endpoint requires Basic authentication to be configured first.")
    assert not _hits(CVE, 'WWW-Authenticate: Basic realm="tomcat"')


def test_a_long_whitespace_run_after_the_colon_stays_cheap():
    """The header value is attacker-controlled, so the cost of NOT matching is their choice.

    The first spelling of the prefix was `"?\\s*:\\s*"?\\s*`: a whitespace run after the colon
    could be split between the two `\\s*` in N+1 ways, and because the prefix is optional and
    followed by a mandatory literal, every split was retried when `Basic` never arrived.
    Measured: 0.24 ms at 200 spaces, 5.4 ms at 1,000, 82.6 ms at 4,000 — quadratic, on an input
    an attacker writes. The ceiling here is deliberately loose (a laptop under load is not a
    benchmark) but far below the quadratic curve: it fails at ~20 ms for n=2000.
    """
    import time

    rules = _rules_for(CVE)
    hostile = "Authorization:" + " " * 2000 + "x"
    worst = 0.0
    for _name, pat in rules:
        start = time.perf_counter()
        assert pat.search(hostile) is None
        worst = max(worst, (time.perf_counter() - start) * 1000)
    assert worst < 5.0, f"{worst:.3f} ms on a 2000-space run — the prefix is ambiguous again"


def test_the_quoted_json_dialect_still_matches_after_the_prefix_was_tightened():
    """The tightened prefix must still accept `"authorization": "Basic …"` — the whole point of
    carrying the quotes was the dialect a decoy's header dict serialises to."""
    assert _hits(CVE, f'{{"authorization": "Basic {TRIGGER_21}"}}')
    assert _hits(CVE, f'{{"Authorization" : "Basic {TRIGGER_21}"}}')
    assert _hits(CVE, f"Authorization:   Basic {TRIGGER_21}")
