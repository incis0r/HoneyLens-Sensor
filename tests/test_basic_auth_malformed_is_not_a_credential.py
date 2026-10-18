"""A malformed `Authorization: Basic` blob is an exploit attempt, not a login.

CVE-2026-114938 sends a blob that cannot be Base64 — the whole point is that the decoder
over-writes its output buffer *while rejecting it*. Python's `base64.b64decode` without
`validate=True` accepts those blobs anyway: the 65-character trigger `"A"*64 + "="` decodes to
48 NUL bytes, and until this change `hp_http._extract_credentials` filed that as a credential
with an empty username (the NULs are stripped before the row reaches the store). Three rows on
`sensor-h` on 2026-11-18 carry exactly that: `credentials.source = basic_auth`,
`username` length 0.

Two defects in one place, and the second was found while fixing the first:

* a blob with `len % 4 == 1` can never be Base64, so decoding it at all is wrong;
* a blob with `len % 4` of 2 or 3 is legal **unpadded** Base64, and `b64decode` rejects it for
  "Incorrect padding". The fleet has one from two addresses — a 63-character blob that is
  `caldav_public_user@localhost:caldav_public_user` — so we were dropping real credentials.

The shape is recorded either way, so a hunt can ask "which requests carried an impossible Basic
blob" without re-parsing header dicts.
"""

from __future__ import annotations

import base64

from honeylens.honeypots.hp_http import HTTPHoneypot

TRIGGER_21 = "A" * 64 + "="
TRIGGER_17 = "A" * 128 + "="
SHORT_MALFORMED = "AAA=="
UNPADDED_CRED = "Y2FsZGF2X3B1YmxpY191c2VyQGxvY2FsaG9zdDpjYWxkYXZfcHVibGljX3VzZXI"  # len 63
PADDED_CRED = base64.b64encode(b"admin:hunter2").decode()


def _hdr(blob: str) -> dict:
    return {"authorization": f"Basic {blob}"}


def _creds(blob: str):
    return HTTPHoneypot._extract_credentials(_hdr(blob), None)


def _shape(blob: str):
    return HTTPHoneypot._basic_auth_shape(_hdr(blob))


# ----------------------------------------------------------------- not a credential


def test_the_21_line_trigger_is_not_recorded_as_a_credential():
    assert _creds(TRIGGER_21) is None


def test_the_17_line_trigger_is_not_recorded_as_a_credential():
    assert _creds(TRIGGER_17) is None


def test_the_short_rung_is_not_recorded_as_a_credential():
    assert _creds(SHORT_MALFORMED) is None


def test_the_overwrite_bytes_never_become_a_username():
    """`"A"*64 + "="` decodes to 48 NUL bytes under non-validating Base64. Storing that as a
    username put an empty-string credential in the corpus and sent 48 NULs at the ingest, which
    is the one byte psycopg refuses to bind."""
    creds = _creds(TRIGGER_21)
    assert creds is None or creds.get("username") not in ("", "\x00" * 48)


# ----------------------------------------------------------------- still a credential


def test_a_padded_credential_still_extracts():
    assert _creds(PADDED_CRED) == {
        "username": "admin",
        "password": "hunter2",
        "source": "basic_auth",
    }


def test_an_unpadded_credential_now_extracts():
    """63 characters, `len % 4 == 3`: legal unpadded Base64 that `b64decode` refuses. Two
    addresses on the fleet send it and we stored nothing."""
    assert _creds(UNPADDED_CRED) == {
        "username": "caldav_public_user@localhost",
        "password": "caldav_public_user",
        "source": "basic_auth",
    }


# ----------------------------------------------------------------- the recorded shape


def test_the_shape_records_why_the_blob_was_rejected():
    shape = _shape(TRIGGER_21)
    assert shape == {"b64_len": 65, "b64_mod4": 1, "b64_valid": False}


def test_the_shape_is_recorded_for_valid_blobs_too():
    """Absence of the field would otherwise be ambiguous between 'valid' and 'old decoy'."""
    shape = _shape(PADDED_CRED)
    assert shape is not None
    assert shape["b64_valid"] is True
    assert shape["b64_mod4"] == 0


def test_no_shape_without_a_basic_header():
    """`_shape` here takes a header dict, not a blob — a Bearer value must not be measured as
    one, because a JWT never reaches `BasicAuthenticator`."""
    assert HTTPHoneypot._basic_auth_shape({}) is None
    assert HTTPHoneypot._basic_auth_shape({"authorization": "Bearer eyJhbGci.eyJzdWIi.sig"}) is None
    assert HTTPHoneypot._extract_credentials({"authorization": "Bearer eyJhbGci"}, None) is None


# ----------------------------------------------------------------- it reaches the record


def test_the_shape_is_in_the_stored_record(monkeypatch):
    """Recording it on the object and never putting it in the event would leave the hunt where
    it started: parsing `metadata->'headers'` in SQL."""
    import inspect

    src = inspect.getsource(HTTPHoneypot)
    assert src.count('["basic_auth"] = shape') == 2, (
        "both the HTTP/1.1 event and the h2c record must carry the shape"
    )
