"""The `payload` field must carry the request body, not just its length.

The NGINX decoy captured the body into metadata (`body_sample`) but wrote only
`POST / body_len=702` into `payload` — the field that appears in the event list,
in exports, in reports and in a plain SQL grep. The evidence was there and
invisible unless you knew to open the metadata.

Concretely, the Cisco AnyConnect campaign on DEV: 27,548 events in a day, each one
displayed as `POST / body_len=700`, while the body underneath said

    <config-auth client="vpn" type="init">
      <device-id computer-name="zwnvafhkxn" device-type="Dell PowerEdge R640" ...>
      <group-select>telecommuters</group-select>

— the tunnel group being enumerated, and a rack server claiming to be a remote
worker's laptop. None of that reached anyone reading the event list.
"""

from __future__ import annotations

from honeylens.honeypots import hp_nginx as hp

BODY = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<config-auth client="vpn" type="init">'
    "<group-select>telecommuters</group-select></config-auth>"
)


def test_the_body_is_in_the_payload():
    out = hp._payload_with_body(f"POST / body_len={len(BODY)}", {"body_sample": BODY})
    assert "group-select" in out and "telecommuters" in out


def test_the_summary_line_is_kept():
    """Reports and greps already key on the `METHOD path body_len=N` shape."""
    out = hp._payload_with_body("POST / body_len=115", {"body_sample": BODY})
    assert out.startswith("POST / body_len=115\n")


def test_a_request_with_no_body_is_unchanged():
    """'no body' and 'an empty body' are different observations; neither gains a
    trailing newline it did not have."""
    assert hp._payload_with_body("GET / body_len=0", {}) == "GET / body_len=0"
    assert hp._payload_with_body("GET / body_len=0", {"body_sample": ""}) == "GET / body_len=0"


def test_a_large_body_is_bounded_and_says_so():
    """Bodies are read up to 1 MiB and payload is stored on every event."""
    out = hp._payload_with_body("POST / body_len=20000", {"body_sample": "A" * 20000})
    assert len(out) < 20000
    assert "truncated" in out
    assert "full body in metadata" in out, "the reader must know where the rest is"


def test_the_bound_is_configurable():
    assert isinstance(hp._PAYLOAD_BODY_BYTES, int) and hp._PAYLOAD_BODY_BYTES > 0


def test_a_capture_level_truncation_is_distinguished_from_ours():
    """If the capture layer already cut the body, saying nothing would imply the
    payload is the whole request."""
    out = hp._payload_with_body(
        "POST /x body_len=9999", {"body_sample": "abc", "body_truncated": True}
    )
    assert "truncated by capture" in out


def test_metadata_still_carries_the_full_body():
    """The payload bound must not become the storage bound."""
    import inspect

    src = inspect.getsource(hp)
    i = src.index("**body_fields,")
    assert "body_fields = _body_fields(http)" in src[:i], (
        "metadata must be spread from the same unbounded capture"
    )
