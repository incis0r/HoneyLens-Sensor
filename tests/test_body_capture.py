"""Bounded, redacted capture of request bodies (MCP paths).

We were recording `body_len=241` for MCP POSTs and discarding the message, so 183
requests from 94 sources over 90 days told us only that somebody knocked. These tests
pin the three properties that make capturing it safe: it is bounded, credentials are
removed, and it does not quietly start capturing everything.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeylens.honeypots.body_capture import MAX_CAPTURE, capture, redact, should_capture


def test_mcp_paths_are_captured():
    for path in (
        "/mcp",
        "/mcp/",
        "/api/mcp",
        "/sse",
        "/.well-known/mcp.json",
        "/messages",
        "/jsonrpc",
    ):
        assert should_capture(path), path


def test_every_body_is_captured():
    """Widened 2026-08-16: bodies are recorded for all captured connections, not only
    the MCP paths the module started with."""
    for path in ("/", "/wp-login.php", "/api/v1/pods", "/index.php", "/.env", "/mcp"):
        assert should_capture(path), path
    out = capture(b"user=admin&password=x", "/wp-login.php")
    assert out["body_sample"].startswith("user=admin")


def test_high_value_paths_are_still_marked():
    """The MCP paths stay distinguishable now that everything is captured, so an
    analyst can still find them without reading the whole pile."""
    assert capture(b"{}", "/mcp").get("body_high_value") is True
    assert "body_high_value" not in capture(b"x=1", "/wp-login.php")


def test_the_real_mcp_handshake_survives_intact():
    body = (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
        '{"protocolVersion":"2024-11-05","clientInfo":{"name":"probe"}}}'
    )
    out = capture(body, "/mcp", "application/json")
    assert out["body_sample"] == body
    assert out["body_len"] == len(body)
    assert out["body_truncated"] is False


def test_capture_is_bounded():
    out = capture("x" * (MAX_CAPTURE * 4), "/mcp")
    assert len(out["body_sample"]) == MAX_CAPTURE
    assert out["body_truncated"] is True
    assert out["body_len"] == MAX_CAPTURE * 4  # true size still reported


def test_credentials_are_stored_verbatim():
    """A honeypot that masks the credential destroys its own evidence.

    Ranking the usernames and passwords actually being tried cannot be done from
    `password=<redacted:7>`, and on a sensor inside a client network a real employee
    credential in a POST dates the compromise — which corpus it came from, and so
    roughly when the account was taken.
    """
    body = (
        '{"Authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",'
        '"api_key":"sk-proj-9f8a7b6c5d4e","password":"hunter2"}'
    )
    out = capture(body, "/mcp")["body_sample"]
    for secret in ("eyJhbGciOiJIUzI1NiJ9", "sk-proj-9f8a7b6c5d4e", "hunter2"):
        assert secret in out, secret
    assert out == body


def test_form_login_attempts_keep_both_halves():
    out = capture(b"username=admin&password=Summer2024!", "/wp-login.php")["body_sample"]
    assert out == "username=admin&password=Summer2024!"


def test_redact_masks_a_bare_jwt_even_unlabelled():
    out = redact("token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcdefghij.sig")
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in out
    assert "redacted-jwt" in out


def test_binary_bodies_are_kept_as_base64_not_mangled():
    """An exploit payload is not text. It is preserved, but base64 so it survives JSON
    and is obviously not a string to read."""
    import base64

    raw = b"\x00\x01\x02\xff\xfe"
    out = capture(raw, "/mcp")
    assert out["body_encoding"] == "binary"
    assert "body_sample" not in out
    assert base64.b64decode(out["body_sample_b64"]) == raw


def test_redact_still_exists_for_the_publication_path():
    """Not applied at capture, but a captured body may reach a blog post or a customer
    report, and the credential must not travel with it."""
    assert "Summer2024" not in redact("password=Summer2024!")
    assert "password=" in redact("password=Summer2024!")


def test_empty_body_yields_only_a_length():
    assert capture(b"", "/mcp") == {"body_len": 0}
