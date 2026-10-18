"""The event page has to show the request, not a summary of it.

`/event_full/{id}` rendered `POST / body_len=700` — the one-line `payload` summary —
while the 700 bytes sat in `metadata` behind a 200px scroll box of raw JSON. The whole
point of capturing bodies is reading them, so the page now renders the request line,
the headers and the full body as their own section.

Everything here is attacker-supplied text going into HTML, so the escaping tests are
not decoration: a honeypot that renders a captured `<script>` unescaped attacks its
own operator with the payload it was built to collect.
"""

from __future__ import annotations

from honeylens.webui.endpoint_generic import http_request_html


def _meta(**kw):
    base = {"method": "POST", "path": "/", "dst_port": 8443}
    base.update(kw)
    return base


# ------------------------------------------------------------------- the body


def test_full_body_is_rendered():
    body = '<config-auth client="vpn" type="init">' + "x" * 600
    out = http_request_html(_meta(body_sample=body, body_len=len(body)))
    assert "config-auth" in out
    assert out.count("x" * 600) == 1, "body was truncated or dropped"


def test_body_is_escaped():
    out = http_request_html(_meta(body_sample="<script>alert(1)</script>", body_len=25))
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_byte_count_is_shown():
    out = http_request_html(_meta(body_sample="abc", body_len=3))
    assert "3" in out


def test_truncation_is_declared():
    """A body cut at MAX_CAPTURE must say so, or the reader trusts a partial record."""
    out = http_request_html(_meta(body_sample="a" * 100, body_len=99999, body_truncated=True))
    assert "truncat" in out.lower()
    assert "99999" in out or "99,999" in out


def test_binary_body_is_offered_as_base64_not_mangled():
    out = http_request_html(_meta(body_sample_b64="AAEC//4=", body_encoding="binary", body_len=5))
    assert "AAEC//4=" in out
    assert "binary" in out.lower()


# ---------------------------------------------------------------- the headers


def test_headers_are_rendered():
    out = http_request_html(
        _meta(
            headers={
                "Host": "198.51.100.10:8443",
                "User-Agent": "AnyConnect Windows 4.5.04029",
                "Content-Type": "application/xml",
            },
            body_sample="x",
            body_len=1,
        )
    )
    assert "User-Agent" in out
    assert "AnyConnect Windows 4.5.04029" in out
    assert "198.51.100.10:8443" in out


def test_header_values_are_escaped():
    """What matters is that no tag can form. `onerror=...` surviving as literal text
    inside a <pre> is the correct outcome — it is evidence, and it is inert."""
    out = http_request_html(
        _meta(headers={"X-Evil": '"><img src=x onerror=alert(1)>'}, body_sample="x", body_len=1)
    )
    assert "<img" not in out
    assert "&lt;img" in out
    assert "&gt;" in out


def test_header_names_are_escaped_too():
    """A header *name* is as attacker-controlled as its value."""
    out = http_request_html(_meta(headers={"<script>x</script>": "v"}, body_sample="x", body_len=1))
    assert "<script>" not in out


# ------------------------------------------------------------- request line


def test_request_line_is_shown():
    out = http_request_html(_meta(method="POST", path="/wp-login.php", body_sample="x", body_len=1))
    assert "POST" in out and "/wp-login.php" in out


def test_path_is_escaped():
    out = http_request_html(_meta(path="/<script>alert(1)</script>", body_sample="x", body_len=1))
    assert "<script>" not in out


# ------------------------------------------------------------------ nothing to show


def test_no_http_metadata_renders_nothing():
    """Non-HTTP honeypots (Modbus, SSH, ...) must not grow an empty section."""
    assert http_request_html({"phase": "connect", "dst_port": 502}) == ""
    assert http_request_html(None) == ""
    assert http_request_html({}) == ""


def test_get_with_no_body_still_shows_the_request_line():
    """The headers of a body-less request are still worth reading."""
    out = http_request_html(
        _meta(method="GET", path="/admin", body_len=0, headers={"User-Agent": "curl/8.4.0"})
    )
    assert "GET" in out and "/admin" in out and "curl/8.4.0" in out
