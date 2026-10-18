#!/usr/bin/env python3
"""NetScaler decoy: authentic Citrix headers, full payload capture, CVE tagging.

The honeypot's whole job is to answer like a real Citrix NetScaler / StoreFront and to
record everything a caller sends. These tests drive the real aiohttp routes through a test
server (no TLS). The event is captured through a shim sink (the real ``build_record``, with
``write_record`` kept in memory instead of on a volume), which is the same envelope
``honeylens-ingest-honeypot`` consumes. One test additionally checks the standalone stdout
feed — what someone running the container outside HoneyLens sees in ``podman logs``.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from honeylens.honeypots import honeypot_netscaler as ns
from honeylens.honeypots import sink as real_sink


class _CaptureSink:
    """Real build_record (full envelope), but write_record kept in memory — no volume."""

    def __init__(self):
        self.records: list[dict] = []

    def build_record(self, **kw):
        return real_sink.build_record(**kw)

    def write_record(self, record):
        self.records.append(record)
        return True


def _exchange(method: str, path: str, *, headers=None, data=None):
    """One request against the decoy; return (resp dict, sink record, event dict)."""
    cap = _CaptureSink()

    async def _main():
        hp = ns.NetScalerHoneypot()
        hp._sink = cap
        app = web.Application()
        hp.setup_routes(app)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            # allow_redirects=False: a 302 must be inspected directly, not followed (§8 docs,
            # §219). raw_headers preserves order and every duplicate Set-Cookie; the dict is a
            # convenience view that collapses duplicates.
            r = await client.request(
                method, path, headers=headers or {}, data=data, allow_redirects=False
            )
            raw = await r.read()
            return {
                "status": r.status,
                "headers": dict(r.headers),
                "raw_headers": [
                    (k.decode("latin-1"), v.decode("latin-1")) for k, v in r.raw_headers
                ],
                # text view tolerates binary assets (gif/ico); body_bytes keeps them exact.
                "body": raw.decode("utf-8", errors="replace"),
                "body_bytes": raw,
            }
        finally:
            await client.close()

    resp = asyncio.run(_main())
    rec = cap.records[-1] if cap.records else {}
    return resp, rec, rec.get("event", {})


def test_http_proxy_header_is_used_only_for_the_trusted_edge():
    assert ns._http_client_ip("198.51.100.1", "198.51.100.1", "203.0.113.19", "198.51.100.1") == (
        "203.0.113.19"
    )
    assert ns._http_client_ip("198.51.100.8", "198.51.100.8", "203.0.113.19", "198.51.100.1") == (
        "198.51.100.8"
    )


def test_http_proxy_rejects_invalid_forwarded_address():
    assert (
        ns._http_client_ip("198.51.100.1", "198.51.100.1", "not-an-ip", "198.51.100.1")
        == "198.51.100.1"
    )


# --- measured classic_gateway response contract (stage B) --------------------------------
# These pin behaviour the byte-for-byte corpus diff (tests/test_netscaler_corpus_diff.py)
# also enforces; here they document the intent at the handler level. The reference is a real
# on-prem NetScaler Gateway on the classic LogonPoint theme — no StoreFront, no IIS banner,
# no Citrix-TransactionId on the gateway surface.


def test_storefront_path_is_not_served_as_storefront():
    """We emulate the gateway, not Citrix StoreFront. A StoreWeb auth path falls through to
    the Apache 404 — never an IIS/Citrix StoreFront response — and never leaks the runtime."""
    resp, _rec, ev = _exchange(
        "POST",
        "/Citrix/StoreWeb/ExplicitAuth/Login",
        headers={"Citrix-Transactionid": "abc-123"},
        data=b"{}",
    )
    h = resp["headers"]
    assert resp["status"] == 404
    assert h.get("Server") == "Apache"  # not Microsoft-IIS
    assert "Citrix-TransactionId" not in h  # the gateway never echoes it
    assert "aiohttp" not in h.get("Server", "") and "Python" not in h.get("Server", "")
    assert ev["surface"] == "storefront"  # still classified by surface for the record


def test_logon_page_is_the_self_contained_gateway():
    """GET of the LogonPoint serves our dependency-free NetScaler Gateway logon: 200, Apache,
    a NetScaler brand and an inline SVG mark, no external asset requests, and no cookies."""
    resp, _rec, _ev = _exchange("GET", "/logon/LogonPoint/tmindex.html")
    assert resp["status"] == 200
    assert resp["headers"].get("Server") == "Apache"
    body = resp["body"]
    assert "NetScaler Gateway" in body and "<svg" in body  # branded, self-contained graphic
    assert "receiver/js/" not in body and "<script" not in body  # no external JS to 404 or crash
    cookies = [v for k, v in resp["raw_headers"] if k.lower() == "set-cookie"]
    assert cookies == []  # cookies ride the entry redirect, not the logon GET


def test_root_redirects_to_logonpoint_with_no_server_banner():
    resp, _rec, _ev = _exchange("GET", "/")
    assert resp["status"] == 302
    locs = [v for k, v in resp["raw_headers"] if k.lower() == "location"]
    assert locs == ["/logon/LogonPoint/tmindex.html"]
    servers = [v for k, v in resp["raw_headers"] if k.lower() == "server"]
    assert servers == []  # the reference sends no Server on a redirect


def test_entry_redirect_clears_nsc_cookies_in_order():
    """The entry redirect (GET /) emits the seven clearing NSC_* cookies in the measured
    order, each Secure+HttpOnly — the vpn/index.html alias behaves identically."""
    expected = ["NSC_DLGE", "NSC_USER", "NSC_CERT", "NSC_TEMP", "NSC_PERS", "NSC_TEMP", "NSC_PERS"]
    for path in ("/", "/vpn/index.html"):
        resp, _rec, _ev = _exchange("GET", path)
        assert resp["status"] == 302
        cookies = [v for k, v in resp["raw_headers"] if k.lower() == "set-cookie"]
        names = [c.split("=", 1)[0] for c in cookies]
        assert names == expected, path
        assert all("secure" in c.lower() and "httponly" in c.lower() for c in cookies)


def test_response_headers_available_as_ordered_list():
    resp, _rec, _ev = _exchange("GET", "/logon/LogonPoint/tmindex.html")
    assert resp["raw_headers"] and all(isinstance(k, str) for k, _ in resp["raw_headers"])
    assert any(k.lower() == "server" for k, _ in resp["raw_headers"])


# --- logon surface: self-contained, renders without external dependencies ----------------


def test_failed_login_renders_gateway_page_with_error_banner():
    """A login POST re-renders the same self-contained page with the classic error banner."""
    resp, _rec, _ev = _exchange(
        "POST",
        "/cgi/login",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=b"login=jsmith&passwd=hunter2",
    )
    assert resp["status"] == 200
    assert resp["headers"].get("Server") == "Apache"
    assert "Incorrect user name or password" in resp["body"]
    assert "NetScaler Gateway" in resp["body"]


def test_logon_surface_makes_no_external_requests():
    """The page must be fully self-contained: no <script>, <link rel=stylesheet> or receiver/
    asset references that would 404 and break the render in a browser."""
    resp, _rec, _ev = _exchange("GET", "/logon/LogonPoint/tmindex.html")
    body = resp["body"]
    assert "<script" not in body
    assert "stylesheet" not in body  # styles are inline
    assert "receiver/" not in body


def test_unknown_logon_subpath_is_the_apache_404():
    """A stale asset path (a browser cache, an old bookmark) still gets the Apache 404."""
    resp, _rec, _ev = _exchange("GET", "/logon/LogonPoint/receiver/js/does-not-exist.js")
    assert resp["status"] == 404
    assert resp["headers"].get("Server") == "Apache"


# --- event writer: bounded, off-loop, counted losses (stage C) ---------------------------


def test_eventlog_counts_drops_when_queue_full():
    from honeylens.honeypots.netscaler_eventlog import EventLog

    el = EventLog(sink=None, maxsize=1)  # not started: the queue fills and stays full
    assert el.submit({"a": 1}) is True
    assert el.submit({"a": 2}) is False  # dropped, not raised
    assert el.metrics["accepted"] == 1 and el.metrics["dropped"] == 1


def test_eventlog_drains_to_sink():
    from honeylens.honeypots.netscaler_eventlog import EventLog

    cap = _CaptureSink()

    async def _run():
        el = EventLog(sink=cap, maxsize=10)
        await el.start()
        el.submit({"schema": "honeylens-event/1", "event": {}})
        await el.aclose()  # flushes the queue before stopping
        return el

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        el = asyncio.run(_run())
    assert len(cap.records) == 1
    assert el.metrics["written"] == 1 and el.metrics["dropped"] == 0


# --- full payload capture ---------------------------------------------------------------


def test_captures_full_credential_body_verbatim():
    body = b"login=acme\\\\jsmith&passwd=Sup3rSecret!&savecredentials=true"
    _resp, rec, ev = _exchange("POST", "/cgi/login", data=body)
    assert ev["method"] == "POST" and ev["path"] == "/cgi/login"
    assert ev["body_len"] == len(body)
    assert "Sup3rSecret!" in ev["body_sample"]  # verbatim — the credential is the evidence
    assert "raw_hex" in rec  # raw request bytes retained


def test_captures_all_request_headers():
    _resp, _rec, ev = _exchange(
        "GET", "/vpn/index.html", headers={"X-Weird-Probe": "marker-9f8a7b"}
    )
    assert ev["headers"].get("X-Weird-Probe") == "marker-9f8a7b"


# --- CVE tagging ------------------------------------------------------------------------


def test_login_command_injection_tagged_88771():
    _resp, rec, _ev = _exchange(
        "POST",
        "/cgi/login",
        headers={"User-Agent": "Mozilla/5.0 ${IFS}b64decode"},
        data=b"login=x",
    )
    assert rec.get("attack_type") == "ns-login-cmd-injection"
    assert rec.get("rules") == ["CVE-2026-88771"]


def test_webshell_hex_alias_tagged_but_legit_css_is_not():
    _r1, rec_mal, _e1 = _exchange("GET", "/logon/LogonPoint/custom/receiver.min.deadbeef.css")
    assert rec_mal.get("rules") == ["CVE-2026-88771"]
    _r2, rec_ok, _e2 = _exchange("GET", "/logon/LogonPoint/custom/receiver.min.css")
    assert "attack_type" not in rec_ok  # the legitimate StoreFront asset is not flagged


def test_citrixbleed_oidc_oversized_host_is_a_low_confidence_candidate():
    _resp, rec, _ev = _exchange(
        "GET",
        "/oauth/idp/.well-known/openid-configuration",
        headers={"Host": "a" * 260},
    )
    assert rec.get("rules") == ["CVE-2023-4966"]
    assert rec.get("attack_type") == "ns-oidc-oversized-host"
    assert rec.get("severity") == "MEDIUM" and rec.get("confidence") == "low"


def test_normal_oidc_request_is_surface_only():
    _resp, rec, ev = _exchange(
        "GET",
        "/oauth/idp/.well-known/openid-configuration",
        headers={"Host": "gateway.example.com"},
    )
    assert "attack_type" not in rec  # a normal discovery call is not an attack
    assert ev["surface"] == "gateway-oidc-discovery"


def test_path_traversal_tagged_19781():
    resp, rec, _ev = _exchange("GET", "/vpns/cfg/smb.conf")
    assert resp["status"] == 404  # the reference answers an unknown /vpns path with Apache 404
    assert rec.get("rules") == ["CVE-2019-19781"]
    assert rec.get("attack_type") == "ns-path-traversal"


def test_bare_vpns_without_traversal_is_surface_only():
    """Merely reaching /vpns/ is not traversal — no CVE, no CRITICAL (docs §8.1)."""
    _resp, rec, ev = _exchange("GET", "/vpns/")
    assert "attack_type" not in rec
    assert ev["surface"] == "gateway-vpns"


def test_normal_login_and_saml_are_not_flagged():
    _r1, rec_login, _e1 = _exchange(
        "POST",
        "/cgi/login",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=b"login=jsmith&passwd=hunter2",
    )
    assert "attack_type" not in rec_login  # a real credential attempt is surface-only
    _r2, rec_saml, _e2 = _exchange("GET", "/saml/login")
    assert "attack_type" not in rec_saml  # reaching SAML is not a bypass (docs §8.6)


def test_all_matching_behaviours_are_returned():
    """A generic path must not mask a stronger payload: both tells are recorded (docs §8.7)."""
    _resp, rec, ev = _exchange(
        "POST",
        "/cgi/login",
        headers={
            "User-Agent": "curl/8 ${IFS}b64decode",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data=b"login",
    )
    behaviours = {m["behaviour"] for m in ev["matches"]}
    assert {"login-cmd-injection", "citrixbleed2-login-shape"} <= behaviours
    assert set(rec["rules"]) == {"CVE-2026-88771", "CVE-2025-5777"}


# --- standalone stdout feed -------------------------------------------------------------


def test_standalone_emits_json_to_stdout_without_a_sink():
    """With no sink (fully standalone), every capture is still one JSON line on stdout."""

    async def _main():
        hp = ns.NetScalerHoneypot()
        hp._sink = None
        app = web.Application()
        hp.setup_routes(app)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            await client.request("POST", "/cgi/login", data=b"login=probe")
        finally:
            await client.close()

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        asyncio.run(_main())
    lines = [json.loads(line) for line in buf.getvalue().splitlines() if line.startswith("{")]
    assert lines, "standalone decoy must print a JSON event line"
    assert lines[-1]["event"]["path"] == "/cgi/login"
    assert lines[-1]["event"]["body_len"] == len(b"login=probe")


# --- manifest wiring --------------------------------------------------------------------


def test_capability_matrix_is_honest_about_every_proposal_cve():
    """The NetScaler decoy proposal lists the CVEs. The matrix must name each one and
    tell the truth per docs §8.8 — a CVE string is not emulation."""
    proposed = {
        "CVE-2026-88771",
        "CVE-2026-88772",
        "CVE-2019-19781",
        "CVE-2023-3519",
        "CVE-2023-4966",
        "CVE-2025-5777",
        "CVE-2025-6543",
        "CVE-2025-7775",
    }
    matrix = ns.capability_matrix()
    assert proposed <= set(matrix)
    # 88772 is DTLS/UDP — no listener, so the matrix must not pretend it is served.
    assert matrix["CVE-2026-88772"]["transport"] == "dtls"
    assert matrix["CVE-2026-88772"]["surface_served"] is False
    # 6543 / 7775 share a surface but have no public signature — captured, not fingerprinted.
    assert matrix["CVE-2025-6543"]["behaviour_signature"] is False
    assert matrix["CVE-2025-6543"]["surface_served"] is True


def test_citrixbleed2_login_shape_tags_only_5777():
    """The CitrixBleed-2 tell is 5777 alone — 6543/7775 are unrelated per the vendor (§8.4)."""
    _resp, rec, _ev = _exchange(
        "POST",
        "/p/u/doAuthentication.do",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=b"login",
    )
    assert rec.get("attack_type") == "ns-citrixbleed2-login-shape"
    assert rec.get("rules") == ["CVE-2025-5777"]


def test_manifest_entry_sane_and_conflict_free():
    from honeylens.honeypots import cli, manifest

    hp = manifest.get("netscaler")
    assert hp.entry == "main" and hp.identity == "netscaler"
    assert hp.port_block == manifest.NETSCALER_PORT_BLOCK == 50000
    # Bound high in its own block; the event still records the protocol port 443/80.
    assert hp.port_map == [(50443, 443), (50080, 80)]
    assert hp.runtime_env["HONEYLENS_PORT_MAP"] == "50443:443,50080:80"
    assert cli.port_conflicts(manifest.HONEYPOTS) == []  # 50000 block stands beside the rest
