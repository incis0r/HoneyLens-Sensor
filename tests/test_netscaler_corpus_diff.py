#!/usr/bin/env python3
"""Differential test: measured NetScaler corpus vs. what the honeypot actually answers.

The contract lives in ``tests/data/netscaler_corpus/manifest.json`` — response values
captured passively from a real NetScaler Gateway (classic LogonPoint theme), a NetScaler
AAA (nFactor) instance, and the Citrix Cloud Workspace facade. Each scenario records the
reference status, header values (``null`` = header present, value dynamic), headers that
must be absent, the exact Set-Cookie sequence, and body length/sha256.

Scenarios where the honeypot is known to diverge from the reference are marked
``xfail(strict=False)``: the suite stays green, every fix shows up as XPASS, and the diff
listing printed on failure documents exactly which response values still differ.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from honeylens.honeypots import honeypot_netscaler as ns

_CORPUS = Path(__file__).parent / "data" / "netscaler_corpus"
if not (_CORPUS / "manifest.json").exists():
    # The corpus is kept local only (gitignored — it holds third-party appliance captures,
    # including an employer StoreFront page). Without it on disk this differential suite has
    # nothing to compare against, so skip it rather than fail a fresh clone / CI.
    pytest.skip("NetScaler corpus not present (local-only)", allow_module_level=True)

MANIFEST = json.loads((_CORPUS / "manifest.json").read_text())


def _probe(method: str, path: str, data=None) -> dict:
    async def _main():
        hp = ns.NetScalerHoneypot()
        app = web.Application()
        hp.setup_routes(app)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            r = await client.request(method, path, data=data, allow_redirects=False)
            return {
                "status": r.status,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "set_cookies": [v for k, v in r.raw_headers if k.lower() == b"set-cookie"],
                "body": await r.read(),
            }
        finally:
            await client.close()

    return asyncio.run(_main())


def _diff(scenario: dict, resp: dict) -> list[str]:
    """Compare one scenario's expectations with a honeypot response; return diffs."""
    out = []
    exp = scenario["expect"]
    if resp["status"] != exp["status"]:
        out.append(f"status: reference={exp['status']} honeypot={resp['status']}")
    for name, want in exp.get("headers", {}).items():
        got = resp["headers"].get(name.lower())
        if got is None:
            out.append(f"header {name}: missing (reference has it)")
        elif want is not None and got != want:
            out.append(f"header {name}: reference={want!r} honeypot={got!r}")
    for name in exp.get("headers_absent", []):
        if name.lower() in resp["headers"]:
            out.append(
                f"header {name}: must be absent, honeypot sends {resp['headers'][name.lower()]!r}"
            )
    want_cookies = exp.get("set_cookie_names_in_order")
    if want_cookies is not None:
        got_names = [c.decode("latin-1").split("=", 1)[0] for c in resp["set_cookies"]]
        if got_names != want_cookies:
            out.append(f"set-cookie order: reference={want_cookies} honeypot={got_names}")
    body = exp.get("body", {})
    if "length" in body and len(resp["body"]) != body["length"]:
        out.append(f"body length: reference={body['length']} honeypot={len(resp['body'])}")
    if "sha256" in body:
        digest = hashlib.sha256(resp["body"]).hexdigest()
        if digest != body["sha256"]:
            out.append(f"body sha256: reference={body['sha256'][:16]}… honeypot={digest[:16]}…")
    for needle in body.get("contains", []):
        if needle.encode() not in resp["body"]:
            out.append(f"body missing reference fragment {needle!r}")
    return out


def _scenarios(profile: str):
    return MANIFEST["profiles"][profile]["scenarios"]


_CLASSIC = _scenarios("classic_gateway")


@pytest.mark.parametrize("scenario", _CLASSIC, ids=[s["id"] for s in _CLASSIC])
def test_classic_gateway_scenario(scenario, request):
    if scenario.get("honeypot_status") == "diverge":
        request.node.add_marker(
            pytest.mark.xfail(
                reason=scenario.get("divergence", "known divergence from reference"),
                strict=False,
            )
        )
    req = scenario["request"]
    resp = _probe(req["method"], req["path"], data=req.get("data"))
    diffs = _diff(scenario, resp)
    assert not diffs, "response differs from measured reference:\n  " + "\n  ".join(diffs)


def test_no_framework_leak_on_any_scenario():
    """Hard invariant: nothing may reveal Python/aiohttp, whatever the path or method."""
    for profile in MANIFEST["profiles"].values():
        for scenario in profile["scenarios"]:
            req = scenario["request"]
            resp = _probe(req["method"], req["path"], data=req.get("data"))
            server = resp["headers"].get("server", "")
            assert "aiohttp" not in server.lower() and "python" not in server.lower(), (
                f"{req['method']} {req['path']}: framework leaked in Server: {server!r}"
            )
            assert b"aiohttp" not in resp["body"].lower(), (
                f"{req['method']} {req['path']}: framework leaked in body"
            )


def test_manifest_bodies_match_corpus_files():
    """The manifest hashes must match the captured bodies on disk (corpus integrity)."""
    base = Path(__file__).parent / "data" / "netscaler_corpus"
    files = {
        "root-redirect": "gateway_classic/00_root.body",
        "vpn-index-redirect": "gateway_classic/01_vpn_index.body",
        "logonpage-get": "gateway_classic/02_logonpoint_tmindex.body",
        "unknown-path-404": "gateway_classic/03_404_random.body",
        "failed-login-post": "gateway_classic/05_post_login.body",
        "aaa-logonpage-get": "gateway_aaa/02_logonpoint_tmindex.body",
        "workspace-root-redirect": "workspace_cloud/root_302.body",
        "storeweb-get": "workspace_cloud/storeweb.html",
    }
    for profile in MANIFEST["profiles"].values():
        for scenario in profile["scenarios"]:
            rel = files.get(scenario["id"])
            want = scenario["expect"].get("body", {}).get("sha256")
            if rel and want:
                digest = hashlib.sha256((base / rel).read_bytes()).hexdigest()
                assert digest == want, f"{scenario['id']}: corpus file {rel} hash mismatch"
