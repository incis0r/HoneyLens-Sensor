#!/usr/bin/env python3
"""Differential test: measured SharePoint corpus vs. what the decoy actually answers (B11).

The contract lives in ``tests/data/sharepoint_corpus/manifest.json`` — response values
captured from a real on-prem SharePoint web front-end with
``scripts/sharepoint_capture_corpus.py``. Each scenario records the reference status, header
values (``null`` = header present, value dynamic), the Set-Cookie name order, and the body
length/sha256. Same shape as ``tests/test_netscaler_corpus_diff.py``.

The corpus is **gitignored** (it holds a third-party box's responses and a deployment's
unique identifiers), so:

* on a fresh clone / in CI the manifest is absent -> the module skips;
* if the capture was taken while the SharePoint web app was down (every surface answered by
  ``Microsoft-HTTPAPI/2.0`` with 404 — raw http.sys, not IIS/SharePoint) the reference is not
  a valid SharePoint baseline, so the module skips with that reason. Re-capture when the site
  on :80/:443 is bound again.

Scenarios known to diverge from the reference are listed in ``_KNOWN_DIVERGENCES`` (committed
here, so the annotation survives a corpus re-capture) and run ``xfail(strict=False)``: the
suite stays green, every fix shows up as XPASS, and the diff listing names what still differs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from honeylens.honeypots import honeypot_sharepoint as sp

_CORPUS = Path(__file__).parent / "data" / "sharepoint_corpus"
if not (_CORPUS / "manifest.json").exists():
    pytest.skip("SharePoint corpus not present (local-only)", allow_module_level=True)

MANIFEST = json.loads((_CORPUS / "manifest.json").read_text())
_SCENARIOS = MANIFEST["scenarios"]

# A capture is a valid SharePoint baseline only if the web app was actually serving. When every
# surface is a raw http.sys 404, the reference box's site was unbound at capture time and a
# diff against the decoy would be all-noise — skip and ask for a re-capture.
if all(
    s["expect"]["status"] == 404
    and (s["expect"]["headers"].get("Server") or "").startswith("Microsoft-HTTPAPI")
    for s in _SCENARIOS
):
    pytest.skip(
        "SharePoint corpus captured while the web app was down (all raw http.sys 404) — "
        "re-run scripts/sharepoint_capture_corpus.py when the site on :80/:443 is bound",
        allow_module_level=True,
    )

# scenario id -> reason the decoy differs from the reference (committed here, so it survives a
# corpus re-capture). Marked xfail(strict=False): the suite stays green and each entry is the
# punch-list for closing a fidelity gap — a fix flips it to XPASS. Three kinds:
#   [intentional] the decoy deliberately diverges from THIS LAB's state (better deception);
#   [artifact]    an effect of the in-process test client, not a real-world gap;
#   [fidelity]    a real gap to close when the decoy is tuned toward the measured box.
# From the 2026-10-07 capture of the internal reference box (SharePoint SE RTM).
_KNOWN_DIVERGENCES: dict[str, str] = {
    "09_trust": "[intentional] decoy serves the WS-Fed sign-in 200 to attract CVE-2026-50522; "
    "this LAB has /_trust unconfigured (404)",
    "10_spinstall0": "[intentional] decoy gates the MachineKey behind a ToolPane flip (cold=404); "
    "this LAB serves 200 at spinstall0",
    "00_root": "[artifact] 302 Location echoes the request Host (correct in prod); the 162 B IIS "
    "redirect body is not reproduced",
    "01_home": "[fidelity] self-contained home page (~4.5 KB) vs the real ~97 KB JS-app page; no "
    "Expires/Last-Modified",
    "02_service_cnf": "[fidelity] Content-Type text/plain (no charset) + static-file headers "
    "(Last-Modified/ETag/Accept-Ranges) not emulated",
    "03_spdisco": "[fidelity] discovery doc shorter than the real ~6 KB; Cache-Control 'private'",
    "04_start": "[fidelity] Cache-Control private,max-age=86400 + Expires not emulated; lighter body",
    "05_api_web_noauth": "[fidelity] real 401 body is XML (application/xml); decoy sends JSON; "
    "SPClientServiceRequestDuration header missing",
    "06_contextinfo": "[fidelity] real contextinfo defaults to XML (application/xml;charset=utf-8); "
    "decoy returns JSON odata=verbose",
    "07_toolpane": "[fidelity] lighter ToolPane body; no Expires/Last-Modified",
    "08_picker": "[fidelity] lighter Picker body; no SharePointError header; Cache-Control 'private'",
    "11_404_random": "[fidelity] IIS 404 carries Cache-Control/Expires/Accept-Ranges/Public-Extension; "
    "decoy 404 is leaner",
}


def _probe(method: str, path: str, data=None) -> dict:
    async def _main():
        hp = sp.SharePointHoneypot()
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
    return out


@pytest.mark.parametrize("scenario", _SCENARIOS, ids=[s["id"] for s in _SCENARIOS])
def test_sharepoint_corpus_scenario(scenario, request):
    if scenario["id"] in _KNOWN_DIVERGENCES:
        request.node.add_marker(
            pytest.mark.xfail(reason=_KNOWN_DIVERGENCES[scenario["id"]], strict=False)
        )
    req = scenario["request"]
    resp = _probe(req["method"], req["path"], data=req.get("data"))
    diffs = _diff(scenario, resp)
    assert not diffs, "response differs from measured reference:\n  " + "\n  ".join(diffs)


def test_no_framework_leak_on_any_scenario():
    """Hard invariant, reference-independent: the decoy never reveals Python/aiohttp."""
    for scenario in _SCENARIOS:
        req = scenario["request"]
        resp = _probe(req["method"], req["path"], data=req.get("data"))
        server = resp["headers"].get("server", "")
        assert "aiohttp" not in server.lower() and "python" not in server.lower(), (
            f"{req['method']} {req['path']}: framework leaked in Server: {server!r}"
        )
        assert b"aiohttp" not in resp["body"].lower(), (
            f"{req['method']} {req['path']}: framework leaked in body"
        )
