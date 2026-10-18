#!/usr/bin/env python3
"""Capture a reference SharePoint corpus for the differential test (todo B11).

Mirrors the NetScaler corpus approach (``tests/test_netscaler_corpus_diff.py``): hit a real
on-prem SharePoint web front-end over HTTP(S), record each surface's status, header values
(dynamic ones nulled), the Set-Cookie name order, and the body length + sha256, and write it
all to ``tests/data/sharepoint_corpus/`` — which is **gitignored**. The capture holds a
third-party appliance's responses and a deployment's unique identifiers, so it never enters
the repo; only this script and the diff test (which skips when the corpus is absent) are
committed.

    scripts/sharepoint_capture_corpus.py http://192.0.2.10

Passive only: GET/HEAD plus one synthetic ToolPane/contextinfo POST with a benign body. No
exploit payloads, no authenticated access, no scanning. Re-run to refresh the corpus when the
reference box is back in its measured state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

_CORPUS = Path(__file__).resolve().parent.parent / "tests" / "data" / "sharepoint_corpus"

# Headers whose value is per-request / per-deployment: kept in the manifest as ``null`` (present
# but dynamic) so the diff asserts presence, not an exact value that could never match.
_DYNAMIC_HEADERS = {
    "date",
    "sprequestguid",
    "request-id",
    "sprequestduration",
    "spiislatency",
    "www-authenticate",  # the Bearer realm GUID is per-deployment
    "content-length",  # asserted via body.length instead
}

# The surfaces the decoy emulates — the differential contract. One synthetic POST body each for
# the ToolPane and contextinfo paths; nothing exploit-shaped.
_SCENARIOS: list[dict] = [
    {"id": "00_root", "method": "GET", "path": "/"},
    {"id": "01_home", "method": "GET", "path": "/SitePages/Home.aspx"},
    {"id": "02_service_cnf", "method": "GET", "path": "/_vti_pvt/service.cnf"},
    {"id": "03_spdisco", "method": "GET", "path": "/_vti_bin/spdisco.aspx"},
    {"id": "04_start", "method": "GET", "path": "/_layouts/15/start.aspx"},
    {"id": "05_api_web_noauth", "method": "GET", "path": "/_api/web"},
    {"id": "06_contextinfo", "method": "POST", "path": "/_api/contextinfo", "body": b""},
    {"id": "07_toolpane", "method": "GET", "path": "/_layouts/15/ToolPane.aspx"},
    {"id": "08_picker", "method": "GET", "path": "/_layouts/15/Picker.aspx"},
    {"id": "09_trust", "method": "GET", "path": "/_trust/"},
    {"id": "10_spinstall0", "method": "GET", "path": "/_layouts/15/spinstall0.aspx"},
    {"id": "11_404_random", "method": "GET", "path": "/zzz-not-a-real-path-zzz"},
]


def _fetch(base: str, scenario: dict, timeout: float, host_header: str | None = None) -> dict:
    url = base.rstrip("/") + scenario["path"]
    body = scenario.get("body")
    req = urllib.request.Request(url, method=scenario["method"], data=body)
    req.add_header("User-Agent", "Mozilla/5.0 (compatible; corpus-capture)")
    # The LAB web app is bound to a host header (e.g. `sharepoint01`); a bare-IP request is
    # answered by raw http.sys (404) instead of IIS/SharePoint, so a capture must send it.
    if host_header:
        req.add_header("Host", host_header)
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Don't follow redirects: a 302 is a scenario in its own right, and its Location host
    # (e.g. sharepoint01) is not DNS-resolvable from the capturing machine anyway.
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        resp = opener.open(req, timeout=timeout)
        status, headers, raw = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:  # 3xx (not followed) + 4xx/5xx carry headers+body
        status, headers, raw = exc.code, exc.headers, exc.read()

    header_pairs = list(headers.items())
    set_cookies = [v for k, v in header_pairs if k.lower() == "set-cookie"]
    out_headers: dict[str, str | None] = {}
    for k, v in header_pairs:
        if k.lower() == "set-cookie":
            continue
        out_headers[k] = None if k.lower() in _DYNAMIC_HEADERS else v
    return {
        "id": scenario["id"],
        "request": {k: scenario[k] for k in ("method", "path") if k in scenario},
        "expect": {
            "status": status,
            "headers": out_headers,
            "set_cookie_names_in_order": [c.split("=", 1)[0] for c in set_cookies],
            "body": {"length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        },
        "_raw": raw,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture a SharePoint reference corpus (B11).")
    ap.add_argument("base", help="base URL of the reference box, e.g. http://192.0.2.10")
    ap.add_argument(
        "--host-header",
        help="Host header to send (the LAB web app is bound to one, e.g. sharepoint01; a bare-IP "
        "request gets a raw http.sys 404 instead of SharePoint)",
    )
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    _CORPUS.mkdir(parents=True, exist_ok=True)
    scenarios = []
    for sc in _SCENARIOS:
        try:
            cap = _fetch(args.base, sc, args.timeout, args.host_header)
        except Exception as exc:
            print(f"  ! {sc['id']} {sc['method']} {sc['path']}: {exc}", file=sys.stderr)
            continue
        (_CORPUS / f"{cap['id']}.body").write_bytes(cap.pop("_raw"))
        scenarios.append(cap)
        print(
            f"  = {cap['id']:18} {cap['request']['method']:4} {cap['request']['path']}"
            f" -> {cap['expect']['status']} ({cap['expect']['body']['length']} B)"
        )

    manifest = {
        "version": 1,
        "captured_at": datetime.now(UTC).isoformat(),
        "capture_method": (
            "Passive GET/HEAD plus synthetic benign POST (ToolPane/contextinfo). No exploit "
            "traffic, no scanning, no authenticated access. Dynamic headers nulled."
        ),
        "source": args.base,
        "host_header": args.host_header,
        "scenarios": scenarios,
    }
    (_CORPUS / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(scenarios)} scenarios -> {_CORPUS}/manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
