"""Tests for the fake-vendor WAF canary and its cross-decoy integration adapters.

The per-honeypot SharePoint path is covered in test_honeypot_sharepoint.py; here we test the
shared adapters (``on_response_prepare`` aiohttp hook, ``apply_raw`` raw-HTTP splice) and that
every web decoy registers the hook so a sensor presents one consistent WAF identity.
"""

from __future__ import annotations

import asyncio

from aiohttp import web

from honeylens import config
from honeylens.honeypots import deception_waf


class _FakeReq:
    def __init__(self, headers: dict | None = None, remote: str = "") -> None:
        self.headers = headers or {}
        self.remote = remote


class _FakeResp:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.headers: dict[str, str] = {}


def _enable(monkeypatch, host: str = "unit-test-host", salt: str = "") -> None:
    monkeypatch.setattr(config, "WAF_CANARY_ENABLED", True)
    monkeypatch.setattr(config, "SENSOR_HOSTNAME", host)
    monkeypatch.setattr(config, "WAF_CANARY_SALT", salt)


# ── on_response_prepare (aiohttp hook) ───────────────────────────────────────────────────


def test_on_response_prepare_absent_by_default():
    req, resp = _FakeReq(remote="9.9.9.9"), _FakeResp()
    asyncio.run(deception_waf.on_response_prepare(req, resp))  # type: ignore[arg-type]
    assert resp.headers == {}


def test_on_response_prepare_adds_host_header_when_enabled(monkeypatch):
    _enable(monkeypatch)
    req, resp = _FakeReq(remote="9.9.9.9"), _FakeResp()
    asyncio.run(deception_waf.on_response_prepare(req, resp))  # type: ignore[arg-type]
    name = deception_waf.header_name("unit-test-host")
    assert name in resp.headers
    assert "id=" in resp.headers[name] and "mode=block" in resp.headers[name]


def test_on_response_prepare_prefers_x_real_ip(monkeypatch):
    _enable(monkeypatch)
    name = deception_waf.header_name("unit-test-host")
    r1 = _FakeResp()
    asyncio.run(
        deception_waf.on_response_prepare(
            _FakeReq(headers={"X-Real-IP": "1.2.3.4"}, remote="10.0.0.1"), r1
        )  # type: ignore[arg-type]
    )
    # value must be the nonce for the X-Real-IP client, not the peer
    assert r1.headers[name] == deception_waf.header_value("unit-test-host", "1.2.3.4")


# ── apply_raw (raw-HTTP splice, e.g. k8s Protocol server) ────────────────────────────────

_RAW = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: kube-apiserver\r\n\r\n{}"


def test_apply_raw_noop_when_disabled():
    assert deception_waf.apply_raw(_RAW, "1.2.3.4") == _RAW


def test_apply_raw_noop_without_header_terminator():
    assert deception_waf.apply_raw(b"garbage no crlf", "1.2.3.4") == b"garbage no crlf"


def test_apply_raw_splices_header_as_last_header_when_enabled(monkeypatch):
    _enable(monkeypatch)
    out = deception_waf.apply_raw(_RAW, "1.2.3.4")
    name = deception_waf.header_name("unit-test-host")
    value = deception_waf.header_value("unit-test-host", "1.2.3.4")
    head, _sep, body = out.partition(b"\r\n\r\n")
    assert body == b"{}"  # body untouched
    assert f"{name}: {value}".encode() in head
    # inserted as the LAST header line, directly before the blank line
    assert head.endswith(f"{name}: {value}".encode())
    # original headers preserved
    assert b"Server: kube-apiserver" in head


def test_apply_raw_nonce_differs_by_ip(monkeypatch):
    _enable(monkeypatch)
    a = deception_waf.apply_raw(_RAW, "1.2.3.4")
    b = deception_waf.apply_raw(_RAW, "5.6.7.8")
    assert a != b  # per-attacker-IP nonce


def test_apply_raw_matches_k8s_builder(monkeypatch):
    _enable(monkeypatch)
    from honeylens.honeypots.honeypot_k8s import build_http_response

    raw = build_http_response(200, "OK", "application/json", "{}")
    out = deception_waf.apply_raw(raw, "1.2.3.4")
    assert deception_waf.header_name("unit-test-host").encode() in out
    assert out.endswith(b"{}")


# ── every web decoy registers the hook (one consistent WAF per host) ─────────────────────


def test_fortigate_registers_waf_hook():
    from honeylens.honeypots.honeypot_fortigate import FortiGateHoneypot

    app = web.Application()
    FortiGateHoneypot().setup_routes(app)
    assert deception_waf.on_response_prepare in app.on_response_prepare


def test_paloalto_management_and_captive_register_waf_hook():
    from honeylens.honeypots.honeypot_paloalto import PaloAltoHoneypot

    hp = PaloAltoHoneypot()
    mgmt = web.Application()
    hp.setup_routes(mgmt)
    assert deception_waf.on_response_prepare in mgmt.on_response_prepare
    captive = web.Application()
    hp.setup_captive_routes(captive)
    assert deception_waf.on_response_prepare in captive.on_response_prepare


# ── callback DETECTION in the central classifier (fleet-wide, any source) ────────────────


def test_classifier_flags_canary_callback_fleet_wide():
    from honeylens.classification.attack_classifier import classify_event_row

    vendor = deception_waf.WAF_VENDORS[0]  # e.g. "Xilsoft-WAF"
    # A client reflects our fake header name/vendor back in a later request to any decoy.
    payload = f"GET /api/v2/cmdb/system?x=X-{vendor}-22092026 HTTP/1.1\r\nHost: h\r\n\r\n"
    hits = classify_event_row(payload, "HTTP")
    assert any(h[0] == "waf-canary-callback" for h in hits)


def test_classifier_canary_is_additive_not_exclusive():
    # A request that reflects a token AND carries a real exploit keeps BOTH classifications
    # (no detection short-circuit).
    from honeylens.classification.attack_classifier import classify_event_row

    vendor = deception_waf.WAF_VENDORS[0]
    payload = (
        f"GET /a?w=X-{vendor}-22092026&f=../../../../../../etc/passwd HTTP/1.1\r\nHost: h\r\n\r\n"
    )
    types = {h[0] for h in classify_event_row(payload, "HTTP")}
    assert "waf-canary-callback" in types
    assert len(types) > 1  # the LFI/traversal rule still fired


def test_classifier_no_canary_on_benign():
    from honeylens.classification.attack_classifier import classify_event_row

    hits = classify_event_row("GET /healthz HTTP/1.1\r\nHost: h\r\n\r\n", "HTTP")
    assert all(h[0] != "waf-canary-callback" for h in hits)


def test_canary_callback_severity_is_high():
    from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY

    assert ATTACK_TYPE_SEVERITY["waf-canary-callback"] == "high"


# ── manifest / quadlet generator (durable per-host enable) ───────────────────────────────

_WEB_DECOYS = ("sharepoint", "netscaler", "fortigate", "paloalto", "k8s")


def _quadlet(name: str) -> str:
    from honeylens.honeypots import manifest
    from honeylens.honeypots.cli import quadlet

    return quadlet(manifest.get(name), state_dir="/s", image_tag="1.0.0", registry="localhost")


def test_web_decoys_are_flagged_waf_canary():
    from honeylens.honeypots import manifest

    for n in _WEB_DECOYS:
        assert manifest.get(n).waf_canary is True
    # a non-web honeypot is not flagged
    assert manifest.get("modbus").waf_canary is False


def test_quadlet_pins_sensor_hostname_on_web_decoys(monkeypatch):
    monkeypatch.delenv("WAF_CANARY_ENABLED", raising=False)
    for n in _WEB_DECOYS:
        q = _quadlet(n)
        assert "Environment=SENSOR_HOSTNAME=" in q  # consistent per-host vendor
        assert "WAF_CANARY_ENABLED" not in q  # OFF by default


def test_quadlet_emits_canary_env_when_enabled(monkeypatch):
    monkeypatch.setenv("WAF_CANARY_ENABLED", "true")
    monkeypatch.setenv("WAF_CANARY_SALT", "deadbeef")
    monkeypatch.setenv("SENSOR_HOSTNAME", "sensor-c")
    q = _quadlet("sharepoint")
    assert "Environment=SENSOR_HOSTNAME=sensor-c" in q
    assert "Environment=WAF_CANARY_ENABLED=true" in q
    assert "Environment=WAF_CANARY_SALT=deadbeef" in q


def test_quadlet_no_canary_on_non_web_decoy(monkeypatch):
    monkeypatch.setenv("WAF_CANARY_ENABLED", "true")
    monkeypatch.setenv("WAF_CANARY_SALT", "deadbeef")
    q = _quadlet("modbus")
    assert "WAF_CANARY" not in q
    assert "SENSOR_HOSTNAME" not in q


def test_netscaler_registers_server_policy_hook():
    # NetScaler wires its own enforce_server_policy (Server banner + canary delegation).
    from honeylens.honeypots import netscaler_profile
    from honeylens.honeypots.honeypot_netscaler import NetScalerHoneypot

    app = web.Application()
    NetScalerHoneypot().setup_routes(app)
    assert netscaler_profile.enforce_server_policy in app.on_response_prepare


def test_netscaler_hook_attaches_canary_when_enabled(monkeypatch):
    from honeylens.honeypots import netscaler_profile

    _enable(monkeypatch)
    req, resp = _FakeReq(remote="9.9.9.9"), _FakeResp(status=200)
    asyncio.run(netscaler_profile.enforce_server_policy(req, resp))  # type: ignore[arg-type]
    assert deception_waf.header_name("unit-test-host") in resp.headers
    assert resp.headers.get("Server") == "Apache"  # existing banner policy preserved


# ── per-host unique vendor (WAF_CANARY_VENDOR override) ──────────────────────────────────


def test_vendor_override_pins_vendor(monkeypatch):
    monkeypatch.setattr(config, "WAF_CANARY_VENDOR", "Zypher-Gateway")
    # the host arg no longer decides the vendor — the pin wins (unique per host via env)
    assert deception_waf.vendor_for_host("whatever") == "Zypher-Gateway"
    assert deception_waf.header_name("whatever").startswith("X-Zypher-Gateway-")


def test_vendor_default_falls_back_to_pool(monkeypatch):
    monkeypatch.setattr(config, "WAF_CANARY_VENDOR", "")
    assert deception_waf.vendor_for_host("some-host") in deception_waf.WAF_VENDORS


def test_pinned_vendor_outside_pool_is_detected(monkeypatch):
    # a vendor pinned outside WAF_VENDORS is still caught when reflected back
    monkeypatch.setattr(config, "WAF_CANARY_VENDOR", "Zypher-Gateway")
    assert deception_waf.is_canary_callback("GET /?x=X-Zypher-Gateway-01012026 HTTP/1.1")


def test_quadlet_emits_vendor_when_set(monkeypatch):
    monkeypatch.setenv("WAF_CANARY_ENABLED", "true")
    monkeypatch.setenv("WAF_CANARY_SALT", "deadbeef")
    monkeypatch.setenv("WAF_CANARY_VENDOR", "Zypher-Gateway")
    monkeypatch.setenv("SENSOR_HOSTNAME", "prodX")
    q = _quadlet("sharepoint")
    assert "Environment=WAF_CANARY_VENDOR=Zypher-Gateway" in q
