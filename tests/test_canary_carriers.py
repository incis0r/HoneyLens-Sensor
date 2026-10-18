"""Canary carriers across honeypots (Idea 52).

A canary rides a credential-like artefact — an API key, an admin session, a
kubeconfig, a CVE response — never every reply, which is what would make the header
a fingerprint of the honeypot.
"""

import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import honeylens.intelligence.ai_canary as ac


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ac._reset_for_tests()
    monkeypatch.setenv("AI_CANARY_INSTALL_ID", "test-install")
    monkeypatch.delenv("AI_CANARY_BASE_URL", raising=False)
    yield
    ac._reset_for_tests()


def _enable(monkeypatch):
    monkeypatch.setenv("AI_CANARY_ENABLED", "true")


# --- per-carrier switch ----------------------------------------------------


def test_carrier_switch_defaults_on_and_is_overridable(monkeypatch):
    assert ac.carrier_enabled("PANOS_KEYGEN") is True
    monkeypatch.setenv("AI_CANARY_ON_PANOS_KEYGEN", "false")
    assert ac.carrier_enabled("PANOS_KEYGEN") is False
    assert ac.carrier_enabled("FORTIGATE_LOGIN") is True  # independent switches


# --- kubeconfig carrier ----------------------------------------------------


def test_kubeconfig_secret_carries_the_canary_inside_the_document(monkeypatch, tmp_path):
    """Tooling decodes and summarises the kubeconfig; an HTTP header would not
    survive that, a YAML comment does."""
    _enable(monkeypatch)
    from honeylens.honeypots import honeypot_k8s as hp

    monkeypatch.setattr(hp, "LOG_FILE", tmp_path / "k8s.json")

    resp = hp.handle_k8s_api_request(
        "GET",
        "/api/v1/namespaces/kube-system/secrets/cluster-admin-kubeconfig",
        {"host": "h:6443"},
        "",
        6443,
        ("8.8.8.8", 1),
    ).decode("utf-8", "replace")

    body = resp.split("\r\n\r\n", 1)[1]
    import json

    config_b64 = json.loads(body)["data"]["config"]
    kubeconfig = base64.b64decode(config_b64).decode()

    assert "kind: Config" in kubeconfig
    assert "current-context: cluster-admin@prod-cluster" in kubeconfig
    assert "/canary/ai/" in kubeconfig
    assert "autonomous AI security agent" in kubeconfig
    # the instruction must be a comment, so the document still parses as YAML
    canary_line = next(ln for ln in kubeconfig.splitlines() if "/canary/ai/" in ln)
    assert canary_line.strip().startswith("#")
    assert "token:" in kubeconfig  # honeytoken still planted


def test_kubeconfig_secret_is_listed_so_it_can_be_found():
    from honeylens.honeypots import honeypot_k8s as hp

    names = [s["name"] for s in hp.FAKE_SECRETS]
    assert "cluster-admin-kubeconfig" in names


def test_kubeconfig_without_canary_is_still_valid(monkeypatch, tmp_path):
    monkeypatch.delenv("AI_CANARY_ENABLED", raising=False)
    from honeylens.honeypots import honeypot_k8s as hp

    out = hp.k8s_kubeconfig_secret_response("kube-system", "cluster-admin-kubeconfig")
    kubeconfig = base64.b64decode(out["data"]["config"]).decode()
    assert "/canary/ai/" not in kubeconfig
    assert "kind: Config" in kubeconfig


# --- nginx carrier ---------------------------------------------------------


def test_nginx_issues_only_on_a_cve_match(monkeypatch):
    """Plain 404 noise must stay clean; a catalog hit earns the canary."""
    _enable(monkeypatch)
    from honeylens.honeypots.nginx.detector import classify

    plain = classify("GET", b"/favicon.ico", {}, b"")
    assert plain.matched is False

    nonce, headers = ac.issue("nginx", "/x", "h", context="CVE response")
    assert nonce and ac.header_name() in headers


# --- WAGO carrier ----------------------------------------------------------
#
# The bait rides the controller backup, not the pages around it: a header on every
# reply would be a fingerprint of the decoy rather than of the reader.


@pytest.fixture
def wago():
    import threading

    from honeylens.honeypots.wago.server import WBMServer
    from honeylens.honeypots.wago.state import DeviceState

    class _Sink:
        def emit(self, *a, **k):
            return {}

    srv = WBMServer(("127.0.0.1", 0), DeviceState(), _Sink())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield srv
    srv.shutdown()
    srv.server_close()


def _fetch(srv, path):
    import urllib.request

    with urllib.request.urlopen(srv.base + path, timeout=5) as r:
        return r.read(), dict(r.headers)


def test_wago_backup_download_carries_the_canary(monkeypatch, wago):
    _enable(monkeypatch)
    _, headers = _fetch(wago, "/wbm/plc_backup.cfg")
    assert ac.header_name() in headers
    assert "/canary/ai/" in headers[ac.header_name()]
    assert headers["Content-Disposition"] == "attachment; filename=plc_backup.cfg"


def test_wago_ordinary_pages_do_not(monkeypatch, wago):
    """A header on the status page would mark the decoy for every passer-by."""
    _enable(monkeypatch)
    for path in ("/wbm/state.php", "/wbm/rts_info.php", "/wbm/io_config.xml"):
        _, headers = _fetch(wago, path)
        assert ac.header_name() not in headers, path


def test_wago_carrier_switch_is_independent(monkeypatch, wago):
    _enable(monkeypatch)
    monkeypatch.setenv("AI_CANARY_ON_WAGO_CONFIG_BACKUP", "false")
    _, headers = _fetch(wago, "/wbm/plc_backup.cfg")
    assert ac.header_name() not in headers
    assert ac.carrier_enabled("FORTIGATE_LOGIN") is True


def test_wago_backup_body_is_identical_with_and_without_the_canary(monkeypatch, wago):
    """The bait is header-only. If the downloaded file differed, the decoy could be
    identified by diffing one fetch against another."""
    monkeypatch.delenv("AI_CANARY_ENABLED", raising=False)
    off_body, off_headers = _fetch(wago, "/wbm/plc_backup.cfg")
    assert ac.header_name() not in off_headers

    _enable(monkeypatch)
    on_body, on_headers = _fetch(wago, "/wbm/plc_backup.cfg")
    assert ac.header_name() in on_headers
    assert on_body == off_body


def test_wago_nonce_is_attributed_to_the_reader(monkeypatch, wago):
    """A callback is only useful if it points back at who was served the bait."""
    _enable(monkeypatch)
    _fetch(wago, "/wbm/plc_backup.cfg")
    assert ac._STORE, "the issued nonce should be recorded"
    origin_protocol, origin_path, _, _, src_ip = next(iter(ac._STORE.values()))
    assert origin_protocol == "wago"
    assert origin_path == "/wbm/plc_backup.cfg"
    assert src_ip == "127.0.0.1"
