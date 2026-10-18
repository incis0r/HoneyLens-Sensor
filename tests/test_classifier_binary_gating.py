"""Binary/ICS-protocol rules must not fire on HTTP traffic.

Regression for the false "Modbus/MQTT attack" tags on plain web requests (an AI
rule's `\\x5a` byte matching the 'z' in a Mozilla User-Agent on port 102).
"""

import re

from honeylens.classification import attack_classifier as AC
from honeylens.classification.binary_detectors import _detect_k8s_attack


def test_helper_identifies_binary_proto_rules():
    assert AC._rule_targets_binary_proto("claude_modbus_fc90_illegal", "AI_DETECTED")
    assert AC._rule_targets_binary_proto("mqtt_wildcard_single", "MQTT_ATTACK")
    assert AC._rule_targets_binary_proto("claude_s7comm_read_szl", "AI_DETECTED")
    assert not AC._rule_targets_binary_proto("http_sqli_union", "SQLI")
    assert not AC._rule_targets_binary_proto("php_webshell_eval", "PHP")


def test_ai_modbus_rule_gated_on_http(monkeypatch):
    # the exact broken DB rule shape: \x5a matches 'z' (Mozilla) with IGNORECASE
    rule = ("AI_DETECTED", "claude_modbus_fc90_illegal", re.compile(r"FC=90|\x5a", re.I))
    monkeypatch.setattr(AC, "_RULES", [*list(AC._RULES), rule])
    payload = (
        "GET / HTTP/1.1\r\nHost: x:102\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    )
    hits = AC.classify_event_row(payload, "HTTP", {"dst_port": 102})
    assert "claude_modbus_fc90_illegal" not in [h[1] for h in hits]


def test_ai_modbus_rule_still_fires_in_ics_context(monkeypatch):
    rule = ("AI_DETECTED", "claude_modbus_fc90_illegal", re.compile(r"FC=90", re.I))
    monkeypatch.setattr(AC, "_RULES", [*list(AC._RULES), rule])
    # non-HTTP, Modbus port, honeypot's textual modbus representation
    hits = AC.classify_event_row("FC=90 unit=1 addr=100", "TCP", {"dst_port": 502})
    assert "claude_modbus_fc90_illegal" in [h[1] for h in hits]


def test_benign_http_get_produces_no_ics_tag(monkeypatch):
    rule = ("AI_DETECTED", "claude_modbus_fc90_illegal", re.compile(r"FC=90|\x5a", re.I))
    monkeypatch.setattr(AC, "_RULES", [*list(AC._RULES), rule])
    hits = AC.classify_event_row(
        "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n\r\n", "HTTP", {"dst_port": 80}
    )
    assert not any(AC._rule_targets_binary_proto(h[1], h[0]) for h in hits)


# ---------------------------------------------------------------------------
# Port-only K8s rules must not label bare SYN scans as attacks
# ---------------------------------------------------------------------------


def test_syn_scan_on_8001_is_not_a_k8s_attack():
    """A SYN scan gives eBPF a ~60-byte frame whose few header bytes slipped past
    the `if not payload` guard, so port 8001 alone tagged it K8S_ATTACK
    (the edge host event d28c5846..., 216.180.246.212 -> :8001, scan_type 'SYN Scan')."""
    hits = _detect_k8s_attack("}\udcef\udcbf", "TCP", {"dst_port": 8001, "scan_type": "SYN Scan"})
    assert [h[1] for h in hits] == []


def test_syn_scan_on_30000_is_not_a_k8s_attack():
    hits = _detect_k8s_attack("}\udcef\udcbf", "TCP", {"dst_port": 30000})
    assert [h[1] for h in hits] == []


def test_real_kubectl_proxy_request_still_detected():
    payload = "GET /api/v1/namespaces/default/pods HTTP/1.1\r\nHost: x:8001\r\n\r\n"
    assert "k8s_kubectl_proxy" in [
        h[1] for h in _detect_k8s_attack(payload, "HTTP", {"dst_port": 8001})
    ]


def test_real_dashboard_request_still_detected():
    payload = "GET /#/login HTTP/1.1\r\nHost: x:30000\r\n\r\n"
    assert "k8s_dashboard_access" in [
        h[1] for h in _detect_k8s_attack(payload, "HTTP", {"dst_port": 30000})
    ]


def test_has_http_request_helper():
    from honeylens.classification.binary_detectors import _has_http_request

    assert _has_http_request("get /api/v1 http/1.1")
    assert _has_http_request("post /apis/apps/v1/deployments")
    assert not _has_http_request("}\udcef\udcbf")
    assert not _has_http_request("")


# --- 2026-08-16: "any HTTP on the port" was still too generous -----------------


def test_bare_get_on_kubectl_proxy_port_is_not_an_attack():
    """The 2026-08-12 fix required a request line, which stopped SYN scans being
    called K8s attacks. It did not stop `GET /`.

    On PROD one host produced 20,432 events with `GET /` and
    `GET /1:0:1:3ABD:514:13E:820000:0:0:0:` over wget — 98.7% of every K8s finding on
    that sensor. Reaching a kubectl proxy means asking it for something
    Kubernetes-shaped; touching the port is reconnaissance and is named as such.
    """
    hits = _detect_k8s_attack(
        "GET / HTTP/1.1\r\nUser-Agent: curl/7.74.0", "HTTP", {"dst_port": 8001}
    )
    names = [h[1] for h in hits]
    assert "k8s_kubectl_proxy" not in names
    assert "k8s_proxy_port_probe" in names
    assert all(h[0] != "K8S_ATTACK" for h in hits)


def test_the_actual_prod_payload_is_not_an_attack():
    hits = _detect_k8s_attack(
        "GET /1:0:1:3ABD:514:13E:820000:0:0:0: HTTP/1.1\r\nUser-Agent: Wget/1.20.1",
        "HTTP",
        {"dst_port": 8001},
    )
    assert all(h[0] != "K8S_ATTACK" for h in hits)


def test_real_kubectl_proxy_api_access_still_fires():
    """The guard must not silence what it exists to preserve."""
    for path in ("/api/v1/namespaces/kube-system/secrets", "/apis/apps/v1/deployments", "/version"):
        hits = _detect_k8s_attack(f"GET {path} HTTP/1.1", "HTTP", {"dst_port": 8001})
        assert "k8s_kubectl_proxy" in [h[1] for h in hits], path
    # /healthz is recognised by its own rule; what matters is that it is Kubernetes and
    # is not simultaneously written off as a blind port probe.
    hits = _detect_k8s_attack("GET /healthz HTTP/1.1", "HTTP", {"dst_port": 8001})
    assert any(h[0] == "K8S_ATTACK" for h in hits)
    assert not any("port_probe" in h[1] for h in hits)


def test_dashboard_port_needs_a_dashboard_path():
    probe = _detect_k8s_attack("GET / HTTP/1.1", "HTTP", {"dst_port": 30000})
    assert "k8s_dashboard_access" not in [h[1] for h in probe]
    real = _detect_k8s_attack("GET /#!/login HTTP/1.1", "HTTP", {"dst_port": 30000})
    assert "k8s_dashboard_access" in [h[1] for h in real]


def test_api_is_not_a_wildcard_for_other_products():
    """`/api\\b` counted `GET /api/mcp` — Model Context Protocol probing, of which
    there is currently a lot — as a Kubernetes attack. Kubernetes owns `/api`,
    `/api/v<N>` and `/apis/`; anything else under `/api/` belongs to someone else."""
    for path in ("/api/mcp", "/sse", "/api/graphql"):
        hits = _detect_k8s_attack(f"GET {path} HTTP/1.1", "HTTP", {"dst_port": 8001})
        assert "k8s_kubectl_proxy" not in [h[1] for h in hits], path
    for path in ("/api", "/api/v1/pods", "/apis/apps/v1"):
        hits = _detect_k8s_attack(f"GET {path} HTTP/1.1", "HTTP", {"dst_port": 8001})
        assert "k8s_kubectl_proxy" in [h[1] for h in hits], path


def test_scanner_wordlist_under_api_is_not_kubernetes():
    """Third iteration on this gate, and the reason it needed one.

    A scanner spraying a generic web wordlist at the kubectl-proxy port produces paths
    that match `/api/v<N>` while having nothing to do with Kubernetes. These are the
    actual requests from 185.177.72.5, which supplied 98.8% of PROD's K8s findings.
    Kubernetes access names a *resource*; a prefix is not evidence.
    """
    for path in (
        "/api/v1/swagger%2ejson",
        "/api/v1/config%2ejson",
        "/api/v1/sms-sender",
        "/apis/%2eenv%2edev",
        "/apis/config/config%2ejs",
        "/apis/%2eenv",
    ):
        hits = _detect_k8s_attack(f"GET {path} HTTP/1.1", "HTTP", {"dst_port": 8001})
        assert "k8s_kubectl_proxy" not in [h[1] for h in hits], path


def test_resource_paths_are_still_kubernetes():
    for path in (
        "/api/v1/pods",
        "/api/v1/nodes",
        "/api/v1/namespaces/prod/secrets/x",
        "/apis/apps/v1/deployments",
        "/api",
        "/version",
    ):
        hits = _detect_k8s_attack(f"GET {path} HTTP/1.1", "HTTP", {"dst_port": 8001})
        assert "k8s_kubectl_proxy" in [h[1] for h in hits], path


def test_a_request_is_never_both_kubernetes_and_a_blind_port_probe():
    """The two labels were independent, so /healthz and /apis/apps/v1 came back as
    K8S_ATTACK *and* a port probe on the same event. The probe is now a fallback that
    only applies when nothing else recognised the request."""
    for path in ("/healthz", "/apis/apps/v1", "/api/v1/pods", "/version"):
        hits = _detect_k8s_attack(f"GET {path} HTTP/1.1", "HTTP", {"dst_port": 8001})
        assert any(h[0] == "K8S_ATTACK" for h in hits), path
        assert not any("port_probe" in h[1] for h in hits), path


def test_api_enumeration_also_needs_a_resource():
    """k8s_api_enumeration matched the `/api/v1` prefix, so the scanner's
    /api/v1/config.json was still recorded as Kubernetes API enumeration even after the
    proxy gate was tightened."""
    for path in ("/api/v1/config%2ejson", "/apis/config/config%2ejs", "/api/v1/sms-sender"):
        hits = _detect_k8s_attack(f"GET {path} HTTP/1.1", "HTTP", {"dst_port": 8001})
        assert "k8s_api_enumeration" not in [h[1] for h in hits], path
