"""OPSEC guards on published blog content.

Regression for a real leak (2026-08-13): the live blog served an /ip/<addr> page
profiling one of our own sensors as a "threat actor", plus a payload block on another
post whose captured request line read `Host: <our own public IP>:6443`.
Addresses below are RFC 5737 documentation ranges — this repo carries no real ones.
The prose sanitiser had worked (the body said "[SENSOR-IP]"), but nothing stopped the
post being about us, and SENSOR_PUBLIC_IPS was unset on that sensor.
"""

import importlib

import pytest


@pytest.fixture
def bp(monkeypatch):
    monkeypatch.setenv("SENSOR_PUBLIC_IPS", "203.0.113.9")
    import honeylens.publishing.blog_publisher as m

    importlib.reload(m)
    m._LEARNED_OWN_IPS.clear()
    yield m
    m._LEARNED_OWN_IPS.clear()


def test_configured_own_ip_is_recognised(bp):
    assert bp._is_own_ip("203.0.113.9")
    assert not bp._is_own_ip("85.239.149.173")


def test_own_ip_is_stripped_from_text(bp):
    assert "203.0.113.9" not in bp._opsec_sanitise("saw 203.0.113.9 probing")


def test_host_header_teaches_us_our_own_address(bp):
    """The leak's exact shape: no configuration named this address."""
    payload = "GET / HTTP/1.1\r\nHost: 198.51.100.7:6443"
    out = bp._opsec_sanitise(payload)
    assert "198.51.100.7" not in out, out
    assert bp._is_own_ip("198.51.100.7")  # remembered for later posts


def test_learned_address_survives_into_the_publish_gate(bp):
    bp._opsec_sanitise("GET / HTTP/1.1\r\nHost: 198.51.100.7:8443")
    assert bp._is_own_ip("198.51.100.7")


def test_attacker_ips_in_payloads_are_left_alone(bp):
    """Only the Host line is ours; the rest of a payload is evidence."""
    payload = "POST /login HTTP/1.1\r\nHost: 203.0.113.9\r\nX-Forwarded-For: 45.148.10.23"
    out = bp._opsec_sanitise(payload)
    assert "45.148.10.23" in out
    assert "203.0.113.9" not in out


def test_private_ranges_still_stripped(bp):
    out = bp._opsec_sanitise("internal 192.168.10.34 and 10.1.2.3 and 172.16.5.6")
    for ip in ("192.168.10.34", "10.1.2.3", "172.16.5.6"):
        assert ip not in out


def _publisher(bp):
    pub = bp.BlogPublisher.__new__(bp.BlogPublisher)  # no config/DB needed for the gate
    pub.enabled = True
    return pub


def test_publisher_refuses_a_post_about_our_own_address(bp):
    res = _publisher(bp).publish("203.0.113.9")
    assert res["status"] == "rejected"
    assert "own public IP" in res["msg"]


def test_publisher_refuses_an_address_learned_from_a_host_header(bp):
    """The real case: nothing configured, but a captured Host header named us."""
    bp._opsec_sanitise("GET / HTTP/1.1\r\nHost: 198.51.100.7:6443")
    assert _publisher(bp).publish("198.51.100.7")["status"] == "rejected"


def test_publisher_still_refuses_private_ips(bp):
    assert _publisher(bp).publish("192.168.10.34")["status"] == "rejected"


def test_publisher_still_accepts_a_real_attacker(bp, monkeypatch):
    """The gate must not become a blanket refusal."""
    monkeypatch.setattr(bp, "_is_own_ip", lambda ip: False)
    res = _publisher(bp).publish("85.239.149.173")
    assert res["status"] != "rejected"


def test_captured_credentials_are_never_published(bp):
    """Honeypot payloads carry credential pairs in the clear on purpose. The
    attacker's password is often a victim's real one, so the publisher redacts it
    even though the sensor keeps it."""
    payload = "credential_attempt username=admin password=Hunter2!"
    out = bp._sanitise_payload(payload)
    assert "Hunter2!" not in out
    assert "password=[REDACTED]" in out
    assert "admin" in out  # the username is still evidence worth showing


@pytest.mark.parametrize("field", ["password", "passwd", "pwd", "secretkey", "SECRET"])
def test_credential_field_variants_are_covered(bp, field):
    out = bp._sanitise_payload(f"POST /login {field}=S3cr3tValue")
    assert "S3cr3tValue" not in out
