"""Two classifications that described the sensor's own plumbing as attacker behaviour.

Both were found by reading a fleet LAN review rather than a bug report, and both are the
same shape: a rule that is correct for the case it was written for, firing on traffic that
merely resembles it.

  * Every `SURICATA ...` alert is an event the engine emits about its own packet
    processing. Their classtype is "Generic Protocol Command Decode", so they were mapped
    to PROTO_ABUSE — 24k on PROD and 44k on sensor-a in 30 days, the third-largest attack type
    on the fleet, and one file download from GitHub produced 2,845 of them in eight
    minutes against a baseline of ~40 an hour.

  * `ssrf_internal_ip` looks for a URL pointing at an internal address. WS-Discovery
    `Hello` announcements carry exactly that — the device stating its own address in
    `<wsd:XAddrs>`. On PROD it scored 227 hits in 30 days and every one was that; the real
    SSRF traffic was caught by the other two SSRF rules.
"""

from __future__ import annotations

import pytest

from honeylens.classification.rules import register_all
from honeylens.classification.scoring import get_severity
from honeylens.classification.text_rules import compile_rule
from honeylens.ingest.suricata import classify_attack

# --- Suricata engine events ------------------------------------------------------


@pytest.mark.parametrize(
    "signature",
    [
        "SURICATA STREAM ESTABLISHED packet out of window",
        "SURICATA STREAM 3way handshake excessive different SYN/ACKs",
        "SURICATA STREAM Packet with invalid ack",
        "SURICATA TCPv4 invalid checksum",
        "SURICATA TLS invalid record type",
        "SURICATA HTTP unable to match response to request",
        "SURICATA HTTP missing Host header",
        "SURICATA Applayer Mismatch protocol both directions",
        "SURICATA SSH invalid banner",
    ],
)
def test_engine_events_are_not_protocol_abuse(signature):
    """All of these arrive with the classtype that used to make them PROTO_ABUSE."""
    assert classify_attack(signature, "Generic Protocol Command Decode") == "ENGINE_ANOMALY"


def test_engine_anomalies_score_as_information():
    """They stay visible — invalid checksums and retransmissions are real capture-quality
    signals — but must not compete with attacks for attention."""
    assert get_severity("ENGINE_ANOMALY", "whatever") == "info"


@pytest.mark.parametrize(
    "signature,category,expected",
    [
        ("ET SCAN Nmap Scripting Engine User-Agent", "Misc activity", "SCANNER"),
        ("ET DROP Dshield Block Listed Source", "Misc Attack", "REPUTATION"),
        ("ET EXPLOIT Possible CVE-2021-44228", "Web Application Attack", "WEB_EXPLOIT"),
        ("GPL SNMP public access udp", "Attempted Information Leak", "INFO_DISCLOSURE"),
    ],
)
def test_real_signatures_are_untouched(signature, category, expected):
    """ET and GPL rules never carry the SURICATA prefix, which is what makes keying on it
    safe. If that ever stopped being true this test says so."""
    assert classify_attack(signature, category) == expected


def test_the_prefix_must_be_at_the_start():
    """A rule merely mentioning the word must not be swallowed by the engine bucket."""
    assert (
        classify_attack("ET INFO Talks About SURICATA Somewhere", "Web Application Attack")
        == "WEB_EXPLOIT"
    )


# --- WS-Discovery vs SSRF --------------------------------------------------------


@pytest.fixture(scope="module")
def rules():
    out = {}

    def add(attack_type, name, pattern, flags=0, *, min_count=None):
        # compile_rule, not re.compile: a counting rule must be built the way production
        # builds it, or it degrades here into "one occurrence" and the table lies.
        out[name] = (attack_type, compile_rule(pattern, flags, min_count=min_count))

    register_all(add)
    return out


def fired(rules, text):
    return {n for n, (_a, rx) in rules.items() if rx.search(text)}


# Addresses below are RFC 5737 documentation range on purpose: this payload is modelled on
# real traffic, and a client's internal addressing has no business in a public repository.
WSD_HELLO = (
    '<?xml version="1.0" encoding="utf-8"?><soap:Envelope '
    'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
    "<soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
    "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</wsa:Action>"
    "</soap:Header><soap:Body><wsd:Hello>"
    "<wsd:XAddrs>http://192.0.2.177:5357/1ac8466c-845d-4cff-89a0-0d2f61b70821/</wsd:XAddrs>"
    "</wsd:Hello></soap:Body></soap:Envelope>"
)

SSDP_NOTIFY = (
    "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    "LOCATION: http://192.0.2.44:2869/upnphost/udhisapi.dll?content=uuid:x\r\n"
    "NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n"
)


def test_a_device_announcing_itself_is_not_ssrf(rules):
    """The exact payload behind 227 mislabels on PROD."""
    assert "ssrf_internal_ip" not in fired(rules, WSD_HELLO)


def test_ssdp_is_not_ssrf_either(rules):
    """Same shape, different protocol — 2,959 such payloads were already on PROD, kept out
    of this rule only by protocol gating rather than by the rule being right."""
    assert "ssrf_internal_ip" not in fired(rules, SSDP_NOTIFY)


@pytest.mark.parametrize(
    "payload",
    [
        "GET /fetch?url=http://127.0.0.1:8080/admin HTTP/1.1",
        "GET /proxy?target=http://192.168.1.1/config HTTP/1.1",
        'POST /api {"callback": "http://10.0.0.5:9200/_cluster/health"}',
        "GET /?u=http://172.16.0.10/ HTTP/1.1",
        "GET /?u=http://localhost/admin HTTP/1.1",
    ],
)
def test_real_ssrf_still_fires(rules, payload):
    """The guard must not cost the rule its purpose."""
    assert "ssrf_internal_ip" in fired(rules, payload), payload


def test_the_guard_covers_the_whole_payload(rules):
    """The discovery marker can sit either side of the URL, which is why the lookahead is
    anchored at the start of the string rather than placed next to the match."""
    before = "<wsd:XAddrs/> ... http://192.168.1.1/x"
    after = "http://192.168.1.1/x ... schemas.xmlsoap.org/ws/2005/04/discovery"
    assert "ssrf_internal_ip" not in fired(rules, before)
    assert "ssrf_internal_ip" not in fired(rules, after)


def test_an_attacker_cannot_hide_behind_the_marker_on_a_web_port(rules):
    """Documented limit, not an oversight.

    Someone who pastes the WS-Discovery namespace into an SSRF payload evades this rule.
    That is accepted: the alternative was 227 false positives against zero true ones on
    this surface, and the other SSRF rules — cloud-metadata and gopher/dict — carry no
    such guard and still fire.
    """
    evasion = (
        "schemas.xmlsoap.org/ws/2005/04/discovery "
        "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1"
    )
    assert "ssrf_internal_ip" not in fired(rules, evasion)
    assert "ssrf_cloud_metadata" in fired(rules, evasion)
