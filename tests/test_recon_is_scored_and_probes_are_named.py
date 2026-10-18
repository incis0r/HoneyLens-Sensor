"""A probe is named a probe, and `RECON` finally scores like one.

B2d. Two findings, measured 2026-11-04 over 30 days.

**A bare request to the etcd port had no verdict.** `GET /` on :2379 appeared 149 times on
`sensor-a`, 107 on `sensor-b` and 61 on `prod`, with `OPTIONS /` (6/12), `/favicon.ico` (19/8/21),
`/robots.txt` (12/11/4), `/sitemap.xml` (6/6/4), nmap's `/nice%20ports%2C/Tri%6Eity.txt%2ebak`
(2/6) and a long tail of other products' login paths -- `/login.jsp`, `/HNAP1`,
`/cgi-bin/login.cgi`, `/evox/about`, `/manage/account/login`. None of it is etcd, all of it is
somebody checking what answers on the port, and none of it was labelled.

**`RECON` was in neither the severity table nor the MITRE map.** Exactly one rule emitted it
-- `k8s_proxy_port_probe`, which exists after 20,432 rows of `GET /` were called K8s attacks
on `prod` -- and with no entry it fell back to `ATTACK_TYPE_SEVERITY`'s `medium` default. So
the verdict whose entire purpose is to say "this was only a probe" scored the same as
enumerating an etcd cluster, and higher than the h2c preface added in B2c. The plan pointed at
`k8s_proxy_port_probe` as the precedent to follow; the precedent needed fixing first.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.mitre_mapping import get_mitre_mapping
from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY, get_severity

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

PROBE = "k8s_etcd_port_probe"


def _hits(path, port=2379, method="GET"):
    return classify_event_row(
        payload=f"{method} {path} HTTP/1.1\r\nHost: x\r\n\r\n",
        protocol="http",
        metadata={"dst_port": port, "path": path, "method": method},
    )


def _rules(path, **kw):
    return {h[1] for h in _hits(path, **kw)}


# ---------------------------------------------------------------------------
# RECON is scored and mapped
# ---------------------------------------------------------------------------


def test_recon_has_its_own_severity():
    assert "RECON" in ATTACK_TYPE_SEVERITY
    assert _RANK[ATTACK_TYPE_SEVERITY["RECON"]] <= _RANK["low"]


def test_recon_is_mapped_to_a_technique():
    assert get_mitre_mapping("RECON")


def test_a_probe_does_not_outrank_a_real_finding():
    """The defect this fixes: `k8s_proxy_port_probe` scored `medium`, the same as etcd cluster
    enumeration and above the h2c preface."""
    probe = _RANK[get_severity("RECON", "k8s_proxy_port_probe")]
    enumeration = _RANK[get_severity("K8S_ATTACK", "k8s_etcd_members")]
    preface = _RANK[get_severity("PROTO_ABUSE", "http2_h2c_prior_knowledge_preface")]

    assert probe < enumeration, (probe, enumeration)
    assert probe <= preface, (probe, preface)


# ---------------------------------------------------------------------------
# The etcd port probe
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/login.jsp",
        "/HNAP1",
        "/cgi-bin/login.cgi",
        "/evox/about",
        "/nice%20ports%2C/Tri%6Eity.txt%2ebak",
    ],
)
def test_a_request_with_no_etcd_path_is_a_port_probe(path):
    assert PROBE in _rules(path)


def test_a_bare_options_is_also_a_probe():
    assert PROBE in _rules("/", method="OPTIONS")


@pytest.mark.parametrize(
    "path",
    [
        "/v3/kv/range",
        "/v2/keys/registry/pods",
        "/version",
        "/health",
        "/metrics",
        "/v2/members",
        "/v2/auth/status",
        "/v1/kv/?recurse=true",
    ],
)
def test_a_real_etcd_request_is_not_called_a_probe(path):
    """Mirrors the `already_k8s` discipline in the kubectl-proxy block: whatever else
    recognised this request, it was not a blind probe. Without that the two labels contradict
    each other on the same event."""
    rules = _rules(path, method="POST")

    assert PROBE not in rules, (path, rules)


def test_an_h2c_preface_is_not_also_called_a_probe():
    """The preface already says what the request was. It is named outside `_detect_k8s_attack`,
    so the probe has to ask about it rather than read it off the hits collected there.

    Today's decoys store `payload` as `"PRI *"`, which `_has_http_request` rejects anyway, so
    this pair cannot occur in the data. It is pinned because a decoy that someday keeps the
    whole request line would otherwise earn both verdicts on one event."""
    hits = classify_event_row(
        payload="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        protocol="http",
        metadata={"dst_port": 2379, "path": "*", "method": "PRI"},
    )
    rules = {h[1] for h in hits}

    assert "http2_h2c_prior_knowledge_preface" in rules
    assert PROBE not in rules, rules


def test_bytes_that_are_not_an_http_request_are_not_a_probe():
    """A TLS ClientHello on :2379 is a protocol mismatch, not an HTTP probe. The decoy
    fabricates a request line for one (157 rows on `sensor-a`, 210 on `sensor-b`) and that is its own
    defect -- B2e -- which this verdict must not paper over."""
    hits = classify_event_row(
        payload="\x16\x03\x01\x01\x00\x01\x00\x00\xfc\x03\x03",
        protocol="http",
        metadata={"dst_port": 2379, "raw_hex": "1603010100010000fc0303"},
    )

    assert PROBE not in {h[1] for h in hits}


def test_it_does_not_fire_off_the_etcd_ports():
    assert PROBE not in _rules("/", port=9999)


def test_the_probe_is_recon_not_an_attack():
    hits = _hits("/")
    probe = [h for h in hits if h[1] == PROBE]

    assert probe, hits
    assert probe[0][0] == "RECON"
    assert _RANK[get_severity(*probe[0][:2])] <= _RANK["low"]
