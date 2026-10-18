"""etcd gets verdicts that distinguish a write from a read, and a probe from a breach.

Measured 2026-11-04 on `sensor-a`, `prod` and `sensor-b`, 30 days. Two defects.

**Every verdict on :2379 resolves to `high`.** Reading the key store, writing to it, deleting
from it and disclosing the version all score the same, so the severity field carries no
information on this decoy. (The severities *stored* in the database show a read at `high` and
a write at `medium`, but that is older code: on HEAD both are `high`.)

**A write is indistinguishable from a read.** `/v3/kv/put`, `/v3/kv/txn` and
`/v3/kv/deleterange` all produce the single name `k8s_etcd_data_access` -- "data access" --
while `/v3/kv/range` additionally gets `k8s_etcd_keys`. The read is therefore better described
than the write that mutates cluster state.

And five endpoints produce nothing at all, measured sensor-a/sensor-b/prod: `/v2/auth/status`
(33/36/6), `/v2/stats/self` (17/11/8), `/v3/cluster/member/list` (22/-/12), `/v3/maintenance`
(2), `/metrics` (23/24/8, 100% unlabelled). Plus `/v1/kv/?recurse=true` (2/-/4), which is
**Consul**, not etcd -- a different product being probed on the same port.

The ordering this file pins: mutating cluster state outranks reading it, reading it outranks
enumerating the cluster, and enumerating outranks an endpoint etcd exposes unauthenticated by
design.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.mitre_mapping import get_mitre_mapping
from honeylens.classification.scoring import RULE_SEVERITY_OVERRIDE as SEVERITY_OVERRIDES
from honeylens.classification.scoring import get_severity

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _classify(path, method="GET", port=2379):
    return classify_event_row(
        payload=f"{method} {path} HTTP/1.1\r\nHost: etcd\r\n\r\n",
        protocol="http",
        metadata={"dst_port": port, "path": path, "method": method},
    )


def _rules(path, **kw):
    return {h[1] for h in _classify(path, **kw)}


def _worst(path, **kw):
    hits = _classify(path, **kw)
    assert hits, f"{path} produced no verdict at all"
    return max(_RANK[get_severity(h[0], h[1])] for h in hits)


# ---------------------------------------------------------------------------
# A write is named as a write
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/v3/kv/put", "/v3/kv/txn"])
def test_a_kv_write_is_named_a_write(path):
    assert "k8s_etcd_kv_write" in _rules(path, method="POST")


def test_a_kv_delete_is_named_a_delete():
    assert "k8s_etcd_kv_delete" in _rules("/v3/kv/deleterange", method="POST")


def test_a_kv_read_is_named_a_read():
    assert "k8s_etcd_kv_read" in _rules("/v3/kv/range", method="POST")


def test_a_write_is_not_also_called_a_read():
    """The whole point: the two must not collapse onto one name again."""
    write = _rules("/v3/kv/put", method="POST")

    assert "k8s_etcd_kv_read" not in write


def test_the_v2_api_is_read_by_its_method():
    """etcd v2 uses the same path for both, so only the method separates them."""
    assert "k8s_etcd_kv_write" in _rules("/v2/keys/foo", method="PUT")
    assert "k8s_etcd_kv_delete" in _rules("/v2/keys/foo", method="DELETE")
    assert "k8s_etcd_kv_read" in _rules("/v2/keys/foo", method="GET")


# ---------------------------------------------------------------------------
# The ordering
# ---------------------------------------------------------------------------


def test_mutating_cluster_state_outranks_reading_it():
    assert _worst("/v3/kv/put", method="POST") > _worst("/v3/kv/range", method="POST")
    assert _worst("/v3/kv/deleterange", method="POST") > _worst("/v3/kv/range", method="POST")


def test_reading_the_key_store_outranks_enumerating_the_cluster():
    assert _worst("/v3/kv/range", method="POST") > _worst("/v2/members")


def test_enumerating_outranks_an_endpoint_open_by_design():
    assert _worst("/v2/members") > _worst("/version")


def test_an_unauthenticated_by_design_endpoint_is_not_high():
    """etcd serves /version, /health and /metrics without credentials. Calling that `high`
    is what made every verdict on this decoy `high`."""
    for path in ("/version", "/health", "/metrics"):
        assert _worst(path) <= _RANK["low"], path


# ---------------------------------------------------------------------------
# The endpoints that had no verdict
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "rule"),
    [
        ("/v2/auth/status", "k8s_etcd_auth_probe"),
        ("/v2/stats/self", "k8s_etcd_stats"),
        ("/v3/cluster/member/list", "k8s_etcd_members"),
        ("/v3/maintenance/status", "k8s_etcd_maintenance"),
        ("/metrics", "k8s_etcd_metrics"),
    ],
)
def test_the_endpoints_that_had_nothing_now_have_a_name(path, rule):
    assert rule in _rules(path)


def test_consul_is_not_filed_as_etcd():
    """`GET /v1/kv/?recurse=true` is Consul's KV API. Measured 2 rows on sensor-a and 4 on prod,
    arriving on the etcd port because the scanner tries both."""
    rules = _rules("/v1/kv/?recurse=true")

    assert "consul_kv_read" in rules
    assert not any("etcd" in r for r in rules), rules


# ---------------------------------------------------------------------------
# Nothing lost, nothing over-claimed
# ---------------------------------------------------------------------------


def test_the_registry_prefix_keeps_its_own_name():
    """Reading `/v2/keys/registry` is reading live Kubernetes cluster state out of etcd, which
    is a stronger claim than a generic range and keeps its own rule."""
    assert "k8s_etcd_keys" in _rules("/v2/keys/registry/pods/default")


def test_none_of_this_fires_off_the_etcd_ports():
    for path in ("/v3/kv/put", "/v3/kv/range", "/v2/auth/status", "/metrics"):
        rules = _rules(path, method="POST", port=9999)
        assert not any("etcd" in r or "consul" in r for r in rules), (path, rules)


@pytest.mark.parametrize(
    "rule",
    [
        "k8s_etcd_kv_write",
        "k8s_etcd_kv_delete",
        "k8s_etcd_kv_read",
        "k8s_etcd_auth_probe",
        "k8s_etcd_stats",
        "k8s_etcd_maintenance",
        "k8s_etcd_metrics",
        "consul_kv_read",
    ],
)
def test_every_new_rule_is_scored_and_mapped(rule):
    """A rule name absent from scoring shows unscored on the dashboard, and the severities
    here are the ordering this file pins, so each is set explicitly rather than inherited.

    On MITRE this asserts less than it looks: `get_mitre_mapping` takes `rule_name` and
    ignores it, mapping by attack type alone. So every rule under `K8S_ATTACK` is mapped the
    moment the type is, and the per-rule argument is decoration. Recorded here so the next
    reader does not take a passing assertion for per-rule coverage."""
    attack_type = "K8S_ATTACK"

    assert get_severity(attack_type, rule) in _RANK, rule
    assert rule in SEVERITY_OVERRIDES, f"{rule} inherits its severity instead of pinning it"
    assert get_mitre_mapping(attack_type, rule), rule
