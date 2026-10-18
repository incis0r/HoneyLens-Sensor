"""Asking for every Secret in the cluster is named as that, not as resource enumeration.

Measured 2026-11-04 on `sensor-a` and `sensor-b`, 30 days. `GET /api/v1/secrets` -- one request
that returns every Secret in the cluster, which is every credential it holds -- appeared 84
times on `sensor-a` and 107 on `sensor-b`, including `?limit=5`, `?limit=500` and `?limit=2`
variants. Every row carried a verdict, which is why a first query made it look fine. None of
those verdicts said "secrets": they were `k8s_api_resources`, `k8s_api_enumeration` and
`scan_user_agent_bot`.

`k8s_secret_read` could not fire. It requires both `/namespaces/` and `/secrets/` *with a
trailing slash*, so it matches only a single named secret. That leaves two gaps, not one:

- cluster-wide `/api/v1/secrets` -- no namespace, no trailing slash
- per-namespace `/api/v1/namespaces/kube-system/secrets` -- 27 rows on `sensor-a`, 13 on `sensor-b`,
  a listing of every Secret in that namespace, and also no trailing slash

So the fleet named a request for one secret a credential-theft attempt, and a request for all
of them generic enumeration.

These rules are deliberately **not** port-gated, and that is measured rather than assumed:
45% of the cluster-wide requests arrived on ports outside `_K8S_PORTS` -- `sensor-a` :443 (27),
:8080 (5), :80 (3), :8000 (1); `sensor-b` :8080 (13), :443 (4), :80 (2), :8443 (1) -- where
`_detect_k8s_attack` returns before reaching any secrets check. A scanner sprays Kubernetes
paths at whatever answers. `/api/v1/secrets` names the product on its own, which is the
section 5.5 principle read forwards: a product verdict needs a product-shaped request, and
this request is one.
"""

from __future__ import annotations

import pytest

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.scoring import RULE_SEVERITY_OVERRIDE, get_severity

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

CLUSTER_WIDE = "k8s_secrets_cluster_wide"
NAMESPACE_LIST = "k8s_secrets_namespace_list"
SINGLE = "k8s_secret_read"


def _rules(path, port=6443, method="GET"):
    return {
        h[1]
        for h in classify_event_row(
            payload=f"{method} {path} HTTP/1.1\r\nHost: k8s\r\n\r\n",
            protocol="http",
            metadata={"dst_port": port, "path": path, "method": method},
        )
    }


def _worst(path, **kw):
    hits = classify_event_row(
        payload=f"GET {path} HTTP/1.1\r\nHost: k8s\r\n\r\n",
        protocol="http",
        metadata=dict({"dst_port": 6443, "path": path, "method": "GET"}, **kw),
    )
    assert hits, path
    return max(_RANK[get_severity(h[0], h[1])] for h in hits)


# ---------------------------------------------------------------------------
# The cluster-wide listing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/secrets",
        "/api/v1/secrets?limit=5",
        "/api/v1/secrets?limit=500",
        "/api/v1/secrets?limit=2",
    ],
)
def test_the_cluster_wide_listing_is_named(path):
    assert CLUSTER_WIDE in _rules(path)


@pytest.mark.parametrize("port", [6443, 443, 8001, 8080, 80, 8000, 8443, 30000])
def test_it_is_not_port_gated(port):
    """45% of the measured rows are on ports where _detect_k8s_attack returns early."""
    assert CLUSTER_WIDE in _rules("/api/v1/secrets", port=port)


def test_every_secret_in_the_cluster_outranks_one_named_secret():
    cluster = _worst("/api/v1/secrets")
    single = _worst("/api/v1/namespaces/kube-system/secrets/cluster-admin-kubeconfig")

    assert cluster > single, (cluster, single)


# ---------------------------------------------------------------------------
# The per-namespace listing, the gap the plan did not name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/namespaces/kube-system/secrets",
        "/api/v1/namespaces/default/secrets",
        "/api/v1/namespaces/production/secrets?limit=100",
    ],
)
def test_a_namespace_listing_is_named(path):
    assert NAMESPACE_LIST in _rules(path)


def test_a_namespace_listing_is_not_called_a_single_read():
    rules = _rules("/api/v1/namespaces/kube-system/secrets")

    assert SINGLE not in rules


def test_a_single_named_secret_keeps_its_own_verdict():
    """Nothing is taken away from the case that already worked."""
    rules = _rules("/api/v1/namespaces/production/secrets/db-credentials")

    assert SINGLE in rules
    assert NAMESPACE_LIST not in rules
    assert CLUSTER_WIDE not in rules


# ---------------------------------------------------------------------------
# It does not over-reach
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/pods",
        "/api/v1/nodes",
        "/api/v1/configmaps",
        "/api/v1/serviceaccounts",
        "/api/v1/secretsmanager/list",
        "/secrets",
        "/api/v2/secrets",
    ],
)
def test_other_collections_are_not_secrets(path):
    rules = _rules(path)

    assert CLUSTER_WIDE not in rules, (path, rules)
    assert NAMESPACE_LIST not in rules, (path, rules)


def test_the_three_secret_verdicts_all_pin_their_severity():
    """`k8s_secret_read` was already pinned at `high` before this change -- unlike the etcd
    rules, which all inherited K8S_ATTACK's default. The two new ones are pinned beside it so
    the ordering is stated in one place rather than half-inherited."""
    for rule in (CLUSTER_WIDE, NAMESPACE_LIST, SINGLE):
        assert rule in RULE_SEVERITY_OVERRIDE, rule
        assert get_severity("K8S_ATTACK", rule) in _RANK, rule
