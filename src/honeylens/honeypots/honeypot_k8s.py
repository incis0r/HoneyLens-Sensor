#!/usr/bin/env python3
"""
Kubernetes API Honeypot

Simulates a vulnerable Kubernetes cluster to detect reconnaissance and attacks.
Responds to common kube-hunter probes and Kubernetes API requests.

Ports simulated:
  - 6443  : Kubernetes API Server (HTTPS)
  - 8080  : Kubernetes API Server (HTTP - insecure)
  - 10250 : Kubelet API (HTTPS)
  - 10255 : Kubelet Read-Only API (HTTP)
  - 2379  : etcd API
  - 8001  : kubectl proxy
  - 30000 : Kubernetes Dashboard (NodePort)

Detected attack patterns (kube-hunter KHV IDs):
  - KHV002: K8s Version Disclosure
  - KHV005: Access to Kubernetes API
  - KHV006: Insecure (HTTP) access to Kubernetes API
  - KHV029: Dashboard Exposed
  - KHV032: Etcd Remote Read Access
  - KHV033: Etcd Remote Version Disclosure
  - KHV034: Etcd Insecure Connection (HTTP)
  - KHV036: Anonymous Authentication
  - KHV037: Exposed Container Logs
  - KHV038: Exposed Running Pods
  - KHV039: Exposed Exec On Container
  - KHV043: Cluster Health Disclosure
  - KHV046: Exposed Kubelet Cmdline
  - KHV050: Read access to Pod service account token
  - KHV052: Exposed Pods

Reference: https://github.com/aquasecurity/kube-hunter
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import ssl
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from honeylens.config import K8S_HONEYPOT_LOG_FILE
from honeylens.eventlog_lock import append_line
from honeylens.honeypots import deception_waf
from honeylens.honeypots.body_capture import capture as _capture_body

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Simulated cluster info
CLUSTER_NAME = "honeypot-cluster"
K8S_VERSION = "v1.26.3"
K8S_GIT_COMMIT = "9e644106593f3f4aa98f8a84b23db5fa378900bd"
ETCD_VERSION = "3.5.7"
NODE_NAME = "honeypot-node-01"
NODE_IP = "10.244.0.1"
POD_CIDR = "10.244.0.0/24"

# Fake namespaces and pods
NAMESPACES = ["default", "kube-system", "kube-public", "monitoring", "production"]
FAKE_PODS = [
    {
        "name": "nginx-deployment-6b474476c4-7x9kl",
        "namespace": "default",
        "status": "Running",
        "ip": "10.244.0.15",
    },
    {
        "name": "nginx-deployment-6b474476c4-abc12",
        "namespace": "default",
        "status": "Running",
        "ip": "10.244.0.16",
    },
    {"name": "redis-master-0", "namespace": "default", "status": "Running", "ip": "10.244.0.20"},
    {
        "name": "coredns-5644d7b6d9-abcde",
        "namespace": "kube-system",
        "status": "Running",
        "ip": "10.244.0.2",
    },
    {
        "name": "coredns-5644d7b6d9-fghij",
        "namespace": "kube-system",
        "status": "Running",
        "ip": "10.244.0.3",
    },
    {"name": "etcd-master", "namespace": "kube-system", "status": "Running", "ip": "10.244.0.4"},
    {
        "name": "kube-apiserver-master",
        "namespace": "kube-system",
        "status": "Running",
        "ip": "10.244.0.5",
    },
    {
        "name": "kube-controller-manager-master",
        "namespace": "kube-system",
        "status": "Running",
        "ip": "10.244.0.6",
    },
    {
        "name": "kube-scheduler-master",
        "namespace": "kube-system",
        "status": "Running",
        "ip": "10.244.0.7",
    },
    {
        "name": "kube-proxy-abc12",
        "namespace": "kube-system",
        "status": "Running",
        "ip": "10.244.0.8",
    },
    {
        "name": "prometheus-server-0",
        "namespace": "monitoring",
        "status": "Running",
        "ip": "10.244.0.30",
    },
    {
        "name": "grafana-7d9c4c5f5-xyz99",
        "namespace": "monitoring",
        "status": "Running",
        "ip": "10.244.0.31",
    },
    {
        "name": "webapp-frontend-5c8f6b7d8-prod1",
        "namespace": "production",
        "status": "Running",
        "ip": "10.244.1.10",
    },
    {
        "name": "webapp-backend-6d7e8f9a0-prod2",
        "namespace": "production",
        "status": "Running",
        "ip": "10.244.1.11",
    },
    {
        "name": "database-mysql-0",
        "namespace": "production",
        "status": "Running",
        "ip": "10.244.1.20",
    },
]

FAKE_NODES = [
    {"name": "master-01", "status": "Ready", "roles": "control-plane,master", "ip": "192.168.1.10"},
    {"name": "worker-01", "status": "Ready", "roles": "worker", "ip": "192.168.1.11"},
    {"name": "worker-02", "status": "Ready", "roles": "worker", "ip": "192.168.1.12"},
]

FAKE_SECRETS = [
    {
        "name": "default-token-abc12",
        "namespace": "default",
        "type": "kubernetes.io/service-account-token",
    },
    {"name": "db-credentials", "namespace": "production", "type": "Opaque"},
    {"name": "tls-secret", "namespace": "production", "type": "kubernetes.io/tls"},
    {"name": "docker-registry", "namespace": "default", "type": "kubernetes.io/dockerconfigjson"},
    {
        "name": "cicd-deployer-token-x7f9k",
        "namespace": "production",
        "type": "kubernetes.io/service-account-token",
    },
    {
        "name": "monitoring-reader-token-q2p8m",
        "namespace": "monitoring",
        "type": "kubernetes.io/service-account-token",
    },
    {
        "name": "vault-agent-token-r3n6j",
        "namespace": "production",
        "type": "kubernetes.io/service-account-token",
    },
    # A stored kubeconfig is a prize worth walking to, and it is the carrier the
    # Idea 52 plan called for: attackers and their tooling read the file itself, so
    # the canary can live inside the document rather than on the HTTP response.
    {"name": "cluster-admin-kubeconfig", "namespace": "kube-system", "type": "Opaque"},
]

# ---------------------------------------------------------------------------
# Fake Service Accounts
# ---------------------------------------------------------------------------

FAKE_SERVICE_ACCOUNTS = [
    {"name": "default", "namespace": "default"},
    {"name": "default", "namespace": "kube-system"},
    {"name": "default", "namespace": "production"},
    {"name": "default", "namespace": "monitoring"},
    {"name": "cicd-deployer", "namespace": "production"},
    {"name": "monitoring-reader", "namespace": "monitoring"},
    {"name": "vault-agent", "namespace": "production"},
]

# ---------------------------------------------------------------------------
# Deception Token Generation
# ---------------------------------------------------------------------------
# Honeytoken JWTs: correct three-part structure with a realistic sub claim,
# but an invalid signature — they will never work on a real cluster.
# Any request presenting one of these tokens is definitionally malicious.


def _make_honeytoken(namespace: str, sa_name: str, secret_name: str) -> str:
    """Generate a fake but structurally plausible JWT service account token.

    Uses SHA1 *intentionally* — this is honeytoken material designed to look
    realistic to attackers, not a security-bearing hash. Real Kubernetes
    service-account `kid` values are arbitrary short hex strings; SHA1
    truncated to 16 chars matches that shape exactly.
    """
    header = (
        base64.urlsafe_b64encode(
            # nosem: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
            json.dumps(
                {
                    "alg": "RS256",
                    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
                    "kid": hashlib.sha1(sa_name.encode(), usedforsecurity=False).hexdigest()[:16],
                }
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )

    now_ts = int(time.time())
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "iss": "kubernetes/serviceaccount",
                    "kubernetes.io/serviceaccount/namespace": namespace,
                    "kubernetes.io/serviceaccount/secret.name": secret_name,
                    "kubernetes.io/serviceaccount/service-account.name": sa_name,
                    "kubernetes.io/serviceaccount/service-account.uid": str(uuid.uuid4()),
                    "sub": f"system:serviceaccount:{namespace}:{sa_name}",
                    "iat": now_ts - 86400,
                    "exp": now_ts + 86400 * 365,
                }
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )

    # Fake signature — wrong length, won't verify
    sig = (
        base64.urlsafe_b64encode(
            hashlib.sha256(f"{header}.{payload}".encode()).digest()
            + hashlib.sha256(secret_name.encode()).digest()
        )
        .rstrip(b"=")
        .decode()
    )

    return f"{header}.{payload}.{sig}"


def _token_fingerprint(token: str) -> str:
    """
    Return a short, unique, log-safe fingerprint for a token.
    Uses SHA-256 of the full token truncated to 16 hex chars — unique per token,
    safe to store in logs, non-reversible.
    """
    return hashlib.sha256(token.encode()).hexdigest()[:16]


# Generated once at startup; consistent across the session
_HONEYTOKEN_DEFS = [
    ("production", "cicd-deployer", "cicd-deployer-token-x7f9k"),
    ("monitoring", "monitoring-reader", "monitoring-reader-token-q2p8m"),
    ("production", "vault-agent", "vault-agent-token-r3n6j"),
    ("default", "default", "default-token-abc12"),
]

# Maps token_fingerprint (first 24 chars) → origin context string
DECEPTION_TOKENS: dict = {}
# Maps fingerprint → full token (for response embedding)
_FULL_TOKENS: dict = {}

for _ns, _sa, _secret in _HONEYTOKEN_DEFS:
    _tok = _make_honeytoken(_ns, _sa, _secret)
    _fp = _token_fingerprint(_tok)
    DECEPTION_TOKENS[_fp] = f"namespace={_ns}, serviceaccount={_sa}, secret={_secret}"
    _FULL_TOKENS[f"{_ns}/{_sa}"] = _tok


def _get_token(namespace: str, sa: str) -> str:
    return _FULL_TOKENS.get(
        f"{namespace}/{sa}", _make_honeytoken(namespace, sa, f"{sa}-token-unknown")
    )


def _check_honeytoken(authorization_header: str):
    """Return (fingerprint, origin) if the Bearer token is a honeytoken, else (None, None)."""
    if not authorization_header:
        return None, None
    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None, None
    token = parts[1]
    fp = _token_fingerprint(token)
    origin = DECEPTION_TOKENS.get(fp)
    return (fp, origin) if origin else (None, None)


# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("k8s_honeypot")

LOG_FILE = Path(K8S_HONEYPOT_LOG_FILE)

# Idea 52 — AI prompt-injection canary (opt-in via AI_CANARY_ENABLED).
try:
    from honeylens.intelligence import ai_canary
except Exception:
    ai_canary = None  # type: ignore[assignment]  # optional module, idiom from the mypy docs

# OpenAI/Ollama-shaped bait: AI scanners probe by path on whatever port answers.
try:
    from honeylens.honeypots import ai_endpoints
except Exception:
    ai_endpoints = None  # type: ignore[assignment]  # optional module, idiom from the mypy docs


def _log_event(port, protocol, peer, data):
    """Log event to JSON file in format compatible with ingest_honeypot.py."""
    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "protocol": protocol,
        "port": port,
        "peer_ip": peer[0] if peer else None,
        "peer_port": peer[1] if peer else None,
        # Include dst_port for attack classifier context
        "dst_port": port,
        **data,
    }
    try:
        append_line(LOG_FILE, json.dumps(event))
    except Exception as e:
        logger.error("Failed to write event log: %s", e)

    logger.info(
        "[%s:%d] %s %s",
        peer[0] if peer else "?",
        port,
        protocol,
        data.get("path", data.get("action", "")),
    )


# ---------------------------------------------------------------------------
# Response Generators
# ---------------------------------------------------------------------------


def k8s_version_response():
    """Generate /version response (KHV002)."""
    return {
        "major": "1",
        "minor": "26",
        "gitVersion": K8S_VERSION,
        "gitCommit": K8S_GIT_COMMIT,
        "gitTreeState": "clean",
        "buildDate": "2023-03-15T13:31:40Z",
        "goVersion": "go1.19.7",
        "compiler": "gc",
        "platform": "linux/amd64",
    }


def k8s_healthz_response():
    """Generate /healthz response (KHV043)."""
    return "ok"


def k8s_livez_response():
    """Generate /livez response."""
    return "[+]ping ok\n[+]log ok\n[+]etcd ok\n[+]poststarthook/start-kube-apiserver-admission-initializer ok\n[+]poststarthook/generic-apiserver-start-informers ok\n[+]poststarthook/priority-and-fairness-config-consumer ok\n[+]poststarthook/priority-and-fairness-filter ok\n[+]poststarthook/storage-object-count-tracker-hook ok\n[+]poststarthook/start-apiextensions-informers ok\n[+]poststarthook/start-apiextensions-controllers ok\n[+]poststarthook/crd-informer-synced ok\n[+]poststarthook/bootstrap-controller ok\n[+]poststarthook/rbac/bootstrap-roles ok\n[+]poststarthook/scheduling/bootstrap-system-priority-classes ok\n[+]poststarthook/priority-and-fairness-config-producer ok\n[+]poststarthook/start-cluster-authentication-info-controller ok\n[+]poststarthook/aggregator-reload-proxy-client-cert ok\n[+]poststarthook/start-kube-aggregator-informers ok\n[+]poststarthook/apiservice-registration-controller ok\n[+]poststarthook/apiservice-status-available-controller ok\n[+]poststarthook/kube-apiserver-autoregistration ok\nlivez check passed"


def k8s_api_response():
    """Generate /api response."""
    return {
        "kind": "APIVersions",
        "versions": ["v1"],
        "serverAddressByClientCIDRs": [
            {"clientCIDR": "0.0.0.0/0", "serverAddress": f"{NODE_IP}:6443"}
        ],
    }


def k8s_apis_response():
    """Generate /apis response."""
    return {
        "kind": "APIGroupList",
        "apiVersion": "v1",
        "groups": [
            {
                "name": "apps",
                "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"},
            },
            {
                "name": "batch",
                "versions": [{"groupVersion": "batch/v1", "version": "v1"}],
                "preferredVersion": {"groupVersion": "batch/v1", "version": "v1"},
            },
            {
                "name": "networking.k8s.io",
                "versions": [{"groupVersion": "networking.k8s.io/v1", "version": "v1"}],
                "preferredVersion": {"groupVersion": "networking.k8s.io/v1", "version": "v1"},
            },
            {
                "name": "rbac.authorization.k8s.io",
                "versions": [{"groupVersion": "rbac.authorization.k8s.io/v1", "version": "v1"}],
                "preferredVersion": {
                    "groupVersion": "rbac.authorization.k8s.io/v1",
                    "version": "v1",
                },
            },
        ],
    }


def k8s_namespaces_response():
    """Generate /api/v1/namespaces response."""
    items = []
    for ns in NAMESPACES:
        items.append(
            {
                "metadata": {
                    "name": ns,
                    "uid": str(uuid.uuid4()),
                    "creationTimestamp": "2023-01-15T10:00:00Z",
                },
                "spec": {"finalizers": ["kubernetes"]},
                "status": {"phase": "Active"},
            }
        )
    return {
        "kind": "NamespaceList",
        "apiVersion": "v1",
        "metadata": {"resourceVersion": "12345"},
        "items": items,
    }


def k8s_pods_response(namespace=None):
    """Generate /api/v1/pods or /api/v1/namespaces/{ns}/pods response (KHV038, KHV052)."""
    pods = FAKE_PODS if not namespace else [p for p in FAKE_PODS if p["namespace"] == namespace]
    items = []
    for pod in pods:
        items.append(
            {
                "metadata": {
                    "name": pod["name"],
                    "namespace": pod["namespace"],
                    "uid": str(uuid.uuid4()),
                    "creationTimestamp": "2023-06-01T10:00:00Z",
                    "labels": {"app": pod["name"].split("-")[0]},
                },
                "spec": {
                    "nodeName": NODE_NAME,
                    "containers": [
                        {
                            "name": pod["name"].split("-")[0],
                            "image": f"{pod['name'].split('-')[0]}:latest",
                            "ports": [{"containerPort": 80}],
                        }
                    ],
                    "serviceAccountName": "default",
                },
                "status": {
                    "phase": pod["status"],
                    "podIP": pod["ip"],
                    "hostIP": NODE_IP,
                    "startTime": "2023-06-01T10:00:05Z",
                    "containerStatuses": [
                        {
                            "name": pod["name"].split("-")[0],
                            "state": {"running": {"startedAt": "2023-06-01T10:00:10Z"}},
                            "ready": True,
                            "restartCount": 0,
                            "image": f"{pod['name'].split('-')[0]}:latest",
                            "containerID": f"containerd://{hashlib.sha256(pod['name'].encode()).hexdigest()[:64]}",
                        }
                    ],
                },
            }
        )
    return {
        "kind": "PodList",
        "apiVersion": "v1",
        "metadata": {"resourceVersion": str(random.randint(10000, 99999))},
        "items": items,
    }


def k8s_nodes_response():
    """Generate /api/v1/nodes response."""
    items = []
    for node in FAKE_NODES:
        items.append(
            {
                "metadata": {
                    "name": node["name"],
                    "uid": str(uuid.uuid4()),
                    "labels": {
                        "kubernetes.io/hostname": node["name"],
                        "node-role.kubernetes.io/" + node["roles"].split(",")[0]: "",
                    },
                },
                "spec": {"podCIDR": POD_CIDR},
                "status": {
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "addresses": [
                        {"type": "InternalIP", "address": node["ip"]},
                        {"type": "Hostname", "address": node["name"]},
                    ],
                    "nodeInfo": {
                        "machineID": hashlib.md5(
                            node["name"].encode(), usedforsecurity=False
                        ).hexdigest(),
                        "systemUUID": str(uuid.uuid4()),
                        "bootID": str(uuid.uuid4()),
                        "kernelVersion": "5.15.0-72-generic",
                        "osImage": "Ubuntu 22.04.2 LTS",
                        "containerRuntimeVersion": "containerd://1.6.20",
                        "kubeletVersion": K8S_VERSION,
                        "kubeProxyVersion": K8S_VERSION,
                        "operatingSystem": "linux",
                        "architecture": "amd64",
                    },
                },
            }
        )
    return {
        "kind": "NodeList",
        "apiVersion": "v1",
        "metadata": {"resourceVersion": str(random.randint(10000, 99999))},
        "items": items,
    }


def k8s_secrets_response(namespace=None):
    """Generate /api/v1/secrets response (KHV050)."""
    secrets = (
        FAKE_SECRETS if not namespace else [s for s in FAKE_SECRETS if s["namespace"] == namespace]
    )
    items = []
    for secret in secrets:
        items.append(
            {
                "metadata": {
                    "name": secret["name"],
                    "namespace": secret["namespace"],
                    "uid": str(uuid.uuid4()),
                    "creationTimestamp": "2023-01-20T10:00:00Z",
                },
                "type": secret["type"],
                "data": {
                    "token": "ZXlKaGJHY2lPaUpTVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5...",  # Fake base64
                    "ca.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...",
                }
                if "token" in secret["name"]
                else {"username": "YWRtaW4=", "password": "c2VjcmV0MTIz"},
            }
        )
    return {
        "kind": "SecretList",
        "apiVersion": "v1",
        "metadata": {"resourceVersion": str(random.randint(10000, 99999))},
        "items": items,
    }


def k8s_services_response(namespace=None):
    """Generate /api/v1/services response."""
    services = [
        {"name": "kubernetes", "namespace": "default", "type": "ClusterIP", "port": 443},
        {"name": "nginx-service", "namespace": "default", "type": "LoadBalancer", "port": 80},
        {"name": "redis-master", "namespace": "default", "type": "ClusterIP", "port": 6379},
        {"name": "kube-dns", "namespace": "kube-system", "type": "ClusterIP", "port": 53},
        {"name": "prometheus", "namespace": "monitoring", "type": "ClusterIP", "port": 9090},
    ]
    if namespace:
        services = [s for s in services if s["namespace"] == namespace]

    items = []
    for svc in services:
        items.append(
            {
                "metadata": {
                    "name": svc["name"],
                    "namespace": svc["namespace"],
                    "uid": str(uuid.uuid4()),
                },
                "spec": {
                    "type": svc["type"],
                    "ports": [{"port": svc["port"], "targetPort": svc["port"], "protocol": "TCP"}],
                    "clusterIP": f"10.96.{random.randint(0, 255)}.{random.randint(1, 254)}",
                },
            }
        )
    return {
        "kind": "ServiceList",
        "apiVersion": "v1",
        "metadata": {"resourceVersion": str(random.randint(10000, 99999))},
        "items": items,
    }


def kubelet_pods_response():
    """Generate /pods response for Kubelet API (KHV038)."""
    return k8s_pods_response()


def kubelet_runningpods_response():
    """Generate /runningpods response for Kubelet API."""
    return k8s_pods_response()


def kubelet_spec_response():
    """Generate /spec response for Kubelet API."""
    return {
        "machineID": hashlib.md5(NODE_NAME.encode(), usedforsecurity=False).hexdigest(),
        "systemUUID": str(uuid.uuid4()),
        "bootID": str(uuid.uuid4()),
        "numCores": 4,
        "cpuFrequency": 2400000,
        "memoryCapacity": 8589934592,
        "topology": [],
    }


def kubelet_metrics_response():
    """Generate /metrics response for Kubelet API (exposes version - KHV002)."""
    return f"""# HELP kubernetes_build_info A metric with a constant '1' value labeled by major, minor, git version, git commit, git tree state, build date, Go version, and compiler from which Kubernetes was built, and platform on which it is running.
# TYPE kubernetes_build_info gauge
kubernetes_build_info{{major="1",minor="26",git_version="{K8S_VERSION}",git_commit="{K8S_GIT_COMMIT}",git_tree_state="clean",build_date="2023-03-15T13:31:40Z",go_version="go1.19.7",compiler="gc",platform="linux/amd64"}} 1
# HELP kubelet_running_pods Number of running pods
# TYPE kubelet_running_pods gauge
kubelet_running_pods {len(FAKE_PODS)}
# HELP kubelet_node_name Node name
# TYPE kubelet_node_name gauge
kubelet_node_name{{node="{NODE_NAME}"}} 1
"""


def kubelet_configz_response():
    """Generate /configz response for Kubelet API (KHV046)."""
    return {
        "kubeletconfig": {
            "enableServer": True,
            "staticPodPath": "/etc/kubernetes/manifests",
            "authentication": {
                "anonymous": {"enabled": True},  # Vulnerable config!
                "webhook": {"enabled": True},
            },
            "authorization": {"mode": "AlwaysAllow"},  # Vulnerable!
            "clusterDomain": "cluster.local",
            "clusterDNS": ["10.96.0.10"],
            "rotateCertificates": True,
            "serverTLSBootstrap": True,
        }
    }


def kubelet_logs_response(pod_name):
    """Generate /containerLogs response (KHV037)."""
    return f"""2023-06-01T10:00:10.123456Z Starting {pod_name}...
2023-06-01T10:00:10.234567Z Initializing application
2023-06-01T10:00:10.345678Z Connected to database
2023-06-01T10:00:10.456789Z Listening on port 80
2023-06-01T10:00:15.567890Z Received request from 10.244.0.1
2023-06-01T10:00:16.678901Z Processing request...
2023-06-01T10:00:17.789012Z Request completed successfully
"""


def etcd_version_response():
    """Generate /version response for etcd (KHV033)."""
    return {"etcdserver": ETCD_VERSION, "etcdcluster": "3.5.0"}


def etcd_health_response():
    """Generate /health response for etcd."""
    return {"health": "true", "reason": ""}


def etcd_keys_response():
    """Generate /v2/keys response for etcd (KHV032)."""
    return {
        "action": "get",
        "node": {
            "key": "/",
            "dir": True,
            "nodes": [{"key": "/registry", "dir": True}, {"key": "/calico", "dir": True}],
        },
    }


def etcd_members_response():
    """Generate /v2/members response for etcd."""
    return {
        "members": [
            {
                "id": "8e9e05c52164694d",
                "name": "etcd-master",
                "peerURLs": [f"https://{NODE_IP}:2380"],
                "clientURLs": [f"https://{NODE_IP}:2379"],
            }
        ]
    }


def dashboard_response():
    """Generate dashboard response (KHV029)."""
    return """<!DOCTYPE html>
<html>
<head>
    <title>Kubernetes Dashboard</title>
    <link rel="icon" type="image/png" href="assets/images/kubernetes-logo.png">
</head>
<body>
    <kd-root></kd-root>
    <script src="runtime.js"></script>
    <script src="polyfills.js"></script>
    <script src="main.js"></script>
</body>
</html>"""


def k8s_serviceaccounts_response(namespace=None):
    """Generate /api/v1/namespaces/{ns}/serviceaccounts response."""
    accounts = (
        FAKE_SERVICE_ACCOUNTS
        if not namespace
        else [a for a in FAKE_SERVICE_ACCOUNTS if a["namespace"] == namespace]
    )
    items = []
    for sa in accounts:
        tok_key = f"{sa['namespace']}/{sa['name']}"
        # Honeytoken: produces a plausible 5-char suffix matching real k8s
        # token-secret naming. Not security-bearing.
        # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
        secret_suffix = hashlib.sha1(tok_key.encode(), usedforsecurity=False).hexdigest()[:5]  # nosec B324 — decoy name suffix
        items.append(
            {
                "metadata": {
                    "name": sa["name"],
                    "namespace": sa["namespace"],
                    "uid": str(uuid.uuid4()),
                    "creationTimestamp": "2023-01-15T10:00:00Z",
                    "annotations": {"kubectl.kubernetes.io/last-applied-configuration": ""},
                },
                "secrets": [{"name": f"{sa['name']}-token-{secret_suffix}"}],
                "automountServiceAccountToken": True,
            }
        )
    return {
        "kind": "ServiceAccountList",
        "apiVersion": "v1",
        "metadata": {"resourceVersion": str(random.randint(10000, 99999))},
        "items": items,
    }


def k8s_secret_detail_response(namespace, name, canary_instruction=None):
    """Generate /api/v1/namespaces/{ns}/secrets/{name} — plants honeytoken.

    When `canary_instruction` is set, it is embedded as an object annotation
    (the AI-canary body carrier, Idea 52 Phase B) — LLM tools that summarise the
    object content are more likely to ingest it than a bare HTTP header.
    """
    if "kubeconfig" in name.lower():
        return k8s_kubeconfig_secret_response(namespace, name, canary_instruction)

    # Determine which SA this secret belongs to
    sa_name = None
    for _ns, _sa, _secret in _HONEYTOKEN_DEFS:
        if _secret == name and _ns == namespace:
            sa_name = _sa
            break

    token_b64 = base64.b64encode(_get_token(namespace, sa_name or "default").encode()).decode()
    ca_b64 = base64.b64encode(
        b"-----BEGIN CERTIFICATE-----\nMIICpDCCAYwCCQDU...fake...CA==\n-----END CERTIFICATE-----"
    ).decode()
    ns_b64 = base64.b64encode(namespace.encode()).decode()

    annotations = {
        "kubernetes.io/service-account.name": sa_name or "default",
        "kubernetes.io/service-account.uid": str(uuid.uuid4()),
    }
    if canary_instruction and ai_canary is not None:
        annotations[ai_canary.ANNOTATION_KEY] = canary_instruction

    return {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "uid": str(uuid.uuid4()),
            "creationTimestamp": "2023-03-01T08:00:00Z",
            "annotations": annotations,
        },
        "type": "kubernetes.io/service-account-token",
        "data": {
            "ca.crt": ca_b64,
            "namespace": ns_b64,
            "token": token_b64,
        },
    }


def k8s_kubeconfig_secret_response(namespace, name, canary_instruction=None):
    """A Secret holding a cluster-admin kubeconfig (Idea 52 kubeconfig carrier).

    The credential is the usual honeytoken, so reuse is still detected. What differs
    is where the canary sits: inside the kubeconfig document, as a YAML comment on
    the token line. Tooling that decodes and summarises the file reads it, which a
    bare HTTP header on the Secret response would not survive.
    """
    token = _get_token(namespace, "cluster-admin")
    ca_b64 = base64.b64encode(
        b"-----BEGIN CERTIFICATE-----\nMIICpDCCAYwCCQDU...fake...CA==\n-----END CERTIFICATE-----"
    ).decode()

    lines = [
        "apiVersion: v1",
        "kind: Config",
        "clusters:",
        "- cluster:",
        f"    certificate-authority-data: {ca_b64}",
        "    server: https://kubernetes.default.svc.cluster.local:6443",
        "  name: prod-cluster",
        "contexts:",
        "- context:",
        "    cluster: prod-cluster",
        "    user: cluster-admin",
        "  name: cluster-admin@prod-cluster",
        "current-context: cluster-admin@prod-cluster",
        "users:",
        "- name: cluster-admin",
        "  user:",
    ]
    if canary_instruction:
        lines.append(f"    # {canary_instruction}")
    lines.append(f"    token: {token}")

    return {
        "kind": "Secret",
        "apiVersion": "v1",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "uid": str(uuid.uuid4()),
            "creationTimestamp": "2023-02-14T09:12:00Z",
            "annotations": {"kubernetes.io/description": "cluster admin kubeconfig"},
        },
        "type": "Opaque",
        "data": {
            "config": base64.b64encode("\n".join(lines).encode()).decode(),
        },
    }


def k8s_tokenrequest_response(namespace, sa_name):
    """Generate TokenRequest response — plants honeytoken via the TokenRequest API."""
    token = _get_token(namespace, sa_name)
    return {
        "kind": "TokenRequest",
        "apiVersion": "authentication.k8s.io/v1",
        "metadata": {
            "creationTimestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "name": sa_name,
            "namespace": namespace,
        },
        "spec": {
            "audiences": ["https://kubernetes.default.svc.cluster.local"],
            "expirationSeconds": 3607,
        },
        "status": {
            "token": token,
            "expirationTimestamp": "2099-01-01T00:00:00Z",
        },
    }


def k8s_pods_deception_response():
    """
    Enriched pod list returned to attacker using a valid honeytoken.
    Looks more privileged than the anonymous response — includes vault namespace
    and automountServiceAccountToken hints to maximise attacker dwell time.
    """
    extra_pods = [
        {
            "name": "vault-agent-injector-7d6f8-xk2pm",
            "namespace": "production",
            "status": "Running",
            "ip": "10.244.1.30",
        },
        {
            "name": "secrets-mgmt-operator-0",
            "namespace": "production",
            "status": "Running",
            "ip": "10.244.1.31",
        },
        {
            "name": "internal-tools-api-56d9f-wrq7n",
            "namespace": "production",
            "status": "Running",
            "ip": "10.244.1.40",
        },
        {
            "name": "ci-runner-7bc4f-lmv9x",
            "namespace": "production",
            "status": "Running",
            "ip": "10.244.1.41",
        },
    ]
    all_pods = FAKE_PODS + extra_pods
    items = []
    for pod in all_pods:
        sa = "cicd-deployer" if pod["namespace"] == "production" else "default"
        items.append(
            {
                "metadata": {
                    "name": pod["name"],
                    "namespace": pod["namespace"],
                    "uid": str(uuid.uuid4()),
                    "creationTimestamp": "2023-06-01T10:00:00Z",
                    "labels": {"app": pod["name"].split("-")[0]},
                    "annotations": {"kubectl.kubernetes.io/last-applied-configuration": ""},
                },
                "spec": {
                    "nodeName": NODE_NAME,
                    "serviceAccountName": sa,
                    "automountServiceAccountToken": True,
                    "containers": [
                        {
                            "name": pod["name"].split("-")[0],
                            "image": f"{pod['name'].split('-')[0]}:latest",
                            "ports": [{"containerPort": 80}],
                            "env": [
                                {"name": "KUBERNETES_SERVICE_HOST", "value": NODE_IP},
                                {"name": "KUBERNETES_SERVICE_PORT", "value": "443"},
                            ],
                            "volumeMounts": [
                                {
                                    "name": "kube-api-access",
                                    "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                                    "readOnly": True,
                                }
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "kube-api-access",
                            "projected": {
                                "sources": [
                                    {
                                        "serviceAccountToken": {
                                            "expirationSeconds": 3607,
                                            "path": "token",
                                        }
                                    },
                                    {
                                        "configMap": {
                                            "name": "kube-root-ca.crt",
                                            "items": [{"key": "ca.crt", "path": "ca.crt"}],
                                        }
                                    },
                                    {
                                        "downwardAPI": {
                                            "items": [
                                                {
                                                    "path": "namespace",
                                                    "fieldRef": {"fieldPath": "metadata.namespace"},
                                                }
                                            ]
                                        }
                                    },
                                ]
                            },
                        }
                    ],
                },
                "status": {
                    "phase": pod["status"],
                    "podIP": pod["ip"],
                    "hostIP": NODE_IP,
                    "startTime": "2023-06-01T10:00:05Z",
                    "containerStatuses": [
                        {
                            "name": pod["name"].split("-")[0],
                            "state": {"running": {"startedAt": "2023-06-01T10:00:10Z"}},
                            "ready": True,
                            "restartCount": 0,
                            "image": f"{pod['name'].split('-')[0]}:latest",
                            "containerID": f"containerd://{hashlib.sha256(pod['name'].encode()).hexdigest()[:64]}",
                        }
                    ],
                },
            }
        )
    return {
        "kind": "PodList",
        "apiVersion": "v1",
        "metadata": {
            "resourceVersion": str(random.randint(10000, 99999)),
            "selfLink": "/api/v1/pods",
        },
        "items": items,
    }


def k8s_namespaces_deception_response():
    """
    Extended namespace list returned to attacker using a valid honeytoken.
    Includes vault and internal-tools namespaces to lure further exploration.
    """
    deception_namespaces = [*NAMESPACES, "vault", "secrets-mgmt", "internal-tools"]
    items = []
    for ns in deception_namespaces:
        items.append(
            {
                "metadata": {
                    "name": ns,
                    "uid": str(uuid.uuid4()),
                    "creationTimestamp": "2023-01-15T10:00:00Z",
                    "labels": {"kubernetes.io/metadata.name": ns},
                },
                "spec": {"finalizers": ["kubernetes"]},
                "status": {"phase": "Active"},
            }
        )
    return {
        "kind": "NamespaceList",
        "apiVersion": "v1",
        "metadata": {
            "resourceVersion": str(random.randint(10000, 99999)),
            "selfLink": "/api/v1/namespaces",
        },
        "items": items,
    }


def k8s_forbidden_response():
    """Generate 403 Forbidden response."""
    return {
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": 'forbidden: User "system:anonymous" cannot list resource "pods" in API group "" at the cluster scope',
        "reason": "Forbidden",
        "details": {},
        "code": 403,
    }


def k8s_unauthorized_response():
    """Generate 401 Unauthorized response."""
    return {
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": "Unauthorized",
        "reason": "Unauthorized",
        "code": 401,
    }


# ---------------------------------------------------------------------------
# HTTP Parser & Handler
# ---------------------------------------------------------------------------


def parse_http_request(data):
    """Parse HTTP request, return (method, path, headers, body)."""
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines:
            return None, None, {}, ""

        # Parse request line
        parts = lines[0].split(" ")
        if len(parts) < 2:
            return None, None, {}, ""

        method = parts[0]
        path = parts[1]

        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key.lower()] = value

        # Get body
        body = "\r\n".join(lines[body_start:]) if body_start < len(lines) else ""

        return method, path, headers, body
    except Exception as e:
        logger.debug("HTTP request parse failed: %s", e)
        return None, None, {}, ""


def build_http_response(status_code, status_text, content_type, body, extra_headers=None):
    """Build HTTP response. `extra_headers` (dict) is appended verbatim."""
    if isinstance(body, dict):
        body = json.dumps(body, indent=2)

    body_bytes = body.encode("utf-8") if isinstance(body, str) else body

    response = f"HTTP/1.1 {status_code} {status_text}\r\n"
    response += f"Content-Type: {content_type}\r\n"
    response += f"Content-Length: {len(body_bytes)}\r\n"
    response += "Server: kube-apiserver\r\n"
    response += "X-Kubernetes-Pf-Flowschema-Uid: system-leader-election\r\n"
    response += "X-Kubernetes-Pf-Prioritylevel-Uid: system\r\n"
    response += "Date: " + datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT") + "\r\n"
    for _hk, _hv in (extra_headers or {}).items():
        # single-line header values only (strip CR/LF to prevent header injection)
        _hv = str(_hv).replace("\r", " ").replace("\n", " ")
        response += f"{_hk}: {_hv}\r\n"
    response += "\r\n"

    return response.encode("utf-8") + body_bytes


# ---------------------------------------------------------------------------
# Request Handlers
# ---------------------------------------------------------------------------


def handle_k8s_api_request(method, path, headers, body, port, peer):
    """Handle Kubernetes API Server request."""
    path_lower = path.lower().split("?")[0]

    # Determine protocol based on port (6443=HTTPS, 8080=HTTP)
    proto = "https" if port == 6443 else "http"

    _is_canary = ai_canary is not None and ai_canary.is_canary_path(path_lower)

    # --- Honeytoken check (always runs first, incl. on canary-callback paths) ---
    auth_header = headers.get("authorization", "")
    token_fp, token_origin = _check_honeytoken(auth_header)
    honeytoken_hit = token_fp is not None

    if honeytoken_hit:
        _log_event(
            port,
            proto,
            peer,
            {
                "method": method,
                "path": path,
                "user_agent": headers.get("user-agent", ""),
                "authorization": "honeytoken",
                "action": "honeytoken_reuse",
                "token_id": token_fp,
                "token_origin": token_origin,
                "attacker_confirmed": True,
                "attack_type": "K8S_ATTACK",
                "rule_name": "k8s_honeytoken_reuse",
            },
        )
    elif not _is_canary:
        ev = {
            "method": method,
            "path": path,
            "user_agent": headers.get("user-agent", ""),
            "authorization": "present" if auth_header else "anonymous",
        }
        # MCP clients probe this port too (it answers plain HTTP), and for JSON-RPC the
        # body is the whole message — a length tells us nothing about whether they asked
        # to initialize, list tools, or call one. Bounded and redacted; see
        # honeypots/body_capture.py.
        ev.update(_capture_body(body, path, headers.get("content-type", "")))
        _log_event(port, proto, peer, ev)

    # --- AI prompt-injection canary callback (Idea 52) ---
    if _is_canary:
        ev = ai_canary.record_callback(method, path, headers, body, peer)
        if ev is not None:
            _log_event(port, proto, peer, ev)
            return build_http_response(204, "No Content", "application/json", "")
        return build_http_response(
            404,
            "Not Found",
            "application/json",
            {"kind": "Status", "status": "Failure", "code": 404},
        )

    # AI-endpoint bait. Scanners probe /v1/models & friends by path against any HTTP
    # port that answers — the 90-day record shows them arriving on this honeypot's
    # 8080 and 30000 — so answer here rather than let an AI-directed probe fall
    # through to a Kubernetes 404 that tells the scanner nothing is home.
    if ai_endpoints is not None:
        bait = ai_endpoints.handle(
            method, path, host=headers.get("host", ""), src_ip=(peer[0] if peer else ""), body=body
        )
        if bait is not None:
            status, payload, bait_headers, bait_event = bait
            _log_event(
                port, proto, peer, dict(bait_event, user_agent=headers.get("user-agent", ""))
            )
            return build_http_response(
                status,
                "OK" if status == 200 else "Method Not Allowed",
                "application/json",
                payload,
                extra_headers=bait_headers,
            )

    # -----------------------------------------------------------------------
    # Version endpoint (KHV002)
    if path_lower in ("/version", "/version/"):
        return build_http_response(200, "OK", "application/json", k8s_version_response())

    # Health endpoints (KHV043)
    if path_lower in ("/healthz", "/healthz/"):
        return build_http_response(200, "OK", "text/plain", k8s_healthz_response())

    if path_lower in ("/livez", "/livez/"):
        return build_http_response(200, "OK", "text/plain", k8s_livez_response())

    if path_lower in ("/readyz", "/readyz/"):
        return build_http_response(200, "OK", "text/plain", "ok")

    # API discovery
    if path_lower in ("/api", "/api/"):
        return build_http_response(200, "OK", "application/json", k8s_api_response())

    if path_lower in ("/apis", "/apis/"):
        return build_http_response(200, "OK", "application/json", k8s_apis_response())

    if path_lower in ("/api/v1", "/api/v1/"):
        return build_http_response(
            200,
            "OK",
            "application/json",
            {"kind": "APIResourceList", "groupVersion": "v1", "resources": []},
        )

    # -----------------------------------------------------------------------
    # Namespaces — deception-enriched when honeytoken is used
    if path_lower in ("/api/v1/namespaces", "/api/v1/namespaces/"):
        if honeytoken_hit:
            return build_http_response(
                200, "OK", "application/json", k8s_namespaces_deception_response()
            )
        return build_http_response(200, "OK", "application/json", k8s_namespaces_response())

    # -----------------------------------------------------------------------
    # ServiceAccounts — new: triggers k8s_serviceaccount_enum
    if "/serviceaccounts" in path_lower:
        parts = path_lower.rstrip("/").split("/")

        # TokenRequest: POST /api/v1/namespaces/{ns}/serviceaccounts/{sa}/token
        if path_lower.endswith("/token") and method == "POST":
            try:
                ns_idx = parts.index("namespaces") + 1
                sa_idx = parts.index("serviceaccounts") + 1
                ns = parts[ns_idx]
                sa_name = parts[sa_idx]
            except (ValueError, IndexError):
                ns, sa_name = "default", "default"
            canary_nonce, canary_headers = None, {}
            if ai_canary is not None and ai_canary.enabled() and ai_canary.on_token_request():
                canary_nonce, canary_headers = ai_canary.issue(
                    "k8s",
                    path,
                    headers.get("host", ""),
                    origin_src_ip=(peer[0] if peer else ""),
                    context="Kubernetes ServiceAccount token",
                )
            _log_event(
                port,
                proto,
                peer,
                {
                    "method": method,
                    "path": path,
                    "action": "token_request",
                    "attack_type": "K8S_ATTACK",
                    "rule_name": "k8s_token_request",
                    "namespace": ns,
                    "serviceaccount": sa_name,
                    "canary_nonce": canary_nonce,
                    # Name the issuing protocol explicitly: the transport is https, so
                    # without this the registry would file the canary under "https".
                    "origin_protocol": "k8s",
                },
            )
            return build_http_response(
                200,
                "OK",
                "application/json",
                k8s_tokenrequest_response(ns, sa_name),
                extra_headers=canary_headers,
            )

        # List: GET /api/v1/namespaces/{ns}/serviceaccounts  or  /api/v1/serviceaccounts
        if "namespaces" in parts:
            try:
                ns = parts[parts.index("namespaces") + 1]
            except IndexError:
                ns = None
        else:
            ns = None
        _log_event(
            port,
            proto,
            peer,
            {
                "method": method,
                "path": path,
                "action": "serviceaccount_enum",
                "attack_type": "K8S_ATTACK",
                "rule_name": "k8s_serviceaccount_enum",
            },
        )
        return build_http_response(200, "OK", "application/json", k8s_serviceaccounts_response(ns))

    # -----------------------------------------------------------------------
    # Secrets — individual secret read plants honeytoken (KHV050)
    # /api/v1/namespaces/{ns}/secrets/{name}
    if "/secrets/" in path_lower and "namespaces" in path_lower:
        parts = path_lower.rstrip("/").split("/")
        try:
            ns_idx = parts.index("namespaces") + 1
            sec_idx = parts.index("secrets") + 1
            ns = parts[ns_idx]
            sname = parts[sec_idx]
        except (ValueError, IndexError):
            ns, sname = "default", "unknown"
        canary_nonce, canary_headers, canary_instr = None, {}, None
        if ai_canary is not None and ai_canary.enabled() and ai_canary.on_secret_read():
            canary_nonce, canary_headers = ai_canary.issue(
                "k8s",
                path,
                headers.get("host", ""),
                origin_src_ip=(peer[0] if peer else ""),
                context=(
                    "Kubernetes kubeconfig"
                    if "kubeconfig" in sname.lower()
                    else "Kubernetes Secret"
                ),
            )
            if canary_nonce and ai_canary.on_annotation():
                canary_instr = canary_headers.get(ai_canary.header_name())
        _log_event(
            port,
            proto,
            peer,
            {
                "method": method,
                "path": path,
                "action": "secret_read",
                "attack_type": "K8S_ATTACK",
                "rule_name": "k8s_secret_read",
                "namespace": ns,
                "secret_name": sname,
                "canary_nonce": canary_nonce,
                "origin_protocol": "k8s",
            },
        )
        return build_http_response(
            200,
            "OK",
            "application/json",
            k8s_secret_detail_response(ns, sname, canary_instruction=canary_instr),
            extra_headers=canary_headers,
        )

    # Secrets list
    if path_lower in ("/api/v1/secrets", "/api/v1/secrets/"):
        return build_http_response(200, "OK", "application/json", k8s_secrets_response())
    if "/namespaces/" in path_lower and "/secrets" in path_lower and "/secrets/" not in path_lower:
        parts = path_lower.split("/")
        try:
            ns = parts[parts.index("namespaces") + 1]
        except (ValueError, IndexError):
            ns = None
        return build_http_response(200, "OK", "application/json", k8s_secrets_response(ns))

    # -----------------------------------------------------------------------
    # Pods — deception-enriched when honeytoken is used (KHV038, KHV052)
    if path_lower in ("/api/v1/pods", "/api/v1/pods/"):
        if honeytoken_hit:
            return build_http_response(200, "OK", "application/json", k8s_pods_deception_response())
        return build_http_response(200, "OK", "application/json", k8s_pods_response())

    # Pods in namespace
    if "/namespaces/" in path_lower and "/pods" in path_lower:
        parts = path_lower.split("/")
        try:
            ns_idx = parts.index("namespaces") + 1
            namespace = parts[ns_idx]
            if honeytoken_hit:
                return build_http_response(
                    200, "OK", "application/json", k8s_pods_deception_response()
                )
            return build_http_response(200, "OK", "application/json", k8s_pods_response(namespace))
        except (ValueError, IndexError) as exc:  # silent: URL path segment not found, fall through
            logging.getLogger(__name__).debug("ignored: %s", exc)

    # -----------------------------------------------------------------------
    # Nodes
    if path_lower in ("/api/v1/nodes", "/api/v1/nodes/"):
        return build_http_response(200, "OK", "application/json", k8s_nodes_response())

    # Services
    if path_lower in ("/api/v1/services", "/api/v1/services/"):
        return build_http_response(200, "OK", "application/json", k8s_services_response())

    # Metrics (KHV002 via metrics)
    if path_lower.startswith("/metrics"):
        return build_http_response(200, "OK", "text/plain", kubelet_metrics_response())

    # OpenAPI / Swagger
    if path_lower.startswith("/openapi"):
        return build_http_response(
            200,
            "OK",
            "application/json",
            {"openapi": "3.0.0", "info": {"title": "Kubernetes", "version": K8S_VERSION}},
        )

    # Default: return API resource list
    return build_http_response(
        200, "OK", "application/json", {"kind": "APIResourceList", "apiVersion": "v1"}
    )


def handle_kubelet_request(method, path, headers, body, port, peer):
    """Handle Kubelet API request."""
    path_lower = path.lower().split("?")[0]

    _log_event(
        port,
        "https",
        peer,
        {
            "method": method,
            "path": path,
            "user_agent": headers.get("user-agent", ""),
        },
    )

    # Pods endpoint (KHV038)
    if path_lower in ("/pods", "/pods/"):
        return build_http_response(200, "OK", "application/json", kubelet_pods_response())

    # Running pods
    if path_lower in ("/runningpods", "/runningpods/"):
        return build_http_response(200, "OK", "application/json", kubelet_runningpods_response())

    # Spec
    if path_lower in ("/spec", "/spec/"):
        return build_http_response(200, "OK", "application/json", kubelet_spec_response())

    # Metrics (KHV002)
    if path_lower.startswith("/metrics"):
        return build_http_response(200, "OK", "text/plain", kubelet_metrics_response())

    # Configz (KHV046)
    if path_lower in ("/configz", "/configz/"):
        return build_http_response(200, "OK", "application/json", kubelet_configz_response())

    # Healthz
    if path_lower.startswith("/healthz"):
        return build_http_response(200, "OK", "text/plain", "ok")

    # Container logs (KHV037)
    if "/containerLogs/" in path or "/logs/" in path:
        return build_http_response(200, "OK", "text/plain", kubelet_logs_response("container"))

    # Exec endpoint (KHV039)
    if "/exec/" in path:
        _log_event(port, "https", peer, {"path": path, "action": "exec_attempt"})
        return build_http_response(200, "OK", "application/json", {"status": "Success"})

    # Run endpoint (KHV040)
    if "/run/" in path:
        _log_event(port, "https", peer, {"path": path, "action": "run_attempt"})
        return build_http_response(200, "OK", "application/json", {"status": "Success"})

    # Attach endpoint (KHV042)
    if "/attach/" in path:
        _log_event(port, "https", peer, {"path": path, "action": "attach_attempt"})
        return build_http_response(200, "OK", "application/json", {"status": "Success"})

    # Port forward (KHV041)
    if "/portForward/" in path:
        _log_event(port, "https", peer, {"path": path, "action": "portforward_attempt"})
        return build_http_response(200, "OK", "application/json", {"status": "Success"})

    return build_http_response(404, "Not Found", "application/json", {"error": "not found"})


def handle_etcd_request(method, path, headers, body, port, peer):
    """Handle etcd API request."""
    path_lower = path.lower().split("?")[0]

    _log_event(
        port,
        "http",
        peer,
        {
            "method": method,
            "path": path,
        },
    )

    # Version (KHV033)
    if path_lower in ("/version", "/version/"):
        return build_http_response(200, "OK", "application/json", etcd_version_response())

    # Health (KHV034)
    if path_lower in ("/health", "/health/"):
        return build_http_response(200, "OK", "application/json", etcd_health_response())

    # Keys (KHV032)
    if path_lower.startswith("/v2/keys"):
        return build_http_response(200, "OK", "application/json", etcd_keys_response())

    # Members
    if path_lower.startswith("/v2/members"):
        return build_http_response(200, "OK", "application/json", etcd_members_response())

    # v3 API
    if path_lower.startswith("/v3/"):
        return build_http_response(
            200, "OK", "application/json", {"header": {"cluster_id": "12345", "member_id": "67890"}}
        )

    return build_http_response(404, "Not Found", "text/plain", "404 page not found")


def handle_dashboard_request(method, path, headers, body, port, peer):
    """Handle Kubernetes Dashboard request (KHV029)."""
    _log_event(
        port,
        "https",
        peer,
        {
            "method": method,
            "path": path,
        },
    )

    if path in ("/", "/index.html", ""):
        return build_http_response(200, "OK", "text/html", dashboard_response())

    if path.startswith("/api/v1"):
        return handle_k8s_api_request(method, path, headers, body, port, peer)

    return build_http_response(200, "OK", "text/html", dashboard_response())


def handle_kubectl_proxy_request(method, path, headers, body, port, peer):
    """Handle kubectl proxy request (KHV049)."""
    _log_event(
        port,
        "http",
        peer,
        {
            "method": method,
            "path": path,
        },
    )

    # Proxy passes through to API server
    return handle_k8s_api_request(method, path, headers, body, port, peer)


# ---------------------------------------------------------------------------
# Protocol Handlers
# ---------------------------------------------------------------------------


class K8sApiHandler(asyncio.Protocol):
    """Handle connections to Kubernetes API Server (6443/8080)."""

    def __init__(self, port, use_ssl=True):
        self.port = port
        self.use_ssl = use_ssl
        self.transport: Any = None
        self.peer = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        logger.debug("K8s API connection from %s", self.peer)

    def data_received(self, data):
        self.buffer += data

        # Check if we have a complete HTTP request
        if b"\r\n\r\n" in self.buffer:
            method, path, headers, body = parse_http_request(self.buffer)
            self.buffer = b""

            if method and path:
                response = handle_k8s_api_request(method, path, headers, body, self.port, self.peer)
                # Fake-vendor WAF canary (off by default): consistent appliance identity
                # across every decoy surface on this sensor. See deception_waf.py.
                response = deception_waf.apply_raw(response, self.peer[0] if self.peer else "")
                self.transport.write(response)

            self.transport.close()

    def connection_lost(self, exc):
        pass  # silent: connection cleanup


class KubeletApiHandler(asyncio.Protocol):
    """Handle connections to Kubelet API (10250/10255)."""

    def __init__(self, port):
        self.port = port
        self.transport: Any = None
        self.peer = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        logger.debug("Kubelet API connection from %s", self.peer)

    def data_received(self, data):
        self.buffer += data

        if b"\r\n\r\n" in self.buffer:
            method, path, headers, body = parse_http_request(self.buffer)
            self.buffer = b""

            if method and path:
                response = handle_kubelet_request(method, path, headers, body, self.port, self.peer)
                # Fake-vendor WAF canary (off by default): consistent appliance identity
                # across every decoy surface on this sensor. See deception_waf.py.
                response = deception_waf.apply_raw(response, self.peer[0] if self.peer else "")
                self.transport.write(response)

            self.transport.close()

    def connection_lost(self, exc):
        pass  # silent: connection cleanup


class EtcdApiHandler(asyncio.Protocol):
    """Handle connections to etcd API (2379)."""

    def __init__(self, port):
        self.port = port
        self.transport: Any = None
        self.peer = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        logger.debug("etcd API connection from %s", self.peer)

    def data_received(self, data):
        self.buffer += data

        if b"\r\n\r\n" in self.buffer:
            method, path, headers, body = parse_http_request(self.buffer)
            self.buffer = b""

            if method and path:
                response = handle_etcd_request(method, path, headers, body, self.port, self.peer)
                # Fake-vendor WAF canary (off by default): consistent appliance identity
                # across every decoy surface on this sensor. See deception_waf.py.
                response = deception_waf.apply_raw(response, self.peer[0] if self.peer else "")
                self.transport.write(response)

            self.transport.close()

    def connection_lost(self, exc):
        pass  # silent: connection cleanup


class DashboardHandler(asyncio.Protocol):
    """Handle connections to Kubernetes Dashboard (30000)."""

    def __init__(self, port):
        self.port = port
        self.transport: Any = None
        self.peer = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        logger.debug("Dashboard connection from %s", self.peer)

    def data_received(self, data):
        self.buffer += data

        if b"\r\n\r\n" in self.buffer:
            method, path, headers, body = parse_http_request(self.buffer)
            self.buffer = b""

            if method and path:
                response = handle_dashboard_request(
                    method, path, headers, body, self.port, self.peer
                )
                # Fake-vendor WAF canary (off by default): consistent appliance identity
                # across every decoy surface on this sensor. See deception_waf.py.
                response = deception_waf.apply_raw(response, self.peer[0] if self.peer else "")
                self.transport.write(response)

            self.transport.close()

    def connection_lost(self, exc):
        pass  # silent: connection cleanup


class KubectlProxyHandler(asyncio.Protocol):
    """Handle connections to kubectl proxy (8001)."""

    def __init__(self, port):
        self.port = port
        self.transport: Any = None
        self.peer = None
        self.buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        logger.debug("kubectl proxy connection from %s", self.peer)

    def data_received(self, data):
        self.buffer += data

        if b"\r\n\r\n" in self.buffer:
            method, path, headers, body = parse_http_request(self.buffer)
            self.buffer = b""

            if method and path:
                response = handle_kubectl_proxy_request(
                    method, path, headers, body, self.port, self.peer
                )
                # Fake-vendor WAF canary (off by default): consistent appliance identity
                # across every decoy surface on this sensor. See deception_waf.py.
                response = deception_waf.apply_raw(response, self.peer[0] if self.peer else "")
                self.transport.write(response)

            self.transport.close()

    def connection_lost(self, exc):
        pass  # silent: connection cleanup


# ---------------------------------------------------------------------------
# SSL Context
# ---------------------------------------------------------------------------


def create_ssl_context():
    """Create SSL context with self-signed cert."""
    import subprocess  # nosec B404 — fixed openssl command below
    import tempfile

    # Generate self-signed certificate
    cert_dir = Path(tempfile.mkdtemp())
    key_file = cert_dir / "server.key"
    cert_file = cert_dir / "server.crt"

    # Generate key and cert using openssl
    subprocess.run(  # noqa: S603 # nosec B603 B607 — fixed openssl command, arguments as a list
        [  # noqa: S607
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_file),
            "-out",
            str(cert_file),
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/CN=kube-apiserver/O=kubernetes",
        ],
        capture_output=True,
        check=True,
    )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)

    return context


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main():
    """Start all honeypot services."""
    loop = asyncio.get_event_loop()

    # Create SSL context
    try:
        ssl_context = create_ssl_context()
        logger.info("SSL context created")
    except Exception as e:
        logger.warning("Could not create SSL context: %s (will run without TLS)", e)
        ssl_context = None

    servers = []

    # Kubernetes API Server (HTTPS - 6443)
    try:
        server = await loop.create_server(
            lambda: K8sApiHandler(6443, use_ssl=True), "0.0.0.0", 6443, ssl=ssl_context
        )
        servers.append(server)
        logger.info("Kubernetes API Server (HTTPS) listening on port 6443")
    except Exception as e:
        logger.error("Failed to start K8s API on 6443: %s", e)

    # Kubernetes API Server (HTTP, insecure). The port is configurable because 8080
    # is contested: on sensors where the NGINX honeypot owns the exposed cleartext
    # 8080, whichever service starts first wins and the other is left crash-looping.
    # Set K8S_HONEYPOT_HTTP_PORT=0 to cede the port entirely — 6443 still carries the
    # API surface and the AI canary.
    try:
        _http_port = int(os.environ.get("K8S_HONEYPOT_HTTP_PORT", "8080") or 0)
    except ValueError:
        _http_port = 8080
    if _http_port:
        try:
            server = await loop.create_server(
                lambda: K8sApiHandler(_http_port, use_ssl=False), "0.0.0.0", _http_port
            )
            servers.append(server)
            logger.info("Kubernetes API Server (HTTP/insecure) listening on port %d", _http_port)
        except Exception as e:
            logger.error("Failed to start K8s API on %d: %s", _http_port, e)
    else:
        logger.info("Kubernetes API Server (HTTP/insecure) disabled (K8S_HONEYPOT_HTTP_PORT=0)")

    # Kubelet API (HTTPS - 10250)
    try:
        server = await loop.create_server(
            lambda: KubeletApiHandler(10250), "0.0.0.0", 10250, ssl=ssl_context
        )
        servers.append(server)
        logger.info("Kubelet API (HTTPS) listening on port 10250")
    except Exception as e:
        logger.error("Failed to start Kubelet API on 10250: %s", e)

    # Kubelet Read-Only API (HTTP - 10255)
    try:
        server = await loop.create_server(lambda: KubeletApiHandler(10255), "0.0.0.0", 10255)
        servers.append(server)
        logger.info("Kubelet Read-Only API (HTTP) listening on port 10255")
    except Exception as e:
        logger.error("Failed to start Kubelet Read-Only API on 10255: %s", e)

    # etcd API (2379)
    try:
        server = await loop.create_server(lambda: EtcdApiHandler(2379), "0.0.0.0", 2379)
        servers.append(server)
        logger.info("etcd API listening on port 2379")
    except Exception as e:
        logger.error("Failed to start etcd API on 2379: %s", e)

    # kubectl proxy (8001)
    try:
        server = await loop.create_server(lambda: KubectlProxyHandler(8001), "0.0.0.0", 8001)
        servers.append(server)
        logger.info("kubectl proxy listening on port 8001")
    except Exception as e:
        logger.error("Failed to start kubectl proxy on 8001: %s", e)

    # Kubernetes Dashboard (30000)
    try:
        server = await loop.create_server(lambda: DashboardHandler(30000), "0.0.0.0", 30000)
        servers.append(server)
        logger.info("Kubernetes Dashboard listening on port 30000")
    except Exception as e:
        logger.error("Failed to start Dashboard on 30000: %s", e)

    logger.info("Kubernetes honeypot started - %d services running", len(servers))
    logger.info("Log file: %s", LOG_FILE)

    # Keep running
    await asyncio.gather(*[s.serve_forever() for s in servers])


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
