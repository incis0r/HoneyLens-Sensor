"""Text attack-detection rules — group: cloud_container.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add(
        "CLOUD_ATTACK",
        "aws_imds_v1",
        r"169\.254\.169\.254/(latest|meta-data|user-data|dynamic)",
        re.IGNORECASE,
    )

    add(
        "CLOUD_ATTACK",
        "aws_imds_credentials",
        r"169\.254\.169\.254/latest/meta-data/iam/security-credentials",
        re.IGNORECASE,
    )

    add("CLOUD_ATTACK", "aws_imds_token", r"169\.254\.170\.2/credentials", re.IGNORECASE)

    add(
        "CLOUD_ATTACK",
        "aws_imds_redirect",
        r"(redirect|location|url)\s*[=:]\s*['\"]?https?://169\.254\.169\.254",
        re.IGNORECASE,
    )

    add("CLOUD_ATTACK", "aws_ssrf_s3", r"s3\.([\w-]+\.)?amazonaws\.com", re.IGNORECASE)

    add(
        "CLOUD_ATTACK",
        "aws_ssrf_internal",
        r"(ec2|sts|iam|lambda|secretsmanager)\.[\w-]+\.amazonaws\.com",
        re.IGNORECASE,
    )

    add(
        "CLOUD_ATTACK",
        "aws_iam_enum",
        r"(iam:ListUsers|iam:GetUser|iam:ListRoles|iam:GetPolicy|iam:ListAccessKeys)",
        re.IGNORECASE,
    )

    add(
        "CLOUD_ATTACK",
        "aws_sts_assume",
        r"sts:AssumeRole|GetSessionToken|GetFederationToken",
        re.IGNORECASE,
    )

    add(
        "CLOUD_ATTACK",
        "azure_imds",
        r"169\.254\.169\.254/metadata/(instance|identity|attested)",
        re.IGNORECASE,
    )

    add("CLOUD_ATTACK", "azure_imds_header", r"Metadata:\s*true", re.IGNORECASE)

    add(
        "CLOUD_ATTACK",
        "azure_managed_identity",
        r"(MSI_ENDPOINT|IDENTITY_ENDPOINT|IDENTITY_HEADER)",
        re.IGNORECASE,
    )

    add(
        "CLOUD_ATTACK",
        "azure_keyvault",
        r"\.vault\.azure\.net/(secrets|keys|certificates)",
        re.IGNORECASE,
    )

    add("CLOUD_ATTACK", "gcp_metadata", r"metadata\.google\.internal", re.IGNORECASE)

    add("CLOUD_ATTACK", "gcp_metadata_flavor", r"Metadata-Flavor:\s*Google", re.IGNORECASE)

    add(
        "CLOUD_ATTACK",
        "gcp_service_account",
        r"computeMetadata/v1/(instance/service-accounts|project)",
        re.IGNORECASE,
    )

    add(
        "CLOUD_ATTACK",
        "gcp_token_endpoint",
        r"/computeMetadata/v1/instance/service-accounts/default/token",
        re.IGNORECASE,
    )

    add(
        "CLOUD_ATTACK",
        "eks_auth",
        r"(eks\.amazonaws\.com|aws-iam-authenticator|eksctl)",
        re.IGNORECASE,
    )

    add("CLOUD_ATTACK", "aks_auth", r"(azmk8s\.io|azure-cli.*kubernetes|kubelogin)", re.IGNORECASE)

    add(
        "CLOUD_ATTACK",
        "gke_auth",
        r"(container\.googleapis\.com|gke-gcloud-auth-plugin)",
        re.IGNORECASE,
    )

    add("CLOUD_ATTACK", "aws_access_key", r"AKIA[0-9A-Z]{16}")

    # Requires the key to be *named*. Without that this matched any 40 characters
    # between quotes: a SHA-1, a session id, a git object. Its single production hit
    # was our own kube-apiserver response, whose resourceVersion is 40 hex characters.
    add(
        "CLOUD_ATTACK",
        "aws_secret_key",
        r"(?i)(?:aws_?secret_?(?:access_?)?key|secret_?access_?key)"
        r"['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z/+]{40}(?![0-9a-zA-Z/+])",
    )

    add("SUPPLY_CHAIN", "npm_scope_injection", r"npm\s+(install|i)\s+@[a-z\-_]+/", re.IGNORECASE)

    add(
        "SUPPLY_CHAIN",
        "pip_extra_index",
        r"--extra-index-url\s+\S+\s+--index-url|pip.*--index-url\s+(?!https://pypi)",
        re.IGNORECASE,
    )

    add(
        "SUPPLY_CHAIN",
        "pip_trusted_host",
        r"--trusted-host\s+(?!pypi\.org|pypi\.python\.org)",
        re.IGNORECASE,
    )

    add(
        "SUPPLY_CHAIN",
        "npm_preinstall_cmd",
        r"['\"]preinstall['\"]\s*:\s*['\"].*?(curl|wget|bash|sh|nc|eval)",
        re.IGNORECASE,
    )

    add(
        "SUPPLY_CHAIN",
        "npm_postinstall_cmd",
        r"['\"]postinstall['\"]\s*:\s*['\"].*?(curl|wget|bash|sh|nc|eval)",
        re.IGNORECASE,
    )

    add(
        "SUPPLY_CHAIN",
        "pip_setup_cmd",
        r"cmdclass\s*=.*?(install|develop).*?subprocess|os\.system",
        re.IGNORECASE,
    )

    add("SUPPLY_CHAIN", "typosquat_lodash", r"\b(lod[a-z]sh|l0dash|lodas|1odash)\b", re.IGNORECASE)

    add(
        "SUPPLY_CHAIN",
        "typosquat_requests",
        r"(pip|install|import|require|from)\s+['\"]?(requ[e]sts|reqeusts|python-requests)['\"]?",
        re.IGNORECASE,
    )

    add(
        "SUPPLY_CHAIN",
        "gha_secret_exfil",
        r"echo\s+\$\{\{\s*secrets\.\w+|curl.*secrets\.",
        re.IGNORECASE,
    )

    add(
        "SUPPLY_CHAIN",
        "gha_pwn_request",
        r"pull_request_target.*checkout.*\$\{\{.*head",
        re.IGNORECASE,
    )

    add(
        "SUPPLY_CHAIN",
        "gha_injection",
        r"\$\{\{\s*(github\.event\.(issue|comment|review)\.body|github\.head_ref)",
        re.IGNORECASE,
    )

    add("K8S_ATTACK", "k8s_scanner_kube_hunter", r"(kube-hunter|kube.?hunter)", re.IGNORECASE)

    add("K8S_ATTACK", "k8s_scanner_trivy", r"(trivy.*kubernetes|kubernetes.*trivy)", re.IGNORECASE)

    add("K8S_ATTACK", "k8s_scanner_kube_bench", r"(kube-bench|kube.?bench)", re.IGNORECASE)

    add("K8S_ATTACK", "k8s_scanner_kubescape", r"(kubescape)", re.IGNORECASE)

    add(
        "K8S_ATTACK",
        "k8s_api_resources",
        r"/api/v1/(pods|nodes|namespaces|secrets|configmaps|services)\b",
        re.IGNORECASE,
    )

    add(
        "K8S_ATTACK",
        "k8s_apis_apps",
        r"/apis/apps/v1/(deployments|daemonsets|replicasets|statefulsets)\b",
        re.IGNORECASE,
    )

    add(
        "K8S_ATTACK",
        "k8s_kubelet_paths",
        r"/(runningpods|containerLogs|portForward)/",
        re.IGNORECASE,
    )

    add(
        "K8S_ATTACK",
        "k8s_response_podlist",
        r"\"kind\"\s*:\s*\"(PodList|NodeList|SecretList|NamespaceList|ServiceList)\"",
        re.IGNORECASE,
    )

    add(
        "K8S_ATTACK",
        "k8s_response_k8s_version",
        r"\"gitVersion\"\s*:\s*\"v\d+\.\d+\.\d+\"",
        re.IGNORECASE,
    )

    add(
        "K8S_ATTACK",
        "k8s_kubelet_config",
        r"\"kubeletconfig\"|\"authentication\".*\"anonymous\"",
        re.IGNORECASE,
    )

    add(
        "K8S_ATTACK",
        "k8s_service_account_token",
        r"/var/run/secrets/kubernetes\.io/serviceaccount",
        re.IGNORECASE,
    )

    add(
        "K8S_ATTACK",
        "k8s_privileged_container",
        r"\"privileged\"\s*:\s*true|securityContext.*privileged.*true",
        re.IGNORECASE,
    )

    add("K8S_ATTACK", "k8s_dashboard", r"(kubernetes-dashboard|kd-root)", re.IGNORECASE)

    add("K8S_ATTACK", "k8s_etcd_response", r"\"etcdserver\"\s*:|\"etcdcluster\"\s*:", re.IGNORECASE)

    add("K8S_ATTACK", "k8s_etcd_keys", r"/v2/keys/registry|/v3/kv/range", re.IGNORECASE)

    add("K8S_ATTACK", "k8s_cve_2018_1002105", r"CVE.?2018.?1002105", re.IGNORECASE)

    add("K8S_ATTACK", "k8s_cve_2019_11247", r"CVE.?2019.?11247", re.IGNORECASE)

    add("K8S_ATTACK", "k8s_cve_2020_8554", r"CVE.?2020.?8554", re.IGNORECASE)

    add("K8S_ATTACK", "k8s_cve_2021_25741", r"CVE.?2021.?25741", re.IGNORECASE)

    add(
        "K8S_ATTACK",
        "k8s_serviceaccount_enum",
        r"/api/v1/(namespaces/[^/]+/)?serviceaccounts",
        re.IGNORECASE,
    )

    add(
        "K8S_ATTACK",
        "k8s_token_request",
        r"/api/v1/namespaces/[^/]+/serviceaccounts/[^/]+/token",
        re.IGNORECASE,
    )

    add("K8S_ATTACK", "k8s_secret_read", r"/api/v1/namespaces/[^/]+/secrets/[^/]+$", re.IGNORECASE)

    add("K8S_ATTACK", "k8s_honeytoken_reuse", r"__honeytoken_reuse_sentinel__", re.IGNORECASE)

    add(
        "K8S_ATTACK",
        "claude_k8s_external_kubelet_metrics_access",
        r"""GET\s+/metrics.*kubectl/v\d+\.\d+\.\d+""",
    )

    add("K8S_ATTACK", "claude_k8s_kubelet_version_recon", r"""GET\s+/version.*User-Agent:""")

    add(
        "K8S_ATTACK",
        "claude_kubernetes_version_disclosure_scan",
        r"""GET\s+/version\s+HTTP/[0-9]\.[0-9].*User-Agent:.*(?:CensysInspect|kube-hunter|kubectl|kubernetes)""",
    )
