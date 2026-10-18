"""Sensor configuration. Secrets and tunables are read from ``.env`` via ``env()``.

Defaults match 0.9, with one structural change: data paths (pcaps, certs, events) do not
live in the code directory but under ``SENSOR_HOME`` (default ``/opt/honeylens``). An
installable package has no "project directory" to keep them in, and SELinux will not let a
systemd unit write just anywhere anyway.

``.env`` locations are described in ``honeylens.env``; the variable contract is kept in
``.env.example``.
"""

import ipaddress
import json
import os
import socket
from pathlib import Path
from typing import Any

from honeylens.env import env
from honeylens.version import VERSION

__all__ = ["VERSION"]

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SENSOR_HOME = Path(env("SENSOR_HOME", "/opt/honeylens"))
DATA_DIR = SENSOR_HOME / "data"  # runtime data: MITRE STIX, CIRCL cache, editable mappings

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DB_CONFIG: dict[str, Any] = {
    "dbname": env("DB_NAME", "sensor"),
    "user": env("DB_USER", "sensor_user"),
    "password": env("DB_PASSWORD", ""),
    "host": env("DB_HOST", "localhost"),
    "port": env("DB_PORT", 5432, cast=int),
    # Without a limit psycopg2 waits for the full TCP timeout (Linux: about 2 min) on an
    # unreachable host — and text_rules connects to the database at import, so the start of
    # every process importing the classifier would hang. Measured 2026-09-19 on 10.255.255.1.
    "connect_timeout": env("DB_CONNECT_TIMEOUT", 5, cast=int),
}
DB_POOL_MIN = env("DB_POOL_MIN", 2, cast=int)
DB_POOL_MAX = env("DB_POOL_MAX", 20, cast=int)

# ---------------------------------------------------------------------------
# API server
# ---------------------------------------------------------------------------

API_HOST = env("API_HOST", "0.0.0.0")  # noqa: S104 # nosec B104 — the sensor listens on all interfaces by design
# The sensor's UI/API sits on a high management port, like sshd (Dariusz, 2026-09-20):
# 8080 is a honeypot port (nginx, K8s, monolith), not the sensor's. The API listens on one
# of these — API_PORT without TLS or API_TLS_PORT with TLS.
API_PORT = env("API_PORT", 60443, cast=int)
API_TLS_PORT = env("API_TLS_PORT", 60443, cast=int)
API_AUTH_USERNAME = env("API_AUTH_USERNAME", "sensor")
API_AUTH_PASSWORD = env("API_AUTH_PASSWORD", "")
API_PCAP_DIR = Path(env("API_PCAP_DIR", SENSOR_HOME / "pcaps"))

# The sensor's sshd port — excluded from capture so it does not make noise
# Database archiving (tools/db_archive.py) — monthly partitions older than DAYS land in
# ARCHIVE_DIR; EXPORT writes SQL, CLEANUP removes the partitioned data after export.
DB_ARCHIVE_DIR = env("DB_ARCHIVE_DIR", str(SENSOR_HOME / "archives"))
DB_ARCHIVE_DAYS = env("DB_ARCHIVE_DAYS", 30, cast=int)
DB_ARCHIVE_EXPORT = env("DB_ARCHIVE_EXPORT", False, cast=bool)
DB_ARCHIVE_CLEANUP = env("DB_ARCHIVE_CLEANUP", True, cast=bool)
# Backup encryption password (tools/backup.py); empty = unencrypted backup.
BACKUP_PASSWORD = env("BACKUP_PASSWORD", "")

SENSOR_SSH_PORT = env("SENSOR_SSH_PORT", 62222, cast=int)


def get_api_bind_address() -> str:
    return API_HOST


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

TLS_CERT_DIR = Path(env("TLS_CERT_DIR", SENSOR_HOME / "certs"))
TLS_CERT_FILE = Path(env("TLS_CERT_FILE", TLS_CERT_DIR / "sensor.crt"))
TLS_KEY_FILE = Path(env("TLS_KEY_FILE", TLS_CERT_DIR / "sensor.key"))
TLS_KEY_TYPE = env("TLS_KEY_TYPE", "EC")
TLS_EC_CURVE = env("TLS_EC_CURVE", "secp384r1")
TLS_RSA_BITS = env("TLS_RSA_BITS", 4096, cast=int)
TLS_MIN_VERSION = env("TLS_MIN_VERSION", "TLSv1.3")
TLS_CIPHERS = env(
    "TLS_CIPHERS", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
)

# ---------------------------------------------------------------------------
# eBPF capture
# ---------------------------------------------------------------------------

INTERFACE = env("INTERFACE", "enp0s31f6")
EVENTS_JSON = Path(env("EVENTS_JSON", SENSOR_HOME / "events.json"))
PCAP_DIR = Path(env("PCAP_DIR", SENSOR_HOME / "pcaps"))
EBPF_LOG_FILE = Path(env("EBPF_LOG_FILE", "/var/log/sensor_ebpf.log"))
EBPF_CHECK_TIMEOUT = env("EBPF_CHECK_TIMEOUT", 10, cast=int)
EBPF_CHECK_STRICT = env("EBPF_CHECK_STRICT", False, cast=bool)
EBPF_PERF_BUFFER_PAGES = env("EBPF_PERF_BUFFER_PAGES", 64, cast=int)
EBPF_RING_BUF_PAGES = EBPF_PERF_BUFFER_PAGES

# PCAP manager (Idea 23). The default 100K files / 5 min could not keep up with scanning
# days on DEV 2026-05-08 (1M+ pcap backlog, disk at 100%). These values give ~4.5M/h.
PCAP_MANAGEMENT = {
    "max_files_per_cycle": 250000,
    "daemon_interval_sec": 120,
}

# ---------------------------------------------------------------------------
# Full eBPF packet dissection (Idea 30, phase 0)
# ---------------------------------------------------------------------------
# Master gate. When False, sensor_tcp.c collects the standard 256-byte sample for every
# port. When True, the monitored_ports map (from EBPF_DISSECTION_PORTS plus the
# ebpf_dissection_ports table) opts selected destination ports into capture of up to 4 KB
# per segment and full_payload storage.
EBPF_FULL_DISSECTION_ENABLED = env("EBPF_FULL_DISSECTION_ENABLED", False, cast=bool)

# Baseline list per port (the DB table overrides at runtime). The BPF program rounds the
# depth to one of the tiers {256, 1024, 4096}.
EBPF_DISSECTION_PORTS: dict[int, dict[str, int]] = {
    # PAN-OS captive-portal — CVE-2026-0300
    4443: {"capture_depth": 4096, "retain_hours": 168},
    6080: {"capture_depth": 4096, "retain_hours": 168},
    6081: {"capture_depth": 4096, "retain_hours": 168},
    6082: {"capture_depth": 4096, "retain_hours": 168},
    # SMTP — bash-revshell vectors
    25: {"capture_depth": 4096, "retain_hours": 72},
    465: {"capture_depth": 4096, "retain_hours": 72},
    587: {"capture_depth": 4096, "retain_hours": 72},
    # Redis — cron-injection vector
    6379: {"capture_depth": 4096, "retain_hours": 168},
    # FTP control
    21: {"capture_depth": 1024, "retain_hours": 72},
    # Tomcat / Java
    8080: {"capture_depth": 4096, "retain_hours": 72},
    8443: {"capture_depth": 4096, "retain_hours": 72},
}
EBPF_DISSECTION_RECONCILE_SEC = env("EBPF_DISSECTION_RECONCILE_SEC", 30, cast=int)
# Hard per-segment capture ceiling; must match payload_sample[] in sensor_tcp.c.
EBPF_DISSECTION_MAX_DEPTH = 4096

ALWAYS_CAPTURE_PORTS = [21, 22, 23, 25, 80, 443, 445, 502, 1433, 1883, 3306, 3389, 5900, 8080, 8443]

SCAN_TYPES = {
    1: "SYN Scan",
    2: "FIN Scan",
    3: "NULL Scan",
    4: "XMAS Scan",
    5: "ACK Scan",
    6: "Normal Traffic",
}

# ---------------------------------------------------------------------------
# Honeypot log sources
# ---------------------------------------------------------------------------

HONEYPOTNG_LOG_DIR = Path(env("HONEYPOTNG_LOG_DIR", "/opt/logs/honeypotng"))
HONEYPOTNG_TRAFFIC_DIR = HONEYPOTNG_LOG_DIR / "traffic_dumps"
HONEYPOTNG_PATTERNS_FILE = HONEYPOTNG_LOG_DIR / "known_patterns.json"
HONEYPOTNG_GLOB = env("HONEYPOTNG_GLOB", str(HONEYPOTNG_LOG_DIR / "*.json"))
# 1.0: the K8s honeypot writes to the honeypot directory (manifest), so the default path is
# there — the separate entry stays for installs that keep the file elsewhere.
K8S_HONEYPOT_LOG_FILE = env("K8S_HONEYPOT_LOG_FILE", str(HONEYPOTNG_LOG_DIR / "honeypot_k8s.json"))
FORTIGATE_LOG_FILE = env("FORTIGATE_LOG_FILE", "/var/log/honeypot_fortigate.json")
# The K8s honeypot log MUST be here, otherwise its events never reach the ingest.
HONEYPOT_LOG_GLOBS = [HONEYPOTNG_GLOB, K8S_HONEYPOT_LOG_FILE]

# ---------------------------------------------------------------------------
# Ollama (local AI)
# ---------------------------------------------------------------------------

AI_ANALYSIS_ENABLED = env("AI_ANALYSIS_ENABLED", True, cast=bool)
OLLAMA_URL = env("OLLAMA_URL", "http://localhost:11434")
OLLAMA_TRIAGE_MODEL = env("OLLAMA_TRIAGE_MODEL", "qwen2.5:3b")
OLLAMA_DEEP_MODEL = env("OLLAMA_DEEP_MODEL", "codellama:34b")
OLLAMA_TIMEOUT = env("OLLAMA_TIMEOUT", 120, cast=int)

AI_TRIAGE_MIN_SEVERITY = env("AI_TRIAGE_MIN_SEVERITY", "MEDIUM")
AI_BATCH_SIZE = env("AI_BATCH_SIZE", 10, cast=int)
AI_CYCLE_INTERVAL = env("AI_CYCLE_INTERVAL", 30, cast=int)

# ---------------------------------------------------------------------------
# Anthropic Claude (external AI)
# ---------------------------------------------------------------------------

USE_EXTERNAL_AI = env("USE_EXTERNAL_AI", False, cast=bool)
AUTO_EXTERNAL_AI = env("AUTO_EXTERNAL_AI", False, cast=bool)
ANTHROPIC_API_KEY = env("ANTHROPIC_API_KEY", "")
ANTHROPIC_TRIAGE_MODEL = env("ANTHROPIC_TRIAGE_MODEL", "claude-haiku-4-5-20251001")
ANTHROPIC_DEEP_MODEL = env("ANTHROPIC_DEEP_MODEL", "claude-sonnet-4-20250514")
DEEP_ANALYSIS_ENGINE = env("DEEP_ANALYSIS_ENGINE", "claude")

# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

SESSION = {
    "lifetime_hours": env("SESSION_LIFETIME_HOURS", 8, cast=int),
    "lifetime_remember_hours": env("SESSION_LIFETIME_REMEMBER_HOURS", 720, cast=int),
    "idle_timeout_hours": env("SESSION_IDLE_TIMEOUT_HOURS", 2, cast=int),
    "idle_timeout_remember_hours": env("SESSION_IDLE_TIMEOUT_REMEMBER_HOURS", 72, cast=int),
    "max_per_user": env("SESSION_MAX_PER_USER", 5, cast=int),
    "cleanup_retain_days": env("SESSION_CLEANUP_RETAIN_DAYS", 7, cast=int),
    "cookie_name": env("SESSION_COOKIE_NAME", "sensor_sid"),
}

# ---------------------------------------------------------------------------
# Threat blog (Idea 24)
# ---------------------------------------------------------------------------

BLOG = {
    "enabled": env("BLOG_ENABLED", False, cast=bool),
    "blog_url": env("BLOG_URL", "https://blog.honeylens.io"),
    "api_key": env("BLOG_API_KEY", ""),
    "basic_user": env("BLOG_BASIC_USER", "sensor"),
    "basic_pass": env("BLOG_BASIC_PASS", ""),
    "verify_tls": env("BLOG_VERIFY_TLS", True, cast=bool),
    "ca_bundle": env("BLOG_CA_BUNDLE", ""),
    # Publishing to the threat blog is manual only (operator-triggered from hunting);
    # there is no auto-publish-on-profile path.
    "publish_timeout_sec": env("BLOG_PUBLISH_TIMEOUT", 30, cast=int),
    "anthropic_model": ANTHROPIC_DEEP_MODEL,
}

# ---------------------------------------------------------------------------
# Scanner exclusions, fingerprint correlation (Idea 28), attack knowledge base (Idea 27)
# ---------------------------------------------------------------------------

SCANNER_EXCLUSIONS: dict[str, Any] = {
    "enabled": env("SCANNER_EXCLUSIONS_ENABLED", True, cast=bool),
    # Resolve the PTR live when stored enrichment has no hostname — the scanner PTR
    # (*.censys-scanner.com, *.shodan.io, ...) is the most reliable scanner tell.
    "rdns_lookup": env("SCANNER_EXCLUSIONS_RDNS", True, cast=bool),
    "rdns_timeout_sec": env("SCANNER_EXCLUSIONS_RDNS_TIMEOUT", 2.0, cast=float),
    "extra_asns": [],
    "extra_org_substrings": [],
    "extra_hostname_suffixes": [],
}

FINGERPRINT_CORRELATION = {
    "enabled": env("FINGERPRINT_ENABLED", True, cast=bool),
    "interval_minutes": env("FINGERPRINT_INTERVAL_MIN", 15, cast=int),
    "max_ips_per_fingerprint": env("FINGERPRINT_MAX_IPS", 20, cast=int),
    "min_cluster_size": env("FINGERPRINT_MIN_CLUSTER", 2, cast=int),
    "min_cluster_confidence": env("FINGERPRINT_MIN_CONFIDENCE", 0.5, cast=float),
}

ATTACK_KB = {
    "enabled": env("ATTACK_KB_ENABLED", True, cast=bool),
    "auto_generate": env("ATTACK_KB_AUTO_GENERATE", True, cast=bool),
    "use_claude": env("ATTACK_KB_USE_CLAUDE", True, cast=bool),
    "claude_model": env("ATTACK_KB_CLAUDE_MODEL", "claude-sonnet-4-6"),
    "ollama_model": env("ATTACK_KB_OLLAMA_MODEL", "qwen2.5:14b"),
    "refresh_interval_days": env("ATTACK_KB_REFRESH_DAYS", 30, cast=int),
    "include_sensor_stats": env("ATTACK_KB_SENSOR_STATS", True, cast=bool),
    "max_example_payloads": env("ATTACK_KB_MAX_PAYLOADS", 5, cast=int),
    "sanitize_payloads": env("ATTACK_KB_SANITIZE", True, cast=bool),
    "enrich_ai_prompts": env("ATTACK_KB_ENRICH_PROMPTS", True, cast=bool),
}

# ---------------------------------------------------------------------------
# Event filtering
# ---------------------------------------------------------------------------


def parse_list(raw: str) -> list[str]:
    """Comma-separated list, without empty items or surrounding whitespace."""
    return [s.strip() for s in (raw or "").split(",") if s.strip()]


def parse_src_host_ports(raw: str) -> dict[str, set[int]]:
    """``IGNORE_SRC_HOST_PORTS`` — silence one source on one port, nothing broader.

    ``IGNORE_LOCAL_SOURCES`` is a blunt instrument: it cuts the source out entirely. Good
    for the sensor's own addresses, bad for everything else — that is how sensor-e stopped
    seeing the subnet its honeypot stands in. This is the scalpel for the middle case: a
    known integration that legitimately talks to one service port on the sensor.

    The originating case: PostgreSQL on sensor-e listens on the LAN and Grafana from the ZDI
    lab queries it with a read-only role ~9 times an hour. That is a third of the sensor's
    daily events and reads like insider activity in the customer report. Cutting the host
    would hide its compromise; cutting port 5432 — an attack on a LAN-reachable database.
    Only the pair is safe to drop.

    Format: comma-separated ``<ip-or-cidr>:<port>``; an address may repeat for several ports::

        IGNORE_SRC_HOST_PORTS=192.0.2.50:5432,192.0.2.50:9090,198.51.100.0/24:161

    Split from the right, so IPv6 (``2001:db8::5:5432``) and CIDR survive. A bad entry is
    skipped, not raised — a typo here must not stop the sensor from starting, and a skipped
    entry simply does not match, which is the safe direction: the event stays.
    """
    out: dict[str, set[int]] = {}
    for item in (raw or "").split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        host, _, port_s = item.rpartition(":")
        host = host.strip()
        try:
            port = int(port_s)
        except ValueError:
            continue
        if not host or not (0 < port < 65536):
            continue
        out.setdefault(host, set()).add(port)
    return out


def parse_cidrs(raw: str) -> tuple[str, ...]:
    """Comma-separated CIDRs, validated and normalised.

    A malformed entry is dropped, silently, like every other parser in this module — but
    unlike the others the consequence here is invisible (a subnet you believe is hidden is
    not), so after setting this, read the value back and count the entries. Dropping beats
    passing it through: these go into SQL as ``inet``, where a bad literal fails the whole
    query and blanks the panel rather than merely filtering nothing.
    """
    out: list[str] = []
    for item in parse_list(raw):
        try:
            out.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            continue
    return tuple(out)


# Subnets hidden from the WebUI/API *views*. This is a DISPLAY filter, not an ingest filter:
# the events are still captured, stored and classified, they just do not clutter dashboards
# with the operator's own management and monitoring traffic. That distinction matters —
# IGNORE_LOCAL_SOURCES above drops events at ingest, and widening it to a whole /24 is what
# once made a sensor stop seeing the subnet its own honeypot stands in (see parse_src_host_ports).
# Default is our lab's range, which is what this was hardcoded to before it was configurable;
# every other deployment must set its own, e.g. DASHBOARD_EXCLUDE_SUBNETS=10.0.0.0/8.
DASHBOARD_EXCLUDE_SUBNETS = parse_cidrs(env("DASHBOARD_EXCLUDE_SUBNETS", "192.168.0.0/24"))

IGNORE_DST_PORT_ABOVE = env("IGNORE_DST_PORT_ABOVE", 30000, cast=int)
IGNORE_SRC_PORT_ABOVE = env("IGNORE_SRC_PORT_ABOVE", 0, cast=int)
IGNORE_LOCAL_SOURCES = parse_list(env("IGNORE_LOCAL_SOURCES", ""))
IGNORE_DST_HOST_PORTS: dict[str, list[int]] = {}  # per install, e.g. {"192.0.2.53": [22]}
IGNORE_SRC_HOST_PORTS = parse_src_host_ports(env("IGNORE_SRC_HOST_PORTS", ""))

# Ports always ignored (sensor management traffic, not an attack)
LLM_HONEYPOT_PORT = env("LLM_HONEYPOT_PORT", 3080, cast=int)
IGNORE_PORTS = [SENSOR_SSH_PORT, API_PORT, API_TLS_PORT, LLM_HONEYPOT_PORT]

# ---------------------------------------------------------------------------
# MiTM detector and whitelist (module constants in 0.9; here so the operator can set them)
# ---------------------------------------------------------------------------

MITM_GATEWAY_IPS = parse_list(env("MITM_GATEWAY_IPS", ""))
MITM_TRUSTED_DNS = parse_list(env("MITM_TRUSTED_DNS", "8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1"))
MITM_TRUSTED_DHCP = parse_list(env("MITM_TRUSTED_DHCP", ""))
MITM_ARP_CHANGE_THRESHOLD = env("MITM_ARP_CHANGE_THRESHOLD", 3, cast=int)
MITM_LOG_FILE = env("MITM_LOG_FILE", "/var/log/mitm_detector.json")
# LLMNR/NBT-NS: legitimate hosts answer name queries all the time. At most one event per
# responder per cooldown, and only past the reply threshold; HIGH only for the broad
# pattern (one host answering many queriers — the Responder/Inveigh shape).
MITM_LLMNR_MIN_REPLIES = env("MITM_LLMNR_MIN_REPLIES", 5, cast=int)
MITM_LLMNR_COOLDOWN = env("MITM_LLMNR_COOLDOWN", 3600, cast=int)
MITM_LLMNR_BROAD_QUERIERS = env("MITM_LLMNR_BROAD_QUERIERS", 8, cast=int)

WHITELIST_IPS = parse_list(env("WHITELIST_IPS", ""))
_whitelist_file = env("WHITELIST_FILE", str(SENSOR_HOME / "whitelist.txt"))
# An empty value disables the file; Path("") would be truthy (it is "."), hence explicit None.
WHITELIST_FILE: Path | None = Path(_whitelist_file) if _whitelist_file else None

# ---------------------------------------------------------------------------
# Credential vault (Idea 38)
# ---------------------------------------------------------------------------

VAULT_MASTER_KEY = env("VAULT_MASTER_KEY", "")

# ---------------------------------------------------------------------------
# Honeypots
# ---------------------------------------------------------------------------

HONEYWEB_HOST = env("HONEYWEB_HOST", "0.0.0.0")  # noqa: S104 # nosec B104 — a honeypot must be reachable from everywhere
HONEYWEB_PORT = env("HONEYWEB_PORT", 8080, cast=int)
# Web UI: grouped navigation (five product areas) or the old flat bar.
WEBUI_NEW_SHELL = env("WEBUI_NEW_SHELL", True, cast=bool)

HONEYWEB_TLS_PORT = env("HONEYWEB_TLS_PORT", 8443, cast=int)
HONEYWEB_LOG_DIR = Path(env("HONEYWEB_LOG_DIR", "/opt/logs/honeyweb"))
HONEYWEB_ACCESS_LOG = HONEYWEB_LOG_DIR / "access.log"
HONEYWEB_CONSOLE_LOG = HONEYWEB_LOG_DIR / "honey_console.log"

# Honeypot services — port: protocol hint (IT protocols; ICS/OT have separate honeypots
# hp_modbus 502, hp_s7comm 102, hp_mqtt 1883, hp_dnp3 20000, hp_iec104 2404, hp_bacnet 47808,
# hp_enip 44818, hp_opcua 4840, hp_fins 9600, hp_memcached 11211)
_HONEYPOTNG_SERVICES_DEFAULT = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    443: "https",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    8080: "http",
    8443: "https",
    9200: "elasticsearch",
    9300: "elasticsearch",
}


def parse_services(raw: str) -> dict[int, str]:
    """``"30021:ftp,30022:ssh"`` -> ``{30021: "ftp", 30022: "ssh"}``; empty text -> defaults.

    In a container the monolith runs without root and cannot bind < 1024, so the honeypot
    manifest hands it this table with high ports (and ``HONEYLENS_PORT_MAP`` translates
    them back to the protocol port in the stored event).
    """
    raw = (raw or "").strip()
    if not raw:
        return dict(_HONEYPOTNG_SERVICES_DEFAULT)
    out: dict[int, str] = {}
    for item in raw.split(","):
        port, _, hint = item.strip().partition(":")
        if port and hint:
            out[int(port)] = hint.strip()
    return out


HONEYPOTNG_SERVICES = parse_services(env("HONEYPOTNG_SERVICES", ""))

HONEY_TLS_CERT = TLS_CERT_DIR / "honey.crt"
HONEY_TLS_KEY = TLS_CERT_DIR / "honey.key"
HONEY_TLS_CIPHERS = env("HONEY_TLS_CIPHERS", "DEFAULT:!aNULL:!eNULL:!MD5")

# FortiGate honeypot
FORTIGATE_ENABLED = env("FORTIGATE_ENABLED", True, cast=bool)
FORTIGATE_PORTS = [10443, 20443]
FORTIGATE_TLS_CERT = TLS_CERT_DIR / "fortigate.crt"
FORTIGATE_TLS_KEY = TLS_CERT_DIR / "fortigate.key"


def get_fortigate_config() -> dict[str, Any]:
    """FortiGate honeypot configuration.

    The installer writes a per-install identity into ``.env`` so that FortiGate traffic
    does not repeat the same model, serial number and hostname everywhere.
    """
    ports_raw = env("FORTIGATE_PORTS", ",".join(str(p) for p in FORTIGATE_PORTS))
    ports = []
    for item in parse_list(str(ports_raw)):
        try:
            ports.append(int(item))
        except ValueError:
            continue
    if not ports:
        ports = list(FORTIGATE_PORTS)
    return {
        "enabled": FORTIGATE_ENABLED,
        "ports": ports,
        "tls_cert": env("FORTIGATE_TLS_CERT", FORTIGATE_TLS_CERT),
        "tls_key": env("FORTIGATE_TLS_KEY", FORTIGATE_TLS_KEY),
        "log_file": FORTIGATE_LOG_FILE,
        "bind_host": env("FORTIGATE_LISTEN_HOST", "0.0.0.0"),  # noqa: S104 # nosec B104 — honeypot
        "model": env("FORTIGATE_MODEL", "FortiGate-60F"),
        "version": env("FORTIGATE_VERSION", "7.4.3"),
        "build": env("FORTIGATE_BUILD", "2573"),
        "serial": env("FORTIGATE_SERIAL", "FGT60FTK22000001"),
        "hostname": env("FORTIGATE_HOSTNAME", "FW-EDGE-01"),
    }


# K8s honeypot
K8S_HONEYPOT_ENABLED = env("K8S_HONEYPOT_ENABLED", True, cast=bool)

# OS fingerprint deception (eBPF, TTL rewrite)
DECEPTION_ENABLED = env("DECEPTION_ENABLED", True, cast=bool)
DECEPTION_INTERFACE = env("DECEPTION_INTERFACE", INTERFACE)

# Fake-vendor WAF canary header (honeypots/deception_waf.py). OFF by default; enable
# per-host like TTL deception. When on, every honeypot response carries a plausible but
# fictional WAF header (per-host vendor identity + opaque per-attacker nonce) that detects
# when a client — notably an LLM triage agent — parses and reflects our response. The salt
# keeps the nonce stable per host; leave it empty to derive it from the host identity.
WAF_CANARY_ENABLED = env("WAF_CANARY_ENABLED", False, cast=bool)
WAF_CANARY_SALT = env("WAF_CANARY_SALT", "")
# Pin the fictional WAF vendor for this host (else derived from SENSOR_HOSTNAME, which can
# collide across hosts). Set per host so every sensor presents a UNIQUE vendor in the header.
WAF_CANARY_VENDOR = env("WAF_CANARY_VENDOR", "")

# OS fingerprints for TTL/TCP-window deception (ebpf/ebpf_ttl_deception.c). The
# port -> profile assignment is built by honeylens.honeypots.manifest from the honeypot's
# ttl_profile field (layer 8), so only the profile definitions live here. bms/ics end up on
# "plc" (embedded devices) — as the 0.9 port dict treated BACnet/S7.
DECEPTION_PROFILES = {
    "windows": {"ttl": 128, "tcp_window": 65535, "tcp_wscale": 8},
    "windows7": {"ttl": 128, "tcp_window": 8192, "tcp_wscale": 2},
    "plc": {"ttl": 30, "tcp_window": 2048, "tcp_wscale": 0},
    "linux": {"ttl": 64, "tcp_window": 29200, "tcp_wscale": 7},
}

# Attacker profiling
ATTACKER_PROFILING: dict[str, Any] = {
    "min_connections": env("PROFILER_MIN_CONNECTIONS", 3, cast=int),
    "min_attack_patterns": env("PROFILER_MIN_ATTACKS", 1, cast=int),
    "max_profiles_per_cycle": env("PROFILER_BATCH_SIZE", 10, cast=int),
    "daemon_interval_sec": env("PROFILER_INTERVAL", 300, cast=int),
    "reprofile_interval_sec": env("PROFILER_REPROFILE_INTERVAL", 21600, cast=int),
    "ollama_url": OLLAMA_URL,
    "ollama_model": env("PROFILER_OLLAMA_MODEL", "") or OLLAMA_DEEP_MODEL,
    "ollama_timeout": OLLAMA_TIMEOUT,
    "ai_provider": env("PROFILER_AI_PROVIDER", "ollama"),
    "nous_api_key": env("NOUS_API_KEY", ""),
    "nous_model": env("PROFILER_NOUS_MODEL", "qwen/qwen3-30b-a3b-instruct-2507"),
    # ai_provider=openai → OpenAI-compatible endpoint (e.g. a client LiteLLM proxy), reusing the
    # same OPENAI_DEEP_* the ai-analyzer uses. Base URL includes /v1 (endpoint is /chat/completions).
    "openai_base_url": env("OPENAI_DEEP_BASE_URL", ""),
    "openai_api_key": env("OPENAI_DEEP_API_KEY", "") or env("OPENAI_API_KEY", ""),
    "openai_model": env("PROFILER_OPENAI_MODEL", "") or env("OPENAI_DEEP_MODEL", ""),
    "ai_max_tokens": env("PROFILER_AI_MAX_TOKENS", 1024, cast=int),
    "auto_profile": env("PROFILER_AUTO", True, cast=bool),
    "cooldown_between_osint_sec": 2,
    "osint_log_retention_days": 90,
    "api_keys": {
        "threatfox": env("OSINT_THREATFOX_KEY", ""),
        "abuseipdb": env("OSINT_ABUSEIPDB_KEY", ""),
        "shodan": env("OSINT_SHODAN_KEY", ""),
        "virustotal": env("OSINT_VIRUSTOTAL_KEY", ""),
        "greynoise": env("OSINT_GREYNOISE_KEY", ""),
        "otx": env("OSINT_OTX_KEY", ""),
        "pulsedive": env("OSINT_PULSEDIVE_KEY", ""),
        "censys_id": env("OSINT_CENSYS_ID", ""),
        "censys_secret": env("OSINT_CENSYS_SECRET", ""),
        "ipinfo": env("OSINT_IPINFO_KEY", ""),
    },
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def get_sensor_interfaces() -> list[str] | None:
    """Interfaces to monitor: comma-separated ``SENSOR_INTERFACES`` or ``INTERFACE``."""
    env_ifaces = os.environ.get("SENSOR_INTERFACES")
    if env_ifaces:
        return parse_list(env_ifaces)
    return [INTERFACE] if INTERFACE else None


def _ip_in_any(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, networks: list[str] | Any
) -> bool:
    for network in networks:
        try:
            if ip in ipaddress.ip_network(network, strict=False):
                return True
        except ValueError:
            continue  # a bad entry does not match — the event stays
    return False


def should_ignore_traffic(
    src_port: int | None = None, dst_port: int | None = None, src_ip: str | None = None
) -> bool:
    """Whether to drop the traffic based on the configured filters."""
    if dst_port and dst_port in IGNORE_PORTS:
        return True
    if dst_port and IGNORE_DST_PORT_ABOVE > 0 and dst_port > IGNORE_DST_PORT_ABOVE:
        if dst_port not in ALWAYS_CAPTURE_PORTS:
            return True
    if src_port and IGNORE_SRC_PORT_ABOVE > 0 and src_port > IGNORE_SRC_PORT_ABOVE:
        if src_port not in ALWAYS_CAPTURE_PORTS:
            return True
    if not src_ip:
        return False
    try:
        ip = ipaddress.ip_address(src_ip)
    except ValueError:
        return False
    if IGNORE_LOCAL_SOURCES and _ip_in_any(ip, IGNORE_LOCAL_SOURCES):
        return True
    # One source, one port: checked last and only as an exact pair, so the same host stays
    # visible on every other port (see parse_src_host_ports).
    if dst_port and IGNORE_SRC_HOST_PORTS:
        hosts = [host for host, ports in IGNORE_SRC_HOST_PORTS.items() if dst_port in ports]
        if hosts and _ip_in_any(ip, hosts):
            return True
    return False


def get_port_filter_sql(column: str = "dst_port") -> str:
    """WHERE fragment for the port filter."""
    if IGNORE_DST_PORT_ABOVE > 0:
        capture_list = ",".join(str(p) for p in ALWAYS_CAPTURE_PORTS)
        return f"({column} <= {IGNORE_DST_PORT_ABOVE} OR {column} IN ({capture_list}))"
    return "TRUE"


# ---------------------------------------------------------------------------
# CIRCL Vulnerability-Lookup (Idea 32)
# ---------------------------------------------------------------------------

CIRCL_INTEGRATION: dict[str, Any] = {
    "enabled": env("CIRCL_ENABLED", True, cast=bool),
    "base_url": "https://vulnerability.circl.lu/api",
    "cache_db": str(SENSOR_HOME / "data" / "circl_cache.db"),
    "cve_cache_ttl_hours": 24,
    "kev_cache_ttl_hours": 6,
    "max_requests_per_sec": 2,
    "auto_enrich_on_ai": True,
    "kev_escalate": True,
    "ics_vendor_watch": [
        "siemens",
        "schneider_electric",
        "abb",
        "rockwell_automation",
        "honeywell",
        "nozominetworks",
        "moxa",
        "phoenix_contact",
        "wago",
    ],
    "ics_check_interval_hours": 6,
}

# ICS protocol → vendor product keywords, for cross-referencing
ICS_PROTOCOL_VENDORS = {
    "s7comm": ["siemens"],
    "modbus": ["schneider_electric", "siemens", "wago", "moxa", "phoenix_contact"],
    "opcua": ["siemens", "rockwell_automation", "abb", "honeywell"],
    "iec104": ["abb", "siemens"],
    "bacnet": ["honeywell", "siemens", "schneider_electric"],
    "enip": ["rockwell_automation", "honeywell"],
    "dnp3": ["schneider_electric", "abb"],
    "mqtt": ["moxa", "siemens"],
}

# ---------------------------------------------------------------------------
# Plugins
# ---------------------------------------------------------------------------
# Explicit list of plugin names loaded at sensor-api startup. Each entry is a package
# honeylens_<name> on sys.path (e.g. pip install honeylens-ja4-plus). Empty list =
# plain OSS HoneyLens.
ENABLED_PLUGINS: list[str] = env("ENABLED_PLUGINS", "", cast=parse_list)

# ---------------------------------------------------------------------------
# SIEM forwarders
# ---------------------------------------------------------------------------
# Every enabled forwarder pushes every classified sensor_events row to an external SIEM
# (syslog / Wazuh / Loki / Splunk / Elastic / webhook). Per-type schemas live in
# honeylens/siem/<type>.py. Credentials from ENV (the *_env keys name the variable NAMES)
# — never raw secrets in the configuration. Source: SIEM_FORWARDERS_JSON (a JSON list of
# dicts); empty = no forwarding, the sensor writes only to the local database.


def parse_siem_config(raw: str) -> list[dict[str, Any]]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return parsed if isinstance(parsed, list) else []


SIEM_FORWARDERS: list[dict[str, Any]] = env("SIEM_FORWARDERS_JSON", "", cast=parse_siem_config)

# Logical sensor name — appears in forwarded events. Defaults to the OS hostname.
SENSOR_HOSTNAME: str = env("SENSOR_HOSTNAME", socket.gethostname())
