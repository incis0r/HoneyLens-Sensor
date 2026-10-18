"""Honeypot manifest: the single source of truth about what is a honeypot and how to run it.

From this one file follow: the ``honeylens-hp <name>`` command (``cli.py``), the
``honeylens/hp-<name>`` image (``containers/honeypot/Containerfile`` with ``ARG HONEYPOT``),
the ``hp-<name>.container`` quadlet (generator in ``cli.py``) and the list of firewalld
forwards. In 0.9 the same information was scattered across 41 systemd units and each
sensor's ``.env`` file — every honeypot took its port, certificate and identity directory
from somewhere else.

Rules:

- **No root, so no ports < 1024.** The process in the container is the ``honeylens`` user
  (uid 1000, ``UserNS=keep-id`` — the same uid as the host user, so files on the volumes
  belong to it), with no privileges at all. A protocol port ≥ 1024 the honeypot binds
  directly; < 1024 it binds as ``30000 + port`` (22 → 30022), the same number is published
  on the host, and firewalld does DNAT from the protocol port. The event carries the
  **protocol port**: ``HONEYLENS_PORT_MAP`` (generated here) translates the bound port back,
  because the classifier and the ICS context look at ``dst_port`` (502, not 30502). The
  monolith has its own ``40000 + port`` block for all ports (``port_block``) so it can stand
  next to the ``hp_*`` honeypots — DNAT decides who gets the traffic. Not ``1<port>``,
  as the decision said: 443 → 10443 collides with FortiGate, and 20000 → 120000 does not
  fit in 16 bits.
- **Identity outside the image.** The certificate (nginx, LLM, FortiGate, monolith), the
  serial number and host key (PAN-OS HTTPS/SSH), the WAGO device file are created on first
  start in the ``identity`` volume and survive a restart and an image update. Honeypots
  without ``identity`` in the manifest (e.g. the banner-only ``hp_ssh``) have nothing to keep.
  A changed serial number is a ready-made honeypot fingerprint. Honeypots that in 0.9 shared
  one device (PAN-OS HTTPS and PAN-OS SSH) share one volume.
- **Logs on a volume shared with the ingest on the host.** The ingest truncates the consumed
  prefix of the file, so the file must be the same on both sides. Vendor-format lines
  (FortiGate, PAN-OS) live in the ``vendor/`` subdirectory so the honeypot ingest's
  ``*.json`` glob does not swallow them — they have their own ingests.
- The container gets **only** the variables from the manifest and ``TZ=UTC``. No sensor
  ``.env``, no database credentials.

Placeholders in ``env``: ``{identity}`` is the identity directory, ``{logs}`` is the log
root — fixed paths (below) in the container, overridable through ``HONEYLENS_IDENTITY_DIR``
and ``HONEYLENS_LOG_ROOT`` when running without a container.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Fixed paths in the container. The log volume is mounted at {logs}, so the default
# HONEYPOTNG_LOG_DIR (/opt/logs/honeypotng) and HONEYWEB_LOG_DIR (/opt/logs/honeyweb) from
# config.py land on it without any variable.
CONTAINER_LOG_ROOT = "/opt/logs"
CONTAINER_IDENTITY_DIR = "/var/lib/honeylens/identity"

BIND_PORT_OFFSET = 30000  # a protocol port < 1024 is bound (and published) as 30000 + port

# Ports that the sensor ITSELF occupies on the sensor host: its PostgreSQL (5432) and
# API/WebUI (60443). A honeypot on such a protocol port binds high as for < 1024 (DNAT
# delivers the traffic), because otherwise it collides with the sensor's own database.
# Measured on a 1.0 sensor: hp-postgres in a restart loop, because 5432 was held by the
# real PostgreSQL 13 — and that is how it is on EVERY sensor 1.0.
HOST_RESERVED_PORTS: frozenset[int] = frozenset({5432, 60443})


def bind_port(port: int, block: int | None = None) -> int:
    """Port bound in the container and published on the host.

    ``block`` moves ALL of a honeypot's ports into a separate block (``block + port``): the
    monolith has 40000+ this way, so as not to collide with the separate ``hp_*`` honeypots
    on the same protocol ports — on the host they run side by side, and DNAT picks which one
    gets the traffic.
    """
    if block is not None:
        return block + port
    if port < 1024 or port in HOST_RESERVED_PORTS:
        return BIND_PORT_OFFSET + port
    return port


@dataclass(frozen=True)
class Honeypot:
    """One honeypot: what to run, what it listens on, what must survive a restart."""

    name: str
    module: str
    entry: str  # class name (BaseHoneypot subclass -> .run()) or function name (main)
    ports: tuple[int, ...]  # PROTOCOL ports (the ones the attacker hits and the database sees)
    udp: bool = False
    identity: str | None = None  # identity volume name; several honeypots may share one
    env: dict[str, str] = field(default_factory=dict)
    # (cert, key, CN) — a pair the launcher generates as self-signed on first start if it
    # does not exist. Only for honeypots that do not do this themselves.
    certs: tuple[tuple[str, str, str], ...] = ()
    port_block: int | None = None  # bind block for all ports (monolith: 40000)
    ttl_profile: str = "linux"  # OS fingerprint profile for eBPF TTL/window spoofing (layer 8)
    note: str = ""
    # Web decoy that carries the fake-vendor WAF canary (deception_waf). The quadlet generator
    # then pins SENSOR_HOSTNAME to this host (so every such decoy presents ONE consistent vendor)
    # and, when WAF_CANARY_ENABLED is set in the generation environment, emits the enable flag
    # and salt. OFF unless that env is set. See docs/deception-waf-canary.md.
    waf_canary: bool = False

    @property
    def transport(self) -> str:
        return "udp" if self.udp else "tcp"

    @property
    def image(self) -> str:
        return f"honeylens/hp-{self.name}"

    @property
    def unit(self) -> str:
        return f"hp-{self.name}"

    @property
    def port_map(self) -> list[tuple[int, int]]:
        """``[(port bound and published on the host, protocol port)]``."""
        return [(bind_port(p, self.port_block), p) for p in self.ports]

    @property
    def runtime_env(self) -> dict[str, str]:
        """Manifest variables plus those that follow from the port mapping.

        ``HONEYLENS_PORT_MAP`` only when something is translated; ``HP_<NAME>_PORT`` for
        BaseHoneypot subclasses (that is how they read the port) — and here the port mapping
        ends in one place, instead of in 41 units.
        """
        out = dict(self.env)
        translated = [(b, p) for b, p in self.port_map if b != p]
        if translated:
            out.setdefault("HONEYLENS_PORT_MAP", ",".join(f"{b}:{p}" for b, p in translated))
            if self.entry[0].isupper():  # BaseHoneypot class: port from HP_<PROTOCOL>_PORT
                out.setdefault(f"HP_{self.name.upper()}_PORT", str(translated[0][0]))
        return out


def _base(
    name: str,
    cls: str,
    port: int,
    *,
    module: str | None = None,
    udp: bool = False,
    ttl: str = "linux",
) -> Honeypot:
    return Honeypot(
        name=name,
        module=module or f"honeylens.honeypots.hp_{name}",
        entry=cls,
        ports=(port,),
        udp=udp,
        ttl_profile=ttl,
    )


_ID = CONTAINER_IDENTITY_DIR
_LOGS = "{logs}"

# Monolith: protocol port -> NG responder hint. Without 8080/8443 from the config.py table:
# in the monolith those two ports belong to Flask (HONEYWEB_PORT/HONEYWEB_TLS_PORT), and in
# 0.9 both bound them at once and Flask died in a daemon thread with "Address already in use".
_MONOLITH_SERVICES = {
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
    9200: "elasticsearch",
    9300: "elasticsearch",
}
_MONOLITH_WEB = {8080: "HONEYWEB_PORT", 8443: "HONEYWEB_TLS_PORT"}
MONOLITH_PORT_BLOCK = 40000
# NetScaler Gateway lives on 443, the same port as llm-tls and the monolith's HTTPS. Its
# own block lets it stand beside them on distinct host ports (bind 50443 / 50080); the host
# DNAT decides which 443 decoy actually fronts external 443.
NETSCALER_PORT_BLOCK = 50000
# On-prem SharePoint is also an HTTP(S) 443/80 appliance; its own block lets it stand beside
# NetScaler (50000) and the other 443 decoys on distinct bind ports (51443 / 51080). The host
# DNAT decides which 443 decoy fronts external 443 — one per sensor.
SHAREPOINT_PORT_BLOCK = 51000

HONEYPOTS: tuple[Honeypot, ...] = (
    # --- family A: BaseHoneypot subclasses (sensor-hp-* units in 0.9) ---
    _base("adb", "ADBHoneypot", 5555),
    _base("afp", "AFPHoneypot", 548),
    _base("bacnet", "BACnetHoneypot", 47808, udp=True, ttl="plc"),
    _base("cassandra", "CassandraHoneypot", 9042),
    _base("dahua", "DahuaHoneypot", 37777),
    _base("dnp3", "DNP3Honeypot", 20000, ttl="plc"),
    _base("elasticsearch", "ElasticsearchHoneypot", 9200),
    _base("enip", "ENIPHoneypot", 44818, ttl="plc"),
    _base("fins", "FinsHoneypot", 9600, ttl="plc"),
    _base("fox", "FoxHoneypot", 1911, module="honeylens.honeypots.ics.fox", ttl="plc"),
    _base("ftp", "FTPHoneypot", 21),
    _base("http", "HTTPHoneypot", 80),
    _base("iec104", "IEC104Honeypot", 2404, ttl="plc"),
    _base("javarmi", "JavaRMIHoneypot", 1099),
    _base("ldap", "LDAPHoneypot", 389, ttl="windows"),
    _base("memcached", "MemcachedHoneypot", 11211),
    _base("modbus", "ModbusHoneypot", 502, ttl="plc"),
    _base("mqtt", "MQTTHoneypot", 1883),
    _base("mysql", "MySQLHoneypot", 3306),
    _base("opcua", "OpcuaHoneypot", 4840, ttl="plc"),
    _base("oracle", "OracleHoneypot", 1521),
    _base("postgres", "PostgresHoneypot", 5432),
    _base(
        "profinet",
        "ProfinetHoneypot",
        34964,
        module="honeylens.honeypots.ics.profinet",
        udp=True,
        ttl="plc",
    ),
    _base("rdp", "RDPHoneypot", 3389, ttl="windows"),
    _base("redis", "RedisHoneypot", 6379),
    _base("rsync", "RsyncHoneypot", 873),
    # 0.9: sensor-hp-s7comm.service runs ics.cotp102, not hp_s7comm (the latter stayed
    # in the tree as its predecessor; PROTOCOL of both is "s7comm").
    _base("s7comm", "Cotp102Honeypot", 102, module="honeylens.honeypots.ics.cotp102", ttl="plc"),
    _base("smb", "SMBHoneypot", 445, ttl="windows"),
    _base("smtp", "SMTPHoneypot", 25),
    _base("ssh", "SSHHoneypot", 22),
    _base("telnet", "TelnetHoneypot", 23),
    _base("vnc", "VNCHoneypot", 5900),
    # --- family A with its own main() ---
    Honeypot(
        name="nginx",
        module="honeylens.honeypots.hp_nginx",
        entry="main",
        ports=(8443, 8000),  # cleartext on 8000: 8080 stays for K8s (Dariusz, 2026-09-20)
        identity="nginx",
        env={
            "HP_NGINX_PORT": "8443",
            "HP_NGINX_HTTP_PORT": "8000",
            "HP_NGINX_CERT": f"{_ID}/nginx.crt",
            "HP_NGINX_KEY": f"{_ID}/nginx.key",
            "HP_NGINX_WINDOW": "120",
        },
        certs=((f"{_ID}/nginx.crt", f"{_ID}/nginx.key", "www.example.com"),),
    ),
    Honeypot(
        name="wago",
        module="honeylens.honeypots.hp_wago",
        entry="main",
        ports=(8090,),
        identity="wago",
        env={"HP_WAGO_PORT": "8090", "WAGO_IDENTITY_DIR": _ID},
    ),
    Honeypot(
        name="llm",
        module="honeylens.honeypots.honeypot_llm",
        entry="main",
        ports=(3080,),
        identity="llm",
        env={"LLM_HONEYPOT_PORT": "3080", "LLM_HONEYPOT_TLS": "false"},
    ),
    # 0.9: sensor-honeypot-llm-tls.service = socat on 443 in front of 3080. In 1.0 the same
    # image terminates TLS itself (uvicorn), on 443, with the certificate from the identity
    # volume.
    Honeypot(
        name="llm-tls",
        module="honeylens.honeypots.honeypot_llm",
        entry="main",
        ports=(443,),
        identity="llm",
        env={
            "LLM_HONEYPOT_PORT": str(bind_port(443)),
            "LLM_HONEYPOT_TLS": "true",
            "LLM_TLS_CERT": f"{_ID}/llm.crt",
            "LLM_TLS_KEY": f"{_ID}/llm.key",
        },
        certs=((f"{_ID}/llm.crt", f"{_ID}/llm.key", "assistant.internal"),),
    ),
    # --- family B: own line format, own files ---
    Honeypot(
        name="k8s",
        module="honeylens.honeypots.honeypot_k8s",
        entry="main",
        # API 6443, insecure API 8080, kubelet 10250/10255, etcd 2379, kubectl proxy 8001,
        # dashboard NodePort 30000 — all from the honeypot's main().
        ports=(6443, 8080, 10250, 10255, 2379, 8001, 30000),
        env={"K8S_HONEYPOT_LOG_FILE": f"{_LOGS}/honeypotng/honeypot_k8s.json"},
        note="certificate generated into a temporary directory on every start (as in 0.9)",
        waf_canary=True,
    ),
    Honeypot(
        name="fortigate",
        module="honeylens.honeypots.honeypot_fortigate",
        entry="main",
        ports=(10443, 20443),
        identity="fortigate",
        env={
            "FORTIGATE_LOG_FILE": f"{_LOGS}/vendor/honeypot_fortigate.json",
            "FORTIGATE_TLS_CERT": f"{_ID}/fortigate.crt",
            "FORTIGATE_TLS_KEY": f"{_ID}/fortigate.key",
        },
        certs=((f"{_ID}/fortigate.crt", f"{_ID}/fortigate.key", "FW-EDGE-01"),),
        waf_canary=True,
    ),
    Honeypot(
        name="paloalto",
        module="honeylens.honeypots.honeypot_paloalto",
        entry="main",
        ports=(4443, 6082, 6080),
        identity="paloalto",
        env={"PANOS_DATA_DIR": _ID, "PALOALTO_LOG_FILE": f"{_LOGS}/vendor/honeypot_paloalto.json"},
        note="run scripts/init_paloalto_honeypot.sh before first start: without "
        "tls/management.{crt,key} in the identity volume this decoy exits 1",
        waf_canary=True,
    ),
    Honeypot(
        name="paloalto-ssh",
        module="honeylens.honeypots.honeypot_paloalto_ssh",
        entry="main",
        ports=(2200,),
        identity="paloalto",  # the same device as PAN-OS HTTPS: shared serial and key
        env={
            "PANOS_DATA_DIR": _ID,
            "PALOALTO_SSH_LOG_FILE": f"{_LOGS}/vendor/honeypot_paloalto_ssh.json",
        },
        note="shares the paloalto identity; needs tls/ssh_host_rsa_key from "
        "scripts/init_paloalto_honeypot.sh or it exits 1",
    ),
    # --- Citrix NetScaler ADC / Gateway: an HTTPS 443 appliance. Own port block so it can
    # stand beside llm-tls and the monolith on 443 (DNAT picks the live 443 decoy). ---
    Honeypot(
        name="netscaler",
        module="honeylens.honeypots.honeypot_netscaler",
        entry="main",
        ports=(443, 80),
        identity="netscaler",
        port_block=NETSCALER_PORT_BLOCK,
        env={
            "NETSCALER_TLS_CERT": f"{_ID}/netscaler.crt",
            "NETSCALER_TLS_KEY": f"{_ID}/netscaler.key",
        },
        # Empty CN: the NetScaler decoy generates its own cert with a per-deployment Gateway
        # hostname (honeypot_netscaler._deployment_hostname), so the CN is not a fleet-wide
        # shared fingerprint. cli.run() skips pre-generation for an empty CN.
        certs=((f"{_ID}/netscaler.crt", f"{_ID}/netscaler.key", ""),),
        note="Citrix NetScaler decoy: full payload capture, tags CVE-2026-88771/19490 and CitrixBleed 1/2",
        waf_canary=True,
    ),
    # --- on-prem Microsoft SharePoint Server: an HTTP(S) 443/80 IIS appliance. Own port block
    # so it stands beside NetScaler and the monolith on 443 (DNAT picks the live 443 decoy).
    # Windows TTL profile — it is a real Windows/IIS box, not a Linux one. ---
    Honeypot(
        name="sharepoint",
        module="honeylens.honeypots.honeypot_sharepoint",
        entry="main",
        ports=(443, 80),
        identity="sharepoint",
        port_block=SHAREPOINT_PORT_BLOCK,
        ttl_profile="windows",
        # SHAREPOINT_LOG_FILE is deliberately NOT set. Unlike the FortiGate and PAN-OS
        # decoys, which write only their own vendor file and need an ingest to read it,
        # this decoy writes through honeypots/sink.py — into HONEYPOTNG_LOG_DIR, which
        # honeylens-ingest-honeypot already consumes and truncates after each commit.
        # Setting the variable here made every deployment ALSO append the identical record
        # to vendor/honeypot_sharepoint.json, and nothing reads, rotates or truncates that
        # file: measured on one sensor at 26 MB and growing, against a database holding the
        # same 16649 events (hourly counts matched exactly, raw bytes included —
        # ingest/honeypot.py decodes raw_hex into full_payload). It was pure disk growth.
        # The decoy guards the write with `if self.log_file:`, so leaving it unset simply
        # disables the duplicate; set it only for standalone runs with no sink.
        env={
            "SHAREPOINT_TLS_CERT": f"{_ID}/sharepoint.crt",
            "SHAREPOINT_TLS_KEY": f"{_ID}/sharepoint.key",
            "SHAREPOINT_DATA_DIR": _ID,
        },
        # Empty CN: the decoy generates its own cert with a per-deployment SharePoint hostname
        # (honeypot_sharepoint._deployment_hostname), so the CN is not a fleet-wide fingerprint.
        certs=((f"{_ID}/sharepoint.crt", f"{_ID}/sharepoint.key", ""),),
        note="SharePoint decoy: anonymous exploit surfaces, MachineKey honeytoken, tags ToolShell CVE-2025-53770/53771 + CVE-2023-29357",
        waf_canary=True,
    ),
    # --- monolith: one process, many ports; stays one container (decision 6) ---
    Honeypot(
        name="honeypot",
        module="honeylens.honeypots.honeypot",
        entry="main",
        ports=(*_MONOLITH_SERVICES, *_MONOLITH_WEB),
        identity="honeypot",
        port_block=MONOLITH_PORT_BLOCK,
        env={
            "TLS_CERT_DIR": _ID,
            **{var: str(MONOLITH_PORT_BLOCK + p) for p, var in _MONOLITH_WEB.items()},
            "HONEYPOTNG_SERVICES": ",".join(
                f"{MONOLITH_PORT_BLOCK + p}:{hint}" for p, hint in _MONOLITH_SERVICES.items()
            ),
        },
        note="0.9: sensor-honeypot.service as root with CAP_NET_RAW (unused: no SOCK_RAW in the code); generates its own certificate (openssl)",
    ),
)

BY_NAME: dict[str, Honeypot] = {hp.name: hp for hp in HONEYPOTS}


def get(name: str) -> Honeypot:
    try:
        return BY_NAME[name]
    except KeyError:
        known = ", ".join(sorted(BY_NAME))
        raise KeyError(f"unknown honeypot {name!r}; known: {known}") from None
