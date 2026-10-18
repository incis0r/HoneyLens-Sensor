#!/usr/bin/env python3
"""
honeypot_paloalto_ssh.py — PAN-OS SSH CLI Honeypot (Phase D)
==============================================================
Interactive SSH server mimicking the PAN-OS CLI shell.

Supports:
- PAN-OS operational mode prompt (admin@PA-850>)
- Configuration mode (admin@PA-850#)
- show system info, show running security-policy, show interface all,
  show session info, show session all
- configure, set, delete, commit, request system restart
- Command history tracking per session
- Credential capture

Default port: 2200
Requires: asyncssh

Usage:
    python honeypots/honeypot_paloalto_ssh.py
    python honeypots/honeypot_paloalto_ssh.py --port 2200
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any, TextIO

from honeylens.eventlog_lock import log_lock

try:
    import asyncssh
except ImportError:
    print("ERROR: asyncssh required. Install with: pip install asyncssh")
    sys.exit(1)

# =============================================================================
# Configuration
# =============================================================================

DATA_DIR = os.environ.get("PANOS_DATA_DIR", "/opt/sensor/data/paloalto")
IDENTITY_DIR = os.path.join(DATA_DIR, "identity")
TLS_DIR = os.path.join(DATA_DIR, "tls")
TEMPLATE_DIR = os.path.join(DATA_DIR, "templates")

DEFAULT_PORT = 2200
DEFAULT_LOG_FILE = "/var/log/honeypot_paloalto_ssh.json"

LOG_FILE = os.environ.get("PALOALTO_SSH_LOG_FILE", DEFAULT_LOG_FILE)
LISTEN_HOST = "0.0.0.0"

# The SSH identification string, which a client reads BEFORE authenticating.
#
# asyncssh defaults to advertising "AsyncSSH_<version>", so the decoy announced itself as a
# Python SSH library on the very first banner grab — one `ssh-keyscan` and the PAN-OS
# persona behind it was worthless. Real PAN-OS runs a (vendor-customised) OpenSSH, so the
# string has to be OpenSSH-shaped.
#
# Palo Alto does not publish the exact build string and it moves between releases, so this
# default is a plausible shape rather than a verified capture: override it from a device you
# can actually observe. It is read from the process environment because this decoy runs in a
# container and takes its settings from the quadlet, not from the host's .env — the same
# reason PANOS_DATA_DIR is not an .env key.
#
# asyncssh prepends "SSH-2.0-" itself, so a prefix given here is stripped; that mirrors how
# hp_ssh.py normalises HP_SSH_BANNER.
DEFAULT_SSH_BANNER = "OpenSSH_8.0"


def _ssh_banner() -> str:
    """The ``server_version`` to hand asyncssh: no ``SSH-2.0-`` prefix, ASCII only."""
    raw = (os.environ.get("PALOALTO_SSH_BANNER") or DEFAULT_SSH_BANNER).strip()
    if raw.upper().startswith("SSH-2.0-"):
        raw = raw[len("SSH-2.0-") :]
    # A non-ASCII or control character here makes asyncssh refuse to start, which would
    # turn a cosmetic setting into the kind of crash loop this decoy just came out of.
    if not raw or not all(32 <= ord(c) < 127 for c in raw):
        logger.warning("PALOALTO_SSH_BANNER is not printable ASCII — using the default")
        return DEFAULT_SSH_BANNER
    return raw


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("paloalto-ssh")


# =============================================================================
# Identity loader (shared with main honeypot)
# =============================================================================


def _load_identity() -> dict:
    identity = {
        "serial": "015101005200",
        "model": "PA-850",
        "hostname": "PA-850",
        "mac": "00:1b:17:aa:bb:cc",
        "sw_version": "11.1.4",
    }
    try:
        for field in ("serial", "model", "hostname", "mac"):
            path = os.path.join(IDENTITY_DIR, field)
            if os.path.isfile(path):
                with open(path) as f:
                    identity[field] = f.read().strip()
        ver_path = os.path.join(IDENTITY_DIR, "version.json")
        if os.path.isfile(ver_path):
            with open(ver_path) as f:
                vdata = json.load(f)
                identity["sw_version"] = vdata.get("sw_version", "11.1.4")
    except Exception as e:
        logger.debug("Identity load fallback: %s", e)
    return identity


def _load_template(name: str) -> str:
    path = os.path.join(TEMPLATE_DIR, name)
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return f"(template {name} not found)"


IDENTITY = _load_identity()


# =============================================================================
# Event logger
# =============================================================================

_log_file: TextIO | None = None


def _ensure_log():
    global _log_file
    if _log_file is not None:
        return
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    except (OSError, ValueError) as exc:  # silent: log dir may already exist or path is invalid
        logging.getLogger(__name__).debug("ignored: %s", exc)
    try:
        _log_file = open(LOG_FILE, "a", buffering=1)
    except OSError as e:
        logger.debug("Cannot open log file %s: %s, using stdout", LOG_FILE, e)
        _log_file = sys.stdout


def log_event(event_type: str, data: dict[str, Any], src_ip: str = "unknown", src_port: int = 0):
    _ensure_log()
    event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "honeypot": "paloalto_ssh",
        "event_type": event_type,
        "src_ip": src_ip,
        "src_port": src_port,
        "data": data,
    }
    try:
        if _log_file is not None:
            with log_lock(LOG_FILE):
                _log_file.write(json.dumps(event) + "\n")
                _log_file.flush()
    except OSError as e:
        logger.debug("Log write failed: %s", e)
    logger.info("[%s] %s:%d %s", event_type, src_ip, src_port, json.dumps(data)[:200])


# =============================================================================
# PAN-OS CLI Session Handler
# =============================================================================


class PanosShellSession:
    """Interactive PAN-OS CLI session for one SSH connection."""

    def __init__(self, username: str, src_ip: str, src_port: int):
        self.username = username
        self.src_ip = src_ip
        self.src_port = src_port
        self.hostname = IDENTITY["hostname"]
        self.model = IDENTITY["model"]
        self.config_mode = False
        self.command_history: list[str] = []
        self.start_time = time.time()

    @property
    def prompt(self) -> str:
        if self.config_mode:
            return f"{self.username}@{self.hostname}# "
        return f"{self.username}@{self.hostname}> "

    def handle_command(self, cmd: str) -> str | None:
        """Process a PAN-OS CLI command and return the response."""
        cmd = cmd.strip()
        if not cmd:
            return ""

        self.command_history.append(cmd)
        cmd_lower = cmd.lower()

        # Configuration mode commands
        if self.config_mode:
            return self._handle_config_command(cmd, cmd_lower)

        # Operational mode commands
        if cmd_lower == "configure":
            return self._cmd_configure()
        elif cmd_lower.startswith("show system info"):
            return self._cmd_show_system_info()
        elif cmd_lower.startswith("show running security-policy"):
            return self._cmd_show_security_policy()
        elif cmd_lower.startswith("show running nat-policy"):
            return self._cmd_show_nat_policy()
        elif cmd_lower.startswith("show session info"):
            return self._cmd_show_session_info()
        elif cmd_lower.startswith("show session all"):
            return self._cmd_show_session_all()
        elif cmd_lower.startswith("show interface"):
            return self._cmd_show_interface()
        elif cmd_lower.startswith("show system disk-space"):
            return self._cmd_show_disk_space()
        elif cmd_lower.startswith("show system resources"):
            return self._cmd_show_resources()
        elif cmd_lower.startswith("show"):
            return self._cmd_show_generic(cmd)
        elif cmd_lower.startswith("request system restart"):
            return self._cmd_request_restart()
        elif cmd_lower.startswith("request"):
            return self._cmd_request_generic(cmd)
        elif cmd_lower.startswith("debug"):
            return self._cmd_debug(cmd)
        elif cmd_lower in ("exit", "quit"):
            return None  # Signal disconnect
        elif cmd_lower == "?":
            return self._cmd_help()
        else:
            log_event(
                "SSH_UNKNOWN_CMD",
                {
                    "command": cmd[:500],
                    "mode": "config" if self.config_mode else "operational",
                },
                self.src_ip,
                self.src_port,
            )
            return f"Unknown command: {cmd}\n"

    def _handle_config_command(self, cmd: str, cmd_lower: str) -> str | None:
        """Handle commands in configuration mode."""
        if cmd_lower in ("exit", "quit"):
            self.config_mode = False
            log_event("SSH_CONFIG_EXIT", {}, self.src_ip, self.src_port)
            return "Exiting configuration mode\n"
        elif cmd_lower.startswith("set "):
            log_event(
                "SSH_CONFIG_SET",
                {
                    "command": cmd[:500],
                    "severity": "CRITICAL",
                },
                self.src_ip,
                self.src_port,
            )
            return ""  # Silent success like real PAN-OS
        elif cmd_lower.startswith("delete "):
            log_event(
                "SSH_CONFIG_DELETE",
                {
                    "command": cmd[:500],
                    "severity": "CRITICAL",
                },
                self.src_ip,
                self.src_port,
            )
            return ""
        elif cmd_lower.startswith("edit "):
            log_event(
                "SSH_CONFIG_EDIT",
                {
                    "command": cmd[:500],
                    "severity": "HIGH",
                },
                self.src_ip,
                self.src_port,
            )
            return ""
        elif cmd_lower == "commit":
            log_event(
                "SSH_COMMIT",
                {
                    "severity": "CRITICAL",
                },
                self.src_ip,
                self.src_port,
            )
            return "Commit job 42 is in progress. Use Ctrl+C to return to command prompt\n..55%...75%...98%...100%\nConfiguration committed successfully\n"
        elif cmd_lower.startswith("show"):
            return self.handle_command(cmd)  # Allow show in config mode
        elif cmd_lower == "top":
            return ""  # Navigate to top of config hierarchy
        elif cmd_lower == "up":
            return ""  # Navigate up one level
        else:
            log_event(
                "SSH_CONFIG_CMD",
                {
                    "command": cmd[:500],
                },
                self.src_ip,
                self.src_port,
            )
            return f"Unknown command: {cmd}\n"

    # =========================================================================
    # Operational Commands
    # =========================================================================

    def _cmd_configure(self) -> str:
        self.config_mode = True
        log_event(
            "SSH_CONFIG_ENTER",
            {
                "severity": "HIGH",
            },
            self.src_ip,
            self.src_port,
        )
        return "Entering configuration mode\n[edit]\n"

    def _cmd_show_system_info(self) -> str:
        log_event("SSH_SHOW_SYSINFO", {}, self.src_ip, self.src_port)
        return _load_template("show_system_info.txt") + "\n"

    def _cmd_show_security_policy(self) -> str:
        log_event("SSH_SHOW_POLICY", {}, self.src_ip, self.src_port)
        return _load_template("show_security_policy.txt") + "\n"

    def _cmd_show_nat_policy(self) -> str:
        log_event("SSH_SHOW_NAT", {}, self.src_ip, self.src_port)
        return """"NAT-outbound" {
        from trust;
        source any;
        to untrust;
        to-interface ethernet1/1;
        destination any;
        service any;
        translate-to source dynamic-ip-and-port interface-address ethernet1/1;
}
"""

    def _cmd_show_session_info(self) -> str:
        log_event("SSH_SHOW_SESSION_INFO", {}, self.src_ip, self.src_port)
        return """Number of sessions supported:          262142
Number of active sessions:             1847
Number of active TCP sessions:         1530
Number of active UDP sessions:         312
Number of active ICMP sessions:        5
Number of active BCAST sessions:       0
Number of active MCAST sessions:       0
Number of predict sessions:            0
Number of active GTP-U tunnels:        0
Number of active GTP-C tunnels:        0
Number of active SCTP associations:    0
Number of installed sessions:          1847
Number of sessions in discard state:   3
Packet rate:                           2147/s
Throughput:                            12 kbps
New connection rate:                   43 cps
"""

    def _cmd_show_session_all(self) -> str:
        log_event("SSH_SHOW_SESSION_ALL", {}, self.src_ip, self.src_port)
        return """ID         Application     State      Type  Flag  Src[Sport]/Zone/Proto        Dst[Dport]
--------   -----------     ------     ----  ----  ----------------------       ----------
12847      dns             ACTIVE     FLOW  NS    10.0.1.55[43821]/trust/17    8.8.8.8[53]
12903      web-browsing    ACTIVE     FLOW  NS    10.0.1.112[58432]/trust/6    142.250.80.46[80]
13012      ssl             ACTIVE     FLOW  NS    10.0.1.112[58433]/trust/6    142.250.80.46[443]
13156      ntp             ACTIVE     FLOW  NS    10.0.0.1[123]/trust/17       129.6.15.28[123]
13298      ping            ACTIVE     FLOW  NS    10.0.1.55[0]/trust/1         1.1.1.1[0]
"""

    def _cmd_show_interface(self) -> str:
        log_event("SSH_SHOW_INTERFACE", {}, self.src_ip, self.src_port)
        return _load_template("show_interface_all.txt") + "\n"

    def _cmd_show_disk_space(self) -> str:
        log_event("SSH_SHOW_DISK", {}, self.src_ip, self.src_port)
        return """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda2       7.8G  3.2G  4.2G  44% /
/dev/sda3        12G  1.9G  9.1G  18% /opt/pancfg
/dev/sda5       3.9G   89M  3.6G   3% /opt/panrepo
/dev/sda6       3.9G  531M  3.2G  15% /opt/panlogs
tmpfs           3.9G  8.0K  3.9G   1% /dev/shm
"""

    def _cmd_show_resources(self) -> str:
        log_event("SSH_SHOW_RESOURCES", {}, self.src_ip, self.src_port)
        return """load average: 0.42, 0.38, 0.35

%Cpu(s):  3.2 us,  1.1 sy,  0.0 ni, 95.2 id,  0.3 wa,  0.0 hi,  0.2 si,  0.0 st
KiB Mem :  8052388 total,  1243892 free,  3812456 used,  2996040 buff/cache
KiB Swap:        0 total,        0 free,        0 used.  3987612 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
 1823 root      20   0 1842692 287240  42108 S   4.3  3.6  68:42.31 pan_task
 1287 root      20   0  912348  89424  12892 S   1.2  1.1  23:15.07 mgmtsrvr
 2156 root      20   0  452896  45208   8932 S   0.8  0.6  12:08.44 logrcvr
 1892 root      20   0  389204  38940   7284 S   0.3  0.5   8:42.18 devsrvr
"""

    def _cmd_show_generic(self, cmd: str) -> str:
        log_event("SSH_SHOW_CMD", {"command": cmd[:500]}, self.src_ip, self.src_port)
        return f'% Unknown command "{cmd}"\n'

    def _cmd_request_restart(self) -> str:
        log_event(
            "SSH_REBOOT_ATTEMPT",
            {
                "severity": "CRITICAL",
            },
            self.src_ip,
            self.src_port,
        )
        return "Stopping services...\nStopping management server...\n"

    def _cmd_request_generic(self, cmd: str) -> str:
        log_event(
            "SSH_REQUEST_CMD",
            {
                "command": cmd[:500],
                "severity": "HIGH",
            },
            self.src_ip,
            self.src_port,
        )
        return ""

    def _cmd_debug(self, cmd: str) -> str:
        log_event(
            "SSH_DEBUG_CMD",
            {
                "command": cmd[:500],
                "severity": "HIGH",
            },
            self.src_ip,
            self.src_port,
        )
        return ""

    def _cmd_help(self) -> str:
        return """  configure        Enter configuration mode
  debug            Debug and diagnose
  exit             Exit operational mode
  less             View log/config file
  ping             Utility ping
  request          Make system-level requests
  set              Set operational parameters
  show             Show operational data
  scp              Copy files
  ssh              Remote SSH to another host
  tail             View end of log file
  test             Run diagnostics
  traceroute       Trace route to host
"""


# =============================================================================
# SSH Server
# =============================================================================


class PanosSSHServer(asyncssh.SSHServer):
    """SSH server that accepts all passwords and logs credentials."""

    def __init__(self):
        self._conn = None

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        self._conn = conn
        peername = conn.get_extra_info("peername")
        src_ip = peername[0] if peername else "unknown"
        src_port = peername[1] if peername else 0
        logger.info("SSH connection from %s:%d", src_ip, src_port)

    def connection_lost(self, exc):
        pass  # silent: connection cleanup

    def begin_auth(self, username: str) -> bool:
        return True  # Require auth

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        peername = self._conn.get_extra_info("peername") if self._conn else None
        src_ip = peername[0] if peername else "unknown"
        src_port = peername[1] if peername else 0

        is_default = username == "admin" and password == "admin"
        log_event(
            "SSH_LOGIN",
            {
                "username": username[:100],
                "password": password[:200],
                "default_creds": is_default,
                "severity": "HIGH" if is_default else "MEDIUM",
            },
            src_ip,
            src_port,
        )

        return True  # Accept all credentials


async def handle_ssh_session(process: asyncssh.SSHServerProcess):
    """Handle an interactive SSH session with PAN-OS CLI."""
    peername = process.get_extra_info("peername")
    src_ip = peername[0] if peername else "unknown"
    src_port = peername[1] if peername else 0
    username = process.get_extra_info("username") or "admin"

    session = PanosShellSession(username, src_ip, src_port)

    log_event(
        "SSH_SESSION_START",
        {
            "username": username,
        },
        src_ip,
        src_port,
    )

    # Send welcome banner
    process.stdout.write(f"\nWelcome to Palo Alto Networks {IDENTITY['model']}\n")
    process.stdout.write(f"Software version: PAN-OS {IDENTITY['sw_version']}\n\n")

    try:
        while True:
            process.stdout.write(session.prompt)
            try:
                line = await asyncio.wait_for(process.stdin.readline(), timeout=300)
            except TimeoutError:
                process.stdout.write("\nSession timed out.\n")
                break

            if not line:
                break

            cmd = line.rstrip("\n\r")
            response = session.handle_command(cmd)

            if response is None:
                # exit/quit
                process.stdout.write("Connection closed.\n")
                break

            if response:
                process.stdout.write(response)

    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
        pass  # silent: connection cleanup
    except Exception as e:
        logger.debug("SSH session error from %s:%d: %s", src_ip, src_port, e)

    log_event(
        "SSH_SESSION_END",
        {
            "username": username,
            "duration_sec": round(time.time() - session.start_time, 1),
            "commands": len(session.command_history),
            "command_history": session.command_history[:50],
        },
        src_ip,
        src_port,
    )

    process.exit(0)


async def start_server(host: str, port: int):
    """Start the PAN-OS SSH honeypot."""
    ssh_key = os.path.join(TLS_DIR, "ssh_host_rsa_key")

    if not os.path.exists(ssh_key):  # noqa: ASYNC240 — a single stat, not worth a thread
        logger.error("SSH host key not found: %s", ssh_key)
        logger.error("Run: scripts/init_paloalto_honeypot.sh")
        sys.exit(1)

    banner = _ssh_banner()
    await asyncssh.create_server(
        PanosSSHServer,
        host,
        port,
        server_host_keys=[ssh_key],
        process_factory=handle_ssh_session,
        server_version=banner,
    )

    logger.info("PAN-OS SSH honeypot listening on %s:%d", host, port)
    logger.info("  Identification string: SSH-2.0-%s", banner)
    logger.info(
        "  Model: %s  Hostname: %s  Version: %s",
        IDENTITY["model"],
        IDENTITY["hostname"],
        IDENTITY["sw_version"],
    )

    await asyncio.Event().wait()


def main():
    parser = argparse.ArgumentParser(description="Palo Alto PAN-OS SSH CLI Honeypot (Phase D)")
    parser.add_argument("--host", default=LISTEN_HOST, help="Bind address")
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help="SSH listen port (default: 2200)"
    )
    args = parser.parse_args()

    asyncio.run(start_server(args.host, args.port))


if __name__ == "__main__":
    main()
