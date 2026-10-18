#!/usr/bin/env python3
"""
device_profiler.py — Device Profiler for Custom Honeypot Generation
====================================================================
Scans a real device on the network, captures banners, web UI, TLS certs,
and response patterns. Produces a device profile JSON that can be used
to generate a high-fidelity honeypot.

Idea 33 — the device-profiler honeypot idea from the 0.9 backlog

Usage:
    python device_profiler.py --target 192.0.2.254 --name netgear-switch
    python device_profiler.py --target 192.0.2.1 --name tplink-router --ports 80,443,22
    python device_profiler.py --target 192.0.2.78 --name librenms --ports 80
    python device_profiler.py --list-profiles

Output: /opt/sensor/custom_honeypots/{name}.json
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
except ImportError:
    print("ERROR: pip install requests", file=sys.stderr)
    sys.exit(2)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("device-profiler")

PROFILE_DIR = os.environ.get(
    "HONEYPOT_PROFILE_DIR",
    "/opt/sensor/custom_honeypots" if os.path.isdir("/opt/sensor") else "./custom_honeypots",
)

DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    102,
    161,
    443,
    445,
    502,
    548,
    873,
    1080,
    1099,
    1433,
    1521,
    1883,
    2222,
    3306,
    3389,
    4840,
    5432,
    5555,
    5900,
    6443,
    8080,
    8443,
    8883,
    9000,
    9042,
    9200,
    10443,
    20443,
    30000,
    37777,
    44818,
    47808,
    60443,
]

BANNER_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    11211: "Memcached",
    27017: "MongoDB",
}

# Max size for static assets (prevent downloading huge files)
MAX_ASSET_SIZE = 512 * 1024  # 512KB
MAX_PAGE_SIZE = 1024 * 1024  # 1MB


def tcp_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if TCP port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except (TimeoutError, ConnectionRefusedError, OSError):
        return False


def grab_banner(host: str, port: int, timeout: float = 5.0) -> str | None:
    """Grab service banner from a TCP port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        # Some services need a probe
        if port in (80, 8080, 8443, 443):
            return None  # HTTP handled separately

        # Send probe for specific protocols
        if port == 21:  # FTP
            pass  # Server sends banner first
        elif port == 25:  # SMTP
            pass
        elif port == 23:  # Telnet
            pass
        elif port == 3306:  # MySQL
            pass

        banner = s.recv(1024)
        s.close()
        return banner.decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def get_tls_info(host: str, port: int, timeout: float = 5.0) -> dict | None:
    """Get TLS certificate and protocol info."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                version = ssock.version()

                # Parse cert if available
                cert_info = {}
                if cert:
                    _subject = cert.get("subject") or ()
                    _issuer = cert.get("issuer") or ()
                    cert_info = {
                        "subject": dict(x[0] for x in _subject),  # type: ignore[misc]
                        "issuer": dict(x[0] for x in _issuer),  # type: ignore[misc]
                        "serial": cert.get("serialNumber", ""),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "san": [x[1] for x in cert.get("subjectAltName", ())],
                    }

                return {
                    "protocol": version,
                    "cipher": cipher[0] if cipher else None,
                    "cert": cert_info,
                }
    except Exception:
        return None


def get_tcp_fingerprint(host: str, port: int, timeout: float = 5.0) -> dict | None:
    """Get TCP fingerprint — TTL, window size, MSS, DF bit, TCP options.

    Connects to an open port and analyses the SYN-ACK response to extract
    OS-level network parameters. These are used by the eBPF TTL deception
    system (Idea 16) to make the honeypot match the real device's fingerprint.
    """
    result: dict[str, Any] = {
        "ttl": None,
        "tcp_window": None,
        "mss": None,
        "df_bit": None,
        "tcp_options": [],
        "os_guess": "unknown",
    }

    # Method 1: Use raw socket to observe SYN-ACK (requires root)
    try:
        import scapy.all as scapy

        pkt = scapy.IP(dst=host) / scapy.TCP(dport=port, flags="S")
        resp = scapy.sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(scapy.TCP):
            result["ttl"] = resp.ttl
            result["tcp_window"] = resp[scapy.TCP].window
            result["df_bit"] = bool(resp[scapy.IP].flags.DF)
            # Extract TCP options
            for opt_name, opt_val in resp[scapy.TCP].options:
                if opt_name == "MSS":
                    result["mss"] = opt_val
                result["tcp_options"].append(opt_name)
            # OS guess from TTL
            result["os_guess"] = _guess_os_from_ttl(resp.ttl, resp[scapy.TCP].window)
            logger.info(
                "  TCP fingerprint (scapy): TTL=%s window=%s MSS=%s DF=%s → %s",
                result["ttl"],
                result["tcp_window"],
                result["mss"],
                result["df_bit"],
                result["os_guess"],
            )
            return result
    except (
        ImportError
    ) as _exc:  # silent: scapy not installed, fall through to ping-based fingerprinting
        logging.getLogger(__name__).debug("ignored: %s", _exc)
    except Exception as e:
        logger.debug("Scapy fingerprint failed: %s", e)

    # Method 2: Use ping for TTL + connect for window (no root needed)
    try:
        # Get TTL from ping
        ping_out = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(timeout)), host],
            capture_output=True,
            text=True,
            timeout=timeout + 1,
        )
        if ping_out.returncode == 0:
            m = re.search(r"ttl=(\d+)", ping_out.stdout, re.IGNORECASE)
            if m:
                result["ttl"] = int(m.group(1))

        # Get TCP window from ss/netstat after connecting
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        # Try to read window size from /proc (Linux only)
        try:
            local_port = s.getsockname()[1]
            ss_out = subprocess.run(
                ["ss", "-ti", f"sport = :{local_port}"], capture_output=True, text=True, timeout=3
            )
            if ss_out.returncode == 0:
                # Parse window from ss output
                wm = re.search(r"rcv_space:(\d+)", ss_out.stdout)
                if wm:
                    result["tcp_window"] = int(wm.group(1))
                mm = re.search(r"mss:(\d+)", ss_out.stdout)
                if mm:
                    result["mss"] = int(mm.group(1))
        except (
            Exception
        ) as _exc:  # silent: ss(8) not available or socket closed, skip window/MSS fields
            logging.getLogger(__name__).debug("ignored: %s", _exc)

        s.close()

        if result["ttl"]:
            result["os_guess"] = _guess_os_from_ttl(result["ttl"], result.get("tcp_window"))
            logger.info(
                "  TCP fingerprint (ping+ss): TTL=%s window=%s MSS=%s → %s",
                result["ttl"],
                result["tcp_window"],
                result["mss"],
                result["os_guess"],
            )
        return result

    except Exception as e:
        logger.debug("TCP fingerprint fallback failed: %s", e)

    return result


def _guess_os_from_ttl(ttl: int, window: int | None = None) -> str:
    """Guess OS family from TTL and TCP window size."""
    if ttl is None:
        return "unknown"

    # TTL ranges (initial TTL minus hops)
    if ttl <= 64:
        os_guess = "Linux/Unix"  # Default TTL 64
        if window:
            if window == 65535:
                os_guess = "macOS/FreeBSD"
            elif window == 29200:
                os_guess = "Linux (modern)"
            elif window == 5840:
                os_guess = "Linux (older)"
            elif window == 14600:
                os_guess = "Linux (default)"
    elif ttl <= 128:
        os_guess = "Windows"  # Default TTL 128
        if window:
            if window == 65535:
                os_guess = "Windows 10/11"
            elif window == 64240:
                os_guess = "Windows Server 2019+"
            elif window == 8192:
                os_guess = "Windows XP/2003"
    elif ttl <= 255:
        os_guess = "Network device"  # Cisco, Solaris use 255
        if window:
            if window == 4128:
                os_guess = "Cisco IOS"
            elif window == 16384:
                os_guess = "Solaris"
    else:
        os_guess = "unknown"

    return os_guess


def crawl_web_ui(
    host: str, port: int, use_https: bool = False, max_pages: int = 20, timeout: float = 10.0
) -> dict:
    """Crawl device web UI — capture pages, headers, assets."""
    scheme = "https" if use_https else "http"
    base_url = f"{scheme}://{host}:{port}"
    session = requests.Session()
    session.verify = False
    # requests.Session has no .timeout — we pass timeout on every get() below.
    session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    result: dict[str, Any] = {
        "base_url": base_url,
        "pages": {},
        "headers": {},
        "redirects": [],
        "static_assets": {},
        "login_form": None,
        "favicon": None,
        "title": None,
        "server": None,
        "technologies": [],
    }

    # Initial request
    try:
        resp = session.get(base_url, allow_redirects=True, timeout=timeout)
    except Exception as e:
        logger.warning("Web UI unreachable at %s: %s", base_url, e)
        return result

    # Capture response
    result["headers"] = dict(resp.headers)
    result["server"] = resp.headers.get("Server", "")
    result["pages"]["/"] = {
        "status": resp.status_code,
        "content_type": resp.headers.get("Content-Type", ""),
        "body": resp.text[:MAX_PAGE_SIZE],
        "size": len(resp.content),
    }

    # Track redirects
    if resp.history:
        for r in resp.history:
            result["redirects"].append(
                {
                    "from": r.url,
                    "to": r.headers.get("Location", ""),
                    "status": r.status_code,
                }
            )

    # Parse HTML
    html_content = resp.text
    _parse_html(html_content, result, base_url)

    # Detect login form
    if _has_login_form(html_content):
        result["login_form"] = {
            "url": resp.url,
            "method": "POST",
            "fields": _extract_form_fields(html_content),
        }

    # Crawl common paths
    common_paths = [
        "/login",
        "/login.html",
        "/Login.htm",
        "/index.htm",
        "/favicon.ico",
        "/robots.txt",
        "/api/",
        "/api/v1/",
        "/api/v2/",
        "/cgi-bin/",
        "/admin/",
        "/manage/",
        "/.well-known/security.txt",
    ]

    visited = {"/"}
    for path in common_paths:
        if len(visited) >= max_pages:
            break
        if path in visited:
            continue
        visited.add(path)

        try:
            url = urljoin(base_url, path)
            r = session.get(url, allow_redirects=False, timeout=5)
            if r.status_code < 500:
                result["pages"][path] = {
                    "status": r.status_code,
                    "content_type": r.headers.get("Content-Type", ""),
                    "body": r.text[:MAX_PAGE_SIZE] if r.status_code == 200 else "",
                    "size": len(r.content),
                    "headers": dict(r.headers),
                }
        except (
            Exception
        ) as _exc:  # silent: probe of this path failed, skip and continue with the next
            logging.getLogger(__name__).debug("ignored: %s", _exc)

    # Download favicon
    try:
        fav_url = urljoin(base_url, "/favicon.ico")
        r = session.get(fav_url, timeout=5)
        if r.status_code == 200 and len(r.content) < MAX_ASSET_SIZE:
            result["favicon"] = base64.b64encode(r.content).decode("ascii")
    except Exception as _exc:  # silent: favicon fetch is best-effort enrichment, not required
        logging.getLogger(__name__).debug("ignored: %s", _exc)

    # Extract referenced static assets (CSS, JS, images)
    for asset_url in _extract_asset_urls(html_content, base_url):
        if len(result["static_assets"]) >= 15:
            break
        try:
            r = session.get(asset_url, timeout=5)
            if r.status_code == 200 and len(r.content) < MAX_ASSET_SIZE:
                path = urlparse(asset_url).path
                result["static_assets"][path] = {
                    "content_type": r.headers.get("Content-Type", ""),
                    "size": len(r.content),
                    "body": r.text[:50000]
                    if "text" in r.headers.get("Content-Type", "")
                    or "javascript" in r.headers.get("Content-Type", "")
                    or "css" in r.headers.get("Content-Type", "")
                    else None,
                    "body_b64": base64.b64encode(r.content).decode("ascii")
                    if len(r.content) < 32768 and "image" in r.headers.get("Content-Type", "")
                    else None,
                }
        except (
            Exception
        ) as _exc:  # silent: static-asset download is best-effort, skip missing/slow assets
            logging.getLogger(__name__).debug("ignored: %s", _exc)

    return result


def _parse_html(html: str, result: dict, base_url: str):
    """Extract metadata from HTML."""
    # Title
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        result["title"] = m.group(1).strip()[:200]

    # Technologies
    techs = []
    tech_patterns = [
        (r"jQuery", "jQuery"),
        (r"bootstrap", "Bootstrap"),
        (r"angular", "Angular"),
        (r"react", "React"),
        (r"vue", "Vue.js"),
        (r"fortinet|fortigate|FortiOS", "FortiGate"),
        (r"netgear", "Netgear"),
        (r"tp-link|tplink", "TP-Link"),
        (r"synology", "Synology"),
        (r"hikvision", "Hikvision"),
        (r"librenms", "LibreNMS"),
        (r"mikrotik", "MikroTik"),
        (r"cisco", "Cisco"),
        (r"ubiquiti|unifi", "Ubiquiti"),
    ]
    for pat, name in tech_patterns:
        if re.search(pat, html, re.IGNORECASE):
            techs.append(name)

    # Server header tech
    server = result.get("server", "")
    if server:
        techs.append(f"Server: {server}")

    result["technologies"] = list(set(techs))


def _has_login_form(html: str) -> bool:
    """Check if HTML contains a login form."""
    return bool(
        re.search(
            r"<form[^>]*>.*?(password|passwd|login|signin|auth)", html, re.IGNORECASE | re.DOTALL
        )
    )


def _extract_form_fields(html: str) -> list:
    """Extract form input fields."""
    fields = []
    for m in re.finditer(r"<input[^>]+>", html, re.IGNORECASE):
        tag = m.group(0)
        name = re.search(r'name=["\']([^"\']+)', tag)
        type_ = re.search(r'type=["\']([^"\']+)', tag)
        if name:
            fields.append(
                {
                    "name": name.group(1),
                    "type": type_.group(1) if type_ else "text",
                }
            )
    return fields


def _extract_asset_urls(html: str, base_url: str) -> list:
    """Extract CSS, JS, and image URLs from HTML."""
    urls = set()
    # CSS
    for m in re.finditer(r'href=["\']([^"\']+\.css[^"\']*)', html, re.IGNORECASE):
        urls.add(urljoin(base_url, m.group(1)))
    # JS
    for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)', html, re.IGNORECASE):
        urls.add(urljoin(base_url, m.group(1)))
    # Images (logo, icons)
    for m in re.finditer(r'src=["\']([^"\']+\.(png|jpg|gif|svg|ico)[^"\']*)', html, re.IGNORECASE):
        urls.add(urljoin(base_url, m.group(1)))
    return sorted(urls)


def profile_device(
    target: str, name: str, ports: list[int] | None = None, timeout: float = 5.0
) -> dict:
    """Full device profiling pipeline."""
    ports = ports or DEFAULT_PORTS
    logger.info("Profiling %s as '%s' — scanning %d ports", target, name, len(ports))

    profile: dict[str, Any] = {
        "name": name,
        "target": target,
        "profiled_at": datetime.now(UTC).isoformat(),
        "profiler_version": "1.1",
        "services": [],
        "web_ui": None,
        "tls": None,
        "tcp_fingerprint": None,
        "device_type": "unknown",
        "vendor": "unknown",
        "model": "unknown",
        "technologies": [],
    }

    # 1. Port scan
    open_ports = []
    logger.info("Port scanning %s...", target)
    for port in ports:
        if tcp_connect(target, port, timeout=2.0):
            open_ports.append(port)
            logger.info("  Port %d/tcp OPEN", port)

    if not open_ports:
        logger.warning("No open ports found on %s", target)
        return profile

    # 1b. TCP fingerprint (TTL, window size, MSS)
    logger.info("TCP fingerprinting %s...", target)
    tcp_fp = get_tcp_fingerprint(target, open_ports[0], timeout)
    if tcp_fp and tcp_fp.get("ttl"):
        profile["tcp_fingerprint"] = tcp_fp
        logger.info(
            "  OS guess: %s (TTL=%s, window=%s)",
            tcp_fp["os_guess"],
            tcp_fp["ttl"],
            tcp_fp["tcp_window"],
        )

    # 2. Banner grab for each open port
    for port in open_ports:
        service = {
            "port": port,
            "protocol": "tcp",
            "banner": None,
            "service_name": BANNER_PORTS.get(port, "unknown"),
            "tls": False,
        }

        # Check if TLS
        tls_info = None
        if port in (443, 8443, 10443, 20443, 60443) or port > 8000:
            tls_info = get_tls_info(target, port, timeout)
            if tls_info:
                service["tls"] = True
                service["tls_info"] = tls_info
                if not profile["tls"]:
                    profile["tls"] = tls_info

        # Banner grab (non-HTTP)
        if port not in (80, 443, 8080, 8443, 10443, 20443, 60443):
            banner = grab_banner(target, port, timeout)
            if banner:
                service["banner"] = banner
                logger.info("  Port %d banner: %s", port, banner[:80])
        else:
            service["service_name"] = "HTTP" if not service["tls"] else "HTTPS"

        profile["services"].append(service)

    # 3. Web UI crawl (find first HTTP/HTTPS port)
    http_ports = [p for p in open_ports if p in (80, 8080)]
    https_ports = [p for p in open_ports if p in (443, 8443, 10443, 20443, 60443)]

    web_port = None
    use_https = False
    if https_ports:
        web_port = https_ports[0]
        use_https = True
    elif http_ports:
        web_port = http_ports[0]

    if web_port:
        logger.info(
            "Crawling web UI on port %d (%s)...", web_port, "HTTPS" if use_https else "HTTP"
        )
        profile["web_ui"] = crawl_web_ui(target, web_port, use_https, timeout=timeout)

        # Extract device info from web UI
        if profile["web_ui"].get("title"):
            profile["model"] = profile["web_ui"]["title"]
        if profile["web_ui"].get("technologies"):
            profile["technologies"] = profile["web_ui"]["technologies"]

        # Detect vendor
        all_text = json.dumps(profile["web_ui"]).lower()
        vendor_patterns = [
            ("netgear", "Netgear"),
            ("tp-link", "TP-Link"),
            ("tplink", "TP-Link"),
            ("cisco", "Cisco"),
            ("fortinet", "Fortinet"),
            ("fortigate", "FortiGate"),
            ("mikrotik", "MikroTik"),
            ("ubiquiti", "Ubiquiti"),
            ("synology", "Synology"),
            ("hikvision", "Hikvision"),
            ("dahua", "Dahua"),
            ("librenms", "LibreNMS"),
            ("pfsense", "pfSense"),
            ("opnsense", "OPNsense"),
        ]
        for pat, vname in vendor_patterns:
            if pat in all_text:
                profile["vendor"] = vname
                break

        # Detect device type
        type_patterns = [
            ("switch", "switch"),
            ("router", "router"),
            ("firewall", "firewall"),
            ("camera", "camera"),
            ("nas", "nas"),
            ("printer", "printer"),
            ("plc", "plc"),
            ("hmi", "hmi"),
            ("monitor", "monitoring"),
        ]
        for pat, dtype in type_patterns:
            if pat in all_text:
                profile["device_type"] = dtype
                break

    # 4. SSH version
    if 22 in open_ports:
        banner = grab_banner(target, 22, timeout)
        if banner:
            for svc in profile["services"]:
                if svc["port"] == 22:
                    svc["banner"] = banner
                    svc["service_name"] = "SSH"

    return profile


def save_profile(profile: dict) -> str:
    """Save profile to JSON file. Returns file path."""
    os.makedirs(PROFILE_DIR, exist_ok=True)
    name = re.sub(r"[^a-zA-Z0-9_-]", "_", profile["name"])
    path = os.path.join(PROFILE_DIR, f"{name}.json")
    with open(path, "w") as f:
        json.dump(profile, f, indent=2, default=str)
    logger.info("Profile saved: %s", path)
    return path


def list_profiles() -> list:
    """List all saved device profiles."""
    if not os.path.isdir(PROFILE_DIR):
        return []
    profiles = []
    for f in sorted(os.listdir(PROFILE_DIR)):
        if f.endswith(".json"):
            path = os.path.join(PROFILE_DIR, f)
            try:
                with open(path) as fh:
                    data = json.load(fh)
                profiles.append(
                    {
                        "name": data.get("name", f),
                        "target": data.get("target", "?"),
                        "vendor": data.get("vendor", "?"),
                        "device_type": data.get("device_type", "?"),
                        "services": len(data.get("services", [])),
                        "profiled_at": data.get("profiled_at", "?"),
                        "file": path,
                    }
                )
            except Exception as _exc:  # silent: malformed/corrupt profile file, skip in listing
                logging.getLogger(__name__).debug("ignored: %s", _exc)
    return profiles


def main():
    parser = argparse.ArgumentParser(description="Device Profiler for Custom Honeypots")
    parser.add_argument("--target", "-t", help="Target IP or hostname to profile")
    parser.add_argument("--name", "-n", help="Profile name (e.g. netgear-switch)")
    parser.add_argument(
        "--ports", "-p", help="Comma-separated ports to scan (default: common ports)"
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="Connection timeout (default: 5s)"
    )
    parser.add_argument("--list-profiles", "-l", action="store_true", help="List saved profiles")
    parser.add_argument("--show", "-s", help="Show profile details by name")
    parser.add_argument(
        "--output", "-o", help="Output directory (default: /opt/sensor/custom_honeypots)"
    )
    args = parser.parse_args()

    if args.output:
        global PROFILE_DIR
        PROFILE_DIR = args.output

    if args.list_profiles:
        profiles = list_profiles()
        if not profiles:
            print(f"No profiles found in {PROFILE_DIR}")
            return
        print(
            f"{'Name':<25} {'Vendor':<15} {'Type':<12} {'Services':<10} {'Target':<18} {'Profiled'}"
        )
        print("-" * 100)
        for p in profiles:
            print(
                f"{p['name']:<25} {p['vendor']:<15} {p['device_type']:<12} {p['services']:<10} {p['target']:<18} {p['profiled_at'][:19]}"
            )
        return

    if args.show:
        path = os.path.join(PROFILE_DIR, f"{args.show}.json")
        if not os.path.exists(path):
            print(f"Profile not found: {path}")
            return
        with open(path) as f:
            data = json.load(f)
        # Print summary without huge bodies
        summary = {k: v for k, v in data.items() if k != "web_ui"}
        if data.get("web_ui"):
            summary["web_ui"] = {
                "title": data["web_ui"].get("title"),
                "server": data["web_ui"].get("server"),
                "pages": list(data["web_ui"].get("pages", {}).keys()),
                "assets": list(data["web_ui"].get("static_assets", {}).keys()),
                "login_form": data["web_ui"].get("login_form"),
                "technologies": data["web_ui"].get("technologies"),
                "redirects": data["web_ui"].get("redirects"),
            }
        print(json.dumps(summary, indent=2, default=str))
        return

    if not args.target or not args.name:
        parser.print_help()
        print("\nExample:")
        print("  python device_profiler.py --target 192.0.2.254 --name netgear-switch")
        print("  python device_profiler.py --target 192.0.2.1 --name tplink-router --ports 80,443")
        return

    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]

    profile = profile_device(args.target, args.name, ports=ports, timeout=args.timeout)
    path = save_profile(profile)

    # Summary
    print("\n" + "=" * 60)
    print(f"  Device Profile: {profile['name']}")
    print("=" * 60)
    print(f"  Target:      {profile['target']}")
    print(f"  Vendor:      {profile['vendor']}")
    print(f"  Device Type: {profile['device_type']}")
    print(f"  Model/Title: {profile.get('model', '?')}")
    if profile.get("tcp_fingerprint"):
        fp = profile["tcp_fingerprint"]
        print(f"  TTL:         {fp.get('ttl', '?')}")
        print(f"  TCP Window:  {fp.get('tcp_window', '?')}")
        print(f"  MSS:         {fp.get('mss', '?')}")
        print(f"  DF Bit:      {fp.get('df_bit', '?')}")
        print(f"  OS Guess:    {fp.get('os_guess', '?')}")
        if fp.get("tcp_options"):
            print(f"  TCP Options: {', '.join(str(o) for o in fp['tcp_options'])}")
    print(f"  Open Ports:  {len(profile['services'])}")
    for svc in profile["services"]:
        tls = " (TLS)" if svc.get("tls") else ""
        banner = f" — {svc['banner'][:60]}" if svc.get("banner") else ""
        print(f"    {svc['port']:>5}/tcp  {svc['service_name']}{tls}{banner}")
    if profile.get("web_ui"):
        ui = profile["web_ui"]
        print(f"  Web Title:   {ui.get('title', '?')}")
        print(f"  Server:      {ui.get('server', '?')}")
        print(f"  Pages:       {len(ui.get('pages', {}))}")
        print(f"  Assets:      {len(ui.get('static_assets', {}))}")
        print(f"  Login Form:  {'Yes' if ui.get('login_form') else 'No'}")
        print(f"  Technologies: {', '.join(ui.get('technologies', []))}")
    print(f"  Saved to:    {path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
