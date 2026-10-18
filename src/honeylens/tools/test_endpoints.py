#!/usr/bin/env python3
"""
HoneyLens Endpoint Smoke Test — v0.02_041+
Run after every deployment to verify all WebUI endpoints respond correctly.

Usage:
    python3 -m tools.test_endpoints --host 127.0.0.1 --port 60443
    python3 -m tools.test_endpoints --host sensor.example.org --port 60443 --user admin --password CHANGEME
    python3 -m tools.test_endpoints --host 127.0.0.1 --port 60443 --quick   # skip slow endpoints

Exit codes: 0 = all passed, 1 = failures detected
"""

import argparse
import json
import sys
import time
from typing import Any

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(2)


# ---------------------------------------------------------------------------
# Endpoint definitions
# ---------------------------------------------------------------------------
# (method, path, expected_status, category, description, slow)
# slow=True endpoints are skipped with --quick

ENDPOINTS = [
    # --- Auth ---
    ("GET", "/login", 200, "auth", "Login page (public)", False),
    # --- Dashboard ---
    ("GET", "/", 200, "dashboard", "Main dashboard HTML", False),
    ("GET", "/status", 200, "dashboard", "System status", False),
    # --- Events ---
    ("GET", "/events?limit=5", 200, "events", "Recent events (paginated)", False),
    ("GET", "/events?limit=5&ip=1.2.3.4", 200, "events", "Events filtered by IP", False),
    ("GET", "/temporal", 200, "events", "Temporal event counts", False),
    # --- Stats / Aggregates ---
    ("GET", "/top_scanners", 200, "stats", "Top scanners (24h)", False),
    ("GET", "/top_ports", 200, "stats", "Top targeted ports (24h)", False),
    ("GET", "/protocols", 200, "stats", "Protocol distribution (24h)", False),
    ("GET", "/sources", 200, "stats", "Event sources (24h)", False),
    # --- Attack Classification ---
    ("GET", "/attack/types", 200, "attacks", "Attack types + stats (24h, merged)", False),
    ("GET", "/attack_rules", 200, "attacks", "Attack rules breakdown (24h)", False),
    ("GET", "/attack/rules_grouped", 200, "attacks", "Rules grouped by type", False),
    # --- Honeypots ---
    ("GET", "/honeypots/summary", 200, "honeypots", "Honeypot summary (24h)", False),
    ("GET", "/honeypots/health", 200, "honeypots", "Honeypot service health", False),
    # --- MiTM ---
    ("GET", "/mitm", 200, "mitm", "MiTM dashboard HTML", False),
    ("GET", "/mitm/summary", 200, "mitm", "MiTM summary + stats (merged)", False),
    ("GET", "/mitm/events?limit=5", 200, "mitm", "MiTM events", False),
    ("GET", "/mitm/arp-cache?limit=10", 200, "mitm", "ARP cache", False),
    # --- ICS/OT ---
    ("GET", "/ics/stats", 200, "ics", "ICS dashboard stats", False),
    ("GET", "/ics/events?limit=5", 200, "ics", "ICS events", False),
    ("GET", "/ics/baselines", 200, "ics", "ICS baselines", False),
    ("GET", "/ics/summary", 200, "ics", "ICS summary", False),
    ("GET", "/ics/mitre-matrix", 200, "ics", "ICS MITRE matrix", False),
    # --- JA4 Fingerprints ---
    ("GET", "/ja3_stats", 200, "ja4", "JA3 stats", False),
    ("GET", "/ja4_stats", 200, "ja4", "JA4 stats", False),
    ("GET", "/ja4/detected", 200, "ja4", "JA4 detected applications", False),
    ("GET", "/ja4/database", 200, "ja4", "JA4 database status", False),
    ("GET", "/ja4/search?q=chrome", 200, "ja4", "JA4 search", False),
    # --- MITRE ATT&CK ---
    ("GET", "/mitre/matrix", 200, "mitre", "MITRE ATT&CK matrix", False),
    ("GET", "/mitre/coverage", 200, "mitre", "MITRE coverage report", False),
    ("GET", "/mitre/tactics", 200, "mitre", "MITRE tactics list", False),
    ("GET", "/mitre/attack-types", 200, "mitre", "Attack types to MITRE mapping", False),
    ("GET", "/mitre/navigator", 200, "mitre", "MITRE Navigator JSON export", False),
    # --- Classifier ---
    ("GET", "/classifier/stats", 200, "classifier", "Classifier stats", False),
    ("GET", "/classifier/rules", 200, "classifier", "Classifier rules", False),
    ("GET", "/classifier/top-threats", 200, "classifier", "Top threats", False),
    ("GET", "/classifier/analyze?payload=test", 200, "classifier", "Payload analysis", False),
    # --- AI Analysis ---
    ("GET", "/ai/stats", 200, "ai", "AI analysis dashboard", False),
    ("GET", "/ai/queue", 200, "ai", "AI review queue", False),
    ("GET", "/ai/rules", 200, "ai", "AI rules management HTML", False),
    ("GET", "/ai/rules/all", 200, "ai", "AI rules (suggested + custom, merged)", False),
    ("GET", "/ai/rules/export", 200, "ai", "AI rules export bundle", False),
    ("GET", "/ai/claude-status", 200, "ai", "Claude integration status", False),
    ("GET", "/ai/analyzed_ips", 200, "ai", "AI analyzed IPs", False),
    # --- Attacker Hunting ---
    ("GET", "/attacker_hunting", 200, "hunting", "Hunting dashboard HTML", False),
    ("GET", "/attacker_hunting/stats", 200, "hunting", "Hunting stats", False),
    ("GET", "/attacker_hunting/ips", 200, "hunting", "Profiled IP set", False),
    ("GET", "/attacker_hunting/history", 200, "hunting", "Hunt history", False),
    ("GET", "/attacker_hunting/map", 200, "hunting", "Attacker world map", False),
    ("GET", "/attacker_hunting/clusters", 200, "hunting", "Fingerprint clusters", False),
    # --- FortiGate ---
    ("GET", "/fortigate/events", 200, "fortigate", "FortiGate events", False),
    ("GET", "/fortigate/stats", 200, "fortigate", "FortiGate stats (7d)", False),
    ("GET", "/fortigate/credentials", 200, "fortigate", "FortiGate captured credentials", False),
    # --- Archive ---
    ("GET", "/archive/tables", 200, "archive", "Archive tables list", False),
    ("GET", "/archive/stats", 200, "archive", "Archive statistics", False),
    # --- Export ---
    ("GET", "/export/attackers?format=json", 200, "export", "Export attackers (JSON)", False),
    ("GET", "/export/attackers/summary", 200, "export", "Export summary", False),
    # --- Blog ---
    ("GET", "/blog/status", 200, "blog", "Blog publisher status", False),
    # --- Admin ---
    ("GET", "/sensor_admin", 200, "admin", "Admin panel HTML", False),
    ("GET", "/sensor_admin/stats", 200, "admin", "Admin stats", False),
    ("GET", "/sensor_admin/status", 200, "admin", "Admin service status", False),
    ("GET", "/sensor_admin/users", 200, "admin", "Admin user list", False),
    ("GET", "/sensor_admin/audit", 200, "admin", "Admin audit log", False),
]

# ---------------------------------------------------------------------------
# Standalone module tests (run via subprocess)
# ---------------------------------------------------------------------------
# (command, description, category)

MODULE_TESTS = [
    (
        "python3 intelligence/circl_enricher.py --test",
        "CIRCL enricher self-test (Phase A+B)",
        "circl",
    ),
]


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------


class EndpointTester:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        timeout: int = 15,
        quick: bool = False,
        verbose: bool = False,
    ):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = timeout
        self.quick = quick
        self.verbose = verbose
        self.username = username
        self.password = password
        self.results: list[Any] = []

    def login(self) -> bool:
        """Authenticate and obtain session cookie."""
        try:
            resp = self.session.post(
                f"{self.base_url}/login",
                data={"username": self.username, "password": self.password},
                timeout=self.timeout,
                allow_redirects=False,
            )
            if self.verbose:
                print(
                    f"\n    Login status: {resp.status_code}, cookies: {bool(self.session.cookies)}"
                )
            if resp.status_code in (302, 303):
                return True
            # Try Basic Auth fallback
            self.session.auth = (self.username, self.password)
            resp = self.session.get(f"{self.base_url}/status", timeout=self.timeout)
            return resp.status_code == 200
        except Exception as e:
            print(f"  LOGIN FAILED: {e}")
            return False

    def test_endpoint(
        self, method: str, path: str, expected: int, category: str, desc: str
    ) -> tuple[bool, float, int, str]:
        """Test a single endpoint. Returns (passed, elapsed_sec, status, error)."""
        url = f"{self.base_url}{path}"
        try:
            t0 = time.time()
            if method == "GET":
                resp = self.session.get(
                    url, timeout=self.timeout, headers={"Accept": "application/json"}
                )
            else:
                resp = self.session.post(
                    url, timeout=self.timeout, headers={"Accept": "application/json"}
                )
            elapsed = time.time() - t0
            status = resp.status_code

            # Accept 200-299, or exact match
            if status == expected or (expected == 200 and 200 <= status < 300):
                return True, elapsed, status, ""
            else:
                body_preview = resp.text[:200] if resp.text else ""
                return False, elapsed, status, body_preview

        except requests.exceptions.Timeout:
            return False, self.timeout, 0, "TIMEOUT"
        except requests.exceptions.ConnectionError as e:
            return False, 0, 0, f"CONNECTION_ERROR: {e}"
        except Exception as e:
            return False, 0, 0, f"ERROR: {e}"

    def run_all(self) -> int:
        """Run all endpoint tests. Returns count of failures."""
        print(f"\n{'=' * 72}")
        print("  HoneyLens Endpoint Smoke Test")
        print(f"  Target: {self.base_url}")
        print(f"  Mode:   {'quick' if self.quick else 'full'}")
        print(f"{'=' * 72}\n")

        # Login
        print("  Authenticating... ", end="", flush=True)
        if not self.login():
            print("FAILED")
            print("\n  Cannot authenticate. Check credentials and try again.")
            return 999
        print("OK\n")

        passed = 0
        failed = 0
        skipped = 0
        slow_endpoints = []
        current_category = ""

        for method, path, expected, category, desc, is_slow in ENDPOINTS:
            if self.quick and is_slow:
                skipped += 1
                continue

            if category != current_category:
                current_category = category
                print(f"  [{category.upper()}]")

            ok, elapsed, status, error = self.test_endpoint(method, path, expected, category, desc)

            if ok:
                passed += 1
                flag = ""
                if elapsed > 5.0:
                    flag = "  ⚠ SLOW"
                    slow_endpoints.append((path, elapsed))
                elif elapsed > 2.0:
                    slow_endpoints.append((path, elapsed))
                print(f"    PASS  {elapsed:5.1f}s  {method:4s} {path:45s} {desc}{flag}")
            else:
                failed += 1
                print(f"    FAIL  {elapsed:5.1f}s  {method:4s} {path:45s} → {status} {error[:80]}")

            self.results.append(
                {
                    "method": method,
                    "path": path,
                    "category": category,
                    "desc": desc,
                    "passed": ok,
                    "status": status,
                    "elapsed": round(elapsed, 3),
                    "error": error,
                }
            )

        # Module self-tests (standalone scripts with --test flag)
        if not self.quick and MODULE_TESTS:
            print("\n  [MODULE TESTS]")
            for cmd, desc, _category in MODULE_TESTS:
                try:
                    import shlex
                    import subprocess

                    t0 = time.time()
                    # MODULE_TESTS holds literal commands with no pipes or
                    # redirections, so no shell is needed — and without one the
                    # entry cannot grow into an injection point later.
                    result = subprocess.run(
                        shlex.split(cmd),
                        capture_output=True,
                        text=True,
                        timeout=120,
                        cwd="/opt/sensor",
                    )
                    elapsed = time.time() - t0
                    if result.returncode == 0:
                        passed += 1
                        # Count sub-tests from output
                        sub_passed = result.stdout.count("PASS")
                        print(f"    PASS  {elapsed:5.1f}s  {desc} ({sub_passed} sub-tests)")
                    else:
                        failed += 1
                        sub_failed = result.stdout.count("FAIL")
                        print(f"    FAIL  {elapsed:5.1f}s  {desc} ({sub_failed} sub-tests failed)")
                        if self.verbose:
                            for line in result.stdout.splitlines():
                                if "FAIL" in line:
                                    print(f"           {line.strip()}")
                except subprocess.TimeoutExpired:
                    failed += 1
                    print(f"    FAIL  120.0s  {desc} (TIMEOUT)")
                except Exception as e:
                    failed += 1
                    print(f"    FAIL    0.0s  {desc} ({e})")

        # Summary
        total = passed + failed
        print(f"\n{'=' * 72}")
        print(f"  Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")
        if slow_endpoints:
            print("\n  Slow endpoints (>2s):")
            for path, elapsed in sorted(slow_endpoints, key=lambda x: -x[1]):
                print(f"    {elapsed:5.1f}s  {path}")
        print(f"{'=' * 72}\n")

        return failed

    def save_json(self, filepath: str):
        """Save results as JSON for CI/CD integration."""
        report = {
            "target": self.base_url,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total": len(self.results),
            "passed": sum(1 for r in self.results if r["passed"]),
            "failed": sum(1 for r in self.results if not r["passed"]),
            "results": self.results,
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Report saved to {filepath}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="HoneyLens deployment smoke test — verify all WebUI endpoints"
    )
    parser.add_argument("--host", required=True, help="Sensor hostname or IP")
    parser.add_argument("--port", type=int, default=60443, help="WebUI port (default: 60443)")
    parser.add_argument("--user", default="admin", help="Username (default: admin)")
    parser.add_argument("--password", default=None, help="Password (prompted if not set)")
    parser.add_argument("--timeout", type=int, default=15, help="Per-request timeout in seconds")
    parser.add_argument("--quick", action="store_true", help="Skip slow endpoints")
    parser.add_argument("--verbose", action="store_true", help="Show response details")
    parser.add_argument("--json", default=None, help="Save JSON report to file")
    args = parser.parse_args()

    if not args.password:
        import getpass

        args.password = getpass.getpass(f"Password for {args.user}@{args.host}: ")

    base_url = f"https://{args.host}:{args.port}"

    tester = EndpointTester(
        base_url=base_url,
        username=args.user,
        password=args.password,
        timeout=args.timeout,
        quick=args.quick,
        verbose=args.verbose,
    )

    failures = tester.run_all()

    if args.json:
        tester.save_json(args.json)

    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
