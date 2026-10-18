"""CVE-2026-0322 detection on the PAN-OS decoy, and the regression it must not cause.

The detection itself is the easy half. The half worth testing is that adding a newer, less
certain label did not steal traffic from CVE-2024-9474, which this decoy already classifies
correctly — 2024-9474 is path-scoped to ``createRemoteAppwebSession``, which lives under
``/php/`` and therefore also satisfies the management-surface test that 0322 uses.

Note on the payloads below: strings such as ``eval('x')`` and ``__import__`` appear only
as attacker-supplied *test data* inside byte literals handed to the detector. Nothing here
evaluates them — the detector only pattern-matches. A scanner flagging ``eval(`` in this
file is matching the payload we are testing for.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from honeylens.honeypots import honeypot_paloalto as pa


def _request(path: str, *, body: bytes = b"", headers=None, cookies=None, query=None):
    """Minimal stand-in for the aiohttp request the detector reads."""
    hdrs = headers or {}
    return SimpleNamespace(
        path=path.split("?")[0],
        path_qs=path,
        headers=hdrs,
        cookies=cookies or {},
        query=query or {},
        _read_bytes=body,
    )


def _detect(request):
    return pa.PaloAltoHoneypot._detect_cves(object(), request)  # unbound: needs no instance state


def _cves(request) -> set[str]:
    return {c["cve"] for c in _detect(request)}


def _entry(request, cve: str) -> dict | None:
    return next((c for c in _detect(request) if c["cve"] == cve), None)


# ── the regression this change exists to avoid ───────────────────────────────────────────


def test_2024_9474_body_is_not_relabelled_as_0322():
    """A createRemoteAppwebSession injection must stay 2024-9474 and gain no 0322 entry.

    Without the deferral this body matches both: the path is under /php/, the shell class
    matches the backticks, and an authenticated context is present.
    """
    req = _request(
        "/php/utils/createRemoteAppwebSession.php",
        body=b"user=`id`",
        cookies={"PHPSESSID": "x"},
    )
    found = _cves(req)
    assert "CVE-2024-9474" in found
    assert "CVE-2026-0322" not in found, "0322 stole traffic from the path-scoped 2024-9474"


# ── the detection ────────────────────────────────────────────────────────────────────────


def test_code_evaluation_payload_is_critical():
    req = _request(
        "/api/?type=op",
        body=b"<request><cmd>__import__('os').system('id')</cmd></request>",
        cookies={"PHPSESSID": "x"},
    )
    entry = _entry(req, "CVE-2026-0322")
    assert entry is not None
    assert entry["severity"] == "CRITICAL"
    assert "code-evaluation" in entry["detail"]


def test_shell_only_payload_is_downgraded_and_says_why():
    """Shell metacharacters are CWE-78, not the CWE-94 this CVE is. Report, do not assert."""
    req = _request("/api/?type=op", body=b"cmd=`id`", cookies={"PHPSESSID": "x"})
    entry = _entry(req, "CVE-2026-0322")
    assert entry is not None
    assert entry["severity"] == "HIGH", "shell-only match must not be asserted as CRITICAL"
    assert "WEAK" in entry["detail"]


@pytest.mark.parametrize(
    ("headers", "path"),
    [
        ({"X-PAN-AUTHCHECK": "off"}, "/api/?type=op"),
        # The real 2025-0108 chain carries a double-encoded traversal; without one that
        # CVE correctly does not fire, which is why this path has it.
        ({}, "/unauth/php/api/..%252f..%252fapi/?type=op"),
    ],
)
def test_chained_auth_bypass_still_reports_0322(headers, path):
    """0322 must coexist with the bypass primitives — the chain is the point.

    Deferring to every already-matched CVE would have suppressed exactly this case.
    """
    req = _request(path, body=b"<cmd>eval('x')</cmd>", headers=headers)
    found = _cves(req)
    assert "CVE-2026-0322" in found
    assert found & {"CVE-2024-0012", "CVE-2025-0108"}, "the bypass primitive should also fire"
    assert "auth-bypass chaining" in _entry(req, "CVE-2026-0322")["detail"]


# ── the gates that keep it narrow ────────────────────────────────────────────────────────


def test_no_detection_without_an_authentication_context():
    """The real bug needs admin credentials; unauthenticated spraying is not this CVE."""
    req = _request("/api/?type=op", body=b"<cmd>eval('x')</cmd>")
    assert "CVE-2026-0322" not in _cves(req)


def test_no_detection_off_the_management_surface():
    req = _request("/global-protect/login.esp2", body=b"eval('x')", cookies={"PHPSESSID": "x"})
    assert "CVE-2026-0322" not in _cves(req)


def test_clean_authenticated_management_request_is_not_flagged():
    req = _request(
        "/api/?type=op&cmd=<show><system><info/></system></show>", cookies={"PHPSESSID": "x"}
    )
    assert "CVE-2026-0322" not in _cves(req)


def test_api_key_in_header_or_query_counts_as_authenticated():
    for req in (
        _request("/api/?type=op", body=b"<cmd>eval('x')</cmd>", headers={"X-PAN-KEY": "k"}),
        _request("/api/?type=op", body=b"<cmd>eval('x')</cmd>", query={"key": "k"}),
    ):
        assert "CVE-2026-0322" in _cves(req)


# ── classification plumbing ──────────────────────────────────────────────────────────────


def test_ingest_maps_the_cve_to_an_attack_type():
    from honeylens.ingest.paloalto import CVE_ATTACK_TYPES

    assert CVE_ATTACK_TYPES["CVE-2026-0322"] == "PANOS_CVE_2026_0322"
    # These two were detected by the decoy but unmapped, so they ingested as generic.
    assert CVE_ATTACK_TYPES["CVE-2026-0257"] == "PANOS_CVE_2026_0257"
    assert CVE_ATTACK_TYPES["CVE-2026-0300"] == "PANOS_CVE_2026_0300"
