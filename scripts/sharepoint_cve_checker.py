#!/usr/bin/env python3
"""
Non-destructive SharePoint Server CVE checker.

Designed for lab/on-prem SharePoint targets you own. It fingerprints the exposed
SharePoint build, runs safe unauthenticated surface/behaviour probes, and reports
per-CVE status as vulnerable/patched/unknown with evidence.

No exploit payloads, webshell writes, command execution, or destructive actions.
"""

import argparse
import base64
import datetime
import json
import re
import ssl
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPHandler, HTTPRedirectHandler, HTTPSHandler, Request, build_opener

USER_AGENT = "HoneyLens-SharePoint-CVE-Checker/1.0"
MAX_BODY = 256 * 1024
VERSION_RE = re.compile(r"\b(?:1[45]|16)\.0(?:\.\d+){1,3}\b")
SERVICE_VERSION_RE = re.compile(r"vti_extenderversion\s*:\s*SR\|([^\r\n]+)", re.I)
REALM_RE = re.compile(r'realm="?([0-9a-fA-F-]{20,}|[^"]+)"?', re.I)

STATUS_VULN = "vulnerable"
STATUS_PATCHED = "patched"
STATUS_NOT_DETECTED = "not_detected"
STATUS_UNKNOWN = "unknown"


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class HttpResult:
    name: str
    method: str
    url: str
    status: int | None
    reason: str
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    error: str | None

    def short(self) -> dict[str, object]:
        return {
            "name": self.name,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "reason": self.reason,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "headers": selected_headers(self.headers),
            "body_sha256_hint": None,
            "body_sample": squash(self.body[:300]),
        }


@dataclass
class Finding:
    cve: str
    name: str
    status: str
    confidence: str
    evidence: list[str]
    limitation: str


def squash(s):
    return re.sub(r"\s+", " ", s or "").strip()


def selected_headers(headers):
    interesting = [
        "microsoftsharepointteamservices",
        "server",
        "www-authenticate",
        "x-sharepointhealthscore",
        "sprequestguid",
        "x-powered-by",
        "location",
        "content-type",
    ]
    out = {}
    lower = {k.lower(): v for k, v in headers.items()}
    for key in interesting:
        if key in lower:
            out[key] = lower[key]
    return out


def normalize_target(raw):
    raw = raw.strip().rstrip("/")
    if not raw:
        raise ValueError("empty target")
    if "://" in raw:
        return [raw]
    return ["http://" + raw, "https://" + raw]


def make_opener(verify_tls=True):
    """Build the HTTP opener, verifying TLS unless explicitly told not to.

    Verification is the default because this checker's whole output is a CVE verdict
    derived from a version banner the server hands us. Against an unverified TLS
    connection anyone on the path can rewrite that banner, so the report would be
    confidently wrong rather than unavailable — the worse of the two outcomes when the
    verdict goes into a client-facing write-up.

    Lab decoys use self-signed certificates and legitimately need verification off;
    that is what ``--insecure-tls`` is for, and the report records that it was used.
    """
    handlers = [NoRedirectHandler(), HTTPHandler()]
    ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    handlers.append(HTTPSHandler(context=ctx))
    return build_opener(*handlers)


def http_request(
    opener, base_url, name, method, path, headers=None, data=None, timeout=8, host_header=None
):
    headers = dict(headers or {})
    headers.setdefault("User-Agent", USER_AGENT)
    headers.setdefault("Accept", "*/*")
    # SharePoint/IIS web apps are usually bound to a host header, so scanning by
    # IP needs the right Host or every path 404s. An explicit override wins.
    if host_header:
        headers["Host"] = host_header
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    body_bytes = None
    if data is not None:
        body_bytes = data if isinstance(data, bytes) else data.encode("utf-8")
    req = Request(url, data=body_bytes, headers=headers, method=method)
    start = time.time()
    status = None
    reason = ""
    res_headers = {}
    body = ""
    error = None
    try:
        resp = opener.open(req, timeout=timeout)
        status = getattr(resp, "status", resp.getcode())
        reason = getattr(resp, "reason", "") or ""
        res_headers = dict(resp.headers.items())
        if method != "HEAD":
            raw = resp.read(MAX_BODY)
            body = raw.decode("utf-8", "replace")
    except HTTPError as e:
        status = e.code
        reason = e.reason or ""
        res_headers = dict(e.headers.items()) if e.headers else {}
        try:
            if method != "HEAD":
                body = e.read(MAX_BODY).decode("utf-8", "replace")
        except Exception:
            body = ""
    except (URLError, ssl.SSLError, TimeoutError) as e:
        error = str(e)
        # A self-signed lab host now fails closed, which reads exactly like an unreachable
        # host unless we say otherwise. URLError wraps the verification error, so match on
        # the text rather than the exception type.
        if "certificate verify failed" in error.lower() or "CERTIFICATE_VERIFY" in error:
            error += " — pass --insecure-tls if this is a lab host with a self-signed certificate"
    except Exception as e:
        error = repr(e)
    elapsed_ms = int((time.time() - start) * 1000)
    return HttpResult(name, method, url, status, reason, res_headers, body, elapsed_ms, error)


def version_tuple(v):
    if not v:
        return None
    nums = re.findall(r"\d+", v)
    if len(nums) < 3:
        return None
    parts = [int(x) for x in nums[:4]]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def cmp_version(a, b):
    ta = version_tuple(a)
    tb = version_tuple(b)
    if ta is None or tb is None:
        return None
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def canonical_version(v):
    """Realign the on-wire build form to the published form.

    SharePoint reports its build two ways. The published / Central-Admin build is
    ``16.0.<BUILD>.<REV>`` (e.g. 16.0.14326.20450) and our thresholds use it. But
    on the wire the ``MicrosoftSharePointTeamServices`` header and
    ``service.cnf`` usually carry ``16.0.0.<BUILD>`` — BUILD in the 4th octet, no
    revision. Left as-is, the 3rd octet is 0 and every SKU/threshold check
    collapses to unknown.

    Return ``(canonical_build_string, rev_known)``: the wire form becomes
    ``16.0.<BUILD>.0`` with ``rev_known=False`` so the caller knows the revision
    is indeterminate; anything already in published form is returned unchanged
    with ``rev_known=True``.
    """
    t = version_tuple(v)
    if t is None:
        return (v, True)
    major, minor, third, fourth = t
    if minor == 0 and third == 0 and fourth >= 4000 and major in (15, 16):
        return ("%d.0.%d.0" % (major, fourth), False)
    return (v, True)


def infer_sku(version):
    vt = version_tuple(version)
    if vt is None:
        return "unknown"
    # SharePoint 2019 builds are 16.0.103xx/104xx. 2016 builds are commonly
    # 16.0.4xxx/5xxx. Subscription Edition public updates are 16.0.14xxx+.
    if vt[0] == 15:
        return "2013"
    if vt[0] != 16:
        return "unknown"
    build = vt[2]
    rev = vt[3]
    if build == 0:
        return "unknown"
    if 4000 <= build < 7000:
        return "2016"
    if 10000 <= build < 12000:
        return "2019"
    if build >= 14000:
        return "subscription"
    # Some service.cnf leaks look like 16.0.0.<build>; keep them unknown so we
    # do not apply the wrong SKU threshold.
    if rev >= 14000:
        return "unknown"
    return "unknown"


def extract_versions(results):
    versions = []
    for r in results:
        h = {k.lower(): v for k, v in r.headers.items()}
        for key in ["microsoftsharepointteamservices", "server", "x-aspnet-version"]:
            if key in h:
                versions.extend(VERSION_RE.findall(h[key]))
                versions.extend(re.findall(r"\b(?:15|16)\.0(?:\.\d+){1,3}\b", h[key]))
        m = SERVICE_VERSION_RE.search(r.body or "")
        if m:
            candidate = m.group(1).strip()
            vm = re.search(r"\b(?:15|16)\.0(?:\.\d+){1,3}\b", candidate)
            if vm:
                versions.append(vm.group(0))
        versions.extend(re.findall(r"\b(?:15|16)\.0(?:\.\d+){1,3}\b", r.body or ""))
    cleaned = []
    for v in versions:
        if isinstance(v, tuple):
            # Defensive: old regex variant with a capture group can produce tuples.
            continue
        if v not in cleaned:
            cleaned.append(v)
    cleaned.sort(key=lambda x: version_tuple(x) or (0, 0, 0, 0), reverse=True)
    return cleaned


def is_login_or_denied(r):
    if r.status in (301, 302, 303, 307, 308, 401, 403):
        return True
    text = (r.body or "").lower()
    return any(x in text for x in ["signin.aspx", "access denied", "unauthorized", "forbidden"])


def body_has_toolpane_edit(r):
    if r.status != 200:
        return False
    text = (r.body or "").lower()
    markers = ["toolpane", "msotlp", "web part", "webpart", "displaymode=edit"]
    return any(m in text for m in markers) and not is_login_or_denied(r)


def body_has_picker_form(r):
    if r.status != 200:
        return False
    text = (r.body or "").lower()
    markers = ["pickerdialogtype", "itempickerdialog", "hiddenspandata", "picker.aspx"]
    return any(m in text for m in markers) and not is_login_or_denied(r)


def body_looks_sharepoint(r):
    text = (r.body or "").lower()
    headers = {k.lower(): v.lower() for k, v in r.headers.items()}
    if "microsoftsharepointteamservices" in headers:
        return True
    if "sharepoint" in text:
        return True
    if "x-sharepointhealthscore" in headers or "sprequestguid" in headers:
        return True
    return False


def unsigned_jwt():
    def b64(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "aud": "00000003-0000-0ff1-ce00-000000000000",
        "iss": "00000003-0000-0ff1-ce00-000000000000",
        "nameid": "checker-only-no-real-claims",
        "exp": int(time.time()) + 300,
    }
    return b64(header) + "." + b64(payload) + "."


def version_status(build, sku, thresholds, rev_known=True):
    if not build:
        return (STATUS_UNKNOWN, "no SharePoint build was fingerprinted")
    threshold = thresholds.get(sku)
    if not threshold:
        return (STATUS_UNKNOWN, "no reliable threshold for inferred SKU %s" % sku)
    tb = version_tuple(build)
    tt = version_tuple(threshold)
    if tb is None or tt is None:
        return (STATUS_UNKNOWN, "could not compare build %s to threshold %s" % (build, threshold))
    # Compare on the BUILD line first (major.minor.build); a different BUILD
    # octet settles it regardless of revision. Only an exact BUILD match needs
    # the revision — and the on-wire 16.0.0.<build> form does not carry one.
    ba = (tb[0], tb[1], tb[2])
    bt = (tt[0], tt[1], tt[2])
    if ba < bt:
        return (
            STATUS_VULN,
            "build %s is below fixed threshold %s for SKU %s" % (build, threshold, sku),
        )
    if ba > bt:
        return (
            STATUS_PATCHED,
            "build %s is at/above fixed threshold %s for SKU %s" % (build, threshold, sku),
        )
    if not rev_known:
        return (
            STATUS_UNKNOWN,
            "build %s matches fixed BUILD %s but the on-wire form carries no revision; patch revision indeterminate"
            % (build, threshold),
        )
    if tb < tt:
        return (
            STATUS_VULN,
            "build %s is below fixed threshold %s for SKU %s" % (build, threshold, sku),
        )
    return (
        STATUS_PATCHED,
        "build %s is at/above fixed threshold %s for SKU %s" % (build, threshold, sku),
    )


def result_by_name(results, name):
    for r in results:
        if r.name == name:
            return r
    return None


def evaluate(findings_input):
    build = findings_input["build"]
    sku = findings_input["sku"]
    rev_known = findings_input.get("rev_known", True)
    results = findings_input["results"]

    def rb(n):
        return result_by_name(results, n)

    findings = []

    toolshell_thresholds = {
        "2016": "16.0.5513.1001",
        "2019": "16.0.10417.20037",
        "subscription": "16.0.18526.20508",
    }
    toolpane = rb("toolshell_toolpane_signout_referer")
    st, ev = version_status(build, sku, toolshell_thresholds, rev_known)
    evidence = [ev]
    confidence = "medium"
    limitation = "Version check plus safe ToolPane SignOut-Referer probe; no deserialization payload is sent."
    if toolpane:
        evidence.append(
            "ToolPane SignOut-Referer probe: HTTP %s %s"
            % (toolpane.status, squash(toolpane.body[:90]))
        )
        if body_has_toolpane_edit(toolpane):
            st = STATUS_VULN
            confidence = "high"
            evidence.append(
                "ToolPane edit surface rendered for SignOut Referer without authentication."
            )
        elif is_login_or_denied(toolpane) and st == STATUS_UNKNOWN:
            st = STATUS_NOT_DETECTED
            confidence = "medium"
            evidence.append("ToolPane probe was redirected/denied; bypass behaviour not observed.")
    findings.append(
        Finding(
            "CVE-2025-53770",
            "ToolShell SharePoint deserialization RCE",
            st,
            confidence,
            evidence,
            limitation,
        )
    )
    findings.append(
        Finding(
            "CVE-2025-53771",
            "ToolShell related spoofing/auth-bypass chain",
            st,
            confidence,
            list(evidence),
            limitation,
        )
    )

    api = rb("api_siteusers")
    jwt = rb("api_unsigned_jwt_currentuser")
    # CVE.org CNA data gives before 16.0.10399.20005 for the published affected range.
    st, ev = version_status(build, sku, {"2019": "16.0.10399.20005"}, rev_known)
    evidence = [ev]
    confidence = "medium" if st != STATUS_UNKNOWN else "low"
    limitation = "Safe unsigned alg:none JWT probe only; full chained RCE is not attempted. Public CNA version data is most precise for SharePoint 2019."
    if api:
        evidence.append(
            "/_api/web/siteusers: HTTP %s; WWW-Authenticate=%s"
            % (api.status, selected_headers(api.headers).get("www-authenticate", ""))
        )
    if jwt:
        evidence.append("unsigned JWT probe: HTTP %s %s" % (jwt.status, squash(jwt.body[:120])))
        if jwt.status == 200 and not is_login_or_denied(jwt):
            st = STATUS_VULN
            confidence = "high"
            evidence.append("/_api accepted an unsigned alg:none bearer token.")
        elif jwt.status in (401, 403) and st == STATUS_UNKNOWN:
            st = STATUS_NOT_DETECTED
            confidence = "medium"
            evidence.append("/_api rejected unsigned bearer token.")
    findings.append(
        Finding(
            "CVE-2023-29357",
            "SharePoint JWT authentication bypass / EoP",
            st,
            confidence,
            evidence,
            limitation,
        )
    )
    findings.append(
        Finding(
            "CVE-2023-24955",
            "SharePoint RCE commonly chained after CVE-2023-29357",
            STATUS_UNKNOWN,
            "low",
            ["No safe unauthenticated RCE-specific check is performed.", *evidence],
            "Requires authenticated/chained write/code-injection conditions; this checker does not mutate SharePoint.",
        )
    )

    picker = rb("picker_itempickerdialog")
    st, ev = version_status(build, sku, {"2019": "16.0.10341.20000"}, rev_known)
    evidence = [ev]
    if picker:
        evidence.append("Picker ItemPickerDialog GET: HTTP %s" % picker.status)
        if body_has_picker_form(picker):
            evidence.append(
                "Picker form surface is reachable; this is exposure evidence, not proof of exploitability."
            )
    findings.append(
        Finding(
            "CVE-2019-0604",
            "SharePoint Picker.aspx XML deserialization RCE",
            st,
            "medium" if st != STATUS_UNKNOWN else "low",
            evidence,
            "Non-destructive check does not send XmlSerializer gadget. 2019 threshold is known; other SKUs are reported unknown unless behavioural/public data is added.",
        )
    )

    st, ev = version_status(build, sku, {"2019": "16.0.10358.20000"}, rev_known)
    findings.append(
        Finding(
            "CVE-2020-0932",
            "SharePoint TypeConverter/WebPart RCE",
            st,
            "medium" if st != STATUS_UNKNOWN else "low",
            [ev],
            "Version-only check for known 2019 April 2020 fixed build; no WebPart payload is sent.",
        )
    )

    st, ev = version_status(build, sku, {"2019": "16.0.10363.12107"}, rev_known)
    findings.append(
        Finding(
            "CVE-2020-1147",
            ".NET/SharePoint deserialization RCE",
            st,
            "medium" if st != STATUS_UNKNOWN else "low",
            [ev],
            "Version-only check for known 2019 July 2020 fixed build; no serialized DataSet/ViewState payload is sent.",
        )
    )

    st, ev = version_status(
        build,
        sku,
        {
            "2016": "16.0.5317.1000",
            "2019": "16.0.10386.20011",
            "subscription": "16.0.14931.20286",
        },
        rev_known,
    )
    findings.append(
        Finding(
            "CVE-2022-29108",
            "SharePoint Server RCE",
            st,
            "high" if st != STATUS_UNKNOWN else "low",
            [ev],
            "CNA affected-version thresholds are used; no authenticated RCE path is exercised.",
        )
    )

    # These are intentionally conservative until exact CNA affected ranges are added.
    for cve, name in [
        ("CVE-2021-27076", "SharePoint InfoPath/List Forms RCE"),
        ("CVE-2021-28474", "SharePoint Server RCE"),
        ("CVE-2021-31181", "SharePoint WebPart interpretation-conflict RCE"),
    ]:
        evidence = []
        if build:
            evidence.append("fingerprinted build %s (SKU %s)" % (build, sku))
            evidence.append("exact fixed-build threshold not embedded for this CVE")
        else:
            evidence.append("no build fingerprint available")
        findings.append(
            Finding(
                cve,
                name,
                STATUS_UNKNOWN,
                "low",
                evidence,
                "Known SharePoint RCE class; add exact MSRC/CNA affected range before making vulnerable/patched claims.",
            )
        )

    webshell = rb("toolshell_spinstall0_indicator")
    evidence = [
        "No public endpoint/fixed-build threshold was available when this checker was written."
    ]
    st = STATUS_UNKNOWN
    confidence = "low"
    if webshell:
        evidence.append("/_layouts/15/spinstall0.aspx indicator probe: HTTP %s" % webshell.status)
        if webshell.status == 200 and re.search(
            r"machinekey|validationkey|decryptionkey", webshell.body or "", re.I
        ):
            st = "indicator_present"
            confidence = "medium"
            evidence.append(
                "spinstall0.aspx returned MachineKey-like content; this is compromise/webshell evidence, not proof of CVE-2026-65660."
            )
    findings.append(
        Finding(
            "CVE-2026-65660",
            "SharePoint authenticated low-priv RCE / webshell activity",
            st,
            confidence,
            evidence,
            "Endpoint/parameter details and patch threshold are not public in the local research notes; report remains unknown unless an indicator is seen.",
        )
    )

    return findings


def choose_base_url(targets, opener, timeout, host_header=None):
    attempts = []
    for base in targets:
        r = http_request(opener, base, "root", "GET", "/", timeout=timeout, host_header=host_header)
        attempts.append(r)
        if r.status is not None and r.status < 600:
            return base, attempts
    return targets[0], attempts


def scan(target, timeout=8, verify_tls=True, host_header=None):
    opener = make_opener(verify_tls)
    base_url, initial = choose_base_url(normalize_target(target), opener, timeout, host_header)
    results = list(initial)
    # The SignOut Referer tell is a path; use the host-header origin when scanning
    # by IP so the Referer host matches the web app the server will route to.
    referer_origin = (
        (urlparse(base_url).scheme + "://" + host_header) if host_header else base_url.rstrip("/")
    )

    probes = [
        ("service_cnf", "GET", "/_vti_pvt/service.cnf", {}, None),
        ("vti_inf", "GET", "/_vti_inf.html", {}, None),
        ("fpse_rpc", "GET", "/_vti_bin/shtml.dll/_vti_rpc", {}, None),
        ("api_web", "GET", "/_api/web", {"Accept": "application/json;odata=verbose"}, None),
        (
            "api_siteusers",
            "GET",
            "/_api/web/siteusers",
            {"Accept": "application/json;odata=verbose"},
            None,
        ),
        (
            "toolshell_toolpane_signout_referer",
            "GET",
            "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx",
            {"Referer": referer_origin + "/_layouts/SignOut.aspx"},
            None,
        ),
        (
            "picker_itempickerdialog",
            "GET",
            "/_layouts/15/Picker.aspx?PickerDialogType=Microsoft.SharePoint.WebControls.ItemPickerDialog",
            {},
            None,
        ),
        ("toolshell_spinstall0_indicator", "GET", "/_layouts/15/spinstall0.aspx", {}, None),
        (
            "api_unsigned_jwt_currentuser",
            "GET",
            "/_api/web/currentuser",
            {
                "Accept": "application/json;odata=verbose",
                "Authorization": "Bearer " + unsigned_jwt(),
            },
            None,
        ),
    ]
    for name, method, path, headers, data in probes:
        results.append(
            http_request(
                opener,
                base_url,
                name,
                method,
                path,
                headers=headers,
                data=data,
                timeout=timeout,
                host_header=host_header,
            )
        )

    versions = extract_versions(results)
    # Canonicalize every candidate (so a wire-form 16.0.0.<build> re-sorts above
    # stray low tokens), then pick the highest BUILD and keep whether its
    # revision was actually on the wire.
    canon = [canonical_version(v) for v in versions]
    canon.sort(key=lambda p: version_tuple(p[0]) or (0, 0, 0, 0), reverse=True)
    build, rev_known = canon[0] if canon else (None, True)
    build_raw = versions[0] if versions else None
    sku = infer_sku(build)
    sharepoint_seen = any(body_looks_sharepoint(r) for r in results) or bool(build)
    realms = []
    for r in results:
        wh = selected_headers(r.headers).get("www-authenticate", "")
        for m in REALM_RE.finditer(wh + "\n" + (r.body or "")):
            value = m.group(1).strip()
            if value and value not in realms:
                realms.append(value)

    findings = evaluate({"build": build, "sku": sku, "rev_known": rev_known, "results": results})
    return {
        "scanner": "HoneyLens SharePoint CVE Checker",
        "scanner_version": "1.0",
        "generated_at_utc": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_input": target,
        "base_url": base_url,
        # Provenance: every verdict below is only as trustworthy as the connection the
        # banner arrived over, so the report says which it was instead of leaving a
        # reader of the JSON to guess.
        "tls_verified": bool(verify_tls),
        "sharepoint_seen": sharepoint_seen,
        "fingerprint": {
            "build": build,
            "build_raw": build_raw,
            "revision_known": rev_known,
            "all_versions_seen": versions,
            "inferred_sku": sku,
            "realms": realms,
        },
        "findings": [finding_to_dict(f) for f in findings],
        "probes": [r.short() for r in results],
        "safety": {
            "destructive": False,
            "exploit_payloads_sent": False,
            "notes": "Only GET/HEAD-style and unsigned-token behavioural probes are used; no webshell write, command execution, or serialized gadget payload is sent.",
        },
    }


def finding_to_dict(f):
    return {
        "cve": f.cve,
        "name": f.name,
        "status": f.status,
        "confidence": f.confidence,
        "evidence": f.evidence,
        "limitation": f.limitation,
    }


def print_text(report):
    fp = report["fingerprint"]
    print("SharePoint CVE status for %s" % report["base_url"])
    print("Generated: %s" % report["generated_at_utc"])
    if report.get("base_url", "").startswith("https://") and not report.get("tls_verified", True):
        print(
            "TLS: NOT VERIFIED (--insecure-tls) — the build below is whatever the path "
            "chose to send; do not quote it as evidence outside a lab."
        )
    print("SharePoint fingerprint seen: %s" % report["sharepoint_seen"])
    build_line = fp["build"] or "unknown"
    if fp.get("build_raw") and fp.get("build_raw") != fp["build"]:
        build_line += " (on-wire %s)" % fp["build_raw"]
    if fp.get("build") and not fp.get("revision_known", True):
        build_line += " [revision not on the wire — boundary builds reported unknown]"
    print("Build: %s" % build_line)
    print("Inferred SKU: %s" % fp["inferred_sku"])
    if fp["realms"]:
        print("Auth realm(s): %s" % ", ".join(fp["realms"]))
    print("")
    print("CVE statuses:")
    width = max(len(f["cve"]) for f in report["findings"])
    for f in report["findings"]:
        print(
            "  %-*s  %-17s  %-6s  %s" % (width, f["cve"], f["status"], f["confidence"], f["name"])
        )
        for ev in f["evidence"][:4]:
            print("    - %s" % ev)
        if f["limitation"]:
            print("    limitation: %s" % f["limitation"])
    print("")
    print("Probe summary:")
    for p in report["probes"]:
        status = p["status"] if p["status"] is not None else "ERR"
        extra = (
            p["error"]
            or p["headers"].get("location", "")
            or p["headers"].get("www-authenticate", "")
        )
        print("  %-34s %-4s %s" % (p["name"], status, squash(str(extra))[:110]))


def self_test():
    assert cmp_version("16.0.10417.20036", "16.0.10417.20037") == -1
    assert cmp_version("16.0.10417.20037", "16.0.10417.20037") == 0
    assert infer_sku("16.0.10417.20037") == "2019"
    assert infer_sku("16.0.5513.1001") == "2016"
    assert infer_sku("16.0.18526.20508") == "subscription"
    fake = HttpResult(
        "service_cnf",
        "GET",
        "http://x/_vti_pvt/service.cnf",
        200,
        "OK",
        {"MicrosoftSharePointTeamServices": "16.0.10417.20037"},
        "vti_extenderversion:SR|16.0.10417.20037",
        1,
        None,
    )
    assert extract_versions([fake])[0] == "16.0.10417.20037"
    reportish = {"build": "16.0.10417.20036", "sku": "2019", "results": [fake]}
    findings = evaluate(reportish)
    by_cve = {f.cve: f for f in findings}
    assert by_cve["CVE-2025-53770"].status == STATUS_VULN
    reportish = {"build": "16.0.10417.20037", "sku": "2019", "results": [fake]}
    findings = evaluate(reportish)
    by_cve = {f.cve: f for f in findings}
    assert by_cve["CVE-2025-53770"].status == STATUS_PATCHED
    token = unsigned_jwt()
    assert token.count(".") == 2

    # On-wire 16.0.0.<build> normalization: the header carries the build in the
    # 4th octet with no revision; it must realign and still infer the SKU.
    assert canonical_version("16.0.14326.20450") == ("16.0.14326.20450", True)
    assert canonical_version("16.0.0.14326") == ("16.0.14326.0", False)
    assert canonical_version("15.0.0.4420") == ("15.0.4420.0", False)
    cv, rk = canonical_version("16.0.0.14326")
    assert infer_sku(cv) == "subscription" and rk is False
    # A different BUILD octet settles ToolShell even without a revision.
    ts = {"2016": "16.0.5513.1001", "2019": "16.0.10417.20037", "subscription": "16.0.18526.20508"}
    assert version_status("16.0.14326.0", "subscription", ts, rev_known=False)[0] == STATUS_VULN
    # Exact BUILD match with no on-wire revision must stay unknown, not guess.
    assert version_status("16.0.18526.0", "subscription", ts, rev_known=False)[0] == STATUS_UNKNOWN
    # Same inputs with a known revision resolve normally.
    assert version_status("16.0.18526.20507", "subscription", ts, rev_known=True)[0] == STATUS_VULN
    assert (
        version_status("16.0.18526.20508", "subscription", ts, rev_known=True)[0] == STATUS_PATCHED
    )
    # End to end: a classic header leak -> ToolShell vulnerable for the LAB SE box.
    hdr = HttpResult(
        "service_cnf",
        "GET",
        "http://x/_vti_pvt/service.cnf",
        200,
        "OK",
        {"MicrosoftSharePointTeamServices": "16.0.0.14326"},
        "",
        1,
        None,
    )
    raw = extract_versions([hdr])
    assert raw == ["16.0.0.14326"]
    cv, rk = canonical_version(raw[0])
    findings = evaluate({"build": cv, "sku": infer_sku(cv), "rev_known": rk, "results": [hdr]})
    assert {f.cve: f for f in findings}["CVE-2025-53770"].status == STATUS_VULN

    print("self-test passed")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Non-destructive SharePoint Server CVE status checker"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target base URL or host/IP (e.g. http://host or 10.0.0.5). Required unless --self-test.",
    )
    parser.add_argument("--timeout", type=int, default=8, help="Per-request timeout seconds")
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--output", help="Write JSON report to this file")
    parser.add_argument(
        "--host-header",
        help="Host header to send (for IIS/SharePoint web apps bound to a host header while you scan by IP), e.g. sp-web01",
    )
    parser.add_argument(
        "--insecure-tls",
        action="store_true",
        help="Do not verify TLS certificates (for lab decoys with self-signed certs). "
        "The report records that it was used.",
    )
    # Accepted and ignored: it used to be how you asked for verification, which is now
    # the default. Kept so commands and notes written against the old flag still run.
    parser.add_argument("--strict-tls", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--self-test", action="store_true", help="Run internal mapping tests and exit"
    )
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if not args.target:
        parser.error("target is required (a base URL or host/IP), unless --self-test")

    try:
        report = scan(
            args.target,
            timeout=args.timeout,
            verify_tls=not args.insecure_tls,
            host_header=args.host_header,
        )
    except Exception as e:
        print("scan failed: %s" % e, file=sys.stderr)
        traceback.print_exc()
        return 2

    if args.output:
        with Path(args.output).open("w") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text(report)
        if args.output:
            print("\nJSON written to %s" % args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
