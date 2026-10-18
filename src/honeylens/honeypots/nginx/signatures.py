"""CVE signature catalog for the NGINX honeypot.

Each entry is a small, self-contained matcher over one HTTP request. Matching is
deliberately shape-based (request structure), not exploit-payload equality, so a
signature keeps working as PoCs mutate. Confidence is labelled honestly — some
CVEs (notably CVE-2026-42533, no public PoC yet) are heuristic.

A signature never raises: `CveSignature.match()` swallows matcher exceptions and
returns None, so a malformed request can never crash a worker (that would be a
*real* crash, not the fake-crash oracle).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# thresholds (all overridable in one place)
# ---------------------------------------------------------------------------
API_PREFIX = b"/api/"
FLOOD_THRESHOLD = 8  # min escapable chars in /api/ to count as overflow (42945)
HIGH_CONFIDENCE_RUN = 64
CAPTURE_LEN_THRESHOLD = 512  # 42533: min single-token length to flag a capture overflow
CAPTURE_LEN_HIGH = 2048  # 42533: length above which confidence rises to medium
CHUNK_MAX = 0x7FFFFFFFFFFFFFFF  # 2013-2028: chunk-size above this is overflow-shaped
RANGE_COUNT_MAX = 8  # 2017-7529: this many comma-ranges is the overflow shape
RANGE_BIG_OFFSET = 0x7FFFFFFF  # 2017-7529: a single range offset this large is suspicious

_ESCAPABLE = re.compile(rb"\+|%2[bB]")
_RUN = re.compile(rb"(?:\+|%2[bB])+")
_A_PAD = b"\x41" * 32  # 42945 depthfirst spray pad
# a "capture-like" token: a long run of non-delimiter bytes in a URL/header value
_TOKEN = re.compile(rb"[^/?&=;,\s]+")

# CVE-2024-4577 — PHP-CGI argument injection. The request smuggles CGI switches
# through a soft hyphen (%AD, or the raw 0xAD byte) that Windows code-page
# conversion folds into "-", so `%ADd allow_url_include=1 -d auto_prepend_file=
# php://input` turns the body into executed PHP.
#
# This lives here, in the NGINX catalog, only as a NEGATIVE guard: 42533's
# overflow primitive is length-based, and a 4577 body is always long enough to
# trip it. Observed on sensor-a 2026-08-27 — a textbook 4577 dropper (its own payload
# ends `echo(md5("Hello CVE-2024-4577"))`) was reported as CVE-2026-42533 because
# its base64 blob was 1149 bytes. Attributing a heuristic CVE to a request that
# carries another CVE's unmistakable fingerprint is worse than saying nothing.
_PHP_CGI_ARG_INJECTION = re.compile(
    rb"(?:%AD|\xad)\s*d[+ ]|allow_url_include|auto_prepend_file", re.IGNORECASE
)


@dataclass
class Match:
    """Result of one signature matching one request."""

    indicators: list = field(default_factory=list)
    confidence: str = "low"  # high|medium|low


@dataclass
class CveSignature:
    cve_id: str
    attack_type: str  # emitted label, e.g. "NGINX_CVE_2026_42533"
    attack_class: str  # short class key, e.g. "cve-2026-42533"
    name: str
    module: str
    is_overflow: bool  # True -> memory-corruption -> fake-crash oracle
    matcher: Callable[[str, bytes, dict, bytes, str], Match | None]

    def match(self, method, raw_path, headers, body, http_version) -> Match | None:
        try:
            return self.matcher(method, raw_path, headers, body, http_version)
        except Exception:
            return None


def _hdr(headers: dict, name: str) -> str:
    """Case-insensitive single header lookup."""
    name = name.lower()
    for k, v in headers.items():
        if k.lower() == name:
            return v or ""
    return ""


def _longest_token(raw_path: bytes, headers: dict) -> int:
    """Length of the longest capture-like token in the URI or a host-family header.

    Only the URI and host-family headers are scanned — those are where nginx
    regex-map captures realistically come from. User-Agent/Referer are excluded
    on purpose: they can be legitimately long and would drive false positives.
    """
    best = 0
    for m in _TOKEN.finditer(raw_path):
        best = max(best, len(m.group(0)))
    for name in ("host", "x-forwarded-host", "x-forwarded-for"):
        v = _hdr(headers, name).encode("latin-1", "replace")
        for m in _TOKEN.finditer(v):
            best = max(best, len(m.group(0)))
    return best


def _longest_body_token(body: bytes) -> int:
    """Length of the longest capture-like token in the request body.

    This is the CVE-2026-42533 *overflow* primitive: a POST whose $request_body
    feeds a regex-map capture between two $1 references, so the VALUE pass writes
    more than the LEN pass measured. Scan is capped so a huge body cannot make
    matching expensive.
    """
    best = 0
    for m in _TOKEN.finditer(body[:65536]):
        best = max(best, len(m.group(0)))
    return best


# ---------------------------------------------------------------------------
# matchers
# ---------------------------------------------------------------------------
def _match_42533(method, raw_path, headers, body, http_version) -> Match | None:
    """CVE-2026-42533 — script-engine regex-map capture overflow.

    Two documented primitives (per the shared-r->captures two-pass bug):
      * LEAK     — a long URI / host-header capture value clobbers *undersized*
                   captures, so the VALUE pass reads uninitialised heap residue
                   (info leak / ASLR bypass). Long URI, typically GET.
      * OVERFLOW — a POST whose $request_body regex clobbers r->captures between
                   two $1 refs, so the VALUE pass writes more than LEN measured
                   (attacker-controlled heap overflow). Long token in the body.

    Shape-based (we can't see the server regex config): a long capture-like token
    in the URI/host headers is a leak probe; a long token in a POST/PUT/PATCH body
    is the overflow trigger. detector._resolve_42533 turns these indicators into
    leak (recon) vs overflow (fake-crash oracle). Confidence rises with magnitude.
    """
    # Yield to a request that is unmistakably a different, *published* CVE. This
    # matcher is length-based and 42533 has no public PoC, so it must never be the
    # label on traffic whose own payload identifies it as something else.
    if _PHP_CGI_ARG_INJECTION.search(raw_path or b"") or _PHP_CGI_ARG_INJECTION.search(
        body[:4096] or b""
    ):
        return None

    n_cap = _longest_token(raw_path, headers)
    n_body = _longest_body_token(body) if method.upper() in ("POST", "PUT", "PATCH") else 0
    indicators = []
    if n_body >= CAPTURE_LEN_THRESHOLD:
        indicators.append(f"cve_2026_42533_overflow:{n_body}")
    if n_cap >= CAPTURE_LEN_THRESHOLD:
        indicators.append(f"cve_2026_42533_leak:{n_cap}")
    if not indicators:
        return None
    # per-primitive confidence resolved in detector._resolve_42533
    return Match(indicators, "low")


def _match_42945(method, raw_path, headers, body, http_version) -> Match | None:
    """CVE-2026-42945 "NGINX Rift" — rewrite-module /api/ escape overflow.

    Returns the raw indicators; the caller (classify) decides dos vs rce and
    folds in the SourceTracker correlation, preserving prior behaviour.
    """
    run = 0
    for m in _RUN.finditer(raw_path):
        run = max(run, len(_ESCAPABLE.findall(m.group(0))))
    api_flood = raw_path.startswith(API_PREFIX) and run >= FLOOD_THRESHOLD
    spray = method.upper() == "POST" and len(body) >= 256 and b"\x00" in body and _A_PAD in body
    # X-Delay is only a supporting signal — never an attack on its own.
    if not (api_flood or spray):
        return None
    indicators = []
    if api_flood:
        indicators.append(f"api_escape_flood:{run}")
    if spray:
        indicators.append("pool_spray_body")
    if _hdr(headers, "x-delay"):
        indicators.append("slow_backend_delay_header")
    conf = "high" if (run >= HIGH_CONFIDENCE_RUN or spray) else "medium"
    return Match(indicators, conf)


def _match_2013_2028(method, raw_path, headers, body, http_version) -> Match | None:
    """CVE-2013-2028 — chunked Transfer-Encoding stack overflow.

    Trigger shape: TE: chunked with a chunk-size line that is huge/overflow-shaped.
    """
    if "chunked" not in _hdr(headers, "transfer-encoding").lower():
        return None
    first_line = body.split(b"\r\n", 1)[0].split(b";", 1)[0].strip()
    if not first_line:
        return None
    try:
        size = int(first_line, 16)
    except ValueError:
        return None
    if size > CHUNK_MAX:
        return Match([f"chunked_overflow:{first_line.decode('latin-1')}"], "high")
    return None


def _match_2017_7529(method, raw_path, headers, body, http_version) -> Match | None:
    """CVE-2017-7529 — range filter integer overflow (cache info leak).

    Trigger shape: a Range header with many comma-ranges or a huge/negative offset.
    """
    rng = _hdr(headers, "range")
    if not rng.lower().startswith("bytes="):
        return None
    spec = rng[len("bytes=") :]
    parts = [p for p in spec.split(",") if p.strip()]
    if len(parts) >= RANGE_COUNT_MAX:
        return Match([f"range_int_overflow:{len(parts)}_ranges"], "medium")
    for p in parts:
        m = re.search(r"-?\d{9,}", p)
        if m and abs(int(m.group(0))) >= RANGE_BIG_OFFSET:
            return Match([f"range_int_overflow:offset={m.group(0)}"], "medium")
    return None


def _match_2022_41741(method, raw_path, headers, body, http_version) -> Match | None:
    """CVE-2022-41741/41742 — ngx_http_mp4_module memory corruption probe."""
    path = raw_path.split(b"?", 1)[0]
    if not path.lower().endswith(b".mp4"):
        return None
    qs = raw_path.split(b"?", 1)[1] if b"?" in raw_path else b""
    if b"start=" in qs or b"end=" in qs or _hdr(headers, "range"):
        return Match(["mp4_module_probe"], "low")
    return None


def _match_2021_23017(method, raw_path, headers, body, http_version) -> Match | None:
    """CVE-2021-23017 — nginx resolver off-by-one heap write.

    Tracked for the banner draw and documentation only. This is a bug in how
    nginx parses a *DNS response* from its resolver — it is NOT triggerable by an
    inbound HTTP request to this honeypot — so there is deliberately no match.
    """
    return None


# ---------------------------------------------------------------------------
# the catalog (ordered; classify runs all, keeps the highest-severity match)
# ---------------------------------------------------------------------------
CATALOG = [
    CveSignature(
        "CVE-2026-42945",
        "cve_2026_42945",
        "cve-2026-42945",
        "NGINX Rift",
        "rewrite",
        True,
        _match_42945,
    ),
    CveSignature(
        "CVE-2026-42533",
        "NGINX_CVE_2026_42533",
        "cve-2026-42533",
        "script-engine regex-map overflow",
        "script/expr",
        True,
        _match_42533,
    ),
    CveSignature(
        "CVE-2013-2028",
        "NGINX_CVE_2013_2028",
        "cve-2013-2028",
        "chunked Transfer-Encoding stack overflow",
        "http chunked",
        True,
        _match_2013_2028,
    ),
    CveSignature(
        "CVE-2017-7529",
        "NGINX_CVE_2017_7529",
        "cve-2017-7529",
        "range filter integer overflow",
        "range filter",
        False,
        _match_2017_7529,
    ),
    CveSignature(
        "CVE-2022-41741",
        "NGINX_CVE_2022_41741",
        "cve-2022-41741",
        "ngx_http_mp4_module memory corruption",
        "mp4",
        False,
        _match_2022_41741,
    ),
    CveSignature(
        "CVE-2021-23017",
        "NGINX_CVE_2021_23017",
        "cve-2021-23017",
        "resolver off-by-one heap write",
        "resolver",
        False,
        _match_2021_23017,
    ),
]
