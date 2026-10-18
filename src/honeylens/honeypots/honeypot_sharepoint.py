#!/usr/bin/env python3
"""
honeypot_sharepoint.py — on-prem Microsoft SharePoint Server decoy
==================================================================
A passive, high-fidelity decoy for on-prem SharePoint Server (2016 / 2019 /
Subscription Edition). It answers with authentic IIS/SharePoint response headers and
plausible bodies, and **records the full request from every caller** — method, path, query,
every header verbatim, and the whole body (payloads included: on a honeypot the captured
payload *is* the evidence; see ``honeylens.honeypots.body_capture``).

It is a decoy, not a target. It never executes anything a caller sends, never deserializes a
``__VIEWSTATE`` / people-picker gadget, and never serves a real ``MachineKey``.

Design:

* **Anonymous on the exploit surfaces** (decided 2026-10-06): ``ToolPane.aspx`` (with the
  SignOut Referer bypass tell), ``Picker.aspx``, ``/_api/*``, ``spinstall0.aspx`` answer
  without an NTLM 401 so the ToolShell chain proceeds and the honeytoken pays off. Background
  paths (``/``, ``/_vti_*``) keep the NTLM 401, as the measured box does.
* **MachineKey honeytoken.** ``spinstall0.aspx`` returns a synthetic, per-deployment
  ``ValidationKey``/``DecryptionKey`` (never real). A later ``__VIEWSTATE`` whose HMAC
  validates against that key is tagged CRITICAL — the confirmed ToolShell stage two.

Surfaces served so probes land and get tagged (surface / behaviour / candidate CVE, the
NetScaler layering — a bare path visit is recon, not exploitation):

* CVE-2025-53770 / 53771 "ToolShell" — ``POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit``
  with ``Referer: …/SignOut.aspx``; then ``spinstall0.aspx`` key theft; then a forged
  ``__VIEWSTATE``.
* CVE-2023-29357 — ``/_api/*`` with a forged OAuth token: ``alg:none``, an empty signature,
  an ``X-PROOF_TOKEN`` header, or the SharePoint principal in ``aud``/``iss`` (B4). The CPE
  lists 2019 only, but this decoy keeps the tag on the advertised SE build **by decision
  (2026-10-06)** — the LAB is configured 29357-vulnerable on SE and the auth-bypass technique
  itself carries the capture value.
* CVE-2026-55040 — ``POST /_api/contextinfo`` FormDigest surface (B6); served, no behaviour.
* CVE-2019-0604 — ``Picker.aspx`` XML gadget markers inc. ``XamlReader``/``ExpandedWrapper``
  (B8), served as a recon surface; on a Subscription Edition build this CVE is out of scope —
  SE postdates the 2019 fix.
* CVE-2026-65660 — gallery endpoints (``AddGallery``/``designgallery`` + ``job=all`` +
  ``MSOTlPn_*``) and a duplicate-``Register`` / oversized-body smuggle heuristic (B5).

Discovery/entry surfaces served so the box does not 404-fingerprint itself: ``spdisco.aspx``
and ``/_layouts/15/start.aspx`` (B7).

Entry point ``honeylens-hp sharepoint`` (or ``python -m honeylens.honeypots.honeypot_sharepoint``).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import ssl
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from aiohttp import web

from honeylens.eventlog_lock import append_line
from honeylens.honeypots import deception_waf, proxy_protocol
from honeylens.honeypots import sharepoint_profile as profile
from honeylens.honeypots.body_capture import capture as capture_body
from honeylens.honeypots.netscaler_eventlog import EventLog

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("sharepoint-honeypot")

# --- appliance identity -----------------------------------------------------------------
# The ON-WIRE build form: MicrosoftSharePointTeamServices carries the build as the LAST field
# of 16.0.0.<build> (4th octet; the published 16.0.<build>.<rev> form puts it 3rd), revision
# absent. 16.0.0.14326 is the Subscription Edition RTM line — below every ToolShell
# fix (SE fixed at 16.0.18526.20508), so the box reads as exploitable. Override via env.
DEFAULT_VERSION = os.environ.get("SHAREPOINT_VERSION", "SharePoint Subscription Edition")
DEFAULT_BUILD = os.environ.get("SHAREPOINT_BUILD", "16.0.0.14326")

# Realistic on-prem SharePoint hostnames; the self-signed cert's CN is drawn from here so it
# is not a fleet-wide fingerprint (the NetScaler lesson).
_HOST_PREFIXES = ("sp", "portal", "intranet", "teams", "sites", "collab", "docs", "spweb")

DEFAULT_LOG_FILE = os.environ.get("SHAREPOINT_LOG_FILE", "")
DEFAULT_PORTS = [443, 80]  # protocol ports; the manifest binds them high (51443 / 51080)

MAX_BODY = int(os.environ.get("SHAREPOINT_CLIENT_MAX_SIZE", 8 * 1024 * 1024))
# B12: the ToolShell confirmed stage-two (a __VIEWSTATE forged with the honeytoken MachineKey,
# carrying the serialized .NET gadget) runs ~535 KB on the wire — far past the fleet-wide 64 KiB
# raw/body ceiling, which would truncate away the single most valuable payload this decoy sees.
# So a PER-HONEYPOT high-value budget (768 KiB covers the observed stage-two with headroom),
# SHAREPOINT_RAW_CAPTURE_BYTES overridable.
_RAW_CAPTURE = int(
    os.environ.get(
        "SHAREPOINT_RAW_CAPTURE_BYTES",
        os.environ.get("HONEYPOT_RAW_CAPTURE_BYTES", 768 * 1024),
    )
)
# ...but the big budget is reserved for the CONFIRMED stage-two only — a __VIEWSTATE forged with
# our honeytoken MachineKey, severity CRITICAL, the ~535 KB payload B12 exists for. An attacker
# cannot reach that without first completing the ToolPane -> spinstall0 honeytoken chain to obtain
# the key, so they cannot cheaply force 768 KiB captures by stuffing a big body with a trivial
# marker (resource-cap-defeat guard). Every other request — any lower-severity tag, or none —
# keeps the fleet-wide 64 KiB default.
_RAW_CAPTURE_DEFAULT = int(os.environ.get("HONEYPOT_RAW_CAPTURE_BYTES", 64 * 1024))


def _capture_budget(tag: dict[str, Any]) -> int:
    """How many bytes of this request to retain: the high-value budget only for the CRITICAL
    confirmed stage-two (the forged-honeytoken __VIEWSTATE), otherwise the fleet-wide default."""
    return _RAW_CAPTURE if tag.get("severity") == "CRITICAL" else _RAW_CAPTURE_DEFAULT


def _identity_dir() -> Path | None:
    """The per-deployment identity directory, or None when unconfigured. The TLS cert's
    directory when the launcher set one (the manifest mounts an identity volume), else
    SHAREPOINT_DATA_DIR. Returns None when neither is set — so importing the module (tests,
    mypy) never writes identity files into the current working directory."""
    cert = os.environ.get("SHAREPOINT_TLS_CERT", "").strip()
    if cert:
        return Path(cert).parent
    data_dir = os.environ.get("SHAREPOINT_DATA_DIR", "").strip()
    return Path(data_dir) if data_dir else None


def _persisted(name: str, make: Callable[[], str]) -> str:
    """Read a per-deployment value from the identity dir, or generate and persist it once, so
    it is stable across restarts and differs per sensor. When no identity dir is configured
    (bare import / tests), or it is read-only, the value is ephemeral and nothing is written."""
    directory = _identity_dir()
    if directory is None:
        return make()  # no side effects on import
    path = directory / name
    try:
        existing = path.read_text().strip()
        if existing:
            return existing
    except OSError:
        pass
    value = make()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n")
        path.chmod(0o600)
    except OSError:
        pass  # read-only identity dir: ephemeral, still unique per start
    return value


def _deployment_hostname() -> str:
    explicit = os.environ.get("SHAREPOINT_HOSTNAME", "").strip()
    if explicit:
        return explicit
    return _persisted(
        "sp_hostname",
        lambda: f"{secrets.choice(_HOST_PREFIXES)}{secrets.randbelow(90) + 10}",
    )


def _deployment_realm() -> str:
    """The tenant realm GUID leaked in the /_api Bearer challenge — per-deployment."""
    import uuid

    return _persisted("sp_realm", lambda: str(uuid.uuid4()))


def _honeytoken_keys() -> tuple[str, str]:
    """A synthetic MachineKey (ValidationKey, DecryptionKey) persisted per deployment. FAKE —
    never a real key. Served by the fake spinstall0.aspx; a __VIEWSTATE signed with the
    ValidationKey is the confirmed ToolShell stage two."""
    # Both 32 bytes (64 hex), matching the spinstall0 dump format (A1).
    validation = _persisted("sp_validation_key", lambda: secrets.token_hex(32))
    decryption = _persisted("sp_decryption_key", lambda: secrets.token_hex(32))
    return validation, decryption


DEFAULT_HOSTNAME = _deployment_hostname()


# --- detection: surface vs. behaviour vs. candidate CVE ---------------------------------
# path substring (lowercased) -> surface label. Order matters; first hit wins.
_SURFACES: tuple[tuple[str, str], ...] = (
    ("/_layouts/15/toolpane.aspx", "toolshell-toolpane"),
    ("/_layouts/15/signout.aspx", "signout"),
    ("spinstall", "webshell-aspx"),
    ("picker.aspx", "people-picker"),
    ("/_trust", "sts-trust"),
    ("/_api/contextinfo", "rest-contextinfo"),
    ("/_api/", "rest-api"),
    ("/_api", "rest-api"),
    ("/_vti_bin/spdisco.aspx", "fpse-discovery"),
    ("/_vti_pvt/service.cnf", "fpse-service-cnf"),
    ("/_vti_", "fpse-recon"),
    ("/_layouts/15/start.aspx", "spa-start"),
    ("/_layouts/", "layouts"),
)

# The ToolShell webshells reported in the wild, anchored on their names — NOT a broad
# "any .aspx under _layouts", which would flag legitimate SharePoint pages (ToolPane.aspx,
# Picker.aspx, …) as webshells (the SMB/Modbus bare-substring lesson). Detecting a novel
# webshell name is a tuning follow-up, not a greedy regex here.
_WEBSHELL_ASPX_RE = re.compile(r"/_layouts/15/(spinstall\d*|spinstall\w*|ghostfile\w*)\.aspx", re.I)
# Serialized-XML / gadget markers in a people-picker body (CVE-2019-0604). B8 adds the
# ExpandedWrapper/XamlReader/PickerDialogType tells seen in the public PoCs alongside the
# ResourceDictionary/ObjectDataProvider ones — the decoy never parses the XAML, only tags it.
_PICKER_GADGET_RE = re.compile(
    rb"hiddenspandata|ObjectDataProvider|ResourceDictionary|System\.Windows\.Data"
    rb"|TypeConfuseDelegate|ExpandedWrapper|XamlReader|PickerDialogType",
    re.I,
)
# Generic post-exploitation command markers (entry-CVE-agnostic).
_CMD_MARKERS = re.compile(rb"cmd\s*/c|powershell|\bIEX\b|System\.Diagnostics\.Process", re.I)
# B2: the ToolShell web-part registration payload in a ToolPane POST body — a stronger,
# higher-confidence tier than the bare SignOut-Referer surface, and the ToolShell stage-one tell.
_MSOTLPN_RE = re.compile(rb"MSOTlPn_(DWP|Uri)", re.I)
# B1 (CVE-2026-50522): a BinaryFormatter / .NET gadget stream in a WS-Federation `wresult`.
# The decoy NEVER deserialises it — these markers only tag the attempt.
_BINARYFORMATTER_RE = re.compile(
    rb"AAEAAAD/////|System\.Runtime\.Remoting|ObjectDataProvider|TypeConfuseDelegate"
    rb"|ResourceDictionary|System\.Windows\.Data|BinaryFormatter",
    re.I,
)
# B5 (CVE-2026-65660): a gallery-endpoint web-part import. The on-wire tell is a duplicate
# `<%@ Register %>` directive (two+ registrations smuggle the attacker's control) and/or an
# oversized aspx body. The decoy never renders the control, only tags the attempt.
_REGISTER_RE = re.compile(rb"<%@\s*Register", re.I)
_ASPX_BODY_MAX = 100 * 1024

# B3: how long a ToolPane POST keeps a source "exploited" (honeytoken served) — ~30 min —
# and a hard cap on how many sources we track, so an internet-facing decoy hammered 24/7
# cannot grow the flip map without bound (resource exhaustion).
_FLIP_TTL = 1800.0
_FLIP_MAX = 4096

# B9: canonicalise a path before matching so detection is not evaded by trivial variants.
_MULTISLASH_RE = re.compile(r"/{2,}")
_LAYOUTS_VER_RE = re.compile(r"/_layouts/1[56]/")


def _normalize(path: str) -> str:
    """Lowercase, collapse repeated slashes (``//`` -> ``/``), and fold the two SharePoint
    layout roots (``/_layouts/15/`` and ``/_layouts/16/``) to one. Without this
    ``/_layouts/16/ToolPane.aspx`` and ``//_layouts/15/...`` slip past every rule (B9)."""
    low = _MULTISLASH_RE.sub("/", path.lower())
    return _LAYOUTS_VER_RE.sub("/_layouts/15/", low)


_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _surface(low_path: str) -> str | None:
    for needle, label in _SURFACES:
        if needle in low_path:
            return label
    return None


def _b(behaviour: str, severity: str, confidence: str, cve: str) -> dict[str, Any]:
    return {"behaviour": behaviour, "severity": severity, "confidence": confidence, "cve": cve}


def _jwt_seg(seg: str) -> dict:
    """Decode a base64url JWT segment to a dict, tolerating padding/garbage."""
    try:
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return {}


def _jwt_auth_bypass(headers: dict[str, str]) -> bool:
    """CVE-2023-29357 auth-bypass tells on a forged OAuth token (B4): an ``X-PROOF_TOKEN``
    header, or a Bearer JWT that is unsigned (``alg:none``), has an empty signature, or carries
    the well-known SharePoint principal in ``aud``/``iss`` followed by ``@``. Decoded without
    trusting the token's contents; nothing is verified or executed."""
    if headers.get("X-PROOF_TOKEN"):
        return True
    auth = headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return False
    parts = auth[7:].strip().split(".")
    if len(parts) < 2:
        return False
    if str(_jwt_seg(parts[0]).get("alg", "")).lower() == "none":
        return True
    if len(parts) >= 3 and parts[2] == "":  # empty signature
        return True
    payload = _jwt_seg(parts[1])
    principal = f"{profile.SHAREPOINT_PRINCIPAL}@"
    return any(principal in str(payload.get(claim, "")) for claim in ("aud", "iss"))


def _form_field(body: bytes, name: str) -> str | None:
    """First value of a urlencoded form field, or None."""
    try:
        parsed = parse_qs(body.decode("latin-1"), keep_blank_values=True)
    except (ValueError, UnicodeDecodeError):
        return None
    vals = parsed.get(name, [])
    return vals[0] if vals else None


def _viewstate_signed_with_key(body: bytes, validation_key: str | None) -> bool:
    """Best-effort: does the ``__VIEWSTATE`` in this form carry an HMAC-SHA256 MAC computed
    with OUR honeytoken ValidationKey? A match is the confirmed ToolShell stage two — the
    attacker read our fake key and forged a signed ViewState.

    Covers the common case where the MAC is ``HMACSHA256(state)`` with no extra modifier.
    Full ASP.NET MAC parity (VIEWSTATEGENERATOR modifier / purpose string) is a follow-up
    once we see real stage-two payloads in the corpus; until then a non-match is inconclusive,
    never a false negative we rely on.
    """
    if not validation_key:
        return False
    raw_b64 = _form_field(body, "__VIEWSTATE")
    if not raw_b64:
        return False
    try:
        raw = base64.b64decode(raw_b64, validate=False)
        key = bytes.fromhex(validation_key)
    except (binascii.Error, ValueError):
        return False
    if len(raw) <= 32:
        return False
    state, mac = raw[:-32], raw[-32:]
    computed = hmac.new(key, state, hashlib.sha256).digest()
    return hmac.compare_digest(mac, computed)


def _behaviours(
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    body: bytes,
    validation_key: str | None = None,
) -> list[dict[str, Any]]:
    """Concrete tells in the request, each with its own severity/confidence/candidate CVE.
    Returns ALL matches, not the first — a generic surface must not mask a stronger payload."""
    low = _normalize(path)
    low_q = query.lower()
    out: list[dict[str, Any]] = []

    # ToolShell: the specific tell is ToolPane.aspx + the SignOut.aspx Referer (auth bypass).
    # Tiered (B2): the bare SignOut-Referer surface, and — stronger — a POST carrying the
    # MSOTlPn_DWP / MSOTlPn_Uri web-part registration payload (the actual stage-one injection).
    if "/_layouts/15/toolpane.aspx" in low:
        referer = headers.get("Referer", "").lower()
        if "signout.aspx" in referer:
            out.append(_b("toolshell-signout-bypass", "HIGH", "medium", "CVE-2025-53770"))
        if method == "POST" and _MSOTLPN_RE.search(body):
            out.append(_b("toolshell-webpart-inject", "HIGH", "high", "CVE-2025-53770"))

    # B1 (CVE-2026-50522): WS-Federation sign-in to /_trust carrying a BinaryFormatter wresult.
    if "/_trust" in low:
        signin = "wa=wsignin1.0" in low_q or b"wsignin1.0" in body.lower()
        if signin and _BINARYFORMATTER_RE.search(body):
            out.append(_b("trust-wsfed-binaryformatter", "HIGH", "medium", "CVE-2026-50522"))

    # Webshell drop/fetch under _layouts (spinstall0, ghostfile, random aspx) — post-exploitation.
    if _WEBSHELL_ASPX_RE.search(low):
        out.append(_b("webshell-aspx", "HIGH", "medium", "CVE-2025-53770"))

    # Confirmed stage two: a __VIEWSTATE signed with our honeytoken MachineKey.
    if method == "POST" and _viewstate_signed_with_key(body, validation_key):
        out.append(_b("viewstate-forged-honeytoken", "CRITICAL", "high", "CVE-2025-53770"))

    # Deception: a client reflected our fake-vendor WAF canary (header name/value) back into
    # a request — it parsed a prior response and acted on it. The vendor is fictional, so an
    # inbound occurrence has no legitimate source; treat it as a canary callback.
    canary_hay = b" ".join(
        [low.encode(), low_q.encode(), repr(sorted(headers.items())).encode(), body]
    )
    if deception_waf.is_canary_callback(canary_hay):
        out.append(_b("waf-canary-callback", "HIGH", "high", ""))

    # CVE-2023-29357: a forged OAuth token on the REST API — alg:none, empty signature,
    # an X-PROOF_TOKEN header, or the SharePoint principal smuggled into aud/iss (B4).
    if low.startswith("/_api") and _jwt_auth_bypass(headers):
        out.append(_b("api-unsigned-jwt", "HIGH", "medium", "CVE-2023-29357"))

    # CVE-2019-0604: people-picker XML-deserialization gadget markers.
    if "picker.aspx" in low and _PICKER_GADGET_RE.search(body):
        out.append(_b("picker-xml-deser", "HIGH", "medium", "CVE-2019-0604"))

    # B5 (CVE-2026-65660): a gallery endpoint (AddGallery/designgallery) with job=all and the
    # MSOTlPn_* web-part payload is the stage-one tell; separately, a duplicate `<%@ Register %>`
    # directive or an oversized .aspx POST body flags the smuggled-control attempt on its own.
    if (
        ("addgallery.aspx" in low or "designgallery.aspx" in low)
        and ("job=all" in low_q or b"job=all" in body.lower())
        and _MSOTLPN_RE.search(body)
    ):
        out.append(_b("gallery-webpart-rce", "HIGH", "medium", "CVE-2026-65660"))
    if (
        method == "POST"
        and low.endswith(".aspx")
        and (len(body) > _ASPX_BODY_MAX or len(_REGISTER_RE.findall(body)) >= 2)
    ):
        out.append(_b("aspx-register-smuggle", "MEDIUM", "low", "CVE-2026-65660"))

    # Entry-CVE-agnostic post-exploitation command markers in an .aspx POST body.
    if method == "POST" and low.endswith(".aspx") and _CMD_MARKERS.search(body):
        out.append(_b("aspx-command-markers", "MEDIUM", "low", "CVE-2026-65660"))

    return out


def _classify(
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    body: bytes,
    validation_key: str | None = None,
) -> dict[str, Any]:
    """Describe a probe in layers. Always returns the surface; attack_type/severity/CVEs are
    set only when a behaviour is present, so a bare surface does not pre-empt the host-side
    classifier or raise a false CRITICAL."""
    surface = _surface(_normalize(path))
    matches = _behaviours(method, path, query, headers, body, validation_key)
    tag: dict[str, Any] = {"surface": surface, "matches": matches}
    if matches:
        primary = max(matches, key=lambda m: _SEVERITY_RANK.get(m["severity"], 0))
        tag["attack_type"] = f"sp-{primary['behaviour']}"
        tag["severity"] = primary["severity"]
        tag["confidence"] = primary["confidence"]
        seen: list[str] = []
        for m in matches:
            if m["cve"] and m["cve"] not in seen:
                seen.append(m["cve"])
        tag["rules"] = seen
    return tag


def capability_matrix() -> dict[str, dict[str, Any]]:
    """Honest coverage per CVE: a CVE string is not emulation. Each row states whether the
    surface is served, whether a behavioural signature exists, and whether a response is
    emulated (the decoy never executes the flaw)."""

    def row(served: bool, signature: bool, emulated: bool) -> dict[str, Any]:
        return {
            "transport": "http",
            "surface_served": served,
            "request_captured": served,
            "behaviour_signature": signature,
            "response_emulated": emulated,
        }

    return {
        "CVE-2025-53770": row(True, True, False),  # ToolPane SignOut bypass + honeytoken stage two
        "CVE-2025-53771": row(True, True, False),  # same chain
        "CVE-2023-29357": row(
            True, True, False
        ),  # forged OAuth: alg:none/empty-sig/proof/aud@ (B4)
        "CVE-2019-0604": row(True, True, False),  # picker gadget markers inc. XamlReader (B8)
        "CVE-2026-50522": row(True, True, False),  # /_trust WS-Fed BinaryFormatter wresult
        "CVE-2026-55040": row(True, False, False),  # /_api/contextinfo surface served (B6)
        "CVE-2026-65660": row(
            True, True, False
        ),  # gallery endpoints + register-smuggle heuristic (B5)
    }


def _request_guid() -> str:
    """A per-request SPRequestGuid, as IIS/SharePoint attaches."""
    import uuid

    return str(uuid.uuid4())


def _http_client_ip(peer_ip: str, remote_ip: str, forwarded: str, trusted_value: str) -> str:
    """Resolve an HTTP-proxied client without trusting attacker-supplied headers."""
    if not trusted_value or not forwarded:
        return remote_ip
    trusted = proxy_protocol.parse_trusted(trusted_value)
    try:
        peer_address = ipaddress.ip_address(peer_ip)
    except ValueError:
        return remote_ip
    if trusted != "all" and not any(peer_address in network for network in trusted):
        return remote_ip
    try:
        return str(ipaddress.ip_address(forwarded))
    except ValueError:
        logger.warning("ignored invalid X-Real-IP from trusted HTTP proxy")
        return remote_ip


class SharePointHoneypot:
    """On-prem SharePoint Server decoy. Captures every request."""

    def __init__(self, log_file: str = DEFAULT_LOG_FILE):
        self.log_file = log_file
        self.build = DEFAULT_BUILD
        self.realm = _deployment_realm()
        self._vkey, self._dkey = _honeytoken_keys()
        self._sink = self._load_sink()
        self._eventlog: EventLog | None = None
        # B3 honeytoken state-flip: source IP -> monotonic time of its last ToolPane POST
        # (ToolShell stage one). spinstall0 serves the MachineKey only to a source that has
        # exploited ToolPane within FLIP_TTL; a cold scanner probing spinstall0 gets a clean box.
        self._flip: dict[str, float] = {}

    @staticmethod
    def _load_sink():
        try:
            from honeylens.honeypots import sink

            return sink
        except Exception as exc:  # pragma: no cover - standalone without the package
            logger.info("sink unavailable (%s); logging to stdout/file only", exc)
            return None

    def _client_ip(self, request: web.Request) -> tuple[str, int]:
        """Resolve the real (src_ip, src_port). PROXY-protocol real IP is already applied by the
        listener; here we also honour X-Real-IP from a trusted HTTP proxy, never from a direct
        client."""
        peer = request.transport.get_extra_info("peername") if request.transport else None
        src_ip = request.remote or (peer[0] if peer else "0.0.0.0")
        if peer:
            src_ip = _http_client_ip(
                peer[0],
                src_ip,
                request.headers.get("X-Real-IP", "").strip(),
                os.environ.get("HONEYLENS_HTTP_PROXY", "").strip(),
            )
        src_port = peer[1] if peer and len(peer) > 1 else 0
        return src_ip, src_port

    def _record_flip(self, src_ip: str) -> None:
        """Mark a source as exploited (ToolPane POST), keeping the map bounded: drop expired
        entries, and if still over the cap evict the oldest. Prevents unbounded growth under a
        flood of distinct sources (resource exhaustion on an internet-facing decoy)."""
        now = time.monotonic()
        self._flip[src_ip] = now
        if len(self._flip) > _FLIP_MAX:
            cutoff = now - _FLIP_TTL
            self._flip = {k: v for k, v in self._flip.items() if v >= cutoff}
            if len(self._flip) > _FLIP_MAX:
                oldest = sorted(self._flip, key=self._flip.__getitem__)[
                    : len(self._flip) - _FLIP_MAX
                ]
                for k in oldest:
                    self._flip.pop(k, None)

    def _source_flipped(self, src_ip: str) -> bool:
        """B3: True when this source POSTed to ToolPane (ToolShell stage one) within FLIP_TTL —
        i.e. it is a real operator mid-chain, not a cold scanner probing spinstall0."""
        ts = self._flip.get(src_ip)
        if ts is None:
            return False
        if time.monotonic() - ts > _FLIP_TTL:
            self._flip.pop(src_ip, None)  # expired; prune
            return False
        return True

    async def _record(self, request: web.Request, event_type: str) -> bytes:
        """Read and record the request. Returns the body for the handler."""
        read_error: str | None = None
        try:
            body = await request.read()
        except Exception as exc:  # disconnect, bad chunking, decode, limit…
            body = b""
            read_error = type(exc).__name__

        headers_ordered = [
            [k.decode("latin-1"), v.decode("latin-1")] for k, v in request.raw_headers
        ]
        headers = dict(request.headers)
        src_ip, src_port = self._client_ip(request)
        sock = request.transport.get_extra_info("sockname") if request.transport else None
        local_port = sock[1] if sock and len(sock) > 1 else 0
        scheme = request.scheme

        # Capture is sacred: a classification bug or crafted input must never stop the event
        # being recorded (fail-CLOSED on capture, not fail-open). Classify defensively; on any
        # error record the request untagged plus the error, so nothing escapes the log.
        classify_error: str | None = None
        try:
            tag = _classify(
                request.method, request.path_qs, request.query_string, headers, body, self._vkey
            )
        except Exception as exc:  # pragma: no cover - defensive; _classify is already guarded
            logger.warning(
                "classify failed (%s); capturing the request untagged", type(exc).__name__
            )
            tag = {"surface": None, "matches": []}
            classify_error = type(exc).__name__

        event: dict[str, Any] = {
            "honeypot": "sharepoint",
            "event_type": event_type,
            "method": request.method,
            "path": request.path,
            "query": request.query_string,
            "scheme": scheme,
            "http_version": f"{request.version.major}.{request.version.minor}",
            "headers_ordered": headers_ordered,
            "headers": headers,
            "surface": tag.get("surface"),
            "capture_complete": read_error is None,
            **capture_body(
                body,
                request.path,
                headers.get("Content-Type", ""),
                max_capture=_capture_budget(tag),
            ),
        }
        if read_error:
            event["read_error"] = read_error
        if classify_error:
            event["classify_error"] = classify_error
        if tag.get("matches"):
            event["matches"] = tag["matches"]
            event["candidate_cves"] = tag.get("rules")

        head = f"{request.method} {request.path_qs} HTTP/{event['http_version']}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in headers_ordered) + "\r\n"
        raw = head.encode("latin-1", "replace") + body

        payload = (
            body[:2000].decode("utf-8", "replace")
            if body
            else f"{request.method} {request.path_qs}"
        )
        self._emit(
            event=event,
            payload=payload,
            raw=raw,
            peer=(src_ip, src_port),
            dst_port=local_port,
            scheme=scheme,
            tag=tag,
        )
        logger.info(
            "[%s] %s %s %s body=%s%s%s",
            event_type,
            src_ip,
            request.method,
            request.path,
            event.get("body_len", 0),
            f" read_error={read_error}" if read_error else "",
            f" {tag['rules'][0]}" if tag.get("rules") else "",
        )
        return body

    def _emit(self, *, event, payload, raw, peer, dst_port, scheme, tag) -> None:
        """Fan the event out: HoneyLens sink (if present), stdout JSON, optional log file."""
        protocol = scheme
        confidence = tag.get("confidence")
        if self._sink is not None:
            record = self._sink.build_record(
                source="sharepoint",
                honeypot="sharepoint",
                protocol=protocol,
                peer=peer,
                event=event,
                payload=payload,
                dst_port=dst_port or None,
                raw=raw,
                raw_capture_bytes=_capture_budget(tag),
                attack_type=tag.get("attack_type"),
                severity=tag.get("severity"),
                confidence=confidence,
                rules=tag.get("rules"),
            )
        else:
            record = {
                "schema": "honeylens-event/1",
                "timestamp": datetime.now(UTC).isoformat(),
                "source": "sharepoint",
                "honeypot": "sharepoint",
                "protocol": protocol,
                "peer_ip": peer[0],
                "peer_port": peer[1],
                "dst_port": dst_port,
                "payload": payload[:2000],
                "event": event,
                "raw_hex": raw[: _capture_budget(tag)].hex(),
            }
            if tag.get("attack_type"):
                record["attack_type"] = tag["attack_type"]
                record["severity"] = tag.get("severity")
                record["confidence"] = confidence
                record["rules"] = tag.get("rules")

        if self._eventlog is not None:
            self._eventlog.submit(record)
            return

        if self._sink is not None:
            try:
                if not self._sink.write_record(record):
                    logger.error("sink write_record returned False — event not persisted")
            except Exception as exc:  # pragma: no cover - disk/volume issue
                logger.error("sink write failed: %s", exc)
        line = json.dumps(record, default=str, separators=(",", ":"))
        print(line, flush=True)
        if self.log_file:
            try:
                append_line(self.log_file, line)
            except OSError as exc:
                logger.error("sharepoint log file write failed (%s): %s", self.log_file, exc)

    # -- the single, case-insensitive dispatcher (IIS paths are case-insensitive) ----------
    async def handle(self, request: web.Request) -> web.Response:
        await self._record(request, "REQUEST")
        low = _normalize(request.path)
        rg = _request_guid()
        src_ip, _ = self._client_ip(request)

        # B3: a ToolPane POST (ToolShell stage one) flips this source into "exploited" for 30 min,
        # which is the gate on serving the MachineKey below.
        if request.method == "POST" and "/_layouts/15/toolpane.aspx" in low:
            self._record_flip(src_ip)

        # Response shape mirrors the measured anonymous-browsing box (docs: measured 2026-10-06).
        # The exploit *detection* is in _classify (already run); the response only has to look
        # like a real, exploitable SharePoint so the chain proceeds.
        if low in ("/", ""):
            host = request.headers.get("Host", DEFAULT_HOSTNAME)
            return profile.redirect_home(self.build, request_guid=rg, host=host)
        if low == "/sitepages/home.aspx":
            return profile.home_page(self.build, request_guid=rg)
        if low == "/_layouts/15/start.aspx":
            # B7: the modern SPA entry page. A plain 200 team-site shell under _layouts.
            return profile.start_page(self.build, request_guid=rg)
        if low == "/_vti_bin/spdisco.aspx":
            # B7: the FrontPage/WS discovery document — 200 text/xml <discovery>/<contractRef>.
            return profile.spdisco(self.build, request_guid=rg)
        if low == "/_vti_pvt/service.cnf":
            return profile.service_cnf(self.build, request_guid=rg)
        if low.startswith("/_trust"):
            # WS-Federation STS surface (CVE-2026-50522). Serve the sign-in page; never
            # deserialise a wresult — _classify tags a BinaryFormatter wresult.
            return profile.trust_signin_page(self.build, request_guid=rg)
        if "/_layouts/15/toolpane.aspx" in low:
            # Anonymous box: ToolPane answers 200 whether or not the SignOut Referer is present
            # (measured). The SignOut-Referer bypass is tagged by _classify, not gated here.
            return profile.toolpane_edit(self.build, request_guid=rg)
        if "spinstall" in low:
            # B3: the crypto-dumper serves the MachineKey honeytoken ONLY to a source that has
            # POSTed to ToolPane within the last 30 min (a real operator mid-chain). A cold
            # scanner probing spinstall0 gets a clean-box 404 — so the token never reads as fake.
            if self._source_flipped(src_ip):
                return profile.spinstall0_dump(
                    self.build,
                    request_guid=rg,
                    validation_key=self._vkey,  # gitleaks:allow — kwarg name, not a secret value
                    decryption_key=self._dkey,  # gitleaks:allow — kwarg name, not a secret value
                )
            return profile.not_found(self.build, request_guid=rg)
        if _WEBSHELL_ASPX_RE.search(low):
            # Other implant names (ghostfile*, …) are an implant PROBE, not a key harvest — never
            # serve the key here (A3). The attempt is still captured and tagged webshell-aspx.
            return profile.not_found(self.build, request_guid=rg)
        if "picker.aspx" in low:
            return profile.picker_form(self.build, request_guid=rg)
        if low == "/_api/contextinfo":
            # B6 (CVE-2026-55040 surface): the FormDigest/context endpoint. A POST gets a context
            # JSON whose LibraryVersion agrees with the advertised build; a GET keeps IIS's 403.
            if request.method == "POST":
                return profile.contextinfo(self.build, request_guid=rg)
            return profile.api_ntlm_challenge(self.build, request_guid=rg)
        if low.startswith("/_api"):
            # No bearer -> 401 NTLM (measured); a presented Bearer -> the realm-leaking 401.
            if request.headers.get("Authorization", "").lower().startswith("bearer "):
                return profile.api_bearer_challenge(self.build, request_guid=rg, realm=self.realm)
            return profile.api_ntlm_challenge(self.build, request_guid=rg)
        if low.startswith("/_vti"):
            return profile.ntlm_challenge(self.build, request_guid=rg)
        if request.method == "POST" and low.endswith(".aspx"):
            return profile.error_500(self.build, request_guid=rg)
        return profile.not_found(self.build, request_guid=rg)

    def setup_routes(self, app: web.Application) -> None:
        app.on_response_prepare.append(profile.enforce_server_policy)
        app.router.add_route("*", "/{tail:.*}", self.handle)


def _ensure_cert(cert: str, key: str) -> bool:
    if os.path.exists(cert) and os.path.exists(key):
        return True
    try:
        from honeylens.honeypots.cli import ensure_self_signed

        return ensure_self_signed(Path(cert), Path(key), DEFAULT_HOSTNAME)
    except Exception as exc:
        logger.warning("could not generate a self-signed cert (%s); falling back to HTTP", exc)
        return False


def _mask_server_banner() -> None:
    """Make aiohttp's default ``Server`` the IIS banner everywhere — including the 400/413/431
    responses it generates before the app runs, which the per-response hook cannot reach."""
    try:
        from aiohttp import web_response

        web_response.SERVER_SOFTWARE = "Microsoft-IIS/10.0"
    except Exception as exc:  # pragma: no cover
        logger.debug("could not mask aiohttp banner: %s", exc)


def _proto_for(bind_port: int) -> tuple[int, str]:
    """(protocol_port, scheme) for a bind port, from HONEYLENS_PORT_MAP. Port 80 is the only
    cleartext scheme; everything else is TLS."""
    mapping = {}
    for entry in os.environ.get("HONEYLENS_PORT_MAP", "").split(","):
        if ":" in entry:
            b, _, p = entry.partition(":")
            mapping[int(b)] = int(p)
    proto = mapping.get(bind_port, bind_port)
    return proto, ("http" if proto == 80 else "https")


async def run_server(host: str, ports: list[int], *, use_tls: bool = True) -> None:
    _mask_server_banner()
    hp = SharePointHoneypot()
    hp._eventlog = EventLog(sink=hp._sink, log_file=hp.log_file)
    await hp._eventlog.start()
    app = web.Application(client_max_size=MAX_BODY)
    hp.setup_routes(app)

    ssl_ctx = None
    if use_tls:
        cert = os.environ.get("SHAREPOINT_TLS_CERT", "./sharepoint.crt")
        keyf = os.environ.get("SHAREPOINT_TLS_KEY", "./sharepoint.key")
        if _ensure_cert(cert, keyf):
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(cert, keyf)
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    runner = web.AppRunner(app)
    await runner.setup()

    pp_env = os.environ.get("HONEYLENS_PROXY_PROTOCOL", "").strip()
    pp_trusted = proxy_protocol.parse_trusted(pp_env) if pp_env else None
    if pp_trusted is not None:
        logger.info("PROXY protocol enabled (trusted sources: %s)", pp_env)

    bound = []
    pp_listeners: list[proxy_protocol.ProxyProtocolListener] = []
    for port in ports:
        proto, scheme = _proto_for(port)
        want_tls = use_tls and scheme == "https"
        if want_tls and ssl_ctx is None:
            logger.error(
                "port %d is a TLS listener (proto %d) but no certificate is available — "
                "skipping; set SHAREPOINT_TLS_CERT/KEY",
                port,
                proto,
            )
            continue
        ctx = ssl_ctx if want_tls else None
        try:
            if pp_trusted is not None:
                listener = proxy_protocol.ProxyProtocolListener(
                    server_factory=runner.server, ssl_context=ctx, trusted=pp_trusted
                )
                await listener.start(host, port)
                pp_listeners.append(listener)
            else:
                await web.TCPSite(runner, host, port, ssl_context=ctx).start()
            logger.info("SharePoint decoy on %s://%s:%d (proto %d)", scheme, host, port, proto)
            bound.append(port)
        except OSError as exc:
            logger.warning("could not bind %d: %s", port, exc)
    if not bound:
        logger.error("no ports bound — exiting")
        sys.exit(1)
    logger.info("SharePoint decoy ready (%s build %s)", DEFAULT_VERSION, DEFAULT_BUILD)
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        for listener in pp_listeners:
            await listener.stop()
        if hp._eventlog is not None:
            await hp._eventlog.aclose()
        await runner.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="On-prem Microsoft SharePoint Server decoy")
    parser.add_argument("--host", default="0.0.0.0", help="bind address")
    parser.add_argument(
        "--port", type=int, action="append", dest="ports", help="port(s) to listen on"
    )
    parser.add_argument("--no-tls", action="store_true", help="serve cleartext HTTP (dev only)")
    args = parser.parse_args()
    port_map = os.environ.get("HONEYLENS_PORT_MAP", "")
    bind_ports = [int(e.split(":")[0]) for e in port_map.split(",") if ":" in e]
    ports = args.ports or bind_ports or DEFAULT_PORTS
    try:
        asyncio.run(run_server(args.host, ports, use_tls=not args.no_tls))
    except KeyboardInterrupt:
        logger.info("shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
