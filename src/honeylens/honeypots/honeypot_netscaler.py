#!/usr/bin/env python3
"""
honeypot_netscaler.py — Citrix NetScaler ADC / Gateway decoy
============================================================
A passive, high-fidelity decoy for Citrix NetScaler (ADC) and NetScaler Gateway /
StoreFront. It answers with authentic Citrix response headers and plausible bodies, and
**records the full request from every caller** — method, path, query, every header
verbatim, and the whole body (credentials included: on a honeypot the captured credential
*is* the evidence; see ``honeylens.honeypots.body_capture``).

It is a decoy, not a target. It never executes anything a caller sends and never reproduces
a memory-disclosure (CitrixBleed) response: it simply captures the attempt and returns a
normal-looking answer. Its value is intelligence — what is being tried against exposed
NetScaler appliances, by whom, with which payloads.

Surfaces exposed so probes land somewhere and get tagged (the decoy returns a plausible
response for each; it does not implement the flaw):

* CVE-2026-88771 — unauthenticated improper-input-validation command execution (CVSS 9.5,
  Citrix bulletin Sep 2026; no public endpoint, tagged heuristically on unauth management
  POSTs).
* CVE-2026-88772 — DTLS memory overflow on VPN vservers (CVSS 9.5). DTLS is UDP and out of
  scope for this HTTP decoy; documented here so the gap is explicit.
* CVE-2026-19490 — authentication bypass on Gateway / AAA vservers with a SAML action
  (CVSS 9.3, Aug 2026): SAML endpoints.
* CVE-2026-19489 — SIP ALG memory overflow on LSN (CVSS 8.8): not HTTP; documented only.
* CVE-2023-4966 "CitrixBleed" — session-token memory disclosure via the OIDC discovery
  endpoint with an oversized Host header.
* CVE-2025-5777 "CitrixBleed 2", CVE-2025-6543, CVE-2025-7775 — the NetScaler
  Gateway / AAA memory over-read / overflow family. Tagged together on the login memory
  tell (a login POST with no credential value); the Gateway/AAA surface is served so the
  probes land. No public per-CVE request signature for 6543 / 7775, so detection on those
  is surface-and-family, not a precise rule.
* CVE-2019-19781 — path-traversal RCE via ``/vpns/`` and ``/vpn/../``.
* CVE-2023-3519 / CVE-2022-27518 — unauth RCE / SAML surfaces.

**Standalone**: the image runs on its own, outside the HoneyLens pipeline. Every captured
request is emitted three ways — through the HoneyLens JSON sink when present, as a JSON
line to stdout (so ``podman logs`` is a live capture feed), and, if ``NETSCALER_LOG_FILE``
is set, appended there. With no database, no ingest and no API, the decoy still captures:

    podman run --rm -p 443:50443 -v "$PWD/logs:/opt/logs" localhost/honeylens/hp-netscaler

Entry point ``honeylens-hp netscaler`` (or ``python -m honeylens.honeypots.honeypot_netscaler``).
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import re
import secrets
import ssl
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aiohttp import web

from honeylens.eventlog_lock import append_line
from honeylens.honeypots import netscaler_profile as profile
from honeylens.honeypots import pre_parser_capture, proxy_protocol
from honeylens.honeypots.body_capture import capture as capture_body
from honeylens.honeypots.netscaler_eventlog import EventLog

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("netscaler-honeypot")

# --- appliance identity -----------------------------------------------------------------
# A build BELOW the versions patched for the Sep/Aug 2026 advisories (14.1-73.37 /
# 13.1-64.23), so the appliance reads as exploitable to a scanner. Override via env.
DEFAULT_VERSION = os.environ.get("NETSCALER_VERSION", "NS14.1")
DEFAULT_BUILD = os.environ.get("NETSCALER_BUILD", "14.1-43.56")

# Realistic Gateway hostnames; the self-signed cert's CN is drawn from here so it is NOT one
# shared name across the whole fleet — a shared CN is a one-glance correlation fingerprint.
_GW_PREFIXES = ("vpn", "sslvpn", "access", "gateway", "remote", "portal", "connect", "ag", "nsg")


def _deployment_hostname() -> str:
    """A stable, per-deployment Gateway hostname. An explicit NETSCALER_HOSTNAME wins; otherwise
    a realistic name is generated once and persisted next to the TLS identity, so each sensor's
    certificate CN differs instead of being a fleet-wide fingerprint."""
    explicit = os.environ.get("NETSCALER_HOSTNAME", "").strip()
    if explicit:
        return explicit
    name = f"{secrets.choice(_GW_PREFIXES)}{secrets.randbelow(90) + 10}"
    # Only persist when an identity dir is actually configured (NETSCALER_TLS_CERT set). With it
    # unset — bare import, tests — return an ephemeral name and write NOTHING, instead of
    # dropping ns_hostname into the current working directory (A4; the fix SharePoint already has).
    cert = os.environ.get("NETSCALER_TLS_CERT", "").strip()
    if not cert:
        return name
    host_file = Path(cert).with_name("ns_hostname")
    try:
        existing = host_file.read_text().strip()
        if existing:
            return existing
    except OSError:
        pass
    try:
        host_file.parent.mkdir(parents=True, exist_ok=True)
        host_file.write_text(name + "\n")
        host_file.chmod(0o600)
    except OSError:
        pass  # read-only identity dir: fall back to the ephemeral name (still unique per start)
    return name


DEFAULT_HOSTNAME = _deployment_hostname()
DEFAULT_PORTS = [443, 80]  # protocol ports; the manifest binds them high (50443 / 50080)
DEFAULT_LOG_FILE = os.environ.get("NETSCALER_LOG_FILE", "")  # optional extra JSON-lines sink

MAX_BODY = int(os.environ.get("NETSCALER_CLIENT_MAX_SIZE", 8 * 1024 * 1024))
# Raw-capture budget for the standalone path (the sink applies its own when present). A
# single budget for now; splitting header vs. body budgets is deferred (docs §6.2).
_RAW_CAPTURE = int(os.environ.get("HONEYPOT_RAW_CAPTURE_BYTES", 64 * 1024))


def _tls_sni(request: web.Request) -> str | None:
    """Server-side SNI. Proper capture needs a TLS ``sni_callback`` wired at context creation
    (docs §6.3); ``transport.server_hostname`` is the client-side field and is None here, so
    we do not report a wrong value. Deferred — returns None until the callback lands."""
    return getattr(request, "_netscaler_sni", None)


# --- detection: surface vs. behaviour vs. candidate CVE ---------------------------------
# A probe is described in three independent layers so a hunter can tell observation from
# hypothesis (see the NetScaler 2.0 design notes §8):
#   * surface  — which Citrix surface the request touched. No severity, no CVE. Just "what".
#   * behaviour — a concrete tell in the request (a traversal sequence, an injection marker,
#                 the CitrixBleed login shape). Carries severity + confidence.
#   * candidate CVE — a *hypothesis* attached to a behaviour, never to a bare surface.
# Merely reaching /saml/ or /vpns/ is surface-only: it does not prove a bypass or traversal,
# so it does not get CRITICAL or a CVE. The host-side classifier still runs on the payload.

# path substring (lowercased) -> surface label. Order matters; first hit wins for the label.
_SURFACES: tuple[tuple[str, str], ...] = (
    (".ctxs.receiver", "gateway-webshell-path"),
    ("/logon/logonpoint/custom/", "gateway-custom-theme"),
    ("/oauth/idp/.well-known/openid-configuration", "gateway-oidc-discovery"),
    ("/cgi/samlauth", "gateway-saml"),
    ("/cgi/samlart", "gateway-saml"),
    ("/saml/", "gateway-saml"),
    ("/gwtest/formssso", "gateway-formssso"),
    ("doauthentication.do", "gateway-login"),
    ("/cgi/login", "gateway-login"),
    ("/vpn/", "gateway-portal"),
    ("/logon/", "gateway-portal"),
    ("/citrix/", "storefront"),
    ("explicitauth", "storefront-auth"),
    ("/vpns/", "gateway-vpns"),
    ("/nitro/", "management-nitro"),
    ("/menu/", "management-ui"),
    ("/nsconfig", "management-config"),
)

# The malicious webshell alias is `receiver.min.<hex>.css` (GreyNoise reporting, Oct 2026) —
# NOT the legitimate `receiver.min.css` StoreFront serves, so match only the hex variant.
_WEBSHELL_RE = re.compile(r"receiver\.min\.[0-9a-f]{4,}\.css", re.I)
# Traversal sequences, raw or percent-encoded (single and double). A bare `/vpns/` is NOT a
# traversal; the sequence or a known exploit artefact is.
_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|%2e%2e|%252e|/\.\./", re.I)
_TRAVERSAL_ARTEFACTS = ("newbm.pl", "rmbm.pl", "smb.conf", "/vpns/cfg/", "/vpns/portal/scripts/")
# CVE-2026-88771 login command injection markers reported in the wild (Citrix bulletin;
# Help Net Security / GreyNoise, Sep-Oct 2026): a base64 blob appended to the User-Agent
# with no space, and `$IFS` / `b64decode` / `pitboss`. These are heuristic — a marker is a
# behaviour to record, not proof that a given request exploited the CVE, so confidence stays
# "medium", never "high".
_CMDI_MARKERS = re.compile(rb"\$\{?IFS|b64decode|pitboss|%0a|\$\(|`", re.I)
_UA_B64_TAIL = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}$")


def _surface(low_path: str) -> str | None:
    for needle, label in _SURFACES:
        if needle in low_path:
            return label
    return None


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


def _behaviours(
    method: str, path: str, headers: dict[str, str], body: bytes
) -> list[dict[str, Any]]:
    """Concrete tells found in the request, each with its own severity, confidence and
    candidate CVE. Returns ALL matches, not the first — a generic path must not mask a
    stronger payload (docs §8.7)."""
    low = path.lower()
    out: list[dict[str, Any]] = []

    if _WEBSHELL_RE.search(path) or ".ctxs.receiver" in low:
        out.append(_b("webshell-alias", "HIGH", "medium", "CVE-2026-88771"))

    on_login = "/cgi/login" in low or "doauthentication.do" in low
    if on_login:
        ua = headers.get("User-Agent", "")
        if _UA_B64_TAIL.search(ua) or _CMDI_MARKERS.search(
            ua.encode("utf-8", "replace") + b"\n" + body
        ):
            out.append(_b("login-cmd-injection", "HIGH", "medium", "CVE-2026-88771"))
        # CitrixBleed 2 (CVE-2025-5777): the precise tell is the form field `login` sent with
        # no `=`/value on a POST (watchTowr). 6543 / 7775 share the surface but NOT the
        # signature — the vendor states they are unrelated — so they are NOT auto-attached.
        ctype = headers.get("Content-Type", "").lower()
        form = "application/x-www-form-urlencoded" in ctype or not ctype
        if method == "POST" and form and _login_no_value(body):
            out.append(_b("citrixbleed2-login-shape", "HIGH", "medium", "CVE-2025-5777"))

    if _TRAVERSAL_RE.search(path) or any(a in low for a in _TRAVERSAL_ARTEFACTS):
        out.append(_b("path-traversal", "HIGH", "medium", "CVE-2019-19781"))

    if "/gwtest/formssso" in low:
        out.append(_b("rce-probe", "MEDIUM", "low", "CVE-2023-3519"))

    if "/oauth/idp/.well-known/openid-configuration" in low and len(headers.get("Host", "")) >= 200:
        # An oversized Host on the OIDC endpoint is a CitrixBleed probe *candidate*, not a
        # confirmed leak (the decoy never leaks memory). Low confidence by design.
        out.append(_b("oidc-oversized-host", "MEDIUM", "low", "CVE-2023-4966"))

    return out


def _b(behaviour: str, severity: str, confidence: str, cve: str) -> dict[str, Any]:
    return {"behaviour": behaviour, "severity": severity, "confidence": confidence, "cve": cve}


def _login_no_value(body: bytes) -> bool:
    """True when the form carries a `login` field with no `=`/value (the CitrixBleed-2 tell),
    not merely the substring `login` somewhere in the body."""
    for field in body.split(b"&"):
        tok = field.strip()
        if tok == b"login" or tok.lower() == b"login":
            return True
    return False


_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _classify(method: str, path: str, headers: dict[str, str], body: bytes) -> dict[str, Any]:
    """Describe a probe in layers. Always returns the surface; ``attack_type``/severity/CVEs
    are set only when a behaviour is present, so a bare surface does not pre-empt the
    host-side classifier or raise a false CRITICAL."""
    surface = _surface(path.lower())
    matches = _behaviours(method, path, headers, body)
    tag: dict[str, Any] = {"surface": surface, "matches": matches}
    if matches:
        primary = max(matches, key=lambda m: _SEVERITY_RANK.get(m["severity"], 0))
        tag["attack_type"] = f"ns-{primary['behaviour']}"
        tag["severity"] = primary["severity"]
        tag["confidence"] = primary["confidence"]
        # all candidate CVEs across matches, de-duplicated, order-stable
        seen: list[str] = []
        for m in matches:
            if m["cve"] not in seen:
                seen.append(m["cve"])
        tag["rules"] = seen
    return tag


def capability_matrix() -> dict[str, dict[str, Any]]:
    """Honest coverage per CVE (docs §8.8): a CVE string in a list is not emulation. Each
    entry states transport, whether the surface is served, whether the request is captured,
    whether a behavioural signature exists, and whether a response is emulated."""
    http = "http"

    def row(served, signature, emulated, transport=http):
        return {
            "transport": transport,
            "surface_served": served,
            "request_captured": served,  # if the surface is served, the request is captured
            "behaviour_signature": signature,
            "response_emulated": emulated,
        }

    return {
        "CVE-2026-88771": row(True, True, False),  # login cmd-injection markers + webshell IOC
        "CVE-2026-88772": row(False, False, False, transport="dtls"),  # UDP/DTLS: not served
        "CVE-2019-19781": row(True, True, False),  # traversal sequence / known artefacts
        "CVE-2023-3519": row(True, False, False),  # /gwtest/formssso surface only
        "CVE-2023-4966": row(True, True, False),  # OIDC + oversized Host candidate
        "CVE-2025-5777": row(True, True, False),  # CitrixBleed-2 login shape
        "CVE-2025-6543": row(True, False, False),  # surface shared; no public signature
        "CVE-2025-7775": row(True, False, False),  # surface shared; no public signature
    }


class NetScalerHoneypot:
    """Citrix NetScaler Gateway / StoreFront decoy. Captures every request."""

    def __init__(self, log_file: str = DEFAULT_LOG_FILE):
        self.log_file = log_file
        self._sink = self._load_sink()  # None when running fully standalone
        self._eventlog: EventLog | None = None  # set by run_server: bounded off-loop writer

    @staticmethod
    def _load_sink():
        """The HoneyLens JSON sink, when the package is present. None → stdout/file only."""
        try:
            from honeylens.honeypots import sink

            return sink
        except Exception as exc:  # pragma: no cover - standalone without the package
            logger.info("sink unavailable (%s); logging to stdout/file only", exc)
            return None

    # -- the one place every request is recorded ------------------------------------------
    async def _record(self, request: web.Request, event_type: str) -> bytes:
        """Read and record the request. Returns the body bytes for the handler.

        A body-read error is recorded as such (``read_error`` + ``capture_complete=False``),
        never silently flattened to an empty body. Headers are kept as an ordered list that
        preserves duplicates (``request.raw_headers``), because a dict drops the second of
        two same-named headers — which is itself evidence. True pre-parser capture of
        requests aiohttp rejects is a separate layer (docs §6, deferred).
        """
        read_error: str | None = None
        try:
            body = await request.read()
        except Exception as exc:  # disconnect, bad chunking, decode, limit…
            body = b""
            read_error = type(exc).__name__

        # Ordered headers with duplicates preserved; the dict is a convenience view only.
        headers_ordered = [
            [k.decode("latin-1"), v.decode("latin-1")] for k, v in request.raw_headers
        ]
        headers = dict(request.headers)
        peer = request.transport.get_extra_info("peername") if request.transport else None
        src_ip = request.remote or (peer[0] if peer else "0.0.0.0")
        # nginx terminates port 80 as HTTP, so it cannot attach a PROXY
        # preamble on that path. Accept X-Real-IP only from the explicitly
        # trusted edge address; a direct client must not be able to forge it.
        if peer:
            src_ip = _http_client_ip(
                peer[0],
                src_ip,
                request.headers.get("X-Real-IP", "").strip(),
                os.environ.get("HONEYLENS_HTTP_PROXY", "").strip(),
            )
        src_port = peer[1] if peer and len(peer) > 1 else 0
        sock = request.transport.get_extra_info("sockname") if request.transport else None
        local_port = sock[1] if sock and len(sock) > 1 else 0
        scheme = request.scheme  # real transport: 'https' on the TLS listener, 'http' on 80

        tag = _classify(request.method, request.path_qs, headers, body)

        event: dict[str, Any] = {
            "honeypot": "netscaler",
            "event_type": event_type,
            "method": request.method,
            "path": request.path,
            "query": request.query_string,
            "scheme": scheme,
            "http_version": f"{request.version.major}.{request.version.minor}",
            "headers_ordered": headers_ordered,
            "headers": headers,
            "tls_sni": _tls_sni(request),
            "surface": tag.get("surface"),
            "capture_complete": read_error is None,
            **capture_body(body, request.path, headers.get("Content-Type", "")),
        }
        if read_error:
            event["read_error"] = read_error
        if tag.get("matches"):
            event["matches"] = tag["matches"]
            event["candidate_cves"] = tag.get("rules")

        # Reconstruct bytes from ordered headers (closer to the wire than a dict; still a
        # post-parser view — see the docstring).
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
        """Fan the event out: HoneyLens sink (if present), stdout JSON, optional log file.

        The envelope is the same whether or not the sink is present and whatever the
        transport — the standalone path mirrors the sink's record shape (docs §7.1), so a
        downstream reader does not have to special-case the destination.
        """
        protocol = scheme  # 'http' or 'https' — the real transport, not a hardcoded 'https'
        confidence = tag.get("confidence")
        if self._sink is not None:
            record = self._sink.build_record(
                source="netscaler",
                honeypot="netscaler",
                protocol=protocol,
                peer=peer,
                event=event,
                payload=payload,
                dst_port=dst_port or None,
                raw=raw,
                attack_type=tag.get("attack_type"),
                severity=tag.get("severity"),
                confidence=confidence,
                rules=tag.get("rules"),
            )
        else:
            record = {
                "schema": "honeylens-event/1",
                "timestamp": datetime.now(UTC).isoformat(),
                "source": "netscaler",
                "honeypot": "netscaler",
                "protocol": protocol,
                "peer_ip": peer[0],
                "peer_port": peer[1],
                "dst_port": dst_port,
                "payload": payload[:2000],
                "event": event,
                "raw_hex": raw[:_RAW_CAPTURE].hex(),
            }
            if tag.get("attack_type"):
                record["attack_type"] = tag["attack_type"]
                record["severity"] = tag.get("severity")
                record["confidence"] = confidence
                record["rules"] = tag.get("rules")

        # Production: hand off to the bounded off-loop writer (non-blocking, counts drops).
        if self._eventlog is not None:
            self._eventlog.submit(record)
            return

        # Synchronous fallback — no running writer (bare module use / tests).
        if self._sink is not None:
            try:
                if not self._sink.write_record(record):
                    logger.error("sink write_record returned False — event not persisted")
            except Exception as exc:  # pragma: no cover - disk/volume issue
                logger.error("sink write failed: %s", exc)
        line = json.dumps(record, default=str, separators=(",", ":"))
        print(line, flush=True)  # standalone visibility: one JSON line per capture
        if self.log_file:
            try:
                append_line(self.log_file, line)
            except OSError as exc:
                logger.error("netscaler log file write failed (%s): %s", self.log_file, exc)

    def record_pre_parser_reject(self, info: dict[str, Any]) -> None:
        """Emit a request aiohttp rejected before the handler ran (E7). ``info`` comes from
        ``pre_parser_capture``: peer, status, the parser's reason, the raw opening bytes, the
        bind port and scheme. Recorded as a distinct ``PRE_PARSER_REJECT`` event so analysts can
        both count the dropped traffic and read what tripped the parser — no attack_type is set
        (most of it is TLS-to-HTTP-port noise; the central classifier can still tag the raw)."""
        raw = info.get("raw") or b""
        event = {
            "honeypot": "netscaler",
            "event_type": "PRE_PARSER_REJECT",
            "reject_status": info.get("status"),
            "reject_reason": info.get("reason"),
            "capture_complete": True,
            "body_len": len(raw),
        }
        payload = f"[pre-parser {info.get('status')}] {info.get('reason', '')}"[:2000]
        self._emit(
            event=event,
            payload=payload,
            raw=raw,
            peer=info.get("peer", ("0.0.0.0", 0)),
            dst_port=info.get("dst_port"),
            scheme=info.get("scheme", "http"),
            tag={},
        )

    # -- handlers (plausible responses; the request is already captured) ------------------
    async def handle_root(self, request: web.Request) -> web.Response:
        await self._record(request, "ROOT")
        return profile.redirect()

    async def handle_vpn_index(self, request: web.Request) -> web.Response:
        await self._record(request, "GATEWAY_REDIRECT")
        return profile.redirect()

    async def handle_logon(self, request: web.Request) -> web.Response:
        await self._record(request, "GATEWAY_LOGON")
        return profile.logon_page()  # aiohttp drops the body for HEAD, keeps Content-Length

    async def handle_login_post(self, request: web.Request) -> web.Response:
        """Login POST (also the CitrixBleed-2 surface): the classic theme re-renders the logon
        page with HTTP 200. The full request — credentials and injection markers — is captured
        by _record before this answers."""
        await self._record(request, "GATEWAY_LOGIN")
        return profile.failed_login()

    async def handle_oidc(self, request: web.Request) -> web.Response:
        """OIDC discovery (a CitrixBleed probe surface). Echoes the Host in the issuer as a
        real appliance does; it never reflects oversized input or leaks memory."""
        await self._record(request, "OIDC_DISCOVERY")
        host = request.headers.get("Host", DEFAULT_HOSTNAME)[:253]
        body = json.dumps(
            {
                "issuer": f"https://{host}/oauth/idp",
                "authorization_endpoint": f"https://{host}/oauth/idp/login",
                "token_endpoint": f"https://{host}/oauth/idp/token",
                "jwks_uri": f"https://{host}/oauth/idp/certs",
                "response_types_supported": ["code", "token", "id_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            }
        )
        return web.Response(
            text=body,
            content_type="application/json",
            headers={"Strict-Transport-Security": profile.HSTS},
        )

    async def handle_saml(self, request: web.Request) -> web.StreamResponse:
        await self._record(request, "SAML")
        raise web.HTTPFound(profile.LOGON_PATH)

    async def handle_traversal(self, request: web.Request) -> web.Response:
        """CVE-2019-19781 surface. A real appliance answers an unknown /vpns path with the
        Apache 404; the probe is captured and classified first."""
        await self._record(request, "VPNS_ACCESS")
        return profile.not_found()

    async def handle_catchall(self, request: web.Request) -> web.Response:
        await self._record(request, "OTHER")
        return profile.not_found()

    def setup_routes(self, app: web.Application) -> None:
        app.on_response_prepare.append(profile.enforce_server_policy)
        r = app.router
        r.add_get("/", self.handle_root)
        r.add_get("/vpn/index.html", self.handle_vpn_index)  # redirect, like the reference
        r.add_get("/logon/LogonPoint/tmindex.html", self.handle_logon)  # GET + HEAD
        r.add_get("/logon/LogonPoint/index.html", self.handle_logon)
        r.add_post("/logon/LogonPoint/index.html", self.handle_login_post)
        for p in ("/cgi/login", "/p/u/doAuthentication.do", "/nf/auth/doAuthentication.do"):
            r.add_route("*", p, self.handle_login_post)
        r.add_get("/oauth/idp/.well-known/openid-configuration", self.handle_oidc)
        r.add_route("*", "/cgi/samlauth", self.handle_saml)
        r.add_route("*", "/saml/{rest:.*}", self.handle_saml)
        r.add_route("*", "/vpns/{rest:.*}", self.handle_traversal)
        r.add_route("*", "/{tail:.*}", self.handle_catchall)


def _ensure_cert(cert: str, key: str) -> bool:
    """Self-signed cert for standalone runs when the launcher did not provide one."""
    if os.path.exists(cert) and os.path.exists(key):
        return True
    try:
        from pathlib import Path

        from honeylens.honeypots.cli import ensure_self_signed

        return ensure_self_signed(Path(cert), Path(key), DEFAULT_HOSTNAME)
    except Exception as exc:
        logger.warning("could not generate a self-signed cert (%s); falling back to HTTP", exc)
        return False


def _mask_server_banner() -> None:
    """Make aiohttp's default ``Server`` the IIS banner everywhere — including the 400/413/
    431 responses it generates for malformed requests *before* the app runs, which the
    per-response hook cannot reach. Those error responses were the easiest fingerprint
    (docs §2): a 9 KB Host returned ``Server: Python/… aiohttp/…``."""
    try:
        from aiohttp import web_response

        # Apache matches the classic-gateway content banner; the Server policy drops it on
        # redirects. Either way, never the Python/aiohttp default.
        web_response.SERVER_SOFTWARE = "Apache"
    except Exception as exc:  # pragma: no cover
        logger.debug("could not mask aiohttp banner: %s", exc)


def _proto_for(bind_port: int) -> tuple[int, str]:
    """(protocol_port, scheme) for a bind port, from the manifest's HONEYLENS_PORT_MAP
    (keys are bind ports). Falls back to identity for a bare standalone run. Port 80 is the
    only cleartext scheme; everything else is a TLS vserver."""
    mapping = {}
    for entry in os.environ.get("HONEYLENS_PORT_MAP", "").split(","):
        if ":" in entry:
            b, _, p = entry.partition(":")
            mapping[int(b)] = int(p)
    proto = mapping.get(bind_port, bind_port)
    return proto, ("http" if proto == 80 else "https")


async def run_server(host: str, ports: list[int], *, use_tls: bool = True) -> None:
    _mask_server_banner()
    hp = NetScalerHoneypot()
    hp._eventlog = EventLog(sink=hp._sink, log_file=hp.log_file)
    await hp._eventlog.start()
    app = web.Application(client_max_size=MAX_BODY)
    hp.setup_routes(app)

    ssl_ctx = None
    if use_tls:
        cert = os.environ.get("NETSCALER_TLS_CERT", "./netscaler.crt")
        keyf = os.environ.get("NETSCALER_TLS_KEY", "./netscaler.key")
        if _ensure_cert(cert, keyf):
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(cert, keyf)
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # scanners still speak 1.2

    runner = web.AppRunner(app)
    await runner.setup()

    # E7: wrap the protocol factory so requests aiohttp rejects before the handler (bad method,
    # oversized headers/body, bad version) are recorded instead of silently dropped. Falls back
    # to the stock factory if aiohttp's internals are not reachable — serving is never at risk.
    loop = asyncio.get_running_loop()
    server = runner.server
    if server is None:  # runner.setup() always creates it; guard for the type-checker
        raise RuntimeError("AppRunner.setup() did not create a server")
    capture_factory = pre_parser_capture.make_capturing_factory(server, hp.record_pre_parser_reject)

    # Behind a reverse proxy (e.g. nginx on an edge host), the decoy's TCP peer is the proxy, so
    # events would record the proxy's address. With PROXY protocol enabled the proxy prepends the
    # real client address and this listener restores it. Trust is gated to the proxy's source so a
    # direct attacker cannot spoof it. Disabled by default (native DNAT already keeps the source).
    pp_env = os.environ.get("HONEYLENS_PROXY_PROTOCOL", "").strip()
    pp_trusted = proxy_protocol.parse_trusted(pp_env) if pp_env else None
    if pp_trusted is not None:
        logger.info("PROXY protocol enabled (trusted sources: %s)", pp_env)

    bound = []
    pp_listeners: list[proxy_protocol.ProxyProtocolListener] = []
    direct_servers: list[asyncio.AbstractServer] = []
    for port in ports:
        proto, scheme = _proto_for(port)
        want_tls = use_tls and scheme == "https"
        if want_tls and ssl_ctx is None:
            # Never downgrade a TLS vserver to cleartext — that is itself a tell. Skip it and
            # say why, rather than turning 443 into HTTP (docs §3 P0).
            logger.error(
                "port %d is a TLS vserver (proto %d) but no certificate is available — "
                "skipping; set NETSCALER_TLS_CERT/KEY",
                port,
                proto,
            )
            continue
        ctx = ssl_ctx if want_tls else None
        try:
            if pp_trusted is not None:
                listener = proxy_protocol.ProxyProtocolListener(
                    server_factory=capture_factory, ssl_context=ctx, trusted=pp_trusted
                )
                await listener.start(host, port)
                pp_listeners.append(listener)
            else:
                # Bind the capturing factory directly (what TCPSite does internally) so the
                # pre-parser capture is in effect on the native-IP path too.
                direct_servers.append(
                    await loop.create_server(capture_factory, host, port, ssl=ctx)
                )
            logger.info("NetScaler decoy on %s://%s:%d (proto %d)", scheme, host, port, proto)
            bound.append(port)
        except OSError as exc:
            logger.warning("could not bind %d: %s", port, exc)
    if not bound:
        logger.error("no ports bound — exiting")
        sys.exit(1)
    logger.info("NetScaler decoy ready (%s %s)", DEFAULT_VERSION, DEFAULT_BUILD)
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        for listener in pp_listeners:
            await listener.stop()
        for srv in direct_servers:
            srv.close()
        if hp._eventlog is not None:
            await hp._eventlog.aclose()
        await runner.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="Citrix NetScaler ADC / Gateway decoy")
    parser.add_argument("--host", default="0.0.0.0", help="bind address")
    parser.add_argument(
        "--port", type=int, action="append", dest="ports", help="port(s) to listen on"
    )
    parser.add_argument("--no-tls", action="store_true", help="serve cleartext HTTP (dev only)")
    args = parser.parse_args()
    # Bind ports come from the manifest via HONEYLENS_PORT_MAP, whose keys are the ports the
    # non-root container actually listens on (50443/50080); the host DNATs 443/80 onto them.
    # The event still records the protocol port, because the sink maps the bound port back.
    # The DEFAULT_PORTS fall back for a bare `python -m` standalone run with no map.
    port_map = os.environ.get("HONEYLENS_PORT_MAP", "")
    bind_ports = [int(e.split(":")[0]) for e in port_map.split(",") if ":" in e]
    ports = args.ports or bind_ports or DEFAULT_PORTS
    try:
        asyncio.run(run_server(args.host, ports, use_tls=not args.no_tls))
    except KeyboardInterrupt:
        logger.info("shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
