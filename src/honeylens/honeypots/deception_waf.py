"""deception_waf.py — fake-vendor WAF response header (AI-triage canary).

OFF by default (``config.WAF_CANARY_ENABLED``). When enabled, every honeypot response
carries a plausible-but-fictional WAF/appliance header, for example::

    X-Xilsoft-WAF-22092026: mode=block; id=9f3a1c7d

**Why.** Real on-prem apps sit behind WAFs that inject vendor headers, so a WAF header is
camouflage, not a honeypot tell. The vendor name is *invented*, which does double duty:

1. **Attribution canary.** The vendor identity is deterministic per sensor host, so a
   leaked or echoed header name points back to exactly one sensor. The header *value*
   carries an opaque per-attacker-IP/day nonce. If either the vendor token or the nonce
   ever shows up in an **inbound** request, something parsed our response and reflected it
   back — the ``waf-canary-callback`` signal (we never emit these strings anywhere a real
   client would learn them legitimately).
2. **Generative-tooling trap.** A human who researches "Xilsoft WAF" finds nothing and
   moves on; an LLM agent asked to "bypass the Xilsoft WAF" often fabricates
   vendor-specific techniques for a product that does not exist, and those confabulated
   requests come back to us.

**Boundaries.** The header is passive. It never instructs the caller to do anything (that
would be prompt-injection / hack-back — out of scope), never references real
infrastructure, and never reveals that the host is a decoy. Vendor names are deliberately
fictional so any hit is unambiguously ours and we do not impersonate a real security
vendor's actual header format.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING

from honeylens import config

if TYPE_CHECKING:
    from aiohttp import web
    # Runtime-free: the aiohttp hook's type hints are strings (PEP 563) so the central
    # classifier can import this module without pulling aiohttp into the ingest layer.

# EXAMPLE invented WAF/appliance vendors — all fictional, and all published with this project,
# so treat them as defaults to replace rather than as secrets. Without an override each sensor
# host is pinned to one of these (see ``vendor_for_host``) so its header identity is stable and
# attributable, but two hosts can hash to the same name. Deployments should set
# ``WAF_CANARY_VENDOR`` to a locally invented name per sensor: that makes the vendor unique AND
# keeps the canary half of the design meaningful, since a reflected string that appears in a
# public repository is much weaker evidence than one that exists only on your sensor.
# See docs/deception-waf-canary.md.
WAF_VENDORS: tuple[str, ...] = (
    "Xilsoft-WAF",
    "CamaraSecWAF",
    "SilentEdge-FW",
    "AppSecGW",
    "NimmoProxy",
    "Vanadium-WAF",
    "Kestrelix-FW",
    "Orbinox-Shield",
)

# Window the deterministic "ruleset release date" falls in — a plausible recent, static
# appliance ruleset version (not today's date, which would make the header name rotate).
_RULESET_EPOCH = date(2026, 1, 1)
_RULESET_SPAN_DAYS = 280


def _h(*parts: str) -> int:
    return int(hashlib.sha256("|".join(parts).encode()).hexdigest(), 16)


def vendor_for_host(host: str) -> str:
    """The one fake vendor this sensor host presents (stable, deterministic).

    ``WAF_CANARY_VENDOR`` pins the vendor explicitly — set it per host so every sensor presents
    a UNIQUE fictional vendor (the hash-from-hostname fallback can collide across hosts). An
    explicit vendor is also folded into the callback-detection tokens, so a pinned vendor that
    is not in ``WAF_VENDORS`` is still caught when reflected back.
    """
    override = getattr(config, "WAF_CANARY_VENDOR", "") or ""
    if override.strip():
        return override.strip()
    return WAF_VENDORS[_h("vendor", host) % len(WAF_VENDORS)]


def _ruleset_date(host: str) -> str:
    """A stable per-host ruleset date as ``DDMMYYYY`` (matches ``X-Xilsoft-WAF-22092026``)."""
    offset = _h("ruleset", host) % _RULESET_SPAN_DAYS
    d = date.fromordinal(_RULESET_EPOCH.toordinal() + offset)
    return d.strftime("%d%m%Y")


def header_name(host: str) -> str:
    """The per-host header name, e.g. ``X-Xilsoft-WAF-22092026``."""
    return f"X-{vendor_for_host(host)}-{_ruleset_date(host)}"


def _nonce(host: str, src_ip: str, salt: str, *, day: str | None = None) -> str:
    """Opaque per-attacker-IP/day canary id (8 hex). Same IP on the same UTC day → same id,
    so a reflected id maps back to that operator's session without per-request noise."""
    day = day or datetime.now(UTC).strftime("%Y%m%d")
    key = (salt or host).encode()
    return hmac.new(key, f"{host}|{src_ip}|{day}".encode(), hashlib.sha256).hexdigest()[:8]


def header_value(host: str, src_ip: str, salt: str = "") -> str:
    """The header value: a plausible appliance verdict plus the opaque canary id."""
    return f"mode=block; id={_nonce(host, src_ip, salt)}"


def waf_header(host: str, src_ip: str, salt: str = "") -> tuple[str, str]:
    """``(name, value)`` to attach to a response. Caller gates on the config flag."""
    return header_name(host), header_value(host, src_ip, salt)


# Lower-cased fictional vendor tokens — their presence in an INBOUND request is the
# callback tell. Both the full ``xilsoft-waf`` and the leading ``xilsoft`` catch a caller
# that reflects the whole header name or just the vendor.
def _vendor_tokens(vendor: str) -> tuple[str, str]:
    v = vendor.lower()
    return v, v.split("-")[0]


_BASE_CALLBACK_TOKENS: tuple[str, ...] = tuple(t for v in WAF_VENDORS for t in _vendor_tokens(v))


def _callback_tokens() -> set[str]:
    """Pool vendor tokens plus this host's pinned ``WAF_CANARY_VENDOR`` (if any), so a vendor
    pinned outside the pool is still recognised when reflected back."""
    tokens = set(_BASE_CALLBACK_TOKENS)
    override = (getattr(config, "WAF_CANARY_VENDOR", "") or "").strip()
    if override:
        tokens.update(_vendor_tokens(override))
    return tokens


def is_canary_callback(haystack: bytes | str) -> bool:
    """True if an inbound request reflects one of our fake-vendor WAF tokens — i.e. a client
    read the header off a response and sent it back. A fictional vendor never appears in a
    legitimate request, so this has no benign source."""
    if isinstance(haystack, bytes):
        hay = haystack.decode("latin1", "ignore").lower()
    else:
        hay = haystack.lower()
    return any(tok in hay for tok in _callback_tokens())


# ── integration adapters ─────────────────────────────────────────────────────────────────
# One consistent fake-vendor WAF identity across *all* of a sensor's web decoys (SharePoint,
# NetScaler, FortiGate, PAN-OS, K8s). A WAF that fronted only one surface would itself be a
# tell, so every decoy on the host presents the same ``vendor_for_host(SENSOR_HOSTNAME)``
# header. Both adapters gate on ``config.WAF_CANARY_ENABLED`` (OFF by default) internally, so
# callers wire them in unconditionally. See docs/deception-waf-canary.md.


def _header_for(src_ip: str) -> tuple[str, str] | None:
    """``(name, value)`` for this host + attacker IP, or ``None`` when the canary is disabled."""
    if not config.WAF_CANARY_ENABLED:
        return None
    return waf_header(config.SENSOR_HOSTNAME, src_ip or "", config.WAF_CANARY_SALT)


async def on_response_prepare(request: web.Request, response: web.StreamResponse) -> None:
    """aiohttp ``on_response_prepare`` hook. Register once per app
    (``app.on_response_prepare.append(deception_waf.on_response_prepare)``) and every response
    carries the host's WAF header when enabled. ``X-Real-IP`` is the PROXY-protocol/edge-restored
    client; fall back to the peer."""
    item = _header_for(request.headers.get("X-Real-IP") or (request.remote or ""))
    if item is not None:
        response.headers[item[0]] = item[1]


def apply_raw(response: bytes, src_ip: str) -> bytes:
    """Splice the WAF header into an already-serialized raw HTTP response, for non-aiohttp
    decoys (e.g. the K8s ``asyncio.Protocol`` server). Inserts it as the last header line before
    the blank line. No-op when disabled or when the response has no header terminator."""
    item = _header_for(src_ip)
    if item is None or b"\r\n\r\n" not in response:
        return response
    name = item[0].replace("\r", " ").replace("\n", " ")
    value = item[1].replace("\r", " ").replace("\n", " ")
    head, _sep, rest = response.partition(b"\r\n\r\n")
    return head + f"\r\n{name}: {value}".encode() + b"\r\n\r\n" + rest
