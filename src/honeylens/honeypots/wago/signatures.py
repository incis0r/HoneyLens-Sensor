"""Attack shapes for the WAGO WBM surface (Idea 54 Phase 2).

Each signature describes a *shape* of request, derived from the real device's page
set and from how these controllers are actually attacked — not from a CVE number.
That ordering is deliberate: this project has already had to clean invented CVE
identifiers out of production data, so an identifier is bound to a signature only
after `intelligence/circl_enricher.py` confirms it exists. Until then a detection
names what it saw (`overlong_parameter:hostname=4200`), which is both honest and
more useful to an analyst than a wrong CVE.

Nothing here executes, decodes or reflects attacker input; matchers read strings and
return indicators.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

# WBM pages an attacker walks before doing anything. Enumeration is only meaningful
# as a count over a window, so the detector tracks it per source.
WBM_PATHS = frozenset(
    {
        "/wbm/state.php",
        "/wbm/rts_info.php",
        "/wbm/tcpip.php",
        "/wbm/ethernet.php",
        "/wbm/sntp.ssi",
        "/wbm/clock.ssi",
        "/wbm/users.ssi",
        "/wbm/hmi_settings.php",
        "/wbm/administration.php",
        "/wbm/firmware_update.php",
        "/wbm/mass_storage.php",
        "/wbm/downloads.ssi",
        "/wbm/port.php",
        "/wbm/modbus.ssi",
        "/wbm/snmp.php",
        "/wbm/io_config.xml",
        "/wbm/webvisu.php",
    }
)

# Vendor and field-service defaults. A source using these is not guessing — it knows
# what it is talking to, which is a different and stronger signal than a dictionary run.
DEFAULT_CREDENTIALS = {
    ("admin", "wago"),
    ("admin", "admin"),
    ("user", "user"),
    ("guest", "guest"),
    ("admin", "Wago"),
    ("root", "wago"),
    ("admin", ""),
    ("admin", "password"),
}

# Field values above this look like a buffer probe rather than configuration. The WBM
# fields these map to (hostname, addresses) are short by nature on a real device.
OVERLONG_PARAM = 512

_TRAVERSAL_RE = re.compile(r"(?:\.\.[\\/]){2,}|%2e%2e[\\/]|/etc/(?:passwd|shadow)", re.I)
_CMD_INJECT_RE = re.compile(
    r"[;&|`]\s*(?:cat|wget|curl|nc|sh|bash|busybox|chmod|tftp)\b"
    r"|\$\((?:[^)]{1,64})\)|\|\|\s*\w+",
    re.I,
)
_SQLI_RE = re.compile(r"(?:'\s*or\s*'?1'?\s*=\s*'?1|union\s+select|--\s|;\s*drop\s+table)", re.I)
_XXE_RE = re.compile(r"<!(?:DOCTYPE|ENTITY)[^>]*SYSTEM", re.I)
_SCRIPT_RE = re.compile(r"<script\b|javascript:|onerror\s*=", re.I)


@dataclass
class Match:
    indicators: list[str] = field(default_factory=list)
    confidence: str = "low"  # high | medium | low


@dataclass
class Signature:
    key: str  # short class key, e.g. "traversal"
    attack_type: str  # HoneyLens attack type
    rule_name: str
    name: str
    matcher: Callable[[str, str, dict[str, str], str], Match | None]
    # CVE stays empty until CIRCL confirms an identifier for this shape. An empty
    # string here is a deliberate state, not an omission.
    cve_id: str = ""

    def match(self, method: str, path: str, fields: dict[str, str], body: str) -> Match | None:
        try:
            return self.matcher(method, path, fields, body)
        except Exception:  # a broken matcher must never break the decoy
            return None


def _values(fields: dict[str, str], body: str) -> list[str]:
    """Everything attacker-controlled in one list: form values plus the raw body,
    so a probe still matches when it arrives in a body we did not parse."""
    out = [str(v) for v in fields.values()]
    if body:
        out.append(body)
    return out


# ---------------------------------------------------------------------------
# CVE binding — verified against CIRCL Vulnerability-Lookup on 2026-08-14
# ---------------------------------------------------------------------------
# Every identifier below was confirmed PUBLISHED via
# `/vulnerability/<id>` before being written here; none came from memory.
#
# Bound to a shape:
#   CVE-2023-1698  9.8 CRITICAL  unauthenticated attacker creates users / changes
#                                device configuration — directly on the WBM surface
#   CVE-2023-4089  2.7 LOW       undocumented local file inclusion (needs admin);
#                                the traversal shape is the observable attempt
#
# Verified but deliberately NOT bound, because we cannot honestly observe them:
#   CVE-2023-1620  4.9 MEDIUM    crafted packet to the CODESYS V2 *runtime*. We serve
#                                the CODESYS info page over HTTP but run no listener
#                                on 2455, so the packet never reaches us. Reconsider
#                                if a CODESYS responder is ever added.
#   CVE-2023-1619  4.9 MEDIUM    "malformed packet", authenticated, high privilege —
#                                too generic to tie to an HTTP request shape without
#                                guessing, and a guess here is exactly what this
#                                verification gate exists to prevent.
#   CVE-2020-12516 7.5 HIGH      affects the 750-88x / 750-352 family; our decoy
#                                presents a 750-8202 identity, so claiming it would
#                                misdescribe the device we emulate.
VERIFIED_CVES = {
    "CVE-2023-1698": "unauth user creation / config change (CVSS 9.8)",
    "CVE-2023-4089": "undocumented local file inclusion, admin-privileged (CVSS 2.7)",
}

# Fields that mean "create or modify an account" rather than "log in". A login is
# username+password; user administration carries a role, a group or an explicit add.
_USER_ADMIN_FIELDS = (
    "new-user",
    "newuser",
    "add-user",
    "user-add",
    "adduser",
    "user-role",
    "role",
    "group",
    "user-group",
    "privilege",
    "new-password",
    "confirm-password",
)


def _match_user_creation(method, path, fields, body) -> Match | None:
    """CVE-2023-1698: user creation / configuration change without authentication.

    Narrow on purpose. Our decoy has no authentication at all, so "unauthenticated"
    cannot be the discriminator — every request would match. What is observable is
    the *shape* of account administration, which a login attempt does not have.
    """
    if method != "POST":
        return None
    if not any(f in fields for f in _USER_ADMIN_FIELDS):
        return None
    hit = next(f for f in _USER_ADMIN_FIELDS if f in fields)
    return Match([f"user_administration:{hit}"], "high")


def _match_traversal(method, path, fields, body) -> Match | None:
    hits = [v[:120] for v in [*_values(fields, body), path] if _TRAVERSAL_RE.search(v)]
    if not hits:
        return None
    return Match([f"path_traversal:{hits[0]}"], "high")


def _match_command_injection(method, path, fields, body) -> Match | None:
    for name, value in fields.items():
        if _CMD_INJECT_RE.search(str(value)):
            return Match([f"command_injection:{name}={str(value)[:100]}"], "high")
    if body and _CMD_INJECT_RE.search(body):
        return Match(["command_injection:body"], "medium")
    return None


def _match_overlong_parameter(method, path, fields, body) -> Match | None:
    for name, value in fields.items():
        if len(str(value)) >= OVERLONG_PARAM:
            return Match(
                [f"overlong_parameter:{name}={len(str(value))}"],
                "high" if len(str(value)) >= OVERLONG_PARAM * 4 else "medium",
            )
    return None


def _match_sqli(method, path, fields, body) -> Match | None:
    for name, value in fields.items():
        if _SQLI_RE.search(str(value)):
            return Match([f"sqli:{name}={str(value)[:80]}"], "medium")
    return None


def _match_xxe(method, path, fields, body) -> Match | None:
    if body and _XXE_RE.search(body):
        return Match(["xxe:doctype_system"], "high")
    return None


def _match_script_injection(method, path, fields, body) -> Match | None:
    for name, value in fields.items():
        if _SCRIPT_RE.search(str(value)):
            return Match([f"script_injection:{name}"], "medium")
    return None


def _match_default_credentials(method, path, fields, body) -> Match | None:
    if "username" not in fields and "password" not in fields:
        return None
    pair = (fields.get("username", ""), fields.get("password", ""))
    if pair in DEFAULT_CREDENTIALS:
        return Match(["default_credentials:{}/{}".format(*pair)], "high")
    return None


def _match_firmware_upload(method, path, fields, body) -> Match | None:
    if method == "POST" and path.startswith("/wbm/firmware_update"):
        return Match(["firmware_upload"], "high")
    return None


def _match_io_map_read(method, path, fields, body) -> Match | None:
    if path in ("/wbm/io_config.xml", "/wbm/plc_backup.cfg"):
        return Match([f"io_map_read:{path}"], "medium")
    return None


def _match_control_write(method, path, fields, body) -> Match | None:
    if method != "POST":
        return None
    action = str(fields.get("plc-action", "")).lower()
    if action in ("stop", "reset"):
        # Stopping a controller is the destructive one; running it is not.
        return Match([f"plc_{action}"], "high")
    if "form-name" in fields and fields.get("form-name") == "process_control":
        return Match(["process_write"], "high")
    if any(k in fields for k in ("pump", "setpoint", "valve")):
        return Match(["process_write"], "high")
    return None


# Order matters: `classify` keeps the first match at a given confidence, so the more
# specific shape must come first. An XXE body quoting file:///etc/passwd also matches
# the traversal regex, and "traversal" would be the wrong headline for it.
SIGNATURES: list[Signature] = [
    Signature(
        "xxe", "WAGO_EXPLOIT_ATTEMPT", "wago_xxe_probe", "External entity in posted XML", _match_xxe
    ),
    Signature(
        "command-injection",
        "WAGO_EXPLOIT_ATTEMPT",
        "wago_command_injection",
        "Shell metacharacters in a WBM field",
        _match_command_injection,
    ),
    Signature(
        "traversal",
        "WAGO_EXPLOIT_ATTEMPT",
        "wago_path_traversal",
        "Path traversal / file inclusion against the WBM",
        _match_traversal,
        cve_id="CVE-2023-4089",
    ),
    Signature(
        "overlong-parameter",
        "WAGO_EXPLOIT_ATTEMPT",
        "wago_overlong_parameter",
        "Oversized WBM parameter (buffer probe)",
        _match_overlong_parameter,
    ),
    Signature(
        "sqli",
        "WAGO_EXPLOIT_ATTEMPT",
        "wago_sqli_probe",
        "SQL injection shape in a WBM field",
        _match_sqli,
    ),
    Signature(
        "script-injection",
        "WAGO_EXPLOIT_ATTEMPT",
        "wago_script_injection",
        "Script injection in a WBM field",
        _match_script_injection,
    ),
    Signature(
        "user-creation",
        "WAGO_EXPLOIT_ATTEMPT",
        "wago_unauth_user_creation",
        "User creation / configuration change without authentication",
        _match_user_creation,
        cve_id="CVE-2023-1698",
    ),
    Signature(
        "default-credentials",
        "WAGO_CREDENTIAL_CAPTURE",
        "wago_default_credentials",
        "Vendor default credentials tried",
        _match_default_credentials,
    ),
    Signature(
        "firmware-upload",
        "WAGO_FIRMWARE_UPLOAD",
        "wago_firmware_upload",
        "Firmware package upload",
        _match_firmware_upload,
    ),
    Signature(
        "io-disclosure",
        "WAGO_IO_DISCLOSURE",
        "wago_io_map_read",
        "I/O map or configuration backup read",
        _match_io_map_read,
    ),
    Signature(
        "control-write",
        "WAGO_CONTROL_WRITE",
        "wago_control_write",
        "Process or controller-state write",
        _match_control_write,
    ),
]
