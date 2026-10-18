"""
fingerprint_extractor.py — Attacker Fingerprint Extraction (Idea 28)
=====================================================================
Extracts client-side fingerprints from event payloads:
  - HTTP: User-Agent, client library+version, header order, Accept-*
  - SSH:  Client version string, library name+version
  - TLS:  JA4+ (from existing ja4_fingerprints table)
  - Credentials: hashed username:password pairs
  - Behavioral: URI sequence hash, port sequence hash

Called by ingest.py/ingest_honeypot.py during ingestion, or by
backfill_fingerprints.py for historical events.

Compatible with Python 3.9+.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

logger = logging.getLogger("honeylens.fingerprint")

# ---------------------------------------------------------------------------
# HTTP User-Agent → Library Detection
# ---------------------------------------------------------------------------

UA_LIB_PATTERNS = [
    # (regex, library_name)  — order matters, first match wins
    (re.compile(r"python-requests/(\S+)", re.I), "python-requests"),
    (re.compile(r"Python-urllib/(\S+)", re.I), "python-urllib"),
    (re.compile(r"aiohttp/(\S+)", re.I), "aiohttp"),
    (re.compile(r"httpx/(\S+)", re.I), "httpx"),
    (re.compile(r"Go-http-client/(\S+)", re.I), "go-http"),
    (re.compile(r"Go/(\S+)", re.I), "go"),
    (re.compile(r"curl/(\S+)", re.I), "curl"),
    (re.compile(r"Wget/(\S+)", re.I), "wget"),
    (re.compile(r"libwww-perl/(\S+)", re.I), "libwww-perl"),
    (re.compile(r"lwp-request/(\S+)", re.I), "lwp-request"),
    (re.compile(r"Java/(\S+)", re.I), "java"),
    (re.compile(r"Apache-HttpClient/(\S+)", re.I), "apache-httpclient"),
    (re.compile(r"okhttp/(\S+)", re.I), "okhttp"),
    (re.compile(r"axios/(\S+)", re.I), "axios"),
    (re.compile(r"node-fetch/(\S+)", re.I), "node-fetch"),
    (re.compile(r"undici/(\S+)", re.I), "undici"),
    (re.compile(r"PHP/(\S+)", re.I), "php"),
    (re.compile(r"Ruby", re.I), "ruby"),
    (re.compile(r"Faraday\s+v?(\S+)", re.I), "faraday"),
    (re.compile(r"RestSharp/(\S+)", re.I), "restsharp"),
    # Security tools
    (re.compile(r"Nuclei\s*/?\s*v?(\S+)", re.I), "nuclei"),
    (re.compile(r"sqlmap/(\S+)", re.I), "sqlmap"),
    (re.compile(r"Nikto/(\S+)", re.I), "nikto"),
    (re.compile(r"WPScan\s+v?(\S+)", re.I), "wpscan"),
    (re.compile(r"Nmap\s+Scripting\s+Engine", re.I), "nmap-nse"),
    (re.compile(r"Zgrab/(\S+)", re.I), "zgrab"),
    (re.compile(r"CensysInspect/(\S+)", re.I), "censys"),
    (re.compile(r"Shodan", re.I), "shodan"),
    (re.compile(r"masscan/(\S+)", re.I), "masscan"),
    (re.compile(r"Tsunami/(\S+)", re.I), "tsunami"),
    (re.compile(r"Fuzz\s*Faster\s*U\s*Fool|ffuf/(\S+)", re.I), "ffuf"),
    (re.compile(r"gobuster/(\S+)", re.I), "gobuster"),
    (re.compile(r"dirsearch/(\S+)", re.I), "dirsearch"),
    (re.compile(r"Burp\s*Suite", re.I), "burpsuite"),
    (re.compile(r"OWASP\s+ZAP/(\S+)", re.I), "zap"),
    (re.compile(r"Acunetix", re.I), "acunetix"),
    # Bots
    (re.compile(r"Googlebot/(\S+)", re.I), "googlebot"),
    (re.compile(r"bingbot/(\S+)", re.I), "bingbot"),
    (re.compile(r"Baiduspider", re.I), "baiduspider"),
    (re.compile(r"YandexBot/(\S+)", re.I), "yandexbot"),
]

# HTTP parsing regexes
_HTTP_METHOD_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/",
    re.MULTILINE,
)
_HTTP_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9\-]*)\s*:\s*(.+?)$", re.MULTILINE)

# SSH version regex
_SSH_VERSION_RE = re.compile(r"SSH-[\d.]+-([\S]+)")
_SSH_LIB_PATTERNS = [
    (re.compile(r"libssh2[_-]?(\S+)", re.I), "libssh2"),
    (re.compile(r"libssh[_-]?(\S+)", re.I), "libssh"),
    (re.compile(r"OpenSSH[_-]?(\S+)", re.I), "openssh"),
    (re.compile(r"PuTTY[_-]?(\S+)?", re.I), "putty"),
    (re.compile(r"paramiko[_-]?(\S+)?", re.I), "paramiko"),
    (re.compile(r"Golang", re.I), "go-ssh"),
    (re.compile(r"Go\b", re.I), "go-ssh"),
    (re.compile(r"JSCH[_-]?(\S+)?", re.I), "jsch"),
    (re.compile(r"AsyncSSH[_-]?(\S+)?", re.I), "asyncssh"),
    (re.compile(r"dropbear[_-]?(\S+)?", re.I), "dropbear"),
    (re.compile(r"Twisted", re.I), "twisted"),
    (re.compile(r"ncrack", re.I), "ncrack"),
    (re.compile(r"Nmap", re.I), "nmap"),
]


# ---------------------------------------------------------------------------
# Fingerprint type constants
# ---------------------------------------------------------------------------

FP_HTTP_UA = "http_ua"
FP_HTTP_UA_HASH = "http_ua_hash"
FP_HTTP_LIB = "http_lib"
FP_HTTP_HEADER_ORDER = "http_header_order"
FP_HTTP_ACCEPT_LANG = "http_accept_lang"
FP_SSH_CLIENT = "ssh_client"
FP_SSH_LIB = "ssh_lib"
FP_JA4 = "ja4"
FP_CRED_HASH = "cred_hash"
FP_URI_SEQUENCE = "uri_sequence"


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _sha256_short(text: str) -> str:
    return _sha256(text)[:16]


class Fingerprint:
    """Single extracted fingerprint."""

    __slots__ = ("detail", "fp_hash", "fp_type", "value")

    def __init__(self, fp_type: str, value: str, detail: dict | None = None) -> None:
        self.fp_type = fp_type
        self.value = value[:512] if value else ""
        self.fp_hash = _sha256(self.value)
        self.detail = detail or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.fp_type,
            "value": self.value,
            "hash": self.fp_hash,
            "detail": self.detail,
        }

    def __repr__(self):
        return f"Fingerprint({self.fp_type}, {self.value[:40]})"


def extract_http_fingerprints(payload: str) -> list[Fingerprint]:
    """Extract HTTP client fingerprints from payload text."""
    fps: list[Fingerprint] = []
    if not payload:
        return fps

    m = _HTTP_METHOD_RE.search(payload)
    if not m:
        return fps

    uri = m.group(2)

    # Collect all headers in order
    header_names: list[str] = []
    ua = None
    accept_lang = None
    _accept_enc = None

    for hm in _HTTP_HEADER_RE.finditer(payload):
        name = hm.group(1).strip()
        val = hm.group(2).strip()
        header_names.append(name.lower())

        nl = name.lower()
        if nl == "user-agent":
            ua = val
        elif nl == "accept-language":
            accept_lang = val
        elif nl == "accept-encoding":
            _accept_enc = val

    # 1. User-Agent (raw)
    if ua:
        fps.append(Fingerprint(FP_HTTP_UA, ua, {"uri": uri[:200]}))
        fps.append(Fingerprint(FP_HTTP_UA_HASH, _sha256(ua), {"ua": ua[:200]}))

        # 2. Client library detection
        for pattern, lib_name in UA_LIB_PATTERNS:
            lm = pattern.search(ua)
            if lm:
                version = lm.group(1) if lm.lastindex and lm.lastindex >= 1 else ""
                lib_val = f"{lib_name}/{version}" if version else lib_name
                fps.append(
                    Fingerprint(
                        FP_HTTP_LIB,
                        lib_val,
                        {
                            "library": lib_name,
                            "version": version,
                            "ua": ua[:200],
                        },
                    )
                )
                break

    # 3. Header order fingerprint
    if len(header_names) >= 3:
        order_str = ",".join(header_names[:15])
        fps.append(
            Fingerprint(
                FP_HTTP_HEADER_ORDER,
                order_str,
                {
                    "header_count": len(header_names),
                },
            )
        )

    # 4. Accept-Language (helps identify operator locale)
    if accept_lang and accept_lang not in ("*", "*/*"):
        fps.append(Fingerprint(FP_HTTP_ACCEPT_LANG, accept_lang[:64]))

    return fps


def extract_ssh_fingerprints(payload: str) -> list[Fingerprint]:
    """Extract SSH client fingerprints from payload."""
    fps: list[Fingerprint] = []
    if not payload:
        return fps

    m = _SSH_VERSION_RE.search(payload)
    if not m:
        return fps

    client_str = m.group(0)  # Full SSH-2.0-XYZ
    software = m.group(1)  # Just the software part

    fps.append(Fingerprint(FP_SSH_CLIENT, client_str, {"software": software}))

    # Parse library
    for pattern, lib_name in _SSH_LIB_PATTERNS:
        lm = pattern.search(software)
        if lm:
            version = lm.group(1) if lm.lastindex and lm.lastindex >= 1 else ""
            lib_val = f"{lib_name}/{version}" if version else lib_name
            fps.append(
                Fingerprint(
                    FP_SSH_LIB,
                    lib_val,
                    {
                        "library": lib_name,
                        "version": version,
                        "raw": client_str,
                    },
                )
            )
            break

    return fps


def extract_credential_fingerprints(metadata: dict | None) -> list[Fingerprint]:
    """Extract credential pair hashes from honeypot metadata."""
    fps: list[Fingerprint] = []
    if not metadata:
        return fps

    username = metadata.get("username") or metadata.get("user") or ""
    password = metadata.get("password") or metadata.get("pass") or ""

    if username and password:
        cred_str = f"{username!s}:{password!s}"
        fps.append(
            Fingerprint(
                FP_CRED_HASH,
                _sha256(cred_str)[:32],
                {
                    "username": str(username)[:64],
                    "pattern": _classify_cred_pattern(str(username), str(password)),
                },
            )
        )

    # Some honeypots log multiple attempts in a list
    attempts = metadata.get("login_attempts") or metadata.get("auth_attempts") or []
    for att in attempts[:10]:
        if isinstance(att, dict):
            u = att.get("username") or att.get("user") or ""
            p = att.get("password") or att.get("pass") or ""
            if u and p:
                cs = f"{u!s}:{p!s}"
                fps.append(
                    Fingerprint(
                        FP_CRED_HASH,
                        _sha256(cs)[:32],
                        {
                            "username": str(u)[:64],
                            "pattern": _classify_cred_pattern(str(u), str(p)),
                        },
                    )
                )

    return fps


def _classify_cred_pattern(username: str, password: str) -> str:
    """Classify credential pair into pattern category."""
    defaults = {
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", ""),
        ("admin", ""),
        ("root", "toor"),
        ("admin", "1234"),
        ("ubnt", "ubnt"),
        ("pi", "raspberry"),
        ("test", "test"),
        ("guest", "guest"),
    }
    if (username.lower(), password.lower()) in defaults:
        return "DEFAULT_CREDS"
    if username.lower() in ("admin", "root", "administrator", "user"):
        return "DICTIONARY"
    return "TARGETED"


def extract_all_fingerprints(
    payload: str | None,
    protocol: str | None = None,
    metadata: dict | None = None,
    ja4: str | None = None,
) -> list[Fingerprint]:
    """
    Extract all fingerprints from an event.

    Args:
        payload:  event payload text
        protocol: detected protocol name
        metadata: event metadata dict (from JSONB)
        ja4:      JA4+ fingerprint string (if available)

    Returns:
        list of Fingerprint objects
    """
    fps: list[Fingerprint] = []
    proto = (protocol or "").lower()

    # HTTP fingerprints
    if payload and (
        proto in ("http", "https", "http-proxy", "")
        or payload[:5] in ("GET /", "POST ", "PUT /", "HEAD ", "DELE")
    ):
        fps.extend(extract_http_fingerprints(payload))

    # SSH fingerprints
    if payload and (proto in ("ssh", "") or "SSH-" in (payload or "")[:20]):
        fps.extend(extract_ssh_fingerprints(payload))

    # Credential fingerprints from honeypot metadata
    if metadata:
        fps.extend(extract_credential_fingerprints(metadata))

    # JA4+ fingerprint
    if ja4 and len(ja4) > 5:
        fps.append(Fingerprint(FP_JA4, ja4))

    # Deduplicate by (type, hash)
    seen: set = set()
    unique: list[Fingerprint] = []
    for fp in fps:
        key = (fp.fp_type, fp.fp_hash)
        if key not in seen:
            seen.add(key)
            unique.append(fp)

    return unique


# ---------------------------------------------------------------------------
# Database storage
# ---------------------------------------------------------------------------


def store_fingerprints(conn: Any, ip: str, fingerprints: list[Fingerprint]) -> int:
    """
    Store fingerprints in attacker_fingerprints table.
    Uses UPSERT — increments event_count on conflict.

    Returns number of fingerprints stored.
    """
    if not fingerprints:
        return 0

    import json

    cur = conn.cursor()
    stored = 0

    for fp in fingerprints:
        try:
            detail_json = json.dumps(fp.detail, default=str, ensure_ascii=True)
            cur.execute(
                """
                INSERT INTO attacker_fingerprints
                    (ip, fingerprint_type, fingerprint_value, fingerprint_hash, detail,
                     event_count, first_seen, last_seen)
                VALUES (%s::inet, %s, %s, %s, %s::jsonb, 1, NOW(), NOW())
                ON CONFLICT (ip, fingerprint_type, fingerprint_hash) DO UPDATE SET
                    event_count = attacker_fingerprints.event_count + 1,
                    last_seen = NOW()
            """,
                (ip, fp.fp_type, fp.value, fp.fp_hash, detail_json),
            )
            stored += 1
        except Exception as exc:
            logger.debug("Failed to store fingerprint %s for %s: %s", fp.fp_type, ip, exc)

    conn.commit()
    return stored


def get_ip_fingerprints(conn: Any, ip: str) -> list[dict]:
    """Get all fingerprints for an IP."""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT fingerprint_type, fingerprint_value, fingerprint_hash,
               detail, event_count, first_seen, last_seen
        FROM attacker_fingerprints
        WHERE ip = %s::inet
        ORDER BY event_count DESC
    """,
        (ip,),
    )
    return [
        {
            "type": r[0],
            "value": r[1],
            "hash": r[2],
            "detail": r[3],
            "count": r[4],
            "first_seen": r[5].isoformat() if r[5] else None,
            "last_seen": r[6].isoformat() if r[6] else None,
        }
        for r in cur.fetchall()
    ]
