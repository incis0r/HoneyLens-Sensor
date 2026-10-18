"""IP address geolocation: MaxMind GeoLite2 database, or ip-api.com as the fallback.

MaxMind (recommended in production): ``GeoLite2-City.mmdb`` at ``GEOIP_DB_PATH`` (default
``/opt/honeylens/GeoLite2-City.mmdb``; until the migrator exists the 0.9 location is read
too). Fallback: ip-api.com, free, 45 queries per minute.

Tester addresses (comma-separated ``TESTER_IPS_LIST`` or the ``TESTER_IPS_FILE`` file) get
the code ``PIRATE`` and a pirate flag instead of a country; private addresses the code ``LAN``.

Usage::

    from honeylens.geoip import lookup_ip, get_country_code, country_flag
    lookup_ip("8.8.8.8")       # {'country': 'United States', 'country_code': 'US', ...}
    get_country_code("8.8.8.8")  # 'US'
"""

import ipaddress
import json
import logging
import socket
import struct
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from honeylens.env import env

logger = logging.getLogger("honeylens.geoip")

GEOIP_DB_CANDIDATES = (
    Path(env("GEOIP_DB_PATH", "/opt/honeylens/GeoLite2-City.mmdb")),
    Path("./GeoLite2-City.mmdb"),
    Path("/opt/sensor/GeoLite2-City.mmdb"),
)

IP_API_URL = (
    "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,"
    "city,lat,lon,isp,org,as"
)
IP_API_RATE_LIMIT = 45  # queries per minute, free-plan limit

CACHE_SIZE = 10000
CACHE_TTL = 86400  # 24 h


def _now() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# Tester / red-team addresses
# ---------------------------------------------------------------------------


def load_tester_ips(env_list: str, file: Path) -> dict[str, str]:
    """``{ip: description}`` from a comma-separated list and an ``ip [description]`` file (``#`` lines skipped)."""
    testers: dict[str, str] = {}
    for item in env_list.split(","):
        ip = item.strip()
        if ip:
            testers[ip] = "Tester (env)"
    if file.is_file():
        try:
            for raw in file.read_text().splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                testers[parts[0]] = parts[1] if len(parts) > 1 else "Tester"
        except OSError as exc:
            logger.warning("Failed to load tester IPs from %s: %s", file, exc)
    return testers


TESTER_IPS: dict[str, str] = load_tester_ips(
    env("TESTER_IPS_LIST", ""), Path(env("TESTER_IPS_FILE", "/opt/honeylens/tester_ips.txt"))
)
if TESTER_IPS:
    logger.info("Loaded %d tester IPs", len(TESTER_IPS))


def is_tester_ip(ip: str) -> bool:
    return ip in TESTER_IPS


def get_tester_name(ip: str) -> str:
    return TESTER_IPS.get(ip, "Tester")


# ---------------------------------------------------------------------------
# MaxMind — opened lazily on the first lookup
# ---------------------------------------------------------------------------

_maxmind_reader: Any = None
_maxmind_tried = False


def _maxmind() -> Any:
    global _maxmind_reader, _maxmind_tried
    if _maxmind_tried:
        return _maxmind_reader
    _maxmind_tried = True
    try:
        import geoip2.database
    except ImportError:
        logger.info("geoip2 module not installed, using ip-api.com fallback")
        return None
    for db_path in GEOIP_DB_CANDIDATES:
        if not db_path.exists():
            continue
        try:
            _maxmind_reader = geoip2.database.Reader(str(db_path))
        except (OSError, ValueError) as exc:
            logger.warning("Failed to load GeoIP database %s: %s", db_path, exc)
            continue
        logger.info("Loaded MaxMind GeoIP database: %s", db_path)
        return _maxmind_reader
    logger.info("MaxMind database not found, using ip-api.com fallback")
    return None


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------


def is_private_ip(ip: str) -> bool:
    """RFC 1918, loopback and link-local. IPv4 only — the same as in 0.9.

    Deliberately not ``ipaddress.is_private``: that also covers 0/8, 100.64/10 (CGNAT) and
    240/4, and changing the set would change the classification of existing events.
    """
    if not ip or ip.count(".") != 3:
        return False
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        return False
    return (
        (ip_int & 0xFF000000) == 0x0A000000  # 10/8
        or (ip_int & 0xFFF00000) == 0xAC100000  # 172.16/12
        or (ip_int & 0xFFFF0000) == 0xC0A80000  # 192.168/16
        or (ip_int & 0xFF000000) == 0x7F000000  # 127/8
        or (ip_int & 0xFFFF0000) == 0xA9FE0000  # 169.254/16
    )


def is_valid_public_ip(ip: str) -> bool:
    if not ip or is_private_ip(ip):
        return False
    try:
        socket.inet_aton(ip)
    except OSError:
        return False
    return True


# ---------------------------------------------------------------------------
# In-memory cache with TTL
# ---------------------------------------------------------------------------

_geo_cache: dict[str, tuple[dict[str, Any], float]] = {}
_geo_cache_lock = threading.Lock()  # lookup_ip is called by many ingest threads at once


def _get_from_cache(ip: str) -> dict[str, Any] | None:
    with _geo_cache_lock:
        entry = _geo_cache.get(ip)
        if entry is None:
            return None
        result, ts = entry
        if _now() - ts < CACHE_TTL:
            return result
        _geo_cache.pop(ip, None)
        return None


def _put_in_cache(ip: str, result: dict[str, Any]) -> None:
    with _geo_cache_lock:
        if len(_geo_cache) >= CACHE_SIZE:
            # Oldest 10 %; pop instead of del, because in 0.9 two threads computing the same
            # "oldest" list deleted the same key and the second one got a KeyError.
            oldest = sorted(_geo_cache.items(), key=lambda kv: kv[1][1])[: CACHE_SIZE // 10]
            for key, _ in oldest:
                _geo_cache.pop(key, None)
        _geo_cache[ip] = (result, _now())


# ---------------------------------------------------------------------------
# MaxMind
# ---------------------------------------------------------------------------


def _lookup_maxmind(ip: str) -> dict[str, Any] | None:
    reader = _maxmind()
    if reader is None:
        return None
    import geoip2.errors

    try:
        response = reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return {
            "ip": ip,
            "country": "Unknown",
            "country_code": "??",
            "city": "",
            "source": "maxmind",
        }
    except (geoip2.errors.GeoIP2Error, ValueError) as exc:
        logger.debug("MaxMind lookup failed for %s: %s", ip, exc)
        return None
    return {
        "ip": ip,
        "country": response.country.name or "Unknown",
        "country_code": response.country.iso_code or "??",
        "city": response.city.name or "",
        "region": response.subdivisions.most_specific.name if response.subdivisions else "",
        "latitude": response.location.latitude,
        "longitude": response.location.longitude,
        "source": "maxmind",
    }


# ---------------------------------------------------------------------------
# ip-api.com (fallback) with a per-minute window limit
# ---------------------------------------------------------------------------

_window_start = 0.0
_calls_in_window = 0


def _rate_reset() -> None:
    global _window_start, _calls_in_window
    _window_start, _calls_in_window = 0.0, 0


def _rate_allow() -> bool:
    """Fixed 60 s window from the first query in the window.

    0.9 reset the counter only after 60 s of SILENCE, so under continuous traffic above the
    limit the fallback never came back to life.
    """
    global _window_start, _calls_in_window
    now = _now()
    if now - _window_start >= 60:
        _window_start, _calls_in_window = now, 0
    return _calls_in_window < IP_API_RATE_LIMIT


def _http_get_json(url: str) -> dict[str, Any]:
    # Scheme and host are fixed (IP_API_URL), and the only variable part is the address that
    # _lookup_ipapi passed through ipaddress.ip_address — file:// has no way in here.
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 # nosec B310 # nosemgrep
        return json.loads(response.read().decode())


def _lookup_ipapi(ip: str) -> dict[str, Any] | None:
    global _calls_in_window
    # Validate before interpolating into the URL: urllib honours file:// and gopher://, so
    # an unvalidated string could escape the path.
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logger.debug("rejecting non-IP value passed to _lookup_ipapi: %r", ip)
        return None
    if not _rate_allow():
        logger.debug("Rate limit reached for ip-api.com")
        return None
    try:
        data = _http_get_json(IP_API_URL.format(ip=ip))
    except (OSError, ValueError) as exc:
        logger.debug("ip-api.com lookup failed for %s: %s", ip, exc)
        return None
    _calls_in_window += 1
    if data.get("status") == "success":
        return {
            "ip": ip,
            "country": data.get("country", "Unknown"),
            "country_code": data.get("countryCode", "??"),
            "city": data.get("city", ""),
            "region": data.get("regionName", ""),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "as": data.get("as", ""),
            "source": "ip-api",
        }
    return {
        "ip": ip,
        "country": "Unknown",
        "country_code": "??",
        "source": "ip-api",
        "error": data.get("message", "lookup failed"),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def lookup_ip(ip: str) -> dict[str, Any]:
    """Geolocate an address: testers → ``PIRATE``, private → ``LAN``, the rest MaxMind/ip-api."""
    if not ip:
        return {"ip": "", "country": "Unknown", "country_code": "??"}
    if is_tester_ip(ip):
        return {
            "ip": ip,
            "country": "Tester",
            "country_code": "PIRATE",
            "city": get_tester_name(ip),
            "source": "tester_list",
            "is_tester": True,
        }
    if is_private_ip(ip):
        return {
            "ip": ip,
            "country": "Local Network",
            "country_code": "LAN",
            "city": "",
            "source": "internal",
        }
    cached = _get_from_cache(ip)
    if cached:
        return cached
    result = _lookup_maxmind(ip) or _lookup_ipapi(ip)
    if not result:
        result = {"ip": ip, "country": "Unknown", "country_code": "??", "source": "none"}
    _put_in_cache(ip, result)
    return result


def get_country_code(ip: str) -> str:
    """ISO country code, ``LAN`` for private, ``PIRATE`` for testers, ``??`` when unknown."""
    if not ip:
        return "??"
    return lookup_ip(ip).get("country_code", "??")


def get_country_name(ip: str) -> str:
    if not ip:
        return "Unknown"
    return lookup_ip(ip).get("country", "Unknown")


def lookup_ip_batch(ips: list[str]) -> dict[str, dict[str, Any]]:
    """Many addresses at once; ordering and cache as in ``lookup_ip``."""
    return {ip: lookup_ip(ip) for ip in ips if ip}


def country_flag(country_code: str) -> str:
    """ISO 3166-1 alpha-2 code → flag; ``🏴‍☠️`` for PIRATE, ``🏠`` for LAN, ``🏴`` when unknown."""
    if not country_code or country_code == "??":
        return "🏴"
    if country_code == "LAN":
        return "🏠"
    if country_code == "PIRATE":
        return "🏴‍☠️"
    code = country_code.upper()
    if len(code) != 2 or not code.isalpha():
        return "🏴"
    return "".join(chr(ord(c) - ord("A") + 0x1F1E6) for c in code)


def main(argv: list[str] | None = None) -> int:
    """``honeylens-geoip <ip> [ip ...]`` — lookup from the shell."""
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("usage: honeylens-geoip <ip_address> [ip2] [ip3] ...", file=sys.stderr)
        return 2
    for ip in args:
        result = lookup_ip(ip)
        flag = country_flag(result.get("country_code", "??"))
        print(f"{ip}: {flag} {result.get('country')} ({result.get('country_code')})")
        for key, label in (("city", "City"), ("region", "Region"), ("isp", "ISP"), ("org", "Org")):
            if result.get(key):
                print(f"  {label}: {result[key]}")
        print(f"  Source: {result.get('source', 'unknown')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
