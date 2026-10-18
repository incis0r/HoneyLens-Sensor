"""
whitelist.py - IP Whitelist Management
"""

import ipaddress
import logging
from pathlib import Path

from honeylens.config import WHITELIST_FILE, WHITELIST_IPS

logger = logging.getLogger("whitelist")


_whitelist_cache = None
_whitelist_mtime: float = 0.0


def get_whitelist(force_reload=False):
    global _whitelist_cache, _whitelist_mtime
    file_mtime = 0.0
    if WHITELIST_FILE and Path(WHITELIST_FILE).exists():
        try:
            file_mtime = Path(WHITELIST_FILE).stat().st_mtime
        except OSError as exc:
            logger.debug("whitelist mtime unavailable: %s", exc)
    if not force_reload and _whitelist_cache is not None:
        if file_mtime == _whitelist_mtime:
            return _whitelist_cache
    whitelist = list(WHITELIST_IPS) if WHITELIST_IPS else []
    if WHITELIST_FILE and Path(WHITELIST_FILE).exists():
        try:
            with Path(WHITELIST_FILE).open() as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Strip inline comments
                        if "#" in line:
                            line = line[: line.index("#")].strip()
                        if line:
                            whitelist.append(line)
        except OSError as exc:
            logger.debug("whitelist file not readable (%s) — optional", exc)
    _whitelist_cache = whitelist
    _whitelist_mtime = file_mtime
    return whitelist


def reload_whitelist():
    return get_whitelist(force_reload=True)


def is_whitelisted(ip_str):
    if not ip_str:
        return False
    if "/" in ip_str:
        ip_str = ip_str.split("/")[0]
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in get_whitelist():
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def get_whitelist_filter(column="src_ip"):
    whitelist = get_whitelist()
    if not whitelist:
        return "", []
    conditions = []
    params = []
    for entry in whitelist:
        if "/" in entry:
            conditions.append(f"NOT ({column}::inet <<= %s::inet)")
        else:
            conditions.append(f"{column}::text != %s")
        params.append(entry)
    if conditions:
        return " AND " + " AND ".join(conditions), params
    return "", []


def add_to_whitelist(ip_or_cidr):
    try:
        if "/" in ip_or_cidr:
            ipaddress.ip_network(ip_or_cidr, strict=False)
        else:
            ipaddress.ip_address(ip_or_cidr)
    except ValueError as e:
        return False, f"Invalid format: {e}"
    if is_whitelisted(ip_or_cidr.split("/")[0]):
        return False, "Already whitelisted"
    if not WHITELIST_FILE:
        return False, "No whitelist file configured"
    try:
        with Path(WHITELIST_FILE).open("a") as f:
            f.write(f"{ip_or_cidr}\n")
        reload_whitelist()
        return True, f"Added {ip_or_cidr}"
    except Exception as e:
        return False, str(e)


def remove_from_whitelist(ip_or_cidr):
    if not WHITELIST_FILE or not Path(WHITELIST_FILE).exists():
        return False, "No whitelist file"
    try:
        with Path(WHITELIST_FILE).open() as f:
            lines = f.readlines()
        new_lines = [line for line in lines if line.strip() != ip_or_cidr]
        if len(new_lines) == len(lines):
            return False, "Not found"
        with Path(WHITELIST_FILE).open("w") as f:
            f.writelines(new_lines)
        reload_whitelist()
        return True, f"Removed {ip_or_cidr}"
    except Exception as e:
        return False, str(e)


def list_whitelist():
    result = []
    for entry in WHITELIST_IPS or []:
        result.append({"entry": entry, "source": "config"})
    if WHITELIST_FILE and Path(WHITELIST_FILE).exists():
        try:
            with Path(WHITELIST_FILE).open() as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        result.append({"entry": line, "source": "file"})
        except OSError as exc:
            logger.debug("whitelist file not readable (%s) — optional", exc)
    return result
