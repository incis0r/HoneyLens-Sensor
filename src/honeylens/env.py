"""Configuration from environment variables: ``.env`` file → ``os.environ`` → default.

Pure standard library, no python-dotenv. The ``.env`` file **wins** over ``os.environ``
— the reverse of dotenv — and that has been intentional since 0.9: the file on the sensor's
disk is the source of truth, and a variable in a systemd unit's environment is the
exception, not the rule.

Usage::

    from honeylens.env import env

    DB_PASSWORD = env("DB_PASSWORD", "")
    API_PORT = env("API_PORT", 3433, cast=int)
    DEBUG = env("DEBUG", False, cast=bool)
"""

import logging
import os
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

logger = logging.getLogger("honeylens.env")

_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)")
_TRUTHY = frozenset({"1", "true", "yes", "on"})

_loaded: dict[str, str] = {}
_env_file_used: Path | None = None


def default_search_paths() -> list[Path]:
    """``.env`` search order: explicit path, current directory, 1.0 install, 0.9 install."""
    paths: list[Path] = []
    explicit = os.environ.get("HONEYLENS_ENV_FILE")
    if explicit:
        paths.append(Path(explicit))
    paths.append(Path.cwd() / ".env")
    paths.append(Path("/opt/honeylens/.env"))
    paths.append(Path("/opt/sensor/.env"))  # until the migrator exists, also read the 0.9 path
    return paths


def load_env_file(path: Path) -> dict[str, str]:
    """Parse ``.env``: ``KEY=VALUE``, quotes, ``export``, full-line and trailing comments."""
    if not path.is_file():
        return {}
    result: dict[str, str] = {}
    with path.open() as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            m = _LINE_RE.match(line)
            if not m:
                continue
            key, val = m.group(1), m.group(2).strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            else:
                comment_pos = val.find(" #")
                if comment_pos > 0:
                    val = val[:comment_pos].rstrip()
            result[key] = val
    return result


def _check_env_permissions(path: Path) -> None:
    """Secrets in a group- or world-readable file are a finding, not a detail."""
    try:
        mode = path.stat().st_mode & 0o777
    except OSError as exc:
        logger.debug("cannot check permissions of %s: %s", path, exc)
        return
    if mode & 0o044:
        logger.warning(
            "SECURITY: %s has unsafe permissions (%04o); expected 0600. Fix: chmod 600 %s",
            path,
            mode,
            path,
        )


def reload(paths: Sequence[Path] | None = None) -> None:
    """Load ``.env`` from the first existing path (``paths`` or the defaults)."""
    global _loaded, _env_file_used
    _loaded, _env_file_used = {}, None
    for path in default_search_paths() if paths is None else paths:
        loaded = load_env_file(path)
        if loaded:
            _loaded, _env_file_used = loaded, path
            _check_env_permissions(path)
            logger.debug("loaded %d variables from %s", len(loaded), path)
            return
    logger.debug("no .env file; os.environ and defaults only")


def env(key: str, default: Any = None, cast: Callable[[Any], Any] | None = None) -> Any:
    """Configuration value: ``.env`` file → ``os.environ`` → ``default``.

    ``cast=bool`` treats ``1/true/yes/on`` (case-insensitive) as true; ``int`` and
    ``float`` work directly; any other callable receives the raw value.
    """
    val: Any = _loaded.get(key)
    if val is None:
        val = os.environ.get(key)
    if val is None:
        if default is None:
            return None
        val = default
    if cast is None:
        return val
    if cast is bool:
        return val if isinstance(val, bool) else str(val).lower() in _TRUTHY
    return cast(val)


def env_file_path() -> Path | None:
    """Path of the loaded ``.env`` or ``None``."""
    return _env_file_used


reload()
