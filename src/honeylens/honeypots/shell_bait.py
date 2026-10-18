"""Answering a web-shell hunt, and refusing to do it under someone else's name.

Some scanners do not attack an application. They sweep for web shells that *other*
people left behind, so they can inherit them: a long list of filenames harvested
from real compromises, requested one after another, all GET, no user-agent. A
default page answers 404-equivalent content and they move on.

If the honeypot answers 200 instead, the scanner believes it found a live shell,
and what it sends *next* is the interesting part — the password it tries, the
command it runs, the address it reports to. That is evidence worth having, and it
is the whole reason this decoy exists.

**The constraint that shapes this module.** A recycled address can inherit a
stranger's DNS. On one sensor a third party's domain still resolves to us, so a
share of this traffic arrives with their hostname in the Host header. Answering
"200, the shell is here" under their name would manufacture evidence that their
site is compromised — evidence an attacker could act on, sell or publish. So:

    Host is a foreign domain  ->  421, empty. We front nobody else's brand.
    Host is our own           ->  bait may answer, and we log what comes back.

That split is not a nicety. It is what makes the bait safe to run at all, and it
costs little: on the sensor this was written for, 22 of the 27 shell-hunting
sources also probe under our own address.

The bait is opt-in (`HP_HTTP_SHELL_BAIT`), and the path list is explicit rather
than a clever pattern. A broad regex would have this honeypot answering 200 to a
large share of everything that scans it, which would change what the sensor
measures and pollute every dataset built on it.
"""

from __future__ import annotations

import os
import re


def _env_list(name: str) -> list[str]:
    raw = os.getenv(name, "") or ""
    return [x.strip().lower().lstrip(".") for x in raw.split(",") if x.strip()]


def _env_bool(name: str, default: bool = False) -> bool:
    v = (os.getenv(name, "") or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


# Filenames observed being swept for on our sensors, plus a few classics. Explicit
# by design — see the module docstring on why this is not a pattern match.
_SHELL_NAMES = {
    "this_is_a_new_hello_world.php",
    "4pjcpmfsd8b.php",
    "3pjcpmfsd8b.php",
    "bdkr28wp.php",
    "classwithtostring.php",
    "images.php",
    "ops.php",
    "1.php",
    "mac.php",
    "simple.php",
    "chosen.php",
    "222.php",
    "dex.php",
    "media.php",
    "fling.php",
    "k.php",
    "admin.php",
    "goods.php",
    "wp.php",
    "shell.php",
    "c99.php",
    "r57.php",
    "alfa.php",
    "wso.php",
    "up.php",
    "cmd.php",
    "byp.php",
    "0.php",
    "x.php",
}

# The file-manager plugin shape, which arrives as a path rather than a bare name.
_SHELL_PATHS = re.compile(
    r"^/wp-content/plugins/[a-z0-9_-]{1,40}/(wp_)?file[_-]?manager\.php$",
    re.IGNORECASE,
)


def extra_names() -> set:
    return {n.lower() for n in _env_list("HP_HTTP_SHELL_BAIT_EXTRA")}


def is_shell_probe(path: str | None) -> bool:
    """True when `path` is a request for a known web-shell filename."""
    if not path:
        return False
    p = path.split("?", 1)[0].strip()
    if not p.lower().endswith(".php"):
        return False
    if _SHELL_PATHS.match(p):
        return True
    name = p.rsplit("/", 1)[-1].lower()
    return name in _SHELL_NAMES or name in extra_names()


def is_foreign_host(host: str | None) -> bool:
    """True when the Host header names a domain that is not ours to answer for.

    Configured as suffixes, so `sfos.com.au` also covers `www.` and `assets.`.
    The port is stripped; a trailing dot is tolerated because resolvers send it.
    """
    foreign = _env_list("HP_HTTP_FOREIGN_HOSTS")
    if not foreign or not host:
        return False
    h = host.split(":", 1)[0].strip().lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in foreign)


def bait_enabled() -> bool:
    return _env_bool("HP_HTTP_SHELL_BAIT", False)


def decide(path: str | None, host: str | None) -> str | None:
    """Return the response mode, or None to serve the ordinary page.

    "misdirected" — a foreign domain resolves here; refuse without content.
    "bait"        — a shell probe under our own name; answer 200, empty.
    """
    if is_foreign_host(host):
        return "misdirected"
    if bait_enabled() and is_shell_probe(path):
        return "bait"
    return None


def build(mode: str, server_header: str) -> bytes:
    """Render the response for a mode returned by `decide`."""
    if mode == "misdirected":
        # 421 is the correct answer for a Host this server is not authoritative
        # for, and it gives a scanner nothing to act on.
        return (
            "HTTP/1.1 421 Misdirected Request\r\n"
            f"Server: {server_header}\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
    if mode == "bait":
        # An empty 200 is what many planted shells return to a bare GET: no
        # banner to fingerprint, but enough for a sweep to record a hit.
        return (
            "HTTP/1.1 200 OK\r\n"
            f"Server: {server_header}\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
    raise ValueError(f"unknown mode {mode!r}")
