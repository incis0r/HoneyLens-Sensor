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
from collections.abc import Iterable


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
    """True when the host a request claims names a domain that is not ours to answer for.

    Configured as suffixes, so `sfos.com.au` also covers `www.` and `assets.`.
    The port is stripped; a trailing dot is tolerated because resolvers send it.

    Userinfo is stripped too, from the LAST `@` so that `user:pass@host` works: without
    that, `user@victim.example` normalised to itself, matched nothing, and was served the
    full page — on all three entry points, since every one of them funnels through here.
    RFC 9113 §8.3.1 makes a `:authority` carrying userinfo malformed and RFC 9110 §7.2 has
    no userinfo in `Host`, so a conformant server rejects such a request outright; we were
    more permissive than both the RFC and Apache, in the direction that serves content
    under someone else's name. Normalising rather than rejecting keeps this function's one
    job, and it errs the safe way: more hosts classified foreign, never fewer.
    """
    foreign = _env_list("HP_HTTP_FOREIGN_HOSTS")
    if not foreign or not host:
        return False
    h = host.rpartition("@")[2].split(":", 1)[0].strip().lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in foreign)


def target_authority(target: str | None) -> str | None:
    """The authority a request-target or an HTTP/2 ``:path`` carries, if any.

    Recognises, by shape alone:

    - ``scheme://authority/...`` absolute-form (RFC 9112 §3.2.2) → the authority.
    - ``host:port`` authority-form (RFC 9112 §3.2.3, CONNECT) → ``host:port``.
    - ``//authority/...`` network-path reference (RFC 3986 §4.2) → the authority.
    - ``/path`` origin-form and ``*`` asterisk-form → ``None``; they carry no authority.

    **``//x`` is ambiguous and that is not fixable here.** RFC 9112 §3.2.1 makes an
    absolute path with an empty first segment a legal origin-form, so ``//images.php`` and
    ``//victim.example/`` are the same shape on the wire and nothing short of guessing
    tells them apart. Both are reported as a claim. That is only sound because
    `host_claims` *adds* this to the other claims instead of replacing them: when it
    replaced ``Host``, ``GET //images.php`` with a foreign ``Host`` classified **fewer**
    hosts foreign, and the bait answered under a stranger's name. A claim that is
    sometimes a path segment can add refusals; it must never remove one.

    Hand-rolled rather than handed to ``urllib.parse``: ``urlsplit`` reads
    ``victim.example:80`` as *scheme* ``victim.example`` with an empty ``netloc``, which is
    the authority-form row above silently vanishing.
    """
    if not target or target == "*":
        return None
    rest = target
    if rest.startswith("//"):
        rest = rest[2:]
    elif rest.startswith("/"):
        return None
    else:
        _scheme, separator, after = rest.partition("://")
        if separator:
            rest = after
    for index, char in enumerate(rest):
        if char in "/?#":
            rest = rest[:index]
            break
    return rest or None


def host_claims(
    *,
    target: str | None = None,
    host_header: str | Iterable[str] | None = None,
    authority: str | None = None,
) -> list[str]:
    """Every host a request claims, in whichever spellings it used.

    **This function exists because the guard below was bypassed four times in four
    rounds, each time by a legal spelling the previous reader had not thought of.** The
    spellings live in two protocols and used to be read in three places, each with its own
    partial view. A union in one place is the answer to that, not a longer list in any one
    caller — so every spelling is gathered here and `decide` refuses if **any** of them
    names a foreign host.

    | # | spelling                              | passed as     | protocol |
    |---|---------------------------------------|---------------|----------|
    | 1 | ``Host`` header, **every value**      | `host_header` | HTTP/1.1 |
    | 2 | authority inside the request-target   | `target`      | HTTP/1.1 |
    | 3 | ``:authority`` pseudo-header          | `authority`   | HTTP/2   |
    | 4 | ``host`` header on a stream           | `host_header` | HTTP/2   |
    | 5 | authority inside an absolute ``:path``| `target`      | HTTP/2   |

    2 and 5 are the same parse (`target_authority`) and 1 and 4 are the same header under
    two protocol names, which is why five spellings need three parameters.

    **Union, not precedence.** RFC 9112 §3.2.2 does say a server must ignore ``Host`` in
    favour of an absolute-form target, and implementing that literally was a regression:
    anything the parser was willing to call an authority then replaced a foreign ``Host``.
    For deciding whether we may serve content the question is not "which claim wins" but
    "did this request name anyone we must not answer for", and that is a union.

    **This is deliberately stricter than both the RFC and httpd, and the strictness is
    ours — not something we are copying.** httpd's ``ap_parse_uri`` only takes the host
    from the request-target when the parsed scheme matches the server's own, or for
    ``CONNECT``; it does not resolve a network-path reference like ``//host/path`` at all,
    where ``Host`` stays authoritative. We refuse on any of these claims regardless. That
    costs us only requests which name a third party *somewhere*, and the thing it buys is
    that we never answer with content under a stranger's name — which is the only reason
    the bait above is safe to run. Erring toward a 421 is cheap; erring the other way
    manufactures evidence against someone who never asked us for anything.

    A sixth spelling gets added **here**. This table is where to look, not a promise that
    it is complete — four rounds say otherwise.
    """
    # One value or all of them: a request may carry `Host` more than once, and the first
    # value is as much a claim as the last. Taking only the last served the full page to a
    # request whose FIRST `Host` named a stranger. Same shape as `decide`'s argument, and
    # the same reason: a bare string must not be read as an iterable of characters.
    headers = [host_header] if isinstance(host_header, str) else list(host_header or ())
    claims = [target_authority(target), *headers, authority]
    return [claim for claim in claims if claim]


def foreign_claim(claims: Iterable[str]) -> str | None:
    """The first claim naming a domain that is not ours, or ``None`` if none does.

    The caller records it as the row's host: without it a refusal said
    ``host='decoy.invalid'`` while the foreign name it actually refused for appeared
    nowhere, and no host-based hunt could find the event.
    """
    for claim in claims:
        if is_foreign_host(claim):
            return claim
    return None


def bait_enabled() -> bool:
    return _env_bool("HP_HTTP_SHELL_BAIT", False)


def decide(path: str | None, host: str | Iterable[str] | None) -> str | None:
    """Return the response mode, or None to serve the ordinary page.

    "misdirected" — a foreign domain resolves here; refuse without content.
    "bait"        — a shell probe under our own name; answer 200, empty.

    ``host`` is the request's host claim, or — from `host_claims` — every claim it
    carries. A request is misdirected when **any** claim is foreign, because one request
    naming a stranger's domain anywhere is a request we must not answer with content.
    """
    claims = [host] if isinstance(host, str) else list(host or ())
    if foreign_claim(claims) is not None:
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
