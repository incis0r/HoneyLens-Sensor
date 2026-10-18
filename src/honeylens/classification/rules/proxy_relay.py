"""Attempts to use the sensor as an HTTP forward proxy.

Measured on the public sensor, 30 days to 2026-11-08, external traffic only: **12,197
`CONNECT` requests from 207 sources, 11,622 of them (95%) with no verdict at all**. That
made it the largest unlabelled family on the busiest sensor in the fleet -- 11x the
unlabelled WordPress traffic on the same host -- and there was no rule for it anywhere in
this package. It arrives at the monolith (10,980), `honeypot-http` (1,188) and even
`honeypot-elasticsearch` (29), because a relay hunter tries every open port, not a web port.

What the requests are, measured rather than assumed. Twenty sources rotate through about ten
destinations on `:443` (5,043), `:80` (5,042) and `:7000` (2,098) -- `tooyoungtoholdon.world`,
`tls.bunnyfeet.baby`, `cdn.youshouldvecomeover.lol` and four Cloudflare-fronted addresses --
and one source reaches for a host named `c2.dstatbot.win`. That is a botnet using open
proxies to get to its own fronted infrastructure; the indicators churn and live in
the internal open-proxy relay IOC notes, not here.

A small, honest minority is not that. 89 of the 12,197 are reachability checks: Shadowserver's
survey (`zgrab`), a proxy-list harvester announcing itself in the user agent, and requests to
`api.ipify.org` / `ip.ipcount.org` -- the "does this relay actually work" probe. Those are
distinguishable and stable, so they get their own rule name under the same verdict and a
lower severity. The lesson is the one `sp-webshell-aspx` taught: a single request does not
say who sent it, and a verdict that claims more than the evidence is a defect even when the
traffic really is hostile.

Hence one verdict and three rule names. `OPEN_PROXY_RELAY` states exactly what happened --
someone asked this host to relay a connection -- and claims nothing about intent, which one
`CONNECT` cannot establish. The distinction an analyst wants lives in
`attack_patterns.rule_name`, which migration 0015 made indexable.

Two payload shapes, because the decoys do not agree on one: the monolith and the
Elasticsearch decoy write the request line (`CONNECT host:port ...`), while `honeypot-http`
writes a JSON summary (`{"phase": "request", "method": "CONNECT", ...}`). A rule matching
only the first would have missed 1,188 rows. `metadata["method"]` is not a usable target --
the classifier's metadata sweep does not read that key, and even if it did, each rule is
matched against each target separately, so no single rule can require both a method and a
path.
"""

from __future__ import annotations

import re

# `CONNECT` followed by whitespace and a host:port authority. Anchored at the start of the
# target: a CONNECT request line begins there, and the anchor is what keeps this off bodies
# that merely mention the word. Oracle's `CONNECT_DATA=` (see database.py) does not match,
# because `_` is not whitespace.
_AUTHORITY = r"[A-Za-z0-9._-]{1,253}:\d{1,5}"

# The destinations a relay checker uses to confirm the tunnel works. Stable, well known, and
# nothing to do with the botnet above -- which is the whole reason they are listed.
_REACHABILITY_HOSTS = (
    r"ipify\.org",
    r"ipcount\.org",
    r"shadowserver\.org",
    r"ifconfig\.me",
    r"icanhazip\.com",
    r"ipinfo\.io",
    r"checkip\.amazonaws\.com",
    r"myip\.com",
    r"ip-api\.com",
    r"ident\.me",
)


def register(add):
    # The fact itself: a forward-proxy request arrived.
    add(
        "OPEN_PROXY_RELAY",
        "open_proxy_connect_request",
        rf"^CONNECT\s+{_AUTHORITY}",
        re.IGNORECASE,
    )
    # The same fact as `honeypot-http` records it.
    add(
        "OPEN_PROXY_RELAY",
        "open_proxy_connect_json",
        r'"method"\s*:\s*"CONNECT"',
        re.IGNORECASE,
    )
    # CONNECT whose target is not an authority at all. Two measured shapes, both malformed
    # and both unmistakably proxy requests:
    #
    #   `CONNECT /`                              nine requests from nine separate sources,
    #                                            the shape of a one-shot survey; zgrab sends it
    #   `CONNECT https://c1.dstatbots.win/dstat` an absolute URI where an authority belongs,
    #                                            from the same actor family as the
    #                                            `dstatbot.win` destinations on another sensor
    #
    # Its own rule because the authority pattern cannot match either, and loosening that one
    # to `\S+` would have it fire on the word "CONNECT" in any sentence. Found by the
    # backfill: 199 of 201 candidates on one sensor matched, and chasing the other two is
    # what turned up the absolute-URI shape.
    add(
        "OPEN_PROXY_RELAY",
        "open_proxy_connect_no_authority",
        r"^CONNECT\s+(?:/|[a-z][a-z0-9+.-]*://)",
        re.IGNORECASE,
    )
    # A subset of the first rule, deliberately: both fire, and the pair of rule_names is how
    # a reader subtracts the surveys from the campaign without re-reading payloads.
    add(
        "OPEN_PROXY_RELAY",
        "open_proxy_reachability_check",
        rf"^CONNECT\s+(?:[A-Za-z0-9._-]{{1,253}}\.)?(?:{'|'.join(_REACHABILITY_HOSTS)}):\d{{1,5}}",
        re.IGNORECASE,
    )
