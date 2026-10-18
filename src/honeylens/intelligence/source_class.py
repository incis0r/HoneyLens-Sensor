"""source_class.py — whose traffic was this?

Phase C of the verdict-defects remediation. Measured over 30 days to 2026-11-04, **2,139,975
rows — 12.8% of everything the fleet recorded — came from us**: our own sensors and jump hosts,
the operator validating a decoy, and the lab's internal ranges. They are the single root cause
behind the window's three most distorted verdicts (`ANOMALY` 99.7% own traffic,
`SURICATA_ALERT` 97.9%, `SCANNER` 83.1%).

The choice was to keep those rows and mark them, not to drop them at ingest: a validation run is
evidence that the decoy works, and an own-traffic row that vanishes cannot be audited. So
provenance becomes a stored fact, written once by the ingest that saw the event, and every reader
filters on it instead of guessing from a CIDR list at report time.

Three things this module is deliberately strict about:

* **`None` means "a real actor".** It is the value readers filter on, and it is what a missing,
  malformed or unrecognised address produces. Guessing "ours" would hide an actor on the strength
  of a parse failure, which is the expensive direction of the error.
* **A varchar, not a boolean.** The standing reporting discipline is two columns — what arrived,
  and what arrived from something that is not an actor — and "why it is ours" is exactly what a
  boolean throws away.
* **`internal` is an explicit list of networks, not `ipaddress.is_private`.** Python counts
  `100.64.0.0/10` as private; CGNAT is where a great many real senders live, and `prod` itself
  sits behind a client NAT. The property would have classified those senders as ours.

Nothing here does I/O. It runs on the ingest hot path, once per event, against networks compiled
at import.

No address of ours is written down here. `SOURCE_CLASS_OWN_INFRA` and `SOURCE_CLASS_VALIDATION`
default to empty and are set in the deployment's env file, because this file is committed.
"""

from __future__ import annotations

import ipaddress
import logging

from honeylens.config import SOURCE_CLASS_OWN_INFRA, SOURCE_CLASS_VALIDATION

logger = logging.getLogger("source_class")

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# The three reasons a row can be ours. Kept to 16 characters: migration 0013 declares
# `source_class VARCHAR(16)`.
OWN_INFRA = "own_infra"
VALIDATION = "validation"
INTERNAL = "internal"


def _compile(raw: tuple[str, ...] | list[str]) -> tuple[IPNetwork, ...]:
    """Configured addresses and CIDRs as network objects, built once.

    A bare address becomes a `/32` (or `/128`), which is what the validation sources need: they
    are an operator's own external addresses, not a subnet we own, and sweeping their neighbours
    in would silently hide whoever sits next to them. `config.parse_cidrs` already normalises
    this, but the module accepts raw strings too so a deployment that sets the value by hand or
    a test that configures it directly behaves identically.
    """
    out: list[IPNetwork] = []
    for item in raw:
        text = str(item).strip()
        if not text:
            continue
        try:
            out.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            logger.warning("source_class: ignoring unparseable entry %r", text)
    return tuple(out)


# RFC1918, loopback, link-local and IPv6 unique-local. Written out rather than taken from
# `is_private` so that CGNAT (`100.64.0.0/10`), `0.0.0.0/8` and the reserved blocks stay
# classifiable as actors — see the module docstring.
_INTERNAL_NETS: tuple[IPNetwork, ...] = _compile(
    (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fe80::/10",
        "fc00::/7",
    )
)

_OWN_INFRA: tuple[IPNetwork, ...] = _compile(SOURCE_CLASS_OWN_INFRA)
_VALIDATION: tuple[IPNetwork, ...] = _compile(SOURCE_CLASS_VALIDATION)


def reload_config() -> None:
    """Re-read the configured lists. For a long-lived service after an env change."""
    global _OWN_INFRA, _VALIDATION
    from honeylens import config

    _OWN_INFRA = _compile(config.SOURCE_CLASS_OWN_INFRA)
    _VALIDATION = _compile(config.SOURCE_CLASS_VALIDATION)


def excluded_networks() -> tuple[str, ...]:
    """Every network a row could be ours from, as CIDR strings, for a SQL-side filter.

    `classify_source` is the authority and runs at ingest, but a reader that must not leak
    our traffic cannot rely on the stored class alone: `source_class IS NULL` also covers
    every row written before migration 0013 and not yet backfilled, so on those rows NULL
    means "not computed", not "a real actor". A reader whose output leaves this project --
    the honeypot read API -- filters on both, and this is the second filter.

    The values come from the deployment's env file at runtime. No address of ours is
    written down in this file, which is the rule stated in the module docstring.
    """
    return tuple(str(net) for net in (_OWN_INFRA + _VALIDATION + _INTERNAL_NETS))


def _parse(ip: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """An address from any of the shapes the store hands us, or None.

    `src_ip::text` on an `inet` column carries a `/32` — the trap recorded in
    `event-store-query-traps` — so a prefix is stripped rather than failing the parse. A
    backfill reading that column would otherwise classify every row as an actor.
    """
    if not ip:
        return None
    text = str(ip).strip()
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _in_any(addr: ipaddress.IPv4Address | ipaddress.IPv6Address, nets) -> bool:
    """`addr in net` raises on a family mismatch, and an ingest that raises loses the event."""
    return any(addr.version == net.version and addr in net for net in nets)


def classify_source(ip: str | None, *, address_learned_from_edge: bool = False) -> str | None:
    """`"own_infra"`, `"validation"`, `"internal"`, or None for a real actor.

    Precedence is own_infra, then validation, then internal. An address can be in two lists --
    a sensor of ours the operator also validates from -- and "our infrastructure" is the more
    specific true statement about it.

    `address_learned_from_edge` says the address did not come from the TCP peer: it was read out
    of an edge header, or it *is* the edge's own address because no usable header arrived. Such a
    row is always None -- a real actor -- and that is the whole point of the flag, in both
    directions:

    * a header the client may have written must not let an attacker claim a private address and
      disappear from the nine dashboard queries that filter `source_class IS NULL`;
    * an address that is ours only because we lost the client's must not hide the interaction
      either. Measured 2026-11-06 on `sensor-c`: 10,650 SharePoint rows carrying a real client in
      `X-Real-IP` stored the edge's own address instead, and every one read `internal`.

    It is the same rule migration 0013 already states for an unparseable address -- "guessing
    'ours' would hide an actor on the strength of a parse failure" -- applied to the other way
    of not knowing. NULL is the safe answer because it is the visible one.
    """
    if address_learned_from_edge:
        return None
    addr = _parse(ip)
    if addr is None:
        return None
    if _in_any(addr, _OWN_INFRA):
        return OWN_INFRA
    if _in_any(addr, _VALIDATION):
        return VALIDATION
    if _in_any(addr, _INTERNAL_NETS):
        return INTERNAL
    return None
