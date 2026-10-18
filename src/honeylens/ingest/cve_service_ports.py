"""Which service a CVE belongs to, so a CVE label stops appearing where that service is not.

A Suricata rule declares a CVE in its metadata and the ingest promotes it to a verdict token.
Nothing in that path asks whether the port the alert landed on runs the affected software, and
four of the worst offenders are third-party rules we cannot edit — so the check has to live here,
where the label is derived, rather than only as a port qualifier in ``rules/suricata/``.

Measured on the fleet 2026-11-04 (the 4 Oct-4 Nov fleet review §5.6). Two distinct defects:

* **bind.** Our nginx script-engine rule (sid 9026731) put ``CVE-2026-42533`` on 402 rows, of
  which **three** were on the nginx decoy: 287 landed on ``:80`` — the Apache bait on ``sensor-a`` and
  ``prod``, the NetScaler decoy on ``sensor-b`` — 66 on etcd's ``:2379``, 27 on the alternate HTTP port, the rest on
  WAGO and K8s ports. Our Apache ``mod_http2`` rule (sid 9026500) put ``CVE-2026-23918`` on 575
  rows across 28 ports including telnet, SMTP, MySQL, RDP, VNC, OPC UA, EtherNet/IP, Fox and AFP;
  451 of those rows sat on ``:8080`` and ``:8000``, the K8s and nginx decoys, not the Apache bait.
* **demote.** ``CVE-2002-1149`` is not ours and not a port problem: it comes from ET sid 2019526,
  *"ET WEB_SERVER WEB-PHP phpinfo access"*, 393 rows on ten web ports. Asking a server for
  ``phpinfo`` is reconnaissance; promoting the CVE the rule declares turns it into a 24-year-old
  exploit finding. No port binding can fix that, so the declaration itself is demoted.

Deliberately conservative. An unknown CVE, an unknown port and an unparseable token all pass:
this module only ever withholds a claim it can show to be wrong. Withholding is safe because the
row keeps its base verdict — measured, that is ``DOS``, ``SCANNER``, ``SURICATA_ALERT``, ``RCE``
or ``WEB_EXPLOIT`` — and the declaration survives in ``payload.cve_declared`` as evidence, the
same treatment the hunting-rule gate already applies.
"""

from __future__ import annotations

import re
from functools import lru_cache

from honeylens.honeypots import manifest

_CVE_RE = re.compile(r"^CVE[-_](\d{4})[-_](\d{4,7})$", re.IGNORECASE)

# CVE → the honeypots in manifest.py that impersonate the affected software. The ports come from
# the manifest so that moving a decoy moves its binding with it; a literal here would drift.
_BOUND_TO_DECOYS: dict[str, tuple[str, ...]] = {
    # nginx script-engine shared-capture leak + heap overflow. Our sids 9026730-9026732.
    "CVE-2026-42533": ("nginx",),
    # nginx Rift, escapable-char flood / pool cleanup. Our sids 9026420-9026424.
    "CVE-2026-42945": ("nginx",),
    # HTTP/2 bomb. Our sids 9026700-9026704. h2bomb.py is imported by hp_nginx, so the nginx
    # decoy is the affected service even though the rules used to name the Apache bait and the
    # PAN-OS captive ports. The behaviour alone, without the CVE, is sid 9026706 on every HTTP
    # decoy port.
    "CVE-2026-49975": ("nginx",),
    # Apache 2.4.66 mod_http2 double-free. Our sids 9026500-9026503. The bait is hp_http on :80;
    # an h2c upgrade offered to the nginx or K8s decoy is not this CVE.
    "CVE-2026-23918": ("http",),
    # PAN-OS GlobalProtect forged auth-override cookie. Our sids 9026330-9026332.
    "CVE-2026-0257": ("paloalto",),
    # NetScaler doAuthentication.do pitboss overflow. Our sids 9026770-9026773.
    "CVE-2026-88771": ("netscaler",),
    # WAGO WBM, our sids 9026755/9026756.
    "CVE-2023-1698": ("wago",),
    "CVE-2023-4089": ("wago",),
}

# (CVE, sid) pairs where the rule's declaration misdescribes what the request did. Keyed on the
# sid as well: it is one rule's claim that is wrong, not the CVE itself.
_DEMOTED_DECLARATIONS: frozenset[tuple[str, int]] = frozenset(
    {
        # "ET WEB_SERVER WEB-PHP phpinfo access" — reconnaissance, not exploitation.
        ("CVE-2002-1149", 2019526),
    }
)


def _as_int(value: object) -> int | None:
    """An int from a Suricata field that may be missing, a string, or something else entirely."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def normalise_cve(cve: object) -> str:
    """``CVE_2026_42533``, ``cve-2026-42533`` → ``CVE-2026-42533``; anything else → ``""``."""
    if not cve:
        return ""
    m = _CVE_RE.match(str(cve).strip())
    if not m:
        return ""
    return f"CVE-{m.group(1)}-{m.group(2)}"


@lru_cache(maxsize=256)
def service_ports_for(cve: object) -> frozenset[int] | None:
    """Ports the CVE's affected service occupies on a 1.0 sensor, or ``None`` when unbound."""
    key = normalise_cve(cve)
    names = _BOUND_TO_DECOYS.get(key)
    if not names:
        return None
    return decoy_ports(names)


@lru_cache(maxsize=64)
def decoy_ports(names: tuple[str, ...]) -> frozenset[int]:
    """Protocol ports and bound ports of the named decoys.

    Both, because the two subsystems that read a port disagree about which one it is. A honeypot
    event carries the protocol port -- ``HONEYLENS_PORT_MAP`` translates the bound port back --
    while Suricata reports what it saw on the wire, and whether that is the protocol port or the
    bound one depends on where the host's DNAT sits relative to the capture interface. Measured
    on ``sensor-b``: the NetScaler decoy's own rows say ``:80``, and Suricata's rows for the same
    decoy say ``:50080``. Naming only one of the pair would silently suppress real findings on
    whichever sensor is plumbed the other way round.
    """
    ports: set[int] = set()
    for name in names:
        hp = manifest.get(name)
        for bound, protocol in hp.port_map:
            ports.add(bound)
            ports.add(protocol)
    return frozenset(ports)


def cve_is_in_service(cve: object, dst_port: object) -> bool:
    """False only for a bound CVE on a port its service does not occupy."""
    ports = service_ports_for(cve)
    if ports is None:
        return True
    port = _as_int(dst_port)
    if not port:
        return True
    return port in ports


def cve_is_a_finding(cve: object, sid: object) -> bool:
    """False when this rule's CVE declaration describes reconnaissance, not exploitation."""
    key = normalise_cve(cve)
    if not key:
        return True
    rule_sid = _as_int(sid)
    if rule_sid is None:
        return True
    return (key, rule_sid) not in _DEMOTED_DECLARATIONS
