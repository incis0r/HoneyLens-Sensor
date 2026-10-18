"""What is this request, when a vendor decoy does not recognise the path?

Each appliance decoy files anything unfamiliar as `UNKNOWN_PATH` and its ingest then
mapped that to a vendor label — `PANOS_PROBE`, `FORTI_PROBE`. That turned "I don't know"
into an assertion about the attacker's target, and the assertion was frequently wrong: a
Cisco AnyConnect probe (`GET /+CSCOE+/logon.html`) landing on the PAN-OS decoy at :4443
was filed as Palo Alto reconnaissance, and the same request on the FortiGate decoy at
:10443 as Fortinet reconnaissance. Neither is what the attacker asked for.

The decoy that answered says nothing about what was requested. The path does. So when the
decoy has no opinion, run the same text rules the generic honeypot ingest uses and let
them name it; keep the vendor label only when nothing else identifies the request, which
is the honest answer for a genuinely unknown path aimed at that decoy.
"""

from __future__ import annotations

import logging

from honeylens.classification.attack_classifier import classify_event_row
from honeylens.classification.scoring import get_severity

logger = logging.getLogger(__name__)


def request_text(data: dict) -> str:
    """The parts of a decoy event a text rule can match against.

    Method, path with query, and User-Agent — the same surface the generic HTTP
    honeypot presents to the classifier. Nothing else from the decoy event is included:
    its own labels are what we are trying not to trust here.
    """
    if not isinstance(data, dict):
        return ""
    path = data.get("path") or ""
    query = data.get("query") or ""
    if query:
        path = f"{path}?{query}"
    parts = [data.get("method") or "", path, data.get("user_agent") or ""]
    return " ".join(p for p in parts if p).strip()


def classify(data: dict):
    """[(attack_type, severity, rule_name)] for an unrecognised path, [] if none match.

    The rule name travels with the verdict so the `attack_patterns` row can record which
    rule decided. Without it the row said `paloalto_unknown_path` while carrying a Cisco
    attack type — the verdict right, the provenance misleading, and no way to tell from
    the table whether the decoy or the classifier produced it.
    """
    text = request_text(data)
    if not text:
        return []
    try:
        hits = classify_event_row(payload=text, protocol="HTTP", metadata=data)
    except Exception as e:
        logger.debug("foreign-path classification failed: %s", e)
        return []
    out, seen = [], set()
    for atype, rule, _snippet in hits:
        if atype in seen:
            continue
        seen.add(atype)
        out.append((atype, get_severity(atype, rule).upper(), rule))
    return out
