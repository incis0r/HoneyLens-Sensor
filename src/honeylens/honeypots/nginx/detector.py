"""Catalog-driven per-request classifier for the NGINX honeypot.

`classify()` runs every signature in the CVE catalog over one request and returns
the single highest-severity match (with the union of all indicators). The
CVE-2026-42945 "Rift" flood/spray -> dos/rce resolution and its cross-request
`SourceTracker` correlation are preserved from the original single-CVE honeypot.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .signatures import CAPTURE_LEN_HIGH, CATALOG

_SEV_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}


@dataclass
class Detection:
    matched: bool = False
    attack_class: str = "none"  # e.g. cve-2026-42945-rce | cve-2026-42533 | none
    cve_id: str = ""
    attack_type: str = ""  # emitted label, e.g. cve_2026_42945_rce
    confidence: str = "none"  # high|medium|low|none
    is_overflow: bool = False  # overflow-class -> fake-crash oracle
    indicators: list = field(default_factory=list)


def _resolve_42945(indicators: list) -> tuple:
    """(attack_class, attack_type, confidence) for a Rift match."""
    kinds = {i.split(":")[0] for i in indicators}
    flood = "api_escape_flood" in kinds
    spray = "pool_spray_body" in kinds
    if spray:
        return "cve-2026-42945-rce", "cve_2026_42945_rce", "high" if flood else "medium"
    run = max(
        (int(i.split(":")[1]) for i in indicators if i.startswith("api_escape_flood")), default=0
    )
    return "cve-2026-42945-dos", "cve_2026_42945_dos", "high" if run >= 64 else "medium"


def _resolve_42533(indicators: list) -> tuple:
    """(attack_class, attack_type, confidence, is_overflow) for a 42533 match.

    A body-driven capture overflow is the memory-corruption trigger (fake-crash
    oracle); a URI/header capture with no body overflow is the info-leak recon
    primitive (no crash). Overflow outranks leak. Confidence rises with magnitude.
    """

    def _mag(prefix):
        return max((int(i.split(":")[1]) for i in indicators if i.startswith(prefix)), default=0)

    if any(i.startswith("cve_2026_42533_overflow") for i in indicators):
        n = _mag("cve_2026_42533_overflow")
        return (
            "cve-2026-42533",
            "NGINX_CVE_2026_42533",
            "high" if n >= CAPTURE_LEN_HIGH else "medium",
            True,
        )
    n = _mag("cve_2026_42533_leak")
    return (
        "cve-2026-42533-leak",
        "NGINX_CVE_2026_42533_LEAK",
        "medium" if n >= CAPTURE_LEN_HIGH else "low",
        False,
    )


def classify(
    method: str, raw_path: bytes, headers: dict, body: bytes, http_version: str = "HTTP/1.1"
) -> Detection:
    """Classify one HTTP request against the whole CVE catalog."""
    all_indicators: list = []
    best_rank = -1
    best = None

    for sig in CATALOG:
        m = sig.match(method, raw_path, headers, body, http_version)
        if not m:
            continue
        all_indicators.extend(m.indicators)
        is_overflow = sig.is_overflow
        if sig.cve_id == "CVE-2026-42945":
            attack_class, attack_type, conf = _resolve_42945(m.indicators)
        elif sig.cve_id == "CVE-2026-42533":
            attack_class, attack_type, conf, is_overflow = _resolve_42533(m.indicators)
        else:
            attack_class, attack_type, conf = sig.attack_class, sig.attack_type, m.confidence
        # overflow-class matches outrank recon-class at equal confidence
        rank = _SEV_RANK.get(conf, 0) * 2 + (1 if is_overflow else 0)
        if rank > best_rank:
            best_rank = rank
            best = Detection(True, attack_class, sig.cve_id, attack_type, conf, is_overflow, [])

    if best is None:
        return Detection(indicators=all_indicators)
    best.indicators = all_indicators
    return best


class SourceTracker:
    """Correlates per-request detections from one source into an attack story.

    A CVE-2026-42945 flood and a spray from the same source within the window
    together mean a full RCE attempt, not two unrelated probes. Other CVEs are
    single-request, so the tracker simply echoes their class.
    """

    def __init__(self, window_seconds: float = 120.0):
        self.window = window_seconds
        self._seen: dict = {}  # src_ip -> list[(ts, indicator)]
        self._lock = threading.Lock()

    def observe(self, src_ip: str, detection: Detection, now: float) -> str:
        with self._lock:
            rec = self._seen.setdefault(src_ip, [])
            for ind in detection.indicators:
                rec.append((now, ind))
            cutoff = now - self.window
            rec[:] = [(t, i) for (t, i) in rec if t >= cutoff]
            kinds = {i.split(":")[0] for (_, i) in rec}
            if "api_escape_flood" in kinds and "pool_spray_body" in kinds:
                return "cve-2026-42945-rce"
            if "pool_spray_body" in kinds:
                return "cve-2026-42945-rce"
            if "api_escape_flood" in kinds:
                return "cve-2026-42945-dos"
            return detection.attack_class
