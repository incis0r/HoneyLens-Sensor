"""Request classification for the WAGO WBM decoy (Idea 54 Phase 2).

Two jobs. Per request, run the signature catalogue and return the strongest match.
Across requests, correlate what one source is doing: a WBM page sweep is invisible in
any single request and obvious over a window, and a source that read the I/O map and
then wrote to the process is telling a different story than one that only did either.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .signatures import SIGNATURES, WBM_PATHS

_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}

# How many distinct WBM pages from one source count as a sweep rather than a visit.
ENUMERATION_THRESHOLD = 5
ENUMERATION_WINDOW = 300.0  # seconds

# A source that read the I/O map and then wrote to the process inside this window is
# the sequence that matters on a real plant: understand the process, then change it.
CHAIN_WINDOW = 1800.0


@dataclass
class Detection:
    matched: bool = False
    attack_class: str = "none"
    attack_type: str = ""
    rule_name: str = ""
    cve_id: str = ""
    confidence: str = "none"
    indicators: list[str] = field(default_factory=list)


def classify(method: str, path: str, fields: dict[str, str], body: str = "") -> Detection:
    """Strongest signature match for one request, or an empty Detection."""
    method = (method or "GET").upper()
    path = (path or "").split("?", 1)[0]
    fields = fields or {}

    best: Detection | None = None
    indicators: list[str] = []
    for sig in SIGNATURES:
        m = sig.match(method, path, fields, body)
        if not m:
            continue
        indicators.extend(m.indicators)
        candidate = Detection(
            matched=True,
            attack_class=sig.key,
            attack_type=sig.attack_type,
            rule_name=sig.rule_name,
            cve_id=sig.cve_id,
            confidence=m.confidence,
            indicators=list(m.indicators),
        )
        if best is None or _CONFIDENCE_RANK[m.confidence] > _CONFIDENCE_RANK[best.confidence]:
            best = candidate

    if best is None:
        return Detection()
    # Keep every indicator, not just the winner's: a request can be both an overlong
    # parameter and a traversal, and dropping one loses evidence.
    best.indicators = indicators
    return best


class SourceTracker:
    """Per-source memory for the patterns a single request cannot show."""

    def __init__(
        self, enumeration_window: float = ENUMERATION_WINDOW, chain_window: float = CHAIN_WINDOW
    ):
        self.enumeration_window = enumeration_window
        self.chain_window = chain_window
        self._pages: dict[str, list[tuple]] = {}  # src -> [(ts, path)]
        self._io_reads: dict[str, float] = {}  # src -> last I/O map read
        self._lock = threading.Lock()
        self._cap = 4096  # bounded: this is attacker-driven

    def observe(
        self, src_ip: str, path: str, detection: Detection, now: float | None = None
    ) -> list[str]:
        """Record the request; return cross-request indicators it completes."""
        now = time.time() if now is None else now
        extra: list[str] = []
        if not src_ip:
            return extra

        with self._lock:
            self._prune_locked(now)

            if path in WBM_PATHS:
                seen = self._pages.setdefault(src_ip, [])
                seen.append((now, path))
                distinct = {p for ts, p in seen if now - ts <= self.enumeration_window}
                if len(distinct) >= ENUMERATION_THRESHOLD:
                    extra.append(f"wbm_enumeration:{len(distinct)}_pages")

            if "io_map_read" in " ".join(detection.indicators):
                self._io_reads[src_ip] = now
            elif detection.attack_type == "WAGO_CONTROL_WRITE":
                last = self._io_reads.get(src_ip)
                if last is not None and now - last <= self.chain_window:
                    # Read the process map, then changed the process.
                    extra.append(f"recon_then_control:{int(now - last)}s")

            # Enforce the cap *after* inserting: pruning first left room for one more
            # entry on every call, so the maps drifted past the limit.
            self._enforce_cap_locked()

        return extra

    def _prune_locked(self, now: float) -> None:
        for src in list(self._pages):
            kept = [(ts, p) for ts, p in self._pages[src] if now - ts <= self.enumeration_window]
            if kept:
                self._pages[src] = kept[-64:]
            else:
                del self._pages[src]
        for src in list(self._io_reads):
            if now - self._io_reads[src] > self.chain_window:
                del self._io_reads[src]

    def _enforce_cap_locked(self) -> None:
        """Hard cap so a spoofed-source flood cannot grow these maps without bound."""
        for store in (self._pages, self._io_reads):
            excess = len(store) - self._cap
            if excess > 0:
                for src in list(store)[:excess]:
                    del store[src]
