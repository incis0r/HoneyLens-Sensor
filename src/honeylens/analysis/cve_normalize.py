#!/usr/bin/env python3
"""
cve_normalize.py — canonicalise / validate AI-emitted CVE identifiers
=====================================================================
The triage/deep models frequently return junk in the ``known_cve`` field: the
literal string ``"null"``, placeholders like ``CVE-XXXX-XXXXX`` or
``CVE-2023-XXXXX``, and the wrong separator (``CVE_2021_44228``). Stored raw,
these pollute the /ai/cves page — "null" alone accounted for hundreds of rows,
and format variants fragment the count for the same CVE.

``normalize_cve`` returns a canonical ``CVE-YYYY-NNNNN`` string or ``None``.
This is a format+plausibility gate only (cheap, offline); it does NOT confirm
the CVE exists — existence enrichment lives in intelligence/circl_enricher.py
(``enrich_cve``), which returns None for non-existent IDs.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")

# Explicit non-values the models emit as text.
_JUNK = {"", "null", "none", "n/a", "na", "nil", "unknown", "no", "false", "-"}

# CVE numbering started in 1999; allow a little slack past the current year for
# recently-reserved IDs, reject anything implausible.
_MIN_YEAR = 1999


def normalize_cve(raw) -> str | None:
    """Return a canonical ``CVE-YYYY-NNNNN`` id, or None if ``raw`` is not a
    well-formed, plausible CVE identifier."""
    if raw is None:
        return None
    s = str(raw).strip()
    if s.lower() in _JUNK:
        return None
    # Normalise separators/case: some models emit CVE_2021_44228 or lowercase.
    s = s.upper().replace("_", "-").replace(" ", "")
    # Placeholder ids (CVE-XXXX-XXXXX, CVE-2023-XXXXX, …).
    if "X" in s:
        return None
    m = _CVE_RE.match(s)
    if not m:
        return None
    year = int(m.group(1))
    max_year = datetime.now(UTC).year + 1
    if year < _MIN_YEAR or year > max_year:
        return None
    return s
