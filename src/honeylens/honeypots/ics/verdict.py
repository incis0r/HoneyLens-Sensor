"""A decoy's verdict, derived from what the decoded frame means.

``honeylens.ics`` decodes a frame and says what it does (``Frame.semantics``). This module is
the only place that turns that meaning into the verdict a decoy writes, so a decoy keeps no
function-code table of its own to disagree with the decoder.

Only an operation is an attack. A code the specification does not define (``anomaly``) or the
decoder does not know (``None``) ordered nothing: it is reconnaissance, a notch above a plain
read so it stands out.
"""

from __future__ import annotations

from honeylens.ics.frame import Frame

Verdict = tuple[str, str]

VERDICT_FOR_SEMANTICS: dict[str | None, Verdict] = {
    "read": ("ICS_RECON", "LOW"),
    "enumerate": ("ICS_RECON", "LOW"),
    "discovery": ("ICS_RECON", "LOW"),
    "write": ("ICS_ATTACK", "HIGH"),
    "command": ("ICS_ATTACK", "CRITICAL"),
    "control": ("ICS_ATTACK", "CRITICAL"),
    "anomaly": ("ICS_RECON", "MEDIUM"),
    None: ("ICS_RECON", "LOW"),
}

# A protocol whose stored history already names one meaning differently keeps that name.
_PROTOCOL_OVERRIDES: dict[str, dict[str | None, Verdict]] = {
    "modbus": {"enumerate": ("MODBUS_RECON", "LOW")},
}

# The decoys on the shared COTP/Fox/PROFINET base speak in kinds (``ics.base.classify``).
_KIND_FOR_SEMANTICS: dict[str | None, str] = {
    "enumerate": "enumeration",
    "discovery": "enumeration",
    "read": "recon",
    "anomaly": "recon",
    None: "recon",
    "write": "write",
    "command": "command",
    "control": "command",
}


def verdict_for_semantics(semantics: str | None, protocol: str | None = None) -> Verdict:
    """(attack_type, severity) for a semantics value, with ``protocol``'s own names applied."""
    override = _PROTOCOL_OVERRIDES.get(protocol or "", {})
    if semantics in override:
        return override[semantics]
    return VERDICT_FOR_SEMANTICS.get(semantics, VERDICT_FOR_SEMANTICS[None])


def verdict_for(frame: Frame) -> Verdict:
    """(attack_type, severity) for a decoded frame."""
    return verdict_for_semantics(frame.semantics, frame.protocol)


def kind_for_semantics(semantics: str | None) -> str:
    """The ``ics.base.classify`` kind for a semantics value."""
    return _KIND_FOR_SEMANTICS.get(semantics, "recon")


def kind_for(frame: Frame) -> str:
    """The ``ics.base.classify`` kind for a decoded frame."""
    return kind_for_semantics(frame.semantics)
