"""A decoy's verdict comes from what the frame means, and the meaning has one table.

Reviewed 2026-11-20: every industrial protocol had two tables. ``honeylens.ics`` decoded the
frame correctly for the screen, and the decoy kept a second, shorter table of its own for the
verdict. Where they disagreed the verdict was wrong: an S7 CPU STOP earned the lowest verdict
on the decoy while the decoder called it ``control``; a FINS program write was
``Unknown_*``/recon; and "function code not in my table" meant ``ICS_ATTACK`` — 286 Modbus rows
(UMAS identification reads) and all 9 DNP3 rows (a delay measurement) in 30 days, with not one
write or command among them.

The decoder's ``semantics`` is the single input. An unknown or out-of-specification code is
not an attack: nothing was ordered.
"""

from __future__ import annotations

import pytest

from honeylens.honeypots.ics import verdict
from honeylens.ics import SEMANTICS, decode


@pytest.mark.parametrize(
    ("semantics", "want"),
    [
        ("read", ("ICS_RECON", "LOW")),
        ("enumerate", ("ICS_RECON", "LOW")),
        ("discovery", ("ICS_RECON", "LOW")),
        ("write", ("ICS_ATTACK", "HIGH")),
        ("command", ("ICS_ATTACK", "CRITICAL")),
        ("control", ("ICS_ATTACK", "CRITICAL")),
        ("anomaly", ("ICS_RECON", "MEDIUM")),
        (None, ("ICS_RECON", "LOW")),
    ],
)
def test_verdict_for_each_semantics(semantics, want):
    assert verdict.verdict_for_semantics(semantics) == want


def test_every_semantics_value_has_a_verdict():
    assert set(verdict.VERDICT_FOR_SEMANTICS) == {*SEMANTICS, None}


def test_only_an_operation_is_an_attack():
    attacks = {s for s, (a, _) in verdict.VERDICT_FOR_SEMANTICS.items() if a == "ICS_ATTACK"}

    assert attacks == {"write", "command", "control"}


def test_modbus_keeps_its_own_name_for_identification():
    assert verdict.verdict_for_semantics("enumerate", "modbus") == ("MODBUS_RECON", "LOW")
    assert verdict.verdict_for_semantics("read", "modbus") == ("ICS_RECON", "LOW")


@pytest.mark.parametrize(
    ("semantics", "want"),
    [
        ("enumerate", "enumeration"),
        ("discovery", "enumeration"),
        ("read", "recon"),
        ("anomaly", "recon"),
        (None, "recon"),
        ("write", "write"),
        ("command", "command"),
        ("control", "command"),
    ],
)
def test_kind_for_the_cotp_family(semantics, want):
    assert verdict.kind_for_semantics(semantics) == want


def test_a_modbus_write_and_a_read_from_the_bytes():
    write = decode("modbus", bytes.fromhex("0600010002"))
    read = decode("modbus", bytes.fromhex("0300000004"))

    assert verdict.verdict_for(write) == ("ICS_ATTACK", "HIGH")
    assert verdict.verdict_for(read) == ("ICS_RECON", "LOW")


def test_a_frame_that_did_not_decode_is_recon_never_an_attack():
    frame = decode("modbus", b"")

    assert verdict.verdict_for(frame)[0] == "ICS_RECON"
