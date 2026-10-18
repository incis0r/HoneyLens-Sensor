"""Faza 4: the OT attack simulator is run on someone's live controller, so a
state-changing operation must never fire by default.

These pin the safety contract: every operation is classified, writes/DoS are refused
unless explicitly allowed, and the classification covers every registered test.
"""

from __future__ import annotations

import honeylens.tools.ics_attack_simulator as sim


def test_every_registered_test_has_an_impact_class():
    for test_id in sim.TESTS:
        klass, _desc = sim._impact(test_id)
        assert klass in (sim.IMPACT_READ, sim.IMPACT_WRITE, sim.IMPACT_DOS), test_id


def test_state_changing_ops_are_write_or_dos():
    """The operations that touch a controller's state must not be classed read."""
    must_not_be_read = {
        "MB04",
        "MB05",
        "MB08",
        "MB11",
        "MB12",
        "MB13",  # modbus writes/diag
        "DNP03",
        "DNP04",
        "DNP05",  # dnp3 control/restart
        "IEC03",
        "IEC04",
        "IEC05",  # iec-104 commands/reset
        "S704",
        "S705",  # s7 write / stop cpu
        "BAC03",
        "BAC04",  # bacnet write / reinitialize
        "MQTT05",
        "MQTT06",
        "MQTT09",  # mqtt publish / retained / injection
        "MB09",
        "MQTT07",  # dos floods
    }
    for test_id in must_not_be_read:
        assert sim._impact(test_id)[0] != sim.IMPACT_READ, f"{test_id} must not be read-only"


def test_known_read_probes_are_read():
    for test_id in ("MB01", "MB03", "DNP02", "IEC02", "S702", "BAC01", "ENIP01", "MQTT01"):
        assert sim._impact(test_id)[0] == sim.IMPACT_READ, test_id


def test_gate_refuses_writes_by_default():
    sim.config.allow_writes = False
    sim.config.allow_dos = False
    assert sim._gate("MB05") is False  # write single register
    assert sim._gate("S705") is False  # stop CPU
    assert sim._gate("MB09") is False  # dos flood
    assert sim._gate("MB01") is True  # read probe always allowed


def test_gate_allows_writes_only_with_the_flag():
    sim.config.allow_writes = True
    sim.config.allow_dos = False
    try:
        assert sim._gate("MB05") is True
        assert sim._gate("S705") is True
        assert sim._gate("MB09") is False, "DoS still needs its own flag"
    finally:
        sim.config.allow_writes = False


def test_gate_allows_dos_only_with_the_flag():
    sim.config.allow_dos = True
    sim.config.allow_writes = False
    try:
        assert sim._gate("MB09") is True
        assert sim._gate("MQTT07") is True
        assert sim._gate("MB05") is False, "a write still needs --allow-writes"
    finally:
        sim.config.allow_dos = False


def test_every_write_op_carries_a_description():
    """The plan requires each state-changing op to say what exactly it will do."""
    for test_id, (klass, desc) in sim.IMPACT.items():
        if klass in (sim.IMPACT_WRITE, sim.IMPACT_DOS):
            assert desc.strip(), f"{test_id} has no impact description"
