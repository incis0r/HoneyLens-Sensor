"""Every unit the repository ships or prints must point at the `sensor` service account.

This exists because of two separate ways the same mistake showed up. The system units in
``containers/systemd`` had an operator's home written into them, which couples the sensor to a
human login — a home that can be relocated or ``ProtectHome``d, at which point rootless
lingering stops working silently. And ``generate_systemd_unit`` still printed 0.9's
``/opt/sensor/venv`` with a relative script path, so the unit it handed the operator could not
start at all under 1.0.

Both are the kind of defect nobody notices by reading: the unit installs fine and fails later,
on a different host, under someone else's hands. So it is asserted here instead.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

UNIT_DIR = Path(__file__).resolve().parent.parent / "containers" / "systemd"
PATH_DIRECTIVE = re.compile(
    r"^(WorkingDirectory|ExecStart|ExecStartPre|EnvironmentFile|Environment)=(.*)$"
)


def _units() -> list[Path]:
    return sorted(
        p for p in UNIT_DIR.iterdir() if p.suffix in {".service", ".timer", ".container", ".socket"}
    )


def test_there_are_units_to_check():
    assert _units(), f"no unit files found under {UNIT_DIR} — the test has lost its subject"


@pytest.mark.parametrize("unit", _units(), ids=lambda p: p.name)
def test_no_unit_points_at_a_login_account(unit: Path):
    """A home under /home must be the service account's, never an operator's.

    Units that can use %h do; the system units cannot, because for them %h is root's home,
    so they name the account explicitly. Either is fine — a different person's home is not.
    """
    offenders = []
    for number, line in enumerate(unit.read_text().splitlines(), start=1):
        match = PATH_DIRECTIVE.match(line.strip())
        if not match:
            continue
        for home in re.findall(r"/home/([A-Za-z0-9_.-]+)", match.group(2)):
            if home != "sensor":
                offenders.append(f"{unit.name}:{number} -> /home/{home}")
    assert not offenders, "units pointing at a non-service home: " + ", ".join(offenders)


def test_the_generated_custom_honeypot_unit_matches_the_1_0_layout():
    from honeylens.tools.honeypot_generator import generate_systemd_unit

    unit = generate_systemd_unit("acme-plc", 8080, 2222)

    assert "/opt/sensor" not in unit, "still emitting the 0.9 install path"
    assert "User=sensor" in unit and "Group=sensor" in unit

    exec_lines = [ln for ln in unit.splitlines() if ln.startswith("ExecStart=")]
    assert len(exec_lines) == 1, "ExecStart must be a single line; systemd needs the backslash"
    exec_start = exec_lines[0]
    assert "/home/sensor/sensor-1.0/.venv/bin/python" in exec_start
    assert " --run acme-plc" in exec_start, "arguments ran into the module name"

    # The reason the old unit was dead: the thing ExecStart named did not exist. Resolve it.
    module = re.search(r"-m ([\w.]+)", exec_start)
    assert module, f"no module in ExecStart: {exec_start}"
    assert importlib.import_module(module.group(1)), "ExecStart names an unimportable module"

    # It writes events through honeylens.database, so it needs the env file, and a system
    # unit cannot abbreviate the path to it.
    assert "HONEYLENS_ENV_FILE=/home/sensor/honeylens-state/.env" in unit
