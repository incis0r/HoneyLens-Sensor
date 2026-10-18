"""Per-instance identity for the WAGO decoy (Idea 54).

Two things are under test here, and the second one is the important one.

Uniqueness and stability: each deployment must present its own controller, and must
present the *same* controller after a restart.

Provenance: the WBM page set this decoy was modelled on came from captures of real,
publicly exposed WAGO controllers belonging to other people. Their MAC and their
CODESYS runtime counters were copied into the first port and would have been served
from our sensors to anyone who asked. `test_no_captured_third_party_values_survive`
is the regression guard that keeps them out — it is an OPSEC test, not a cosmetic one.
"""

import json
import os
import pathlib
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeylens.honeypots.wago import identity as wago_identity
from honeylens.honeypots.wago.state import DeviceState

# Values lifted verbatim from the source captures (185.165.96.228, 77.170.216.131).
# They identify somebody else's equipment. None may appear in our code or output.
CAPTURED_THIRD_PARTY_VALUES = (
    "00:30:DE:40:1D:B7",  # MAC of the real controller at 185.165.96.228
    "00:30:DE:52:8A:41",  # the single fixed MAC the first port shipped with
    "35768636",
    "51818231",
    "129546132",
    "1036372",
    "129546548",  # task counters
    "pfc200-pump-01",  # fleet-wide hostname
    "192.168.50.20",
    "192.168.50.5",
    "982313",
    "443902",  # interface counters
    "185.165.96.228",
    "77.170.216.131",  # the captured hosts themselves
)

_WAGO_PKG = pathlib.Path(wago_identity.__file__).parent


def test_instances_are_unique():
    """Four sensors answering with one MAC is one signature, not four decoys."""
    a, b = wago_identity.generate(8090), wago_identity.generate(8090)
    assert a["mac"] != b["mac"]
    assert a["serial"] != b["serial"]
    assert a["task_cycles"] != b["task_cycles"]
    assert (a["hostname"], a["ip_address"]) != (b["hostname"], b["ip_address"])


def test_mac_keeps_the_wago_oui():
    """Randomising the vendor prefix would stop it reading as a WAGO at all."""
    for _ in range(20):
        assert wago_identity.generate()["mac"].startswith("00:30:DE")


def test_identity_is_stable_across_restarts(tmp_path):
    """A controller whose MAC changes on restart is not a controller."""
    path = str(tmp_path / "id.json")
    first = wago_identity.load_or_create(path, 8090)
    second = wago_identity.load_or_create(path, 8090)
    assert first == second
    assert json.loads(pathlib.Path(path).read_text())["mac"] == first["mac"]


def test_identity_file_is_not_world_readable(tmp_path):
    path = str(tmp_path / "id.json")
    wago_identity.load_or_create(path, 8090)
    assert (os.stat(path).st_mode & 0o077) == 0


def test_upgrade_backfills_without_changing_the_unit(tmp_path):
    """Adding a field in a later version must not silently re-issue a live decoy's
    MAC — the operator's correlation across months depends on it holding still."""
    path = tmp_path / "id.json"
    seeded = wago_identity.generate(8090)
    original_mac = seeded["mac"]
    del seeded["snmp_location"]  # simulate an older schema
    path.write_text(json.dumps(seeded))

    loaded = wago_identity.load_or_create(str(path), 8090)
    assert loaded["mac"] == original_mac  # unchanged
    assert loaded["snmp_location"]  # and the gap is filled


def test_corrupt_file_regenerates_rather_than_crashing(tmp_path):
    """A damaged cosmetic file must not keep the decoy from starting."""
    path = tmp_path / "id.json"
    path.write_text("{ not json")
    loaded = wago_identity.load_or_create(str(path), 8090)
    assert loaded["mac"].startswith("00:30:DE")


def test_two_ports_on_one_host_are_two_devices():
    assert wago_identity.default_path(8090) != wago_identity.default_path(8091)


def test_no_captured_third_party_values_survive():
    """The reason this module exists.

    Republishing another operator's device fingerprint from our sensors is the harm;
    being fingerprintable ourselves is the side effect. Neither the package source nor
    a running decoy's rendered state may contain any captured value.
    """
    for source in _WAGO_PKG.glob("*.py"):
        text = source.read_text()
        for bad in CAPTURED_THIRD_PARTY_VALUES:
            if source.name == "identity.py" or source.name.startswith("test"):
                continue  # the guard list itself is allowed to name them
            assert bad not in text, f"{source.name} still carries captured value {bad!r}"

    rendered = json.dumps(DeviceState(identity=wago_identity.generate()).snapshot())
    for bad in CAPTURED_THIRD_PARTY_VALUES:
        assert bad not in rendered, f"decoy would serve captured value {bad!r}"


def test_state_uses_the_identity_it_is_given():
    ident = wago_identity.generate(8090)
    snap = DeviceState(identity=ident).snapshot()
    assert snap["mac"] == ident["mac"]
    assert snap["hostname"] == ident["hostname"]
    assert snap["serial"] == ident["serial"]
    # The model is deliberately NOT randomised: the detection rules key on it.
    assert snap["order_number"] == "750-8202"


def test_seed_is_not_derived_from_anything_observable():
    """If the identity could be recomputed from a scan result, this open-source file
    would turn every decoy into a beacon confirming 'HoneyLens is here'."""
    import inspect

    src = inspect.getsource(wago_identity)
    for leak in (
        "gethostname",
        "getfqdn",
        "socket.",
        "SENSOR_PUBLIC_IP",
        "platform.node",
        "get_public_ip",
    ):
        assert leak not in src, f"identity seed must not read {leak}"
    assert "os.urandom" in src
