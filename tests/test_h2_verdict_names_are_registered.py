"""Every verdict name the HTTP/2 decoy can write is scored, mapped and bound.

`cve_2026_49975_*` had been emitted since September with no severity entry and no MITRE
mapping, so an unscored HIGH reached the dashboard. The names below close that together with the
ones the h2 capture adds. `h2_protocol_error` joined them when the baseline stopped
covering connections that died on an HTTP/2 protocol failure. (`cve_2026_23918_recon` is not here: it was demoted to
`h2c_upgrade_recon`, and another test asserts the old name is gone from the tree.)
"""

from __future__ import annotations

import pytest

from honeylens.classification.mitre_mapping import get_mitre_mapping
from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY
from honeylens.ingest.cve_service_ports import cve_is_in_service

NAMES = [
    "cve_2026_119618_probe",
    "cve_2026_119618_flood",
    "h2_rapid_reset",
    "h2_prior_knowledge",
    "h2_protocol_error",
    "h2c_upgrade_recon",
    "cve_2026_49975_zero_window",
    "cve_2026_49975_window_drip",
    "cve_2026_49975_hpack_bomb",
]

SEVERITY = {
    "cve_2026_119618_flood": "high",
    "cve_2026_49975_zero_window": "high",
    "cve_2026_119618_probe": "medium",
    "h2_rapid_reset": "medium",
    "cve_2026_49975_window_drip": "medium",
    "cve_2026_49975_hpack_bomb": "medium",
    "h2_prior_knowledge": "low",
    "h2_protocol_error": "low",
    "h2c_upgrade_recon": "low",
}

# Tactics that would claim the attacker got in or ran something; no h2 verdict observed that.
_UNOBSERVED_TACTICS = {"initial-access", "execution", "persistence", "lateral-movement"}


def test_the_name_list_is_the_whole_expected_set():
    assert len(NAMES) == 9 and set(NAMES) == set(SEVERITY)


@pytest.mark.parametrize("name", NAMES)
def test_every_name_is_scored(name):
    assert name in ATTACK_TYPE_SEVERITY


@pytest.mark.parametrize("name", NAMES)
def test_every_name_is_scored_at_its_tier(name):
    assert ATTACK_TYPE_SEVERITY[name] == SEVERITY[name]


@pytest.mark.parametrize("name", NAMES)
def test_every_name_is_mapped(name):
    assert get_mitre_mapping(name)


def test_the_recon_names_claim_no_exploitation_technique():
    for name in ("h2_prior_knowledge", "h2_protocol_error", "h2c_upgrade_recon"):
        mapping = get_mitre_mapping(name)
        assert mapping
        assert all(m["tactic"] == "reconnaissance" for m in mapping)
        assert [m["technique"] for m in mapping] == ["T1595.002"]


@pytest.mark.parametrize("name", NAMES)
def test_no_name_claims_access_or_execution_nobody_observed(name):
    mapping = get_mitre_mapping(name)
    assert mapping
    assert not {m["tactic"] for m in mapping} & _UNOBSERVED_TACTICS


@pytest.mark.parametrize(
    "name",
    [
        "cve_2026_119618_flood",
        "h2_rapid_reset",
        "cve_2026_49975_zero_window",
        "cve_2026_49975_window_drip",
        "cve_2026_49975_hpack_bomb",
    ],
)
def test_the_denial_of_service_names_map_to_endpoint_dos(name):
    assert [m["technique"].split(".")[0] for m in get_mitre_mapping(name)] == ["T1499"]
    assert {m["tactic"] for m in get_mitre_mapping(name)} == {"impact"}


def test_49975_is_bound_to_the_http_decoy_too():
    assert cve_is_in_service("CVE-2026-49975", 80) is True
    assert cve_is_in_service("CVE-2026-49975", 8443) is True


def test_49975_is_still_not_bound_to_an_unrelated_port():
    assert cve_is_in_service("CVE-2026-49975", 2379) is False


def test_the_probe_is_reconnaissance_because_it_carries_no_volume():
    """It presents the race's preconditions and nothing that exhausts anything."""
    assert [(m["technique"], m["tactic"]) for m in get_mitre_mapping("cve_2026_119618_probe")] == [
        ("T1595.002", "reconnaissance")
    ]
