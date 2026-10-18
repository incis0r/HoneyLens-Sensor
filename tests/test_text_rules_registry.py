#!/usr/bin/env python3
"""Guard for the text-rules registry split (Phase 2 / T8).

`classification/text_rules.py` was split so the individual `_add(...)` rule
definitions live in the per-family `classification/rules/` package behind a
registry, while `text_rules.py` stays a stable façade. These tests pin the
invariant: the fully-assembled rule set and the façade surface are unchanged.

The golden snapshot (`tests/data/text_rules_snapshot.json`) is the frozen
`(attack_type, name, pattern, flags)` multiset captured before the split. The
matcher in `attack_classifier.py` collects *all* hits (no first-match break),
so rule ordering is irrelevant — identity is the sorted multiset.
"""

import json
import pathlib

from honeylens.classification import text_rules as t

_SNAPSHOT = pathlib.Path(__file__).with_name("data") / "text_rules_snapshot.json"


def _current():
    return sorted([a, n, rx.pattern, rx.flags] for a, n, rx in t._RULES)


def test_rule_set_matches_golden_snapshot():
    """Every rule (type, name, pattern, compiled flags) is preserved exactly."""
    golden = json.loads(_SNAPSHOT.read_text())
    current = _current()
    assert current == golden, (
        f"rule set drifted from the golden snapshot "
        f"(golden={len(golden)} current={len(current)}). "
        "If this change is intentional, regenerate "
        "tests/data/text_rules_snapshot.json."
    )


def test_rule_count_and_names():
    # 675 since 2026-10-04: +1 Citrix NetScaler CVE-2026-88771 pre-auth command injection
    # (citrix_cve_2026_88771_pitboss_cmdi, APPLIANCE_EXPLOIT) — the watchTowr PoC's
    # pitboss/NSPPE log-poisoning IOC, given to the central classifier. See
    # tests/test_cisco_webvpn_classification.py.
    #
    # 674 since 2026-09-07: the 670 below plus the Cisco SSL-VPN *GET* surface —
    # cisco_webvpn_portal_probe, cisco_anyconnect_oem_customization (VPN_RECON),
    # cisco_cve_2020_3452_file_read (APPLIANCE_EXPLOIT) and
    # cisco_webvpn_credentials_in_query (CREDENTIAL). The earlier AnyConnect rules
    # all keyed on a POSTed body, so `GET /+CSCOE+/logon.html` matched nothing and was
    # being filed as AI_DETECTED, PANOS_PROBE or FORTI_PROBE depending on which decoy
    # answered. See tests/test_cisco_webvpn_classification.py.
    #
    # 670 since 2026-08-27: +3 Cisco AnyConnect (VPN_RECON), then +12 from the August
    # rule review — Ivanti x2, PAN-OS CVE-2024-3400, Spring x2, fastjson, and six
    # LLM/provider-credential rules. See tests/test_new_signatures_aug_review.py.
    assert len(t._RULES) == 675
    names = [n for _, n, _ in t._RULES]
    # 675 rules, 673 distinct names (two MQTT names intentionally repeat)
    assert len(set(names)) == 673


def test_facade_surface_intact():
    """text_rules.py must keep exporting the symbols its consumers import."""
    for name, expected_len in [
        ("_ICS_PORTS", 15),
        ("_HTTP_PORTS", 15),
        ("_K8S_PORTS", 10),
        ("_ICS_PORT_CONTEXT_RULES", 18),
        ("_HTTP_EXCLUDED_RULES", 93),
        ("_BINARY_PROTOCOLS", 45),
        ("_PLAINTEXT_PROTOCOLS", 15),
        ("_ENCRYPTED_PROTOCOLS", 14),
    ]:
        obj = getattr(t, name)
        assert len(obj) == expected_len, f"{name} changed size"
    assert isinstance(t._CUSTOM_RULE_NAMES, set)
    for fn in ("reload_custom_rules", "get_custom_rule_names", "is_custom_rule"):
        assert callable(getattr(t, fn)), f"{fn} missing"


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
