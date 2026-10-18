"""Reloading custom rules must be visible to the classifier.

attack_classifier imports _RULES by reference at startup. In 0.9 the reload swapped the
list out, so the classifier would have been left with a stale one — the path was dead,
because the loader never ran. In 1.0 it does run, so we guard the object identity and the
effect of the reload.
"""

from __future__ import annotations

import re

from honeylens.classification import attack_classifier, custom_rules_loader, text_rules


def test_classifier_and_registry_share_one_rules_list() -> None:
    assert attack_classifier._RULES is text_rules._RULES


def test_reload_removes_old_custom_rules_in_place(monkeypatch) -> None:
    before = len(text_rules._RULES)
    text_rules._RULES.append(("AI_DETECTED", "custom_zzz_probe", re.compile(r"zzz-probe", re.I)))
    text_rules._CUSTOM_RULE_NAMES.add("custom_zzz_probe")
    assert any(
        h[1] == "custom_zzz_probe"
        for h in attack_classifier.classify_event_row(
            "GET /zzz-probe HTTP/1.1\r\n\r\n", "HTTP", {"dst_port": 80}
        )
    )

    monkeypatch.setattr(text_rules, "_load_custom_rules_from_db", lambda: 0)
    assert custom_rules_loader.reload_custom_rules() == 0

    assert len(text_rules._RULES) == before
    assert attack_classifier._RULES is text_rules._RULES
    assert not any(
        h[1] == "custom_zzz_probe"
        for h in attack_classifier.classify_event_row(
            "GET /zzz-probe HTTP/1.1\r\n\r\n", "HTTP", {"dst_port": 80}
        )
    )
    assert custom_rules_loader.get_custom_rule_names() == set()


def test_facade_reexports_scoring_and_reload() -> None:
    for name in (
        "get_all_rules",
        "get_rules_flat",
        "get_attack_types",
        "get_classifier_stats",
        "reload_custom_rules",
        "ATTACK_TYPE_SEVERITY",
    ):
        assert hasattr(attack_classifier, name), name
    assert (
        attack_classifier.get_attack_types()[:1] and "SQLI" in attack_classifier.get_attack_types()
    )
    assert sum(len(v) for v in attack_classifier.get_all_rules().values()) == len(text_rules._RULES)
