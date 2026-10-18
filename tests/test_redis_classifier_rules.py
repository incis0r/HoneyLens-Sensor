import honeylens.classification.text_rules as tr


def _rules_for(attack_type):
    return [(name, pat) for (at, name, pat) in tr._RULES if at == attack_type]


def test_restore_nack_rule_matches_chain_not_benign():
    rules = _rules_for("REDIS_HEAP_CORRUPT")
    assert rules, "no REDIS_HEAP_CORRUPT rule registered"
    hit = any(pat.search("RESTORE s 0 <blob> XGROUP DELCONSUMER s g c") for _n, pat in rules)
    assert hit
    benign = any(pat.search("GET user:42 name") for _n, pat in rules)
    assert not benign


def test_topk_and_tdigest_rules_registered():
    assert any(
        pat.search("TOPK.RESERVE t 50 2000 7 0.9") for _n, pat in _rules_for("REDIS_TOPK_WILDFREE")
    )
    assert any(
        pat.search("TDIGEST.CREATE d COMPRESSION 100")
        for _n, pat in _rules_for("REDIS_TDIGEST_OVERFLOW")
    )


def test_redis_attack_types_are_critical_severity():
    from honeylens.classification.scoring import ATTACK_TYPE_SEVERITY

    for at in (
        "REDIS_HEAP_CORRUPT",
        "REDIS_TOPK_WILDFREE",
        "REDIS_TDIGEST_OVERFLOW",
        "REDIS_EXPLOIT_CHAIN",
    ):
        assert ATTACK_TYPE_SEVERITY.get(at) == "critical", at
