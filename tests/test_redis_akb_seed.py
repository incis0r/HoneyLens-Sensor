from pathlib import Path


def test_redis_memcorrupt_definition_seeded():
    sql = Path("src/honeylens/data/attack_kb_seed.sql").read_text()
    assert "REDIS_MEMORY_CORRUPTION" in sql
    assert "CVE-2026-25243" in sql and "CVE-2026-25589" in sql


def test_ai_agent_callback_definition_seeded():
    """Idea 52 — the canary needs an AKB entry like any other attack type, but it
    documents the attacker's tooling rather than an attack on the sensor."""
    sql = Path("src/honeylens/data/attack_kb_seed.sql").read_text()
    assert "AI_AGENT_CALLBACK" in sql
    assert "9026740" in sql  # links to the Suricata pack
    assert "AI_ASSISTED_AUTOMATION" in sql  # links to the attacker tag


def test_wago_control_write_definition_seeded():
    """Idea 54: the entry an operator reads when a valve moves. Any CVE it names must
    be one the Phase 3 gate verified against CIRCL."""
    sql = Path("src/honeylens/data/attack_kb_seed.sql").read_text()
    assert "WAGO_CONTROL_WRITE" in sql
    assert "9026750-9026759" in sql  # links to the Suricata pack
    import re

    entry = next(
        line
        for line in sql.splitlines()
        if line.startswith("INSERT INTO attack_definitions") and "WAGO_CONTROL_WRITE" in line
    )
    from honeylens.honeypots.wago.signatures import VERIFIED_CVES

    assert set(re.findall(r"CVE-\d{4}-\d+", entry)) <= set(VERIFIED_CVES)
