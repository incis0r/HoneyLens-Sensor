"""Unit guards for the nightly backfill trigger and the classification review tool.

Neither test touches the database or an LLM — they pin the pure logic: the rule
fingerprint is stable, and the review tool's verdict parser and suspect set behave.
"""

from honeylens.tools import auto_backfill, backfill_attacks, classification_tunning


def test_rules_fingerprint_is_stable_and_hex():
    a = auto_backfill.rules_fingerprint()
    b = auto_backfill.rules_fingerprint()
    assert a == b
    assert len(a) == 64 and all(c in "0123456789abcdef" for c in a)


def test_logic_version_is_folded_into_the_fingerprint(monkeypatch):
    before = auto_backfill.rules_fingerprint()
    monkeypatch.setattr(auto_backfill, "LOGIC_VERSION", auto_backfill.LOGIC_VERSION + 1)
    assert auto_backfill.rules_fingerprint() != before


def test_smb_is_a_binary_protocol_attack():
    # The sensor-c false positive (SMB tagged on HTTPS) must be in the suspect set.
    assert "SMB" in classification_tunning.BINARY_PROTOCOL_ATTACKS
    assert "MODBUS" in classification_tunning.BINARY_PROTOCOL_ATTACKS


def test_replace_patterns_is_wired_and_safe_on_empty_input():
    # The config field exists, and the replace helpers no-op (no DB) on empty input.
    assert backfill_attacks.BackfillConfig(replace_patterns=True).replace_patterns is True
    assert backfill_attacks.delete_patterns_for_events([], dry_run=True) == 0
    assert backfill_attacks.rebuild_attack_types([], dry_run=True) == 0
    assert backfill_attacks.delete_patterns_for_events([]) == 0  # empty short-circuits before DB
    # delete is central-only: honeypot-authored rule names are not in the central registry
    central = backfill_attacks._central_rule_names()
    assert "citrix_cve_2026_88771_pitboss_cmdi" in central  # a central rule
    assert "CVE-2019-19781" not in central  # a decoy-authored tag — must be preserved


def test_parse_verdict_extracts_json_and_tolerates_noise():
    assert classification_tunning._parse_verdict('ok {"wrong": true, "reason": "x"} tail') == {
        "wrong": True,
        "reason": "x",
    }
    assert classification_tunning._parse_verdict("no json here") == {}
    assert classification_tunning._parse_verdict("") == {}


# --- auto_backfill main() + state helpers (C3): mocked DB, no real database ------------


class _Cur:
    def __init__(self, fetchone=None):
        self._fetchone = fetchone
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return self._fetchone


class _Conn:
    def __init__(self, fetchone=None):
        self.cur = _Cur(fetchone)
        self.commits = 0
        self.closed = False

    def cursor(self):
        return self.cur

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


def test_state_helpers_roundtrip_on_a_mock_conn():
    conn = _Conn(fetchone=("deadbeef",))
    auto_backfill._ensure_state_table(conn)
    assert auto_backfill._get_stored(conn) == "deadbeef"
    assert auto_backfill._get_stored(_Conn(fetchone=None)) is None  # empty table
    auto_backfill._store(conn, "newfp")
    assert conn.commits >= 1
    assert any("INSERT INTO classification_state" in sql for sql, _ in conn.cur.executed)


def _patch_db(monkeypatch, conn):
    import honeylens.database as db

    monkeypatch.setattr(db, "legacy_get_db", lambda: conn)


def test_main_check_prints_and_never_backfills(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["ab", "--check"])
    _patch_db(monkeypatch, _Conn(fetchone=None))
    import honeylens.tools.backfill_attacks as bf

    monkeypatch.setattr(
        bf, "backfill", lambda cfg: (_ for _ in ()).throw(AssertionError("no backfill on --check"))
    )
    assert auto_backfill.main() == 0
    assert "changed=True" in capsys.readouterr().out


def test_main_unchanged_does_nothing(monkeypatch):
    current = auto_backfill.rules_fingerprint()
    monkeypatch.setattr("sys.argv", ["ab"])
    _patch_db(monkeypatch, _Conn(fetchone=(current,)))  # stored == current -> unchanged
    import honeylens.tools.backfill_attacks as bf

    monkeypatch.setattr(
        bf, "backfill", lambda cfg: (_ for _ in ()).throw(AssertionError("must not backfill"))
    )
    assert auto_backfill.main() == 0


def test_main_force_dry_run_triggers_backfill_but_does_not_store(monkeypatch):
    current = auto_backfill.rules_fingerprint()
    conn = _Conn(fetchone=(current,))  # unchanged, but --force overrides
    monkeypatch.setattr("sys.argv", ["ab", "--force", "--dry-run"])
    _patch_db(monkeypatch, conn)
    import honeylens.tools.backfill_attacks as bf

    seen = {}
    monkeypatch.setattr(bf, "backfill", lambda cfg: seen.update(cfg=cfg))
    assert auto_backfill.main() == 0
    assert seen["cfg"].dry_run is True and seen["cfg"].replace_patterns is True
    # dry-run must not persist a new fingerprint
    assert not any("INSERT INTO classification_state" in sql for sql, _ in conn.cur.executed)


def test_main_changed_backfills_then_stores(monkeypatch):
    conn = _Conn(fetchone=None)  # nothing stored -> changed
    monkeypatch.setattr("sys.argv", ["ab", "--apply"])  # E1: writing is opt-in
    _patch_db(monkeypatch, conn)
    import honeylens.tools.backfill_attacks as bf

    seen = {}
    monkeypatch.setattr(bf, "backfill", lambda cfg: seen.update(cfg=cfg))
    assert auto_backfill.main() == 0
    assert seen["cfg"].reprocess_all is True and seen["cfg"].dry_run is False
    assert any("INSERT INTO classification_state" in sql for sql, _ in conn.cur.executed), (
        "a real (--apply) backfill stores the new fingerprint"
    )


def test_main_bare_run_is_dry_by_default_and_does_not_store(monkeypatch):
    # E1: a bare run (no --apply) changes nothing, even when the rules changed — the backfill
    # runs in dry-run and no fingerprint is persisted, so it stays armed for a real --apply run.
    conn = _Conn(fetchone=None)  # nothing stored -> changed
    monkeypatch.setattr("sys.argv", ["ab"])
    _patch_db(monkeypatch, conn)
    import honeylens.tools.backfill_attacks as bf

    seen = {}
    monkeypatch.setattr(bf, "backfill", lambda cfg: seen.update(cfg=cfg))
    assert auto_backfill.main() == 0
    assert seen["cfg"].dry_run is True
    assert not any("INSERT INTO classification_state" in sql for sql, _ in conn.cur.executed)
