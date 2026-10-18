"""Migrator 0.9 -> 1.0 (Phase 5, skeleton).

The core of the migration is the honeypot identities — a changed serial number or
certificate fingerprint is a ready-made honeypot fingerprint, so these tests make sure the
copy is faithful (SHA-256) and that nothing from the manifest drops off the list. The second
pillar is the .env translation: secrets carried 1:1, API_PORT forced to 60443, honeypot
ports skipped (the manifest owns them), unknown keys reported rather than deleted.
"""

from __future__ import annotations

from pathlib import Path

from honeylens.honeypots.manifest import HONEYPOTS
from honeylens.tools import migrate_sensor as ms

# --- identities: agreement with the manifest -------------------------------------


def test_identity_moves_cover_exactly_manifest_volumes():
    """Every identity volume from the manifest has an entry in the migrator and vice versa —
    otherwise some honeypot would get a fresh identity on the first 1.0 start (a ready-made
    fingerprint)."""
    manifest_volumes = {hp.identity for hp in HONEYPOTS if hp.identity}
    move_volumes = {m.volume for m in ms.IDENTITY_MOVES}
    # 1.0-native decoys (no 0.9 identity, e.g. netscaler) are generated fresh, not migrated.
    assert move_volumes == manifest_volumes - ms.NATIVE_1_0_IDENTITIES
    assert move_volumes.isdisjoint(ms.NATIVE_1_0_IDENTITIES)


# --- identities: plan and copy ---------------------------------------------------


def _seed_old_root(root: Path) -> None:
    (root / "certs").mkdir(parents=True)
    (root / "certs" / "nginx.crt").write_text("NGINX-CERT")
    (root / "certs" / "nginx.key").write_text("NGINX-KEY")
    (root / "certs" / "honey.crt").write_text("HONEY-CERT")
    (root / "certs" / "honey.key").write_text("HONEY-KEY")
    wago = root / "data" / "wago"
    wago.mkdir(parents=True)
    (wago / "wago_8090.json").write_text('{"serial": "0751-9301"}')


def test_plan_marks_present_and_missing_sources(tmp_path):
    old = tmp_path / "sensor"
    _seed_old_root(old)
    state = tmp_path / "state"
    items = ms.plan_identity(old, state, force=False)
    by_name = {it.src.name: it for it in items}
    assert by_name["nginx.crt"].status == "copy"
    # llm/fortigate certs were not seeded -> missing source
    assert by_name["llm.crt"].status == "missing-source"


def test_apply_copies_and_verifies_bit_for_bit(tmp_path):
    old = tmp_path / "sensor"
    _seed_old_root(old)
    state = tmp_path / "state"
    items = ms.apply_identity(ms.plan_identity(old, state, force=False), force=False)

    nginx = state / "identity" / "nginx" / "nginx.crt"
    assert nginx.read_text() == "NGINX-CERT"
    # the monolith goes into the `honeypot` volume
    assert (state / "identity" / "honeypot" / "honey.crt").read_text() == "HONEY-CERT"
    # the wago directory keeps its structure
    assert (state / "identity" / "wago" / "wago_8090.json").exists()
    copied = next(it for it in items if it.src.name == "nginx.crt")
    assert copied.status == "verified"


def test_apply_does_not_overwrite_without_force(tmp_path):
    old = tmp_path / "sensor"
    _seed_old_root(old)
    state = tmp_path / "state"
    dst = state / "identity" / "nginx" / "nginx.crt"
    dst.parent.mkdir(parents=True)
    dst.write_text("EXISTING-DO-NOT-TOUCH")

    ms.apply_identity(ms.plan_identity(old, state, force=False), force=False)
    assert dst.read_text() == "EXISTING-DO-NOT-TOUCH"

    ms.apply_identity(ms.plan_identity(old, state, force=True), force=True)
    assert dst.read_text() == "NGINX-CERT"


# --- .env: translation -----------------------------------------------------------


def test_translate_forces_api_port_and_carries_secrets():
    old = "DB_PASSWORD=s3cr3t\nANTHROPIC_API_KEY=sk-live\nAPI_PORT=8443\n"
    res = ms.translate_env(old)
    assert res.result["API_PORT"] == "60443"
    assert "API_PORT" in res.forced
    assert res.result["DB_PASSWORD"] == "s3cr3t"
    assert res.result["ANTHROPIC_API_KEY"] == "sk-live"
    assert "DB_PASSWORD" in res.carried


def test_translate_drops_manifest_port_keys():
    port_keys = ms._manifest_port_keys()
    assert "LLM_HONEYPOT_PORT" in port_keys  # sanity: the manifest really has them
    old = "LLM_HONEYPOT_PORT=3080\nDB_HOST=db.local\n"
    res = ms.translate_env(old)
    assert "LLM_HONEYPOT_PORT" not in res.result
    assert "LLM_HONEYPOT_PORT" in res.dropped_ports
    assert res.result["DB_HOST"] == "db.local"  # non-port keys stay


def test_translate_reports_unknown_but_keeps_it():
    old = "TOTALLY_MADE_UP_VAR=1\n"
    res = ms.translate_env(old)
    assert res.result["TOTALLY_MADE_UP_VAR"] == "1"
    assert "TOTALLY_MADE_UP_VAR" in res.unknown


def test_translate_adds_new_keys_with_defaults():
    res = ms.translate_env("DB_HOST=db\n")
    assert res.result["WEBUI_NEW_SHELL"] == "true"
    assert res.result["BACKUP_PASSWORD"] == ""  # secret: empty, to be filled in
    assert "BACKUP_PASSWORD" in res.added


def test_render_has_header_and_all_keys():
    res = ms.translate_env("DB_HOST=db\n")
    text = res.render()
    assert text.startswith("#")
    assert "DB_HOST=db" in text
    assert "API_PORT=60443" in text


def test_parse_env_strips_one_quote_pair_and_keeps_hash_in_value():
    parsed = ms.parse_env("DB_PASSWORD=\"p#ss'word\"\nA='x'\n")
    assert parsed["DB_PASSWORD"] == "p#ss'word"  # only the outer pair; # in the value stays
    assert parsed["A"] == "x"


def test_report_never_prints_secret_values(capsys):
    """The .env report must print variable names, never their values — .env is secrets."""
    old = "DB_PASSWORD=TOPSECRET\nVAULT_MASTER_KEY=MASTERSECRET\nANTHROPIC_API_KEY=sk-XYZ\n"
    res = ms.translate_env(old)
    ms._print_env_report(res, Path("/opt/sensor/.env"), Path("/opt/honeylens/.env"))
    out = capsys.readouterr().out
    for secret in ("TOPSECRET", "MASTERSECRET", "sk-XYZ"):
        assert secret not in out


# --- identities: path overrides and irregular entries ----------------------------


def test_override_dir_from_env_is_honoured(tmp_path):
    """The operator moved certs/ elsewhere (TLS_CERT_DIR) — the migrator has to look there,
    otherwise the honeypot would generate a fresh identity on the first 1.0 start."""
    old = tmp_path / "sensor"
    (old / "elsewhere").mkdir(parents=True)
    (old / "elsewhere" / "nginx.crt").write_text("MOVED-CERT")
    state = tmp_path / "state"
    overrides = {"TLS_CERT_DIR": str(old / "elsewhere")}
    items = ms.apply_identity(
        ms.plan_identity(old, state, force=False, overrides=overrides), force=False
    )
    nginx = next(it for it in items if it.src.name == "nginx.crt")
    assert nginx.status == "verified"
    assert (state / "identity" / "nginx" / "nginx.crt").read_text() == "MOVED-CERT"


def test_broken_symlink_in_tree_is_flagged_not_dropped(tmp_path):
    """A broken symlink in an identity directory must land in the report as 'irregular',
    not vanish silently — that is exactly how an identity gets lost unnoticed."""
    old = tmp_path / "sensor"
    wago = old / "data" / "wago"
    wago.mkdir(parents=True)
    (wago / "wago_8090.json").write_text("{}")
    (wago / "dangling.json").symlink_to(wago / "does_not_exist.json")
    state = tmp_path / "state"
    items = ms.plan_identity(old, state, force=False)
    statuses = {it.src.name: it.status for it in items}
    assert statuses["dangling.json"] == "irregular"
    assert statuses["wago_8090.json"] == "copy"


def test_apply_skips_irregular_entries(tmp_path):
    old = tmp_path / "sensor"
    wago = old / "data" / "wago"
    wago.mkdir(parents=True)
    (wago / "dangling.json").symlink_to(wago / "missing.json")
    state = tmp_path / "state"
    ms.apply_identity(ms.plan_identity(old, state, force=False), force=False)
    assert not (state / "identity" / "wago" / "dangling.json").exists()


# --- .env: the set of known keys must not drift from .env.example ----------------


def test_known_keys_match_env_example():
    """If .env.example gained a variable but KNOWN_KEYS did not, the migrator would report it
    as 'unknown to 1.0' — this test forces both to be updated together."""
    root = Path(__file__).resolve().parent.parent
    example = root / ".env.example"
    keys = set(ms.parse_env(example.read_text()))
    assert keys == set(ms.KNOWN_KEYS)


# --- CLI (main) ------------------------------------------------------------------


def _rc(argv):
    return ms.main(argv)


def test_main_dry_run_writes_nothing(tmp_path):
    old = tmp_path / "sensor"
    _seed_old_root(old)
    (old / ".env").write_text("DB_PASSWORD=x\n")
    state = tmp_path / "state"
    new_env = tmp_path / "out" / ".env"
    rc = _rc(["--old-root", str(old), "--state-dir", str(state), "--new-env", str(new_env)])
    assert rc == 0
    assert not state.exists()  # dry-run does not touch the disk
    assert not new_env.exists()


def test_main_apply_copies_and_writes_env_0600(tmp_path):
    old = tmp_path / "sensor"
    _seed_old_root(old)
    (old / ".env").write_text("DB_PASSWORD=x\nAPI_PORT=8443\n")
    state = tmp_path / "state"
    new_env = tmp_path / "out" / ".env"
    rc = _rc(
        ["--old-root", str(old), "--state-dir", str(state), "--new-env", str(new_env), "--apply"]
    )
    assert rc == 0
    assert (state / "identity" / "nginx" / "nginx.crt").read_text() == "NGINX-CERT"
    assert new_env.exists()
    assert (new_env.stat().st_mode & 0o777) == 0o600  # secrets: owner only
    assert "API_PORT=60443" in new_env.read_text()


def test_main_missing_old_env_still_migrates_identities(tmp_path):
    old = tmp_path / "sensor"
    _seed_old_root(old)  # no .env file
    state = tmp_path / "state"
    new_env = tmp_path / "out" / ".env"
    rc = _rc(
        ["--old-root", str(old), "--state-dir", str(state), "--new-env", str(new_env), "--apply"]
    )
    assert rc == 0
    assert (state / "identity" / "nginx" / "nginx.crt").exists()
    assert not new_env.exists()  # no source .env -> we write nothing
