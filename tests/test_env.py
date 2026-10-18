"""core.env — .env, then os.environ, then the default value, in that order."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from honeylens import env as envmod


@pytest.fixture
def envfile(tmp_path: Path) -> Path:
    p = tmp_path / ".env"
    p.write_text(
        "# comment\n"
        "PLAIN=value\n"
        'QUOTED="with # hash inside"\n'
        "SINGLE='single quoted'\n"
        "INLINE=abc # comment after value\n"
        "export EXPORTED=yes\n"
        "EMPTY=\n"
        "NUM=42\n"
        "FLAG=on\n"
        "not a valid line\n"
        "  SPACED = nope\n"
    )
    p.chmod(0o600)
    return p


def test_load_env_file_parses_the_documented_forms(envfile: Path) -> None:
    got = envmod.load_env_file(envfile)
    assert got == {
        "PLAIN": "value",
        "QUOTED": "with # hash inside",
        "SINGLE": "single quoted",
        "INLINE": "abc",
        "EXPORTED": "yes",
        "EMPTY": "",
        "NUM": "42",
        "FLAG": "on",
    }


def test_missing_file_is_empty(tmp_path: Path) -> None:
    assert envmod.load_env_file(tmp_path / "nope") == {}


def test_resolution_order_file_then_environ_then_default(envfile: Path, monkeypatch) -> None:
    monkeypatch.setenv("PLAIN", "from-environ")
    monkeypatch.setenv("ONLY_ENVIRON", "e")
    envmod.reload([envfile])
    try:
        assert envmod.env("PLAIN") == "value"  # the file wins, as in 0.9
        assert envmod.env("ONLY_ENVIRON") == "e"
        assert envmod.env("NOWHERE", "dflt") == "dflt"
        assert envmod.env("NOWHERE") is None
        assert envmod.env_file_path() == envfile
    finally:
        envmod.reload([])


def test_casts(envfile: Path) -> None:
    envmod.reload([envfile])
    try:
        assert envmod.env("NUM", cast=int) == 42
        assert envmod.env("NUM", cast=float) == 42.0
        assert envmod.env("FLAG", cast=bool) is True
        assert envmod.env("PLAIN", cast=bool) is False
        assert envmod.env("MISSING", True, cast=bool) is True
        assert envmod.env("MISSING", 7, cast=int) == 7
        assert envmod.env("PLAIN", cast=lambda s: s.upper()) == "VALUE"
    finally:
        envmod.reload([])


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "On"])
def test_bool_truthy_spellings(raw: str, monkeypatch) -> None:
    monkeypatch.setenv("B", raw)
    envmod.reload([])
    assert envmod.env("B", cast=bool) is True


def test_no_file_means_environ_only(monkeypatch) -> None:
    envmod.reload([])
    monkeypatch.setenv("X_ONLY", "1")
    assert envmod.env("X_ONLY") == "1"
    assert envmod.env_file_path() is None


def test_permissive_env_file_is_reported(envfile: Path, caplog) -> None:
    envfile.chmod(0o644)
    with caplog.at_level(logging.WARNING, logger="honeylens.env"):
        envmod.reload([envfile])
    envmod.reload([])
    assert any("0644" in r.message and "chmod 600" in r.message for r in caplog.records)


def test_default_search_paths_are_the_documented_ones(monkeypatch) -> None:
    monkeypatch.delenv("HONEYLENS_ENV_FILE", raising=False)
    paths = envmod.default_search_paths()
    assert paths[0] == Path.cwd() / ".env"
    assert Path("/opt/honeylens/.env") in paths
    assert Path("/opt/sensor/.env") in paths  # 0.9 installs until the migrator lands
    monkeypatch.setenv("HONEYLENS_ENV_FILE", "/tmp/x.env")
    assert envmod.default_search_paths()[0] == Path("/tmp/x.env")
