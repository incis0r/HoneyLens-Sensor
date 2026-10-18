"""Version identity: the number from the package, the commit and the tree fingerprint from
the stamp files.

A port of the 0.9 tests from tests/test_build_stamp.py. Two 0.9 tests have no counterpart
here: running tests/test_build_stamp.sh and checking the ordering in hl-update.sh — both
concern shell scripts that will arrive with the installer layer, not with core.
"""

from __future__ import annotations

from pathlib import Path

import honeylens
from honeylens import version


def _stamp(dir_: Path, build: str | None = None, tree: str | None = None) -> None:
    if build is not None:
        (dir_ / "BUILD_INFO").write_text(build + "\n")
    if tree is not None:
        (dir_ / "TREE_SHA").write_text(tree + "\n")


def test_version_number_comes_from_the_package() -> None:
    assert version.VERSION_NUMBER == honeylens.__version__
    assert version.VERSION.startswith(version.VERSION_NUMBER + "+")


def test_the_version_names_the_commit_and_the_tree(tmp_path: Path) -> None:
    _stamp(tmp_path, build="3137769a", tree="4f21c0de9988aabb")
    build, tree = version.read_stamps(tmp_path)
    assert (build, tree) == ("3137769a", "4f21c0de")
    assert version.display_version("1.0.0", build, tree) == "1.0.0 (build 3137769a, tree 4f21c0de)"


def test_an_unstamped_install_reads_as_it_always_did(tmp_path: Path) -> None:
    """An install from before stamping must not suddenly print an empty fingerprint."""
    _stamp(tmp_path, build="3137769a")
    build, tree = version.read_stamps(tmp_path)
    assert tree == ""
    assert version.display_version("1.0.0", build, tree) == "1.0.0 (build 3137769a)"


def test_two_installs_of_the_same_commit_can_still_differ(tmp_path: Path) -> None:
    """The reason the tree fingerprint exists: on 2026-09-05 three sensors reported build
    6b049263 over three different trees. Only the fingerprint tells them apart."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    _stamp(a, build="6b049263", tree="aaaaaaaa1111")
    _stamp(b, build="6b049263", tree="bbbbbbbb2222")
    ver_a = version.display_version("1.0.0", *version.read_stamps(a))
    ver_b = version.display_version("1.0.0", *version.read_stamps(b))
    assert ver_a != ver_b
    assert "6b049263" in ver_a and "6b049263" in ver_b


def test_no_stamp_and_no_git_falls_back_to_dev(tmp_path: Path) -> None:
    build, tree = version.read_stamps(tmp_path)
    assert (build, tree) == ("dev", "")


def test_empty_build_info_is_not_a_build(tmp_path: Path) -> None:
    (tmp_path / "BUILD_INFO").write_text("\n")
    build, _ = version.read_stamps(tmp_path)
    assert build == "dev"


def test_stamp_dir_can_be_pointed_by_env(tmp_path: Path, monkeypatch) -> None:
    _stamp(tmp_path, build="cafe0001", tree="feed0002")
    monkeypatch.setenv("HONEYLENS_STAMP_DIR", str(tmp_path))
    assert version.read_stamps() == ("cafe0001", "feed0002")
