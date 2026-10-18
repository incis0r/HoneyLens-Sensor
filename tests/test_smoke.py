"""Smoke test: the package imports from the installed installation and runs on 3.12.

It exists so that `make all` on an empty repository has something to run. Pytest with no
tests exits with code 5, so without this file the last item of Phase 0 cannot be passed.
The interpreter version check is not decoration: a venv accidentally built on a different
Python looks identical, and this whole line of work exists so as not to be on 3.9.
"""

import sys
import tomllib
from pathlib import Path

import honeylens


def test_interpreter_is_312() -> None:
    assert sys.version_info[:2] == (3, 12), sys.version


def test_package_version_matches_pyproject() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject.open("rb") as fh:
        declared = tomllib.load(fh)["project"]["version"]
    assert honeylens.__version__ == declared
