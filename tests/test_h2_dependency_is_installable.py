"""The h2 library has to reach the honeypot image, not just the lock file.

containers/honeypot/Containerfile installs with ``pip install -c requirements.txt .``:
requirements.txt is a CONSTRAINT there, so a package listed only in it is never installed.
"""

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_h2_is_a_project_dependency_not_only_a_constraint():
    """requirements.txt is passed to pip as -c, so a package listed only there
    is never installed in the honeypot image. It has to be in pyproject."""
    text = (ROOT / "pyproject.toml").read_text()
    deps = text.split("dependencies = [", 1)[1].split("]", 1)[0]
    assert "h2>=" in deps


def test_the_h2_library_imports():
    import h2.config
    import h2.connection
    import h2.events

    assert h2.connection.H2Connection
