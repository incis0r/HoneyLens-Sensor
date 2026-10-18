"""Version identity: package number plus build stamp and tree fingerprint.

The version number (``VERSION_NUMBER``) comes from the package — ``honeylens.__version__``
— not from a hand-edited ``VERSION`` file as in 0.9. The two stamp files stay, because
they describe what the number does not say:

  BUILD_INFO   short hash of the commit the install was built from; written by the
               stamping script at the end of a deployment,
  TREE_SHA     digest over every installed first-party ``.py`` file; same code, same
               digest — one file swapped by hand, a different digest.

Both are needed. The commit says where the code was supposed to come from; the tree
fingerprint says what actually sits on disk. On 2026-09-05 three sensors reported build
6b049263 over three different trees, because files placed by hand never rewrite the stamp.

Stamp directory: ``HONEYLENS_STAMP_DIR`` or the package directory. Without a stamp, from a
git checkout, the build is ``git rev-parse --short=8 HEAD``; without git — ``dev``.
"""

import os
import subprocess  # nosec B404 — a single fixed git invocation, no shell, see _git_short_hash
from pathlib import Path

from honeylens import __version__ as VERSION_NUMBER

PRODUCT_NAME = "HoneyLens Sensor"
PRODUCT_SHORT = "HLS"

_PACKAGE_DIR = Path(__file__).resolve().parent


def _git_short_hash(root: Path) -> str:
    """``git rev-parse --short=8 HEAD`` in ``root``; ``dev`` when it is not a checkout."""
    try:
        out = subprocess.run(  # noqa: S603 # nosec B603 B607 — fixed arguments, no shell; git from PATH as everywhere
            ["git", "-C", str(root), "rev-parse", "--short=8", "HEAD"],  # noqa: S607
            capture_output=True,
            timeout=2,
            check=True,
        )
    except (subprocess.SubprocessError, OSError):
        return "dev"
    return out.stdout.decode("ascii", "replace").strip() or "dev"


def _read_stamp(path: Path, width: int | None = None) -> str:
    try:
        value = path.read_text().strip()
    except OSError:
        return ""
    return value[:width] if width else value


def stamp_dir() -> Path:
    override = os.environ.get("HONEYLENS_STAMP_DIR")
    return Path(override) if override else _PACKAGE_DIR


def read_stamps(directory: Path | None = None) -> tuple[str, str]:
    """(build, tree) from the stamp files in ``directory``.

    No ``BUILD_INFO`` (or an empty file) → the git hash if the directory sits in a
    checkout, otherwise ``dev``. No ``TREE_SHA`` → an empty fingerprint: an install from
    before stamping must read exactly as it used to, not print an empty bracket.
    """
    root = directory if directory is not None else stamp_dir()
    build = _read_stamp(root / "BUILD_INFO") or _git_short_hash(root)
    tree = _read_stamp(root / "TREE_SHA", width=8)
    return build, tree


BUILD_NUMBER, TREE_ID = read_stamps()

__version__ = f"{VERSION_NUMBER}+{BUILD_NUMBER}"
VERSION = __version__


def display_version(
    version: str = VERSION_NUMBER, build: str = BUILD_NUMBER, tree: str = TREE_ID
) -> str:
    """Human-readable version for the admin dashboard."""
    if tree:
        return f"{version} (build {build}, tree {tree})"
    return f"{version} (build {build})"
