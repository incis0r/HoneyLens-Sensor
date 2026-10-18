"""The README's decoy table is a claim about the manifest, so it can be tested.

Measured 2026-11-06, on the tree that was about to be published: the README said
"43 honeypots" in three places and its two decoy tables held 43 rows, while
``HONEYPOTS`` held 44. The missing one was ``express``, the Node/Express bait added
for the React Server Components work; nothing broke, because nothing reads the
README. It is the front page of the public branch, which is exactly why the number
on it is worth an assertion rather than a habit.

The count claims and the table are tested separately on purpose: a decoy added
without a row and a decoy added with a row but no count bump are different
mistakes, and the failure should say which one happened.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from honeylens.honeypots.manifest import HONEYPOTS

README = Path(__file__).resolve().parents[1] / "README.md"

_TABLE_START = "### Network and application decoys"
_TABLE_END = "## Port model"
_ROW = re.compile(r"^\| ([a-z0-9_-]+) \|", re.MULTILINE)


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _decoy_table() -> str:
    """Just the two decoy tables. Bounding the scan matters: the README has other
    tables whose first cell is lowercase, and counting those would make this pass
    for the wrong reason."""
    text = _readme()
    start = text.index(_TABLE_START)
    return text[start : text.index(_TABLE_END, start)]


def _names() -> list[str]:
    return sorted(HONEYPOTS) if isinstance(HONEYPOTS, dict) else sorted(h.name for h in HONEYPOTS)


def test_every_decoy_in_the_manifest_has_a_row():
    rows = set(_ROW.findall(_decoy_table()))
    missing = [n for n in _names() if n not in rows]
    assert not missing, f"decoys in the manifest with no README row: {missing}"


def test_the_table_invents_no_decoy():
    rows = _ROW.findall(_decoy_table())
    extra = [r for r in rows if r not in set(_names())]
    assert not extra, f"README rows naming no decoy in the manifest: {extra}"


def test_no_decoy_is_listed_twice():
    rows = _ROW.findall(_decoy_table())
    assert len(rows) == len(set(rows)), "a decoy is listed more than once"


@pytest.mark.parametrize(
    "claim",
    [
        "**{n} honeypots** — from SSH, HTTP, RDP and databases",
        "| **Deception** | {n} honeypots as separate containers",
        "All {n} decoys, generated from the manifest.",
    ],
)
def test_the_prose_counts_match_the_manifest(claim):
    assert claim.format(n=len(HONEYPOTS)) in _readme()
