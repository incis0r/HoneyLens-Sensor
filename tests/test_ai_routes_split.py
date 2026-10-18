#!/usr/bin/env python3
"""Guard for the routes/ai.py -> routes/ai/ package split (Phase 2 / T10).

The AI routes were split from a single module into a per-feature package. The
combined `router` must register the expected route table. Matching is by the
(methods, path, name) multiset — order across distinct paths is irrelevant to
FastAPI routing. (A pre-existing duplicate GET /ai/rules/suggested was later
removed: the second handler was a dead route; it is now the private helper
_pending_suggested_rules that /ai/rules/all calls.)
"""

import json
import pathlib

from honeylens.routes.ai import router

_SNAPSHOT = pathlib.Path(__file__).with_name("data") / "ai_routes_snapshot.json"


def _flatten(routes):
    """FastAPI >= 0.135 keeps an included router as one `_IncludedRouter` entry; the
    route table the snapshot describes is the flattened one."""
    for r in routes:
        inner = getattr(r, "original_router", None)
        if inner is not None:
            yield from _flatten(inner.routes)
        else:
            yield r


def _current():
    return [
        [sorted(getattr(r, "methods", []) or []), r.path, r.name] for r in _flatten(router.routes)
    ]


def test_route_table_matches_golden_snapshot():
    golden = json.loads(_SNAPSHOT.read_text())
    current = _current()
    assert sorted(current) == sorted(golden), (
        "AI route table drifted from the golden snapshot. If intentional, "
        "regenerate tests/data/ai_routes_snapshot.json."
    )


def test_route_count_and_single_suggested():
    cur = _current()
    assert len(cur) == 23
    # the former duplicate GET /ai/rules/suggested is now a single route
    suggested = [r for r in cur if r[1] == "/ai/rules/suggested"]
    assert len(suggested) == 1 and suggested[0][0] == ["GET"]


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
