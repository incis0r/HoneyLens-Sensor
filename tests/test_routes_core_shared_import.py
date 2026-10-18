"""The event list (`get_events`) and the JSON export rely on shared query builders that
stayed in `honeylens.api`. `routes/core.py` reached for them with a lazy import, which in
0.9 read `import api` (a flat name from under the sys.path bootstrap). In 1.0 that import
raised `ModuleNotFoundError: No module named 'api'` — but only on the
`GET /events?src_ip=...` / JSON export path, so it surfaced as a 500 only on the first real
traffic, not in the module import tests.

This test pins that `_get_shared()` resolves to `honeylens.api` and exposes the builders
that `core.py` uses.
"""

from __future__ import annotations

from honeylens.routes import core


def test_get_shared_resolves_to_honeylens_api():
    shared = core._get_shared()
    assert shared.__name__ == "honeylens.api"


def test_get_shared_exposes_the_query_builders_core_uses():
    shared = core._get_shared()
    for fn in ("_build_events_query", "_build_events_query_with_ja3", "_events_search_bar_html"):
        assert callable(getattr(shared, fn)), f"honeylens.api.{fn} must exist for routes.core"
