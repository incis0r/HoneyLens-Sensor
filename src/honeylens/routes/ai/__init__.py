"""AI Analysis routes package (Phase 2 / T10).

Split from the routes/ai.py monolith into per-feature modules; the combined
`router` preserves the original route table (tests/test_ai_routes_split.py).
All /ai/rules* handlers stay in rules.py to keep the order-sensitive duplicate
GET /ai/rules/suggested and the ai_rules_all -> sibling references intact.
The `import *` re-exports the shared helpers so existing
`from routes.ai import _zd_colour`-style imports keep working.
"""

from fastapi import APIRouter

from honeylens.routes.ai._common import *  # noqa: F403 (back-compat helper re-export)

from . import (
    analysis,
    candidates,
    cost,
    feedback,
    queue,
    rules,
    search,
    stats,
    timeline,
)

router = APIRouter()
for _m in (cost, stats, rules, feedback, candidates, search, timeline, queue, analysis):
    router.include_router(_m.router)
