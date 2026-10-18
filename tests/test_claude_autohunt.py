"""Auto-hunt after a Claude analysis: the profiler coroutine must run both from
synchronous code and from under a running event loop (FastAPI routes).

In 0.9 auto-hunt never worked (wrong profile_ip signature, the coroutine treated as a
dict); after the fix asyncio.run would fail inside the loop — hence the separate thread.
"""

from __future__ import annotations

import asyncio

from honeylens.analysis.claude_analyzer import _run_coroutine_blocking


async def _work(x: int) -> int:
    await asyncio.sleep(0)
    return x * 2


def test_runs_from_plain_sync_code() -> None:
    assert _run_coroutine_blocking(_work(21)) == 42


def test_runs_from_inside_a_running_loop() -> None:
    async def route() -> int:
        return _run_coroutine_blocking(_work(5))

    assert asyncio.run(route()) == 10
