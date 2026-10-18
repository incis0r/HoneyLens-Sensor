"""Bounded, off-loop event writer for the NetScaler decoy.

The decoy's handlers must never block the event loop on disk or stdout, and a sink that
falls behind must *lose events visibly*, not silently. This writer sits between the handler
and the destinations:

    handler -> submit() (non-blocking) -> bounded queue -> background drain -> sink / stdout / file

What it gives:

* **Off-loop writes.** The drain runs each write through ``asyncio.to_thread`` so the sink's
  open-append and the stdout/file writes do not stall request handling.
* **A bounded queue.** When the queue is full, ``submit`` drops the event and counts it
  rather than applying back-pressure to the handler or growing without limit.
* **Counters that reconcile.** ``accepted = written + sink_false + sink_error`` (eventually)
  and ``dropped`` is explicit, so "events in" minus "events out" is always accountable —
  the review's "no unexplained loss".

What it deliberately does NOT change: the shared sink's contract. The sink still opens its
honeypotng file per append because ``honeylens-ingest-honeypot`` truncates it; this writer
calls that same ``write_record`` off the loop. A durable spool with checkpoints, co-designed
with ingest, is a separate task and is intentionally not bolted on here.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from honeylens.eventlog_lock import append_line

logger = logging.getLogger("netscaler-honeypot")


class EventLog:
    """Async fan-out of event records to the sink, stdout and an optional file."""

    def __init__(self, *, sink: Any = None, log_file: str = "", maxsize: int = 10000) -> None:
        self.sink = sink
        self.log_file = log_file
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        self.metrics: dict[str, int] = {
            "accepted": 0,  # submitted and queued
            "written": 0,  # written to the sink successfully
            "dropped": 0,  # queue full on submit — lost, but counted
            "sink_false": 0,  # sink.write_record returned False
            "sink_error": 0,  # sink.write_record raised
            "file_error": 0,  # optional log file write failed
        }
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._drain(), name="netscaler-eventlog")

    async def aclose(self) -> None:
        if self._task is not None:
            await self.queue.join()  # let queued events flush
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def submit(self, record: dict[str, Any]) -> bool:
        """Non-blocking hand-off from a handler. False (and counted) when the queue is full."""
        try:
            self.queue.put_nowait(record)
        except asyncio.QueueFull:
            self.metrics["dropped"] += 1
            return False
        self.metrics["accepted"] += 1
        return True

    async def _drain(self) -> None:
        while True:
            record = await self.queue.get()
            try:
                await asyncio.to_thread(self._write, record)
            except Exception as exc:  # pragma: no cover - defensive; a write must not kill drain
                logger.error("eventlog drain error: %s", exc)
            finally:
                self.queue.task_done()

    def _write(self, record: dict[str, Any]) -> None:
        """Runs in a worker thread: blocking sink/stdout/file writes live here, off the loop."""
        if self.sink is not None:
            try:
                if self.sink.write_record(record):
                    self.metrics["written"] += 1
                else:
                    self.metrics["sink_false"] += 1
                    logger.error("sink write_record returned False — event not persisted")
            except Exception as exc:
                self.metrics["sink_error"] += 1
                logger.error("sink write failed: %s", exc)
        line = json.dumps(record, default=str, separators=(",", ":"))
        print(line, flush=True)
        if self.log_file:
            try:
                append_line(self.log_file, line)
            except OSError as exc:
                self.metrics["file_error"] += 1
                logger.error("netscaler log file write failed (%s): %s", self.log_file, exc)
