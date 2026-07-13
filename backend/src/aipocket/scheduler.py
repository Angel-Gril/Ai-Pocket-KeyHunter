from __future__ import annotations

import asyncio
import contextlib
import logging
import signal

from aipocket.core.config import settings
from aipocket.services.scanner import run_scan
from aipocket.services.writer import new_run_dir

log = logging.getLogger(__name__)


class Scheduler:
    def __init__(self):
        self._stop = asyncio.Event()

    async def run_forever(self):
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self._stop.set)

        log.info("Scheduler started. interval=%ds", settings.scheduler_interval)
        while not self._stop.is_set():
            try:
                run_dir = new_run_dir()
                result = await run_scan(run_dir=run_dir)
                log.info(
                    "Run done: %d valid / %d creds. Sleeping %ds...",
                    result.total_valid,
                    result.total_credentials,
                    settings.scheduler_interval,
                )
            except Exception:
                log.exception("Scan run failed")

            try:
                await asyncio.wait_for(self._stop.wait(), timeout=settings.scheduler_interval)
            except TimeoutError:
                continue

        log.info("Scheduler stopped.")

    def stop(self):
        self._stop.set()


async def run_once(query_budgets=None):
    """Run a single scan into its own run folder. Returns the ScanRunResult."""
    run_dir = new_run_dir()
    result = await run_scan(query_budgets=query_budgets, run_dir=run_dir)
    return result
