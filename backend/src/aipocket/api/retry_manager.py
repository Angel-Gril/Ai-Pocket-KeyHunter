"""In-process job tracker for web-triggered GPT-failed-batch retries.

Only one retry runs at a time (process-wide). Mirrors the ScanManager pattern:
POST starts a background task; GET returns the latest job snapshot for polling.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from aipocket.services.retry_gpt_failed import RetryGptFailedReport, retry_gpt_failed

log = logging.getLogger(__name__)


class RetryManager:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._state: dict[str, Any] = {
            "state": "idle",  # idle | running | finished | error
            "run_id": None,
            "started_at": None,
            "finished_at": None,
            "error": None,
            "report": None,
        }

    def status(self) -> dict[str, Any]:
        return dict(self._state)

    def is_running(self) -> bool:
        return self._state["state"] == "running"

    def start(self, run_id: str) -> dict[str, Any]:
        if self.is_running():
            raise RuntimeError("a GPT-failed retry is already running")
        self._state = {
            "state": "running",
            "run_id": run_id,
            "started_at": datetime.now(UTC).isoformat(),
            "finished_at": None,
            "error": None,
            "report": None,
        }
        self._task = asyncio.create_task(self._run(run_id), name=f"retry-gpt-failed-{run_id}")
        return self.status()

    async def _run(self, run_id: str) -> None:
        async with self._lock:
            try:
                report: RetryGptFailedReport = await retry_gpt_failed(run_id)
                self._state["state"] = "finished"
                self._state["report"] = {
                    "run_id": report.run_id,
                    "failed_files": report.failed_files,
                    "failed_hits": report.failed_hits,
                    "credentials_found": report.credentials_found,
                    "valid_appended": report.valid_appended,
                    "suspicious_appended": report.suspicious_appended,
                    "high_value_final": report.high_value_final,
                    "archived_files": list(report.archived_files),
                    "jsonl_paths": list(report.jsonl_paths),
                    "message": report.message,
                }
            except Exception as e:  # noqa: BLE001 — surface any failure to the UI
                log.exception("GPT-failed retry crashed for %s", run_id)
                self._state["state"] = "error"
                self._state["error"] = str(e)
            finally:
                self._state["finished_at"] = datetime.now(UTC).isoformat()
                self._task = None
