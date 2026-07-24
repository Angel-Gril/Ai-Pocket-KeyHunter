"""In-process singleton scan-task manager.

Wraps the existing async :func:`aipocket.scanner.run_scan` so the web layer can:

* run ONE scan at a time (global singleton; a second start returns 409);
* start it in the background and return immediately;
* expose a live state machine (idle/running/stopping/finished/interrupted);
* buffer the most recent log lines in memory for a rolling window + SSE, while
  ALSO writing the full log to ``<run_dir>/run.log`` (same mechanism as the CLI);
* stop a running scan cooperatively (``task.cancel()``);
* expose a human-readable ``phase`` string updated via :mod:`aipocket.core.scan_phase`.

Process restart == the in-flight scan is lost; state resets to ``idle`` — which
matches the "restart = interrupted, no resume" semantic from the spec.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from aipocket.core.config import settings
from aipocket.core.scan_phase import reset_phase_reporter, set_phase_reporter

if TYPE_CHECKING:
    from aipocket.core.models import ScanRunResult

log = logging.getLogger(__name__)

_LOG_FMT = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"
)


class _BufferHandler(logging.Handler):
    """Logging handler that appends formatted lines to the manager's buffer.

    Runs on whatever thread emits the log record (scanner uses a thread pool for
    FOFA/Shodan), so the append is guarded by the manager's lock.
    """

    def __init__(self, manager: ScanManager):
        super().__init__()
        self.setFormatter(_LOG_FMT)
        self._manager = manager

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:  # noqa: BLE001
            return
        self._manager._ingest_log(msg)


class ScanManager:
    States = ("idle", "running", "stopping", "finished", "interrupted")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = "idle"
        self._source: str | None = None
        self._mode = "incremental"
        self._github_pack_ids: tuple[str, ...] = ()
        self._manual_enrich: tuple[str, ...] = ()
        self._run_dir: Path | None = None
        self._started_at: str | None = None
        self._finished_at: str | None = None
        self._error: str | None = None

        self._task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

        # Log buffer: (seq, line). seq is monotonic across the process lifetime.
        maxlen = max(100, int(settings.web_log_buffer_lines))
        self._buffer: deque[tuple[int, str]] = deque(maxlen=maxlen)
        self._seq = 0
        self._handlers: list[logging.Handler] = []

        self._progress = self._empty_progress()
        self._phase = ""

    @staticmethod
    def _empty_progress() -> dict[str, int]:
        return {
            "raw_hits": 0,
            "unique_targets": 0,
            "candidates": 0,
            "active_requests": 0,
            "final_verified": 0,
            "suspicious": 0,
            "high_value_final": 0,
        }

    # -- introspection -----------------------------------------------------
    @property
    def state(self) -> str:
        return self._state

    def set_phase(self, message: str) -> None:
        """Update the coarse phase label shown on the web console."""
        with self._lock:
            self._phase = (message or "").strip()

    def status(self) -> dict:
        with self._lock:
            run_id = self._run_dir.name if self._run_dir else None
            return {
                "state": self._state,
                "source": self._source,
                "mode": self._mode,
                "github_pack_ids": list(self._github_pack_ids),
                "manual_enrich": list(self._manual_enrich),
                "run_id": run_id,
                "started_at": self._started_at,
                "finished_at": self._finished_at,
                "error": self._error,
                "progress": dict(self._progress),
                "phase": self._phase,
                "log_seq": self._seq,
            }

    def logs_since(self, since: int) -> tuple[list[tuple[int, str]], int]:
        """Return buffered lines with seq > ``since`` and the latest seq."""
        with self._lock:
            lines = [(s, ln) for (s, ln) in self._buffer if s > since]
            return lines, self._seq

    def recent(self, n: int) -> list[tuple[int, str]]:
        with self._lock:
            return list(self._buffer)[-n:]

    # -- log ingestion -----------------------------------------------------
    def _ingest_log(self, msg: str) -> None:
        with self._lock:
            self._seq += 1
            self._buffer.append((self._seq, msg))

    # -- lifecycle ---------------------------------------------------------
    def start(
        self,
        source: str,
        mode: str = "incremental",
        github_pack_ids: tuple[str, ...] = (),
        resume_run_id: str = "",
        manual_enrich: tuple[str, ...] = (),
    ) -> dict:
        """Start a background scan. Raises RuntimeError if one is already running."""
        with self._lock:
            if self._state in ("running", "stopping"):
                raise RuntimeError("a scan is already running")
            self._reset_for_new_run(
                source,
                mode,
                github_pack_ids,
                resume_run_id=resume_run_id,
                manual_enrich=manual_enrich,
            )

        self._loop = asyncio.get_running_loop()
        self._attach_log_handlers()
        self._task = asyncio.create_task(
            self._run(
                source,
                mode,
                github_pack_ids,
                resume_run_id=resume_run_id,
                manual_enrich=manual_enrich,
            )
        )
        return self.status()

    def _reset_for_new_run(
        self,
        source: str,
        mode: str,
        github_pack_ids: tuple[str, ...] = (),
        *,
        resume_run_id: str = "",
        manual_enrich: tuple[str, ...] = (),
    ) -> None:
        from aipocket.services.writer import new_run_dir

        self._source = source
        self._mode = mode
        self._github_pack_ids = github_pack_ids
        self._manual_enrich = tuple(manual_enrich)
        if resume_run_id:
            self._run_dir = settings.results_path / resume_run_id
            self._run_dir.mkdir(parents=True, exist_ok=True)
        else:
            self._run_dir = new_run_dir()
        self._started_at = datetime.now(UTC).isoformat()
        self._finished_at = None
        self._error = None
        self._state = "running"
        self._progress = self._empty_progress()
        self._phase = "恢复中" if resume_run_id else "启动中"

    def _attach_log_handlers(self) -> None:
        # Attach to the "aipocket" logger (not root), so only our own modules'
        # records are buffered/written — unrelated libraries keep their handlers,
        # and we don't force the whole process to INFO.
        target = logging.getLogger("aipocket")
        buf = _BufferHandler(self)
        buf.setLevel(logging.INFO)
        target.addHandler(buf)
        self._handlers = [buf]
        if self._run_dir is not None:
            fh = logging.FileHandler(self._run_dir / "run.log", encoding="utf-8")
            fh.setFormatter(_LOG_FMT)
            fh.setLevel(logging.INFO)
            target.addHandler(fh)
            self._handlers.append(fh)
        # Ensure INFO records from aipocket.* actually reach our handlers.
        if target.level > logging.INFO or target.level == logging.NOTSET:
            target.setLevel(logging.INFO)

    def _detach_log_handlers(self) -> None:
        target = logging.getLogger("aipocket")
        for h in self._handlers:
            try:
                target.removeHandler(h)
                h.close()
            except Exception:  # noqa: BLE001
                pass
        self._handlers = []

    @staticmethod
    def _sources_for_scan(source: str) -> set[str] | None:
        """Map status label → ``run_scan(sources=…)`` set.

        - ``all`` / empty → None (every configured source)
        - ``fofa`` → ``{"fofa"}``
        - ``fofa,shodan`` → ``{"fofa", "shodan"}``
        """
        label = (source or "all").strip()
        if not label or label == "all":
            return None
        parts = {p.strip() for p in label.split(",") if p.strip()}
        if not parts or "all" in parts:
            return None
        return parts

    async def _run(
        self,
        source: str,
        mode: str = "incremental",
        github_pack_ids: tuple[str, ...] = (),
        resume_run_id: str = "",
        manual_enrich: tuple[str, ...] = (),
    ) -> None:
        from aipocket.services.scanner import run_scan

        # Restrict the scan to the chosen source(s) via a parameter — no global
        # settings mutation, so concurrent /settings reads/writes stay correct.
        sources = self._sources_for_scan(source)

        result: ScanRunResult | None = None
        phase_token = set_phase_reporter(self.set_phase)
        try:
            log.info(
                "Web scan starting (source=%s, run=%s, resume=%s, manual_enrich=%s)",
                source,
                self._run_dir,
                resume_run_id or "-",
                ",".join(manual_enrich) or "-",
            )
            from aipocket.core.scan_phase import report_phase

            enrich_note = f" · enrich={','.join(manual_enrich)}" if manual_enrich else ""
            report_phase(
                f"{'恢复' if resume_run_id else '启动'}扫描 · source={source}{enrich_note}"
            )
            result = await run_scan(
                run_dir=self._run_dir,
                sources=sources,
                mode=mode,
                github_pack_ids=github_pack_ids,
                resume_run_id=resume_run_id or None,
                manual_enrich=manual_enrich,
            )
            with self._lock:
                self._state = "finished"
                self._progress = {
                    "raw_hits": result.raw_hits_count,
                    "unique_targets": result.unique_targets,
                    "candidates": result.candidates,
                    "active_requests": result.active_requests,
                    "final_verified": result.final_verified,
                    "suspicious": result.suspicious,
                    "high_value_final": result.high_value_final,
                }
                self._phase = f"已完成 · 可用 {result.final_verified} / 候选 {result.candidates}"
            log.info(
                "Web scan finished: %d valid / %d creds",
                result.total_valid,
                result.total_credentials,
            )
        except asyncio.CancelledError:
            with self._lock:
                self._state = "interrupted"
                self._phase = "已中断"
            log.warning("Web scan interrupted (stopped by request)")
            raise
        except Exception as e:  # noqa: BLE001 — surface but don't crash the server
            with self._lock:
                self._state = "interrupted"
                self._error = str(e)
                self._phase = f"失败 · {type(e).__name__}"
            log.exception("Web scan failed: %s", e)
        finally:
            reset_phase_reporter(phase_token)
            with self._lock:
                self._finished_at = datetime.now(UTC).isoformat()
            self._detach_log_handlers()
            # run.log can be hundreds of KB; offload the synchronous UPDATE so it
            # doesn't block the event loop (and thus other endpoints).
            await asyncio.to_thread(self._persist_log_to_pg)

    def _persist_log_to_pg(self) -> None:
        """Store the final run.log text on the PG runs row (no-op when PG disabled).

        Called after handlers are detached (log file flushed/closed) so the text
        is complete. Best-effort: a failure here must not crash the manager. Only
        runs when the run row already exists — a scan interrupted before
        persist_run_pg leaves no row, and the UPDATE simply matches zero rows.
        """
        if not settings.pg_enabled or self._run_dir is None:
            return
        log_file = self._run_dir / "run.log"
        if not log_file.exists():
            return
        try:
            from aipocket.services.writer import update_run_log_pg

            update_run_log_pg(self._run_dir.name, log_file.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001 — logging persistence is non-critical
            log.warning("Failed to persist run.log to PG: %s", e)

    async def stop(self) -> dict:
        with self._lock:
            if self._state != "running":
                raise RuntimeError("no scan is running")
            self._state = "stopping"
            task = self._task
        if task is not None:
            task.cancel()
        return self.status()
