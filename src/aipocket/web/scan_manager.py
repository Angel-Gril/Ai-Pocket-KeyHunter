"""In-process singleton scan-task manager.

Wraps the existing async :func:`aipocket.scanner.run_scan` so the web layer can:

* run ONE scan at a time (global singleton; a second start returns 409);
* start it in the background and return immediately;
* expose a live state machine (idle/running/stopping/finished/interrupted);
* buffer the most recent log lines in memory for a rolling window + SSE, while
  ALSO writing the full log to ``<run_dir>/run.log`` (same mechanism as the CLI);
* stop a running scan cooperatively (``task.cancel()``);
* derive coarse progress from the scanner's existing log lines (no scanner change).

Process restart == the in-flight scan is lost; state resets to ``idle`` — which
matches the "restart = interrupted, no resume" semantic from the spec.
"""

from __future__ import annotations

import asyncio
import logging
import re
import threading
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..config import settings

if TYPE_CHECKING:
    from ..models import ScanRunResult

log = logging.getLogger(__name__)

_LOG_FMT = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"
)

# Progress regexes matched against scanner log lines (best-effort; the scanner
# emits these today — see scanner.py). If the wording changes, progress simply
# stays at its last value; the scan itself is unaffected.
_RE_TOTAL_HITS = re.compile(r"Total hits:\s*(\d+)")
_RE_VALIDATING = re.compile(r"Validating\s+(\d+)\s+credential")
_RE_EXTRACTED = re.compile(r"Extracted\s+(\d+)\s+candidate")


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

        # Progress counters, updated from log parsing + final result.
        self._hosts = 0
        self._credentials = 0
        self._validated = 0
        self._valid = 0

    # -- introspection -----------------------------------------------------
    @property
    def state(self) -> str:
        return self._state

    def status(self) -> dict:
        with self._lock:
            run_id = self._run_dir.name if self._run_dir else None
            return {
                "state": self._state,
                "source": self._source,
                "run_id": run_id,
                "started_at": self._started_at,
                "finished_at": self._finished_at,
                "error": self._error,
                "progress": {
                    "hosts": self._hosts,
                    "credentials": self._credentials,
                    "validated": self._validated,
                    "valid": self._valid,
                },
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
            self._parse_progress(msg)

    def _parse_progress(self, msg: str) -> None:
        m = _RE_TOTAL_HITS.search(msg)
        if m:
            self._hosts = int(m.group(1))
        m = _RE_EXTRACTED.search(msg)
        if m:
            self._credentials = max(self._credentials, int(m.group(1)))
        m = _RE_VALIDATING.search(msg)
        if m:
            self._validated = int(m.group(1))

    # -- lifecycle ---------------------------------------------------------
    def start(self, source: str) -> dict:
        """Start a background scan. Raises RuntimeError if one is already running."""
        with self._lock:
            if self._state in ("running", "stopping"):
                raise RuntimeError("a scan is already running")
            self._reset_for_new_run(source)

        self._loop = asyncio.get_running_loop()
        self._attach_log_handlers()
        self._task = asyncio.create_task(self._run(source))
        return self.status()

    def _reset_for_new_run(self, source: str) -> None:
        from ..writer import new_run_dir

        self._source = source
        self._run_dir = new_run_dir()
        self._started_at = datetime.now(UTC).isoformat()
        self._finished_at = None
        self._error = None
        self._state = "running"
        self._hosts = self._credentials = self._validated = self._valid = 0

    def _attach_log_handlers(self) -> None:
        root = logging.getLogger()
        buf = _BufferHandler(self)
        buf.setLevel(logging.INFO)
        root.addHandler(buf)
        self._handlers = [buf]
        if self._run_dir is not None:
            fh = logging.FileHandler(self._run_dir / "run.log", encoding="utf-8")
            fh.setFormatter(_LOG_FMT)
            fh.setLevel(logging.INFO)
            root.addHandler(fh)
            self._handlers.append(fh)
        # Ensure INFO records actually propagate to our handlers.
        if root.level > logging.INFO or root.level == logging.NOTSET:
            root.setLevel(logging.INFO)

    def _detach_log_handlers(self) -> None:
        root = logging.getLogger()
        for h in self._handlers:
            try:
                root.removeHandler(h)
                h.close()
            except Exception:  # noqa: BLE001
                pass
        self._handlers = []

    async def _run(self, source: str) -> None:
        from ..scanner import run_scan

        # Restrict the scan to the chosen source(s) by temporarily blanking the
        # OTHER source's keys — run_scan skips a source whose keys are empty
        # (see scanner.py). Restored in finally so config isn't permanently
        # mutated. (Editing settings here is safe: single-scan singleton.)
        saved_fofa = settings.fofa_keys
        saved_shodan = settings.shodan_keys
        if source == "fofa":
            settings.shodan_keys = ""
        elif source == "shodan":
            settings.fofa_keys = ""

        result: ScanRunResult | None = None
        try:
            log.info("Web scan starting (source=%s, run=%s)", source, self._run_dir)
            result = await run_scan(run_dir=self._run_dir)
            with self._lock:
                self._state = "finished"
                self._valid = result.total_valid
                self._credentials = result.total_credentials
                self._hosts = result.total_hosts
            log.info(
                "Web scan finished: %d valid / %d creds",
                result.total_valid, result.total_credentials,
            )
        except asyncio.CancelledError:
            with self._lock:
                self._state = "interrupted"
            log.warning("Web scan interrupted (stopped by request)")
            raise
        except Exception as e:  # noqa: BLE001 — surface but don't crash the server
            with self._lock:
                self._state = "interrupted"
                self._error = str(e)
            log.exception("Web scan failed: %s", e)
        finally:
            settings.fofa_keys = saved_fofa
            settings.shodan_keys = saved_shodan
            with self._lock:
                self._finished_at = datetime.now(UTC).isoformat()
            self._detach_log_handlers()

    async def stop(self) -> dict:
        with self._lock:
            if self._state != "running":
                raise RuntimeError("no scan is running")
            self._state = "stopping"
            task = self._task
        if task is not None:
            task.cancel()
        return self.status()
