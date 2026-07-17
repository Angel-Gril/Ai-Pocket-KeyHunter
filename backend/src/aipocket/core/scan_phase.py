"""Coarse scan-phase reporting for CLI logs and the web console.

Discovery / validation steps call :func:`report_phase` to:

1. emit a clear ``阶段 · …`` INFO line (visible in the rolling log panel);
2. optionally push the same string to a process-local reporter (web ScanManager).

CLI scans leave the reporter unset — only the log line is emitted.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextvars import ContextVar, Token

log = logging.getLogger(__name__)

PhaseReporter = Callable[[str], None]

_phase_reporter: ContextVar[PhaseReporter | None] = ContextVar(
    "aipocket_phase_reporter", default=None
)


def set_phase_reporter(reporter: PhaseReporter | None) -> Token:
    """Install (or clear) the current task's phase reporter. Returns a reset token."""
    return _phase_reporter.set(reporter)


def reset_phase_reporter(token: Token) -> None:
    _phase_reporter.reset(token)


def report_phase(message: str) -> None:
    """Log a human-readable phase marker and notify the web UI if attached."""
    text = (message or "").strip()
    if not text:
        return
    log.info("阶段 · %s", text)
    reporter = _phase_reporter.get()
    if reporter is not None:
        try:
            reporter(text)
        except Exception:  # noqa: BLE001 — phase UI must never break a scan
            log.debug("phase reporter failed", exc_info=True)
