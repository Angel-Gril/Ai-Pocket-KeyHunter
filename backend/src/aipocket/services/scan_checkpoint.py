"""Durable scan phase checkpoints on ``runs.phase`` / ``runs.phase_detail``.

Resume is opt-in (CLI ``--resume-run`` / API ``resume_run_id``). Default new
scans still allocate a fresh ``run_id``.
"""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.config import settings

log = logging.getLogger(__name__)

# Suggested phase values (string enum).
PHASE_STARTED = "started"
PHASE_DISCOVERY = "discovery"
PHASE_EXTRACT = "extract"
PHASE_PROBE = "probe"
PHASE_GPT = "gpt"
PHASE_VALIDATE = "validate"
PHASE_FINALIZE = "finalize"
PHASE_FINISHED = "finished"
PHASE_INTERRUPTED = "interrupted"

# Ordered pipeline stages used for resume decisions.
_PHASE_ORDER = (
    PHASE_STARTED,
    PHASE_DISCOVERY,
    PHASE_EXTRACT,
    PHASE_PROBE,
    PHASE_GPT,
    PHASE_VALIDATE,
    PHASE_FINALIZE,
    PHASE_FINISHED,
)


def phase_rank(phase: str) -> int:
    try:
        return _PHASE_ORDER.index(phase)
    except ValueError:
        return -1


def phase_at_least(current: str, minimum: str) -> bool:
    return phase_rank(current) >= phase_rank(minimum) and phase_rank(current) >= 0


def mark_phase(run_id: str, phase: str, **detail: Any) -> None:
    """UPDATE runs.phase / phase_detail. No-op when PG disabled or run_id empty."""
    if not settings.pg_enabled or not run_id:
        return
    try:
        from psycopg.types.json import Jsonb

        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn, conn.transaction():
            if detail:
                conn.execute(
                    """
                    UPDATE runs
                    SET phase = %s,
                        phase_detail = COALESCE(phase_detail, '{}'::jsonb) || %s::jsonb
                    WHERE run_id = %s
                    """,
                    (phase, Jsonb(detail), run_id),
                )
            else:
                conn.execute(
                    "UPDATE runs SET phase = %s WHERE run_id = %s",
                    (phase, run_id),
                )
        log.debug("scan phase run=%s phase=%s detail_keys=%s", run_id, phase, list(detail))
    except Exception as e:  # noqa: BLE001 — checkpoint must not fail the scan
        log.warning("mark_phase failed run=%s phase=%s: %s", run_id, phase, e)


def load_phase(run_id: str) -> tuple[str, dict[str, Any]]:
    """Return (phase, phase_detail) for a run. Empty when missing/PG off."""
    if not settings.pg_enabled or not run_id:
        return "", {}
    try:
        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT phase, phase_detail, state FROM runs WHERE run_id = %s",
                (run_id,),
            )
            row = cur.fetchone()
        if not row:
            return "", {}
        phase = row["phase"] if isinstance(row, dict) else row[0]
        detail = row["phase_detail"] if isinstance(row, dict) else row[1]
        if not isinstance(detail, dict):
            detail = {}
        return str(phase or ""), detail
    except Exception as e:  # noqa: BLE001
        log.warning("load_phase failed run=%s: %s", run_id, e)
        return "", {}


def load_run_state(run_id: str) -> dict[str, Any] | None:
    """Load minimal run row for resume validation. None if missing."""
    if not settings.pg_enabled or not run_id:
        return None
    try:
        from aipocket.core.db import get_pool

        pool = get_pool()
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_id, state, phase, phase_detail, scan_mode, started_at
                FROM runs WHERE run_id = %s
                """,
                (run_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        if isinstance(row, dict):
            return dict(row)
        return {
            "run_id": row[0],
            "state": row[1],
            "phase": row[2],
            "phase_detail": row[3] if isinstance(row[3], dict) else {},
            "scan_mode": row[4],
            "started_at": row[5],
        }
    except Exception as e:  # noqa: BLE001
        log.warning("load_run_state failed run=%s: %s", run_id, e)
        return None
