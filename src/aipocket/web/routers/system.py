"""System control endpoints — backend restart (hot-reload fallback)."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from fastapi import APIRouter, Depends

from ..auth import get_current_user

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/system", tags=["system"], dependencies=[Depends(get_current_user)])

# asyncio only holds weak refs to tasks, so keep our own strong ref until done —
# otherwise the restart task could be GC'd mid-flight before it re-execs.
_background_tasks: set[asyncio.Task] = set()


async def _delayed_restart() -> None:
    """Re-exec the process after a short delay so the HTTP response flushes.

    On a bare host this replaces the current process image with a fresh one
    (picking up the new .env). Under Docker/systemd with a restart policy,
    exiting is enough — the supervisor relaunches the container.
    """
    await asyncio.sleep(0.5)
    log.warning("Restart requested via API — re-executing process")
    try:
        os.execv(sys.executable, [sys.executable, *sys.argv])
    except Exception:  # noqa: BLE001 — fall back to a hard exit for the supervisor
        log.exception("os.execv failed; exiting for supervisor to restart")
        os._exit(3)


@router.post("/restart")
async def restart() -> dict:
    """Request a backend restart. Returns immediately; restart happens after."""
    task = asyncio.create_task(_delayed_restart())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return {"restarting": True}
