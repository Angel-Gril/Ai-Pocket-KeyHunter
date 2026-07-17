"""Scan control + live log endpoints (SSE + polling fallback)."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Query, Request
from sse_starlette.sse import EventSourceResponse

from ..deps import get_current_user, get_current_user_sse
from ..errors import ApiError
from ..scan_manager import ScanManager
from ..schemas import (
    ScanLogLine,
    ScanLogsResponse,
    ScanProgress,
    ScanStartRequest,
    ScanStatusResponse,
)

router = APIRouter(prefix="/api/scan", tags=["scan"])

# Standard endpoints require the bearer token via the ``Authorization`` header.
# The SSE stream is defined on the parent ``router`` instead, so it can use its
# own query-param-aware dependency without weakening these.
_protected = APIRouter(dependencies=[Depends(get_current_user)])


def _manager(request: Request) -> ScanManager:
    return request.app.state.scan_manager


def _to_status(raw: dict) -> ScanStatusResponse:
    return ScanStatusResponse(
        state=raw["state"],
        source=raw.get("source"),
        mode=raw.get("mode", "incremental"),
        run_id=raw.get("run_id"),
        github_pack_ids=raw.get("github_pack_ids", []),
        started_at=raw.get("started_at"),
        finished_at=raw.get("finished_at"),
        error=raw.get("error"),
        progress=ScanProgress(**raw.get("progress", {})),
        phase=raw.get("phase") or "",
        log_seq=raw.get("log_seq", 0),
    )


@_protected.post("/start", response_model=ScanStatusResponse)
async def start_scan(body: ScanStartRequest, request: Request) -> ScanStatusResponse:
    mgr = _manager(request)
    try:
        raw = mgr.start(body.source, body.mode, tuple(body.github_pack_ids))
    except RuntimeError as e:
        # A scan is already running → conflict; the frontend greys out the button.
        raise ApiError(str(e), status_code=409, code="conflict") from e
    return _to_status(raw)


@_protected.post("/stop", response_model=ScanStatusResponse)
async def stop_scan(request: Request) -> ScanStatusResponse:
    mgr = _manager(request)
    try:
        raw = await mgr.stop()
    except RuntimeError as e:
        raise ApiError(str(e), status_code=409, code="conflict") from e
    return _to_status(raw)


@_protected.get("/status", response_model=ScanStatusResponse)
async def scan_status(request: Request) -> ScanStatusResponse:
    return _to_status(_manager(request).status())


@_protected.get("/logs", response_model=ScanLogsResponse)
async def scan_logs(request: Request, since: int = Query(0, ge=0)) -> ScanLogsResponse:
    """Polling fallback — return buffered lines with seq > since."""
    lines, last = _manager(request).logs_since(since)
    return ScanLogsResponse(
        lines=[ScanLogLine(seq=s, line=ln) for s, ln in lines],
        last_seq=last,
    )


@router.get("/logs/stream", dependencies=[Depends(get_current_user_sse)])
async def scan_logs_stream(request: Request, since: int = Query(0, ge=0)) -> EventSourceResponse:
    """SSE stream — replay recent lines, then push new ones as they arrive.

    NOTE: behind nginx set ``proxy_buffering off;`` for this location, or the
    stream will be buffered and appear frozen.
    """
    mgr = _manager(request)

    async def _gen():
        cursor = since
        # Initial replay of whatever is already buffered past the cursor.
        while True:
            if await request.is_disconnected():
                break
            lines, last = mgr.logs_since(cursor)
            for seq, ln in lines:
                yield {"event": "log", "id": str(seq), "data": ln}
                cursor = seq
            # Emit a status heartbeat so the client can track state transitions.
            status = mgr.status()
            yield {"event": "status", "data": status["state"]}
            if status["state"] in ("finished", "interrupted", "idle") and cursor >= last:
                # Nothing more will come for this run; close the stream.
                break
            await asyncio.sleep(1.0)

    return EventSourceResponse(_gen())


router.include_router(_protected)
