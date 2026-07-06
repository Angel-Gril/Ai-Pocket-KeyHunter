"""Scan-result read endpoints: runs timeline + per-run valid/suspicious/log."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from ..auth import get_current_user
from ..results_reader import (
    list_runs,
    load_run_records,
    read_run_log,
)

router = APIRouter(prefix="/api/runs", tags=["runs"], dependencies=[Depends(get_current_user)])


@router.get("")
async def get_runs() -> dict:
    """All runs grouped by day (newest first)."""
    # Reading + parsing the results tree is blocking I/O — keep it off the loop.
    return {"days": await asyncio.to_thread(list_runs)}


@router.get("/{run_id}/valid")
async def get_run_valid(run_id: str) -> dict:
    """Valid keys for a run — apikeys masked, full record otherwise."""
    results = await asyncio.to_thread(load_run_records, run_id, "valid")
    return {"run_id": run_id, "results": results}


@router.get("/{run_id}/suspicious")
async def get_run_suspicious(run_id: str) -> dict:
    """Suspicious (quarantined) keys for a run — apikeys masked."""
    results = await asyncio.to_thread(load_run_records, run_id, "suspicious")
    return {"run_id": run_id, "results": results}


@router.get("/{run_id}/log", response_class=PlainTextResponse)
async def get_run_log(run_id: str) -> str:
    """Full on-disk run.log for a finished run."""
    return await asyncio.to_thread(read_run_log, run_id)
