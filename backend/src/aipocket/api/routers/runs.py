"""Scan-result read endpoints: runs timeline + per-run valid/suspicious/log.

Also exposes GPT-failed-batch inspection + retry (append-only recovery).
"""

from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse

from ..deps import get_current_user
from ..errors import ApiError
from ..results_reader import (
    list_runs,
    load_run_records,
    read_run_log,
)
from ..schemas import (
    DeleteRunResponse,
    GptFailedFileInfo,
    GptFailedStatusResponse,
    RetryGptFailedJobStatus,
    RetryGptFailedReportView,
)

router = APIRouter(prefix="/api/runs", tags=["runs"], dependencies=[Depends(get_current_user)])


@router.get("")
async def get_runs() -> dict:
    """All runs grouped by day (newest first)."""
    # Reading + parsing the results tree is blocking I/O — keep it off the loop.
    return {"days": await asyncio.to_thread(list_runs)}

@router.delete("/{run_id}", response_model=DeleteRunResponse)
async def remove_run(run_id: str) -> DeleteRunResponse:
    if not re.fullmatch(r"run_\d{4}_\d{2}_\d{2}_\d{2}-\d{2}-\d{2}", run_id):
        raise ApiError("invalid run id", status_code=400, code="bad_request")
    from aipocket.services.result_operations import delete_run

    try:
        report = await asyncio.to_thread(delete_run, run_id)
    except RuntimeError as exc:
        raise ApiError(str(exc), status_code=409, code="postgres_required") from exc
    except LookupError as exc:
        raise ApiError(f"run not found: {run_id}", status_code=404, code="not_found") from exc
    except ValueError as exc:
        raise ApiError(str(exc), status_code=409, code="run_not_empty") from exc
    return DeleteRunResponse(**report)


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


def _job_status(raw: dict) -> RetryGptFailedJobStatus:
    report_raw = raw.get("report")
    report = RetryGptFailedReportView(**report_raw) if report_raw else None
    return RetryGptFailedJobStatus(
        state=raw.get("state", "idle"),
        run_id=raw.get("run_id"),
        started_at=raw.get("started_at"),
        finished_at=raw.get("finished_at"),
        error=raw.get("error"),
        report=report,
    )


@router.get("/{run_id}/gpt-failed", response_model=GptFailedStatusResponse)
async def get_gpt_failed_status(run_id: str, request: Request) -> GptFailedStatusResponse:
    """Pending GPT failed-batch files for a run + latest retry job snapshot."""
    from aipocket.services.retry_gpt_failed import inspect_gpt_failed

    try:
        summary = await asyncio.to_thread(inspect_gpt_failed, run_id)
    except ValueError as e:
        raise ApiError(str(e), status_code=400, code="bad_request") from e
    except FileNotFoundError as e:
        raise ApiError(str(e), status_code=404, code="not_found") from e

    retry_mgr = request.app.state.retry_manager
    job = _job_status(retry_mgr.status())
    # Only expose job detail when it matches this run (or is idle).
    if job.run_id and job.run_id != run_id and job.state != "idle":
        job = RetryGptFailedJobStatus(state="idle")

    return GptFailedStatusResponse(
        run_id=run_id,
        failed_files=len(summary.failed_files),
        failed_hits=summary.failed_hits,
        files=[
            GptFailedFileInfo(name=f.name, hits=f.hits, batch_idx=f.batch_idx)
            for f in summary.failed_files
        ],
        retry=job
        if (job.run_id == run_id or job.state == "idle")
        else RetryGptFailedJobStatus(state="idle"),
    )


@router.post("/{run_id}/retry-gpt-failed", response_model=RetryGptFailedJobStatus)
async def start_retry_gpt_failed(run_id: str, request: Request) -> RetryGptFailedJobStatus:
    """Start a background retry of GPT-failed batches; recovered keys are **appended**.

    Rejects with 409 when:
    - another retry is already running
    - a full scan is currently running
    - there are no pending failed-batch files
    """
    from aipocket.services.retry_gpt_failed import inspect_gpt_failed

    scan_mgr = request.app.state.scan_manager
    if scan_mgr.status().get("state") in ("running", "stopping"):
        raise ApiError(
            "cannot retry while a scan is running",
            status_code=409,
            code="conflict",
        )

    try:
        summary = await asyncio.to_thread(inspect_gpt_failed, run_id)
    except ValueError as e:
        raise ApiError(str(e), status_code=400, code="bad_request") from e
    except FileNotFoundError as e:
        raise ApiError(str(e), status_code=404, code="not_found") from e

    if not summary.has_failures:
        raise ApiError(
            "no gpt_failed_batch_*.jsonl files to retry",
            status_code=404,
            code="not_found",
        )

    retry_mgr = request.app.state.retry_manager
    try:
        raw = retry_mgr.start(run_id)
    except RuntimeError as e:
        raise ApiError(str(e), status_code=409, code="conflict") from e
    return _job_status(raw)
