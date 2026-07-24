"""Manual scan targets — user-supplied relay/gateway URLs for source=manual."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Query

from aipocket.services import manual_target_store

from ..deps import get_current_user
from ..errors import ApiError
from ..schemas import (
    ManualTarget,
    ManualTargetBulkRequest,
    ManualTargetBulkResponse,
    ManualTargetDeleteRequest,
    ManualTargetDeleteResponse,
    ManualTargetListResponse,
)

router = APIRouter(
    prefix="/api/manual-targets",
    tags=["manual-targets"],
    dependencies=[Depends(get_current_user)],
)


def _to_target(row: dict) -> ManualTarget:
    return ManualTarget(
        url=row.get("url") or "",
        host_key=row.get("host_key") or "",
        scheme=row.get("scheme") or "https",
        hostname=row.get("hostname") or "",
        port=int(row.get("port") or 0),
        enabled=bool(row.get("enabled", True)),
        notes=row.get("notes") or "",
        first_seen=row.get("first_seen") or "",
        last_seen=row.get("last_seen") or "",
    )


@router.get("", response_model=ManualTargetListResponse)
async def list_manual_targets(
    enabled_only: bool = Query(False, description="Only return enabled targets"),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
) -> ManualTargetListResponse:
    rows, total = await asyncio.to_thread(
        manual_target_store.list_targets,
        enabled_only=enabled_only,
        limit=limit,
        offset=offset,
    )
    return ManualTargetListResponse(
        results=[_to_target(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=ManualTargetBulkResponse)
async def upsert_manual_targets(body: ManualTargetBulkRequest) -> ManualTargetBulkResponse:
    """Sanitize and persist pasted URLs (append/upsert or full replace)."""
    try:
        if body.replace:
            result = await asyncio.to_thread(
                manual_target_store.replace_targets,
                body.urls,
                notes=body.notes,
            )
        else:
            result = await asyncio.to_thread(
                manual_target_store.add_targets,
                body.urls,
                notes=body.notes,
            )
    except ValueError as e:
        raise ApiError(str(e), status_code=400, code="bad_request") from e
    return ManualTargetBulkResponse(
        added=int(result.get("added") or 0),
        updated=int(result.get("updated") or 0),
        rejected=list(result.get("rejected") or []),
        targets=[_to_target(r) for r in (result.get("targets") or [])],
    )


@router.delete("", response_model=ManualTargetDeleteResponse)
async def delete_manual_target(
    url: str = Query(..., min_length=1, description="Canonical or raw URL to remove"),
) -> ManualTargetDeleteResponse:
    try:
        ok = await asyncio.to_thread(manual_target_store.delete_target, url)
    except ValueError as e:
        raise ApiError(str(e), status_code=400, code="bad_request") from e
    if not ok:
        raise ApiError("target not found", status_code=404, code="not_found")
    return ManualTargetDeleteResponse(deleted=1)


@router.post("/bulk-delete", response_model=ManualTargetDeleteResponse)
async def bulk_delete_manual_targets(
    body: ManualTargetDeleteRequest,
) -> ManualTargetDeleteResponse:
    try:
        n = await asyncio.to_thread(manual_target_store.delete_targets, body.urls)
    except ValueError as e:
        raise ApiError(str(e), status_code=400, code="bad_request") from e
    return ManualTargetDeleteResponse(deleted=n)
