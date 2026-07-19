"""Honeypot site cache CRUD — list / create / update / delete known bad hosts."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Query

from aipocket.services import honeypot_store

from ..deps import get_current_user
from ..errors import ApiError
from ..schemas import (
    HoneypotBulkDeleteRequest,
    HoneypotBulkDeleteResponse,
    HoneypotCreateRequest,
    HoneypotListResponse,
    HoneypotSite,
    HoneypotUpdateRequest,
)

router = APIRouter(
    prefix="/api/honeypot",
    tags=["honeypot"],
    dependencies=[Depends(get_current_user)],
)


def _to_site(row: dict) -> HoneypotSite:
    return HoneypotSite(
        host_key=row.get("host_key") or "",
        host=row.get("host") or row.get("host_key") or "",
        reason=row.get("reason") or "",
        source=row.get("source") or "auto",
        first_seen=row.get("first_seen") or "",
        last_seen=row.get("last_seen") or "",
        hit_count=int(row.get("hit_count") or 1),
        run_id=row.get("run_id") or "",
        notes=row.get("notes") or "",
    )


@router.get("", response_model=HoneypotListResponse)
async def list_honeypots(
    q: str = Query("", description="Search host / reason / notes"),
    source: str = Query("", description="Filter: auto | manual | empty=all"),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
) -> HoneypotListResponse:
    """List known honeypot sites (newest last_seen first)."""
    rows, total = await asyncio.to_thread(
        honeypot_store.list_sites,
        q=q,
        source=source,
        limit=limit,
        offset=offset,
    )
    return HoneypotListResponse(
        results=[_to_site(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=HoneypotSite)
async def create_honeypot(body: HoneypotCreateRequest) -> HoneypotSite:
    """Manually add a honeypot site (skipped by subsequent scans)."""
    try:
        row = await asyncio.to_thread(
            honeypot_store.create_site,
            body.host,
            reason=body.reason,
            notes=body.notes,
        )
    except ValueError as e:
        raise ApiError(str(e), code="bad_request") from e
    return _to_site(row)


@router.patch("", response_model=HoneypotSite)
async def update_honeypot(body: HoneypotUpdateRequest) -> HoneypotSite:
    """Update reason / notes for an existing honeypot site."""
    try:
        row = await asyncio.to_thread(
            honeypot_store.update_site,
            body.host_key,
            reason=body.reason,
            notes=body.notes,
        )
    except KeyError as e:
        raise ApiError("honeypot site not found", status_code=404, code="not_found") from e
    except ValueError as e:
        raise ApiError(str(e), code="bad_request") from e
    return _to_site(row)


@router.delete("")
async def delete_honeypot(
    host_key: str = Query(..., min_length=1, description="Normalized host key to remove"),
) -> dict:
    """Remove one site so subsequent scans will probe it again."""
    ok = await asyncio.to_thread(honeypot_store.delete_site, host_key)
    if not ok:
        raise ApiError("honeypot site not found", status_code=404, code="not_found")
    return {"ok": True, "host_key": host_key}


@router.post("/bulk-delete", response_model=HoneypotBulkDeleteResponse)
async def bulk_delete_honeypots(body: HoneypotBulkDeleteRequest) -> HoneypotBulkDeleteResponse:
    deleted = await asyncio.to_thread(honeypot_store.delete_sites, body.host_keys)
    return HoneypotBulkDeleteResponse(deleted=deleted)
