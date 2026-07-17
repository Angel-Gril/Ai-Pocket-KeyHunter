"""CVE endpoints — read the AI CVE list, sync from Tavily, and manual add."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends

from aipocket.core.config import settings

from ..deps import get_current_user
from ..errors import ApiError
from ..schemas import CveAddRequest, CveAddResponse, CveSyncResponse

router = APIRouter(prefix="/api/cve", tags=["cve"], dependencies=[Depends(get_current_user)])


@router.get("")
async def get_cve() -> dict:
    """Return the current AI advisory list (CVE/GHSA/Huntr/disclosures).

    Response keeps the legacy ``cves`` key for the UI while also returning
    ``advisories`` with the same records for newer clients.
    """
    from aipocket.services.queries import load_cves

    records = await asyncio.to_thread(load_cves)
    return {"cves": records, "advisories": records}


@router.post("/sync", response_model=CveSyncResponse)
async def sync_cve() -> CveSyncResponse:
    """Trigger a Tavily CVE sync (short task, waited on synchronously)."""
    if not settings.tavily_key:
        raise ApiError("TAVILY_KEY not configured", code="bad_request")
    from aipocket.clients.tavily import sync_cves

    merged, added = await sync_cves()
    return CveSyncResponse(total=len(merged), added=added)


@router.post("/add", response_model=CveAddResponse)
async def add_cve(body: CveAddRequest) -> CveAddResponse:
    """Manually add a CVE from a URL and/or form fields.

    Records are persisted via the same merge path as Tavily sync (PG + optional
    JSONL), so they remain after the next 「同步 CVE」.
    """
    from aipocket.services.cve_manual import add_manual_cve

    try:
        record, created, total = await add_manual_cve(
            url=body.url,
            cve_id=body.id,
            product=body.product,
            cve_type=body.type,
            description=body.description,
            cvss=body.cvss,
            huntable=body.huntable,
        )
    except ValueError as exc:
        raise ApiError(str(exc), code="bad_request") from exc

    return CveAddResponse(created=created, total=total, cve=record)
