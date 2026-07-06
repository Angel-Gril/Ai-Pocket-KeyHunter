"""CVE endpoints — read the AI CVE list and trigger a Tavily sync."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends

from ...config import settings
from ..auth import get_current_user
from ..errors import ApiError
from ..schemas import CveSyncResponse

router = APIRouter(prefix="/api/cve", tags=["cve"], dependencies=[Depends(get_current_user)])


@router.get("")
async def get_cve() -> dict:
    """Return the current AI CVE list (sources/cve_2026_ai.json)."""
    from ...queries import load_cves

    return {"cves": await asyncio.to_thread(load_cves)}


@router.post("/sync", response_model=CveSyncResponse)
async def sync_cve() -> CveSyncResponse:
    """Trigger a Tavily CVE sync (short task, waited on synchronously)."""
    if not settings.tavily_key:
        raise ApiError("TAVILY_KEY not configured", code="bad_request")
    from ...tavily_client import sync_cves

    merged, added = await sync_cves()
    return CveSyncResponse(total=len(merged), added=added)
