"""Settings + connectivity endpoints."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends

from ..deps import get_current_user
from ..schemas import (
    FofaCheckResponse,
    GithubCheckResponse,
    SettingsUpdate,
    SettingsUpdateResponse,
    SettingsView,
    ShodanCheckResponse,
)
from ..settings_io import (
    check_fofa,
    check_github,
    check_shodan,
    current_view,
    update_settings,
)

router = APIRouter(
    prefix="/api/settings", tags=["settings"], dependencies=[Depends(get_current_user)]
)


@router.get("", response_model=SettingsView)
async def get_settings() -> SettingsView:
    """Editable FOFA/Shodan config (sensitive keys masked)."""
    return current_view()


@router.put("", response_model=SettingsUpdateResponse)
async def put_settings(body: SettingsUpdate) -> SettingsUpdateResponse:
    """Write config back to .env and hot-reload the running settings."""
    return update_settings(body)


@router.post("/check/fofa", response_model=FofaCheckResponse)
async def check_fofa_endpoint() -> FofaCheckResponse:
    """FOFA connectivity (three-state). Consumes a tiny amount of quota."""
    # FofaClient is synchronous — run off the event loop.
    return await asyncio.to_thread(check_fofa)


@router.post("/check/shodan", response_model=ShodanCheckResponse)
async def check_shodan_endpoint() -> ShodanCheckResponse:
    """Shodan connectivity + real remaining credits (no quota cost)."""
    return await asyncio.to_thread(check_shodan)


@router.post("/check/github", response_model=GithubCheckResponse)
async def check_github_endpoint() -> GithubCheckResponse:
    """GitHub connectivity via /rate_limit (no search quota)."""
    return await asyncio.to_thread(check_github)
