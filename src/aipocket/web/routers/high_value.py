"""High-value key endpoint — cross-run accumulated view."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends

from ...high_value_writer import load_all
from ..auth import get_current_user
from ..masking import mask_apikey

router = APIRouter(prefix="/api/high-value", tags=["high-value"], dependencies=[Depends(get_current_user)])


@router.get("")
async def get_high_value() -> dict:
    """All high-value keys accumulated across every run (apikeys masked).

    Reuses :func:`aipocket.high_value_writer.load_all` (append-only log) and
    dedups by apikey keeping the last-written entry.
    """
    entries = await asyncio.to_thread(load_all)
    # Dedup by apikey (last write wins) — the file is append-only.
    by_key: dict[str, dict] = {}
    for e in entries:
        key = e.get("apikey", "")
        if key:
            by_key[key] = e
    masked = []
    for e in by_key.values():
        row = dict(e)
        row["apikey"] = mask_apikey(e.get("apikey", ""))
        masked.append(row)
    # Newest first by saved_at.
    masked.sort(key=lambda r: r.get("saved_at", ""), reverse=True)
    return {"results": masked}
