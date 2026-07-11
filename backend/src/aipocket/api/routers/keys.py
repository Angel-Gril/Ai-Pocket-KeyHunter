"""Cross-run key list — all valid / suspicious keys, deduped by apikey."""

from __future__ import annotations

import asyncio
from typing import Literal

from fastapi import APIRouter, Depends

from ..deps import get_current_user
from ..results_reader import load_all_records

router = APIRouter(prefix="/api/keys", tags=["keys"], dependencies=[Depends(get_current_user)])


@router.get("/{kind}")
async def get_all_keys(kind: Literal["valid", "suspicious"]) -> dict:
    """All keys of the given kind across every run (apikeys masked, deduped).

    Dedup is by plaintext apikey, newest run wins. Each row includes
    ``source_run_id`` + ``source_index`` so the client can call ``/key/reveal``
    against the originating run.
    """
    results = await asyncio.to_thread(load_all_records, kind)
    return {"kind": kind, "results": results}
