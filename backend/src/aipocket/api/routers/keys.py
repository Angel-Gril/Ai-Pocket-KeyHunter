"""Cross-run key list — all valid / suspicious keys, deduped by apikey."""

from __future__ import annotations

import asyncio
from typing import Literal

from fastapi import APIRouter, Depends

from ..deps import get_current_user
from ..errors import ApiError
from ..results_reader import load_all_records
from ..schemas import PromoteKeysRequest, PromoteKeysResponse

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

@router.post("/promote", response_model=PromoteKeysResponse)
async def promote_keys(body: PromoteKeysRequest) -> PromoteKeysResponse:
    from aipocket.services.result_operations import promote_results

    try:
        report = await asyncio.to_thread(promote_results, body.result_ids, body.note)
    except RuntimeError as exc:
        raise ApiError(str(exc), status_code=409, code="postgres_required") from exc
    except LookupError as exc:
        raise ApiError(str(exc), status_code=404, code="not_found") from exc
    except ValueError as exc:
        raise ApiError(str(exc), status_code=409, code="conflict") from exc
    return PromoteKeysResponse(**report)
