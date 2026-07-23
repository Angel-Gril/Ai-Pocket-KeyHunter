"""Single-key test endpoints (models / balance / chat) + reveal plaintext."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends

from ..deps import get_current_user
from ..errors import ApiError
from ..key_tester import list_models, query_key_balance, test_chat
from ..results_reader import reveal_apikey
from ..schemas import (
    BalanceRequest,
    BalanceResponse,
    ChatRequest,
    ChatResponse,
    KeyRef,
    ModelsResponse,
    RevealRequest,
    RevealResponse,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/key", tags=["key"], dependencies=[Depends(get_current_user)])


@router.post("/models", response_model=ModelsResponse)
async def key_models(body: KeyRef) -> ModelsResponse:
    if not body.apikey:
        raise ApiError("apikey required", code="bad_request")
    models = await list_models(body.apikey, body.apiurl)
    return ModelsResponse(models=models)


@router.post("/balance", response_model=BalanceResponse)
async def key_balance(body: BalanceRequest) -> BalanceResponse:
    if not body.apikey:
        raise ApiError("apikey required", code="bad_request")
    bal = await query_key_balance(body.apikey, body.apiurl)
    balance_usd = str(bal.get("balance_usd", ""))
    tier = str(bal.get("tier", ""))
    gateway = str(bal.get("gateway", ""))

    persisted = False
    persisted_result_id: int | None = None
    high_value_updated = False
    if body.result_id is not None or body.high_value:
        from aipocket.services.result_operations import update_balance_fields

        # evidence payload is the probe detail itself (same shape as scan enrichment).
        evidence = dict(bal) if isinstance(bal, dict) else {}
        try:
            report = await asyncio.to_thread(
                update_balance_fields,
                apikey=body.apikey,
                balance=balance_usd,
                tier=tier,
                gateway=gateway,
                provider_evidence=evidence or None,
                result_id=body.result_id,
                high_value=body.high_value,
            )
        except RuntimeError as exc:
            raise ApiError(str(exc), status_code=409, code="postgres_required") from exc
        except LookupError as exc:
            raise ApiError(str(exc), status_code=404, code="not_found") from exc
        except ValueError as exc:
            raise ApiError(str(exc), status_code=409, code="conflict") from exc
        except Exception as exc:  # noqa: BLE001 — probe still succeeds; surface persist failure
            log.exception("Failed to persist balance for key …%s", body.apikey[-4:])
            raise ApiError(
                f"balance probe ok but persist failed: {exc}",
                status_code=500,
                code="persist_failed",
            ) from exc
        persisted = bool(report.get("persisted"))
        persisted_result_id = report.get("result_id")
        high_value_updated = bool(report.get("high_value"))

    return BalanceResponse(
        gateway=gateway,
        balance_usd=balance_usd,
        tier=tier,
        detail=bal,
        persisted=persisted,
        result_id=persisted_result_id,
        high_value_updated=high_value_updated,
    )


@router.post("/chat", response_model=ChatResponse)
async def key_chat(body: ChatRequest) -> ChatResponse:
    """Test a chat completion. WARNING: this SPENDS the target key's credit."""
    if not body.apikey:
        raise ApiError("apikey required", code="bad_request")
    if not body.model:
        raise ApiError("model required (pick one from /api/key/models first)", code="bad_request")
    result = await test_chat(body.apikey, body.apiurl, body.model)
    return ChatResponse(
        success=result.valid,
        status_code=result.status_code,
        model=result.model_available or body.model,
        snippet=result.response_snippet,
        error=result.error,
    )


@router.post("/reveal", response_model=RevealResponse)
async def key_reveal(body: RevealRequest) -> RevealResponse:
    """Recover ONE plaintext apikey by re-reading the run file on disk."""
    found = reveal_apikey(
        body.run_id,
        body.kind,
        masked=body.masked,
        apiurl=body.apiurl,
        index=body.index,
    )
    return RevealResponse(apikey=found["apikey"], apiurl=found.get("apiurl", ""))
