"""Single-key test endpoints (models / balance / chat) + reveal plaintext."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth import get_current_user
from ..errors import ApiError
from ..key_tester import list_models, query_key_balance, test_chat
from ..results_reader import reveal_apikey
from ..schemas import (
    BalanceResponse,
    ChatRequest,
    ChatResponse,
    KeyRef,
    ModelsResponse,
    RevealRequest,
    RevealResponse,
)

router = APIRouter(prefix="/api/key", tags=["key"], dependencies=[Depends(get_current_user)])


@router.post("/models", response_model=ModelsResponse)
async def key_models(body: KeyRef) -> ModelsResponse:
    if not body.apikey:
        raise ApiError("apikey required", code="bad_request")
    models = await list_models(body.apikey, body.apiurl)
    return ModelsResponse(models=models)


@router.post("/balance", response_model=BalanceResponse)
async def key_balance(body: KeyRef) -> BalanceResponse:
    if not body.apikey:
        raise ApiError("apikey required", code="bad_request")
    bal = await query_key_balance(body.apikey, body.apiurl)
    return BalanceResponse(
        gateway=str(bal.get("gateway", "")),
        balance_usd=str(bal.get("balance_usd", "")),
        tier=str(bal.get("tier", "")),
        detail=bal,
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
