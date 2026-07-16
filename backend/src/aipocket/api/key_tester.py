"""Single-key test operations — thin wrappers over the existing validator/balance.

Three INDEPENDENT operations, never chained automatically (the frontend exposes
three separate buttons):

* :func:`list_models`  — GET /v1/models (cheap)                → validator._fetch_models_list
* :func:`query_key_balance` — balance probes (cheap)           → balance.query_balance
* :func:`test_chat`    — one minimal chat completion (SPENDS)  → validator._probe

Each builds a throwaway :class:`Credential` from the ``{apikey, apiurl}`` a row
in the results list carries. No probing logic is re-implemented here — we call
the same functions the scanner uses so behavior stays identical.
"""

from __future__ import annotations

import logging

import httpx

from aipocket.core.config import settings
from aipocket.core.models import Credential, ValidationResult
from aipocket.services import validator as _v
from aipocket.services.providers import resolve_provider

log = logging.getLogger(__name__)


def _client() -> httpx.AsyncClient:
    timeout = httpx.Timeout(settings.validate_timeout)
    return httpx.AsyncClient(timeout=timeout, follow_redirects=True)


async def list_models(apikey: str, apiurl: str) -> list[str]:
    """Fetch the model list for a key via GET /v1/models (best-effort, cheap).

    Gemini/Google keys use the official generativelanguage models endpoint with
    query-param auth — OpenAI-style /v1/models normalization produces a 404 path
    like /v1beta/v1/models and must not be used.
    """
    cred = Credential(apikey=apikey, apiurl=apiurl)
    resolution = resolve_provider(apiurl=apiurl, apikey=apikey)
    async with _client() as client:
        if resolution.provider in {"google", "gemini"} or resolution.protocol_family == "gemini":
            from aipocket.services.providers.gemini import validate_gemini

            validation = await validate_gemini(client, cred)
            return list(validation.models) if validation.valid else []
        chat_url = _v._normalize_apiurl(apiurl)
        if not chat_url:
            return []
        return await _v._fetch_models_list(client, cred, chat_url)


async def query_key_balance(apikey: str, apiurl: str) -> dict:
    """Query balance/credits for a key (cheap; reuses balance.query_balance)."""
    from aipocket.services.balance import query_balance

    cred = Credential(apikey=apikey, apiurl=apiurl)
    async with _client() as client:
        return await query_balance(client, cred)


async def test_chat(apikey: str, apiurl: str, model: str) -> ValidationResult:
    """Send ONE minimal chat/message with the user-selected model. SPENDS credit.

    Routes through the provider registry/state machine used by the scanner so
    Anthropic, OpenAI, Azure, and gateway semantics stay consistent.
    """
    cred = Credential(apikey=apikey, apiurl=apiurl)
    resolution = resolve_provider(apiurl=apiurl, apikey=apikey)
    log.debug(
        "test_chat provider=%s model=%s",
        resolution.provider,
        model,
    )
    async with _client() as client:
        # Full probe path — adapters honor inference when the selected model is used
        # by _probe_chat_completions / anthropic messages for gateway hosts.
        result = await _v._probe(client, cred)
        if result.model_available and model and result.model_available != model:
            # Prefer the caller-selected model when the default probe list diverged.
            if resolution.protocol_family == "anthropic" or resolution.provider == "anthropic":
                chat_url = (
                    _v._normalize_apiurl(apiurl) or "https://api.anthropic.com/v1/chat/completions"
                )
                result = await _v._probe_anthropic(client, cred, chat_url, result, [model])
            elif resolution.provider not in {
                "openai",
                "azure_openai",
                "vertex",
                "google",
                "gemini",
            }:
                chat_url = _v._normalize_apiurl(apiurl)
                if chat_url:
                    result = await _v._probe_chat_completions(
                        client, cred, chat_url, result, [model]
                    )
        return result
