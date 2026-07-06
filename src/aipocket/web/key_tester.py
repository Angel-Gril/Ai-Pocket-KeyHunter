"""Single-key test operations — thin wrappers over the existing validator/balance.

Three INDEPENDENT operations, never chained automatically (the frontend exposes
three separate buttons):

* :func:`list_models`  — GET /v1/models (cheap)                → validator._fetch_models_list
* :func:`query_key_balance` — balance probes (cheap)           → balance.query_balance
* :func:`test_chat`    — one minimal chat completion (SPENDS)  → validator._probe_chat_completions / _probe_anthropic

Each builds a throwaway :class:`Credential` from the ``{apikey, apiurl}`` a row
in the results list carries. No probing logic is re-implemented here — we call
the same functions the scanner uses so behavior stays identical.
"""

from __future__ import annotations

import logging

import httpx

from .. import validator as _v
from ..config import settings
from ..models import Credential, ProviderInfo, ValidationResult

log = logging.getLogger(__name__)


def _client() -> httpx.AsyncClient:
    timeout = httpx.Timeout(settings.validate_timeout)
    return httpx.AsyncClient(timeout=timeout, follow_redirects=True)


async def list_models(apikey: str, apiurl: str) -> list[str]:
    """Fetch the model list for a key via GET /v1/models (best-effort, cheap)."""
    cred = Credential(apikey=apikey, apiurl=apiurl)
    chat_url = _v._normalize_apiurl(apiurl)
    if not chat_url:
        return []
    async with _client() as client:
        return await _v._fetch_models_list(client, cred, chat_url)


async def query_key_balance(apikey: str, apiurl: str) -> dict:
    """Query balance/credits for a key (cheap; reuses balance.query_balance)."""
    from ..balance import query_balance

    cred = Credential(apikey=apikey, apiurl=apiurl)
    async with _client() as client:
        return await query_balance(client, cred)


async def test_chat(apikey: str, apiurl: str, model: str) -> ValidationResult:
    """Send ONE minimal chat/message with the user-selected model. SPENDS credit.

    Routes to Anthropic's /v1/messages convention for sk-ant / anthropic hosts,
    otherwise OpenAI-style /v1/chat/completions — mirroring _probe()'s routing,
    but with the single, explicitly-chosen model rather than a probe list.
    """
    cred = Credential(apikey=apikey, apiurl=apiurl)
    chat_url = _v._normalize_apiurl(apiurl)
    if not chat_url:
        return ValidationResult(credential=cred, error="no apiurl")

    provider, category, _ = _v._route_provider(cred.apiurl)
    # sk-ant keys are always Anthropic even if the apiurl domain is unknown.
    if cred.apikey.startswith("sk-ant") or provider in _v.ANTHROPIC_PROVIDERS:
        provider = "anthropic"

    result = ValidationResult(
        credential=cred,
        provider_info=ProviderInfo.model_validate({"provider": provider, "category": category}),
    )
    async with _client() as client:
        if provider == "anthropic":
            return await _v._probe_anthropic(client, cred, chat_url, result, [model])
        return await _v._probe_chat_completions(client, cred, chat_url, result, [model])
