"""Single-key test operations over provider-aware validation and evidence probes.

Three INDEPENDENT operations, never chained automatically (the frontend exposes
three separate buttons):

* :func:`list_models` — provider-specific read-only model discovery
* :func:`query_key_balance` — provider-aware balance/quota/identity evidence
* :func:`test_chat` — one minimal chat completion (SPENDS)

Each builds a throwaway :class:`Credential` from the ``{apikey, apiurl}`` a row
in the results list carries.

**test_chat contract** (critical — do not regress):

* ``success`` / ``valid=True`` **only** when the chat/messages endpoint returns
  HTTP **200** with a real completion/message body.
* **401/403** → unauthorized (key dead or forbidden) — never report as 200.
* **429** → rate-limited (key may be real but not usable right now) — never
  report models-list 200 as chat success.
* Official OpenAI/Anthropic adapters used by the scanner are often READ_ONLY
  (models list only). This path **must not** reuse that shortcut.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import httpx

from aipocket.core.config import settings
from aipocket.core.models import Credential, ProviderInfo, ValidationResult
from aipocket.core.validation_state import apply_state
from aipocket.services import validator as _v
from aipocket.services.credential_policy import apply_credential_policy
from aipocket.services.providers import provider_registry, resolve_provider
from aipocket.services.providers.anthropic import validate_anthropic
from aipocket.services.providers.endpoints import build_operation_url, canonicalize_endpoint
from aipocket.services.providers.openai import InferencePolicy, validate_openai

log = logging.getLogger(__name__)


def _client() -> httpx.AsyncClient:
    timeout = httpx.Timeout(settings.validate_timeout)
    return httpx.AsyncClient(timeout=timeout, follow_redirects=True)


def _route_to_official(cred: Credential) -> Credential | None:
    """Mirror scanner routing and the shared pre-request credential policy."""
    key_spec = provider_registry.match_key(cred.apikey)
    if key_spec is not None and key_spec.official_api_url:
        domain_spec = provider_registry.match_domain(cred.apiurl)
        if domain_spec is None:
            cred.leak_host = cred.leak_host or cred.apiurl
            cred.apiurl = key_spec.official_api_url
            cred.routed_to_official = True
    return apply_credential_policy(cred)


async def list_models(apikey: str, apiurl: str) -> list[str]:
    """Fetch the model list for a key via GET /v1/models (best-effort, cheap).

    Gemini/Google keys use the official generativelanguage models endpoint with
    query-param auth — OpenAI-style /v1/models normalization produces a 404 path
    like /v1beta/v1/models and must not be used.
    """
    cred = Credential(apikey=apikey, apiurl=apiurl)
    cred = _route_to_official(cred)
    if cred is None:
        return []
    resolution = resolve_provider(apiurl=cred.apiurl, apikey=apikey)
    async with _client() as client:
        if resolution.provider in {"google", "gemini"} or resolution.protocol_family == "gemini":
            from aipocket.services.providers.gemini import validate_gemini

            validation = await validate_gemini(client, cred)
            return list(validation.models) if validation.valid else []
        endpoint = canonicalize_endpoint(cred.apiurl, provider=resolution.provider)
        chat_url = build_operation_url(endpoint, provider=resolution.provider, operation="chat")
        if not chat_url:
            return []
        return await _v._fetch_models_list(client, cred, chat_url)


async def query_key_balance(apikey: str, apiurl: str) -> dict:
    """Query read-only provider evidence without cross-provider serial probing."""
    from aipocket.services.balance import query_balance
    from aipocket.services.balance_dispatch import apply_probe_result, dispatch_probe

    cred = _route_to_official(Credential(apikey=apikey, apiurl=apiurl))
    if cred is None:
        return {"gateway": "unsupported", "balance_usd": "", "reason": "excluded:google_generative_language"}
    resolution = resolve_provider(apiurl=cred.apiurl, apikey=apikey)
    result = ValidationResult(
        credential=cred,
        validation_state="structurally_valid",
        provider_info=ProviderInfo(
            validation_provider=resolution.provider,
            provider=resolution.provider,
            category=resolution.category,
        ),
    )
    async with _client() as client:
        probe = await dispatch_probe(client, result)
        if probe.matched:
            apply_probe_result(result, probe)
            evidence = dict(result.provider_evidence)
            evidence["gateway"] = probe.provider
            evidence["balance_usd"] = probe.balance_usd
            return evidence
        if resolution.provider in {"unknown", "gateway", "ambiguous"}:
            return await query_balance(client, cred)
    return {"gateway": resolution.provider, "balance_usd": ""}


def _map_adapter_to_result(
    cred: Credential,
    *,
    provider: str,
    category: str,
    valid: bool,
    status_code: int | None,
    error: str,
    models: list[str] | tuple[str, ...] = (),
    verified_model: str = "",
    snippet: str = "",
    inference: bool = False,
) -> ValidationResult:
    """Build a ValidationResult with honest status_code (never invent 200)."""
    result = ValidationResult(
        credential=cred,
        validated_at=datetime.now(UTC).isoformat(),
        status_code=status_code,
        error=error,
        model_available=verified_model,
        response_snippet=snippet,
        provider_info=ProviderInfo(
            provider=provider,  # type: ignore[arg-type]
            category=category,  # type: ignore[arg-type]
            models_available=list(models),
            models_verified=[verified_model] if verified_model else [],
        ),
    )
    apply_state(result, "structurally_valid")
    if valid and inference and verified_model and status_code == 200:
        apply_state(result, "inference_verified")
    elif valid and status_code == 200:
        apply_state(result, "authentication_confirmed")
    elif status_code == 429:
        # Rate-limited: key may be real, but chat is not usable — not success.
        apply_state(result, "rate_limited_unconfirmed")
        result.valid = False  # test_chat must not report success on 429
        result.error = error or "rate_limited"
    else:
        apply_state(result, "auth_rejected")
        result.valid = False
    return result


async def test_chat(apikey: str, apiurl: str, model: str) -> ValidationResult:
    """Send ONE minimal chat/message with the user-selected model. SPENDS credit.

    Official OpenAI / Anthropic keys always hit a real completions/messages call
    with ``model``. Models-list 200 alone is **never** treated as chat success.
    """
    cred = Credential(apikey=apikey, apiurl=apiurl)
    cred = _route_to_official(cred)
    if cred is None:
        result = ValidationResult(
            credential=Credential(apikey=apikey, apiurl=apiurl),
            error="excluded:google_generative_language",
        )
        apply_state(result, "unsupported_context")
        return result
    resolution = resolve_provider(apiurl=cred.apiurl, apikey=apikey)
    log.debug(
        "test_chat provider=%s model=%s",
        resolution.provider,
        model,
    )

    async with _client() as client:
        # --- Official OpenAI: force ALLOW_MINIMAL inference with selected model ---
        if resolution.provider == "openai":
            validation = await validate_openai(
                client,
                cred,
                InferencePolicy.ALLOW_MINIMAL,
                probe_model=model,
            )
            snippet = ""
            success = (
                validation.valid
                and validation.inference_performed
                and validation.status_code == 200
                and bool(validation.verified_model)
            )
            if success:
                snippet = f"model={validation.verified_model}"
            return _map_adapter_to_result(
                cred,
                provider="openai",
                category=resolution.category,
                valid=success,
                status_code=validation.status_code,
                error=validation.error if not success else "",
                models=list(validation.models),
                verified_model=validation.verified_model if success else "",
                snippet=snippet,
                inference=True,
            )

        # --- Official Anthropic: messages with selected model only ---
        if resolution.provider == "anthropic":
            validation = await validate_anthropic(client, cred, probe_model=model)
            # Admin/OAuth keys don't do messages — org scope is not "chat success".
            if validation.credential_kind.value in {"admin", "oauth"}:
                return _map_adapter_to_result(
                    cred,
                    provider="anthropic",
                    category=resolution.category,
                    valid=False,
                    status_code=validation.status_code,
                    error=validation.error or "admin-key-no-chat",
                    models=list(validation.models),
                )
            success = (
                validation.valid
                and validation.status_code == 200
                and bool(validation.verified_model)
            )
            return _map_adapter_to_result(
                cred,
                provider="anthropic",
                category=resolution.category,
                valid=success,
                status_code=validation.status_code,
                error="" if success else (validation.error or "messages-probe-failed"),
                models=list(validation.models),
                verified_model=validation.verified_model if success else "",
                snippet=f"model={validation.verified_model}" if success else "",
                inference=True,
            )

        # --- Azure / Gemini / Vertex / gateways: existing protocol probes ---
        result = ValidationResult(
            credential=cred,
            validated_at=datetime.now(UTC).isoformat(),
            provider_info=ProviderInfo(
                provider=resolution.provider,  # type: ignore[arg-type]
                category=resolution.category,  # type: ignore[arg-type]
            ),
        )
        apply_state(result, "structurally_valid")

        if resolution.provider == "azure_openai":
            from aipocket.services.providers.azure_openai import (
                AzureInferencePolicy,
                validate_azure_openai,
            )

            validation = await validate_azure_openai(
                client,
                cred,
                AzureInferencePolicy.ALLOW_MINIMAL,
            )
            success = (
                validation.valid
                and validation.inference_performed
                and validation.status_code == 200
            )
            return _map_adapter_to_result(
                cred,
                provider="azure_openai",
                category=resolution.category,
                valid=success,
                status_code=validation.status_code,
                error="" if success else (validation.error or "inference-failed"),
                models=list(validation.models),
                verified_model=list(validation.models)[0] if success and validation.models else "",
                inference=True,
            )

        if resolution.provider in {"google", "gemini"}:
            from aipocket.services.providers.gemini import validate_gemini

            validation = await validate_gemini(client, cred)
            # Gemini adapter is models-list based today; surface that honestly —
            # do not claim chat success without generation (status only from adapter).
            return _map_adapter_to_result(
                cred,
                provider=resolution.provider,
                category=resolution.category,
                valid=False,
                status_code=validation.status_code,
                error="gemini-chat-not-implemented-use-models",
                models=list(validation.models),
            )

        endpoint = canonicalize_endpoint(cred.apiurl, provider=resolution.provider)
        chat_url = build_operation_url(endpoint, provider=resolution.provider, operation="chat")
        if not chat_url:
            result.error = "no apiurl"
            apply_state(result, "unsupported_context")
            return result

        # Always probe with the user-selected model only (one spend).
        if resolution.protocol_family == "anthropic" or resolution.provider == "anthropic":
            return await _v._probe_anthropic(client, cred, chat_url, result, [model])
        return await _v._probe_chat_completions(client, cred, chat_url, result, [model])
