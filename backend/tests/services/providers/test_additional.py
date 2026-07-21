from __future__ import annotations

import httpx
import pytest
import respx

from aipocket.core.credentials import CredentialBundle
from aipocket.core.models import Credential
from aipocket.services.providers.additional import validate_additional_provider
from aipocket.services.validator import _probe


def _credential(
    provider: str, endpoint: str, key: str = "generic-token-12345678901234567890"
) -> Credential:
    bundle = CredentialBundle.create(
        key,
        provider_hint=provider,
        endpoint_candidates=(endpoint,),
    )
    return Credential(apikey=key, apiurl=endpoint, bundle=bundle)


@pytest.mark.parametrize(
    ("provider", "endpoint", "method", "payload"),
    [
        (
            "cohere",
            "https://api.cohere.com/v1/check-api-key",
            "POST",
            {"valid": True, "organization_id": "org_1"},
        ),
        (
            "replicate",
            "https://api.replicate.com/v1/account",
            "GET",
            {"username": "acct"},
        ),
        (
            "together",
            "https://api.together.ai/v1/models",
            "GET",
            [{"id": "meta-llama/Llama-3.3"}],
        ),
        (
            "fireworks",
            "https://api.fireworks.ai/inference/v1/models",
            "GET",
            {"data": [{"id": "accounts/fireworks/models/llama"}]},
        ),
    ],
)
@respx.mock
async def test_read_only_provider_adapter_confirms_auth(
    provider: str,
    endpoint: str,
    method: str,
    payload: object,
) -> None:
    route = respx.request(method, endpoint).mock(return_value=httpx.Response(200, json=payload))
    base = endpoint.removesuffix("/check-api-key").removesuffix("/account").removesuffix("/models")
    credential = _credential(provider, base)

    async with httpx.AsyncClient() as client:
        result = await validate_additional_provider(client, credential, provider)  # type: ignore[arg-type]

    assert result.valid is True
    assert result.status_code == 200
    assert route.called
    assert route.calls[0].request.headers["authorization"].startswith("Bearer ")


@pytest.mark.parametrize(
    "apikey",
    [
        'authz.split(" ", 1)[1] if authz.lower().startswith("bearer ") else ',
        "geminiKeychain.read() ?? ",
        "sk-中文",
    ],
)
@respx.mock
async def test_additional_provider_rejects_header_unsafe_apikey_without_http(apikey: str) -> None:
    """Production LocalProtocolError / UnicodeEncodeError cases on Together path."""
    credential = _credential("together", "https://api.together.ai/v1", key=apikey)
    async with httpx.AsyncClient() as client:
        result = await validate_additional_provider(client, credential, "together")
    assert result.valid is False
    assert result.error == "header-unsafe-apikey"
    assert len(respx.calls) == 0


@respx.mock
async def test_probe_rejects_header_unsafe_before_together_http() -> None:
    credential = _credential(
        "together",
        "https://api.together.ai/v1",
        key="(ps.ai_api_key if ps and ps.ai_api_key else settings.ai_api_key) or ",
    )
    async with httpx.AsyncClient() as client:
        result = await _probe(client, credential)
    assert result.valid is False
    assert result.error == "header-unsafe-apikey"
    assert result.validation_state == "auth_rejected"
    assert len(respx.calls) == 0


@pytest.mark.parametrize("provider", ["cohere", "replicate", "together", "fireworks"])
@respx.mock
async def test_validator_routes_additional_provider_to_official_adapter(provider: str) -> None:
    endpoints = {
        "cohere": "https://api.cohere.com/v1",
        "replicate": "https://api.replicate.com/v1",
        "together": "https://api.together.ai/v1",
        "fireworks": "https://api.fireworks.ai/inference/v1",
    }
    routes = {
        "cohere": ("POST", "https://api.cohere.com/v1/check-api-key", {"valid": True}),
        "replicate": ("GET", "https://api.replicate.com/v1/account", {"username": "acct"}),
        "together": ("GET", "https://api.together.ai/v1/models", [{"id": "model"}]),
        "fireworks": (
            "GET",
            "https://api.fireworks.ai/inference/v1/models",
            {"data": [{"id": "model"}]},
        ),
    }
    method, url, payload = routes[provider]
    respx.request(method, url).mock(return_value=httpx.Response(200, json=payload))
    credential = _credential(provider, endpoints[provider])

    async with httpx.AsyncClient() as client:
        result = await _probe(client, credential)

    assert result.is_authenticated
    assert result.provider_info.validation_provider == provider
    assert result.provider_info.credential_issuer == provider


@pytest.mark.parametrize(
    ("provider", "method", "endpoint"),
    [
        ("cohere", "POST", "https://api.cohere.com/v1/check-api-key"),
        ("replicate", "GET", "https://api.replicate.com/v1/account"),
        ("together", "GET", "https://api.together.ai/v1/models"),
        ("fireworks", "GET", "https://api.fireworks.ai/inference/v1/models"),
    ],
)
@respx.mock
async def test_read_only_provider_adapter_rejects_invalid_auth(
    provider: str,
    method: str,
    endpoint: str,
) -> None:
    respx.request(method, endpoint).mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    credential = _credential(provider, endpoint.rsplit("/", 1)[0])

    async with httpx.AsyncClient() as client:
        result = await validate_additional_provider(client, credential, provider)  # type: ignore[arg-type]

    assert result.valid is False
    assert result.status_code == 401
    assert result.error == "unauthorized"
