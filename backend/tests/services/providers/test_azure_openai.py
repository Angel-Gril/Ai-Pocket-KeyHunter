from __future__ import annotations

import httpx
import pytest
import respx

from aipocket.core.credentials import CredentialBundle, CredentialContext, CredentialKind
from aipocket.core.models import Credential
from aipocket.services.providers.azure_openai import (
    AzureAuthKind,
    AzureInferencePolicy,
    classify_azure_openai_credential,
    validate_azure_openai,
)
from aipocket.services.providers.registry import (
    resolve_provider,
    uses_azure_openai_adapter,
    uses_openai_adapter,
)
from aipocket.services.validator import _forged_key_probe, _probe

KEY = "0123456789abcdef0123456789abcdef"
RESOURCE = "https://sample.openai.azure.com"


def _credential(
    secret: str = KEY,
    *,
    endpoint: str = RESOURCE,
    deployment: str = "",
    api_version: str = "",
    credential_kind: CredentialKind = "api_key",
) -> Credential:
    bundle = CredentialBundle.create(
        secret,
        credential_kind=credential_kind,
        provider_hint="azure_openai",
        endpoint_candidates=(endpoint,) if endpoint else (),
        context=CredentialContext(
            azure_resource="sample" if endpoint else "",
            deployment=deployment,
            api_version=api_version,
        ),
    )
    return Credential(apikey=secret, apiurl=endpoint, bundle=bundle)


def test_opaque_resource_key_requires_bound_azure_endpoint() -> None:
    assert classify_azure_openai_credential(_credential()) is AzureAuthKind.API_KEY
    assert classify_azure_openai_credential(_credential(endpoint="")) is None


def test_registry_classifies_azure_endpoint_and_public_openai_conflict() -> None:
    azure = resolve_provider(apiurl=f"{RESOURCE}/openai/v1", apikey=KEY)
    conflict = resolve_provider(apiurl=f"{RESOURCE}/openai/v1", apikey="sk-proj-" + "a" * 40)

    assert azure.provider == "azure_openai"
    assert conflict.provider == "ambiguous"
    assert conflict.reason == "provider-conflict"
    assert uses_openai_adapter(apiurl=f"{RESOURCE}/openai/v1", apikey=KEY) is False
    assert uses_azure_openai_adapter(apiurl=f"{RESOURCE}/openai/v1", apikey=KEY) is True


@respx.mock
async def test_v1_key_auth_preserves_path_and_reads_models_without_spending() -> None:
    route = respx.get(f"{RESOURCE}/openai/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-4o"}]})
    )

    async with httpx.AsyncClient() as client:
        result = await validate_azure_openai(
            client,
            _credential(endpoint=f"{RESOURCE}/openai/v1"),
        )

    assert result.valid is True
    assert result.models == ("gpt-4o",)
    assert result.inference_performed is False
    assert route.calls[0].request.headers["api-key"] == KEY
    assert "authorization" not in route.calls[0].request.headers
    assert [call.request.method for call in respx.calls] == ["GET"]


@respx.mock
async def test_legacy_deployment_preserves_path_version_and_api_key_header() -> None:
    url = f"{RESOURCE}/openai/deployments/chat/models?api-version=2024-10-21"
    route = respx.get(url).mock(
        return_value=httpx.Response(200, json={"data": [{"id": "chat"}]})
    )

    async with httpx.AsyncClient() as client:
        result = await validate_azure_openai(
            client,
            _credential(
                deployment="chat",
                api_version="2024-10-21",
            ),
        )

    assert result.valid is True
    assert route.calls[0].request.headers["api-key"] == KEY


@respx.mock
async def test_entra_token_uses_bearer_auth() -> None:
    token = "entra-token-value-abcdefghijklmnopqrstuvwxyz"
    route = respx.get(f"{RESOURCE}/openai/v1/models").mock(
        return_value=httpx.Response(200, json={"data": []})
    )

    async with httpx.AsyncClient() as client:
        result = await validate_azure_openai(
            client,
            _credential(
                token,
                endpoint=f"{RESOURCE}/openai/v1",
                credential_kind="token",
            ),
        )

    assert result.valid is True
    assert route.calls[0].request.headers["authorization"] == f"Bearer {token}"
    assert "api-key" not in route.calls[0].request.headers


@respx.mock
async def test_inference_requires_explicit_policy() -> None:
    respx.get(f"{RESOURCE}/openai/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-4o"}]})
    )
    inference = respx.post(f"{RESOURCE}/openai/v1/responses").mock(
        return_value=httpx.Response(200, json={"id": "response"})
    )

    async with httpx.AsyncClient() as client:
        result = await validate_azure_openai(
            client,
            _credential(endpoint=f"{RESOURCE}/openai/v1"),
            AzureInferencePolicy.ALLOW_MINIMAL,
        )

    assert result.valid is True
    assert result.inference_performed is True
    assert inference.called


@respx.mock
async def test_validator_dispatches_azure_bundle_to_read_only_adapter() -> None:
    respx.get(f"{RESOURCE}/openai/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-4o"}]})
    )

    async with httpx.AsyncClient() as client:
        result = await _probe(
            client,
            _credential(endpoint=f"{RESOURCE}/openai/v1"),
        )

    assert result.valid is True
    assert result.provider_info.provider == "azure_openai"
    assert result.provider_info.models_available == ["gpt-4o"]
    assert [call.request.method for call in respx.calls] == ["GET"]


@respx.mock
async def test_forged_probe_uses_azure_key_header_and_preserves_v1_path() -> None:
    route = respx.post(f"{RESOURCE}/openai/v1/responses").mock(
        return_value=httpx.Response(401)
    )

    async with httpx.AsyncClient() as client:
        verdict = await _forged_key_probe(
            client,
            f"{RESOURCE}/openai/v1/responses",
            "gpt-4o",
            provider="azure_openai",
        )

    assert verdict == ""
    assert route.calls[0].request.headers["api-key"] == "0" * 32
    assert "authorization" not in route.calls[0].request.headers


@pytest.mark.parametrize(
    ("credential", "error"),
    [
        (_credential(endpoint=""), "missing-azure-endpoint"),
        (
            _credential("sk-proj-" + "a" * 40, endpoint=f"{RESOURCE}/openai/v1"),
            "public-openai-conflict",
        ),
    ],
)
async def test_missing_endpoint_and_public_openai_conflict_are_classified(
    credential: Credential,
    error: str,
) -> None:
    async with httpx.AsyncClient() as client:
        result = await validate_azure_openai(client, credential)

    assert result.valid is False
    assert result.error == error
