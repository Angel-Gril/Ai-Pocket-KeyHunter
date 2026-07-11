from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlencode, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict

from aipocket.core.models import Credential


class AzureAuthKind(StrEnum):
    API_KEY = "api_key"
    ENTRA_BEARER = "entra_bearer"


class AzureInferencePolicy(StrEnum):
    READ_ONLY = "read_only"
    ALLOW_MINIMAL = "allow_minimal"


class AzureOpenAIValidation(BaseModel):
    model_config = ConfigDict(frozen=True)

    auth_kind: AzureAuthKind
    valid: bool
    status_code: int | None = None
    models: tuple[str, ...] = ()
    inference_performed: bool = False
    error: str = ""


def _is_azure_endpoint(endpoint: str) -> bool:
    host = (urlsplit(endpoint).hostname or "").lower().rstrip(".")
    return host.endswith(".openai.azure.com")


def classify_azure_openai_credential(credential: Credential) -> AzureAuthKind | None:
    bundle = credential.bundle
    endpoint_bound = _is_azure_endpoint(credential.apiurl) and (
        bundle is None
        or bundle.provider_hint == "azure_openai"
        or credential.apiurl in bundle.endpoint_candidates
    )
    if not endpoint_bound or credential.apikey.startswith("sk-"):
        return None
    if bundle is not None and bundle.credential_kind == "token":
        return AzureAuthKind.ENTRA_BEARER
    if len(credential.apikey) == 32:
        return AzureAuthKind.API_KEY
    return None


def _request_url(credential: Credential, operation: str) -> str:
    endpoint = credential.apiurl.rstrip("/")
    context = credential.bundle.context if credential.bundle is not None else None
    if endpoint.endswith("/openai/v1"):
        return f"{endpoint}/{operation}"
    deployment = context.deployment if context is not None else ""
    api_version = context.api_version if context is not None else ""
    path = f"{endpoint}/openai/deployments/{deployment}/{operation}"
    return f"{path}?{urlencode({'api-version': api_version})}"


def _headers(credential: Credential, kind: AzureAuthKind) -> dict[str, str]:
    if kind is AzureAuthKind.ENTRA_BEARER:
        return {"Authorization": f"Bearer {credential.apikey}"}
    return {"api-key": credential.apikey}


async def validate_azure_openai(
    client: httpx.AsyncClient,
    credential: Credential,
    policy: AzureInferencePolicy = AzureInferencePolicy.READ_ONLY,
) -> AzureOpenAIValidation:
    if not credential.apiurl or not _is_azure_endpoint(credential.apiurl):
        return AzureOpenAIValidation(
            auth_kind=AzureAuthKind.API_KEY,
            valid=False,
            error="missing-azure-endpoint",
        )
    if credential.apikey.startswith("sk-"):
        return AzureOpenAIValidation(
            auth_kind=AzureAuthKind.API_KEY,
            valid=False,
            error="public-openai-conflict",
        )
    kind = classify_azure_openai_credential(credential)
    if kind is None:
        return AzureOpenAIValidation(
            auth_kind=AzureAuthKind.API_KEY,
            valid=False,
            error="not-azure-openai-credential",
        )
    context = credential.bundle.context if credential.bundle is not None else None
    is_v1 = credential.apiurl.rstrip("/").endswith("/openai/v1")
    if not is_v1 and (context is None or not context.deployment or not context.api_version):
        return AzureOpenAIValidation(
            auth_kind=kind,
            valid=False,
            error="missing-legacy-azure-context",
        )

    headers = _headers(credential, kind)
    response = await client.get(_request_url(credential, "models"), headers=headers)
    if response.status_code != 200:
        return AzureOpenAIValidation(
            auth_kind=kind,
            valid=False,
            status_code=response.status_code,
            error="models-read-failed",
        )
    payload = response.json()
    data = payload.get("data", []) if isinstance(payload, dict) else []
    models = tuple(
        str(item["id"])
        for item in data
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    if policy is AzureInferencePolicy.READ_ONLY or not models:
        return AzureOpenAIValidation(
            auth_kind=kind,
            valid=True,
            status_code=response.status_code,
            models=models,
        )

    inference_url = _request_url(credential, "responses")
    inference = await client.post(
        inference_url,
        headers=headers,
        json={"model": models[0], "input": "ping", "max_output_tokens": 1},
    )
    return AzureOpenAIValidation(
        auth_kind=kind,
        valid=inference.status_code == 200,
        status_code=inference.status_code,
        models=models,
        inference_performed=True,
        error="" if inference.status_code == 200 else "inference-failed",
    )
