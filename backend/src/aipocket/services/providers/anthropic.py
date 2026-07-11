from __future__ import annotations

from enum import StrEnum
from typing import Final

import httpx
from pydantic import BaseModel, ConfigDict

from aipocket.core.models import Credential

_BASE_URL: Final = "https://api.anthropic.com/v1"
_ANTHROPIC_VERSION: Final = "2023-06-01"
_ORG_SCOPE: Final = "org:admin"


class AnthropicCredentialKind(StrEnum):
    API = "api"
    ADMIN = "admin"
    OAUTH = "oauth"


class AnthropicValidation(BaseModel):
    model_config = ConfigDict(frozen=True)

    credential_kind: AnthropicCredentialKind
    valid: bool
    status_code: int | None = None
    models: tuple[str, ...] = ()
    verified_model: str = ""
    organization_id: str = ""
    workspace: str = ""
    scope: str = ""
    error: str = ""


def classify_anthropic_credential(credential: Credential) -> AnthropicCredentialKind | None:
    key = credential.apikey
    if key.startswith("sk-ant-admin"):
        return AnthropicCredentialKind.ADMIN
    if key.startswith("sk-ant-oat") or key.startswith("sk-ant-sid"):
        return AnthropicCredentialKind.OAUTH
    if key.startswith("sk-ant-api") or key.startswith("sk-ant-"):
        bundle_is_anthropic = (
            credential.bundle is not None and credential.bundle.provider_hint == "anthropic"
        )
        endpoint_is_anthropic = "anthropic.com" in credential.apiurl.lower()
        if bundle_is_anthropic or endpoint_is_anthropic or key.startswith("sk-ant-api"):
            return AnthropicCredentialKind.API
        return None
    return None


def _base_headers(credential: Credential, kind: AnthropicCredentialKind) -> dict[str, str]:
    headers = {
        "anthropic-version": _ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }
    if kind is AnthropicCredentialKind.OAUTH:
        headers["Authorization"] = f"Bearer {credential.apikey}"
    else:
        headers["x-api-key"] = credential.apikey
    return headers


def _parse_org(payload: object) -> tuple[str, str]:
    if not isinstance(payload, dict):
        return "", ""
    org_id = str(payload.get("id") or payload.get("organization_id") or "")
    # Never capture member/key listings — only stable org identity fields.
    name = str(payload.get("name") or "")
    return org_id, name


async def _validate_org_scope(
    client: httpx.AsyncClient,
    credential: Credential,
    kind: AnthropicCredentialKind,
) -> AnthropicValidation:
    headers = _base_headers(credential, kind)
    response = await client.get(f"{_BASE_URL}/organizations/me", headers=headers)
    if response.status_code != 200:
        return AnthropicValidation(
            credential_kind=kind,
            valid=False,
            status_code=response.status_code,
            error="org-scope-read-failed",
        )
    org_id, _name = _parse_org(response.json())
    context = credential.bundle.context if credential.bundle is not None else None
    workspace = context.workspace if context is not None else ""
    return AnthropicValidation(
        credential_kind=kind,
        valid=True,
        status_code=response.status_code,
        organization_id=org_id,
        workspace=workspace,
        scope=_ORG_SCOPE,
    )


async def _validate_api_key(
    client: httpx.AsyncClient,
    credential: Credential,
) -> AnthropicValidation:
    headers = _base_headers(credential, AnthropicCredentialKind.API)
    models_response = await client.get(f"{_BASE_URL}/models", headers=headers)
    models: tuple[str, ...] = ()
    if models_response.status_code == 200:
        body = models_response.json()
        data = body.get("data", []) if isinstance(body, dict) else []
        models = tuple(
            str(item["id"])
            for item in data
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        )
    elif models_response.status_code in (401, 403):
        return AnthropicValidation(
            credential_kind=AnthropicCredentialKind.API,
            valid=False,
            status_code=models_response.status_code,
            error="unauthorized",
        )

    # Prefer listed models; fall back to a stable high-value probe model.
    probe_model = models[0] if models else "claude-sonnet-4-6"
    messages_response = await client.post(
        f"{_BASE_URL}/messages",
        headers=headers,
        json={
            "model": probe_model,
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 5,
        },
    )
    if messages_response.status_code != 200:
        # Models list alone is insufficient proof for ordinary API keys.
        if models and models_response.status_code == 200:
            return AnthropicValidation(
                credential_kind=AnthropicCredentialKind.API,
                valid=True,
                status_code=models_response.status_code,
                models=models,
                error="" if messages_response.status_code in (404, 400) else "messages-probe-failed",
            )
        return AnthropicValidation(
            credential_kind=AnthropicCredentialKind.API,
            valid=False,
            status_code=messages_response.status_code,
            models=models,
            error="messages-probe-failed",
        )

    body = messages_response.json()
    verified = ""
    if isinstance(body, dict) and (
        "content" in body or (body.get("type") == "message" and body.get("id"))
    ):
        verified = str(body.get("model") or probe_model)

    return AnthropicValidation(
        credential_kind=AnthropicCredentialKind.API,
        valid=bool(verified) or bool(models),
        status_code=messages_response.status_code,
        models=models,
        verified_model=verified or (models[0] if models else ""),
    )


async def validate_anthropic(
    client: httpx.AsyncClient,
    credential: Credential,
) -> AnthropicValidation:
    kind = classify_anthropic_credential(credential)
    if kind is None:
        return AnthropicValidation(
            credential_kind=AnthropicCredentialKind.API,
            valid=False,
            error="not-anthropic-credential",
        )
    if kind is AnthropicCredentialKind.ADMIN or kind is AnthropicCredentialKind.OAUTH:
        return await _validate_org_scope(client, credential, kind)
    return await _validate_api_key(client, credential)
