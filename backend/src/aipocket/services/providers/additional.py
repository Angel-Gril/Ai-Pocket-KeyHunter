from __future__ import annotations

from typing import Any

import httpx

from aipocket.core.models import Credential, ProviderName
from aipocket.services.http_transport import is_http_header_value_safe

from .base import ReadOnlyProviderValidation

_BASE_URLS: dict[ProviderName, str] = {
    "cohere": "https://api.cohere.com/v1",
    "replicate": "https://api.replicate.com/v1",
    "together": "https://api.together.ai/v1",
    "fireworks": "https://api.fireworks.ai",
}


def _status_error(status_code: int) -> str:
    if status_code in (401, 403):
        return "unauthorized"
    if status_code == 429:
        return "rate_limited"
    return "read-failed"


def _string_values(items: object, *fields: str) -> tuple[str, ...]:
    if not isinstance(items, list):
        return ()
    values: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        value = next((item.get(field) for field in fields if item.get(field)), None)
        if value is not None:
            text = str(value)
            if text not in values:
                values.append(text)
    return tuple(values)


async def validate_additional_provider(
    client: httpx.AsyncClient,
    credential: Credential,
    provider: ProviderName,
) -> ReadOnlyProviderValidation:
    """Validate additional discovery-pack providers using read-only official APIs."""
    if provider not in _BASE_URLS:
        return ReadOnlyProviderValidation(valid=False, error="unsupported-provider")
    if not is_http_header_value_safe(credential.apikey):
        return ReadOnlyProviderValidation(valid=False, error="header-unsafe-apikey")

    headers = {"Authorization": f"Bearer {credential.apikey}"}
    if provider == "cohere":
        response = await client.post(f"{_BASE_URLS[provider]}/check-api-key", headers=headers)
        if response.status_code != 200:
            return ReadOnlyProviderValidation(
                valid=False,
                status_code=response.status_code,
                error=_status_error(response.status_code),
            )
        payload = response.json() if response.content else {}
        if not isinstance(payload, dict) or payload.get("valid") is not True:
            return ReadOnlyProviderValidation(
                valid=False,
                status_code=response.status_code,
                error="invalid-key",
            )
        scope = str(payload.get("organization_id") or "")
        return ReadOnlyProviderValidation(valid=True, status_code=200, scope=scope)

    if provider == "replicate":
        response = await client.get(f"{_BASE_URLS[provider]}/account", headers=headers)
        if response.status_code != 200:
            return ReadOnlyProviderValidation(
                valid=False,
                status_code=response.status_code,
                error=_status_error(response.status_code),
            )
        payload = response.json() if response.content else {}
        scope = str(payload.get("username") or "") if isinstance(payload, dict) else ""
        return ReadOnlyProviderValidation(valid=True, status_code=200, scope=scope)

    if provider == "together":
        response = await client.get(f"{_BASE_URLS[provider]}/models", headers=headers)
        if response.status_code != 200:
            return ReadOnlyProviderValidation(
                valid=False,
                status_code=response.status_code,
                error=_status_error(response.status_code),
            )
        payload: Any = response.json() if response.content else []
        items = (
            payload
            if isinstance(payload, list)
            else payload.get("data", [])
            if isinstance(payload, dict)
            else []
        )
        return ReadOnlyProviderValidation(
            valid=True,
            status_code=200,
            models=_string_values(items, "id", "name"),
        )

    # Fireworks' management API requires an account path for private models.
    # The public inference model-list route is OpenAI-compatible and read-only.
    response = await client.get(
        f"{_BASE_URLS[provider]}/inference/v1/models",
        headers=headers,
    )
    if response.status_code != 200:
        return ReadOnlyProviderValidation(
            valid=False,
            status_code=response.status_code,
            error=_status_error(response.status_code),
        )
    payload = response.json() if response.content else {}
    items = payload.get("data", []) if isinstance(payload, dict) else payload
    return ReadOnlyProviderValidation(
        valid=True,
        status_code=200,
        models=_string_values(items, "id", "name"),
    )
