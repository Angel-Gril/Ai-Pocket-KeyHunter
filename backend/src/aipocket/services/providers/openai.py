from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import httpx
from pydantic import BaseModel, ConfigDict, Field

from aipocket.core.models import Credential

_BASE_URL: Final = "https://api.openai.com/v1"


class OpenAICredentialKind(StrEnum):
    PROJECT = "project"
    SERVICE_ACCOUNT = "service_account"
    ADMIN = "admin"
    ORDINARY = "ordinary"


class InferencePolicy(StrEnum):
    READ_ONLY = "read_only"
    ALLOW_MINIMAL = "allow_minimal"


class TierEvidence(StrEnum):
    TIER5_CONFIRMED = "tier5_confirmed"
    TIER5_CANDIDATE = "tier5_candidate"
    UNKNOWN = "unknown"


class ModelLimit(BaseModel):
    model_config = ConfigDict(frozen=True)

    model: str
    rpm: int | None = None
    tpm: int | None = None


class LimitProfile(BaseModel):
    model_config = ConfigDict(frozen=True)

    models: tuple[ModelLimit, ...] = ()
    tier: TierEvidence = TierEvidence.UNKNOWN
    authoritative: bool = False


class OpenAIValidation(BaseModel):
    model_config = ConfigDict(frozen=True)

    credential_kind: OpenAICredentialKind
    valid: bool
    status_code: int | None = None
    models: tuple[str, ...] = ()
    verified_model: str = ""
    inference_performed: bool = False
    limit_profile: LimitProfile = Field(default_factory=LimitProfile)
    error: str = ""


@dataclass(frozen=True, slots=True)
class _RequestContext:
    headers: dict[str, str]
    project: str


def classify_openai_credential(credential: Credential) -> OpenAICredentialKind | None:
    key = credential.apikey
    match key:
        case value if value.startswith("sk-proj-"):
            return OpenAICredentialKind.PROJECT
        case value if value.startswith("sk-svcacct-"):
            return OpenAICredentialKind.SERVICE_ACCOUNT
        case value if value.startswith("sk-admin-"):
            return OpenAICredentialKind.ADMIN
        case value if value.startswith("sk-"):
            bundle_is_openai = (
                credential.bundle is not None and credential.bundle.provider_hint == "openai"
            )
            endpoint_is_openai = credential.apiurl.rstrip("/").endswith("openai.com/v1")
            return OpenAICredentialKind.ORDINARY if bundle_is_openai or endpoint_is_openai else None
        case _:
            return None


def _request_context(credential: Credential) -> _RequestContext:
    context = credential.bundle.context if credential.bundle is not None else None
    headers = {"Authorization": f"Bearer {credential.apikey}"}
    project = context.project if context is not None else ""
    organization = context.organization if context is not None else ""
    if project:
        headers["OpenAI-Project"] = project
    if organization:
        headers["OpenAI-Organization"] = organization
    return _RequestContext(headers=headers, project=project)


def _header_limit(model: str, response: httpx.Response) -> ModelLimit | None:
    rpm_raw = response.headers.get("x-ratelimit-limit-requests")
    tpm_raw = response.headers.get("x-ratelimit-limit-tokens")
    if rpm_raw is None and tpm_raw is None:
        return None
    try:
        rpm = int(rpm_raw) if rpm_raw is not None else None
        tpm = int(tpm_raw) if tpm_raw is not None else None
    except ValueError:
        return None
    return ModelLimit(model=model, rpm=rpm, tpm=tpm)


def _profile(
    limits: tuple[ModelLimit, ...], *, authoritative: bool, explicit_tier: str = ""
) -> LimitProfile:
    if authoritative and explicit_tier.lower().replace("_", "") == "tier5":
        tier = TierEvidence.TIER5_CONFIRMED
    elif any(limit.rpm is not None or limit.tpm is not None for limit in limits):
        tier = TierEvidence.TIER5_CANDIDATE
    else:
        tier = TierEvidence.UNKNOWN
    return LimitProfile(models=limits, tier=tier, authoritative=authoritative)


async def _validate_admin(
    client: httpx.AsyncClient,
    credential: Credential,
    request: _RequestContext,
) -> OpenAIValidation:
    projects_response = await client.get(
        f"{_BASE_URL}/organization/projects", headers=request.headers
    )
    if projects_response.status_code != 200:
        return OpenAIValidation(
            credential_kind=OpenAICredentialKind.ADMIN,
            valid=False,
            status_code=projects_response.status_code,
            error="admin-projects-read-failed",
        )
    payload = projects_response.json()
    projects = payload.get("data", []) if isinstance(payload, dict) else []
    project_ids = tuple(
        str(item["id"])
        for item in projects
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    limits: list[ModelLimit] = []
    explicit_tier = ""
    for project_id in project_ids:
        response = await client.get(
            f"{_BASE_URL}/organization/projects/{project_id}/rate_limits",
            headers=request.headers,
        )
        if response.status_code != 200:
            continue
        body = response.json()
        if not isinstance(body, dict):
            continue
        explicit_tier = str(body.get("account_tier", explicit_tier))
        data = body.get("data", [])
        if isinstance(data, list):
            limits.extend(
                ModelLimit(
                    model=str(item.get("model", "")),
                    rpm=item.get("max_requests_per_1_minute"),
                    tpm=item.get("max_tokens_per_1_minute"),
                )
                for item in data
                if isinstance(item, dict) and item.get("model")
            )
    return OpenAIValidation(
        credential_kind=OpenAICredentialKind.ADMIN,
        valid=True,
        status_code=projects_response.status_code,
        limit_profile=_profile(tuple(limits), authoritative=True, explicit_tier=explicit_tier),
    )


async def validate_openai(
    client: httpx.AsyncClient,
    credential: Credential,
    policy: InferencePolicy = InferencePolicy.READ_ONLY,
) -> OpenAIValidation:
    kind = classify_openai_credential(credential)
    if kind is None:
        return OpenAIValidation(
            credential_kind=OpenAICredentialKind.ORDINARY,
            valid=False,
            error="not-openai-credential",
        )
    request = _request_context(credential)
    if kind is OpenAICredentialKind.ADMIN:
        return await _validate_admin(client, credential, request)

    models_response = await client.get(f"{_BASE_URL}/models", headers=request.headers)
    if models_response.status_code != 200:
        return OpenAIValidation(
            credential_kind=kind,
            valid=False,
            status_code=models_response.status_code,
            error="models-read-failed",
        )
    body = models_response.json()
    data = body.get("data", []) if isinstance(body, dict) else []
    models = tuple(
        str(item["id"])
        for item in data
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    model = models[0] if models else ""
    header_limit = _header_limit(model, models_response)
    limits = (header_limit,) if header_limit is not None else ()
    if policy is InferencePolicy.READ_ONLY or not model:
        return OpenAIValidation(
            credential_kind=kind,
            valid=True,
            status_code=models_response.status_code,
            models=models,
            limit_profile=_profile(limits, authoritative=False),
        )

    inference_response = await client.post(
        f"{_BASE_URL}/responses",
        headers=request.headers,
        json={"model": model, "input": "ping", "max_output_tokens": 1},
    )
    inference_limit = _header_limit(model, inference_response)
    inference_limits = (inference_limit,) if inference_limit is not None else limits
    return OpenAIValidation(
        credential_kind=kind,
        valid=inference_response.status_code == 200,
        status_code=inference_response.status_code,
        models=models,
        verified_model=model if inference_response.status_code == 200 else "",
        inference_performed=True,
        limit_profile=_profile(inference_limits, authoritative=False),
        error="" if inference_response.status_code == 200 else "inference-failed",
    )
