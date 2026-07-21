from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import httpx
from pydantic import BaseModel, ConfigDict, Field

from aipocket.core.models import Credential
from aipocket.services.http_transport import is_http_header_value_safe

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
    # Optional context headers must also be ASCII; scraped CJK org/project names
    # otherwise raise UnicodeEncodeError inside httpx header normalization.
    if project and is_http_header_value_safe(project):
        headers["OpenAI-Project"] = project
    if organization and is_http_header_value_safe(organization):
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
            error=_status_error(
                projects_response.status_code, default="admin-projects-read-failed"
            ),
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


def _status_error(status_code: int, *, default: str) -> str:
    """Map HTTP status to a stable error tag (200/401/429 must not be collapsed)."""
    if status_code in (401, 403):
        return "unauthorized"
    if status_code == 429:
        return "rate_limited"
    return default


def _looks_like_openai_completion(body: object) -> bool:
    """True for chat/completions or Responses API success bodies."""
    if not isinstance(body, dict):
        return False
    if isinstance(body.get("choices"), list) and body["choices"]:
        return True
    # Responses API
    resp_id = body.get("id")
    if body.get("object") == "response" or (
        isinstance(resp_id, str) and resp_id.startswith("resp_")
    ):
        return True
    return body.get("output") is not None or body.get("status") in {
        "completed",
        "incomplete",
    }


async def validate_openai(
    client: httpx.AsyncClient,
    credential: Credential,
    policy: InferencePolicy = InferencePolicy.READ_ONLY,
    *,
    probe_model: str = "",
) -> OpenAIValidation:
    """Validate an OpenAI key.

    Status-code contract:

    * **200** on models (READ_ONLY) or on inference (ALLOW_MINIMAL) → valid
    * **401/403** → unauthorized (``valid=False``)
    * **429** → rate-limited (``valid=False`` for spend/chat; distinct from 401)
    * ALLOW_MINIMAL never treats models-list 200 as chat success — only a real
      completion body with status 200 does.
    """
    kind = classify_openai_credential(credential)
    if kind is None:
        return OpenAIValidation(
            credential_kind=OpenAICredentialKind.ORDINARY,
            valid=False,
            error="not-openai-credential",
        )
    if not is_http_header_value_safe(credential.apikey):
        return OpenAIValidation(
            credential_kind=kind,
            valid=False,
            error="non-ascii-apikey",
        )
    request = _request_context(credential)
    if kind is OpenAICredentialKind.ADMIN:
        return await _validate_admin(client, credential, request)

    models_response = await client.get(f"{_BASE_URL}/models", headers=request.headers)
    if models_response.status_code in (401, 403):
        return OpenAIValidation(
            credential_kind=kind,
            valid=False,
            status_code=models_response.status_code,
            error="unauthorized",
        )
    if models_response.status_code == 429:
        return OpenAIValidation(
            credential_kind=kind,
            valid=False,
            status_code=429,
            error="rate_limited",
        )
    if models_response.status_code != 200:
        return OpenAIValidation(
            credential_kind=kind,
            valid=False,
            status_code=models_response.status_code,
            error=_status_error(models_response.status_code, default="models-read-failed"),
        )
    body = models_response.json()
    data = body.get("data", []) if isinstance(body, dict) else []
    models = tuple(
        str(item["id"])
        for item in data
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    model = probe_model or (models[0] if models else "")
    header_limit = _header_limit(model or (models[0] if models else ""), models_response)
    limits = (header_limit,) if header_limit is not None else ()
    if policy is InferencePolicy.READ_ONLY or not model:
        return OpenAIValidation(
            credential_kind=kind,
            valid=True,
            status_code=models_response.status_code,
            models=models,
            limit_profile=_profile(limits, authoritative=False),
        )

    # Prefer chat/completions for explicit model tests (broader key support);
    # fall back to Responses API if completions rejects the model shape.
    inference_response = await client.post(
        f"{_BASE_URL}/chat/completions",
        headers=request.headers,
        json={
            "model": model,
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 5,
            "stream": False,
        },
    )
    # Some org/project keys only expose Responses; retry once if completions 404s.
    if inference_response.status_code == 404:
        inference_response = await client.post(
            f"{_BASE_URL}/responses",
            headers=request.headers,
            json={"model": model, "input": "ping", "max_output_tokens": 1},
        )

    sc = inference_response.status_code
    inference_limit = _header_limit(model, inference_response)
    inference_limits = (inference_limit,) if inference_limit is not None else limits

    if sc in (401, 403):
        return OpenAIValidation(
            credential_kind=kind,
            valid=False,
            status_code=sc,
            models=models,
            inference_performed=True,
            limit_profile=_profile(inference_limits, authoritative=False),
            error="unauthorized",
        )
    if sc == 429:
        return OpenAIValidation(
            credential_kind=kind,
            valid=False,
            status_code=429,
            models=models,
            inference_performed=True,
            limit_profile=_profile(inference_limits, authoritative=False),
            error="rate_limited",
        )
    if sc != 200:
        return OpenAIValidation(
            credential_kind=kind,
            valid=False,
            status_code=sc,
            models=models,
            inference_performed=True,
            limit_profile=_profile(inference_limits, authoritative=False),
            error=_status_error(sc, default="inference-failed"),
        )

    try:
        inf_body = inference_response.json()
    except ValueError:
        inf_body = None
    if not _looks_like_openai_completion(inf_body):
        return OpenAIValidation(
            credential_kind=kind,
            valid=False,
            status_code=200,
            models=models,
            inference_performed=True,
            limit_profile=_profile(inference_limits, authoritative=False),
            error="inference-noncompletion",
        )

    verified = model
    if isinstance(inf_body, dict) and inf_body.get("model"):
        verified = str(inf_body["model"])

    return OpenAIValidation(
        credential_kind=kind,
        valid=True,
        status_code=200,
        models=models,
        verified_model=verified,
        inference_performed=True,
        limit_profile=_profile(inference_limits, authoritative=False),
        error="",
    )
