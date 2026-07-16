from __future__ import annotations

import httpx
import pytest
import respx

from aipocket.core.credentials import CredentialBundle, CredentialContext
from aipocket.core.models import Credential
from aipocket.services.balance import query_balance
from aipocket.services.providers.openai import (
    InferencePolicy,
    OpenAICredentialKind,
    OpenAIValidation,
    TierEvidence,
    classify_openai_credential,
    validate_openai,
)
from aipocket.services.validator import _probe

BASE = "https://api.openai.com/v1"


def _credential(key: str, *, organization: str = "", project: str = "") -> Credential:
    bundle = CredentialBundle.create(
        key,
        provider_hint="openai",
        endpoint_candidates=(BASE,),
        context=CredentialContext(organization=organization, project=project),
    )
    return Credential(apikey=key, apiurl=BASE, bundle=bundle)


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("sk-proj-" + "a" * 40, OpenAICredentialKind.PROJECT),
        ("sk-svcacct-" + "a" * 40, OpenAICredentialKind.SERVICE_ACCOUNT),
        ("sk-admin-" + "a" * 40, OpenAICredentialKind.ADMIN),
        ("sk-" + "a" * 48, OpenAICredentialKind.ORDINARY),
    ],
)
def test_classifies_openai_key_kinds_without_treating_every_sk_key_as_openai(
    key: str,
    expected: OpenAICredentialKind,
) -> None:
    assert classify_openai_credential(_credential(key)) is expected


def test_ordinary_key_requires_bundle_or_openai_endpoint_evidence() -> None:
    credential = Credential(apikey="sk-" + "a" * 48, apiurl="https://gateway.example/v1")

    assert classify_openai_credential(credential) is None


@respx.mock
async def test_project_key_uses_models_first_and_does_not_spend_by_default() -> None:
    models = respx.get(f"{BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-5"}]})
    )

    async with httpx.AsyncClient() as client:
        result = await validate_openai(
            client,
            _credential("sk-proj-" + "a" * 40, project="proj_123"),
            InferencePolicy.READ_ONLY,
        )

    assert result.valid is True
    assert result.models == ("gpt-5",)
    assert result.inference_performed is False
    assert models.called
    assert [call.request.method for call in respx.calls] == ["GET"]


@respx.mock
async def test_service_account_can_make_inference_only_with_explicit_policy() -> None:
    respx.get(f"{BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-5"}]})
    )
    inference = respx.post(f"{BASE}/responses").mock(
        return_value=httpx.Response(
            200,
            json={"id": "resp_123", "model": "gpt-5"},
            headers={
                "x-ratelimit-limit-requests": "10000",
                "x-ratelimit-limit-tokens": "2000000",
            },
        )
    )

    async with httpx.AsyncClient() as client:
        result = await validate_openai(
            client,
            _credential("sk-svcacct-" + "a" * 40, project="proj_123"),
            InferencePolicy.ALLOW_MINIMAL,
        )

    assert result.valid is True
    assert result.inference_performed is True
    assert inference.called
    assert result.limit_profile.models[0].model == "gpt-5"
    assert result.limit_profile.models[0].rpm == 10000
    assert result.limit_profile.models[0].tpm == 2000000
    assert result.limit_profile.tier is TierEvidence.TIER5_CANDIDATE


@respx.mock
async def test_single_rpm_header_never_confirms_tier_five() -> None:
    respx.get(f"{BASE}/models").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": "gpt-5"}]},
            headers={"x-ratelimit-limit-requests": "10000"},
        )
    )

    async with httpx.AsyncClient() as client:
        result = await validate_openai(
            client,
            _credential("sk-proj-" + "a" * 40),
            InferencePolicy.READ_ONLY,
        )

    assert result.limit_profile.tier is TierEvidence.TIER5_CANDIDATE
    assert result.limit_profile.tier is not TierEvidence.TIER5_CONFIRMED


@respx.mock
async def test_admin_key_uses_only_read_only_org_project_and_rate_limit_endpoints() -> None:
    respx.get(f"{BASE}/organization/projects").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "proj_123"}]})
    )
    respx.get(f"{BASE}/organization/projects/proj_123/rate_limits").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "model": "gpt-5",
                        "max_requests_per_1_minute": 10000,
                        "max_tokens_per_1_minute": 2000000,
                    }
                ],
                "account_tier": "tier_5",
            },
        )
    )

    async with httpx.AsyncClient() as client:
        result = await validate_openai(
            client,
            _credential("sk-admin-" + "a" * 40, organization="org_123"),
            InferencePolicy.ALLOW_MINIMAL,
        )

    assert isinstance(result, OpenAIValidation)
    assert result.valid is True
    assert result.limit_profile.tier is TierEvidence.TIER5_CONFIRMED
    assert result.limit_profile.models[0].rpm == 10000
    assert result.inference_performed is False
    assert [call.request.method for call in respx.calls] == ["GET", "GET"]
    assert all("users" not in str(call.request.url) for call in respx.calls)
    assert all("api_keys" not in str(call.request.url) for call in respx.calls)


@respx.mock
async def test_validator_dispatches_structured_openai_bundle_to_read_only_adapter() -> None:
    respx.get(f"{BASE}/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "gpt-5"}]})
    )

    async with httpx.AsyncClient() as client:
        result = await _probe(client, _credential("sk-proj-" + "a" * 40))

    assert result.valid is True
    assert result.tier == TierEvidence.UNKNOWN.value
    assert result.provider_info.models_available == ["gpt-5"]
    assert [call.request.method for call in respx.calls] == ["GET"]


@respx.mock
async def test_balance_dispatch_returns_credit_grants_when_available() -> None:
    respx.get("https://api.openai.com/dashboard/billing/credit_grants").mock(
        return_value=httpx.Response(
            200,
            json={
                "object": "credit_summary",
                "total_granted": 18.0,
                "total_used": 3.5,
                "total_available": 14.5,
                "grants": {
                    "object": "list",
                    "data": [
                        {
                            "object": "credit_grant",
                            "grant_amount": 18.0,
                            "used_amount": 3.5,
                        }
                    ],
                },
            },
        )
    )

    async with httpx.AsyncClient() as client:
        result = await query_balance(client, _credential("sk-proj-" + "a" * 40))

    assert result["gateway"] == "openai"
    assert result["balance_usd"] == 14.5
    assert result["source"] == "credit_grants"
    assert result["alive"] is True


@respx.mock
async def test_balance_dispatch_returns_na_and_tier_when_billing_gated() -> None:
    """Dashboard billing often rejects API keys; still resolve alive key + tier."""
    respx.get("https://api.openai.com/dashboard/billing/credit_grants").mock(
        return_value=httpx.Response(401, json={"error": {"message": "Unauthorized"}})
    )
    respx.get("https://api.openai.com/v1/dashboard/billing/credit_grants").mock(
        return_value=httpx.Response(401, json={"error": {"message": "Unauthorized"}})
    )
    respx.get("https://api.openai.com/dashboard/billing/subscription").mock(
        return_value=httpx.Response(401, json={"error": {"message": "Unauthorized"}})
    )
    respx.get("https://api.openai.com/v1/dashboard/billing/subscription").mock(
        return_value=httpx.Response(401, json={"error": {"message": "Unauthorized"}})
    )
    respx.get(f"{BASE}/models").mock(
        return_value=httpx.Response(
            200,
            json={"data": [{"id": "gpt-5"}, {"id": "gpt-4o-mini"}]},
            headers={
                "x-ratelimit-limit-requests": "10000",
                "x-ratelimit-limit-tokens": "30000000",
            },
        )
    )

    async with httpx.AsyncClient() as client:
        result = await query_balance(client, _credential("sk-proj-" + "a" * 40))

    assert result["gateway"] == "openai"
    assert result["balance_usd"] == "N/A"
    assert result["source"] == "api_key_no_balance"
    assert result["alive"] is True
    assert result["tier"] == "tier5_candidate"
    assert result["model_count"] == 2


@respx.mock
async def test_balance_openai_prefix_forces_official_host() -> None:
    grants = respx.get("https://api.openai.com/dashboard/billing/credit_grants").mock(
        return_value=httpx.Response(
            200,
            json={"object": "credit_summary", "total_available": 2.25},
        )
    )
    respx.get("https://evil-proxy.example/dashboard/billing/credit_grants").mock(
        return_value=httpx.Response(200, json={"total_available": 999})
    )

    cred = Credential(
        apikey="sk-proj-" + "b" * 40,
        apiurl="https://evil-proxy.example/v1",
    )
    async with httpx.AsyncClient() as client:
        result = await query_balance(client, cred)

    assert result["gateway"] == "openai"
    assert result["balance_usd"] == 2.25
    assert grants.called
