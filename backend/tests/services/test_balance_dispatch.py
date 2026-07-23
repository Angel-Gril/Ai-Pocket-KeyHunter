from __future__ import annotations

import httpx
import pytest
import respx

from aipocket.core.models import Credential, ProviderInfo, ValidationResult
from aipocket.services.balance_dispatch import ProbeResult, apply_probe_result, dispatch_probe


def _result(provider: str, apiurl: str) -> ValidationResult:
    return ValidationResult(
        credential=Credential(apikey="sk-test-provider-evidence-123456", apiurl=apiurl),
        valid=True,
        validation_state="authentication_confirmed",
        provider_info=ProviderInfo(
            validation_provider=provider,  # type: ignore[arg-type]
            provider=provider,  # type: ignore[arg-type]
            category="gateway"
            if provider in {"gateway", "newapi", "oneapi", "litellm"}
            else "domestic",
        ),
    )


@respx.mock
async def test_glm_error_body_never_matches_litellm() -> None:
    respx.get("https://open.bigmodel.cn/api/paas/v4/models").mock(
        return_value=httpx.Response(200, json={"code": 500, "success": False})
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("glm", "https://open.bigmodel.cn/api/paas/v4"))
    assert probe.matched is False


@pytest.mark.parametrize(
    "payload",
    [
        {"success": False, "key_info": {"spend": 0, "max_budget": 10}},
        {"code": 500, "success": False},
        {"key_info": {"spend": "0", "max_budget": "10"}},
        {"error": {"message": "boom"}},
    ],
)
@respx.mock
async def test_litellm_requires_successful_budget_schema(payload: dict) -> None:
    base = "https://gateway.example"
    respx.get(f"{base}/api/status").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/api/user/self").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/dashboard/billing/subscription").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/key/info").mock(return_value=httpx.Response(200, json=payload))
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("gateway", f"{base}/v1"))
    assert probe.matched is False


@respx.mock
async def test_newapi_requires_two_independent_signals() -> None:
    base = "https://relay.example"
    respx.get(f"{base}/api/status").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "data": {
                    "quota_per_unit": 500000,
                    "stripe_unit_price": 1,
                    "self_use_mode_enabled": True,
                    "system_name": "NewAPI",
                    "version": "0.8",
                },
            },
        )
    )
    respx.get(f"{base}/api/user/self").mock(
        return_value=httpx.Response(
            200,
            json={"success": True, "data": {"quota": 1000, "used_quota": 100}},
        )
    )
    respx.get(f"{base}/dashboard/billing/subscription").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("gateway", f"{base}/v1"))
    assert probe.matched is True
    assert probe.provider == "newapi"
    assert probe.quota == {"quota": 1000, "used_quota": 100}


@respx.mock
async def test_minimax_quota_is_not_cash_balance() -> None:
    respx.get("https://api.minimax.io/v1/token_plan/remains").mock(
        return_value=httpx.Response(
            200,
            json={"base_resp": {"status_code": 0}, "model_remains": [{"model_name": "M2"}]},
        )
    )
    result = _result("minimax", "https://api.minimax.io/v1")
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, result)
    apply_probe_result(result, probe)
    assert probe.evidence_kind == "quota"
    assert result.balance == ""
    assert result.provider_info.balance_provider == ""


@respx.mock
async def test_ksyun_only_reads_bearer_models_entitlement() -> None:
    route = respx.get("https://kspmas.ksyun.com/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "deepseek-v3"}]})
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("ksyun", "https://kspmas.ksyun.com/v1"))
    assert route.called
    assert probe.evidence_kind == "entitlement"
    assert probe.entitlements == {"models": ["deepseek-v3"]}


@respx.mock
async def test_fireworks_unknown_quota_has_no_fake_tier() -> None:
    respx.get("https://api.fireworks.ai/v1/accounts").mock(
        return_value=httpx.Response(200, json={"accounts": [{"name": "accounts/acme"}]})
    )
    respx.get("https://api.fireworks.ai/v1/accounts/acme").mock(
        return_value=httpx.Response(200, json={"accountType": "STANDARD", "suspendState": "ACTIVE"})
    )
    respx.get("https://api.fireworks.ai/v1/accounts/acme/quotas").mock(
        return_value=httpx.Response(
            200,
            json={"quotas": [{"name": "monthly-spend-usd", "maxValue": 1234, "usage": 50}]},
        )
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(
            client, _result("fireworks", "https://api.fireworks.ai/inference/v1")
        )
    assert probe.matched is True
    assert probe.tier == ""
    assert probe.account_type == "STANDARD"


@pytest.mark.parametrize("code", ["1308", "1310", "1311", "1314", "1321"])
async def test_glm_preserves_only_documented_passive_business_codes(code: str) -> None:
    result = _result("glm", "https://open.bigmodel.cn/api/paas/v4")
    result.error = f'429: {{"error":{{"code":"{code}","message":"reset 2026-07-23T00:00:00Z"}}}}'
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, result)
    assert probe.matched is True
    assert probe.source == "glm:passive_error"
    assert probe.quota == {"business_code": code, "reset_at": "2026-07-23T00:00:00Z"}


@respx.mock
async def test_glm_ignores_undocumented_business_code() -> None:
    result = _result("glm", "https://open.bigmodel.cn/api/paas/v4")
    result.error = '{"error":{"code":"1309","message":"unknown"}}'
    respx.get("https://open.bigmodel.cn/api/paas/v4/models").mock(
        return_value=httpx.Response(400, json={"error": {"code": "1309"}})
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, result)
    assert probe.matched is False


@respx.mock
async def test_gateway_html_and_error_bodies_never_match() -> None:
    base = "https://html.example"
    for path in ("/api/status", "/api/user/self", "/dashboard/billing/subscription", "/key/info"):
        respx.get(f"{base}{path}").mock(
            return_value=httpx.Response(200, text="<html>not an api</html>")
        )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("gateway", f"{base}/v1"))
    assert probe.matched is False


@respx.mock
async def test_newapi_requires_product_status_even_when_self_and_billing_match() -> None:
    base = "https://ambiguous.example"
    respx.get(f"{base}/api/status").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/api/user/self").mock(
        return_value=httpx.Response(
            200, json={"success": True, "data": {"quota": 10, "used_quota": 1}}
        )
    )
    respx.get(f"{base}/dashboard/billing/subscription").mock(
        return_value=httpx.Response(
            200, json={"object": "billing_subscription", "hard_limit_usd": 20}
        )
    )
    respx.get(f"{base}/key/info").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("gateway", f"{base}/v1"))
    assert probe.matched is False


@respx.mock
async def test_newapi_billing_usage_requires_strict_list_schema() -> None:
    base = "https://newapi.example"
    respx.get(f"{base}/api/status").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "data": {
                    "quota_per_unit": 500000,
                    "stripe_unit_price": 1,
                    "self_use_mode_enabled": True,
                    "system_name": "NewAPI",
                    "version": "1.0",
                },
            },
        )
    )
    respx.get(f"{base}/api/user/self").mock(return_value=httpx.Response(401))
    respx.get(f"{base}/dashboard/billing/subscription").mock(
        return_value=httpx.Response(
            200, json={"object": "billing_subscription", "hard_limit_usd": 20}
        )
    )
    usage_route = respx.get(f"{base}/dashboard/billing/usage").mock(
        return_value=httpx.Response(200, json={"object": "list", "total_usage": 250})
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("gateway", f"{base}/v1"))
    assert usage_route.called
    assert probe.provider == "newapi"
    assert probe.quota == {"hard_limit_usd": 20}
    assert probe.usage == {"total_usage": 250, "unit": "cents"}


@respx.mock
async def test_oneapi_requires_status_and_self_signals() -> None:
    base = "https://oneapi.example"
    respx.get(f"{base}/api/status").mock(
        return_value=httpx.Response(
            200,
            json={"success": True, "data": {"system_name": "One API", "version": "0.6"}},
        )
    )
    respx.get(f"{base}/api/user/self").mock(
        return_value=httpx.Response(
            200, json={"success": True, "data": {"quota": 9, "used_quota": 2}}
        )
    )
    respx.get(f"{base}/dashboard/billing/subscription").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("gateway", f"{base}/v1"))
    assert probe.provider == "oneapi"
    assert probe.quota == {"quota": 9, "used_quota": 2}


@respx.mock
async def test_together_identity_keeps_only_observed_rate_limits() -> None:
    route = respx.get("https://api.together.ai/v1/whoami").mock(
        return_value=httpx.Response(
            200,
            json={"id": "user-1", "project_id": "project-1"},
            headers={"x-ratelimit-remaining-requests": "7"},
        )
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("together", "https://api.together.ai/v1"))
    assert route.called
    assert probe.evidence_kind == "quota"
    assert probe.quota == {"rate_limits": {"x-ratelimit-remaining-requests": "7"}}
    assert probe.identity == {"id": "user-1", "project_id": "project-1"}


@respx.mock
async def test_groq_without_headers_does_not_invent_quota_or_plan() -> None:
    respx.get("https://api.groq.com/openai/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "llama-3.3"}]})
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("groq", "https://api.groq.com/openai/v1"))
    assert probe.matched is True
    assert probe.evidence_kind == "liveness"
    assert probe.quota == {}
    assert probe.plan == ""


@respx.mock
async def test_cohere_and_replicate_return_identity_not_plan() -> None:
    respx.post("https://api.cohere.com/v1/check-api-key").mock(
        return_value=httpx.Response(200, json={"valid": True, "organization_id": "org-1"})
    )
    respx.get("https://api.replicate.com/v1/account").mock(
        return_value=httpx.Response(200, json={"type": "organization", "username": "acme"})
    )
    async with httpx.AsyncClient() as client:
        cohere = await dispatch_probe(client, _result("cohere", "https://api.cohere.com/v1"))
        replicate = await dispatch_probe(
            client, _result("replicate", "https://api.replicate.com/v1")
        )
    assert cohere.evidence_kind == "identity"
    assert cohere.identity == {"organization_id": "org-1"}
    assert cohere.plan == ""
    assert replicate.evidence_kind == "identity"
    assert replicate.account_type == "organization"
    assert replicate.plan == ""


async def test_longcat_uses_validated_liveness_and_preserves_depleted_state() -> None:
    result = _result("longcat", "https://api.longcat.chat/openai")
    result.error = "余额不足，请充值"
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, result)
    assert probe.matched is True
    assert probe.balance_native == ""
    assert probe.detail["cash_balance_state"] == "depleted"


@respx.mock
async def test_fireworks_unauthorized_account_list_produces_no_evidence() -> None:
    respx.get("https://api.fireworks.ai/v1/accounts").mock(return_value=httpx.Response(403))
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(
            client, _result("fireworks", "https://api.fireworks.ai/inference/v1")
        )
    assert probe.matched is False


async def test_azure_and_vertex_never_call_management_planes() -> None:
    for provider, endpoint in (
        ("azure_openai", "https://sample.openai.azure.com/openai/v1"),
        ("vertex", "https://aiplatform.googleapis.com/v1"),
    ):
        async with httpx.AsyncClient() as client:
            probe = await dispatch_probe(client, _result(provider, endpoint))
        assert probe.matched is True
        assert probe.evidence_kind == "liveness"


@respx.mock
async def test_deepseek_aggregates_native_cash_balance() -> None:
    respx.get("https://api.deepseek.com/user/balance").mock(
        return_value=httpx.Response(
            200,
            json={
                "balance_infos": [
                    {"currency": "CNY", "total_balance": 1.25},
                    {"currency": "cny", "total_balance": 2.75},
                ]
            },
        )
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("deepseek", "https://api.deepseek.com"))
    assert probe.evidence_kind == "cash_balance"
    assert probe.balance_native == 4.0
    assert probe.currency == "CNY"


@respx.mock
async def test_deepseek_accepts_official_string_total_balance() -> None:
    """Official API types total_balance as string (see DeepSeek docs example)."""
    respx.get("https://api.deepseek.com/user/balance").mock(
        return_value=httpx.Response(
            200,
            json={
                "is_available": True,
                "balance_infos": [
                    {
                        "currency": "CNY",
                        "total_balance": "110.00",
                        "granted_balance": "10.00",
                        "topped_up_balance": "100.00",
                    }
                ],
            },
        )
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("deepseek", "https://api.deepseek.com"))
    assert probe.matched is True
    assert probe.evidence_kind == "cash_balance"
    assert probe.balance_native == 110.0
    assert probe.balance_usd == ""
    assert probe.currency == "CNY"
    assert probe.source == "deepseek:user_balance"


@respx.mock
async def test_deepseek_usd_wallet_sets_balance_usd() -> None:
    respx.get("https://api.deepseek.com/user/balance").mock(
        return_value=httpx.Response(
            200,
            json={
                "is_available": True,
                "balance_infos": [
                    {
                        "currency": "USD",
                        "total_balance": "12.50",
                        "granted_balance": "0.00",
                        "topped_up_balance": "12.50",
                    }
                ],
            },
        )
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("deepseek", "https://api.deepseek.com"))
    assert probe.matched is True
    assert probe.balance_usd == 12.5
    assert probe.balance_native == ""
    assert probe.currency == "USD"


@respx.mock
async def test_kimi_domestic_balance_and_international_liveness_are_separate() -> None:
    respx.get("https://api.moonshot.cn/v1/users/me/balance").mock(
        return_value=httpx.Response(200, json={"data": {"available_balance": 8.5}})
    )
    respx.get("https://api.moonshot.ai/v1/models").mock(
        return_value=httpx.Response(200, json={"data": [{"id": "kimi-k2"}]})
    )
    async with httpx.AsyncClient() as client:
        domestic = await dispatch_probe(client, _result("kimi", "https://api.moonshot.cn/v1"))
        international = await dispatch_probe(client, _result("kimi", "https://api.moonshot.ai/v1"))
    assert domestic.balance_native == 8.5
    assert domestic.evidence_kind == "cash_balance"
    assert international.balance_native == ""
    assert international.evidence_kind == "liveness"


@respx.mock
async def test_models_rate_limit_is_liveness_without_fake_quota() -> None:
    respx.get("https://integrate.api.nvidia.com/v1/models").mock(
        return_value=httpx.Response(429, headers={"x-ratelimit-reset-requests": "2s"})
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(
            client, _result("nvidia", "https://integrate.api.nvidia.com/v1")
        )
    assert probe.matched is True
    assert probe.evidence_kind == "liveness"
    assert probe.quota == {}
    assert probe.detail["rate_limits"] == {"x-ratelimit-reset-requests": "2s"}


@respx.mock
async def test_litellm_valid_budget_schema_returns_quota() -> None:
    base = "https://litellm.example"
    respx.get(f"{base}/api/status").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/api/user/self").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/dashboard/billing/subscription").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/key/info").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "key_info": {"spend": 3, "max_budget": 10, "tier": "team", "models": ["gpt-4o"]},
            },
        )
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("gateway", f"{base}/v1"))
    assert probe.provider == "litellm"
    assert probe.quota == {"spend": 3.0, "max_budget": 10.0, "remaining": 7.0}
    assert probe.tier == "team"
    assert probe.balance_usd == 7.0


@respx.mock
async def test_litellm_info_envelope_null_max_budget_is_unlimited() -> None:
    """Current LiteLLM proxy returns ``info`` (not ``key_info``); null budget = unlimited."""
    base = "https://llm.alem.ai"
    respx.get(f"{base}/api/status").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/api/user/self").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/dashboard/billing/subscription").mock(return_value=httpx.Response(404))
    respx.get(f"{base}/key/info").mock(
        return_value=httpx.Response(
            200,
            json={
                "key": "hashed",
                "info": {
                    "spend": 0.0,
                    "max_budget": None,
                    "models": ["qwen3-6"],
                    "budget_duration": "30d",
                },
            },
        )
    )
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("gateway", f"{base}/v1"))
    assert probe.matched is True
    assert probe.provider == "litellm"
    assert probe.balance_usd == "N/A"
    assert probe.quota.get("unlimited") is True
    assert probe.quota.get("spend") == 0.0
    assert probe.source == "litellm:key_no_limit"


def test_apply_probe_result_updates_cash_balance_and_attribution() -> None:
    result = _result("gateway", "https://relay.example/v1")
    result.provider_info.credential_issuer = "gateway"
    probe = ProbeResult(
        matched=True,
        provider="deepseek",
        source="deepseek:user_balance",
        evidence_kind="cash_balance",
        balance_native=6.5,
        currency="CNY",
        tier="provider-returned-tier",
        alive=True,
    )
    apply_probe_result(result, probe)
    assert result.balance == "¥6.5"
    assert result.tier == "provider-returned-tier"
    assert result.gateway == "deepseek"
    assert result.provider_info.credential_issuer == "deepseek"
    assert result.provider_info.balance_provider == "deepseek"
    assert result.provider_evidence["observed_at"]


async def test_openai_legacy_adapter_maps_typed_evidence(monkeypatch) -> None:
    async def fake_probe(_client, _credential):
        return {
            "balance_usd": 12.5,
            "source": "official",
            "hard_limit_usd": 20,
            "used_usd": 7.5,
            "organization_id": "org-1",
            "alive": True,
        }

    monkeypatch.setattr("aipocket.services.balance._probe_openai", fake_probe)
    async with httpx.AsyncClient() as client:
        probe = await dispatch_probe(client, _result("openai", "https://api.openai.com/v1"))
    assert probe.evidence_kind == "cash_balance"
    assert probe.balance_usd == 12.5
    assert probe.quota == {"hard_limit_usd": 20}
    assert probe.usage == {"used_usd": 7.5}
    assert probe.identity == {"organization_id": "org-1"}
