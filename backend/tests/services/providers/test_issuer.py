"""Unit tests for decide_issuer dual attribution."""

from __future__ import annotations

from aipocket.services.providers.issuer import _is_domain_suffix, decide_issuer

GLM_KEY = "f7638a0d932046079d9900bda54cdde9.79EtThsVS0IEdssm"
GLM_URL = "https://open.bigmodel.cn/api/paas/v4"
GENERIC_SK = "sk-canarygatewaytoken1234567890abcdef"
OPENAI_PROJ = "sk-proj-" + "a" * 40


def test_discovery_hints_alone_leave_issuer_unknown() -> None:
    d = decide_issuer(
        apikey=GLM_KEY,
        apiurl=GLM_URL,
        validation_provider="glm",
        auth_confirmed=False,
        provider_hint="glm",
        variable_names=("GLM_API_KEY",),
        models_available=["glm-5.1"],
    )
    assert d.credential_issuer == "unknown"
    assert d.issuer_evidence == ""
    # Capability may still be derived from models when present
    assert "glm" in d.served_model_families
    assert d.validation_provider == "glm"


def test_exclusive_glm_shape_plus_official_auth() -> None:
    d = decide_issuer(
        apikey=GLM_KEY,
        apiurl=GLM_URL,
        validation_provider="glm",
        auth_confirmed=True,
        models_available=["glm-5.1"],
    )
    assert d.credential_issuer == "glm"
    assert "key_shape" in d.issuer_evidence
    assert "glm" in d.served_model_families


def test_generic_token_official_domain_auth() -> None:
    d = decide_issuer(
        apikey=GENERIC_SK,
        apiurl=GLM_URL,
        validation_provider="glm",
        auth_confirmed=True,
        provider_hint="glm",
        variable_names=("GLM_API_KEY",),
    )
    assert d.credential_issuer == "glm"
    assert "official_domain" in d.issuer_evidence or "validated_endpoint" in d.issuer_evidence


def test_generic_token_gateway_auth() -> None:
    d = decide_issuer(
        apikey=GENERIC_SK,
        apiurl="https://relay.example.com/v1",
        validation_provider="gateway",
        auth_confirmed=True,
        models_available=["glm-5.1", "gpt-4o"],
    )
    assert d.credential_issuer == "gateway"
    assert d.issuer_evidence == "validated_endpoint"
    assert "glm" in d.served_model_families
    assert "openai" in d.served_model_families


def test_model_list_does_not_set_issuer() -> None:
    d = decide_issuer(
        apikey=GENERIC_SK,
        apiurl="https://newapi.example.com/v1",
        validation_provider="gateway",
        auth_confirmed=True,
        models_available=["glm-5.1", "glm-4-flash", "qwen-turbo"],
    )
    assert d.credential_issuer == "gateway"
    assert set(d.served_model_families) >= {"glm", "qwen"}


def test_openai_exclusive_shape() -> None:
    d = decide_issuer(
        apikey=OPENAI_PROJ,
        apiurl="https://api.openai.com/v1",
        validation_provider="openai",
        auth_confirmed=True,
        models_available=["gpt-4o"],
    )
    assert d.credential_issuer == "openai"
    assert "key_shape" in d.issuer_evidence


def test_kimi_official_generic_token() -> None:
    d = decide_issuer(
        apikey=GENERIC_SK,
        apiurl="https://api.moonshot.cn/v1",
        validation_provider="kimi",
        auth_confirmed=True,
        provider_hint="kimi",
        variable_names=("MOONSHOT_API_KEY",),
        models_available=["kimi-k2.5", "moonshot-v1-8k"],
    )
    assert d.credential_issuer == "kimi"
    assert "kimi" in d.served_model_families or "moonshot" in d.served_model_families


def test_auth_rejected_keeps_unknown_issuer() -> None:
    d = decide_issuer(
        apikey=GLM_KEY,
        apiurl=GLM_URL,
        validation_provider="glm",
        auth_confirmed=False,
    )
    assert d.credential_issuer == "unknown"


def test_additional_pack_providers_resolve_and_attribute_official_auth() -> None:
    cases = (
        ("cohere", "https://api.cohere.com/v1", "command-r-plus"),
        ("replicate", "https://api.replicate.com/v1", "replicate/model"),
        ("together", "https://api.together.xyz/v1", "meta-llama/Llama-3.3"),
        (
            "fireworks",
            "https://api.fireworks.ai/inference/v1",
            "accounts/fireworks/models/llama-v3p1",
        ),
    )
    from aipocket.services.providers.registry import resolve_provider

    for provider, url, model in cases:
        resolution = resolve_provider(apiurl=url)
        assert resolution.provider == provider
        decision = decide_issuer(
            apikey="generic-token-12345678901234567890",
            apiurl=url,
            validation_provider=provider,
            auth_confirmed=True,
            provider_hint=provider,
            models_available=[model],
        )
        assert decision.credential_issuer == provider
        assert "validated_endpoint" in decision.issuer_evidence


def test_longcat_requires_exact_api_host() -> None:
    exact = decide_issuer(
        apikey=GENERIC_SK,
        apiurl="https://api.longcat.chat/openai",
        validation_provider="longcat",
        models_available=["LongCat-2.0"],
        auth_confirmed=True,
    )
    assert exact.credential_issuer == "longcat"
    assert _is_domain_suffix("api.longcat.chat", "api.longcat.chat") is True
    assert _is_domain_suffix("longcat.chat", "api.longcat.chat") is False
