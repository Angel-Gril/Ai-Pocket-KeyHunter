from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from aipocket.core.models import ProviderInfo
from aipocket.services.providers import (
    ProviderRegistry,
    ProviderSpec,
    provider_registry,
    resolve_provider,
)

EXPECTED_PROVIDERS = {
    "openai",
    "anthropic",
    "deepseek",
    "kimi",
    "glm",
    "qwen",
    "siliconflow",
    "google",
    "cohere",
    "replicate",
    "together",
    "fireworks",
    "groq",
    "openrouter",
    "azure_openai",
    "vertex",
    "gemini",
    "minimax",
    "nvidia",
    "ksyun",
    "longcat",
    "newapi",
    "oneapi",
    "litellm",
    "gateway",
    "ambiguous",
    "unknown",
}

CURRENT_DOMAIN_ROUTES = {
    "https://api.openai.com/v1": (
        "openai",
        ("gpt-5.6-sol", "gpt-5.6", "gpt-5.5", "gpt-5.4", "gpt-4o-mini", "gpt-3.5-turbo"),
    ),
    "https://files.oaiusercontent.com/v1": (
        "openai",
        ("gpt-5.6-sol", "gpt-5.6", "gpt-5.5", "gpt-5.4", "gpt-4o-mini"),
    ),
    "https://api.anthropic.com/v1": (
        "anthropic",
        (
            "claude-fable-5",
            "claude-sonnet-5",
            "claude-sonnet-4-6",
            "claude-opus-4-8",
            "claude-opus-4-7",
            "claude-haiku-4-5-20251001",
        ),
    ),
    "https://api.deepseek.com/v1": (
        "deepseek",
        ("deepseek-v4-pro", "deepseek-v4-flash", "deepseek-chat"),
    ),
    "https://api.moonshot.cn/v1": (
        "kimi",
        ("kimi-k3", "kimi-k2.7-code", "kimi-k2.6", "kimi-k2.5", "moonshot-v1-8k"),
    ),
    "https://api.moonshot.ai/v1": (
        "kimi",
        ("kimi-k3", "kimi-k2.7-code", "kimi-k2.6", "kimi-k2.5", "moonshot-v1-8k"),
    ),
    "https://open.bigmodel.cn/api/paas/v4": (
        "glm",
        ("glm-5.2", "glm-5.1", "glm-5", "glm-4-flash"),
    ),
    "https://api.zhipuai.cn/v4": (
        "glm",
        ("glm-5.2", "glm-5.1", "glm-5", "glm-4-flash"),
    ),
    "https://api.siliconflow.cn/v1": (
        "siliconflow",
        (
            "deepseek-ai/DeepSeek-V4-Pro",
            "deepseek-ai/DeepSeek-V4-Flash",
            "deepseek-ai/DeepSeek-V3",
            "Qwen/Qwen3.5-397B-A17B",
            "Qwen/Qwen3-Max",
            "Qwen/Qwen3-32B",
            "THUDM/GLM-Z1-32B-0414",
            "zai-org/GLM-4.5",
            "moonshotai/Kimi-K2.5",
        ),
    ),
    "https://dashscope.aliyuncs.com/compatible-mode/v1": (
        "qwen",
        ("qwen3.7-max", "qwen3-max", "qwen-turbo"),
    ),
    "https://dashscope-intl.aliyuncs.com/compatible-mode/v1": (
        "qwen",
        ("qwen3.7-max", "qwen3-max", "qwen-turbo"),
    ),
    "https://qianfan.baidu.com/v2": (
        "qwen",
        ("ernie-bot-turbo", "ernie-4.0-8k"),
    ),
    "https://generativelanguage.googleapis.com/v1beta": (
        "google",
        ("gemini-3.5-flash", "gemini-3.1-pro-preview", "gemini-1.5-flash"),
    ),
}

CURRENT_PREFIX_ROUTES = {
    "sk-proj-" + "a" * 32: "openai",
    "sk-admin-" + "a" * 32: "openai",
    "sk-svcacct-" + "a" * 32: "openai",
    "sk-ant-admin-" + "A" * 32: "anthropic",
    "sk-ant-api-" + "A" * 32: "anthropic",
    "sk-ant-oat-" + "A" * 32: "anthropic",
    "sk-ant-sid-" + "A" * 32: "anthropic",
    "AIza" + "A" * 35: "google",
}


def test_registry_contains_complete_provider_vocabulary():
    assert {spec.name for spec in provider_registry.specs()} == EXPECTED_PROVIDERS


def test_every_registered_provider_is_model_representable():
    for spec in provider_registry.specs():
        assert ProviderInfo(provider=spec.name, category=spec.category)


def test_every_spec_has_a_supported_protocol_family():
    supported = {"openai_compatible", "anthropic", "gemini", "vertex"}
    for spec in provider_registry.specs():
        assert spec.protocol_family in supported


def test_specs_and_registry_collection_are_immutable():
    specs = provider_registry.specs()
    assert isinstance(specs, tuple)
    with pytest.raises(FrozenInstanceError):
        specs[0].category = "unknown"  # type: ignore[misc]
    with pytest.raises(TypeError):
        specs[0].default_model_hints[0] = "replacement"  # type: ignore[index]


def test_registry_constructor_normalizes_specs_to_an_immutable_tuple():
    registry = ProviderRegistry(list(provider_registry.specs()))  # type: ignore[arg-type]
    assert isinstance(registry.specs(), tuple)


def test_every_current_domain_route_resolves_through_registry():
    for apiurl, (expected_provider, expected_models) in CURRENT_DOMAIN_ROUTES.items():
        decision = resolve_provider(apiurl=apiurl)
        assert decision.provider == expected_provider
        assert decision.default_model_hints == expected_models


def test_every_current_prefix_route_resolves_through_registry():
    for apikey, expected in CURRENT_PREFIX_ROUTES.items():
        assert resolve_provider(apikey=apikey).provider == expected


def test_groq_domain_resolves_through_registry():
    assert resolve_provider(apiurl="https://api.groq.com/openai/v1").provider == "groq"


def test_openrouter_key_resolves_through_registry():
    apikey = "sk-or-v1-" + "a" * 32
    assert resolve_provider(apikey=apikey).provider == "openrouter"


def test_cohere_is_first_party_not_aggregator():
    """Cohere serves its own Command models — not OpenAI/Claude multi-vendor."""
    decision = resolve_provider(apiurl="https://api.cohere.com/v1")
    assert decision.provider == "cohere"
    assert decision.category == "international"
    assert decision.default_model_hints[0].startswith("command")


@pytest.mark.parametrize(
    ("apiurl", "provider"),
    [
        ("https://openrouter.ai/api/v1", "openrouter"),
        ("https://api.siliconflow.cn/v1", "siliconflow"),
        ("https://api.together.ai/v1", "together"),
        ("https://api.fireworks.ai/inference/v1", "fireworks"),
        ("https://api.replicate.com/v1", "replicate"),
    ],
)
def test_multi_model_hosts_are_gateway_category(apiurl: str, provider: str):
    decision = resolve_provider(apiurl=apiurl)
    assert decision.provider == provider
    assert decision.category == "gateway"
    assert decision.default_model_hints  # must probe something high-value


def test_openrouter_hints_prioritize_international_models():
    """International aggregator: OpenAI/Claude before domestic."""
    hints = resolve_provider(apiurl="https://openrouter.ai/api/v1").default_model_hints
    assert hints[0].startswith("openai/")
    assert any(h.startswith("anthropic/") for h in hints)
    first_domestic = next(
        (
            i
            for i, h in enumerate(hints)
            if h.startswith(("deepseek/", "qwen/", "z-ai/", "moonshotai/"))
        ),
        len(hints),
    )
    first_intl = next(
        (i for i, h in enumerate(hints) if h.startswith(("openai/", "anthropic/"))),
        len(hints),
    )
    assert first_intl < first_domestic


def test_siliconflow_hints_prioritize_domestic_models():
    """Domestic aggregator: DeepSeek/Qwen/GLM before any Western open weights."""
    hints = resolve_provider(apiurl="https://api.siliconflow.cn/v1").default_model_hints
    assert hints[0].startswith("deepseek-ai/")
    joined = " ".join(hints)
    assert "Qwen/" in joined
    assert "GLM" in joined or "glm" in joined.lower()
    assert not any(h.startswith(("openai/", "anthropic/", "gpt-", "claude-")) for h in hints)


def test_together_hints_prioritize_international_open_models():
    hints = resolve_provider(apiurl="https://api.together.ai/v1").default_model_hints
    assert hints[0].startswith("meta-llama/")
    deepseek_idx = next((i for i, h in enumerate(hints) if "deepseek" in h.lower()), len(hints))
    assert deepseek_idx > 0  # Llama before DeepSeek


@pytest.mark.parametrize(
    ("apiurl", "provider", "protocol_family"),
    [
        ("https://resource.openai.azure.com/openai/v1", "azure_openai", "openai_compatible"),
        ("https://us-central1-aiplatform.googleapis.com/v1", "vertex", "vertex"),
        ("https://ai.google.dev/gemini-api", "gemini", "gemini"),
        ("https://api.groq.com/openai/v1", "groq", "openai_compatible"),
        ("https://openrouter.ai/api/v1", "openrouter", "openai_compatible"),
    ],
)
def test_added_provider_domains_resolve_with_supported_protocols(
    apiurl: str, provider: str, protocol_family: str
):
    decision = resolve_provider(apiurl=apiurl)
    assert decision.provider == provider
    assert decision.protocol_family == protocol_family


@pytest.mark.parametrize(
    "apiurl",
    [
        "https://attacker-openai.com/v1",
        "https://fake-anthropic.com/v1",
        "https://not-googleapis.com/v1",
    ],
)
def test_provider_domains_require_a_real_dns_boundary(apiurl: str):
    # Spoofed hosts must NOT match official domain suffixes; with an endpoint
    # they classify as third-party gateway (not the spoofed brand).
    decision = resolve_provider(apiurl=apiurl)
    assert decision.provider == "gateway"
    assert decision.reason == "unmatched-endpoint"


def test_spoofed_domain_does_not_suppress_key_prefix_resolution():
    decision = resolve_provider(
        apiurl="https://attacker-openai.com/v1",
        apikey="sk-ant-api-" + "A" * 32,
    )
    assert decision.provider == "anthropic"


def test_non_routable_sentinel_specs_are_registered():
    assert provider_registry.get("gateway").category == "gateway"
    assert provider_registry.get("ambiguous").category == "unknown"


def test_unmatched_endpoint_resolves_to_gateway():
    """Third-party hosts (NewAPI/OneAPI/relay sites) are gateways, not unknown."""
    decision = resolve_provider(
        apiurl="https://apinet.cloud/v1",
        apikey="sk-" + "a" * 40,
    )
    assert decision.provider == "gateway"
    assert decision.category == "gateway"
    assert decision.reason == "unmatched-endpoint"


def test_unmatched_linode_style_endpoint_resolves_to_gateway():
    decision = resolve_provider(
        apiurl="http://74-207-234-196.ip.linodeusercontent.com:7790",
        apikey="GOCSxxxxH1vK",
    )
    assert decision.provider == "gateway"
    assert decision.reason == "unmatched-endpoint"


def test_no_signal_resolves_to_unknown_spec():
    """No domain and no key prefix → unknown (not gateway)."""
    decision = resolve_provider(apikey="synthetic-key")
    assert decision.provider == "unknown"
    assert decision.category == "unknown"
    assert decision.reason == "unmatched"


def test_invalid_ipv6_url_does_not_raise():
    """Historical junk netlocs must not crash resolve_provider."""
    decision = resolve_provider(apiurl="http://[::1", apikey="sk-" + "a" * 40)
    assert decision.provider == "gateway"
    assert decision.reason == "unmatched-endpoint"


def test_provider_spec_requires_immutable_tuple_fields():
    with pytest.raises(TypeError):
        ProviderSpec(  # type: ignore[arg-type]
            name="unknown",
            category="unknown",
            domain_suffixes=["example.test"],
            key_prefixes=(),
            protocol_family="openai_compatible",
            default_model_hints=(),
        )
