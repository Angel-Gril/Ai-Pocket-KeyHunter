from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import urlparse

from aipocket.core.models import ProviderName

from .base import ProviderResolution, ProviderSpec
from .gemini import is_gemini_api_key

# ---------------------------------------------------------------------------
# First-party model families (official hosts only serve their own models)
# ---------------------------------------------------------------------------
_OPENAI_MODELS = ("gpt-5.6-sol", "gpt-5.6", "gpt-5.5", "gpt-5.4", "gpt-4o-mini", "gpt-3.5-turbo")
_OAIUSERCONTENT_MODELS = ("gpt-5.6-sol", "gpt-5.6", "gpt-5.5", "gpt-5.4", "gpt-4o-mini")
_ANTHROPIC_MODELS = (
    "claude-fable-5",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-haiku-4-5-20251001",
)
_DEEPSEEK_MODELS = ("deepseek-v4-pro", "deepseek-v4-flash", "deepseek-chat")
_GLM_MODELS = ("glm-5.2", "glm-5.1", "glm-5", "glm-4-flash")
_QWEN_MODELS = ("qwen3.7-max", "qwen3-max", "qwen-turbo")
_KIMI_MODELS = (
    "kimi-k3",
    "kimi-k2.7-code",
    "kimi-k2.6",
    "kimi-k2.5",
    "moonshot-v1-8k",
)
# Cohere is first-party (Command family) — NOT a multi-model aggregator.
_COHERE_MODELS = ("command-r-plus", "command-r", "command-a-03-2025")
_MINIMAX_MODELS = ("MiniMax-M2.7", "MiniMax-M2.5")
_NVIDIA_MODELS = ("meta/llama-3.3-70b-instruct", "nvidia/llama-3.1-nemotron-ultra-253b-v1")
_KSYUN_MODELS = ("deepseek-v3", "qwen3-235b-a22b")
_LONGCAT_MODELS = ("LongCat-2.0",)

# ---------------------------------------------------------------------------
# Multi-vendor gateways / aggregators — region-aware probe order
#
# Domestic aggregators (e.g. SiliconFlow, Chinese NewAPI relays):
#   DeepSeek → GLM → Qwen → Kimi first, then OpenAI/Claude as secondary.
# International aggregators (OpenRouter, Together, Fireworks, Replicate, Groq):
#   OpenAI → Claude → Llama/Meta first, then domestic models as secondary.
#
# Bare IDs match NewAPI/OneAPI-style relays; vendor-prefixed IDs match
# OpenRouter / SiliconFlow org namespaces.
# ---------------------------------------------------------------------------
_INTERNATIONAL_BARE = (
    "gpt-5.6-sol",
    "gpt-5.6",
    "gpt-5.5",
    "gpt-5.4",
    "claude-fable-5",
    "claude-sonnet-5",
    "claude-sonnet-4-6",
    "claude-opus-4-8",
)
_DOMESTIC_BARE = (
    "deepseek-v4-pro",
    "deepseek-v4-flash",
    "glm-5.2",
    "glm-5.1",
    "qwen3.7-max",
    "qwen3-max",
    "kimi-k3",
)
# Unknown third-party endpoints (may be either region) — international canaries first
# for honeypot resistance, then domestic high-value.
_FALLBACK_MODELS = (*_INTERNATIONAL_BARE, *_DOMESTIC_BARE)
# Domestic multi-vendor relays (Chinese NewAPI etc. when attributed domestic).
_DOMESTIC_GATEWAY_MODELS = (*_DOMESTIC_BARE, *_INTERNATIONAL_BARE)

# OpenRouter: international multi-vendor first, domestic vendor prefixes later.
_OPENROUTER_MODELS = (
    "openai/gpt-5.6-sol",
    "openai/gpt-5.6",
    "openai/gpt-5.5",
    "anthropic/claude-fable-5",
    "anthropic/claude-sonnet-5",
    "anthropic/claude-sonnet-4",
    "anthropic/claude-opus-4.1",
    "deepseek/deepseek-v4-pro",
    "deepseek/deepseek-chat",
    "z-ai/glm-4.5",
    "qwen/qwen3-max",
    "moonshotai/kimi-k3",
    *_INTERNATIONAL_BARE,
    *_DOMESTIC_BARE,
)
# SiliconFlow: domestic Chinese aggregator — DeepSeek / Qwen / GLM / Kimi first.
_SILICONFLOW_MODELS = (
    "deepseek-ai/DeepSeek-V4-Pro",
    "deepseek-ai/DeepSeek-V4-Flash",
    "deepseek-ai/DeepSeek-V3",
    "Qwen/Qwen3.5-397B-A17B",
    "Qwen/Qwen3-Max",
    "Qwen/Qwen3-32B",
    "THUDM/GLM-Z1-32B-0414",
    "zai-org/GLM-4.5",
    "moonshotai/Kimi-K2.5",
)
# International open-model hosts: Western open weights first, Chinese OSS later.
_TOGETHER_MODELS = (
    "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
    "deepseek-ai/DeepSeek-V3",
    "deepseek-ai/DeepSeek-R1",
    "Qwen/Qwen2.5-72B-Instruct-Turbo",
)
_FIREWORKS_MODELS = (
    "accounts/fireworks/models/llama-v3p3-70b-instruct",
    "accounts/fireworks/models/llama-v3p1-405b-instruct",
    "accounts/fireworks/models/deepseek-v3",
    "accounts/fireworks/models/deepseek-r1",
    "accounts/fireworks/models/qwen2p5-72b-instruct",
)
_GROQ_MODELS = (
    "llama-3.3-70b-versatile",
    "llama-3.1-70b-versatile",
    "deepseek-r1-distill-llama-70b",
    "qwen-qwq-32b",
)
_REPLICATE_MODELS = (
    "meta/meta-llama-3.1-405b-instruct",
    "meta/meta-llama-3-70b-instruct",
    "deepseek-ai/deepseek-r1",
)

# Providers whose default probe order should put domestic high-value models first
# when /v1/models is available (see validator.high_value_probe_order).
DOMESTIC_PROBE_PROVIDERS = frozenset(
    {"siliconflow", "deepseek", "kimi", "glm", "qwen", "minimax", "ksyun", "longcat"}
)
INTERNATIONAL_PROBE_PROVIDERS = frozenset(
    {
        "openai",
        "anthropic",
        "openrouter",
        "together",
        "fireworks",
        "replicate",
        "groq",
        "cohere",
        "google",
        "gemini",
        "azure_openai",
        "vertex",
        "nvidia",
    }
)

_PROVIDER_SPECS = (
    ProviderSpec(
        name="openai",
        category="international",
        domain_suffixes=("openai.com", "oaiusercontent.com"),
        key_prefixes=("sk-proj", "sk-admin", "sk-svcacct"),
        protocol_family="openai_compatible",
        default_model_hints=_OPENAI_MODELS,
        official_api_url="https://api.openai.com/v1",
        domain_model_hints=(("oaiusercontent.com", _OAIUSERCONTENT_MODELS),),
    ),
    ProviderSpec(
        name="anthropic",
        category="international",
        domain_suffixes=("anthropic.com",),
        key_prefixes=("sk-ant-admin", "sk-ant-api", "sk-ant-oat", "sk-ant-sid"),
        protocol_family="anthropic",
        default_model_hints=_ANTHROPIC_MODELS,
        official_api_url="https://api.anthropic.com/v1",
    ),
    ProviderSpec(
        name="deepseek",
        category="domestic",
        domain_suffixes=("deepseek.com",),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_DEEPSEEK_MODELS,
    ),
    ProviderSpec(
        name="kimi",
        category="domestic",
        domain_suffixes=("moonshot.cn",),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_KIMI_MODELS,
        official_api_url="https://api.moonshot.cn/v1",
    ),
    ProviderSpec(
        name="glm",
        category="domestic",
        domain_suffixes=("bigmodel.cn", "zhipuai.cn", "zhipuai.com"),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_GLM_MODELS,
        # OpenAI-compatible chat base (balance probe uses host + /api/paas/v4/...).
        official_api_url="https://open.bigmodel.cn/api/paas/v4",
    ),
    ProviderSpec(
        name="minimax",
        category="domestic",
        domain_suffixes=("minimax.io", "minimaxi.com", "minimax.chat"),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_MINIMAX_MODELS,
        official_api_url="https://api.minimax.io/v1",
    ),
    ProviderSpec(
        name="nvidia",
        category="international",
        domain_suffixes=("integrate.api.nvidia.com",),
        key_prefixes=("nvapi-",),
        protocol_family="openai_compatible",
        default_model_hints=_NVIDIA_MODELS,
        official_api_url="https://integrate.api.nvidia.com/v1",
    ),
    ProviderSpec(
        name="ksyun",
        category="domestic",
        domain_suffixes=("kspmas.ksyun.com",),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_KSYUN_MODELS,
        official_api_url="https://kspmas.ksyun.com/v1",
    ),
    ProviderSpec(
        name="longcat",
        category="domestic",
        domain_suffixes=("api.longcat.chat",),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_LONGCAT_MODELS,
        official_api_url="https://api.longcat.chat/openai",
    ),
    ProviderSpec(
        name="qwen",
        category="domestic",
        # CN + intl + coding-plan hosts. dashscope-intl is NOT a suffix of
        # dashscope.aliyuncs.com (hyphenated label), so list both explicitly.
        domain_suffixes=(
            "dashscope.aliyuncs.com",
            "dashscope-intl.aliyuncs.com",
            "dashscope-us.aliyuncs.com",
            "baidu.com",
        ),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_QWEN_MODELS,
        domain_model_hints=(("baidu.com", ("ernie-bot-turbo", "ernie-4.0-8k")),),
        official_api_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    ),
    # Aggregator: hosts DeepSeek / Qwen / GLM / Llama (not official OpenAI/Claude).
    ProviderSpec(
        name="siliconflow",
        category="gateway",
        domain_suffixes=("siliconflow.cn",),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_SILICONFLOW_MODELS,
        official_api_url="https://api.siliconflow.cn/v1",
    ),
    # First-party Command models — not a multi-vendor aggregator.
    ProviderSpec(
        name="cohere",
        category="international",
        domain_suffixes=("cohere.com", "cohere.ai"),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_COHERE_MODELS,
        official_api_url="https://api.cohere.com/v1",
    ),
    # Model marketplace / open-weight hosting (not proprietary OpenAI/Claude).
    ProviderSpec(
        name="replicate",
        category="gateway",
        domain_suffixes=("replicate.com",),
        key_prefixes=("r8_",),
        protocol_family="openai_compatible",
        default_model_hints=_REPLICATE_MODELS,
        official_api_url="https://api.replicate.com/v1",
    ),
    ProviderSpec(
        name="together",
        category="gateway",
        domain_suffixes=("together.xyz", "together.ai"),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_TOGETHER_MODELS,
        official_api_url="https://api.together.ai/v1",
    ),
    ProviderSpec(
        name="fireworks",
        category="gateway",
        domain_suffixes=("fireworks.ai",),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_FIREWORKS_MODELS,
        official_api_url="https://api.fireworks.ai/inference/v1",
    ),
    # Fast open-model inference (LPU) — not a multi-vendor OpenAI/Claude broker.
    ProviderSpec(
        name="groq",
        category="international",
        domain_suffixes=("groq.com",),
        key_prefixes=("gsk_",),
        protocol_family="openai_compatible",
        default_model_hints=_GROQ_MODELS,
        official_api_url="https://api.groq.com/openai/v1",
    ),
    # True multi-vendor aggregator (OpenAI + Claude + DeepSeek + …).
    ProviderSpec(
        name="openrouter",
        category="gateway",
        domain_suffixes=("openrouter.ai",),
        key_prefixes=("sk-or-v1-",),
        protocol_family="openai_compatible",
        default_model_hints=_OPENROUTER_MODELS,
        official_api_url="https://openrouter.ai/api/v1",
    ),
    ProviderSpec(
        name="azure_openai",
        category="international",
        domain_suffixes=("openai.azure.com",),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_OPENAI_MODELS[:2],
    ),
    ProviderSpec(
        name="vertex",
        category="international",
        domain_suffixes=("aiplatform.googleapis.com",),
        key_prefixes=(),
        protocol_family="vertex",
        default_model_hints=("gemini-3.5-flash", "gemini-3.1-pro-preview"),
    ),
    ProviderSpec(
        name="google",
        category="international",
        # generativelanguage only — vertex hosts are matched by the vertex spec.
        # Key matching uses exact Gemini API key shape via is_gemini_api_key (not bare AIza*).
        domain_suffixes=("generativelanguage.googleapis.com",),
        key_prefixes=(),
        protocol_family="gemini",
        default_model_hints=(
            "gemini-3.5-flash",
            "gemini-3.1-pro-preview",
            "gemini-1.5-flash",
        ),
        official_api_url="https://generativelanguage.googleapis.com/v1beta",
    ),
    ProviderSpec(
        name="gemini",
        category="international",
        domain_suffixes=("ai.google.dev",),
        key_prefixes=(),
        protocol_family="gemini",
        default_model_hints=("gemini-3.5-flash", "gemini-3.1-pro-preview"),
    ),
    ProviderSpec(
        name="newapi",
        category="gateway",
        domain_suffixes=(),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_FALLBACK_MODELS,
    ),
    ProviderSpec(
        name="oneapi",
        category="gateway",
        domain_suffixes=(),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_FALLBACK_MODELS,
    ),
    ProviderSpec(
        name="litellm",
        category="gateway",
        domain_suffixes=(),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_FALLBACK_MODELS,
    ),
    ProviderSpec(
        name="gateway",
        category="gateway",
        domain_suffixes=(),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_FALLBACK_MODELS,
    ),
    ProviderSpec(
        name="ambiguous",
        category="unknown",
        domain_suffixes=(),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_FALLBACK_MODELS,
    ),
    ProviderSpec(
        name="unknown",
        category="unknown",
        domain_suffixes=(),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=_FALLBACK_MODELS,
    ),
)


def _hostname(apiurl: str) -> str:
    candidate = apiurl.strip().lower()
    if not candidate:
        return ""
    try:
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    except ValueError:
        # Historical junk (unbalanced brackets, invalid IPv6 netloc, etc.).
        return ""
    return (parsed.hostname or "").rstrip(".")


def _is_domain_suffix(host: str, suffix: str) -> bool:
    if suffix == "api.longcat.chat":
        return host == suffix
    suffix = suffix.lower().rstrip(".")
    if host == suffix or host.endswith(f".{suffix}"):
        return True
    return suffix == "aiplatform.googleapis.com" and host.endswith(f"-{suffix}")


@dataclass(frozen=True, slots=True)
class ProviderRegistry:
    _specs: tuple[ProviderSpec, ...]
    _by_name: Mapping[ProviderName, ProviderSpec] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        specs = tuple(self._specs)
        object.__setattr__(self, "_specs", specs)
        by_name = {spec.name: spec for spec in specs}
        if len(by_name) != len(specs):
            raise ValueError("provider names must be unique")
        if "unknown" not in by_name:
            raise ValueError("provider registry requires an unknown provider")
        object.__setattr__(self, "_by_name", MappingProxyType(by_name))

    def specs(self) -> tuple[ProviderSpec, ...]:
        return self._specs

    def get(self, name: ProviderName) -> ProviderSpec:
        return self._by_name[name]

    def _match_domain(self, apiurl: str) -> tuple[ProviderSpec, str] | None:
        host = _hostname(apiurl)
        if not host:
            return None
        matches = (
            (len(suffix), spec, suffix)
            for spec in self._specs
            for suffix in spec.domain_suffixes
            if _is_domain_suffix(host, suffix)
        )
        match = max(matches, key=lambda candidate: candidate[0], default=None)
        return (match[1], match[2]) if match is not None else None

    def match_domain(self, apiurl: str) -> ProviderSpec | None:
        match = self._match_domain(apiurl)
        return match[0] if match is not None else None

    def match_key(self, apikey: str) -> ProviderSpec | None:
        if is_gemini_api_key(apikey):
            return self.get("google")
        matches = (
            (len(prefix), spec)
            for spec in self._specs
            for prefix in spec.key_prefixes
            if apikey.startswith(prefix)
        )
        return max(matches, key=lambda match: match[0], default=(0, None))[1]

    def resolve(self, *, apiurl: str = "", apikey: str = "") -> ProviderResolution:
        domain_match = self._match_domain(apiurl)
        key_spec = self.match_key(apikey)
        if (
            domain_match is not None
            and key_spec is not None
            and domain_match[0].name != key_spec.name
        ):
            ambiguous = self.get("ambiguous")
            return ProviderResolution(
                ambiguous,
                "provider-conflict",
                ambiguous.default_model_hints,
            )
        if domain_match is not None:
            spec, suffix = domain_match
            return ProviderResolution(
                spec,
                "domain-match",
                spec.model_hints_for_domain(suffix),
            )
        if key_spec is not None:
            return ProviderResolution(
                key_spec,
                "key-prefix-match",
                key_spec.default_model_hints,
            )
        # A concrete endpoint with no official domain/key match is a third-party
        # OpenAI-compatible gateway (self-hosted NewAPI/OneAPI, reverse proxies,
        # relay sites). Reserve ``unknown`` for no-endpoint / no-signal cases.
        if apiurl.strip():
            gateway = self.get("gateway")
            return ProviderResolution(
                gateway,
                "unmatched-endpoint",
                gateway.default_model_hints,
            )
        unknown = self.get("unknown")
        return ProviderResolution(unknown, "unmatched", unknown.default_model_hints)


provider_registry = ProviderRegistry(_PROVIDER_SPECS)


def resolve_provider(*, apiurl: str = "", apikey: str = "") -> ProviderResolution:
    return provider_registry.resolve(apiurl=apiurl, apikey=apikey)


def uses_openai_adapter(*, apiurl: str = "", apikey: str = "") -> bool:
    return resolve_provider(apiurl=apiurl, apikey=apikey).provider == "openai"


def uses_azure_openai_adapter(*, apiurl: str = "", apikey: str = "") -> bool:
    return resolve_provider(apiurl=apiurl, apikey=apikey).provider == "azure_openai"


def uses_gemini_adapter(*, apiurl: str = "", apikey: str = "") -> bool:
    decision = resolve_provider(apiurl=apiurl, apikey=apikey)
    return decision.provider in {"google", "gemini"} or decision.protocol_family == "gemini"


def uses_vertex_adapter(*, apiurl: str = "", apikey: str = "") -> bool:
    decision = resolve_provider(apiurl=apiurl, apikey=apikey)
    return decision.provider == "vertex" or decision.protocol_family == "vertex"


def uses_anthropic_adapter(*, apiurl: str = "", apikey: str = "") -> bool:
    decision = resolve_provider(apiurl=apiurl, apikey=apikey)
    return decision.provider == "anthropic" or decision.protocol_family == "anthropic"
