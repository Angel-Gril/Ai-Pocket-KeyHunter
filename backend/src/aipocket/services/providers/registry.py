from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import urlparse

from aipocket.core.models import ProviderName

from .base import ProviderResolution, ProviderSpec
from .gemini import is_gemini_api_key

_OPENAI_MODELS = ("gpt-5.5", "gpt-5.4", "gpt-4o-mini", "gpt-3.5-turbo")
_OAIUSERCONTENT_MODELS = ("gpt-5.5", "gpt-5.4", "gpt-4o-mini")
_ANTHROPIC_MODELS = (
    "claude-sonnet-4-6",
    "claude-sonnet-5",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "claude-haiku-4-5-20251001",
)
_FALLBACK_MODELS = (
    "gpt-5.5",
    "gpt-5.4",
    "claude-sonnet-4-6",
    "claude-opus-4-8",
    "claude-opus-4-7",
    "deepseek-v4-pro",
    "deepseek-v4-flash",
    "glm-5.1",
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
        key_prefixes=("sk-ant-api", "sk-ant-oat", "sk-ant-sid"),
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
        default_model_hints=("deepseek-v4-pro", "deepseek-v4-flash", "deepseek-chat"),
    ),
    ProviderSpec(
        name="kimi",
        category="domestic",
        domain_suffixes=("moonshot.cn",),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=(
            "kimi-k2.7-code",
            "kimi-k2.6",
            "kimi-k2.5",
            "moonshot-v1-8k",
        ),
    ),
    ProviderSpec(
        name="glm",
        category="domestic",
        domain_suffixes=("bigmodel.cn", "zhipuai.cn", "zhipuai.com"),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=("glm-5.2", "glm-5.1", "glm-5", "glm-4-flash"),
    ),
    ProviderSpec(
        name="qwen",
        category="domestic",
        domain_suffixes=("dashscope.aliyuncs.com", "baidu.com"),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=("qwen3.7-max", "qwen3-max", "qwen-turbo"),
        domain_model_hints=(("baidu.com", ("ernie-bot-turbo", "ernie-4.0-8k")),),
    ),
    ProviderSpec(
        name="siliconflow",
        category="domestic",
        domain_suffixes=("siliconflow.cn",),
        key_prefixes=(),
        protocol_family="openai_compatible",
        default_model_hints=(
            "deepseek-ai/DeepSeek-V3",
            "Qwen/Qwen2.5-7B-Instruct",
        ),
    ),
    ProviderSpec(
        name="groq",
        category="international",
        domain_suffixes=("groq.com",),
        key_prefixes=("gsk_",),
        protocol_family="openai_compatible",
        default_model_hints=("llama-3.3-70b-versatile",),
        official_api_url="https://api.groq.com/openai/v1",
    ),
    ProviderSpec(
        name="openrouter",
        category="gateway",
        domain_suffixes=("openrouter.ai",),
        key_prefixes=("sk-or-v1-",),
        protocol_family="openai_compatible",
        default_model_hints=_FALLBACK_MODELS,
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
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    return (parsed.hostname or "").rstrip(".")


def _is_domain_suffix(host: str, suffix: str) -> bool:
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
