"""Credential issuer vs validation-provider dual attribution.

Decision order (plan §3.5 / Task 7):

1. Discovery hints (provider_hint, variables, key patterns) alone → issuer stays
   ``unknown`` until authentication succeeds.
2. Official exclusive key shape + official endpoint auth → official issuer.
3. Generic token + official domain + official auth → official issuer.
4. Generic token + gateway endpoint auth → ``gateway``.
5. Model list / verified models prove family (e.g. ``glm-*``) → only
   ``served_model_families``; never rewrite issuer.
6. ``issuer_evidence`` records the winning verified signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from aipocket.core.key_patterns import KEY_PATTERNS
from aipocket.core.models import ProviderName
from aipocket.services.providers.registry import provider_registry

IssuerName = ProviderName | Literal["gateway", "unknown"]

# Exclusive key shapes that strongly identify an official issuer when the
# secret matches the canonical pattern *and* official auth succeeds.
_EXCLUSIVE_SHAPE_TO_ISSUER: tuple[tuple[str, ProviderName], ...] = (
    ("openrouter", "openrouter"),
    ("anthropic", "anthropic"),
    ("openai_proj", "openai"),
    ("google", "google"),
    ("groq", "groq"),
    ("replicate", "replicate"),
    ("glm", "glm"),
    # glm_jwt is intentionally NOT exclusive — only a candidate when co-located
    # with GLM variable/domain evidence (handled separately if needed).
)

_PATTERN_BY_ID: dict[str, re.Pattern[str]] = {name: pat for name, pat in KEY_PATTERNS}

# Model-id → capability family prefixes (longest first for matching).
_MODEL_FAMILY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("moonshot", "moonshot"),
    ("deepseek", "deepseek"),
    ("claude", "anthropic"),
    ("gemini", "gemini"),
    ("meta-llama", "together"),
    ("accounts/fireworks", "fireworks"),
    ("command", "cohere"),
    ("glm", "glm"),
    ("qwen", "qwen"),
    ("kimi", "kimi"),
    ("gpt", "openai"),
)


@dataclass(frozen=True, slots=True)
class IssuerDecision:
    validation_provider: ProviderName
    credential_issuer: IssuerName
    issuer_evidence: str
    served_model_families: tuple[str, ...]


def decide_issuer(
    *,
    apikey: str,
    apiurl: str = "",
    validation_provider: ProviderName = "unknown",
    auth_confirmed: bool = False,
    models_available: list[str] | tuple[str, ...] | None = None,
    models_verified: list[str] | tuple[str, ...] | None = None,
    provider_hint: str = "unknown",
    variable_names: tuple[str, ...] | list[str] = (),
) -> IssuerDecision:
    """Pure function: map verified auth + evidence → issuer / capability fields.

    ``validation_provider`` is the adapter/endpoint party (registry resolution).
    Discovery-only signals never promote issuer without ``auth_confirmed``.
    """
    families = _served_model_families(
        models_available=models_available or (),
        models_verified=models_verified or (),
    )

    # Always keep validation_provider as the endpoint/adapter party.
    # Discovery hints alone must not set issuer.
    if not auth_confirmed:
        return IssuerDecision(
            validation_provider=validation_provider,
            credential_issuer="unknown",
            issuer_evidence="",
            served_model_families=families,
        )

    exclusive = _match_exclusive_key_shape(apikey)
    on_official = _is_official_endpoint(apiurl, validation_provider)
    is_gateway_endpoint = validation_provider in {"gateway", "ambiguous", "unknown"} or (
        not on_official and validation_provider not in _OFFICIAL_PROVIDER_NAMES
    )

    # 2) Exclusive key shape + official endpoint auth → official issuer
    if exclusive is not None and (
        on_official or validation_provider == exclusive or _url_matches_issuer(apiurl, exclusive)
    ):
        evidence = "key_shape|validated_endpoint"
        if on_official or _url_matches_issuer(apiurl, exclusive):
            evidence = "key_shape|official_domain|validated_endpoint"
        return IssuerDecision(
            validation_provider=validation_provider,
            credential_issuer=exclusive,
            issuer_evidence=evidence,
            served_model_families=families,
        )

    # Exclusive shape auth'd on a non-official/gateway host still attributes
    # the secret issuer to the exclusive provider (key belongs to that vendor);
    # validation_provider remains the host party.
    if exclusive is not None and is_gateway_endpoint:
        return IssuerDecision(
            validation_provider=validation_provider,
            credential_issuer=exclusive,
            issuer_evidence="key_shape|validated_endpoint",
            served_model_families=families,
        )

    # 3) Generic token + official domain + official auth → official issuer
    if on_official and validation_provider in _OFFICIAL_PROVIDER_NAMES:
        evidence_parts = ["official_domain", "validated_endpoint"]
        # Co-located variable / bundle hint strengthens evidence but is not required.
        if _hint_supports(provider_hint, variable_names, validation_provider):
            evidence_parts.insert(0, "bundle_hint")
        return IssuerDecision(
            validation_provider=validation_provider,
            credential_issuer=validation_provider,
            issuer_evidence="|".join(evidence_parts),
            served_model_families=families,
        )

    # 4) Generic token + gateway endpoint auth → gateway
    if is_gateway_endpoint or validation_provider == "gateway":
        return IssuerDecision(
            validation_provider="gateway"
            if validation_provider in {"gateway", "unknown", "ambiguous"}
            else validation_provider,
            credential_issuer="gateway",
            issuer_evidence="validated_endpoint",
            served_model_families=families,
        )

    # Fallback: auth on a known official-ish provider without domain match
    if validation_provider in _OFFICIAL_PROVIDER_NAMES:
        return IssuerDecision(
            validation_provider=validation_provider,
            credential_issuer=validation_provider,
            issuer_evidence="validated_endpoint",
            served_model_families=families,
        )

    return IssuerDecision(
        validation_provider=validation_provider,
        credential_issuer="unknown",
        issuer_evidence="",
        served_model_families=families,
    )


_OFFICIAL_PROVIDER_NAMES: frozenset[str] = frozenset(
    {
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
    }
)


def _match_exclusive_key_shape(apikey: str) -> ProviderName | None:
    key = (apikey or "").strip()
    if not key:
        return None
    for pattern_id, issuer in _EXCLUSIVE_SHAPE_TO_ISSUER:
        pattern = _PATTERN_BY_ID.get(pattern_id)
        if pattern is None:
            continue
        m = pattern.search(key)
        if m and m.group(1) == key:
            return issuer
        # Also accept fullmatch without word boundaries for clean keys
        if pattern_id == "glm" and re.fullmatch(r"[a-f0-9]{32}\.[A-Za-z0-9]{16}", key):
            return "glm"
    return None


def _hostname(apiurl: str) -> str:
    candidate = (apiurl or "").strip().lower()
    if not candidate:
        return ""
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    return (parsed.hostname or "").rstrip(".")


def _is_domain_suffix(host: str, suffix: str) -> bool:
    suffix = suffix.lower().rstrip(".")
    if not host or not suffix:
        return False
    return host == suffix or host.endswith(f".{suffix}")


def _is_official_endpoint(apiurl: str, validation_provider: ProviderName) -> bool:
    """True when *apiurl* host matches the resolved provider's official domains."""
    if validation_provider not in _OFFICIAL_PROVIDER_NAMES:
        return False
    try:
        spec = provider_registry.get(validation_provider)
    except KeyError:
        return False
    host = _hostname(apiurl)
    if not host:
        return False
    return any(_is_domain_suffix(host, s) for s in spec.domain_suffixes)


def _url_matches_issuer(apiurl: str, issuer: ProviderName) -> bool:
    try:
        spec = provider_registry.get(issuer)
    except KeyError:
        return False
    host = _hostname(apiurl)
    return bool(host) and any(_is_domain_suffix(host, s) for s in spec.domain_suffixes)


def _hint_supports(
    provider_hint: str,
    variable_names: tuple[str, ...] | list[str],
    provider: ProviderName,
) -> bool:
    if provider_hint and provider_hint == provider:
        return True
    aliases = _PROVIDER_VARIABLE_ALIASES.get(provider, (provider,))
    joined = " ".join(variable_names).lower()
    return any(alias in joined for alias in aliases)


_PROVIDER_VARIABLE_ALIASES: dict[str, tuple[str, ...]] = {
    "glm": ("glm", "zhipu", "bigmodel"),
    "kimi": ("kimi", "moonshot"),
    "qwen": ("qwen", "dashscope", "tongyi"),
    "openai": ("openai",),
    "anthropic": ("anthropic", "claude"),
    "google": ("google", "gemini", "generativelanguage"),
    "vertex": ("vertex", "gcp"),
    "groq": ("groq",),
    "openrouter": ("openrouter",),
    "deepseek": ("deepseek",),
    "siliconflow": ("siliconflow",),
    "cohere": ("cohere", "command"),
    "replicate": ("replicate",),
    "together": ("together",),
    "fireworks": ("fireworks",),
}


def _served_model_families(
    *,
    models_available: list[str] | tuple[str, ...],
    models_verified: list[str] | tuple[str, ...],
) -> tuple[str, ...]:
    """Extract capability families from model ids — never used as issuer."""
    seen: list[str] = []
    for model in (*models_available, *models_verified):
        family = _family_for_model(str(model))
        if family and family not in seen:
            seen.append(family)
    return tuple(seen)


def _family_for_model(model: str) -> str:
    m = model.lower().strip()
    # Strip common gateway prefixes: "zhipu/glm-4", "openai/gpt-4o"
    if "/" in m:
        m = m.rsplit("/", 1)[-1]
    for prefix, family in _MODEL_FAMILY_PREFIXES:
        if m.startswith(prefix):
            return family
    return ""
