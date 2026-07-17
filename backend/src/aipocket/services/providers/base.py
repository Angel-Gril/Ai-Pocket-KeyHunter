from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from aipocket.core.models import ProviderCategory, ProviderName

ProtocolFamily = Literal["openai_compatible", "anthropic", "gemini", "vertex"]
SUPPORTED_PROTOCOL_FAMILIES = frozenset({"openai_compatible", "anthropic", "gemini", "vertex"})


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """Static routing and probing metadata for one provider."""

    name: ProviderName
    category: ProviderCategory
    domain_suffixes: tuple[str, ...]
    key_prefixes: tuple[str, ...]
    protocol_family: ProtocolFamily
    default_model_hints: tuple[str, ...]
    official_api_url: str = ""
    domain_model_hints: tuple[tuple[str, tuple[str, ...]], ...] = ()

    def __post_init__(self) -> None:
        tuple_fields = (
            self.domain_suffixes,
            self.key_prefixes,
            self.default_model_hints,
            self.domain_model_hints,
        )
        if any(not isinstance(value, tuple) for value in tuple_fields):
            raise TypeError("ProviderSpec routing and model collections must be tuples")
        if any(
            not isinstance(route, tuple) or len(route) != 2 or not isinstance(route[1], tuple)
            for route in self.domain_model_hints
        ):
            raise TypeError("ProviderSpec domain model routes must contain tuples")
        if self.protocol_family not in SUPPORTED_PROTOCOL_FAMILIES:
            raise ValueError(f"unsupported protocol family: {self.protocol_family}")

    def model_hints_for_domain(self, suffix: str) -> tuple[str, ...]:
        for route_suffix, model_hints in self.domain_model_hints:
            if route_suffix == suffix:
                return model_hints
        return self.default_model_hints


@dataclass(frozen=True, slots=True)
class ProviderResolution:
    """The registry spec selected for a domain or key prefix."""

    spec: ProviderSpec
    reason: str
    model_hints: tuple[str, ...]

    @property
    def provider(self) -> ProviderName:
        return self.spec.name

    @property
    def category(self) -> ProviderCategory:
        return self.spec.category

    @property
    def protocol_family(self) -> ProtocolFamily:
        return self.spec.protocol_family

    @property
    def default_model_hints(self) -> tuple[str, ...]:
        return self.model_hints

    @property
    def official_api_url(self) -> str:
        return self.spec.official_api_url


@dataclass(frozen=True, slots=True)
class ReadOnlyProviderValidation:
    valid: bool
    status_code: int | None = None
    models: tuple[str, ...] = ()
    scope: str = ""
    error: str = ""
