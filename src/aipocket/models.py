from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

SourceType = Literal["header", "banner", "body", "fingerprint"]

# Canonical provider categories
Provider = Literal[
    "openai", "anthropic", "deepseek", "kimi", "glm",
    "qwen", "siliconflow", "google", "gateway", "unknown",
]
ProviderCategory = Literal["international", "domestic", "gateway", "unknown"]


class ProviderInfo(BaseModel):
    """Provider classification + model availability for a validated credential."""
    provider: Provider = "unknown"
    category: ProviderCategory = "unknown"
    # Models listed by GET /v1/models (or equivalent)
    models_available: list[str] = Field(default_factory=list)
    # Models that actually returned a valid chat completion during probing
    models_verified: list[str] = Field(default_factory=list)
    # Official balance endpoint reported this key's provider (redundant w/ balance probes)
    balance_provider: str = ""


class Credential(BaseModel):
    apikey: str
    apiurl: str = ""
    source: str = ""
    source_type: SourceType = "fingerprint"
    # Which discovery backend found this credential: "fofa", "shodan", or "fofa,shodan"
    backend: str = ""
    host: str = ""
    ip: str = ""
    port: str = ""
    product: str = ""
    raw_context: str = ""


class ValidationResult(BaseModel):
    credential: Credential
    valid: bool = False
    status_code: int | None = None
    error: str = ""
    tier: str = ""
    gateway: str = ""
    balance: str = ""
    rate_limit_headers: dict[str, str] = Field(default_factory=dict)
    model_available: str = ""
    response_snippet: str = ""
    provider_info: ProviderInfo = Field(default_factory=ProviderInfo)
    validated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class ScanRunResult(BaseModel):
    started_at: str
    finished_at: str
    # Which discovery backends contributed to this run, e.g. ["fofa", "shodan"]
    sources: list[str] = Field(default_factory=list)
    total_hosts: int
    # Per-source hit counts, e.g. {"fofa": 320, "shodan": 540}
    hits_by_source: dict[str, int] = Field(default_factory=dict)
    total_credentials: int
    total_valid: int
    queries_used: list[str]
    results: list[ValidationResult]
    raw_hits: list[dict[str, Any]] = Field(default_factory=list)


Credential.model_rebuild()
ProviderInfo.model_rebuild()
ValidationResult.model_rebuild()
ScanRunResult.model_rebuild()
