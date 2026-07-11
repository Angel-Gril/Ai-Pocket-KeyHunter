from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from aipocket.core.credentials import CredentialBundle
from aipocket.core.validation_state import (
    AUTHENTICATED_STATES,
    ValidationState,
)

SourceType = Literal["header", "banner", "body", "fingerprint"]

# Canonical provider vocabulary shared by validation and provider routing.
ProviderName = Literal[
    "openai",
    "anthropic",
    "deepseek",
    "kimi",
    "glm",
    "qwen",
    "siliconflow",
    "google",
    "groq",
    "openrouter",
    "azure_openai",
    "vertex",
    "gemini",
    "gateway",
    "ambiguous",
    "unknown",
]
ProviderCategory = Literal["international", "domestic", "gateway", "unknown"]


class ProviderInfo(BaseModel):
    """Provider classification + model availability for a validated credential."""

    provider: ProviderName = "unknown"
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
    # Original URL the key was scraped from. Populated when provider-registry
    # key-prefix routing overrides apiurl to the official endpoint, preserving
    # the true provenance while validation is redirected.
    leak_host: str = ""
    # True when provider-registry routing selected an official validation endpoint.
    routed_to_official: bool = False
    bundle: CredentialBundle | None = Field(default=None, exclude=True)


class ValidationResult(BaseModel):
    credential: Credential
    # Derived convenience mirror of validation_state for legacy callers. Prefer
    # validation_state / is_authenticated / is_final for new code.
    valid: bool = False
    validation_state: ValidationState = "discovered"
    credential_kind: str = ""
    scope: str = ""
    tier_evidence: str = ""
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
    # Suspicious-host quarantine flag. Set by honeypot._quarantine_suspicious_hosts
    # when verify_no_auth sees a forged-key 429 (open-proxy signal) or a
    # 200-non-completion (not-a-real-gateway signal). Suspicious results keep
    # valid=True but are split out of valid_*.jsonl into suspicious_*.jsonl for
    # manual review — they are NOT auto-rejected.
    suspicious: bool = False
    suspicious_reason: str = ""

    @property
    def is_authenticated(self) -> bool:
        return self.validation_state in AUTHENTICATED_STATES

    @property
    def is_final(self) -> bool:
        return self.validation_state == "final_verified"


class ScanRunResult(BaseModel):
    started_at: str
    finished_at: str
    # Which discovery backends contributed to this run, e.g. ["fofa", "shodan"]
    sources: list[str] = Field(default_factory=list)
    total_hosts: int
    # Per-source hit counts, e.g. {"fofa": 320, "shodan": 540}
    hits_by_source: dict[str, int] = Field(default_factory=dict)
    raw_hits_count: int = 0
    unique_targets: int = 0
    candidates: int = 0
    active_requests: int = 0
    final_verified: int = 0
    suspicious: int = 0
    high_value_final: int = 0
    total_credentials: int
    total_valid: int
    queries_used: list[str]
    results: list[ValidationResult]
    raw_hits: list[dict[str, Any]] = Field(default_factory=list)


Credential.model_rebuild()
ProviderInfo.model_rebuild()
ValidationResult.model_rebuild()
ScanRunResult.model_rebuild()
