from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

SourceType = Literal["header", "banner", "body", "fingerprint"]


class Credential(BaseModel):
    apikey: str
    apiurl: str = ""
    source: str = ""
    source_type: SourceType = "fingerprint"
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
    validated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class ScanRunResult(BaseModel):
    started_at: str
    finished_at: str
    total_hosts: int
    total_credentials: int
    total_valid: int
    queries_used: list[str]
    results: list[ValidationResult]
    raw_hits: list[dict[str, Any]] = Field(default_factory=list)


Credential.model_rebuild()
ValidationResult.model_rebuild()
ScanRunResult.model_rebuild()
