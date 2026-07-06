"""Pydantic request/response schemas for the web API.

Response models here are deliberately loose (extra dicts pass through) where the
underlying record shape is a plain JSONL dict — the frontend does local
search/filter over the full payload, so we favor returning everything the
business modules already produce over a rigid contract.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ScanSource = Literal["fofa", "shodan", "all"]
ExportFormat = Literal["json", "csv"]
ExportDataset = Literal["selected", "run", "high-value"]


# ----------------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------------
class LoginRequest(BaseModel):
    password: str


class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    expires_in: int


# ----------------------------------------------------------------------------
# Single-key testing
# ----------------------------------------------------------------------------
class KeyRef(BaseModel):
    apikey: str
    apiurl: str = ""


class ModelsResponse(BaseModel):
    models: list[str]


class BalanceResponse(BaseModel):
    gateway: str = ""
    balance_usd: str = ""
    tier: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)


class ChatRequest(BaseModel):
    apikey: str
    apiurl: str = ""
    # Required — the user must explicitly pick a model (this call SPENDS credit).
    model: str


class ChatResponse(BaseModel):
    success: bool
    status_code: int | None = None
    model: str = ""
    snippet: str = ""
    error: str = ""
    # Always true for this endpoint — surfaced so the frontend can warn the user.
    consumes_credit: bool = True


class RevealRequest(BaseModel):
    run_id: str
    # Match by the masked value shown in the list (server re-reads plaintext),
    # or by 0-based line index within the file, or by apiurl to disambiguate.
    masked: str | None = None
    apiurl: str | None = None
    index: int | None = None
    # Which file to read from within the run dir.
    kind: Literal["valid", "suspicious"] = "valid"


class RevealResponse(BaseModel):
    apikey: str
    apiurl: str = ""


# ----------------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------------
class ExportRequest(BaseModel):
    dataset: ExportDataset
    format: ExportFormat = "json"
    # dataset="run" → run_id required; dataset="selected" → keys required.
    run_id: str | None = None
    kind: Literal["valid", "suspicious"] = "valid"
    keys: list[KeyRef] = Field(default_factory=list)


# ----------------------------------------------------------------------------
# Scan
# ----------------------------------------------------------------------------
class ScanStartRequest(BaseModel):
    source: ScanSource = "all"


class ScanProgress(BaseModel):
    hosts: int = 0
    credentials: int = 0
    validated: int = 0
    valid: int = 0


class ScanStatusResponse(BaseModel):
    state: str  # idle | running | stopping | finished | interrupted
    source: str | None = None
    run_id: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    progress: ScanProgress = Field(default_factory=ScanProgress)
    error: str | None = None
    log_seq: int = 0  # latest log sequence number (for ?since= polling)


class ScanLogLine(BaseModel):
    seq: int
    line: str


class ScanLogsResponse(BaseModel):
    lines: list[ScanLogLine]
    last_seq: int


# ----------------------------------------------------------------------------
# CVE
# ----------------------------------------------------------------------------
class CveSyncResponse(BaseModel):
    total: int
    added: int


# ----------------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------------
class SettingsView(BaseModel):
    """Editable FOFA/Shodan config. Sensitive keys are masked on read."""

    fofa_keys: str  # masked on GET
    fofa_base_url: str
    fofa_page_size: int
    fofa_max_pages: int
    fofa_timeout: float
    shodan_keys: str  # masked on GET
    shodan_base_url: str
    shodan_max_pages: int
    shodan_timeout: float
    shodan_page_delay: float
    validate_concurrency: int
    prober_concurrency: int


class SettingsUpdate(BaseModel):
    """All fields optional — only provided fields are written.

    For key fields, an all-masked value (contains "****") is treated as
    "unchanged" so a round-trip of the masked GET doesn't clobber real keys.
    """

    fofa_keys: str | None = None
    fofa_base_url: str | None = None
    fofa_page_size: int | None = None
    fofa_max_pages: int | None = None
    fofa_timeout: float | None = None
    shodan_keys: str | None = None
    shodan_base_url: str | None = None
    shodan_max_pages: int | None = None
    shodan_timeout: float | None = None
    shodan_page_delay: float | None = None
    validate_concurrency: int | None = None
    prober_concurrency: int | None = None


class SettingsUpdateResponse(BaseModel):
    updated: list[str]
    hot_reloaded: list[str]
    restart_required: list[str]
    settings: SettingsView


class FofaCheckResponse(BaseModel):
    # ok | quota_exhausted | invalid
    status: Literal["ok", "quota_exhausted", "invalid"]
    message: str = ""
    consumes_quota: bool = True


class ShodanKeyInfo(BaseModel):
    key_masked: str
    plan: str = ""
    query_credits: int = 0
    alive: bool = True


class ShodanCheckResponse(BaseModel):
    keys: list[ShodanKeyInfo] = Field(default_factory=list)
    total_query_credits: int = 0
    n_keys: int = 0
    n_dead: int = 0
    consumes_quota: bool = False
