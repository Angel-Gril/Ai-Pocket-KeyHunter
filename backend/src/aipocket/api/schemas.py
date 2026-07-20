"""Pydantic request/response schemas for the web API.

Response models here are deliberately loose (extra dicts pass through) where the
underlying record shape is a plain JSONL dict — the frontend does local
search/filter over the full payload, so we favor returning everything the
business modules already produce over a rigid contract.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ScanSourceItem = Literal["fofa", "shodan", "github"]
ScanSource = Literal["fofa", "shodan", "github", "all"]
ScanMode = Literal["full", "incremental"]
_ALL_SCAN_SOURCES: frozenset[str] = frozenset({"fofa", "shodan", "github"})
GitHubPackId = Literal[
    "all",
    "glm",
    "kimi",
    "qwen",
    "cohere",
    "replicate",
    "together",
    "fireworks",
    "deepseek",
    "openai",
    "anthropic",
    "azure_openai",
    "minimax",
]
ExportFormat = Literal["json", "csv"]
ExportDataset = Literal["selected", "run", "high-value", "all"]


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


class HighValueRevealRequest(BaseModel):
    """Reveal a high-value plaintext apikey by its masked value (cross-run store)."""

    masked: str
    apiurl: str | None = None


# ----------------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------------
class ExportRequest(BaseModel):
    dataset: ExportDataset
    format: ExportFormat = "json"
    # dataset="run"      → run_id required
    # dataset="selected" → run_id + indices (preferred; server reads plaintext),
    #                      or the legacy `keys` list of explicit plaintext rows.
    # dataset="all"      → cross-run valid/suspicious (kind); optional indices
    #                      select a subset of the deduped aggregate list.
    run_id: str | None = None
    kind: Literal["valid", "suspicious"] = "valid"
    indices: list[int] = Field(default_factory=list)
    keys: list[KeyRef] = Field(default_factory=list)


# ----------------------------------------------------------------------------
# Scan
# ----------------------------------------------------------------------------
class ScanStartRequest(BaseModel):
    """Start a scan.

    Prefer ``sources`` for multi-select (e.g. FOFA + Shodan without GitHub).
    Legacy single-value ``source`` remains accepted; when both are set,
    non-empty ``sources`` wins.
    """

    source: ScanSource = "all"
    sources: list[ScanSourceItem] = Field(default_factory=list, max_length=3)
    mode: ScanMode = "incremental"
    github_pack_ids: list[GitHubPackId] = Field(default_factory=list, max_length=16)
    # Opt-in resume of an interrupted run (C8). Empty/default = new run_id.
    resume_run_id: str = ""

    def resolved_source_label(self) -> str:
        """Canonical status label: ``all`` | ``fofa`` | ``fofa,shodan`` | …"""
        if self.sources:
            items = sorted(set(self.sources))
            if set(items) >= _ALL_SCAN_SOURCES:
                return "all"
            return ",".join(items)
        return self.source


class ScanProgress(BaseModel):
    raw_hits: int = 0
    unique_targets: int = 0
    candidates: int = 0
    active_requests: int = 0
    final_verified: int = 0
    suspicious: int = 0
    high_value_final: int = 0


class ScanStatusResponse(BaseModel):
    state: str  # idle | running | stopping | finished | interrupted
    source: str | None = None
    mode: ScanMode = "incremental"
    github_pack_ids: list[GitHubPackId] = Field(default_factory=list)
    run_id: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    progress: ScanProgress = Field(default_factory=ScanProgress)
    phase: str = ""  # coarse human-readable stage for the live console
    error: str | None = None
    log_seq: int = 0  # latest log sequence number (for ?since= polling)


class ScanLogLine(BaseModel):
    seq: int
    line: str


class ScanLogsResponse(BaseModel):
    lines: list[ScanLogLine]
    last_seq: int


# ----------------------------------------------------------------------------
# GPT-failed batch retry (per-run append)
# ----------------------------------------------------------------------------
class GptFailedFileInfo(BaseModel):
    name: str
    hits: int
    batch_idx: int | None = None


class RetryGptFailedReportView(BaseModel):
    run_id: str
    failed_files: int = 0
    failed_hits: int = 0
    credentials_found: int = 0
    valid_appended: int = 0
    suspicious_appended: int = 0
    high_value_final: int = 0
    archived_files: list[str] = Field(default_factory=list)
    jsonl_paths: list[str] = Field(default_factory=list)
    message: str = ""


class RetryGptFailedJobStatus(BaseModel):
    """Background retry job snapshot (poll while state == running)."""

    state: str  # idle | running | finished | error
    run_id: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    report: RetryGptFailedReportView | None = None


class GptFailedStatusResponse(BaseModel):
    run_id: str
    failed_files: int
    failed_hits: int
    files: list[GptFailedFileInfo] = Field(default_factory=list)
    retry: RetryGptFailedJobStatus


# ----------------------------------------------------------------------------
# CVE
# ----------------------------------------------------------------------------
class CveSyncResponse(BaseModel):
    total: int
    added: int


class CveAddRequest(BaseModel):
    """Add a CVE manually from a source URL and/or explicit fields.

    Prefer ``url`` (fetched and parsed). If parse is incomplete or no URL is
    given, supply ``id`` + ``product`` (and optionally the rest).
    """

    url: str = ""
    id: str = ""
    product: str = ""
    type: str = ""
    description: str = ""
    cvss: float = 0.0
    huntable: str = ""


class CveAddResponse(BaseModel):
    created: bool
    total: int
    cve: dict[str, Any]


# ----------------------------------------------------------------------------
# Honeypot site cache
# ----------------------------------------------------------------------------
class HoneypotSite(BaseModel):
    host_key: str
    host: str = ""
    reason: str = ""
    source: str = "auto"  # auto | manual
    first_seen: str = ""
    last_seen: str = ""
    hit_count: int = 1
    run_id: str = ""
    notes: str = ""


class HoneypotListResponse(BaseModel):
    results: list[HoneypotSite] = Field(default_factory=list)
    total: int = 0
    limit: int = 200
    offset: int = 0


class HoneypotCreateRequest(BaseModel):
    host: str
    reason: str = "honeypot:manual"
    notes: str = ""


class HoneypotUpdateRequest(BaseModel):
    host_key: str
    reason: str | None = None
    notes: str | None = None


class HoneypotBulkDeleteRequest(BaseModel):
    host_keys: list[str] = Field(default_factory=list, max_length=500)


class HoneypotBulkDeleteResponse(BaseModel):
    deleted: int = 0


# ----------------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------------
class SettingsView(BaseModel):
    """Editable FOFA/Shodan/GitHub config. Sensitive keys are masked on read."""

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
    github_tokens: str = ""  # masked on GET
    github_api_base_url: str = "https://api.github.com"
    github_hunter_enabled: bool = True
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
    github_tokens: str | None = None
    github_api_base_url: str | None = None
    github_hunter_enabled: bool | None = None
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


class GithubCheckResponse(BaseModel):
    """GitHub /rate_limit connectivity snapshot (no search cost)."""

    status: Literal["ok", "invalid", "disabled"] = "invalid"
    message: str = ""
    core_remaining: int | None = None
    search_remaining: int | None = None
    code_search_remaining: int | None = None
    n_tokens: int = 0
