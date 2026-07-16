from __future__ import annotations

from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    fofa_keys: str = ""
    fofa_base_url: str = "https://fofoapi.com"
    fofa_page_size: int = 100
    fofa_max_pages: int = 10
    fofa_timeout: float = 30.0
    fofa_query_concurrency: int = 3
    fofa_page_delay: float = 0.3

    # ===== Shodan (second data source) =====
    shodan_keys: str = ""
    shodan_base_url: str = "https://api.shodan.io"
    shodan_max_pages: int = 10
    shodan_timeout: float = 30.0
    shodan_page_delay: float = 1.0

    query_exploration_ratio: float = 0.2
    fofa_query_budget: int = 24
    shodan_query_budget: int = 16
    shodan_shard_host_budget: int = 1000
    shodan_credit_budget: int = 8

    scan_fast: bool = False
    scan_prober: bool = True
    prober_concurrency: int = 50
    # Max hosts scheduled as asyncio tasks at once. Full scans can hit 10k–30k
    # targets; creating every Task up-front OOMs small VPS boxes. Batches keep
    # peak task/client memory bounded while concurrency still governs in-flight
    # HTTP. 500 is a safe default for ~4–6GB hosts.
    prober_batch_size: int = 500
    # Per-target HTTP budget for product probers. Weak-password dict needs headroom.
    max_requests_per_target: int = 600
    # Independent budget for GenericPageProber so it cannot starve product L1 nodes.
    generic_max_requests_per_target: int = 12
    max_probe_redirects: int = 2
    min_probe_evidence_score: int = 50
    intrusive_checks: bool = False
    # Optional origin allowlist for L1+. Empty = unrestricted when intrusive_checks
    # is True (full sweep). Non-empty = exact-origin match only.
    # L1+ never runs when intrusive_checks is False, regardless of this value.
    authorized_probe_scope: str = ""
    # Vuln-class probe risk policy (comma-separated VulnClass names, or * / all).
    # Product Specs cover L0–L3; these gates decide what actually executes.
    probe_vuln_classes: str = "*"
    # Max risk 0–3. Code default 1 (L0+L1 when intrusive). Set 3 in .env for L2/L3.
    probe_max_risk: int = 1
    # L2/L3 class flags (code default off). Full-sweep .env.example turns them on;
    # still need intrusive_checks + probe_max_risk >= 2/3.
    probe_ssrf_enabled: bool = False
    probe_sqli_enabled: bool = False
    probe_rce_enabled: bool = False
    # Weak-password dictionary (password-per-line). Empty = packaged default.
    weak_password_dict_path: str = ""
    # Usernames tried with each dict password (admin first = higher ROI).
    weak_password_usernames: str = "admin,root"
    # Cap login pairs per target (0 = full dict × usernames, still budget-limited).
    weak_password_max_attempts: int = 0

    validate_concurrency: int = 20
    validate_timeout: float = 15.0

    scheduler_enabled: bool = False
    scheduler_interval: int = 3600
    scan_lock_ttl: int = 7200

    tavily_base_url: str = ""
    tavily_key: str = ""

    gpt_base_url: str = ""
    gpt_key: str = ""
    gpt_model: str = "gpt-4o-mini"
    gpt_fast: bool = False
    # reasoning_effort sent to reasoning models (e.g. grok-4.5). "high" gives the
    # best extraction quality; grok-4.5 is fast enough that low is unnecessary.
    # Set "" / "none" to omit the field for models that don't accept it.
    gpt_reasoning_effort: str = "high"
    gpt_recheck_concurrency: int = 5
    gpt_recheck_batch_size: int = 10
    # Seconds to wait between GPT extract and GPT re-check to avoid rate-limit storms
    gpt_recheck_cooldown: float = 5.0
    # When True, dump each GPT batch payload to <run>/gpt_debug/ for debugging
    # prompt/extract issues. Off by default (writes a lot of files).
    gpt_debug: bool = False
    gpt_recheck: bool = False

    results_dir: str = "results"

    # ===== Web API (FastAPI service layer) =====
    # Global password for the web UI — a single shared secret entered once on the
    # login page. Empty => the app refuses to start (see web/app.py). NEVER echoed
    # back by /api/settings and never written to logs.
    web_password: str = ""
    # HMAC secret used to sign JWT session tokens. Must be set (any long random
    # string). Empty => the app refuses to start.
    web_jwt_secret: str = ""
    # Session token lifetime in seconds (default 24h).
    web_token_ttl: int = 86400
    # CORS allowed origins (comma-separated). "*" for dev; set to the real
    # frontend origin in production.
    web_cors_origins: str = "*"
    # Directory holding the built React frontend (index.html + assets). When it
    # exists, the API mounts it as static files. Empty/missing => API only.
    web_static_dir: str = ""
    # Max scan log lines held in memory for the rolling window / SSE replay.
    web_log_buffer_lines: int = 2000

    # ===== Cross-run dedup (Redis) =====
    # When True, hosts/credentials already processed in a previous run are
    # skipped (successful validations are cached + reused; failures get a short
    # TTL so they can be retried). Disabling, or an unreachable Redis, falls
    # back to the original no-dedup behavior.
    dedup_enabled: bool = True
    dedup_redis_url: str = "redis://localhost:6379/0"
    dedup_host_ttl: int = 604800  # 7d — host already probed + GPT-extracted
    dedup_cred_ttl: int = 259200  # 3d — successful ValidationResult cached
    dedup_rejected_ttl: int = 2592000  # 30d — deterministic validation rejection
    dedup_transient_ttl: int = 21600  # 6h — network/rate-limit retry window
    dedup_balance_ttl: int = 86400  # 1d — balance query result cached

    # ===== PostgreSQL (persistent source of truth) =====
    # SQLAlchemy-style / libpq connection URL for the results/high-value/CVE
    # store. Empty => PG disabled: the app keeps using JSONL files only (the
    # original behavior), so existing deployments without a DATABASE_URL are
    # unaffected until they opt in.
    database_url: str = ""
    # Connection pool sizing (psycopg_pool.ConnectionPool).
    pg_pool_min: int = 2
    pg_pool_max: int = 10
    # Transitional dual-write: when True AND a database_url is set, writes go to
    # BOTH PostgreSQL and the legacy JSONL files. Defaults to False — PG is the
    # sole source of truth. Set True temporarily when migrating an existing
    # deployment that still needs the JSONL files written (for backfill + verify
    # + a rollback path) before committing to PG-only.
    pg_dual_write: bool = False

    # ===== Planner metrics version =====
    # 2 = rank by active_requests (validation credentials); 3 = total_active_http_requests
    # (ledger). Default 2 after WS-A; flip to 3 after shadow compare window.
    planner_metrics_version: int = 2

    # ===== GitHub artifact hunter =====
    github_hunter_enabled: bool = True
    github_tokens: str = ""
    github_api_base_url: str = "https://api.github.com"
    github_api_version: str = "2022-11-28"
    github_commit_query_budget: int = 6
    github_code_query_budget: int = 6
    github_search_page_size: int = 100
    github_max_pages_per_shard: int = 10
    github_lookback_hours: int = 24
    github_backfill_from: str = ""
    github_overlap_minutes: int = 15
    github_request_timeout: float = 20.0
    github_artifact_concurrency: int = 8
    github_max_commit_files: int = 3000
    github_max_blob_bytes: int = 1_048_576
    github_blob_fallback_budget: int = 100
    github_file_history_enabled: bool = True
    github_file_history_commit_limit: int = 100

    @field_validator("fofa_keys", "shodan_keys", "github_tokens")
    @classmethod
    def _strip_keys(cls, v: str) -> str:
        return ",".join(k.strip() for k in v.split(",") if k.strip())

    @property
    def keys(self) -> list[str]:
        return [k for k in self.fofa_keys.split(",") if k]

    @property
    def shodan_key_list(self) -> list[str]:
        return [k for k in self.shodan_keys.split(",") if k]

    @property
    def github_token_list(self) -> list[str]:
        return [k for k in self.github_tokens.split(",") if k]

    @property
    def authorized_probe_scope_list(self) -> tuple[str, ...]:
        return tuple(
            value.strip().rstrip("/")
            for value in self.authorized_probe_scope.split(",")
            if value.strip()
        )

    @property
    def results_path(self) -> Path:
        return Path(self.results_dir)

    @property
    def pg_enabled(self) -> bool:
        """True when a DATABASE_URL is configured (PG is the source of truth)."""
        return bool(self.database_url.strip())

    @property
    def write_jsonl(self) -> bool:
        """True when JSONL files should be written.

        Always True when PG is disabled. When PG is enabled, only True during the
        transitional dual-write phase (``pg_dual_write``).
        """
        return (not self.pg_enabled) or self.pg_dual_write

    @property
    def web_cors_origin_list(self) -> list[str]:
        raw = self.web_cors_origins.strip()
        if raw in ("", "*"):
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]


settings = Settings()  # type: ignore[call-arg]
