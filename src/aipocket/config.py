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

    scan_fast: bool = False
    scan_prober: bool = True
    prober_concurrency: int = 50

    validate_concurrency: int = 20
    validate_timeout: float = 15.0

    scheduler_enabled: bool = False
    scheduler_interval: int = 3600

    tavily_base_url: str = ""
    tavily_key: str = ""

    gpt_base_url: str = ""
    gpt_key: str = ""
    gpt_model: str = "gpt-4o-mini"
    gpt_fast: bool = False
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
    dedup_host_ttl: int = 604800    # 7d — host already probed + GPT-extracted
    dedup_cred_ttl: int = 259200    # 3d — successful ValidationResult cached
    dedup_fail_ttl: int = 21600     # 6h — failed cred, retried after this
    dedup_balance_ttl: int = 86400  # 1d — balance query result cached

    @field_validator("fofa_keys", "shodan_keys")
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
    def results_path(self) -> Path:
        return Path(self.results_dir)

    @property
    def web_cors_origin_list(self) -> list[str]:
        raw = self.web_cors_origins.strip()
        if raw in ("", "*"):
            return ["*"]
        return [o.strip() for o in raw.split(",") if o.strip()]


settings = Settings()  # type: ignore[call-arg]
