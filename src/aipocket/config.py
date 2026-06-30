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
    shodan_max_pages: int = 1
    shodan_timeout: float = 30.0
    shodan_page_delay: float = 1.0

    scan_fast: bool = False

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

    results_dir: str = "results"

    @field_validator("fofa_keys", "shodan_keys")
    @classmethod
    def _strip_keys(cls, v: str) -> str:
        return ",".join(k.strip() for k in v.split(",") if k.strip())

    @property
    def keys(self) -> list[str]:
        return [k.strip() for k in self.fofa_keys.split(",") if k.strip()]

    @property
    def shodan_key_list(self) -> list[str]:
        return [k.strip() for k in self.shodan_keys.split(",") if k.strip()]

    @property
    def results_path(self) -> Path:
        p = Path(self.results_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()  # type: ignore[call-arg]
