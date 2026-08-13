from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).resolve().parent / "data"

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class Settings:
    fofa_key: str
    fofa_email: str
    fofa_base_url: str
    fofa_page_size: int
    fofa_max_pages: int
    proxy: str | None
    timeout: float
    concurrency: int

    @classmethod
    def load(cls, env_file: Path | None = None) -> Settings:
        load_dotenv(env_file or ROOT / ".env", override=False)
        return cls(
            fofa_key=os.getenv("FOFA_KEY", "").strip(),
            fofa_email=os.getenv("FOFA_EMAIL", "").strip(),
            fofa_base_url=os.getenv("FOFA_BASE_URL", "https://fofa.info").rstrip("/"),
            fofa_page_size=int(os.getenv("FOFA_PAGE_SIZE", "100")),
            fofa_max_pages=int(os.getenv("FOFA_MAX_PAGES", "3")),
            proxy=(os.getenv("KEYHUNTER_PROXY") or "").strip() or None,
            timeout=float(os.getenv("KEYHUNTER_TIMEOUT", "12")),
            concurrency=int(os.getenv("KEYHUNTER_CONCURRENCY", "8")),
        )


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
