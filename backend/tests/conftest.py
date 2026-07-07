from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Neutralize PostgreSQL config for the whole test session BEFORE anything imports
# aipocket.config (which builds the `settings` singleton at import time). The
# developer's .env may set DATABASE_URL; an empty env var takes priority over the
# .env file in pydantic-settings, so every Settings() built during tests — the
# singleton AND fresh instances constructed inside tests — sees PG as disabled.
# Without this the suite would block trying to reach a Postgres that isn't up in
# the test process, and JSONL writes (which most tests assert) would be turned
# off. Tests that exercise the PG paths opt in explicitly via a fake pool.
os.environ["DATABASE_URL"] = ""
os.environ["PG_DUAL_WRITE"] = "false"


@pytest.fixture(autouse=True)
def _disable_dedup_by_default(monkeypatch):
    """Every test runs with dedup disabled by default so the suite never depends
    on a live Redis. Tests that exercise dedup opt back in by re-patching
    `dedup_enabled` / `get_dedup_store` themselves (monkeypatch is LIFO, so a
    later setattr in the test wins)."""
    monkeypatch.setattr("aipocket.core.config.settings.dedup_enabled", False)


@pytest.fixture(autouse=True)
def _disable_pg_by_default(monkeypatch):
    """Belt-and-suspenders guard for the `settings` singleton.

    The session-level env neutralization above already keeps every fresh
    ``Settings()`` PG-free, but if the singleton was imported before this module
    ran (import ordering), its fields were parsed from the .env. Re-clear the two
    inputs ``pg_enabled`` / ``write_jsonl`` derive from so the singleton also
    reports PG disabled.

    ``pg_enabled`` / ``write_jsonl`` are read-only computed properties, so we
    override those inputs rather than the properties themselves. Tests for the PG
    code paths opt back in by setting ``database_url`` + monkeypatching
    ``aipocket.db.get_pool`` with a fake pool (monkeypatch is LIFO, so a later
    setattr in the test wins)."""
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    monkeypatch.setattr("aipocket.core.config.settings.pg_dual_write", False)


@pytest.fixture
def sample_cves() -> list[dict[str, Any]]:
    return [
        {
            "id": "CVE-2026-32625",
            "cvss": 9.6,
            "product": "LibreChat",
            "type": "API key泄露",
            "description": "LibreChat MCP server integration resolves env var placeholders.",
            "huntable": "高",
            "date": "2026-06-04",
        },
        {
            "id": "CVE-2026-35030",
            "cvss": 9.1,
            "product": "LiteLLM (AI Gateway)",
            "type": "认证绕过",
            "description": "OIDC userinfo cache collision.",
            "huntable": "高",
            "date": "2026-04-08",
        },
        {
            "id": "CVE-2026-5497",
            "cvss": 7.5,
            "product": "vLLM",
            "type": "DoS",
            "description": "OOM via video frames.",
            "huntable": "中",
            "date": "2026-06-15",
        },
    ]


@pytest.fixture
def fofa_row_factory():
    def _make(
        host: str = "https://example.com",
        ip: str = "1.2.3.4",
        port: str = "443",
        header: str = "",
        banner: str = "",
        title: str = "",
        product: str = "",
    ) -> list[str]:
        return [host, ip, port, header, banner, product, title]

    return _make


@pytest.fixture
def fofa_response_factory():
    def _make(rows: list[list[str]], fields: str = "host,ip,port,header,banner,product,title", size: int = 100):
        return {
            "error": False,
            "consumed_fpoint": 0,
            "required_fpoints": 0,
            "size": size,
            "tip": "",
            "page": 1,
            "mode": "extended",
            "query": "test",
            "results": rows,
        }

    return _make


@pytest.fixture
def real_cves() -> list[dict[str, Any]]:
    p = ROOT / "sources" / "cve_2026_ai.json"
    if not p.exists():
        pytest.skip(f"{p} not found")
    return json.loads(p.read_text(encoding="utf-8"))


def b64q(query: str) -> str:
    return base64.b64encode(query.encode()).decode()
