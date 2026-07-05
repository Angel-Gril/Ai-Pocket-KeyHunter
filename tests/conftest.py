from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _disable_dedup_by_default(monkeypatch):
    """Every test runs with dedup disabled by default so the suite never depends
    on a live Redis. Tests that exercise dedup opt back in by re-patching
    `dedup_enabled` / `get_dedup_store` themselves (monkeypatch is LIFO, so a
    later setattr in the test wins)."""
    monkeypatch.setattr("aipocket.config.settings.dedup_enabled", False)


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
