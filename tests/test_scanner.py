from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from aipocket.models import ValidationResult
from aipocket.scanner import _trim_hits, run_scan


@pytest.mark.asyncio
async def test_run_scan_no_hits_returns_empty(monkeypatch):
    monkeypatch.setattr("aipocket.scanner.build_queries", lambda: [{"query": "q", "cve_id": "c", "product": "p", "type": "t"}])

    mock_fofa = MagicMock()
    mock_fofa.search.return_value = []
    mock_fofa.__enter__ = MagicMock(return_value=mock_fofa)
    mock_fofa.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr("aipocket.scanner.FofaClient", lambda: mock_fofa)

    result = await run_scan(max_queries=1)
    assert result.total_hosts == 0
    assert result.total_credentials == 0
    assert result.total_valid == 0
    assert result.results == []


@pytest.mark.asyncio
async def test_run_scan_extracts_and_validates(monkeypatch):
    monkeypatch.setattr("aipocket.scanner.build_queries", lambda: [{"query": "q", "cve_id": "c", "product": "p", "type": "t"}])
    monkeypatch.setattr("aipocket.config.settings.gpt_key", "")
    monkeypatch.setattr("aipocket.config.settings.gpt_base_url", "")

    hits = [{"host": "https://a.com", "ip": "1.1.1.1", "port": "443", "header": "Bearer sk-proj-abc123def456ghi789", "banner": "", "title": "", "product": "", "cert": ""}]
    mock_fofa = MagicMock()
    mock_fofa.search.return_value = hits
    mock_fofa.__enter__ = MagicMock(return_value=mock_fofa)
    mock_fofa.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr("aipocket.scanner.FofaClient", lambda: mock_fofa)

    async def fake_validate(creds):
        return [ValidationResult(credential=c, valid=True, status_code=200, tier="tier5") for c in creds]

    monkeypatch.setattr("aipocket.scanner.validate_all", fake_validate)

    result = await run_scan(max_queries=1)
    assert result.total_hosts == 1
    assert result.total_credentials >= 1
    assert result.total_valid == result.total_credentials


def test_trim_hits_under_limit():
    hits = [{"i": i} for i in range(10)]
    assert _trim_hits(hits) == hits


def test_trim_hits_over_limit():
    hits = [{"i": i} for i in range(600)]
    trimmed = _trim_hits(hits, limit=500)
    assert len(trimmed) == 500
    assert trimmed[0]["i"] == 0
    assert trimmed[-1]["i"] == 499


def test_trim_hits_exact_limit():
    hits = [{"i": i} for i in range(500)]
    trimmed = _trim_hits(hits, limit=500)
    assert len(trimmed) == 500
