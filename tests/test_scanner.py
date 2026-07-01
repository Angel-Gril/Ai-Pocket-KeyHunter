from __future__ import annotations

import copy
from unittest.mock import MagicMock

import pytest

from aipocket.models import ValidationResult
from aipocket.scanner import _trim_hits, run_scan

FOFA_KEY = "Bearer sk-proj-abc123def456ghi789"


def _make_mock_client(hits):
    """A MagicMock client usable as a context manager returning `hits` per search()."""
    mock = MagicMock()
    mock.search.return_value = hits
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    return mock


@pytest.mark.asyncio
async def test_run_scan_fofa_and_shodan_both_run(monkeypatch):
    """One scan walks BOTH sources and merges their hits."""
    monkeypatch.setattr(
        "aipocket.scanner.build_queries",
        lambda **kw: [{"query": "q", "cve_id": "c", "product": "p", "type": "t"}],
    )
    monkeypatch.setattr(
        "aipocket.shodan_queries.build_shodan_queries",
        lambda **kw: [{"query": "sq", "cve_id": "sc", "product": "sp", "type": "t"}],
    )
    # Enable both sources
    monkeypatch.setattr("aipocket.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.config.settings.shodan_keys", "sk")
    monkeypatch.setattr("aipocket.config.settings.gpt_key", "")
    monkeypatch.setattr("aipocket.config.settings.gpt_base_url", "")

    fofa_hits = [
        {"host": "https://a.com", "ip": "1.1.1.1", "port": "443",
         "header": f"Bearer {FOFA_KEY}", "banner": "", "title": "", "product": "", "cert": ""}
    ]
    shodan_hits = [
        {"host": "https://b.com", "ip": "2.2.2.2", "port": "443",
         "header": f"Bearer {FOFA_KEY}", "banner": "", "title": "", "product": "", "cert": ""}
    ]

    monkeypatch.setattr("aipocket.scanner.FofaClient", lambda: _make_mock_client(fofa_hits))
    monkeypatch.setattr("aipocket.shodan_client.ShodanClient", lambda: _make_mock_client(shodan_hits))

    async def fake_validate(creds):
        return [ValidationResult(credential=c, valid=True, status_code=200, tier="tier5") for c in creds]

    monkeypatch.setattr("aipocket.scanner.validate_all", fake_validate)

    result = await run_scan(max_queries=1)

    # Both sources contributed
    assert "fofa" in result.sources
    assert "shodan" in result.sources
    assert result.hits_by_source == {"fofa": 1, "shodan": 1}
    assert result.total_hosts == 2
    # The same key from both hosts -> 2 distinct creds, each tagged with its backend
    assert result.total_credentials == 2
    backends = {r.credential.backend for r in result.results}
    assert backends == {"fofa", "shodan"}


@pytest.mark.asyncio
async def test_run_scan_same_key_from_both_sources_merges_backend(monkeypatch):
    """When both sources find the same apikey+url, the credential keeps both backends."""
    monkeypatch.setattr("aipocket.scanner.build_queries", lambda **kw: [{"query": "q", "cve_id": "c", "product": "p", "type": "t"}])
    monkeypatch.setattr("aipocket.shodan_queries.build_shodan_queries", lambda **kw: [{"query": "sq", "cve_id": "sc", "product": "sp", "type": "t"}])
    monkeypatch.setattr("aipocket.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.config.settings.shodan_keys", "sk")
    monkeypatch.setattr("aipocket.config.settings.gpt_key", "")
    monkeypatch.setattr("aipocket.config.settings.gpt_base_url", "")

    same_hits = [
        {"host": "https://a.com", "ip": "1.1.1.1", "port": "443",
         "header": f"Bearer {FOFA_KEY}", "banner": "", "title": "", "product": "", "cert": ""}
    ]
    # distinct dict objects per source (the scanner tags each hit with _source)
    monkeypatch.setattr("aipocket.scanner.FofaClient", lambda: _make_mock_client(copy.deepcopy(same_hits)))
    monkeypatch.setattr("aipocket.shodan_client.ShodanClient", lambda: _make_mock_client(copy.deepcopy(same_hits)))

    async def fake_validate(creds):
        return [ValidationResult(credential=c, valid=True, status_code=200) for c in creds]

    monkeypatch.setattr("aipocket.scanner.validate_all", fake_validate)

    result = await run_scan(max_queries=1)
    assert result.total_credentials == 1
    # Backend should record both discovery sources
    assert "fofa" in result.results[0].credential.backend
    assert "shodan" in result.results[0].credential.backend


@pytest.mark.asyncio
async def test_run_scan_fofa_only_when_shodan_unconfigured(monkeypatch):
    monkeypatch.setattr("aipocket.scanner.build_queries", lambda **kw: [{"query": "q", "cve_id": "c", "product": "p", "type": "t"}])
    monkeypatch.setattr("aipocket.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.config.settings.gpt_key", "")

    monkeypatch.setattr("aipocket.scanner.FofaClient", lambda: _make_mock_client([]))

    result = await run_scan(max_queries=1)
    assert result.sources == ["fofa"] or result.sources == []  # fofa ran (0 hits)
    assert "shodan" not in result.sources


@pytest.mark.asyncio
async def test_run_scan_no_source_configured_raises(monkeypatch):
    monkeypatch.setattr("aipocket.config.settings.fofa_keys", "")
    monkeypatch.setattr("aipocket.config.settings.shodan_keys", "")
    with pytest.raises(RuntimeError):
        await run_scan(max_queries=1)


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
