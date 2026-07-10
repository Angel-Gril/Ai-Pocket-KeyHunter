from __future__ import annotations

import copy
from unittest.mock import MagicMock

import pytest

from aipocket.core.models import Credential, ValidationResult
from aipocket.services.scanner import _trim_hits, run_scan

FOFA_KEY = "Bearer sk-proj-abc123def456ghi789"


def _make_mock_client(hits):
    """A MagicMock client usable as a context manager returning `hits` per search()."""
    mock = MagicMock()
    mock.search.return_value = hits
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    return mock


@pytest.mark.asyncio
async def test_run_scan_fofa_and_shodan_both_run(tmp_path, monkeypatch):
    """One scan walks BOTH sources and merges their hits."""
    monkeypatch.setattr(
        "aipocket.services.scanner.build_queries",
        lambda **kw: [{"query": "q", "cve_id": "c", "product": "p", "type": "t"}],
    )
    monkeypatch.setattr(
        "aipocket.services.shodan_queries.build_shodan_queries",
        lambda **kw: [{"query": "sq", "cve_id": "sc", "product": "sp", "type": "t"}],
    )
    # Enable both sources
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "sk")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_base_url", "")
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))

    fofa_hits = [
        {"host": "https://a.com", "ip": "1.1.1.1", "port": "443",
         "header": f"Bearer {FOFA_KEY}", "banner": "", "title": "", "product": "", "cert": ""}
    ]
    shodan_hits = [
        {"host": "https://b.com", "ip": "2.2.2.2", "port": "443",
         "header": f"Bearer {FOFA_KEY}", "banner": "", "title": "", "product": "", "cert": ""}
    ]

    monkeypatch.setattr("aipocket.services.scanner.FofaClient", lambda: _make_mock_client(fofa_hits))
    monkeypatch.setattr("aipocket.clients.shodan.ShodanClient", lambda: _make_mock_client(shodan_hits))

    async def fake_validate(creds):
        return [ValidationResult(credential=c, valid=True, status_code=200, tier="tier5") for c in creds]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", fake_validate)

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
async def test_run_scan_same_key_from_both_sources_merges_backend(tmp_path, monkeypatch):
    """When both sources find the same apikey+url, the credential keeps both backends."""
    monkeypatch.setattr("aipocket.services.scanner.build_queries", lambda **kw: [{"query": "q", "cve_id": "c", "product": "p", "type": "t"}])
    monkeypatch.setattr("aipocket.services.shodan_queries.build_shodan_queries", lambda **kw: [{"query": "sq", "cve_id": "sc", "product": "sp", "type": "t"}])
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "sk")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_key", "")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_base_url", "")
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))

    same_hits = [
        {"host": "https://a.com", "ip": "1.1.1.1", "port": "443",
         "header": f"Bearer {FOFA_KEY}", "banner": "", "title": "", "product": "", "cert": ""}
    ]
    # distinct dict objects per source (the scanner tags each hit with _source)
    monkeypatch.setattr("aipocket.services.scanner.FofaClient", lambda: _make_mock_client(copy.deepcopy(same_hits)))
    monkeypatch.setattr("aipocket.clients.shodan.ShodanClient", lambda: _make_mock_client(copy.deepcopy(same_hits)))

    async def fake_validate(creds):
        return [ValidationResult(credential=c, valid=True, status_code=200) for c in creds]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", fake_validate)

    result = await run_scan(max_queries=1)
    assert result.total_credentials == 1
    # Backend should record both discovery sources
    assert "fofa" in result.results[0].credential.backend
    assert "shodan" in result.results[0].credential.backend


@pytest.mark.asyncio
async def test_run_scan_fofa_only_when_shodan_unconfigured(tmp_path, monkeypatch):
    monkeypatch.setattr("aipocket.services.scanner.build_queries", lambda **kw: [{"query": "q", "cve_id": "c", "product": "p", "type": "t"}])
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_key", "")
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))

    monkeypatch.setattr("aipocket.services.scanner.FofaClient", lambda: _make_mock_client([]))

    result = await run_scan(max_queries=1)
    assert result.sources == ["fofa"] or result.sources == []  # fofa ran (0 hits)
    assert "shodan" not in result.sources


@pytest.mark.asyncio
async def test_run_scan_no_source_configured_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
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


# ---------------------------------------------------------------------------
# Cross-run dedup behavior
# ---------------------------------------------------------------------------


def _scan_mocks(monkeypatch, tmp_path, *, fofa_hits, shodan_hits):
    """Wire the standard scan mocks shared by the dedup tests below."""
    monkeypatch.setattr(
        "aipocket.services.scanner.build_queries",
        lambda **kw: [{"query": "q", "cve_id": "c", "product": "p", "type": "t"}],
    )
    monkeypatch.setattr(
        "aipocket.services.shodan_queries.build_shodan_queries",
        lambda **kw: [{"query": "sq", "cve_id": "sc", "product": "sp", "type": "t"}],
    )
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "sk")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_key", "")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_base_url", "")
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
    monkeypatch.setattr("aipocket.services.scanner.FofaClient", lambda: _make_mock_client(fofa_hits))
    monkeypatch.setattr(
        "aipocket.clients.shodan.ShodanClient", lambda: _make_mock_client(shodan_hits)
    )


@pytest.mark.asyncio
async def test_dedup_second_run_skips_cached_valid_credential(tmp_path, monkeypatch):
    """A credential validated in run 1 is reused from cache in run 2 — validate_all
    is NOT called for it on the second run."""
    fakeredis = pytest.importorskip("fakeredis")
    from aipocket.services.dedup import RedisDedupStore

    store = RedisDedupStore(fakeredis.FakeAsyncRedis(decode_responses=True))
    monkeypatch.setattr("aipocket.services.scanner.get_dedup_store", lambda: _returning(store))

    hits = [
        {"host": "https://a.com", "ip": "1.1.1.1", "port": "443",
         "header": f"Bearer {FOFA_KEY}", "banner": "", "title": "", "product": "", "cert": ""}
    ]
    _scan_mocks(monkeypatch, tmp_path, fofa_hits=hits, shodan_hits=[])

    validate_calls: list[list[Credential]] = []

    async def counting_validate(creds):
        validate_calls.append(list(creds))
        return [ValidationResult(credential=c, valid=True, status_code=200, tier="tier5") for c in creds]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", counting_validate)

    await run_scan(max_queries=1)
    await run_scan(max_queries=1)

    # First run validated the cred; second run served it from cache.
    assert len(validate_calls) == 1
    assert len(validate_calls[0]) == 1


@pytest.mark.asyncio
async def test_dedup_recently_failed_cred_skipped_same_run(tmp_path, monkeypatch):
    """A cred marked failed within the dedup window is not re-validated on a
    subsequent run (short-TTL retry semantics)."""
    fakeredis = pytest.importorskip("fakeredis")
    from aipocket.services.dedup import RedisDedupStore

    store = RedisDedupStore(fakeredis.FakeAsyncRedis(decode_responses=True))
    # Pre-seed the cred as recently failed. apiurl matches what the extractor
    # derives from the host (it populates apiurl from host when none in header).
    cred = Credential(apikey="sk-proj-abc123def456ghi789", apiurl="https://a.com", host="https://a.com")
    await store.mark_failed(cred)
    monkeypatch.setattr("aipocket.services.scanner.get_dedup_store", lambda: _returning(store))

    hits = [
        {"host": "https://a.com", "ip": "1.1.1.1", "port": "443",
         "header": f"Bearer {FOFA_KEY}", "banner": "", "title": "", "product": "", "cert": ""}
    ]
    _scan_mocks(monkeypatch, tmp_path, fofa_hits=hits, shodan_hits=[])

    validated: list[Credential] = []

    async def counting_validate(creds):
        validated.extend(creds)
        return [ValidationResult(credential=c, valid=False) for c in creds]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", counting_validate)

    result = await run_scan(max_queries=1)
    # The failed cred was skipped, so nothing reached validate_all.
    assert validated == []
    assert result.total_valid == 0


async def test_scanner_passes_forged_key_verdicts_to_finalizer(tmp_path, monkeypatch):
    hits = [
        {"host": "https://a.com", "ip": "1.1.1.1", "port": "443",
         "header": f"Bearer {FOFA_KEY}", "banner": "", "title": "", "product": "", "cert": ""}
    ]
    _scan_mocks(monkeypatch, tmp_path, fofa_hits=hits, shodan_hits=[])
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.scan_prober", False)
    monkeypatch.setattr("aipocket.core.config.settings.gpt_recheck", False)

    async def fake_validate(creds):
        return [ValidationResult(credential=c, valid=True, status_code=200) for c in creds]

    async def fake_verdicts(results):
        return {results[0].credential.host}, set()

    monkeypatch.setattr("aipocket.services.scanner.validate_all", fake_validate)
    monkeypatch.setattr("aipocket.services.validator.verify_no_auth", fake_verdicts)

    result = await run_scan(max_queries=1)

    assert result.total_valid == 0


class _returning:
    """Awaitable wrapper so `await get_dedup_store()` returns the cached store."""

    def __init__(self, store):
        self._store = store

    def __await__(self):
        async def _get():
            return self._store
        return _get().__await__()
