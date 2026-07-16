from __future__ import annotations

import copy
from unittest.mock import MagicMock

import pytest

from aipocket.core.models import Credential, ValidationResult
from aipocket.core.targets import canonicalize_hits
from aipocket.services.scanner import (
    QueryBudgets,
    _complete_ledger,
    _fetch_fofa,
    _fetch_shodan,
    _trim_hits,
    run_scan,
)

FOFA_KEY = "Bearer sk-proj-abc123def456ghi789"


def _make_mock_client(hits):
    """A MagicMock client usable as a context manager returning `hits` per search()."""
    mock = MagicMock()
    mock.search.return_value = hits
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    return mock


def test_fofa_fetch_preserves_complete_query_provenance(monkeypatch):
    query = {
        "query": "product=example",
        "cve_id": "CVE-1",
        "product": "example",
        "type": "product",
        "advisory_ids": ["CVE-1", "CVE-2"],
        "product_hints": ["example", "example-ai"],
    }
    monkeypatch.setattr("aipocket.services.scanner.build_queries", lambda **kw: [query])
    monkeypatch.setattr(
        "aipocket.services.scanner.FofaClient",
        lambda: _make_mock_client([{"host": "example.com", "protocol": "https"}]),
    )

    hits, _ = _fetch_fofa(max_queries=1)
    target = canonicalize_hits(hits)[0]

    assert target.advisory_ids == frozenset({"CVE-1", "CVE-2"})
    assert target.product_hints == frozenset({"example", "example-ai"})


def test_shodan_fetch_preserves_complete_query_provenance(monkeypatch):
    query = {
        "query": 'http.title:"example"',
        "cve_id": "CVE-1",
        "product": "example",
        "type": "product",
        "advisory_ids": ["CVE-1", "CVE-2"],
        "product_hints": ["example", "example-ai"],
    }
    client = _make_mock_client([{"host": "example.com", "protocol": "https"}])
    client.info.return_value = {}
    client.count.return_value = 1
    monkeypatch.setattr(
        "aipocket.services.shodan_queries.build_shodan_queries", lambda **kw: [query]
    )
    monkeypatch.setattr("aipocket.clients.shodan.ShodanClient", lambda: client)

    hits, _ = _fetch_shodan(max_queries=1)
    target = canonicalize_hits(hits)[0]

    assert target.advisory_ids == frozenset({"CVE-1", "CVE-2"})
    assert target.product_hints == frozenset({"example", "example-ai"})


def test_complete_ledger_rejects_stale_instrumentation_version(monkeypatch):
    from aipocket.core.request_ledger import RequestLedger

    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/test")
    monkeypatch.setattr("aipocket.services.http_transport.HTTP_INSTRUMENTATION_VERSION", 0)
    ledger = RequestLedger(run_id="run_old", on_flush=lambda _batch: None)

    total, complete, reason = _complete_ledger(ledger)

    assert total == 0
    assert complete is False
    assert reason == "http_instrumentation_incomplete"


@pytest.mark.asyncio
async def test_run_scan_creates_parent_before_fetch_without_run_dir(monkeypatch):
    from aipocket.core.metrics import QueryUsage
    from aipocket.discovery.base import SourceFetchResult

    events: list[str] = []
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/test")
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "key")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.scan_prober", False)
    monkeypatch.setattr("aipocket.core.config.settings.gpt_key", "")
    monkeypatch.setattr(
        "aipocket.services.writer.create_run_pg",
        lambda *_args: events.append("parent"),
    )
    monkeypatch.setattr(
        "aipocket.services.writer.persist_ledger_batch_pg",
        lambda *_args: events.append("ledger"),
    )
    monkeypatch.setattr(
        "aipocket.services.writer.persist_run_pg",
        lambda *_args: events.append("finished"),
    )
    monkeypatch.setattr(
        "aipocket.services.writer.mark_run_interrupted_pg",
        lambda *_args: events.append("interrupted"),
    )

    async def fake_fetch_all(*_args, **_kwargs):
        events.append("fetch")
        return [SourceFetchResult(source="fofa", query_usage=(QueryUsage(query="q"),))]

    monkeypatch.setattr("aipocket.discovery.registry.SourceRegistry.fetch_all", fake_fetch_all)

    await run_scan(sources={"fofa"})

    assert events == ["parent", "fetch", "finished"]


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
        {
            "host": "https://a.com",
            "ip": "1.1.1.1",
            "port": "443",
            "header": f"Bearer {FOFA_KEY}",
            "banner": "",
            "title": "",
            "product": "",
            "cert": "",
        }
    ]
    shodan_hits = [
        {
            "host": "https://b.com",
            "ip": "2.2.2.2",
            "port": "443",
            "header": f"Bearer {FOFA_KEY}",
            "banner": "",
            "title": "",
            "product": "",
            "cert": "",
        }
    ]

    monkeypatch.setattr(
        "aipocket.services.scanner.FofaClient", lambda: _make_mock_client(fofa_hits)
    )
    monkeypatch.setattr(
        "aipocket.clients.shodan.ShodanClient", lambda: _make_mock_client(shodan_hits)
    )

    async def fake_validate(creds, **kwargs):
        return [
            ValidationResult(credential=c, valid=True, status_code=200, tier="tier5") for c in creds
        ]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", fake_validate)

    result = await run_scan(query_budgets=QueryBudgets(1, 1))

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

    same_hits = [
        {
            "host": "https://a.com",
            "ip": "1.1.1.1",
            "port": "443",
            "header": f"Bearer {FOFA_KEY}",
            "banner": "",
            "title": "",
            "product": "",
            "cert": "",
        }
    ]
    # distinct dict objects per source (the scanner tags each hit with _source)
    monkeypatch.setattr(
        "aipocket.services.scanner.FofaClient", lambda: _make_mock_client(copy.deepcopy(same_hits))
    )
    monkeypatch.setattr(
        "aipocket.clients.shodan.ShodanClient", lambda: _make_mock_client(copy.deepcopy(same_hits))
    )

    async def fake_validate(creds, **kwargs):
        return [ValidationResult(credential=c, valid=True, status_code=200) for c in creds]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", fake_validate)

    result = await run_scan(query_budgets=QueryBudgets(1, 1))
    assert result.total_credentials == 1
    # Backend should record both discovery sources
    assert "fofa" in result.results[0].credential.backend
    assert "shodan" in result.results[0].credential.backend


@pytest.mark.asyncio
async def test_run_scan_probes_unique_targets_and_reports_discovery_counts(tmp_path, monkeypatch):
    same_endpoint = [{"host": "example.com:443", "protocol": "https", "header": "", "banner": ""}]
    _scan_mocks(
        monkeypatch,
        tmp_path,
        fofa_hits=copy.deepcopy(same_endpoint),
        shodan_hits=[
            {"host": "https://EXAMPLE.com", "protocol": "https", "header": "", "banner": ""}
        ],
    )
    monkeypatch.setattr("aipocket.core.config.settings.gpt_base_url", "")
    from aipocket.prober.runner import ProbeReport, ProbeStatus, ProbeTargetOutcome

    probed = []

    async def capture_probe(targets, allowed_products):
        probed.extend(targets)
        return ProbeReport(
            credentials=(),
            outcomes=tuple(
                ProbeTargetOutcome(
                    identity_hash=target.identity.identity_hash,
                    status=ProbeStatus.SKIPPED,
                    request_count=0,
                    prober="generic",
                )
                for target in targets
            ),
        )

    monkeypatch.setattr("aipocket.prober.probe_hosts", capture_probe)
    (tmp_path / "run_test").mkdir()

    result = await run_scan(query_budgets=QueryBudgets(1, 1), run_dir=tmp_path / "run_test")

    assert len(probed) == 1
    assert result.total_hosts == 1
    import json

    scan_path = next((tmp_path / "run_test").glob("scan_*.jsonl"))
    metadata = json.loads(scan_path.read_text().splitlines()[0])
    assert metadata["raw_hits"] == 2
    assert metadata["unique_targets"] == 1


@pytest.mark.asyncio
async def test_run_scan_preserves_exact_source_query_pairs_for_merged_target(tmp_path, monkeypatch):
    same_endpoint = [{"host": "https://example.com", "protocol": "https"}]
    _scan_mocks(
        monkeypatch,
        tmp_path,
        fofa_hits=copy.deepcopy(same_endpoint),
        shodan_hits=copy.deepcopy(same_endpoint),
    )
    monkeypatch.setattr("aipocket.core.config.settings.scan_prober", False)
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/test")
    monkeypatch.setattr("aipocket.services.writer.create_run_pg", lambda *_args: None)
    monkeypatch.setattr("aipocket.services.writer.persist_ledger_batch_pg", lambda *_args: None)
    monkeypatch.setattr("aipocket.services.scanner.load_query_history", lambda _source: ())
    persisted_metrics = []

    def capture_persist(
        _run_id,
        _metadata,
        _valid,
        _suspicious,
        metrics,
        _validation_outcomes=None,
        _observation_counts=None,
    ):
        persisted_metrics.extend(metrics)

    monkeypatch.setattr("aipocket.services.writer.persist_run_pg", capture_persist)
    run_dir = tmp_path / "run_test"
    run_dir.mkdir()

    await run_scan(query_budgets=QueryBudgets(1, 1), run_dir=run_dir)

    rows = {
        (metric.source, metric.query): metric.funnel.unique_targets
        for metric in persisted_metrics
        if metric.funnel.unique_targets
    }
    assert rows == {("fofa", "q"): 1, ("shodan", "sq"): 1}


@pytest.mark.asyncio
async def test_run_scan_fofa_only_when_shodan_unconfigured(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "aipocket.services.scanner.build_queries",
        lambda **kw: [{"query": "q", "cve_id": "c", "product": "p", "type": "t"}],
    )
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_key", "")
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))

    monkeypatch.setattr("aipocket.services.scanner.FofaClient", lambda: _make_mock_client([]))

    result = await run_scan(query_budgets=QueryBudgets(1, 1))
    assert result.sources == ["fofa"] or result.sources == []  # fofa ran (0 hits)
    assert "shodan" not in result.sources


@pytest.mark.asyncio
async def test_run_scan_no_source_configured_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
    with pytest.raises(RuntimeError):
        await run_scan(query_budgets=QueryBudgets(1, 1))


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
    monkeypatch.setattr(
        "aipocket.services.scanner.FofaClient", lambda: _make_mock_client(fofa_hits)
    )
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
        {
            "host": "https://a.com",
            "ip": "1.1.1.1",
            "port": "443",
            "header": f"Bearer {FOFA_KEY}",
            "banner": "",
            "title": "",
            "product": "",
            "cert": "",
        }
    ]
    _scan_mocks(monkeypatch, tmp_path, fofa_hits=hits, shodan_hits=[])

    validate_calls: list[list[Credential]] = []

    async def counting_validate(creds, **kwargs):
        validate_calls.append(list(creds))
        return [
            ValidationResult(credential=c, valid=True, status_code=200, tier="tier5") for c in creds
        ]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", counting_validate)

    await run_scan(query_budgets=QueryBudgets(1, 1))
    await run_scan(query_budgets=QueryBudgets(1, 1))

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
    cred = Credential(
        apikey="sk-proj-abc123def456ghi789", apiurl="https://a.com", host="https://a.com"
    )
    await store.mark_failure(cred, "rejected")
    monkeypatch.setattr("aipocket.services.scanner.get_dedup_store", lambda: _returning(store))

    hits = [
        {
            "host": "https://a.com",
            "ip": "1.1.1.1",
            "port": "443",
            "header": f"Bearer {FOFA_KEY}",
            "banner": "",
            "title": "",
            "product": "",
            "cert": "",
        }
    ]
    _scan_mocks(monkeypatch, tmp_path, fofa_hits=hits, shodan_hits=[])

    validated: list[Credential] = []

    async def counting_validate(creds, **kwargs):
        validated.extend(creds)
        return [ValidationResult(credential=c, valid=False) for c in creds]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", counting_validate)

    result = await run_scan(query_budgets=QueryBudgets(1, 1))
    # The failed cred was skipped, so nothing reached validate_all.
    assert validated == []
    assert result.total_valid == 0


async def test_scanner_passes_forged_key_verdicts_to_finalizer(tmp_path, monkeypatch):
    hits = [
        {
            "host": "https://a.com",
            "ip": "1.1.1.1",
            "port": "443",
            "header": f"Bearer {FOFA_KEY}",
            "banner": "",
            "title": "",
            "product": "",
            "cert": "",
        }
    ]
    _scan_mocks(monkeypatch, tmp_path, fofa_hits=hits, shodan_hits=[])
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.scan_prober", False)
    monkeypatch.setattr("aipocket.core.config.settings.gpt_recheck", False)

    async def fake_validate(creds, **kwargs):
        return [ValidationResult(credential=c, valid=True, status_code=200) for c in creds]

    async def fake_verdicts(results, **kwargs):
        return {results[0].credential.host}, set()

    monkeypatch.setattr("aipocket.services.scanner.validate_all", fake_validate)
    monkeypatch.setattr("aipocket.services.validator.verify_no_auth", fake_verdicts)

    result = await run_scan(query_budgets=QueryBudgets(1, 1))

    assert result.total_valid == 0


@pytest.mark.asyncio
async def test_scanner_marks_only_probe_targets_with_real_requests(tmp_path, monkeypatch):
    from aipocket.prober.runner import ProbeReport, ProbeStatus, ProbeTargetOutcome
    from aipocket.services.dedup import NoopDedupStore

    hits = [
        {"host": "https://attempted.example", "protocol": "https"},
        {"host": "https://rejected.example", "protocol": "https"},
    ]
    _scan_mocks(monkeypatch, tmp_path, fofa_hits=hits, shodan_hits=[])
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")

    class TrackingDedup(NoopDedupStore):
        def __init__(self):
            self.marked: list[tuple[str, str]] = []

        async def mark_target(self, stage, target):
            self.marked.append((stage, target.identity.identity_hash))

    store = TrackingDedup()
    monkeypatch.setattr("aipocket.services.scanner.get_dedup_store", lambda: _returning(store))

    async def fake_probe(targets, allowed_products):
        return ProbeReport(
            credentials=(),
            outcomes=(
                ProbeTargetOutcome(
                    identity_hash=targets[0].identity.identity_hash,
                    status=ProbeStatus.ATTEMPTED,
                    request_count=1,
                    prober="generic",
                ),
                ProbeTargetOutcome(
                    identity_hash=targets[1].identity.identity_hash,
                    status=ProbeStatus.REJECTED_BY_EVIDENCE,
                    request_count=0,
                    prober="",
                ),
            ),
        )

    monkeypatch.setattr("aipocket.prober.probe_hosts", fake_probe)

    await run_scan(query_budgets=QueryBudgets(1, 1))

    expected = canonicalize_hits(hits)[0].identity.identity_hash
    assert store.marked == [("probe", expected)]


class _returning:
    """Awaitable wrapper so `await get_dedup_store()` returns the cached store."""

    def __init__(self, store):
        self._store = store

    def __await__(self):
        async def _get():
            return self._store

        return _get().__await__()


@pytest.mark.asyncio
async def test_gpt_sampling_filters_seen_before_applying_limit() -> None:
    from aipocket.services.dedup import NoopDedupStore
    from aipocket.services.scanner import _select_gpt_targets

    targets = canonicalize_hits(
        [
            {
                "host": f"https://target-{index}.example",
                "protocol": "https",
                "banner": "rich response body",
                "_source": "shodan",
            }
            for index in range(6)
        ]
    )

    class SeenFirstTwo(NoopDedupStore):
        async def filter_unseen_targets(self, stage, candidates):
            assert stage == "gpt"
            return candidates[2:]

    selected = await _select_gpt_targets(targets, SeenFirstTwo(), limit=3)

    assert [target.identity.hostname for target in selected] == [
        "target-2.example",
        "target-3.example",
        "target-4.example",
    ]


@pytest.mark.asyncio
async def test_scanner_marks_only_successful_gpt_entries(tmp_path, monkeypatch) -> None:
    from aipocket.prober.runner import ProbeReport
    from aipocket.services.analyzer import GPTExtractionReport
    from aipocket.services.dedup import NoopDedupStore

    hits = [
        {
            "host": f"https://gpt-{index}.example",
            "protocol": "https",
            "banner": "rich response body",
        }
        for index in range(2)
    ]
    _scan_mocks(monkeypatch, tmp_path, fofa_hits=hits, shodan_hits=[])
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")

    class TrackingDedup(NoopDedupStore):
        def __init__(self):
            self.marked: list[tuple[str, str]] = []

        async def mark_target(self, stage, target):
            self.marked.append((stage, target.identity.identity_hash))

    store = TrackingDedup()
    monkeypatch.setattr("aipocket.services.scanner.get_dedup_store", lambda: _returning(store))
    monkeypatch.setattr(
        "aipocket.prober.probe_hosts",
        lambda *args: _returning(ProbeReport(credentials=(), outcomes=())),
    )

    async def fake_extract(sampled):
        return GPTExtractionReport(
            credentials=(),
            successful_entry_ids=frozenset({sampled[0]["_entry_id"]}),
            failed_entry_ids=frozenset({sampled[1]["_entry_id"]}),
        )

    monkeypatch.setattr("aipocket.services.analyzer.extract_with_gpt", fake_extract)

    await run_scan(query_budgets=QueryBudgets(1, 1))

    targets = canonicalize_hits(hits)
    assert store.marked == [("gpt", targets[0].identity.identity_hash)]
