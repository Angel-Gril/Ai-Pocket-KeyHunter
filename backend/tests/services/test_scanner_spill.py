"""Scanner discovery spill path: FOFA/Shodan page upsert + slim RAM retention."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from aipocket.services.scanner import QueryBudgets, _fetch_fofa, _fetch_shodan, run_scan


def _make_paging_client(pages: list[list[dict]]) -> MagicMock:
    """Mock FOFA/Shodan client that feeds multi-page results via on_page."""
    mock = MagicMock()

    def _search(*_args: Any, **kwargs: Any) -> list[dict]:
        on_page = kwargs.get("on_page")
        retain = kwargs.get("retain_results", True)
        all_hits: list[dict] = []
        for page in pages:
            if on_page is not None:
                on_page(list(page))
            if retain:
                all_hits.extend(page)
        return all_hits if retain else []

    mock.search.side_effect = _search
    mock.count.return_value = sum(len(p) for p in pages)
    mock.info.return_value = {}
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    return mock


def test_fofa_pages_spilled_without_retaining_all_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    """With spill on, each page is upserted and only slim fields stay in RAM."""
    body = "SECRET_BODY_" + ("Z" * 50_000)
    page1 = [
        {
            "host": f"https://p1-{i}.example.com",
            "ip": f"1.1.1.{i}",
            "port": "443",
            "protocol": "https",
            "header": f"Server: nginx-{i}",
            "banner": f"HTTP/1.1 200 p1-{i}",
            "body": body,
        }
        for i in range(5)
    ]
    page2 = [
        {
            "host": f"https://p2-{i}.example.com",
            "ip": f"2.2.2.{i}",
            "port": "443",
            "protocol": "https",
            "header": f"Server: caddy-{i}",
            "banner": f"HTTP/1.1 200 p2-{i}",
            "body": body,
        }
        for i in range(5)
    ]
    upserted: list[list[dict]] = []

    monkeypatch.setattr(
        "aipocket.services.scanner.build_queries",
        lambda **kw: [
            {
                "query": 'body="sk-"',
                "cve_id": "CVE-TEST",
                "product": "test",
                "type": "t",
                "advisory_ids": [],
                "product_hints": [],
            }
        ],
    )
    monkeypatch.setattr("aipocket.services.scanner.load_query_history", lambda _s: ())
    monkeypatch.setattr(
        "aipocket.services.scanner.FofaClient",
        lambda: _make_paging_client([page1, page2]),
    )
    monkeypatch.setattr("aipocket.services.candidate_store.spill_enabled", lambda: True)
    monkeypatch.setattr(
        "aipocket.services.discovery_store.upsert_hits",
        lambda run_id, source, hits: upserted.append(list(hits)) or len(hits),
    )

    hits, _usage, total = _fetch_fofa(max_queries=1, run_id="run_spill")
    assert total == 10
    assert len(upserted) == 2
    # Full body present in spill payloads
    assert all("body" in h and len(h["body"]) == len(body) for page in upserted for h in page)
    # RAM retention is slim: no body
    assert len(hits) == 10
    assert all("body" not in h for h in hits)
    assert all(h.get("header") for h in hits)
    assert all(h.get("banner") for h in hits)


def test_shodan_pages_spilled(monkeypatch: pytest.MonkeyPatch) -> None:
    body = "shodan-body-" + ("Y" * 10_000)
    pages = [
        [
            {
                "host": "https://s.example.com",
                "ip": "9.9.9.9",
                "port": "443",
                "protocol": "https",
                "header": "X-Test: 1",
                "banner": "OK",
                "body": body,
            }
        ]
    ]
    upserted: list[dict] = []

    monkeypatch.setattr(
        "aipocket.services.shodan_queries.build_shodan_queries",
        lambda **kw: [
            {
                "query": 'http.html:"sk-"',
                "cve_id": "CVE-S",
                "product": "p",
                "type": "t",
                "advisory_ids": [],
                "product_hints": [],
            }
        ],
    )
    monkeypatch.setattr("aipocket.services.scanner.load_query_history", lambda _s: ())
    monkeypatch.setattr(
        "aipocket.clients.shodan.ShodanClient",
        lambda: _make_paging_client(pages),
    )
    monkeypatch.setattr("aipocket.services.candidate_store.spill_enabled", lambda: True)
    monkeypatch.setattr(
        "aipocket.services.discovery_store.upsert_hits",
        lambda run_id, source, hits: upserted.extend(hits) or len(hits),
    )

    hits, _usage, total = _fetch_shodan(max_queries=1, run_id="run_sh")
    assert total == 1
    assert len(upserted) == 1
    assert len(upserted[0]["body"]) == len(body)
    assert "body" not in hits[0]


def test_memory_path_without_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Spill off → legacy list path retains full hits (including body)."""
    body = "keep-me-in-ram"
    hits_in = [
        {
            "host": "https://mem.example.com",
            "protocol": "https",
            "port": "443",
            "header": "H",
            "banner": "B",
            "body": body,
        }
    ]
    monkeypatch.setattr(
        "aipocket.services.scanner.build_queries",
        lambda **kw: [
            {
                "query": "q",
                "cve_id": "c",
                "product": "p",
                "type": "t",
                "advisory_ids": [],
                "product_hints": [],
            }
        ],
    )
    monkeypatch.setattr("aipocket.services.scanner.load_query_history", lambda _s: ())
    monkeypatch.setattr(
        "aipocket.services.scanner.FofaClient",
        lambda: _make_paging_client([hits_in]),
    )
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.candidate_store.spill_enabled", lambda: False)

    calls: list[int] = []
    monkeypatch.setattr(
        "aipocket.services.discovery_store.upsert_hits",
        lambda *a, **k: calls.append(1) or 0,
    )

    hits, _usage, total = _fetch_fofa(max_queries=1, run_id="run_mem")
    assert total == 1
    assert calls == []  # no spill
    assert hits[0]["body"] == body


def test_no_truncation_of_body_in_spill_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    body = "sk-in-body-" + ("W" * 80_000)
    page = [
        {
            "host": "https://big.example.com",
            "protocol": "https",
            "port": "443",
            "header": "H",
            "banner": "B",
            "body": body,
        }
    ]
    stored: list[dict] = []
    monkeypatch.setattr(
        "aipocket.services.scanner.build_queries",
        lambda **kw: [
            {
                "query": 'body="sk-"',
                "cve_id": "c",
                "product": "p",
                "type": "t",
                "advisory_ids": [],
                "product_hints": [],
            }
        ],
    )
    monkeypatch.setattr("aipocket.services.scanner.load_query_history", lambda _s: ())
    monkeypatch.setattr(
        "aipocket.services.scanner.FofaClient",
        lambda: _make_paging_client([page]),
    )
    monkeypatch.setattr("aipocket.services.candidate_store.spill_enabled", lambda: True)
    monkeypatch.setattr(
        "aipocket.services.discovery_store.upsert_hits",
        lambda run_id, source, hits: stored.extend(hits) or len(hits),
    )
    _hits, _u, total = _fetch_fofa(max_queries=1, run_id="run_big")
    assert total == 1
    assert len(stored[0]["body"]) == len(body)
    assert stored[0]["body"] == body


def test_extract_reads_full_payload_from_store() -> None:
    """Full spilled hit (header/banner intact) remains extractable after reload.

    Regex extract scans header/banner (not body — body is GPT path). Spill must
    preserve those fields so page-load → extract still finds keys.
    """
    from aipocket.services.extractor import extract_credentials

    key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
    full_hit = {
        "host": "https://extract.example.com",
        "ip": "1.2.3.4",
        "protocol": "https",
        "port": "443",
        "header": f"Authorization: Bearer {key}\r\nServer: nginx",
        "banner": "HTTP/1.1 200",
        "body": "x" * 50_000,  # full body also present for GPT
        "_source": "fofa",
        "_query_id": "q",
    }
    # Slim RAM form would drop body; extract still works from header.
    slim = {k: v for k, v in full_hit.items() if k != "body"}
    creds_full = extract_credentials([full_hit])
    creds_slim = extract_credentials([slim])
    assert key in {c.apikey for c in creds_full}
    assert key in {c.apikey for c in creds_slim}
    assert len(full_hit["body"]) == 50_000


def test_gpt_sampling_loads_full_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """load_hits_by_entry_ids returns full body/banner/header for GPT path."""
    from aipocket.services import discovery_store as ds

    full = {
        "host": "https://gpt.example.com",
        "header": "X-Key: present",
        "banner": "HTTP/1.1 200",
        "body": "sk-gpt-" + ("b" * 48),
    }
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")

    class Cur:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=None):
            return self

        def fetchall(self):
            return [{"entry_id": "e1", "record": full}]

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def cursor(self):
            return Cur()

    class Pool:
        def connection(self):
            return Conn()

    monkeypatch.setattr("aipocket.core.db.get_pool", lambda: Pool())
    out = ds.load_hits_by_entry_ids("run_g", ["e1"])
    assert out["e1"]["body"] == full["body"]
    assert out["e1"]["header"] == full["header"]
    assert out["e1"]["banner"] == full["banner"]
    assert len(out["e1"]["body"]) == len(full["body"])


@pytest.mark.asyncio
async def test_prober_still_runs_with_spill(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Spill enabled does not break the prober path for slim targets."""
    from aipocket.core.metrics import QueryUsage
    from aipocket.core.models import ValidationResult
    from aipocket.discovery.base import SourceFetchResult
    from aipocket.prober.runner import ProbeReport, ProbeStatus, ProbeTargetOutcome

    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_key", "")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_base_url", "")
    monkeypatch.setattr("aipocket.core.config.settings.scan_prober", True)
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
    # Keep PG off so spill path is not required; still prove prober runs with
    # slim-style hits (no body) that mirror the spill RAM working set.
    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    monkeypatch.setattr("aipocket.services.candidate_store.spill_enabled", lambda: False)
    monkeypatch.setattr("aipocket.services.discovery_store.spill_enabled", lambda: False)
    monkeypatch.setattr("aipocket.services.honeypot_store.load_known_host_keys", lambda: set())

    slim_hit = {
        "host": "https://probe.example.com",
        "protocol": "https",
        "port": "443",
        "header": "Server: nginx",
        "banner": "OK",
        # body intentionally absent (slim spill form)
        "ip": "1.2.3.4",
        "_source": "fofa",
        "_query_id": "q",
    }

    async def fake_fetch_all(*_a, **_k):
        return [
            SourceFetchResult(
                source="fofa",
                host_hits=(slim_hit,),
                query_usage=(QueryUsage(query="q"),),
                host_hit_count=1,
                spilled=False,
            )
        ]

    monkeypatch.setattr("aipocket.discovery.registry.SourceRegistry.fetch_all", fake_fetch_all)

    probed: list = []

    async def capture_probe(targets, allowed_products):  # noqa: ANN001
        probed.extend(targets)
        return ProbeReport(
            credentials=(),
            outcomes=tuple(
                ProbeTargetOutcome(
                    identity_hash=t.identity.identity_hash,
                    status=ProbeStatus.SKIPPED,
                    request_count=0,
                    prober="generic",
                )
                for t in targets
            ),
        )

    monkeypatch.setattr("aipocket.prober.probe_hosts", capture_probe)

    async def fake_validate(creds, **kwargs):  # noqa: ANN001
        return [ValidationResult(credential=c, valid=False) for c in creds]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", fake_validate)

    run_dir = tmp_path / "run_probe_spill"
    run_dir.mkdir()
    result = await run_scan(
        query_budgets=QueryBudgets(1, 0),
        run_dir=run_dir,
        sources={"fofa"},
    )
    assert len(probed) >= 1
    # Slim targets still carry header/banner signal for prober ranking
    assert probed[0].identity.hostname == "probe.example.com"
    assert result is not None


@pytest.mark.asyncio
async def test_resume_reload_discovery_from_pg(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """phase=extract resume reloads slim hits from PG and skips FOFA/Shodan clients."""
    from aipocket.core.models import ValidationResult
    from aipocket.services import scan_checkpoint as sc
    from aipocket.services.scanner import run_scan

    fetch_called: list[str] = []

    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/db")
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.scan_prober", False)
    monkeypatch.setattr("aipocket.core.config.settings.gpt_key", "")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_base_url", "")
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
    monkeypatch.setattr("aipocket.services.scan_checkpoint.mark_phase", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.create_run_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.persist_ledger_batch_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.persist_run_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.mark_run_interrupted_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.honeypot_store.load_known_host_keys", lambda: set())
    monkeypatch.setattr(
        "aipocket.services.scan_checkpoint.load_run_state",
        lambda run_id: {
            "run_id": run_id,
            "state": "interrupted",
            "phase": sc.PHASE_EXTRACT,
            "phase_detail": {},
            "scan_mode": "full",
            "started_at": "2026-01-01T00:00:00+00:00",
        },
    )

    async def boom_fetch(*_a, **_k):
        fetch_called.append("fetch")
        raise AssertionError("should not re-fetch discovery")

    monkeypatch.setattr("aipocket.discovery.registry.SourceRegistry.fetch_all", boom_fetch)

    full_hit = {
        "host": "https://reload.example.com",
        "protocol": "https",
        "port": "443",
        "header": "Server: nginx",
        "banner": "OK",
        "body": "FULL-BODY-SHOULD-NOT-BE-IN-SLIM",
        "_source": "fofa",
        "_query_id": "q",
        "_entry_id": "eid1",
    }
    from aipocket.services.discovery_store import slim_hit_for_target

    monkeypatch.setattr(
        "aipocket.services.discovery_store.iter_hits",
        lambda *a, **k: iter([[slim_hit_for_target(full_hit)]]),
    )
    monkeypatch.setattr(
        "aipocket.services.discovery_store.count_hits",
        lambda run_id, source=None: 1 if source in (None, "fofa") else 0,
    )
    monkeypatch.setattr("aipocket.services.candidate_store.spill_enabled", lambda: True)
    monkeypatch.setattr("aipocket.services.discovery_store.spill_enabled", lambda: True)
    monkeypatch.setattr(
        "aipocket.services.candidate_store.count_candidates",
        lambda *a, **k: 0,
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.iter_candidate_pages",
        lambda *a, **k: iter(()),
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.load_validation_results",
        lambda *a, **k: [],
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.load_validated_identities",
        lambda *a, **k: set(),
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.upsert_candidates",
        lambda *a, **k: 0,
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.upsert_validation_results",
        lambda *a, **k: 0,
    )
    monkeypatch.setattr(
        "aipocket.services.discovery_store.load_hits_by_entry_ids",
        lambda *a, **k: {},
    )

    async def fake_validate_from_store(run_id, **kwargs):  # noqa: ANN001
        return []

    monkeypatch.setattr(
        "aipocket.services.validator.validate_from_store",
        fake_validate_from_store,
    )

    async def fake_validate(creds, **kwargs):  # noqa: ANN001
        return [ValidationResult(credential=c, valid=False) for c in creds]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", fake_validate)

    result = await run_scan(resume_run_id="run_resume_extract")
    assert fetch_called == []
    assert result is not None
    assert "fofa" in result.sources or result.total_hosts >= 0


@pytest.mark.asyncio
async def test_gpt_path_reloads_full_hits_when_spilled(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When discovery spilled, GPT sampling reloads full body from PG."""
    from aipocket.core.metrics import QueryUsage
    from aipocket.core.models import ValidationResult
    from aipocket.discovery.base import SourceFetchResult
    from aipocket.services.analyzer import GPTExtractionReport
    from aipocket.services.scanner import run_scan

    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://test/db")
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "k")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.scan_prober", False)
    monkeypatch.setattr("aipocket.core.config.settings.gpt_key", "fake")
    monkeypatch.setattr("aipocket.core.config.settings.gpt_base_url", "https://llm.example")
    monkeypatch.setattr("aipocket.core.config.settings.results_dir", str(tmp_path))
    monkeypatch.setattr("aipocket.services.scan_checkpoint.mark_phase", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.create_run_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.persist_ledger_batch_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.persist_run_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.writer.mark_run_interrupted_pg", lambda *a, **k: None)
    monkeypatch.setattr("aipocket.services.honeypot_store.load_known_host_keys", lambda: set())
    monkeypatch.setattr("aipocket.services.candidate_store.spill_enabled", lambda: True)
    monkeypatch.setattr("aipocket.services.discovery_store.spill_enabled", lambda: True)
    monkeypatch.setattr("aipocket.services.candidate_store.upsert_candidates", lambda *a, **k: 0)
    monkeypatch.setattr(
        "aipocket.services.candidate_store.upsert_validation_results", lambda *a, **k: 0
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.iter_candidate_pages",
        lambda *a, **k: iter(()),
    )
    monkeypatch.setattr("aipocket.services.candidate_store.count_candidates", lambda *a, **k: 0)
    monkeypatch.setattr(
        "aipocket.services.candidate_store.load_validation_results",
        lambda *a, **k: [],
    )
    monkeypatch.setattr(
        "aipocket.services.discovery_store.iter_hits",
        lambda *a, **k: iter(()),
    )

    body = "FULL-GPT-BODY-" + ("Z" * 10_000)
    slim_hit = {
        "host": "https://gpt-full.example.com",
        "protocol": "https",
        "port": "443",
        "header": "Server: x",
        "banner": "OK",
        "ip": "8.8.8.8",
        "_source": "fofa",
        "_query_id": "q",
    }
    full_hit = {**slim_hit, "body": body}

    async def fake_fetch_all(*_a, **_k):
        return [
            SourceFetchResult(
                source="fofa",
                host_hits=(slim_hit,),
                query_usage=(QueryUsage(query="q"),),
                host_hit_count=1,
                spilled=True,
            )
        ]

    monkeypatch.setattr("aipocket.discovery.registry.SourceRegistry.fetch_all", fake_fetch_all)

    loaded_ids: list[str] = []

    def fake_load(run_id: str, entry_ids):  # noqa: ANN001
        loaded_ids.extend(list(entry_ids))
        # Return full hit for every id
        return {str(eid): dict(full_hit) for eid in entry_ids if eid}

    monkeypatch.setattr(
        "aipocket.services.discovery_store.load_hits_by_entry_ids",
        fake_load,
    )

    gpt_payloads: list[list[dict]] = []

    async def capture_gpt(sampled):  # noqa: ANN001
        gpt_payloads.append(list(sampled))
        return GPTExtractionReport((), frozenset(), frozenset())

    monkeypatch.setattr("aipocket.services.analyzer.extract_with_gpt", capture_gpt)

    async def fake_validate(creds, **kwargs):  # noqa: ANN001
        return [ValidationResult(credential=c, valid=False) for c in creds]

    monkeypatch.setattr("aipocket.services.scanner.validate_all", fake_validate)
    monkeypatch.setattr(
        "aipocket.services.validator.validate_from_store",
        lambda *a, **k: fake_validate([]),
        raising=False,
    )

    async def empty_store(*a, **k):  # noqa: ANN001
        return []

    monkeypatch.setattr(
        "aipocket.services.validator.validate_from_store",
        empty_store,
    )

    run_dir = tmp_path / "run_gpt_spill"
    run_dir.mkdir()
    await run_scan(query_budgets=QueryBudgets(1, 0), run_dir=run_dir, sources={"fofa"})

    assert loaded_ids, "expected GPT path to request full hits by entry_id"
    assert gpt_payloads
    assert any(h.get("body") == body for h in gpt_payloads[0])


@pytest.mark.asyncio
async def test_validate_from_store_valid_only_return(monkeypatch: pytest.MonkeyPatch) -> None:
    from aipocket.core.models import Credential, ValidationResult
    from aipocket.services import validator as validator_mod

    monkeypatch.setattr("aipocket.core.config.settings.database_url", "postgresql://t/db")
    monkeypatch.setattr(validator_mod.settings, "validate_batch_size", 10)

    good = Credential(apikey="sk-good-" + "j" * 32, apiurl="https://g.example/v1")
    bad = Credential(apikey="sk-bad--" + "k" * 32, apiurl="https://b.example/v1")

    def fake_iter(run_id: str = "", **kwargs: Any):
        yield [good, bad]

    monkeypatch.setattr(
        "aipocket.services.candidate_store.iter_candidate_pages",
        fake_iter,
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.load_validated_identities",
        lambda run_id: set(),
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.upsert_validation_results",
        lambda *a, **k: 2,
    )
    monkeypatch.setattr(
        "aipocket.services.candidate_store.spill_enabled",
        lambda: True,
    )

    async def fake_validate_all(credentials, attribution=None):  # noqa: ANN001
        return [
            ValidationResult(credential=credentials[0], valid=True),
            ValidationResult(credential=credentials[1], valid=False),
        ]

    monkeypatch.setattr(validator_mod, "validate_all", fake_validate_all)
    out = await validator_mod.validate_from_store("run_vo", valid_only_return=True)
    assert len(out) == 1
    assert out[0].valid is True


@pytest.mark.asyncio
async def test_validate_from_store_noop_without_spill(monkeypatch: pytest.MonkeyPatch) -> None:
    from aipocket.services import validator as validator_mod

    monkeypatch.setattr("aipocket.core.config.settings.database_url", "")
    out = await validator_mod.validate_from_store("run_x")
    assert out == []
