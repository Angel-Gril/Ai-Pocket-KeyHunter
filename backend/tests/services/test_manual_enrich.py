"""Tests for manual target FOFA/Shodan domain enrichment."""

from __future__ import annotations

from typing import Any

import pytest

from aipocket.services.manual_enrich import (
    enrich_manual_hits,
    normalize_enrich_engines,
)


def test_normalize_enrich_engines() -> None:
    assert normalize_enrich_engines(None) == frozenset()
    assert normalize_enrich_engines([]) == frozenset()
    assert normalize_enrich_engines(["fofa", "shodan", "github"]) == frozenset({"fofa", "shodan"})
    assert normalize_enrich_engines("shodan,fofa") == frozenset({"fofa", "shodan"})


def test_enrich_no_engines_returns_seeds() -> None:
    seeds = [{"host": "https://web.example.com", "_source": "manual"}]
    hits, usage, errors = enrich_manual_hits(seeds, engines=())
    assert hits == seeds
    assert usage == ()
    assert errors == ()


def test_enrich_merges_title_from_shodan(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeShodan:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def search(self, query: str, pages: int | None = None, **kwargs: Any) -> list[dict]:
            assert 'hostname:"chunfeng.mentalout.top"' in query
            return [
                {
                    "host": "chunfeng.mentalout.top",
                    "title": "New API",
                    "banner": "<title>New API</title>",
                    "header": "HTTP/1.1 200 OK",
                    "product": "nginx",
                }
            ]

    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "sk-test")
    monkeypatch.setattr(
        "aipocket.clients.shodan.ShodanClient",
        _FakeShodan,
    )

    seeds = [
        {
            "host": "https://chunfeng.mentalout.top",
            "protocol": "https",
            "port": "443",
            "_source": "manual",
            "_query_id": "manual-target",
        }
    ]
    hits, usage, errors = enrich_manual_hits(seeds, engines={"shodan"})
    assert errors == ()
    assert len(usage) == 1
    assert usage[0].lane == "manual-enrich"
    # Seed keeps URL + gains fingerprint
    seed = hits[0]
    assert seed["host"] == "https://chunfeng.mentalout.top"
    assert seed["title"] == "New API"
    assert "New API" in seed["banner"]
    assert "shodan" in (seed.get("_manual_enrich") or [])
    # Extra shodan row appended
    assert any(h.get("_source") == "shodan" for h in hits)
    assert any(h.get("title") == "New API" and h.get("_source") == "shodan" for h in hits)


def test_enrich_fofa_and_shodan(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeFofa:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def search(
            self, query: str, pages: int | None = None, size: int | None = None, **kwargs: Any
        ) -> list[dict]:
            return [{"host": "a.example.com", "title": "LiteLLM", "banner": "litellm"}]

    class _FakeShodan:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def search(self, query: str, pages: int | None = None, **kwargs: Any) -> list[dict]:
            return [{"host": "a.example.com", "title": "New API", "banner": "new-api"}]

    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "fk")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "sk")
    monkeypatch.setattr("aipocket.clients.fofa.FofaClient", _FakeFofa)
    monkeypatch.setattr("aipocket.clients.shodan.ShodanClient", _FakeShodan)

    seeds = [{"host": "https://a.example.com", "_source": "manual"}]
    hits, usage, errors = enrich_manual_hits(seeds, engines={"fofa", "shodan"})
    assert errors == ()
    assert len(usage) == 2
    seed = hits[0]
    assert seed["title"]  # merged something
    assert set(seed.get("_manual_enrich") or []) == {"fofa", "shodan"}


def test_enrich_missing_keys_soft_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipocket.core.config.settings.fofa_keys", "")
    monkeypatch.setattr("aipocket.core.config.settings.shodan_keys", "")
    seeds = [{"host": "https://a.example.com", "_source": "manual"}]
    hits, usage, errors = enrich_manual_hits(seeds, engines={"fofa", "shodan"})
    assert len(hits) == 1  # seeds preserved
    assert usage == ()
    assert any("fofa" in e for e in errors)
    assert any("shodan" in e for e in errors)


@pytest.mark.asyncio
async def test_manual_source_passes_enrich(monkeypatch: pytest.MonkeyPatch) -> None:
    from aipocket.discovery.base import SourceBudgets
    from aipocket.discovery.manual_source import ManualSource

    monkeypatch.setattr(
        "aipocket.discovery.manual_source.load_enabled_urls",
        lambda: ["https://web.example.com"],
    )

    called: dict[str, Any] = {}

    def _fake_enrich(hits: list, *, engines: Any) -> tuple:
        called["engines"] = frozenset(engines)
        enriched = [dict(hits[0])]
        enriched[0]["title"] = "New API"
        return enriched, (), ()

    monkeypatch.setattr(
        "aipocket.discovery.manual_source.enrich_manual_hits",
        _fake_enrich,
    )

    src = ManualSource()
    result = await src.fetch(
        budgets=SourceBudgets(),
        mode="incremental",
        manual_enrich={"shodan", "fofa"},
    )
    assert called["engines"] == frozenset({"fofa", "shodan"})
    assert result.host_hits[0]["title"] == "New API"
