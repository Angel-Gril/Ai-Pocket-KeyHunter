"""Tests for ManualSource discovery adapter."""

from __future__ import annotations

import pytest

from aipocket.core.targets import DiscoveryTarget, TargetIdentity, canonicalize_hits
from aipocket.discovery.manual_source import ManualSource
from aipocket.discovery.registry import SourceRegistry, merge_fetch_results
from aipocket.prober.evidence import score_target


@pytest.mark.asyncio
async def test_fetch_empty_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "aipocket.discovery.manual_source.load_enabled_urls",
        lambda: [],
    )
    src = ManualSource()
    assert src.is_configured() is False
    result = await src.fetch(budgets=None, mode="incremental")  # type: ignore[arg-type]
    assert result.source == "manual"
    assert result.host_hits == ()
    assert result.errors
    err = result.errors[0].lower()
    assert "no enabled targets" in err or "自定义狩猎" in result.errors[0]


@pytest.mark.asyncio
async def test_fetch_loads_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "aipocket.discovery.manual_source.load_enabled_urls",
        lambda: ["https://web.ymocode.com", "https://web2.ymocode.com"],
    )
    src = ManualSource()
    from aipocket.discovery.base import SourceBudgets

    result = await src.fetch(budgets=SourceBudgets(), mode="incremental")
    assert len(result.host_hits) == 2
    assert result.host_hit_count == 2
    assert result.errors == ()
    assert all(h["_source"] == "manual" for h in result.host_hits)
    assert result.host_hits[0]["host"] == "https://web.ymocode.com"


def test_manual_not_in_default_all_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    """Manual is opt-in: full/all scans must not auto-include it."""
    registry = SourceRegistry.default()
    resolved = registry.resolve(requested=None)
    names = {s.name for s in resolved}
    assert "manual" not in names


def test_manual_included_when_explicitly_requested() -> None:
    registry = SourceRegistry.default()
    resolved = registry.resolve(requested={"manual"})
    assert len(resolved) == 1
    assert resolved[0].name == "manual"


@pytest.mark.asyncio
async def test_merge_manual_hits() -> None:
    monkeypatch_urls = ["https://web.ymocode.com"]
    from aipocket.discovery.base import SourceBudgets

    src = ManualSource()

    import aipocket.discovery.manual_source as ms

    original = ms.load_enabled_urls
    ms.load_enabled_urls = lambda: monkeypatch_urls  # type: ignore[assignment]
    try:
        result = await src.fetch(budgets=SourceBudgets(), mode="full")
    finally:
        ms.load_enabled_urls = original  # type: ignore[assignment]

    host_hits, cred_obs, sources_used, hits_by_source, *_ = merge_fetch_results([result])
    assert sources_used == ["manual"]
    assert hits_by_source["manual"] == 1
    assert len(host_hits) == 1
    assert cred_obs == []

    targets = canonicalize_hits(host_hits)
    assert len(targets) == 1
    assert targets[0].identity == TargetIdentity("https", "web.ymocode.com", 443)
    assert "manual" in targets[0].sources


def test_manual_target_evidence_score_passes_probe_gate() -> None:
    target = DiscoveryTarget(
        identity=TargetIdentity("https", "web.ymocode.com", 443),
        sources=frozenset({"manual"}),
    )
    evidence = score_target(target)
    assert evidence.score >= 50
    assert "manual target" in evidence.reasons
