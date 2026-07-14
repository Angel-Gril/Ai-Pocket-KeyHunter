"""Generic vs product budget isolation + ProbeReport findings plumbing."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from aipocket.core.targets import DiscoveryTarget, TargetIdentity
from aipocket.prober.probers import GenericPageProber, LobeChatProber, NewAPIProber
from aipocket.prober.runner import (
    ProbeAssignment,
    _budget_for_prober,
    _probe_one,
    probe_hosts,
)


def test_generic_and_product_budgets_are_independent() -> None:
    g = _budget_for_prober(GenericPageProber)
    p = _budget_for_prober(NewAPIProber)
    assert g.limit <= 32  # generic is small
    assert p.limit >= 30  # product gets the full product budget
    assert g.limit < p.limit
    assert g is not p  # independent counters


@pytest.mark.asyncio
async def test_product_budget_not_shared_with_generic() -> None:
    """Generic and product each get their own RequestBudget."""
    target = DiscoveryTarget(
        identity=TargetIdentity("https", "both.example", 443),
        product_hints=frozenset({"new-api"}),
        content_evidence=("OPENAI_API_KEY=sk-proj-real-looking-key-here-xx",),
        hit={
            "host": "https://both.example",
            "title": "New API",
            "protocol": "https",
            "_requires_content_refetch": True,
        },
    )
    assignment = ProbeAssignment(target=target, probers=(GenericPageProber, NewAPIProber))

    with respx.mock(assert_all_called=False) as router:
        router.route().mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient(follow_redirects=False) as client:
            _creds, outcome, _findings, nodes = await _probe_one(
                client, asyncio.Semaphore(5), assignment
            )

    assert "generic" in outcome.prober
    assert "new-api" in outcome.prober
    assert outcome.request_count >= 1
    assert isinstance(nodes, list)


@pytest.mark.asyncio
async def test_probe_report_includes_findings_field() -> None:
    key = "sk-proj-" + "Z" * 40
    target = DiscoveryTarget(
        identity=TargetIdentity("https", "lobe.example", 443),
        product_hints=frozenset({"lobechat"}),
        content_evidence=(f"OPENAI_API_KEY={key}",),
        hit={
            "host": "https://lobe.example",
            "title": "LobeChat",
            "protocol": "https",
        },
    )
    with respx.mock(assert_all_called=False) as router:
        router.get("https://lobe.example/api/config").mock(
            return_value=httpx.Response(200, text=f'{{"OPENAI_API_KEY": "{key}"}}')
        )
        router.route().mock(return_value=httpx.Response(404))
        report = await probe_hosts([target], frozenset({"lobechat"}))

    assert any(key in c.apikey for c in report.credentials)
    assert len(report.findings) >= 1
    assert any(f.confirmed for f in report.findings)
    assert len(report.node_outcomes) >= 1
    # LobeChat only has unauth_read Spec → at least one executed node
    assert any(n.status.value == "executed" for n in report.node_outcomes)
    assert LobeChatProber.product_name in report.outcomes[0].prober
