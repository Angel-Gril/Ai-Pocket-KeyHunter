from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError

import httpx
import pytest
import respx

from aipocket.core.models import Credential
from aipocket.core.targets import DiscoveryTarget, TargetIdentity
from aipocket.prober.base import Prober
from aipocket.prober.budget import BudgetExhausted, RequestBudget
from aipocket.prober import runner
from aipocket.prober.evidence import TargetEvidence, score_target
from aipocket.prober.runner import _eligible_targets


def _target(
    *, evidence: tuple[str, ...] = (), products: frozenset[str] = frozenset()
) -> DiscoveryTarget:
    return DiscoveryTarget(
        identity=TargetIdentity("https", "target.example", 443),
        product_hints=products,
        content_evidence=evidence,
    )


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        (_target(evidence=("OPENAI_API_KEY=sk-proj-real-looking-key",)), "credential pattern"),
        (_target(evidence=("ANTHROPIC_API_KEY configured in .env",)), "configuration exposure"),
        (_target(products=frozenset({"litellm"})), "product fingerprint"),
    ],
)
def test_score_target_rewards_strong_evidence(target: DiscoveryTarget, reason: str) -> None:
    result = score_target(target)

    assert result.score >= 60
    assert reason in result.reasons


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("Read our API documentation and developer blog", "documentation/blog penalty"),
        ('<div id="root"></div><script src="/assets/index.js"></script>', "SPA fallback penalty"),
    ],
)
def test_score_target_penalizes_low_yield_pages(content: str, reason: str) -> None:
    result = score_target(_target(evidence=(content,)))

    assert result.score < 0
    assert reason in result.reasons


def test_target_evidence_is_immutable() -> None:
    result = TargetEvidence(score=10, reasons=("test",))

    with pytest.raises(FrozenInstanceError):
        result.__setattr__("score", 20)


def test_request_budget_consumes_exactly_and_never_goes_negative() -> None:
    budget = RequestBudget(limit=2)

    budget.consume()
    budget.consume()
    assert budget.consumed == 2

    assert budget.remaining == 0
    with pytest.raises(BudgetExhausted):
        budget.consume()
    assert budget.remaining == 0


class _TestProber(Prober):
    product_name = "test"

    @classmethod
    def identify(cls, hit: dict[str, object]) -> bool:
        return True

    async def probe(self, hit: dict[str, object]) -> list[Credential]:
        return []


@pytest.mark.asyncio
async def test_redirects_consume_one_request_each() -> None:
    budget = RequestBudget(limit=2)
    sem = asyncio.Semaphore(1)
    with respx.mock as router:
        router.get("https://target.example/start").mock(
            return_value=httpx.Response(302, headers={"location": "/finish"})
        )
        router.get("https://target.example/finish").mock(return_value=httpx.Response(200))
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await _TestProber(client, sem, budget)._get("https://target.example/start")

    assert response is not None
    assert response.status_code == 200
    assert budget.remaining == 0


@pytest.mark.asyncio
async def test_tls_retry_consumes_an_additional_request(monkeypatch: pytest.MonkeyPatch) -> None:
    budget = RequestBudget(limit=2)
    sem = asyncio.Semaphore(1)

    async def fail_tls(*args: object, **kwargs: object) -> httpx.Response:
        raise httpx.ConnectError("certificate verify failed")

    class _InsecureClient:
        async def __aenter__(self) -> _InsecureClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str, **kwargs: object) -> httpx.Response:
            return httpx.Response(200)

    client = httpx.AsyncClient()
    monkeypatch.setattr(client, "get", fail_tls)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _InsecureClient())

    response = await _TestProber(client, sem, budget)._get("https://target.example")

    assert response is not None
    assert budget.remaining == 0
    await client.aclose()


def test_runner_gates_targets_below_minimum_score() -> None:
    strong = _target(evidence=("OPENAI_API_KEY=sk-proj-real-looking-key",))
    weak = _target(evidence=("Read our developer blog",))

    eligible = _eligible_targets([strong, weak], minimum_score=50)

    assert eligible == [(strong, score_target(strong))]


def test_safe_recipe_allowlist_is_not_product_evidence() -> None:
    hit = {
        "host": "https://generic.example",
        "title": "unrelated service",
        "header": "",
        "banner": "",
        "_safe_recipe_products": ["flowise", "litellm"],
    }

    selected = runner._select_prober(hit, runner._all_probers())

    assert selected is None


def test_product_prober_requires_allowlist_membership() -> None:
    target = _target(products=frozenset({"flowise"}))

    assignments, rejected = runner._build_assignments([target], frozenset({"litellm"}))

    assert rejected == []
    assert [[prober.product_name for prober in item.probers] for item in assignments] == [
        ["generic"]
    ]


def test_allowlisted_product_hint_selects_product_prober() -> None:
    target = _target(products=frozenset({"flowise"}))

    assignments, rejected = runner._build_assignments([target], frozenset({"flowise"}))

    assert rejected == []
    assert [[prober.product_name for prober in item.probers] for item in assignments] == [
        ["flowise"]
    ]


@pytest.mark.asyncio
async def test_probe_report_distinguishes_attempted_and_evidence_rejected() -> None:
    attempted = DiscoveryTarget(
        identity=TargetIdentity("https", "attempted.example", 443),
        content_evidence=("OPENAI_API_KEY=sk-proj-real-looking-key",),
    )
    rejected = DiscoveryTarget(
        identity=TargetIdentity("https", "rejected.example", 443),
        content_evidence=("Read our developer documentation",),
    )

    with respx.mock(assert_all_called=False) as router_mock:
        router_mock.route().mock(return_value=httpx.Response(404))
        report = await runner.probe_hosts([attempted, rejected], frozenset())

    outcomes = {outcome.identity_hash: outcome for outcome in report.outcomes}
    assert report.credentials == ()
    assert outcomes[attempted.identity.identity_hash].status is runner.ProbeStatus.ATTEMPTED
    assert outcomes[attempted.identity.identity_hash].request_count > 0
    assert (
        outcomes[rejected.identity.identity_hash].status
        is runner.ProbeStatus.REJECTED_BY_EVIDENCE
    )
    assert outcomes[rejected.identity.identity_hash].request_count == 0


@pytest.mark.asyncio
async def test_request_budgets_are_isolated_on_shared_client() -> None:
    first_budget = RequestBudget(limit=2)
    second_budget = RequestBudget(limit=2)
    sem = asyncio.Semaphore(2)

    with respx.mock() as router_mock:
        router_mock.get("https://first.example/").mock(return_value=httpx.Response(200))
        router_mock.get("https://second.example/").mock(return_value=httpx.Response(200))
        async with httpx.AsyncClient(follow_redirects=False) as client:
            first = _TestProber(client, sem, first_budget)
            second = _TestProber(client, sem, second_budget)
            await first._get("https://first.example/")
            await second._get("https://second.example/")

    assert first_budget.consumed == 1
    assert second_budget.consumed == 1
