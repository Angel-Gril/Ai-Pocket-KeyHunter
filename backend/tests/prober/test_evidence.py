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
        budget.consume()
        raise httpx.ConnectError("certificate verify failed")

    class _InsecureClient:
        async def __aenter__(self) -> _InsecureClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str, **kwargs: object) -> httpx.Response:
            budget.consume()
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
