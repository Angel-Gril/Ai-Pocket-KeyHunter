from __future__ import annotations

from aipocket.core.metrics import QueryFunnel, QueryMetric
from aipocket.services.query_planner import (
    PlannerConfig,
    QueryCandidate,
    QueryLane,
    plan_queries,
)


def _candidate(query: str, lane: QueryLane, order: int) -> QueryCandidate:
    return QueryCandidate(query=query, lane=lane, stable_order=order)


def test_first_run_plan_includes_each_query_lane() -> None:
    candidates = (
        _candidate("direct-1", QueryLane.DIRECT, 0),
        _candidate("direct-2", QueryLane.DIRECT, 1),
        _candidate("product-1", QueryLane.PRODUCT, 2),
        _candidate("provider-1", QueryLane.PROVIDER, 3),
    )

    planned = plan_queries(candidates, (), PlannerConfig(max_queries=3, seed=7))

    assert [item.lane for item in planned] == [
        QueryLane.DIRECT,
        QueryLane.PRODUCT,
        QueryLane.PROVIDER,
    ]


def test_seeded_plan_reserves_twenty_percent_for_exploration() -> None:
    candidates = tuple(_candidate(f"q-{index}", QueryLane.DIRECT, index) for index in range(10))
    history = tuple(
        QueryMetric(
            source="fofa",
            query=f"q-{index}",
            funnel=QueryFunnel(active_requests=10, final_verified=10 - index),
        )
        for index in range(10)
    )
    config = PlannerConfig(max_queries=5, exploration_ratio=0.2, seed=41)

    first = plan_queries(candidates, history, config)
    second = plan_queries(candidates, history, config)

    assert first == second
    assert [item.query for item in first[:4]] == ["q-0", "q-1", "q-2", "q-3"]
    assert first[4].query not in {"q-0", "q-1", "q-2", "q-3"}


def test_repeated_zero_yield_is_demoted_but_remains_explorable() -> None:
    candidates = (
        _candidate("productive", QueryLane.DIRECT, 0),
        _candidate("zero-yield", QueryLane.DIRECT, 1),
    )
    history = (
        QueryMetric(
            source="fofa",
            query="productive",
            funnel=QueryFunnel(active_requests=10, final_verified=3),
        ),
        QueryMetric(
            source="fofa",
            query="zero-yield",
            funnel=QueryFunnel(active_requests=30, final_verified=0),
        ),
    )

    exploitation = plan_queries(
        candidates,
        history,
        PlannerConfig(max_queries=1, exploration_ratio=0.0, seed=2),
    )
    exploration = plan_queries(
        candidates,
        history,
        PlannerConfig(max_queries=2, exploration_ratio=0.5, seed=2),
    )

    assert [item.query for item in exploitation] == ["productive"]
    assert {item.query for item in exploration} == {"productive", "zero-yield"}


def test_minimum_sample_prior_prevents_one_hit_wonder_from_dominating() -> None:
    candidates = (
        _candidate("sampled", QueryLane.DIRECT, 0),
        _candidate("one-hit", QueryLane.DIRECT, 1),
    )
    history = (
        QueryMetric(
            source="fofa",
            query="sampled",
            funnel=QueryFunnel(active_requests=20, final_verified=4),
        ),
        QueryMetric(
            source="fofa",
            query="one-hit",
            funnel=QueryFunnel(active_requests=1, final_verified=1),
        ),
    )

    planned = plan_queries(
        candidates,
        history,
        PlannerConfig(max_queries=1, exploration_ratio=0.0, minimum_samples=10, seed=0),
    )

    assert [item.query for item in planned] == ["sampled"]
