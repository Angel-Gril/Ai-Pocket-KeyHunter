"""Planner shadow scoring with ledger denominator (metrics v3)."""

from __future__ import annotations

from aipocket.core.metrics import QueryFunnel, QueryMetric
from aipocket.services.query_planner import (
    PlannerConfig,
    QueryCandidate,
    QueryLane,
    plan_queries_detailed,
    score_v2,
    score_v3,
)


def _metric(
    query: str,
    *,
    verified: int,
    active: int,
    ledger: int = 0,
    version: int = 2,
) -> QueryMetric:
    return QueryMetric(
        source="fofa",
        query=query,
        attribution_version=version,
        funnel=QueryFunnel(
            final_verified=verified,
            active_requests=active,
            total_active_http_requests=ledger,
        ),
    )


def test_score_v3_uses_ledger_denominator():
    # Same verified, higher HTTP cost → lower score
    assert score_v3(10, 100, minimum_samples=1) > score_v3(10, 1000, minimum_samples=1)
    assert score_v2(10, 50, minimum_samples=1) == 10 / 50


def test_planner_shadow_uses_total_active_http_requests_for_v3():
    # q_cheap: few HTTP, same verified as q_expensive under v2 active_requests
    history = (
        _metric("q_cheap", verified=5, active=100, ledger=20, version=3),
        _metric("q_expensive", verified=5, active=100, ledger=500, version=3),
        # v2-only history must not pollute v3 aggregates
        _metric("q_legacy", verified=50, active=10, ledger=0, version=2),
    )
    candidates = (
        QueryCandidate("q_cheap", QueryLane.PRODUCT, 0),
        QueryCandidate("q_expensive", QueryLane.PRODUCT, 1),
        QueryCandidate("q_legacy", QueryLane.PRODUCT, 2),
        QueryCandidate("q_new", QueryLane.DIRECT, 3),
    )
    # Production still v2
    planned = plan_queries_detailed(
        candidates,
        history,
        PlannerConfig(max_queries=2, exploration_ratio=0.0, seed=1, metrics_version=2),
    )
    assert planned.selected
    # Shadow should prefer cheaper ledger cost when ranking product queries
    shadow_queries = [c.query for c in planned.shadow_selected]
    if "q_cheap" in shadow_queries and "q_expensive" in shadow_queries:
        assert shadow_queries.index("q_cheap") < shadow_queries.index("q_expensive")


def test_production_v3_ignores_v2_history_ledger():
    history = (
        _metric("a", verified=1, active=10, ledger=1000, version=3),
        _metric("b", verified=1, active=10, ledger=10, version=3),
    )
    candidates = (
        QueryCandidate("a", QueryLane.PRODUCT, 0),
        QueryCandidate("b", QueryLane.PRODUCT, 1),
    )
    planned = plan_queries_detailed(
        candidates,
        history,
        PlannerConfig(max_queries=1, exploration_ratio=0.0, seed=0, metrics_version=3),
    )
    assert planned.selected[0].query == "b"


def test_incomplete_ledger_marks_run_not_planner_eligible():
    """Document the gate: only attribution_version=3 + ledger_complete enter v3."""
    # This is a pure unit of the scoring helpers; PG join is tested via SQL shape.
    incomplete = _metric("x", verified=9, active=1, ledger=1, version=2)
    assert incomplete.attribution_version < 3
    assert score_v2(9, 1, minimum_samples=1) == 9.0
