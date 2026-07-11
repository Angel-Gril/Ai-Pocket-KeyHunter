from __future__ import annotations

import random
from dataclasses import dataclass
from enum import StrEnum

from aipocket.core.metrics import QueryMetric
from aipocket.services.shadow_eval import plan_with_shadow


class QueryLane(StrEnum):
    DIRECT = "direct"
    PRODUCT = "product"
    PROVIDER = "provider"


@dataclass(frozen=True, slots=True)
class QueryCandidate:
    query: str
    lane: QueryLane
    stable_order: int


@dataclass(frozen=True, slots=True)
class PlannerConfig:
    max_queries: int | None
    exploration_ratio: float = 0.2
    minimum_samples: int = 10
    seed: int = 0
    shadow_mode: bool = True


@dataclass(frozen=True, slots=True)
class PlannedQueries:
    selected: tuple[QueryCandidate, ...]
    shadow_selected: tuple[QueryCandidate, ...]


def plan_queries(
    candidates: tuple[QueryCandidate, ...],
    history: tuple[QueryMetric, ...],
    config: PlannerConfig,
) -> tuple[QueryCandidate, ...]:
    """Select a stable exploitation/exploration mix while preserving lane coverage."""
    return plan_queries_detailed(candidates, history, config).selected


def plan_queries_detailed(
    candidates: tuple[QueryCandidate, ...],
    history: tuple[QueryMetric, ...],
    config: PlannerConfig,
) -> PlannedQueries:
    """Like :func:`plan_queries` but also records shadow new-versus-old decisions."""
    if not candidates:
        return PlannedQueries((), ())
    limit = (
        len(candidates) if config.max_queries is None else min(config.max_queries, len(candidates))
    )
    if limit <= 0:
        return PlannedQueries((), ())

    totals: dict[str, tuple[int, int]] = {}
    for metric in history:
        requests, verified = totals.get(metric.query, (0, 0))
        totals[metric.query] = (
            requests + metric.funnel.active_requests,
            verified + metric.funnel.final_verified,
        )

    def score(candidate: QueryCandidate) -> tuple[float, int]:
        requests, verified = totals.get(candidate.query, (0, 0))
        effective_requests = max(requests, config.minimum_samples)
        return (verified / effective_requests, -candidate.stable_order)

    ranked = sorted(candidates, key=score, reverse=True)
    selected: list[QueryCandidate] = []
    if limit >= len(QueryLane):
        for lane in QueryLane:
            lane_candidates = [candidate for candidate in ranked if candidate.lane is lane]
            if lane_candidates:
                selected.append(lane_candidates[0])

    remaining_slots = limit - len(selected)
    exploration_slots = min(remaining_slots, round(limit * config.exploration_ratio))
    exploitation_slots = remaining_slots - exploration_slots
    remaining = [candidate for candidate in ranked if candidate not in selected]
    selected.extend(remaining[:exploitation_slots])
    exploration_pool = remaining[exploitation_slots:]
    rng = random.Random(config.seed)
    selected.extend(rng.sample(exploration_pool, min(exploration_slots, len(exploration_pool))))
    candidate_plan = tuple(selected[:limit])

    # Shadow records the candidate plan without changing production until accepted.
    production_ids = tuple(item.query for item in candidate_plan)
    # In pure first-run planning production == candidate; callers may pass history-driven
    # baselines later. Shadow helper still records the pair.
    effective_ids, shadow_ids = plan_with_shadow(
        production_selection=production_ids,
        candidate_selection=production_ids,
        shadow_mode=config.shadow_mode,
    )
    by_query = {item.query: item for item in candidates}
    effective = tuple(by_query[q] for q in effective_ids if q in by_query)
    shadow = tuple(by_query[q] for q in shadow_ids if q in by_query)
    return PlannedQueries(selected=effective, shadow_selected=shadow)


def load_query_history(source: str) -> tuple[QueryMetric, ...]:
    """Read persisted funnel history when PostgreSQL is enabled."""
    from aipocket.core.config import settings

    if not settings.pg_enabled:
        return ()
    from aipocket.core.db import get_pool
    from aipocket.core.metrics import QueryFunnel

    with get_pool().connection() as connection:
        rows = connection.execute(
            """
            SELECT source, query, sum(raw_hits) AS raw_hits,
                   sum(unique_targets) AS unique_targets,
                   sum(active_requests) AS active_requests,
                   sum(candidates) AS candidates,
                   sum(auth_confirmed) AS auth_confirmed,
                   sum(final_verified) AS final_verified,
                   sum(noauth_rejected) AS noauth_rejected,
                   sum(query_credits) AS query_credits
            FROM query_metrics WHERE source = %s GROUP BY source, query ORDER BY query
            """,
            (source,),
        ).fetchall()
    return tuple(
        QueryMetric(
            source=row["source"],
            query=row["query"],
            funnel=QueryFunnel(**{name: row[name] for name in QueryFunnel.model_fields}),
        )
        for row in rows
    )


def candidate_lane(query: dict[str, str]) -> QueryLane:
    lane = query.get("lane")
    if lane is not None:
        return QueryLane(lane)
    if query.get("cve_id") == "DIRECT-CRED-LEAK":
        return QueryLane.DIRECT
    return QueryLane.PRODUCT
