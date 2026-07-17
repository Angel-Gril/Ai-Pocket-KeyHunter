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
    # Production ranking version: 2 = active_requests, 3 = ledger HTTP count.
    # Default 2 after WS-A; flip to 3 after shadow compare window.
    metrics_version: int = 2


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


def score_v2(verified: int, active_requests: int, *, minimum_samples: int) -> float:
    """Legacy score: final_verified / validation_credentials (active_requests)."""
    return verified / max(active_requests, minimum_samples)


def score_v3(verified: int, ledger_requests: int, *, minimum_samples: int) -> float:
    """Metrics v3 score: final_verified / total_active_http_requests (ledger)."""
    return verified / max(ledger_requests, minimum_samples)


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

    # Production scoring still uses v2 (active_requests) until PLANNER_METRICS_VERSION=3.
    # Shadow ranking always computes v3 when ledger denominators are present.
    totals_v2: dict[str, tuple[int, int]] = {}
    totals_v3: dict[str, tuple[int, int]] = {}
    for metric in history:
        requests, verified = totals_v2.get(metric.query, (0, 0))
        totals_v2[metric.query] = (
            requests + metric.funnel.active_requests,
            verified + metric.funnel.final_verified,
        )
        # Only attribution_version>=3 rows contribute ledger cost to v3 aggregates.
        if metric.attribution_version >= 3 and metric.funnel.total_active_http_requests > 0:
            lreq, lver = totals_v3.get(metric.query, (0, 0))
            totals_v3[metric.query] = (
                lreq + metric.funnel.total_active_http_requests,
                lver + metric.funnel.final_verified,
            )

    use_v3 = config.metrics_version >= 3

    def score(candidate: QueryCandidate) -> tuple[float, int]:
        if use_v3:
            requests, verified = totals_v3.get(candidate.query, (0, 0))
            return (
                score_v3(verified, requests, minimum_samples=config.minimum_samples),
                -candidate.stable_order,
            )
        requests, verified = totals_v2.get(candidate.query, (0, 0))
        return (
            score_v2(verified, requests, minimum_samples=config.minimum_samples),
            -candidate.stable_order,
        )

    def shadow_score(candidate: QueryCandidate) -> tuple[float, int]:
        requests, verified = totals_v3.get(candidate.query, (0, 0))
        if requests <= 0:
            # Fall back to v2 numbers so shadow still ranks when no v3 history.
            requests, verified = totals_v2.get(candidate.query, (0, 0))
            return (
                score_v2(verified, requests, minimum_samples=config.minimum_samples),
                -candidate.stable_order,
            )
        return (
            score_v3(verified, requests, minimum_samples=config.minimum_samples),
            -candidate.stable_order,
        )

    ranked = sorted(candidates, key=score, reverse=True)
    shadow_ranked = sorted(candidates, key=shadow_score, reverse=True)
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

    # Shadow plan ranked by v3 ledger denominator (does not change production).
    shadow_selected: list[QueryCandidate] = []
    if limit >= len(QueryLane):
        for lane in QueryLane:
            lane_candidates = [c for c in shadow_ranked if c.lane is lane]
            if lane_candidates:
                shadow_selected.append(lane_candidates[0])
    shadow_remaining_slots = limit - len(shadow_selected)
    shadow_exploration = min(shadow_remaining_slots, round(limit * config.exploration_ratio))
    shadow_exploit = shadow_remaining_slots - shadow_exploration
    shadow_rest = [c for c in shadow_ranked if c not in shadow_selected]
    shadow_selected.extend(shadow_rest[:shadow_exploit])
    shadow_pool = shadow_rest[shadow_exploit:]
    shadow_rng = random.Random(config.seed)
    shadow_selected.extend(
        shadow_rng.sample(shadow_pool, min(shadow_exploration, len(shadow_pool)))
    )
    shadow_plan = tuple(shadow_selected[:limit])

    production_ids = tuple(item.query for item in candidate_plan)
    shadow_ids_in = tuple(item.query for item in shadow_plan)
    effective_ids, shadow_ids = plan_with_shadow(
        production_selection=production_ids,
        candidate_selection=shadow_ids_in if config.shadow_mode else production_ids,
        shadow_mode=config.shadow_mode,
    )
    by_query = {item.query: item for item in candidates}
    effective = tuple(by_query[q] for q in effective_ids if q in by_query)
    shadow = tuple(by_query[q] for q in shadow_ids if q in by_query)
    return PlannedQueries(selected=effective, shadow_selected=shadow)


def load_query_history(
    source: str, *, attribution_version: int | None = None
) -> tuple[QueryMetric, ...]:
    """Read persisted funnel history when PostgreSQL is enabled.

    Default loads attribution_version=2 (production). Pass 3 for v3 ledger history.
    Rows from incomplete ledger runs are excluded by joining ledger_complete runs
    when attribution_version=3.
    """
    from aipocket.core.config import settings

    if not settings.pg_enabled:
        return ()
    from aipocket.core.db import get_pool
    from aipocket.core.metrics import QueryFunnel

    version = attribution_version
    if version is None:
        version = 3 if settings.planner_metrics_version >= 3 else 2

    if version >= 3:
        sql = """
            SELECT qm.source, qm.query,
                   sum(qm.raw_hits) AS raw_hits,
                   sum(qm.unique_targets) AS unique_targets,
                   sum(qm.active_requests) AS active_requests,
                   sum(qm.candidates) AS candidates,
                   sum(qm.prefilter_survivors) AS prefilter_survivors,
                   sum(qm.auth_confirmed) AS auth_confirmed,
                   sum(qm.final_verified) AS final_verified,
                   sum(qm.noauth_rejected) AS noauth_rejected,
                   sum(qm.query_credits) AS query_credits,
                   sum(qm.total_active_http_requests) AS total_active_http_requests,
                   max(qm.query_id) AS query_id,
                   max(qm.lane) AS lane,
                   max(qm.pack_id) AS pack_id
            FROM query_metrics qm
            JOIN runs r ON r.run_id = qm.run_id
            WHERE qm.source = %s
              AND qm.attribution_version = 3
              AND r.ledger_complete = TRUE
            GROUP BY qm.source, qm.query ORDER BY qm.query
            """
    else:
        sql = """
            SELECT source, query, sum(raw_hits) AS raw_hits,
                   sum(unique_targets) AS unique_targets,
                   sum(active_requests) AS active_requests,
                   sum(candidates) AS candidates,
                   sum(prefilter_survivors) AS prefilter_survivors,
                   sum(auth_confirmed) AS auth_confirmed,
                   sum(final_verified) AS final_verified,
                   sum(noauth_rejected) AS noauth_rejected,
                   sum(query_credits) AS query_credits,
                   0 AS total_active_http_requests,
                   '' AS query_id,
                   '' AS lane,
                   '' AS pack_id
            FROM query_metrics
            WHERE source = %s AND attribution_version = 2
            GROUP BY source, query ORDER BY query
            """

    with get_pool().connection() as connection:
        rows = connection.execute(sql, (source,)).fetchall()
    out: list[QueryMetric] = []
    for row in rows:
        funnel_kwargs = {
            name: int(row[name] or 0) for name in QueryFunnel.model_fields if name in row
        }
        out.append(
            QueryMetric(
                source=row["source"],
                query=row["query"],
                funnel=QueryFunnel(**funnel_kwargs),
                attribution_version=version,
                query_id=str(row.get("query_id") or ""),
                lane=str(row.get("lane") or ""),
                pack_id=str(row.get("pack_id") or ""),
            )
        )
    return tuple(out)


def candidate_lane(query: dict[str, str]) -> QueryLane:
    lane = query.get("lane")
    if lane is not None:
        return QueryLane(lane)
    if query.get("cve_id") == "DIRECT-CRED-LEAK":
        return QueryLane.DIRECT
    return QueryLane.PRODUCT
