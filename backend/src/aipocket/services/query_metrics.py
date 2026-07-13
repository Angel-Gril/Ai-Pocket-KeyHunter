from __future__ import annotations

from dataclasses import dataclass, field

from aipocket.core.metrics import QueryFunnel, QueryMetric
from aipocket.core.observations import CanonicalCredentialObservation, CredentialIdentity


@dataclass(slots=True)
class QueryMetricsCollector:
    """Mutable scan-lifetime accumulator that emits immutable metric snapshots."""

    _funnels: dict[tuple[str, str], dict[str, int]] = field(default_factory=dict)
    _observed: dict[tuple[str, str, str], set[CredentialIdentity]] = field(default_factory=dict)

    def increment(self, source: str, query: str, **increments: int) -> None:
        values = self._funnels.setdefault((source, query), QueryFunnel().model_dump())
        for name, amount in increments.items():
            if amount < 0:
                msg = f"metric increment must be non-negative: {name}={amount}"
                raise ValueError(msg)
            if name not in values:
                msg = f"unknown query funnel metric: {name}"
                raise ValueError(msg)
            values[name] += amount

    def observe(self, stage: str, observation: CanonicalCredentialObservation) -> None:
        if stage not in QueryFunnel.model_fields:
            raise ValueError(f"unknown query funnel metric: {stage}")
        source, query = observation.primary_provenance
        self._funnels.setdefault((source, query), QueryFunnel().model_dump())
        self._observed.setdefault((source, query, stage), set()).add(observation.identity)

    def snapshot(self) -> list[QueryMetric]:
        snapshots = {key: dict(values) for key, values in self._funnels.items()}
        for (source, query, stage), identities in self._observed.items():
            snapshots[(source, query)][stage] = len(identities)
        return [
            QueryMetric(source=source, query=query, funnel=QueryFunnel(**values))
            for (source, query), values in sorted(snapshots.items())
        ]
