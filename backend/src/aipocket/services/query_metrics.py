from __future__ import annotations

from dataclasses import dataclass, field

from aipocket.core.metrics import QueryFunnel, QueryMetric


@dataclass(slots=True)
class QueryMetricsCollector:
    """Mutable scan-lifetime accumulator that emits immutable metric snapshots."""

    _funnels: dict[tuple[str, str], dict[str, int]] = field(default_factory=dict)

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

    def snapshot(self) -> list[QueryMetric]:
        return [
            QueryMetric(source=source, query=query, funnel=QueryFunnel(**values))
            for (source, query), values in sorted(self._funnels.items())
        ]
