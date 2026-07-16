from __future__ import annotations

from dataclasses import dataclass, field

from aipocket.core.metrics import QueryFunnel, QueryMetric
from aipocket.core.observations import CanonicalCredentialObservation, CredentialIdentity


@dataclass(slots=True)
class QueryMetricsCollector:
    """Mutable scan-lifetime accumulator that emits immutable metric snapshots."""

    _funnels: dict[tuple[str, str], dict[str, int]] = field(default_factory=dict)
    _observed: dict[tuple[str, str, str], set[CredentialIdentity]] = field(default_factory=dict)
    _attribution: dict[tuple[str, str], tuple[str, str, str]] = field(default_factory=dict)
    _ledger_applied: bool = False

    def increment(
        self,
        source: str,
        query: str,
        *,
        query_id: str = "",
        lane: str = "",
        pack_id: str = "",
        **increments: int,
    ) -> None:
        values = self._funnels.setdefault((source, query), QueryFunnel().model_dump())
        if query_id or lane or pack_id:
            self._attribution[(source, query)] = (query_id or query, lane, pack_id)
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

    def apply_ledger(self, by_query: dict[tuple[str, str], int]) -> None:
        """Attach physical-attempt counts to already registered query metadata."""
        if self._ledger_applied:
            return
        for (source, query_id), count in by_query.items():
            matches = [
                key
                for key, attribution in self._attribution.items()
                if key[0] == source and attribution[0] == query_id
            ]
            key = matches[0] if matches else (source, query_id)
            values = self._funnels.setdefault(key, QueryFunnel().model_dump())
            values["total_active_http_requests"] += count
            self._attribution.setdefault(key, (query_id, "", ""))

        self._ledger_applied = True

    def snapshot(self, *, attribution_version: int = 2) -> list[QueryMetric]:
        snapshots = {key: dict(values) for key, values in self._funnels.items()}
        for (source, query, stage), identities in self._observed.items():
            snapshots[(source, query)][stage] = len(identities)
        rows: list[QueryMetric] = []
        for (source, query), values in sorted(snapshots.items()):
            query_id, lane, pack_id = self._attribution.get((source, query), (query, "", ""))
            rows.append(
                QueryMetric(
                    source=source,
                    query=query,
                    funnel=QueryFunnel(**values),
                    attribution_version=attribution_version,
                    query_id=query_id if attribution_version >= 3 else "",
                    lane=lane if attribution_version >= 3 else "",
                    pack_id=pack_id if attribution_version >= 3 else "",
                )
            )
        return rows
