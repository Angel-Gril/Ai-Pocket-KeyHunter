from __future__ import annotations

from aipocket.core.models import Credential
from aipocket.core.observations import ExtractionMethod, ObservationRegistry
from aipocket.services.query_metrics import QueryMetricsCollector


def test_collector_keeps_one_monotonic_funnel_per_source_query() -> None:
    collector = QueryMetricsCollector()

    collector.increment("fofa", "product=example", raw_hits=3, query_credits=1)
    collector.increment("fofa", "product=example", raw_hits=2, unique_targets=2)
    collector.increment("shodan", 'http.title:"example"', raw_hits=1)

    rows = collector.snapshot()

    assert len(rows) == 2
    assert rows[0].source == "fofa"
    assert rows[0].query == "product=example"
    assert rows[0].funnel.raw_hits == 5
    assert rows[0].funnel.unique_targets == 2
    assert rows[0].funnel.query_credits == 1
    assert rows[1].source == "shodan"


def test_snapshot_is_immutable_and_does_not_change_after_later_increments() -> None:
    collector = QueryMetricsCollector()
    collector.increment("fofa", "q", candidates=1)
    first = collector.snapshot()

    collector.increment("fofa", "q", candidates=2, auth_confirmed=1)

    assert first[0].funnel.candidates == 1
    assert collector.snapshot()[0].funnel.candidates == 3
    assert collector.snapshot()[0].funnel.auth_confirmed == 1


def test_canonical_observation_is_counted_once_with_first_attribution() -> None:
    registry = ObservationRegistry()
    credential = Credential(
        apikey="sk-proj-" + "a" * 24,
        apiurl="https://api.example/v1/",
        host="https://leak.example",
    )
    first = registry.observe(
        credential,
        ExtractionMethod.REGEX,
        (("fofa", "query-1"), ("shodan", "query-2")),
    )
    registry.observe(
        credential,
        ExtractionMethod.PROBER,
        (("shodan", "query-2"),),
    )
    registry.observe(
        credential,
        ExtractionMethod.GPT,
        (("fofa", "query-1"),),
    )

    collector = QueryMetricsCollector()
    collector.observe("candidates", first)
    collector.observe("candidates", registry.observations[0])
    rows = collector.snapshot()

    assert len(registry.observations) == 1
    assert registry.observations[0].method is ExtractionMethod.REGEX
    assert registry.observations[0].primary_provenance == ("fofa", "query-1")
    assert registry.observations[0].all_provenance == {
        ("fofa", "query-1"),
        ("shodan", "query-2"),
    }
    assert len(rows) == 1
    assert rows[0].query == "query-1"
    assert rows[0].funnel.candidates == 1
    assert rows[0].attribution_version == 2
