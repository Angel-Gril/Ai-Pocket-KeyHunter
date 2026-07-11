from __future__ import annotations

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
