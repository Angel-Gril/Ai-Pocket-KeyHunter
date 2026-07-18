"""Tests for GitHub query shard builders and date bisection."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aipocket.services.github_queries import (
    GitHubPackView,
    GitHubQueryShard,
    bisect_date_window,
    build_code_snapshot_shards,
    build_commit_message_shards,
    build_seeded_file_history_shards,
    default_window,
)

PACK = GitHubPackView(
    pack_id="glm",
    commit_message_anchors=(
        "glm api key",
        "GLM API KEY",  # case-only duplicate
        "zhipu",
        "path:.env leak",  # forbidden — should be dropped
    ),
    code_content_anchors=("GLM_API_KEY", "open.bigmodel.cn"),
    code_qualifier_groups=(
        ("extension:env", "path:.env"),
        ("extension:json",),
    ),
)


def test_commit_terms_never_receive_code_only_qualifiers():
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 2, tzinfo=UTC)
    shards = build_commit_message_shards(
        PACK,
        window_start=start,
        window_end=end,
        extra_qualifiers=("path:config", "is:public"),  # path forbidden, is:public ok
    )
    # Case-only dup collapsed; path-containing anchor dropped.
    anchors = {s.anchor.casefold() for s in shards}
    assert "glm api key" in anchors
    assert "zhipu" in anchors
    assert "path:.env leak" not in anchors
    for s in shards:
        s.assert_lane_invariants()
        q = s.build_q()
        assert "path:" not in q
        assert "filename:" not in q
        assert "extension:" not in q
        assert "language:" not in q
        assert "committer-date:" in q
        assert s.rate_resource == "search"
        # is:public retained if not forbidden form
        assert "path:config" not in s.qualifiers


def test_code_snapshot_uses_qualifier_groups():
    shards = build_code_snapshot_shards(PACK)
    assert len(shards) == 4  # 2 anchors × 2 groups
    for s in shards:
        assert s.lane == "code_snapshot"
        assert s.rate_resource == "code_search"
        q = s.build_q()
        assert s.anchor in q
        assert "committer-date:" not in q


def test_seeded_file_history_shards():
    shards = build_seeded_file_history_shards(
        PACK,
        [
            {
                "owner": "o",
                "repo": "r",
                "path": ".env",
                "repo_id": "1",
                "seed_origin": "code_snapshot",
                "public": True,
            },
            {"owner": "o", "repo": "r", "path": ".env", "public": True},  # dup
            {"owner": "x", "repo": "y", "path": "config.yml", "public": True},
        ],
    )
    assert len(shards) == 2
    assert all(s.lane == "seeded_file_history" for s in shards)
    assert all(s.rate_resource == "core" for s in shards)
    assert all(s.coverage_mode == "seeded_only" for s in shards)
    assert shards[0].build_q() == ""


def test_date_bisection_on_incomplete_results():
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 10, tzinfo=UTC)
    shard = GitHubQueryShard(
        lane="commit_message",
        pack_id="glm",
        query_id="q1",
        anchor="zhipu",
        qualifiers=(),
        window_start=start,
        window_end=end,
        rate_resource="search",
        page_budget=10,
        shard_id="s1",
        coverage_mode="complete",
    )
    children = bisect_date_window(shard)
    assert len(children) == 2
    assert children[0].window_end == children[1].window_start
    assert children[0].window_start == start
    assert children[1].window_end == end


def test_single_day_saturation_marks_truncated():
    start = datetime(2026, 7, 1, 0, 0, tzinfo=UTC)
    end = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    shard = GitHubQueryShard(
        lane="commit_message",
        pack_id="glm",
        query_id="q1",
        anchor="zhipu",
        qualifiers=(),
        window_start=start,
        window_end=end,
        rate_resource="search",
        page_budget=10,
        shard_id="s1",
        coverage_mode="complete",
    )
    children = bisect_date_window(shard)
    assert len(children) == 1
    assert children[0].coverage_mode == "truncated"


def test_forbidden_qualifiers_raise_on_assert():
    shard = GitHubQueryShard(
        lane="commit_message",
        pack_id="glm",
        query_id="bad",
        anchor="ok",
        qualifiers=("path:secrets",),
        window_start=None,
        window_end=None,
        rate_resource="search",
        page_budget=1,
        shard_id="x",
        coverage_mode="complete",
    )
    with pytest.raises(ValueError, match="path/filename/extension/language|forbidden"):
        shard.assert_lane_invariants()


def test_default_window_overlap():
    now = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
    start, end = default_window(
        lookback_hours=24,
        overlap_minutes=15,
        watermark="2026-07-16T10:00:00+00:00",
        now=now,
    )
    assert end == now
    # watermark - 15 min
    assert start == datetime(2026, 7, 16, 9, 45, tzinfo=UTC)


def test_default_window_without_watermark_uses_lookback():
    now = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
    start, end = default_window(
        lookback_hours=720,
        overlap_minutes=15,
        watermark="",
        now=now,
    )
    assert end == now
    assert start == datetime(2026, 6, 16, 12, 0, tzinfo=UTC)
