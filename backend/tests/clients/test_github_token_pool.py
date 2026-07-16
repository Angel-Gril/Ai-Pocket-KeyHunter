"""Unit tests for quota-aware GitHubTokenPool."""

from __future__ import annotations

import time

from aipocket.clients.github_token_pool import GitHubTokenPool


def test_independent_remaining_for_search_vs_core():
    pool = GitHubTokenPool(["tok_aaa", "tok_bbb"])
    pool.update_from_headers(
        "tok_aaa",
        {
            "x-ratelimit-resource": "search",
            "x-ratelimit-remaining": "1",
            "x-ratelimit-reset": str(int(time.time()) + 3600),
        },
    )
    pool.update_from_headers(
        "tok_bbb",
        {
            "x-ratelimit-resource": "search",
            "x-ratelimit-remaining": "30",
            "x-ratelimit-reset": str(int(time.time()) + 3600),
        },
    )
    # core defaults equal — either ok; search prefers higher remaining.
    picked = pool.pick("search")
    assert picked == "tok_bbb"
    # Exhaust bbb search; aaa still has 1.
    pool.update_from_headers(
        "tok_bbb",
        {
            "x-ratelimit-resource": "search",
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": str(int(time.time()) + 3600),
        },
    )
    assert pool.pick("search") == "tok_aaa"
    # core still available on bbb despite search=0
    assert pool.remaining("tok_bbb", "core") > 0
    assert pool.pick("core") in {"tok_aaa", "tok_bbb"}


def test_auth_failure_marks_token_dead():
    pool = GitHubTokenPool(["dead_tok", "live_tok"])
    pool.mark_dead("dead_tok", "auth 401")
    assert "dead_tok" in pool.dead
    for _ in range(5):
        assert pool.pick("core") == "live_tok"


def test_primary_rate_limit_cooldown_until_reset():
    pool = GitHubTokenPool(["t1"])
    reset = int(time.time()) + 120
    wait = pool.apply_rate_limit_response(
        "t1",
        resource="search",
        headers={
            "x-ratelimit-resource": "search",
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": str(reset),
        },
        secondary=False,
    )
    assert wait >= 1.0
    # A cooled token is deferred instead of being returned for an early retry.
    assert pool.pick("search") is None
    assert pool.retry_after("search") is not None


def test_secondary_rate_limit_min_60s():
    pool = GitHubTokenPool(["t1"])
    wait = pool.apply_rate_limit_response(
        "t1",
        resource="core",
        headers={"retry-after": "5"},
        secondary=True,
    )
    assert wait >= 60.0
    # Global cooldown blocks all resources.
    assert pool._ready_tokens("core", time.monotonic()) == []
    assert pool._ready_tokens("search", time.monotonic()) == []
    assert pool.pick("core") is None
    assert pool.pick("search") is None
    assert pool.retry_after("core") is not None


def test_retry_after_respected():
    pool = GitHubTokenPool(["t1"])
    wait = pool.apply_rate_limit_response(
        "t1",
        resource="code_search",
        headers={
            "retry-after": "42",
            "x-ratelimit-resource": "code_search",
            "x-ratelimit-remaining": "0",
        },
        secondary=False,
    )
    assert wait == 42.0
    assert pool._ready_tokens("code_search", time.monotonic()) == []
    # Other resources remain usable.
    assert pool.pick("core") == "t1"


def test_pick_prefers_budget_for_resource():
    pool = GitHubTokenPool(["low", "high"])
    pool.update_from_headers(
        "low",
        {"x-ratelimit-resource": "core", "x-ratelimit-remaining": "2"},
    )
    pool.update_from_headers(
        "high",
        {"x-ratelimit-resource": "core", "x-ratelimit-remaining": "4000"},
    )
    assert pool.pick("core") == "high"
