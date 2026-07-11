from __future__ import annotations

import time

from aipocket.clients.key_pool import KeyPool, rate_limit_backoff


def test_pick_skips_dead_keys():
    pool = KeyPool(["a", "b", "c"], min_interval=0, max_rounds=2)
    pool.mark_dead("a", "test")
    pool.mark_dead("c", "test")
    seen = {pool.pick() for _ in range(4)}
    assert seen == {"b"}


def test_max_attempts_scales_and_has_floor():
    pool = KeyPool(["only"], min_interval=0, max_rounds=3)
    assert pool.max_attempts() == 5  # floor
    pool2 = KeyPool(["k1", "k2", "k3", "k4"], min_interval=0, max_rounds=3)
    assert pool2.max_attempts() == 12


def test_cooldown_waits_for_soonest_key(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    pool = KeyPool(["a", "b"], min_interval=0, max_rounds=2)
    pool.cooldown("a", 0.4)
    pool.cooldown("b", 0.2)
    key = pool.pick()
    assert key in {"a", "b"}
    assert sleeps  # waited for a cooling key
    assert min(sleeps) >= 0.15


def test_rate_limit_backoff_grows_and_caps():
    assert rate_limit_backoff(1, base=1.0) == 1.0
    assert rate_limit_backoff(2, base=1.0) == 2.0
    assert rate_limit_backoff(3, base=1.0) == 4.0
    assert rate_limit_backoff(10, base=1.0, cap=30.0) == 30.0
