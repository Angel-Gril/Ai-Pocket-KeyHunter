from __future__ import annotations

import pytest

from aipocket.core.config import settings
from aipocket.services.dedup import (
    NoopDedupStore,
    RedisDedupStore,
    _cred_key,
    _host_key,
    get_dedup_store,
)
from aipocket.core.models import Credential, ValidationResult


def _cred(apikey: str = "sk-test-aaa", apiurl: str = "https://h.com/v1") -> Credential:
    return Credential(apikey=apikey, apiurl=apiurl, host="https://h.com")


# ---------------------------------------------------------------------------
# key derivation
# ---------------------------------------------------------------------------


def test_cred_key_stable_and_url_sensitive():
    c1 = _cred("sk-a", "https://x.com/v1")
    c2 = _cred("sk-a", "https://x.com/v1")
    c3 = _cred("sk-a", "https://y.com/v1")
    assert _cred_key(c1) == _cred_key(c2)
    assert _cred_key(c1) != _cred_key(c3)


def test_cred_key_falls_back_to_host_when_url_empty():
    c = Credential(apikey="sk-a", apiurl="", host="https://h.com")
    assert _cred_key(c) == _cred_key(Credential(apikey="sk-a", apiurl="https://h.com"))


def test_host_key_empty_string_safe():
    assert isinstance(_host_key(""), str)
    assert _host_key("a") != _host_key("b")


# ---------------------------------------------------------------------------
# NoopDedupStore
# ---------------------------------------------------------------------------


async def test_noop_filters_return_everything_and_cache_misses():
    s = NoopDedupStore()
    hosts = [{"host": "a"}, {"host": "b"}]
    assert await s.filter_unseen_hosts(hosts) == hosts
    assert await s.get_cached_valid(_cred()) is None
    assert await s.get_cached_balance(_cred()) is None
    assert await s.is_recently_failed(_cred()) is False
    # All write ops are no-ops; just confirm they don't raise.
    await s.mark_host("a")
    await s.cache_valid(ValidationResult(credential=_cred(), valid=True))
    await s.mark_failed(_cred())
    await s.cache_balance(_cred(), {"balance_usd": 1})
    await s.close()


# ---------------------------------------------------------------------------
# RedisDedupStore — uses fakeredis
# ---------------------------------------------------------------------------


@pytest.fixture
def redis_store(monkeypatch):
    fakeredis = pytest.importorskip("fakeredis")
    client = fakeredis.FakeAsyncRedis(decode_responses=True)
    # Keep TTLs tiny so we can exercise expiry without sleeping for hours.
    monkeypatch.setattr(settings, "dedup_enabled", True)
    monkeypatch.setattr(settings, "dedup_host_ttl", 604800)
    monkeypatch.setattr(settings, "dedup_cred_ttl", 259200)
    monkeypatch.setattr(settings, "dedup_fail_ttl", 21600)
    monkeypatch.setattr(settings, "dedup_balance_ttl", 86400)
    return RedisDedupStore(client), client


async def test_host_mark_and_filter(redis_store):
    store, _ = redis_store
    hosts = [{"host": "a.com"}, {"host": "b.com"}, {"host": "c.com"}]
    await store.mark_host("a.com")
    unseen = await store.filter_unseen_hosts(hosts)
    assert {h["host"] for h in unseen} == {"b.com", "c.com"}


async def test_host_filter_empty_input(redis_store):
    store, _ = redis_store
    assert await store.filter_unseen_hosts([]) == []


async def test_valid_result_round_trip(redis_store):
    store, _ = redis_store
    cred = _cred()
    result = ValidationResult(
        credential=cred, valid=True, status_code=200, tier="tier5", model_available="gpt-4"
    )
    await store.cache_valid(result)
    hit = await store.get_cached_valid(cred)
    assert hit is not None
    assert hit.valid is True
    assert hit.status_code == 200
    assert hit.tier == "tier5"
    assert hit.model_available == "gpt-4"
    assert hit.credential.apikey == cred.apikey


async def test_valid_cache_miss_for_unknown_cred(redis_store):
    store, _ = redis_store
    await store.cache_valid(ValidationResult(credential=_cred("sk-real"), valid=True))
    assert await store.get_cached_valid(_cred("sk-other")) is None


async def test_failed_marker_round_trip(redis_store):
    store, _ = redis_store
    cred = _cred()
    assert await store.is_recently_failed(cred) is False
    await store.mark_failed(cred)
    assert await store.is_recently_failed(cred) is True
    # Different cred is unaffected.
    assert await store.is_recently_failed(_cred("sk-other")) is False


async def test_balance_round_trip(redis_store):
    store, _ = redis_store
    cred = _cred()
    assert await store.get_cached_balance(cred) is None
    await store.cache_balance(cred, {"balance_usd": 12.34, "gateway": "openai"})
    hit = await store.get_cached_balance(cred)
    assert hit == {"balance_usd": 12.34, "gateway": "openai"}


async def test_corrupt_cred_cache_returns_none(redis_store):
    store, client = redis_store
    cred = _cred()
    # Write garbage directly under the cred key.
    from aipocket.services.dedup import _PREFIX
    from aipocket.services.dedup import _cred_key as ck
    await client.set(f"{_PREFIX}:cred:ok:{ck(cred)}", "not-json{")
    assert await store.get_cached_valid(cred) is None


async def test_balance_corrupt_returns_none(redis_store):
    store, client = redis_store
    cred = _cred()
    from aipocket.services.dedup import _PREFIX
    from aipocket.services.dedup import _cred_key as ck
    await client.set(f"{_PREFIX}:cred:bal:{ck(cred)}", "not-json")
    assert await store.get_cached_balance(cred) is None


# ---------------------------------------------------------------------------
# get_dedup_store factory
# ---------------------------------------------------------------------------


async def test_factory_disabled_returns_noop(monkeypatch):
    monkeypatch.setattr(settings, "dedup_enabled", False)
    store = await get_dedup_store()
    assert isinstance(store, NoopDedupStore)


async def test_factory_unreachable_redis_degrades(monkeypatch):
    """A clearly-bad URL must not raise — it returns NoopDedupStore."""
    monkeypatch.setattr(settings, "dedup_enabled", True)
    monkeypatch.setattr(settings, "dedup_redis_url", "redis://127.0.0.1:1/0")
    store = await get_dedup_store()
    assert isinstance(store, NoopDedupStore)
