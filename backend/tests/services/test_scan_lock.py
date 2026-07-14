from __future__ import annotations

import asyncio

import pytest

from aipocket.services.scan_lock import ScanLease, ScanLockedError, clear_stale_scan_lock


class FakeScriptRedis:
    def __init__(self) -> None:
        self.value: str | None = None
        self.ttl = 0

    async def set(self, _key, value, *, nx, px):
        if nx and self.value is not None:
            return False
        self.value = value
        self.ttl = px
        return True

    async def eval(self, script, _numkeys, _key, token, *args):
        if self.value != token:
            return 0
        if "pexpire" in script:
            self.ttl = args[0]
            return 1
        self.value = None
        return 1


@pytest.mark.asyncio
async def test_scan_lease_is_exclusive_and_token_safe() -> None:
    redis = FakeScriptRedis()
    first = ScanLease(redis, "owner-a", 60)
    second = ScanLease(redis, "owner-b", 60)

    assert await redis.set("aipocket:scan:lock", first.token, nx=True, px=60_000)
    assert not await redis.set("aipocket:scan:lock", second.token, nx=True, px=60_000)
    assert await second.renew() is False
    assert await second.release() is False
    assert await first.renew() is True
    assert await first.release() is True
    assert await redis.set("aipocket:scan:lock", second.token, nx=True, px=60_000)


@pytest.mark.asyncio
async def test_lease_loss_cancels_running_work() -> None:
    redis = FakeScriptRedis()
    lease = ScanLease(redis, "owner-a", 3)
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def work() -> None:
        started.set()
        try:
            await asyncio.Future()
        finally:
            cancelled.set()

    assert await redis.set("aipocket:scan:lock", lease.token, nx=True, px=3_000)
    task = asyncio.create_task(lease.run(work()))
    await started.wait()
    redis.value = "owner-b"

    with pytest.raises(ScanLockedError, match="ownership was lost"):
        await task
    assert cancelled.is_set()


class _FakeRedisClient:
    """Minimal redis.asyncio stand-in for clear_stale_scan_lock tests."""

    def __init__(self, *, delete_result: int = 1, fail: bool = False) -> None:
        self.delete_result = delete_result
        self.fail = fail
        self.deleted_keys: list[str] = []
        self.closed = False

    async def delete(self, key: str) -> int:
        if self.fail:
            raise ConnectionError("redis down")
        self.deleted_keys.append(key)
        return self.delete_result

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_clear_stale_scan_lock_deletes_key(monkeypatch) -> None:
    client = _FakeRedisClient(delete_result=1)

    class _Redis:
        @staticmethod
        def from_url(*_a, **_k):
            return client

    monkeypatch.setattr("redis.asyncio.Redis", _Redis)

    assert await clear_stale_scan_lock() is True
    assert client.deleted_keys == ["aipocket:scan:lock"]
    assert client.closed is True


@pytest.mark.asyncio
async def test_clear_stale_scan_lock_returns_false_when_absent(monkeypatch) -> None:
    client = _FakeRedisClient(delete_result=0)

    class _Redis:
        @staticmethod
        def from_url(*_a, **_k):
            return client

    monkeypatch.setattr("redis.asyncio.Redis", _Redis)

    assert await clear_stale_scan_lock() is False
    assert client.closed is True


@pytest.mark.asyncio
async def test_clear_stale_scan_lock_swallows_redis_errors(monkeypatch) -> None:
    client = _FakeRedisClient(fail=True)

    class _Redis:
        @staticmethod
        def from_url(*_a, **_k):
            return client

    monkeypatch.setattr("redis.asyncio.Redis", _Redis)

    assert await clear_stale_scan_lock() is False
    assert client.closed is True
