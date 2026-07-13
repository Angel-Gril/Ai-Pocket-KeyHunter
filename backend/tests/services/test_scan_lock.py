from __future__ import annotations

import pytest

from aipocket.services.scan_lock import ScanLease


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
