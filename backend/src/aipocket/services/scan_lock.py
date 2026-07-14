from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from dataclasses import dataclass, field
from typing import Any

from aipocket.core.config import settings

log = logging.getLogger(__name__)

_LOCK_KEY = "aipocket:scan:lock"
_RENEW_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('pexpire', KEYS[1], ARGV[2])
end
return 0
"""
_RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0
"""


class ScanLockedError(RuntimeError):
    pass


@dataclass(slots=True)
class ScanLease:
    redis: Any
    token: str
    ttl_seconds: int
    _heartbeat_task: asyncio.Task[None] | None = field(default=None, init=False)

    async def renew(self) -> bool:
        result = await self.redis.eval(
            _RENEW_SCRIPT,
            1,
            _LOCK_KEY,
            self.token,
            self.ttl_seconds * 1000,
        )
        return bool(result)

    async def release(self) -> bool:
        result = await self.redis.eval(_RELEASE_SCRIPT, 1, _LOCK_KEY, self.token)
        return bool(result)

    async def _heartbeat(self) -> None:
        while True:
            await asyncio.sleep(max(1.0, self.ttl_seconds / 3))
            if not await self.renew():
                raise ScanLockedError("scan lease ownership was lost")

    async def run(self, awaitable: Any) -> Any:
        """Run scan work while the lease heartbeat remains healthy."""
        heartbeat = asyncio.create_task(self._heartbeat())
        work = asyncio.ensure_future(awaitable)
        self._heartbeat_task = heartbeat
        done, _pending = await asyncio.wait({heartbeat, work}, return_when=asyncio.FIRST_COMPLETED)
        if heartbeat in done:
            try:
                await heartbeat
            except BaseException:
                work.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await work
                raise
        return await work

    async def __aenter__(self) -> ScanLease:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._heartbeat_task
        await self.release()
        await self.redis.aclose()


async def acquire_scan_lease() -> ScanLease:
    from redis.asyncio import Redis

    redis = Redis.from_url(settings.dedup_redis_url, decode_responses=True)
    token = secrets.token_urlsafe(32)
    ttl_seconds = max(3, int(settings.scan_lock_ttl))
    try:
        acquired = await redis.set(_LOCK_KEY, token, nx=True, px=ttl_seconds * 1000)
    except Exception:
        await redis.aclose()
        raise
    if not acquired:
        await redis.aclose()
        raise ScanLockedError("a scan is already running")
    return ScanLease(redis=redis, token=token, ttl_seconds=ttl_seconds)


async def clear_stale_scan_lock() -> bool:
    """Delete any leftover scan lock (best-effort).

    Call on process startup after a hard restart (Docker kill, OOM, etc.).
    The previous process could not run ``ScanLease.release()``, so Redis may still
    hold ``aipocket:scan:lock`` for up to ``scan_lock_ttl`` seconds and block new
    scans. Safe for single-instance / single-active-scanner deploys: an in-flight
    scan in *another* process would lose its lease on the next heartbeat.
    """
    from redis.asyncio import Redis

    redis = Redis.from_url(settings.dedup_redis_url, decode_responses=True)
    try:
        removed = bool(await redis.delete(_LOCK_KEY))
        if removed:
            log.warning(
                "Cleared stale scan lock %s (previous process likely died mid-scan)",
                _LOCK_KEY,
            )
        return removed
    except Exception as e:  # noqa: BLE001 — startup must not fail if Redis is down
        log.warning("Could not clear stale scan lock: %s", e)
        return False
    finally:
        await redis.aclose()
