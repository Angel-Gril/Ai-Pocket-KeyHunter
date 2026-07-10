"""Cross-run deduplication store.

The scan pipeline has four expensive stages (host probing, GPT extraction,
credential validation, balance queries). Without a persistent dedup layer each
of these stages re-does work it already completed in a previous run, because
the in-memory ``seen`` sets in :mod:`scanner`/:mod:`analyzer` are lost when the
process exits.

This module provides a :class:`DedupStore` backed by Redis. Successful results
are cached and reused on the next run; failures get a short TTL so transient
errors (network, gateway timeouts) are retried later rather than cached as bad
forever. If Redis is unreachable or ``dedup_enabled`` is False, a
:class:`NoopDedupStore` is returned so the pipeline behaves exactly as before.

Keys are hashed (sha1) so raw API keys never become Redis key names. All
operations are atomic Redis primitives (SET NX + EX, GET, SISMEMBER-style SET),
so concurrent scans (e.g. the scheduler) are safe.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any, Protocol

from aipocket.core.config import settings

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from aipocket.core.models import Credential, ValidationResult

log = logging.getLogger(__name__)

_PREFIX = "aipocket:dedup"


def _h(s: str) -> str:
    """sha1 hex of a string — stable, non-reversible key component."""
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def _cred_key(cred: Credential) -> str:
    # apiurl may be empty when only host is known; fall back to host so the key
    # is still unique per endpoint.
    url = cred.apiurl or cred.host
    return _h(f"{cred.apikey}|{url}")


def _host_key(host: str) -> str:
    return _h(host or "")


class DedupStore(Protocol):
    """Persistent deduplication cache shared across runs."""

    # ---- host-level (probe + GPT share this marker) ----
    async def mark_host(self, host: str) -> None: ...
    async def filter_unseen_hosts(self, hosts: list[dict]) -> list[dict]: ...

    # ---- credential-level validation cache ----
    async def get_cached_valid(self, cred: Credential) -> ValidationResult | None: ...
    async def cache_valid(self, result: ValidationResult) -> None: ...
    async def is_recently_failed(self, cred: Credential) -> bool: ...
    async def mark_failed(self, cred: Credential) -> None: ...
    async def mark_rejected(self, cred: Credential) -> None: ...
    async def mark_transient(self, cred: Credential) -> None: ...

    # ---- balance cache ----
    async def get_cached_balance(self, cred: Credential) -> dict[str, Any] | None: ...
    async def cache_balance(self, cred: Credential, data: dict[str, Any]) -> None: ...

    async def close(self) -> None: ...


class NoopDedupStore:
    """No-op implementation — every method does nothing, cache reads miss."""

    async def mark_host(self, host: str) -> None:
        pass

    async def filter_unseen_hosts(self, hosts: list[dict]) -> list[dict]:
        return hosts

    async def get_cached_valid(self, cred: Credential) -> ValidationResult | None:
        return None

    async def cache_valid(self, result: ValidationResult) -> None:
        pass

    async def is_recently_failed(self, cred: Credential) -> bool:
        return False

    async def mark_failed(self, cred: Credential) -> None:
        pass

    async def mark_rejected(self, cred: Credential) -> None:
        pass

    async def mark_transient(self, cred: Credential) -> None:
        pass

    async def get_cached_balance(self, cred: Credential) -> dict[str, Any] | None:
        return None

    async def cache_balance(self, cred: Credential, data: dict[str, Any]) -> None:
        pass

    async def close(self) -> None:
        pass


class RedisDedupStore:
    """Redis-backed dedup store. Atomic ops + TTLs; safe under concurrency."""

    def __init__(self, client: Redis) -> None:
        self._r = client

    @staticmethod
    def _k(suffix: str) -> str:
        return f"{_PREFIX}:{suffix}"

    async def mark_host(self, host: str) -> None:
        await self._r.set(self._k(f"host:{_host_key(host)}"), "1", ex=settings.dedup_host_ttl)

    async def filter_unseen_hosts(self, hosts: list[dict]) -> list[dict]:
        if not hosts:
            return hosts
        # Batch existence check with a single MGET over the host keys.
        keys = [self._k(f"host:{_host_key(h.get('host', ''))}") for h in hosts]
        seen = await self._r.mget(keys)
        return [h for h, s in zip(hosts, seen, strict=True) if s is None]

    async def get_cached_valid(self, cred: Credential) -> ValidationResult | None:
        from aipocket.core.models import ValidationResult

        raw = await self._r.get(self._k(f"cred:ok:{_cred_key(cred)}"))
        if not raw:
            return None
        try:
            return ValidationResult.model_validate_json(raw)
        except Exception as e:  # noqa: BLE001 - corrupt cache shouldn't crash the run
            log.warning("dedup: corrupt cred cache entry, ignoring: %s", e)
            return None

    async def cache_valid(self, result: ValidationResult) -> None:
        await self._r.set(
            self._k(f"cred:ok:{_cred_key(result.credential)}"),
            result.model_dump_json(),
            ex=settings.dedup_cred_ttl,
        )

    async def is_recently_failed(self, cred: Credential) -> bool:
        return bool(await self._r.get(self._k(f"cred:fail:{_cred_key(cred)}")))

    async def mark_failed(self, cred: Credential) -> None:
        await self._r.set(
            self._k(f"cred:fail:{_cred_key(cred)}"), "1", ex=settings.dedup_fail_ttl
        )

    async def mark_rejected(self, cred: Credential) -> None:
        await self._r.set(
            self._k(f"cred:rejected:{_cred_key(cred)}"), "1", ex=settings.dedup_fail_ttl
        )

    async def mark_transient(self, cred: Credential) -> None:
        await self._r.set(
            self._k(f"cred:transient:{_cred_key(cred)}"), "1", ex=settings.dedup_fail_ttl
        )

    async def get_cached_balance(self, cred: Credential) -> dict[str, Any] | None:
        raw = await self._r.get(self._k(f"cred:bal:{_cred_key(cred)}"))
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    async def cache_balance(self, cred: Credential, data: dict[str, Any]) -> None:
        await self._r.set(
            self._k(f"cred:bal:{_cred_key(cred)}"),
            json.dumps(data),
            ex=settings.dedup_balance_ttl,
        )

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            await self._r.aclose()


async def get_dedup_store() -> DedupStore:
    """Return a configured dedup store, or Noop on disable/unreachable Redis.

    Lazily imported so the redis dependency isn't required at module import
    time (tests can run without it installed).
    """
    if not settings.dedup_enabled:
        return NoopDedupStore()
    try:
        from redis.asyncio import from_url

        client = from_url(settings.dedup_redis_url, decode_responses=True)
        # Fail fast: a PING confirms the server is reachable before we hand the
        # store out, so the whole run doesn't run under a broken connection.
        await client.ping()
        log.info("dedup: Redis connected at %s", settings.dedup_redis_url)
        return RedisDedupStore(client)
    except Exception as e:  # noqa: BLE001 - any failure → graceful degrade
        log.warning("dedup: Redis unavailable (%s), degrading to no-op dedup", e)
        return NoopDedupStore()
