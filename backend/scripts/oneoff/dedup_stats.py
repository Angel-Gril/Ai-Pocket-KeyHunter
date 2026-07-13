"""Report cross-run dedup cache stats from Redis.

Shows how many hosts/credentials/balance results are cached, plus sample TTLs,
so you can see whether dedup is actually populating across runs.

Usage:
    uv run python scripts/dedup_stats.py
    DEDUP_REDIS_URL=redis://host:6379/0 uv run python scripts/dedup_stats.py
"""

from __future__ import annotations

import asyncio
import sys

from aipocket.core.config import settings

PREFIX = "aipocket:dedup"


async def main() -> int:
    if not settings.dedup_enabled:
        print("DEDUP_ENABLED=false — dedup is disabled.")
        return 0

    try:
        from redis.asyncio import from_url
    except ImportError:
        print("redis package not installed. Run: uv sync")
        return 1

    client = from_url(settings.dedup_redis_url, decode_responses=True)
    try:
        await client.ping()
    except Exception as e:  # noqa: BLE001
        print(f"Cannot reach Redis at {settings.dedup_redis_url}: {e}")
        return 1

    categories = {
        "host (probed+GPT-extracted)": f"{PREFIX}:host:",
        "cred:ok (valid cached)": f"{PREFIX}:cred:ok:",
        "cred:outcome (rejected/transient)": f"{PREFIX}:cred:outcome:",
        "cred:bal (balance cached)": f"{PREFIX}:cred:bal:",
    }

    print(f"Redis: {settings.dedup_redis_url}\n")
    print(f"{'category':<35} {'count':>8}")
    print("-" * 45)
    for label, pat in categories.items():
        n = 0
        ttl_sum = 0
        async for _ in client.scan_iter(match=f"{pat}*", count=1000):
            n += 1
        if n:
            # Sample TTLs from a handful of keys for a rough average.
            sampled = 0
            async for k in client.scan_iter(match=f"{pat}*", count=100):
                ttl_sum += await client.ttl(k)
                sampled += 1
                if sampled >= 50:
                    break
            avg_ttl = ttl_sum / sampled if sampled else 0
            print(f"{label:<35} {n:>8}   (avg TTL ~{int(avg_ttl)}s)")
        else:
            print(f"{label:<35} {n:>8}")

    await client.aclose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
