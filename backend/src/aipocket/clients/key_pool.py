"""Shared multi-key rotation with throttling and multi-round retries.

Both FOFA and Shodan clients used a fail-fast loop of ``len(keys)`` attempts that
skipped dead keys without retrying live ones. That made a single 429 (or one
dead key eating a slot) surface as ``all keys failed`` even when another key
still had quota.

This pool:
- round-robins **only among live keys** (dead keys never consume attempts)
- enforces a global min interval between HTTP calls (per client instance)
- supports per-key cooldowns (rate-limit backoff)
- allows multiple full rounds over the live set before giving up
"""

from __future__ import annotations

import logging
import time

log = logging.getLogger(__name__)


class KeyPool:
    """Round-robin among live keys with optional global min interval."""

    def __init__(
        self,
        keys: list[str],
        *,
        min_interval: float = 0.0,
        label: str = "key",
        max_rounds: int = 3,
    ):
        if not keys:
            raise ValueError("keys required")
        self.keys = list(keys)
        self.min_interval = max(0.0, float(min_interval))
        self.label = label
        self.max_rounds = max(1, int(max_rounds))
        self._dead: set[str] = set()
        self._rr = 0
        self._last_request_mono = 0.0
        self._key_cooldown_until: dict[str, float] = {}

    @property
    def dead(self) -> set[str]:
        return self._dead

    def live_keys(self) -> list[str]:
        return [k for k in self.keys if k not in self._dead]

    def mark_dead(self, key: str, reason: str) -> None:
        if key in self._dead:
            return
        log.error("  %s %s… dead: %s", self.label, key[:6], reason)
        self._dead.add(key)

    def cooldown(self, key: str, seconds: float) -> None:
        until = time.monotonic() + max(0.0, seconds)
        prev = self._key_cooldown_until.get(key, 0.0)
        self._key_cooldown_until[key] = max(prev, until)

    def max_attempts(self) -> int:
        """Upper bound of tries for one logical request.

        At least a few attempts even with a single live key (so 429 can recover),
        scaled by configured key count so multi-key pools get more chances.
        """
        n = max(len(self.live_keys()), 1)
        return max(5, n * self.max_rounds)

    def pick(self) -> str | None:
        """Pick next live key, waiting out cooldowns if needed."""
        live = self.live_keys()
        if not live:
            return None

        now = time.monotonic()
        n = len(live)
        for i in range(n):
            key = live[(self._rr + i) % n]
            if self._key_cooldown_until.get(key, 0.0) <= now:
                self._rr = (self._rr + i + 1) % n
                return key

        # All live keys cooling down — wait for the soonest, then use it.
        key = min(live, key=lambda k: self._key_cooldown_until.get(k, 0.0))
        wait = self._key_cooldown_until.get(key, 0.0) - now
        if wait > 0:
            log.warning(
                "  %s %s… cooling down %.1fs",
                self.label,
                key[:6],
                wait,
            )
            time.sleep(wait)
        live_after = self.live_keys()
        if not live_after:
            return None
        if key not in live_after:
            key = live_after[0]
        try:
            idx = live_after.index(key)
            self._rr = (idx + 1) % len(live_after)
        except ValueError:
            self._rr = 0
        return key

    def throttle(self) -> None:
        """Sleep so consecutive HTTP calls respect ``min_interval``."""
        if self.min_interval <= 0:
            self._last_request_mono = time.monotonic()
            return
        now = time.monotonic()
        wait = self.min_interval - (now - self._last_request_mono)
        if wait > 0:
            time.sleep(wait)
        self._last_request_mono = time.monotonic()


def rate_limit_backoff(attempt: int, base: float, *, cap: float = 30.0) -> float:
    """Exponential backoff: base, 2base, 4base… capped."""
    base = max(base, 0.5)
    exp = min(max(attempt - 1, 0), 5)
    return min(cap, base * (2**exp))
