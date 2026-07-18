"""Quota-aware GitHub token pool with per-resource remaining counters.

Unlike :class:`KeyPool` (generic round-robin), this pool tracks independent
``core`` / ``search`` / ``code_search`` remaining quotas per token so search
pagination never starves artifact fetches (and vice versa).

Rules:
- 401 / invalid auth → mark token dead
- Primary rate limit → cooldown until X-RateLimit-Reset or Retry-After
- Secondary rate limit → ≥60s pause (no tight retry loop)
- Repo 404/409 must *not* kill the token (handled by the client, not here)
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Literal

from aipocket.core.request_ledger import RateResource

log = logging.getLogger(__name__)

GitHubResource = Literal["core", "search", "code_search"]
GITHUB_RESOURCES: tuple[GitHubResource, ...] = ("core", "search", "code_search")

# Sensible authenticated defaults until /rate_limit or response headers arrive.
_DEFAULT_REMAINING: dict[GitHubResource, int] = {
    "core": 5000,
    "search": 30,
    "code_search": 10,
}

_SECONDARY_MIN_COOLDOWN = 60.0


def _as_github_resource(resource: RateResource | str) -> GitHubResource:
    if resource in GITHUB_RESOURCES:
        return resource  # type: ignore[return-value]
    return "core"


class GitHubTokenPool:
    """Per-token remaining for core / search / code_search; pick by resource."""

    def __init__(self, tokens: list[str], *, label: str = "github token") -> None:
        if not tokens:
            raise ValueError("tokens required")
        self.tokens = list(tokens)
        self.label = label
        self._dead: set[str] = set()
        self._dead_reasons: dict[str, str] = {}
        # remaining[token][resource] = int
        self._remaining: dict[str, dict[GitHubResource, int]] = {
            t: dict(_DEFAULT_REMAINING) for t in self.tokens
        }
        # reset_at[token][resource] = unix epoch seconds (wall clock)
        self._reset_at: dict[str, dict[GitHubResource, float]] = {
            t: {r: 0.0 for r in GITHUB_RESOURCES} for t in self.tokens
        }
        # cooldown_until[token][resource] = monotonic deadline (resource-scoped)
        self._cooldown_until: dict[str, dict[GitHubResource, float]] = {
            t: {r: 0.0 for r in GITHUB_RESOURCES} for t in self.tokens
        }
        # Global (secondary) cooldown per token — blocks all resources.
        self._global_cooldown_until: dict[str, float] = {t: 0.0 for t in self.tokens}
        self._rr: dict[GitHubResource, int] = {r: 0 for r in GITHUB_RESOURCES}

    @property
    def dead(self) -> set[str]:
        return set(self._dead)

    def live_tokens(self) -> list[str]:
        return [t for t in self.tokens if t not in self._dead]

    def remaining(self, token: str, resource: RateResource | str) -> int:
        res = _as_github_resource(resource)
        return int(self._remaining.get(token, {}).get(res, 0))

    def mark_dead(self, token: str, reason: str) -> None:
        if token in self._dead:
            return
        log.error("  %s %s… dead: %s", self.label, token[:6], reason)
        self._dead.add(token)
        self._dead_reasons[token] = reason

    def cooldown(
        self,
        token: str,
        seconds: float,
        *,
        resource: RateResource | str | None = None,
    ) -> None:
        """Pause *token* for *seconds*.

        When *resource* is None the pause is global (secondary rate limit).
        Otherwise only that resource is cooled down.
        """
        seconds = max(0.0, float(seconds))
        until = time.monotonic() + seconds
        if resource is None:
            prev = self._global_cooldown_until.get(token, 0.0)
            self._global_cooldown_until[token] = max(prev, until)
            log.warning(
                "  %s %s… global cooldown %.1fs",
                self.label,
                token[:6],
                seconds,
            )
            return
        res = _as_github_resource(resource)
        bucket = self._cooldown_until.setdefault(token, {r: 0.0 for r in GITHUB_RESOURCES})
        bucket[res] = max(bucket.get(res, 0.0), until)
        log.warning(
            "  %s %s… %s cooldown %.1fs",
            self.label,
            token[:6],
            res,
            seconds,
        )

    def cooldown_secondary(self, token: str, seconds: float | None = None) -> None:
        """Secondary rate limit — enforce a minimum 60s pause."""
        pause = max(_SECONDARY_MIN_COOLDOWN, float(seconds or _SECONDARY_MIN_COOLDOWN))
        self.cooldown(token, pause, resource=None)

    def update_from_headers(self, token: str, headers: object) -> None:
        """Refresh remaining/reset from GitHub rate-limit response headers.

        Expected headers (case-insensitive via httpx.Headers):
        - X-RateLimit-Resource
        - X-RateLimit-Remaining
        - X-RateLimit-Reset  (unix epoch)
        """
        get = _header_get(headers)
        resource_raw = (get("x-ratelimit-resource") or "core").strip().lower()
        res = _as_github_resource(resource_raw if resource_raw in GITHUB_RESOURCES else "core")

        remaining_raw = get("x-ratelimit-remaining")
        if remaining_raw is not None and remaining_raw != "":
            try:
                rem = max(0, int(remaining_raw))
            except (TypeError, ValueError):
                rem = self._remaining.get(token, {}).get(res, 0)
            bucket = self._remaining.setdefault(token, dict(_DEFAULT_REMAINING))
            bucket[res] = rem

        reset_raw = get("x-ratelimit-reset")
        if reset_raw is not None and reset_raw != "":
            try:
                reset_epoch = float(reset_raw)
            except (TypeError, ValueError):
                reset_epoch = 0.0
            self._reset_at.setdefault(token, {r: 0.0 for r in GITHUB_RESOURCES})[res] = reset_epoch

    def apply_rate_limit_response(
        self,
        token: str,
        *,
        resource: RateResource | str,
        headers: object,
        secondary: bool = False,
    ) -> float:
        """Record a 403/429 and return recommended wait seconds."""
        self.update_from_headers(token, headers)
        get = _header_get(headers)
        retry_after = _parse_retry_after(get("retry-after"))
        res = _as_github_resource(resource)

        if secondary:
            wait = max(_SECONDARY_MIN_COOLDOWN, retry_after or _SECONDARY_MIN_COOLDOWN)
            self.cooldown_secondary(token, wait)
            return wait

        if retry_after is not None:
            self.cooldown(token, retry_after, resource=res)
            return retry_after

        reset_epoch = self._reset_at.get(token, {}).get(res, 0.0)
        if reset_epoch > 0:
            wait = max(1.0, reset_epoch - time.time())
            # Cap pathological reset clocks at 1 hour for safety.
            wait = min(wait, 3600.0)
            self.cooldown(token, wait, resource=res)
            return wait

        # Fallback exponential-ish default.
        wait = 30.0
        self.cooldown(token, wait, resource=res)
        return wait

    def pick(self, resource: RateResource | str) -> str | None:
        """Pick a ready live token; never return a cooling or exhausted token.

        Selection policy (per resource, independent of other resources):
        1. Drop dead / global-cooldown / resource-cooldown / remaining<=0 tokens.
        2. Prefer highest remaining quota for *this* resource.
        3. Round-robin among tokens that share the same top remaining value so
           multi-PAT pools spread load instead of sticky-selecting token[0].
        """
        res = _as_github_resource(resource)
        now = time.monotonic()
        wall = time.time()

        # Revive tokens whose reset clock has passed.
        for token in self.live_tokens():
            rem = self._remaining.get(token, {}).get(res, 0)
            if rem <= 0:
                reset_epoch = self._reset_at.get(token, {}).get(res, 0.0)
                if reset_epoch and reset_epoch <= wall:
                    self._remaining.setdefault(token, dict(_DEFAULT_REMAINING))[res] = max(
                        1, _DEFAULT_REMAINING[res]
                    )
                    # Clear stale resource cooldown once reset has elapsed.
                    cd = self._cooldown_until.get(token)
                    if cd is not None and cd.get(res, 0.0) <= now:
                        cd[res] = 0.0

        ready = self._ready_tokens(res, now)
        return self._select(res, ready) if ready else None

    def snapshot(self) -> dict[str, dict[str, int | float | bool]]:
        """Debug/ops view: remaining + cooldown per token/resource (no secrets)."""
        now = time.monotonic()
        out: dict[str, dict[str, int | float | bool]] = {}
        for token in self.tokens:
            label = f"{token[:6]}…"
            out[label] = {
                "dead": token in self._dead,
                "global_cd_s": max(0.0, self._global_cooldown_until.get(token, 0.0) - now),
            }
            for res in GITHUB_RESOURCES:
                out[label][f"{res}_remaining"] = self._remaining.get(token, {}).get(res, 0)
                out[label][f"{res}_cd_s"] = max(
                    0.0, self._cooldown_until.get(token, {}).get(res, 0.0) - now
                )
        return out

    def retry_after(self, resource: RateResource | str) -> float | None:
        """Seconds until the earliest live token is usable, or None when all are dead."""
        res = _as_github_resource(resource)
        live = self.live_tokens()
        if not live:
            return None
        now = time.monotonic()
        wall = time.time()
        waits: list[float] = []
        for token in live:
            wait = max(0.0, self._available_at(token, res) - now)
            if self._remaining.get(token, {}).get(res, 0) <= 0:
                reset_epoch = self._reset_at.get(token, {}).get(res, 0.0)
                if reset_epoch > wall:
                    wait = max(wait, reset_epoch - wall)
            waits.append(wait)
        return min(waits) if waits else None

    def _ready_tokens(self, res: GitHubResource, now: float) -> list[str]:
        out: list[str] = []
        for token in self.live_tokens():
            if self._global_cooldown_until.get(token, 0.0) > now:
                continue
            if self._cooldown_until.get(token, {}).get(res, 0.0) > now:
                continue
            rem = self._remaining.get(token, {}).get(res, 0)
            if rem <= 0:
                continue
            out.append(token)
        return out

    def _available_at(self, token: str, res: GitHubResource) -> float:
        global_cd = self._global_cooldown_until.get(token, 0.0)
        res_cd = self._cooldown_until.get(token, {}).get(res, 0.0)
        return max(global_cd, res_cd)

    def _select(self, res: GitHubResource, ready: list[str]) -> str:
        # Highest remaining; RR among equal remaining.
        ready_sorted = sorted(
            ready,
            key=lambda t: (
                -self._remaining.get(t, {}).get(res, 0),
                self.tokens.index(t) if t in self.tokens else 0,
            ),
        )
        best_rem = self._remaining.get(ready_sorted[0], {}).get(res, 0)
        top = [t for t in ready_sorted if self._remaining.get(t, {}).get(res, 0) == best_rem]
        start = self._rr[res] % len(top)
        chosen = top[start]
        self._rr[res] = (start + 1) % max(len(top), 1)
        return chosen


def _header_get(headers: object) -> Callable[[str], str | None]:
    if headers is None:
        return lambda _k: None

    def get(name: str) -> str | None:
        try:
            # httpx.Headers is case-insensitive
            val = headers.get(name)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            try:
                val = headers.get(name.title())  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                return None
        if val is None:
            return None
        return str(val)

    return get


def _parse_retry_after(raw: str | None) -> float | None:
    if raw is None or raw == "":
        return None
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return None
