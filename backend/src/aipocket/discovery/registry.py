"""Resolve and run discovery sources for a scan."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from aipocket.core.config import Settings
from aipocket.core.config import settings as default_settings
from aipocket.core.models import ScanMode
from aipocket.core.scan_policy import ScanPolicy, policy_from_mode
from aipocket.discovery.base import (
    CredentialSourceObservation,
    DiscoverySource,
    SourceBudgets,
    SourceFetchResult,
)
from aipocket.discovery.fofa_source import FofaSource
from aipocket.discovery.shodan_source import ShodanSource

log = logging.getLogger(__name__)


def _builtin_sources(cfg: Settings) -> dict[str, DiscoverySource]:
    sources: dict[str, DiscoverySource] = {
        "fofa": FofaSource(),
        "shodan": ShodanSource(),
    }
    # GitHub adapter is optional — import lazily so FOFA/Shodan work without it.
    try:
        from aipocket.discovery.github_source import GitHubSource

        sources["github"] = GitHubSource()
    except ImportError:
        pass
    # Manual targets are always registered; is_configured() gates empty lists.
    try:
        from aipocket.discovery.manual_source import ManualSource

        sources["manual"] = ManualSource()
    except ImportError:
        pass
    return sources


class SourceRegistry:
    def __init__(self, sources: dict[str, DiscoverySource] | None = None) -> None:
        self._sources = sources or {}

    @classmethod
    def default(cls, cfg: Settings | None = None) -> SourceRegistry:
        return cls(_builtin_sources(cfg or default_settings))

    def register(self, source: DiscoverySource) -> None:
        self._sources[source.name] = source

    def resolve(
        self,
        requested: set[str] | None,
        settings: Settings | None = None,
    ) -> list[DiscoverySource]:
        """Return sources that should run for this scan.

        - requested=None / {"all"} → every known source that is configured
          (GitHub may still self-skip when tokens/PG missing).
        - requested={"fofa"} → only fofa if configured, else empty list.
        """
        cfg = settings or default_settings
        if not self._sources:
            self._sources = _builtin_sources(cfg)

        names: set[str]
        if requested is None or requested == {"all"} or "all" in (requested or set()):
            names = set(self._sources)
        else:
            names = set(requested)

        out: list[DiscoverySource] = []
        for name in sorted(names):
            src = self._sources.get(name)
            if src is None:
                log.warning("Unknown discovery source %r — ignored", name)
                continue
            if not src.is_configured():
                # Strict single-source request still surfaces as unconfigured later.
                if requested is not None and name in requested and "all" not in requested:
                    out.append(src)  # let fetch report the error
                else:
                    log.info("%s not configured — skipping", name)
                continue
            out.append(src)
        return out

    async def fetch_all(
        self,
        sources: list[DiscoverySource],
        *,
        budgets: SourceBudgets,
        mode: ScanMode,
        policy: ScanPolicy | None = None,
        skip_direct: bool = False,
        **kwargs: Any,
    ) -> list[SourceFetchResult]:
        strict_sources = frozenset(kwargs.pop("strict_sources", ()))
        policy = policy or policy_from_mode(mode)
        if not sources:
            return []
        coros = [
            s.fetch(
                budgets=budgets,
                mode=mode,
                policy=policy,
                skip_direct=skip_direct,
                strict=s.name in strict_sources,
                **kwargs,
            )
            for s in sources
        ]
        raw = await asyncio.gather(*coros, return_exceptions=True)
        results: list[SourceFetchResult] = []
        for src, item in zip(sources, raw, strict=True):
            if isinstance(item, Exception):
                log.error("Source %s failed: %s", src.name, item)
                results.append(
                    SourceFetchResult(source=src.name, errors=(f"{type(item).__name__}: {item}",))
                )
            else:
                results.append(item)
        return results


def merge_fetch_results(
    results: list[SourceFetchResult],
) -> tuple[
    list[dict[str, Any]],
    list[CredentialSourceObservation],
    list[str],
    dict[str, int],
    list[str],
    list,
]:
    """Split host hits vs credential observations; never cross-contaminate."""
    host_hits: list[dict[str, Any]] = []
    cred_obs: list[CredentialSourceObservation] = []
    sources_used: list[str] = []
    hits_by_source: dict[str, int] = {}
    queries_used: list[str] = []
    all_usage: list = []
    errors: list[str] = []

    for r in results:
        if r.errors and not r.host_hits and not r.credential_observations:
            errors.extend(r.errors)
            continue
        has_data = bool(r.host_hits or r.credential_observations or r.query_usage)
        if has_data and r.source not in sources_used:
            sources_used.append(r.source)
        host_hits.extend(r.host_hits)
        cred_obs.extend(r.credential_observations)
        # Host count for host sources; observation count for credential sources.
        # Prefer explicit counters when the source spilled payloads to PG.
        is_cred_lane = r.source == "github" or (
            bool(r.credential_observations) and not r.host_hits and r.host_hit_count is None
        )
        if is_cred_lane:
            hits_by_source[r.source] = (
                r.credential_observation_count
                if r.credential_observation_count is not None
                else len(r.credential_observations)
            )
        else:
            hits_by_source[r.source] = (
                r.host_hit_count if r.host_hit_count is not None else len(r.host_hits)
            )
        for u in r.query_usage:
            queries_used.append(u.query)
            all_usage.append(u)
        errors.extend(r.errors)

    return host_hits, cred_obs, sources_used, hits_by_source, queries_used, all_usage
