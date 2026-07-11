"""Runner — concurrent prober dispatch.

Given a list of hits from FOFA/Shodan, identify each hit's product, route it
to the matching prober, and run probes concurrently (in memory-bounded batches).
Returns a flat list of :class:`~aipocket.models.Credential` discovered via
active probing.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from aipocket.core.config import settings
from aipocket.core.models import Credential
from aipocket.core.targets import DiscoveryTarget, canonicalize_hits

from .base import PROBE_TIMEOUT, Prober
from .budget import RequestBudget
from .evidence import TargetEvidence, score_target

log = logging.getLogger(__name__)

HIGH_EVIDENCE_SCORE = 70


def _prober_concurrency() -> int:
    return max(1, int(settings.prober_concurrency))


def _prober_batch_size() -> int:
    """Hosts scheduled as asyncio tasks per wave (memory cap)."""
    return max(1, int(settings.prober_batch_size))


def _all_probers() -> list[type[Prober]]:
    """Import and return all prober classes (lazy to avoid circular issues)."""
    from .probers import (
        DifyProber,
        FastGPTProber,
        FlowiseProber,
        LangflowProber,
        LibreChatProber,
        LiteLLMProber,
        LobeChatProber,
        NewAPIProber,
        OneAPIProber,
        OpenWebUIProber,
    )

    return [
        FlowiseProber,
        LangflowProber,
        LiteLLMProber,
        NewAPIProber,
        OneAPIProber,
        LobeChatProber,
        OpenWebUIProber,
        LibreChatProber,
        DifyProber,
        FastGPTProber,
    ]


def _select_prober(hit: dict[str, Any], prober_classes: list[type[Prober]]) -> type[Prober] | None:
    hints = {
        str(value).lower().replace("_", "-")
        for value in (hit.get("_product_hints") or [hit.get("_product", "")])
        if value
    }
    # Advisory-gated safe recipes may attach product coverage only for known fingerprints.
    for value in hit.get("_safe_recipe_products") or []:
        hints.add(str(value).lower().replace("_", "-"))
    for cls in prober_classes:
        if cls.product_name.lower() in hints:
            return cls
    for cls in prober_classes:
        try:
            if cls.identify(hit):
                return cls
        except Exception:  # noqa: BLE001 — identify must never crash the run
            continue
    return None


def attach_safe_recipe_products(
    hits: list[dict[str, Any]], products: frozenset[str]
) -> list[dict[str, Any]]:
    """Annotate hits with advisory-approved product fingerprints (no exploit payloads)."""
    if not products:
        return hits
    annotated: list[dict[str, Any]] = []
    for hit in hits:
        copy = dict(hit)
        copy["_safe_recipe_products"] = sorted(products)
        annotated.append(copy)
    return annotated


def _eligible_targets(
    targets: list[DiscoveryTarget], minimum_score: int
) -> list[tuple[DiscoveryTarget, TargetEvidence]]:
    scored = [(target, score_target(target)) for target in targets]
    return [(target, evidence) for target, evidence in scored if evidence.score >= minimum_score]


def _build_assignments(
    hits: list[dict[str, Any]],
) -> list[tuple[type[Prober], dict[str, Any]]]:
    """Fingerprint each hit and assign a prober (product or generic)."""
    prober_classes = _all_probers()
    assignments: list[tuple[type[Prober], dict[str, Any]]] = []
    unmatched_hits: list[dict[str, Any]] = []
    for hit in hits:
        selected = (
            _select_prober(hit, prober_classes)
            if hit["_evidence_score"] >= HIGH_EVIDENCE_SCORE
            else None
        )
        if selected is None:
            unmatched_hits.append(hit)
        else:
            assignments.append((selected, hit))

    # Route unmatched hosts to GenericPageProber — fetches index + .env + common
    # config paths to catch keys (especially Claude/Anthropic) in page bodies.
    from .probers import GenericPageProber

    for hit in unmatched_hits:
        assignments.append((GenericPageProber, hit))

    product_count = len(assignments) - len(unmatched_hits)
    log.info(
        "Prober: %d hits → %d probe tasks (product=%d, generic=%d)",
        len(hits),
        len(assignments),
        product_count,
        len(unmatched_hits),
    )
    return assignments


async def _probe_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    prober_cls: type[Prober],
    hit: dict[str, Any],
) -> list[Credential]:
    host_label = str(hit.get("host", "?"))[:40]
    p = prober_cls(
        client,
        sem,
        RequestBudget(settings.max_requests_per_target),
        max_redirects=settings.max_probe_redirects,
        intrusive_checks=settings.intrusive_checks,
        authorized_scope=settings.authorized_probe_scope_list,
    )
    try:
        return await p.probe(hit)
    except Exception as e:  # noqa: BLE001
        log.debug("prober %s on %s crashed: %s", p.product_name, host_label, type(e).__name__)
        return []


async def _run_probe_batch(
    batch: list[tuple[type[Prober], dict[str, Any]]],
    *,
    sem: asyncio.Semaphore,
    concurrency: int,
    batch_idx: int,
    batch_total: int,
    hosts_done_before: int,
    hosts_total: int,
) -> list[list[Credential]]:
    """Schedule and await one wave of probe tasks (bounded set of asyncio Tasks)."""
    batch_len = len(batch)
    start = hosts_done_before + 1
    end = hosts_done_before + batch_len
    log.info(
        "Prober batch %d/%d: hosts %d–%d / %d (%d tasks, concurrency=%d)",
        batch_idx,
        batch_total,
        start,
        end,
        hosts_total,
        batch_len,
        concurrency,
    )

    # One shared client per batch: avoids per-host client setup and caps open
    # sockets to roughly the concurrency limit (not the full batch size).
    limits = httpx.Limits(
        max_connections=max(concurrency * 2, settings.max_requests_per_target),
        max_keepalive_connections=concurrency,
    )
    results: list[list[Credential]] = []
    async with httpx.AsyncClient(
        timeout=PROBE_TIMEOUT,
        limits=limits,
        follow_redirects=False,
    ) as client:
        tasks = [
            asyncio.create_task(_probe_one(client, sem, prober_cls, hit))
            for prober_cls, hit in batch
        ]
        # Progress every ~half-batch (or 50 hosts), so the web log stays alive
        # without flooding during large waves.
        progress_step = max(50, batch_len // 2) or 1
        batch_creds = 0
        for done, coro in enumerate(asyncio.as_completed(tasks), start=1):
            batch_result = await coro
            results.append(batch_result)
            batch_creds += len(batch_result)
            if done % progress_step == 0 or done == batch_len:
                overall = hosts_done_before + done
                log.info(
                    "Prober progress: %d / %d hosts (batch %d/%d, batch_creds=%d)",
                    overall,
                    hosts_total,
                    batch_idx,
                    batch_total,
                    batch_creds,
                )

    log.info(
        "Prober batch %d/%d done: +%d creds this batch (hosts %d/%d)",
        batch_idx,
        batch_total,
        sum(len(r) for r in results),
        hosts_done_before + batch_len,
        hosts_total,
    )
    return results


def _dedupe_creds(batches: list[list[Credential]]) -> list[Credential]:
    seen: set[tuple[str, str]] = set()
    all_creds: list[Credential] = []
    for batch in batches:
        for cred in batch:
            key = (cred.apikey, cred.host)
            if key not in seen:
                seen.add(key)
                all_creds.append(cred)
    return all_creds


async def probe_hosts(hits: list[dict[str, Any]]) -> list[Credential]:
    """Probe all hits for exposed credentials.

    Each hit is fingerprinted against all registered probers. Matching probers
    run concurrently (bounded by a semaphore), scheduled in **batches** so
    large scans (10k–30k hosts) do not materialize tens of thousands of
    asyncio Tasks at once. Returns de-duplicated credentials tagged
    ``source_type="fingerprint"``.
    """
    if not hits:
        return []

    eligible = _eligible_targets(canonicalize_hits(hits), settings.min_probe_evidence_score)
    hits = []
    for target, evidence in eligible:
        hit = target.to_hit()
        hit["_evidence_score"] = evidence.score
        hits.append(hit)
    if not hits:
        return []

    assignments = _build_assignments(hits)
    if not assignments:
        return []

    concurrency = _prober_concurrency()
    batch_size = _prober_batch_size()
    total = len(assignments)
    batch_total = (total + batch_size - 1) // batch_size
    log.info(
        "Prober plan: %d hosts, concurrency=%d, batch_size=%d → %d batch(es)",
        total,
        concurrency,
        batch_size,
        batch_total,
    )

    sem = asyncio.Semaphore(concurrency)
    collected: list[list[Credential]] = []
    hosts_done = 0

    for batch_idx in range(1, batch_total + 1):
        offset = (batch_idx - 1) * batch_size
        batch = assignments[offset : offset + batch_size]
        batch_results = await _run_probe_batch(
            batch,
            sem=sem,
            concurrency=concurrency,
            batch_idx=batch_idx,
            batch_total=batch_total,
            hosts_done_before=hosts_done,
            hosts_total=total,
        )
        collected.extend(batch_results)
        hosts_done += len(batch)

    all_creds = _dedupe_creds(collected)
    log.info(
        "Prober extracted %d credentials from %d hosts (%d batches)",
        len(all_creds),
        total,
        batch_total,
    )
    return all_creds
