"""Runner — concurrent prober dispatch.

Given a list of hits from FOFA/Shodan, identify each hit's product, route it
to the matching prober, and run all probes concurrently. Returns a flat list
of :class:`~aipocket.models.Credential` discovered via active probing.
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

MEDIUM_EVIDENCE_SCORE = 50
HIGH_EVIDENCE_SCORE = 70


def _prober_concurrency() -> int:
    return settings.prober_concurrency


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


async def probe_hosts(hits: list[dict[str, Any]]) -> list[Credential]:
    """Probe all hits for exposed credentials.

    Each hit is fingerprinted against all registered probers. Matching probers
    run concurrently (bounded by a semaphore). Returns de-duplicated
    credentials tagged ``source_type="fingerprint"``.
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

    prober_classes = _all_probers()

    # Pre-group hits by detected product to avoid scanning every hit N times.
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

    log.info(
        "Prober: %d hits → %d probe tasks (product=%d, generic=%d)",
        len(hits),
        len(assignments),
        len(assignments) - len(unmatched_hits),
        len(unmatched_hits),
    )

    if not assignments:
        return []

    concurrency = _prober_concurrency()
    log.info("Prober concurrency: %d", concurrency)
    sem = asyncio.Semaphore(concurrency)
    all_creds: list[Credential] = []
    tasks: list[asyncio.Task[list[Credential]]] = []
    for cls, hit in assignments:
        host_label = hit.get("host", "?")[:40]

        async def _run(
            prober_cls: type[Prober] = cls,
            h: dict[str, Any] = hit,
            hl: str = host_label,
        ) -> list[Credential]:
            async with httpx.AsyncClient(
                timeout=PROBE_TIMEOUT,
                limits=httpx.Limits(max_connections=settings.max_requests_per_target),
                follow_redirects=False,
            ) as client:
                p = prober_cls(
                    client,
                    sem,
                    RequestBudget(settings.max_requests_per_target),
                    max_redirects=settings.max_probe_redirects,
                    intrusive_checks=settings.intrusive_checks,
                    authorized_scope=settings.authorized_probe_scope_list,
                )
                try:
                    return await p.probe(h)
                except Exception as e:  # noqa: BLE001
                    log.debug("prober %s on %s crashed: %s", p.product_name, hl, type(e).__name__)
                    return []

        tasks.append(asyncio.ensure_future(_run()))

    # Drive completion via as_completed so we can emit periodic INFO progress.
    # gather would block until every task finishes, leaving the web UI's log
    # buffer silent for the whole probing phase (3.5w+ hosts at concurrency 50
    # can take 20+ min). Logging roughly every 500 finished hosts keeps the
    # Scan page visibly alive without flooding it.
    progress_step = max(500, len(assignments) // 20) or 1
    results: list[list[Credential]] = []
    for done, coro in enumerate(asyncio.as_completed(tasks), start=1):
        results.append(await coro)
        if done % progress_step == 0 or done == len(assignments):
            log.info("Prober progress: %d / %d hosts", done, len(assignments))

    seen: set[tuple[str, str]] = set()
    for batch in results:
        for cred in batch:
            key = (cred.apikey, cred.host)
            if key not in seen:
                seen.add(key)
                all_creds.append(cred)

    log.info("Prober extracted %d credentials from %d hosts", len(all_creds), len(assignments))
    return all_creds
