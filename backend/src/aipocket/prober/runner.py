"""Runner — concurrent prober dispatch.

Given a list of hits from FOFA/Shodan, identify each hit's product, route it
to the matching prober, and run probes concurrently (in memory-bounded batches).
Returns a flat list of :class:`~aipocket.models.Credential` discovered via
active probing.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx

from aipocket.core.config import settings
from aipocket.core.models import Credential
from aipocket.core.targets import DiscoveryTarget

from .base import PROBE_TIMEOUT, Prober
from .budget import RequestBudget
from .evidence import TargetEvidence, score_target

log = logging.getLogger(__name__)

HIGH_EVIDENCE_SCORE = 70


class ProbeStatus(StrEnum):
    ATTEMPTED = "attempted"
    REJECTED_BY_EVIDENCE = "rejected_by_evidence"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ProbeTargetOutcome:
    identity_hash: str
    status: ProbeStatus
    request_count: int
    prober: str
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ProbeReport:
    credentials: tuple[Credential, ...]
    outcomes: tuple[ProbeTargetOutcome, ...]


@dataclass(frozen=True, slots=True)
class ProbeAssignment:
    target: DiscoveryTarget
    probers: tuple[type[Prober], ...]


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


def _eligible_targets(
    targets: list[DiscoveryTarget], minimum_score: int
) -> list[tuple[DiscoveryTarget, TargetEvidence]]:
    scored = [(target, score_target(target)) for target in targets]
    return [(target, evidence) for target, evidence in scored if evidence.score >= minimum_score]


def _build_assignments(
    targets: list[DiscoveryTarget], allowed_products: frozenset[str]
) -> tuple[list[ProbeAssignment], list[ProbeTargetOutcome]]:
    """Assign evidence-qualified targets without treating the allowlist as evidence."""
    from .probers import GenericPageProber

    prober_classes = _all_probers()
    normalized_allowed = {product.lower().replace("_", "-") for product in allowed_products}
    assignments: list[ProbeAssignment] = []
    rejected: list[ProbeTargetOutcome] = []
    product_count = 0

    for target in targets:
        evidence = score_target(target)
        if evidence.score < settings.min_probe_evidence_score:
            rejected.append(
                ProbeTargetOutcome(
                    identity_hash=target.identity.identity_hash,
                    status=ProbeStatus.REJECTED_BY_EVIDENCE,
                    request_count=0,
                    prober="",
                    reason=",".join(evidence.reasons) or f"score={evidence.score}",
                )
            )
            continue

        selected = (
            _select_prober(target.to_hit(), prober_classes)
            if evidence.score >= HIGH_EVIDENCE_SCORE
            else None
        )
        requires_refetch = bool(target.hit.get("_requires_content_refetch"))
        if (
            requires_refetch
            and selected is not None
            and selected.product_name.lower() in normalized_allowed
        ):
            probers = (GenericPageProber, selected)
            product_count += 1
        elif selected is not None and selected.product_name.lower() in normalized_allowed:
            probers = (selected,)
            product_count += 1
        else:
            probers = (GenericPageProber,)
        assignments.append(ProbeAssignment(target=target, probers=probers))

    log.info(
        "Prober: %d targets → %d probe tasks (product=%d, generic=%d, rejected=%d)",
        len(targets),
        len(assignments),
        product_count,
        len(assignments) - product_count,
        len(rejected),
    )
    return assignments, rejected


async def _probe_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    assignment: ProbeAssignment,
) -> tuple[list[Credential], ProbeTargetOutcome]:
    target = assignment.target
    hit = target.to_hit()
    hit["_evidence_score"] = score_target(target).score
    host_label = target.identity.url[:40]
    budget = RequestBudget(settings.max_requests_per_target)
    credentials: list[Credential] = []
    prober_names: list[str] = []
    status = ProbeStatus.SKIPPED
    reason = "no-request-issued"

    try:
        for prober_cls in assignment.probers:
            if budget.remaining <= 0:
                break
            prober = prober_cls(
                client,
                sem,
                budget,
                max_redirects=settings.max_probe_redirects,
                intrusive_checks=settings.intrusive_checks,
                authorized_scope=settings.authorized_probe_scope_list,
            )
            prober_names.append(prober.product_name)
            credentials.extend(await prober.probe(hit))
        if budget.consumed > 0:
            status = ProbeStatus.ATTEMPTED
            reason = ""
    except Exception as exc:  # noqa: BLE001 - isolate each target
        status = ProbeStatus.FAILED
        reason = type(exc).__name__
        log.debug(
            "prober %s on %s crashed: %s",
            ",".join(prober_names) or "unknown",
            host_label,
            reason,
        )

    return credentials, ProbeTargetOutcome(
        identity_hash=target.identity.identity_hash,
        status=status,
        request_count=budget.consumed,
        prober=",".join(prober_names),
        reason=reason,
    )


async def _run_probe_batch(
    batch: list[ProbeAssignment],
    *,
    sem: asyncio.Semaphore,
    concurrency: int,
    batch_idx: int,
    batch_total: int,
    hosts_done_before: int,
    hosts_total: int,
) -> list[tuple[list[Credential], ProbeTargetOutcome]]:
    """Schedule and await one bounded wave of target probe assignments."""
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

    limits = httpx.Limits(
        max_connections=max(concurrency * 2, settings.max_requests_per_target),
        max_keepalive_connections=concurrency,
    )
    results: list[tuple[list[Credential], ProbeTargetOutcome]] = []
    async with httpx.AsyncClient(
        timeout=PROBE_TIMEOUT,
        limits=limits,
        follow_redirects=False,
    ) as client:
        tasks = [asyncio.create_task(_probe_one(client, sem, assignment)) for assignment in batch]
        progress_step = max(50, batch_len // 2) or 1
        batch_creds = 0
        for done, coro in enumerate(asyncio.as_completed(tasks), start=1):
            batch_result = await coro
            results.append(batch_result)
            batch_creds += len(batch_result[0])
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
        sum(len(credentials) for credentials, _ in results),
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


async def probe_hosts(
    targets: list[DiscoveryTarget], allowed_products: frozenset[str]
) -> ProbeReport:
    """Probe canonical targets and report every routing/execution outcome."""
    if not targets:
        return ProbeReport(credentials=(), outcomes=())

    assignments, rejected = _build_assignments(targets, allowed_products)
    if not assignments:
        return ProbeReport(credentials=(), outcomes=tuple(rejected))

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
    outcomes = list(rejected)
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
        for credentials, outcome in batch_results:
            collected.append(credentials)
            outcomes.append(outcome)
        hosts_done += len(batch)

    all_creds = _dedupe_creds(collected)
    log.info(
        "Prober extracted %d credentials from %d attempted assignments (%d batches)",
        len(all_creds),
        total,
        batch_total,
    )
    return ProbeReport(credentials=tuple(all_creds), outcomes=tuple(outcomes))
