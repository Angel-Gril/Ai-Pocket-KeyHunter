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
from .capability.types import Finding, NodeOutcome
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
    findings: tuple[Finding, ...] = ()
    node_outcomes: tuple[NodeOutcome, ...] = ()
    # When True, credentials/findings/node_outcomes were spilled to PG
    # (scan_candidates / scan_probe_events) and the tuple fields may be empty.
    spilled: bool = False
    credential_count: int = 0


@dataclass(frozen=True, slots=True)
class ProbeAssignment:
    target: DiscoveryTarget
    probers: tuple[type[Prober], ...]


def _prober_concurrency() -> int:
    return max(1, int(settings.prober_concurrency))


def _prober_batch_size() -> int:
    """Hosts scheduled as asyncio tasks per wave (memory cap)."""
    return max(1, int(settings.prober_batch_size))


# product_name aliases so query/CVE labels route to the correct prober.
_PRODUCT_ALIASES: dict[str, str] = {
    "new-api": "new-api",
    "newapi": "new-api",
    "one-api": "one-api",
    "oneapi": "one-api",
    "litellm": "litellm",
    "flowise": "flowise",
    "flowiseai": "flowise",
    "librechat": "librechat",
    "dify": "dify",
    "openwebui": "openwebui",
    "open-webui": "openwebui",
    "open webui": "openwebui",
    "langflow": "langflow",
    "fastgpt": "fastgpt",
    "fast-gpt": "fastgpt",
    "lobechat": "lobechat",
    "lobe-chat": "lobechat",
    "chatgpt-next-web": "chatgpt-next-web",
    "nextchat": "chatgpt-next-web",
    "next-chat": "chatgpt-next-web",
    "next-web": "chatgpt-next-web",
    "portkey": "portkey",
    "portkey-ai-gateway": "portkey",
    "portkey ai gateway": "portkey",
    "openrouter": "openrouter",
    "open-router": "openrouter",
    "anythingllm": "anythingllm",
    "anything-llm": "anythingllm",
}


def _normalize_hint(value: str) -> str:
    return value.lower().replace("_", "-").strip()


def _hint_to_product(hint: str) -> str | None:
    """Map a free-form product hint to a prober product_name."""
    key = _normalize_hint(hint)
    if key in _PRODUCT_ALIASES:
        return _PRODUCT_ALIASES[key]
    # Token containment: "Portkey AI Gateway" → tokens match portkey
    compact = key.replace(" ", "-")
    if compact in _PRODUCT_ALIASES:
        return _PRODUCT_ALIASES[compact]
    for alias, product in _PRODUCT_ALIASES.items():
        if alias in key or alias in compact:
            return product
    return None


def _all_probers() -> list[type[Prober]]:
    """Import and return all prober classes (lazy to avoid circular issues)."""
    from .probers import (
        AnythingLLMProber,
        ChatGPTNextWebProber,
        DifyProber,
        FastGPTProber,
        FlowiseProber,
        LangflowProber,
        LibreChatProber,
        LiteLLMProber,
        LobeChatProber,
        NewAPIProber,
        OneAPIProber,
        OpenRouterProber,
        OpenWebUIProber,
        PortkeyProber,
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
        ChatGPTNextWebProber,
        PortkeyProber,
        OpenRouterProber,
        AnythingLLMProber,
    ]


def _select_prober(hit: dict[str, Any], prober_classes: list[type[Prober]]) -> type[Prober] | None:
    raw_hints = list(hit.get("_product_hints") or [])
    if hit.get("_product"):
        raw_hints.insert(0, hit["_product"])
    resolved: list[str] = []
    for value in raw_hints:
        if not value:
            continue
        product = _hint_to_product(str(value))
        if product:
            resolved.append(product)
        else:
            resolved.append(_normalize_hint(str(value)))
    by_name = {cls.product_name.lower(): cls for cls in prober_classes}
    for product in resolved:
        cls = by_name.get(product)
        if cls is not None:
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


def _allowed_product_names(allowed_products: frozenset[str]) -> frozenset[str]:
    """Normalize allowlist entries (CVE labels, aliases) to prober product_name values."""
    resolved: set[str] = set()
    for product in allowed_products:
        mapped = _hint_to_product(str(product))
        if mapped:
            resolved.add(mapped)
        else:
            resolved.add(_normalize_hint(str(product)))
    return frozenset(resolved)


def _build_assignments(
    targets: list[DiscoveryTarget], allowed_products: frozenset[str]
) -> tuple[list[ProbeAssignment], list[ProbeTargetOutcome]]:
    """Assign evidence-qualified targets without treating the allowlist as evidence."""
    from .probers import GenericPageProber

    prober_classes = _all_probers()
    normalized_allowed = _allowed_product_names(allowed_products)
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


def _budget_for_prober(prober_cls: type[Prober]) -> RequestBudget:
    """Allocate a request budget for one prober on a target.

    Generic and product probers use **independent** budgets so a refetch
    generic pass cannot starve weak-password / IDOR on the product adapter.
    """
    name = (getattr(prober_cls, "product_name", "") or "").lower()
    if name == "generic":
        limit = max(1, int(getattr(settings, "generic_max_requests_per_target", 12)))
    else:
        limit = max(1, int(settings.max_requests_per_target))
    return RequestBudget(limit)


async def _probe_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    assignment: ProbeAssignment,
) -> tuple[list[Credential], ProbeTargetOutcome, list[Finding], list[NodeOutcome]]:
    target = assignment.target
    hit = target.to_hit()
    hit["_evidence_score"] = score_target(target).score
    from aipocket.core.request_ledger import RequestAttribution, current_query_attribution

    source, query_id = target.provenance_pairs[0] if target.provenance_pairs else ("", "")
    attribution_token = current_query_attribution.set(
        RequestAttribution(source=source, query_id=query_id, lane="probe")
    )
    host_label = target.identity.url[:40]
    credentials: list[Credential] = []
    findings: list[Finding] = []
    node_outcomes: list[NodeOutcome] = []
    prober_names: list[str] = []
    total_requests = 0
    status = ProbeStatus.SKIPPED
    reason = "no-request-issued"

    try:
        try:
            for prober_cls in assignment.probers:
                budget = _budget_for_prober(prober_cls)
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
                total_requests += budget.consumed
                last = getattr(prober, "last_result", None)
                if last is not None:
                    findings.extend(last.findings)
                    node_outcomes.extend(last.node_outcomes)
            if total_requests > 0:
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

        return (
            credentials,
            ProbeTargetOutcome(
                identity_hash=target.identity.identity_hash,
                status=status,
                request_count=total_requests,
                prober=",".join(prober_names),
                reason=reason,
            ),
            findings,
            node_outcomes,
        )
    finally:
        current_query_attribution.reset(attribution_token)


async def _run_probe_batch(
    batch: list[ProbeAssignment],
    *,
    sem: asyncio.Semaphore,
    concurrency: int,
    batch_idx: int,
    batch_total: int,
    hosts_done_before: int,
    hosts_total: int,
) -> list[tuple[list[Credential], ProbeTargetOutcome, list[Finding], list[NodeOutcome]]]:
    """Run one wave with a fixed worker pool (no N-task fan-out)."""
    batch_len = len(batch)
    start = hosts_done_before + 1
    end = hosts_done_before + batch_len
    log.info(
        "Prober batch %d/%d: hosts %d–%d / %d (workers=%d, concurrency=%d)",
        batch_idx,
        batch_total,
        start,
        end,
        hosts_total,
        min(concurrency, batch_len),
        concurrency,
    )

    limits = httpx.Limits(
        max_connections=max(concurrency * 2, settings.max_requests_per_target),
        max_keepalive_connections=concurrency,
    )
    results: list[
        tuple[list[Credential], ProbeTargetOutcome, list[Finding], list[NodeOutcome]]
    ] = []
    queue: asyncio.Queue[ProbeAssignment | None] = asyncio.Queue()
    for assignment in batch:
        queue.put_nowait(assignment)
    # One sentinel per worker so each exits cleanly.
    worker_n = max(1, min(concurrency, batch_len))
    for _ in range(worker_n):
        queue.put_nowait(None)

    progress_lock = asyncio.Lock()
    done_count = 0
    batch_creds = 0
    progress_step = max(50, batch_len // 2) or 1

    async def _worker(client: httpx.AsyncClient) -> None:
        nonlocal done_count, batch_creds
        while True:
            assignment = await queue.get()
            if assignment is None:
                return
            batch_result = await _probe_one(client, sem, assignment)
            async with progress_lock:
                results.append(batch_result)
                done_count += 1
                batch_creds += len(batch_result[0])
                if done_count % progress_step == 0 or done_count == batch_len:
                    overall = hosts_done_before + done_count
                    log.info(
                        "Prober progress: %d / %d hosts (batch %d/%d, batch_creds=%d)",
                        overall,
                        hosts_total,
                        batch_idx,
                        batch_total,
                        batch_creds,
                    )

    async with httpx.AsyncClient(
        timeout=PROBE_TIMEOUT,
        limits=limits,
        follow_redirects=False,
    ) as client:
        await asyncio.gather(*(_worker(client) for _ in range(worker_n)))

    log.info(
        "Prober batch %d/%d done: +%d creds this batch (hosts %d/%d)",
        batch_idx,
        batch_total,
        batch_creds,
        hosts_done_before + batch_len,
        hosts_total,
    )
    return results


def _dedupe_creds(creds: list[Credential]) -> list[Credential]:
    seen: set[tuple[str, str]] = set()
    all_creds: list[Credential] = []
    for cred in creds:
        key = (cred.apikey, cred.host)
        if key not in seen:
            seen.add(key)
            all_creds.append(cred)
    return all_creds


def _summarize_node_outcomes(node_outcomes: list[NodeOutcome]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in node_outcomes:
        key = node.status.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _spill_batch_to_pg(
    run_id: str,
    *,
    credentials: list[Credential],
    outcomes: list[ProbeTargetOutcome],
    findings: list[Finding],
    node_outcomes: list[NodeOutcome],
) -> int:
    """Write one batch to PG and return credential rows attempted."""
    from aipocket.services.candidate_store import (
        STAGE_PROBER,
        insert_probe_events,
        upsert_candidates,
    )

    n = upsert_candidates(run_id, STAGE_PROBER, credentials, method="prober")
    insert_probe_events(
        run_id,
        outcomes=outcomes,
        findings=findings,
        node_outcomes=node_outcomes,
    )
    return n


async def probe_hosts(
    targets: list[DiscoveryTarget], allowed_products: frozenset[str]
) -> ProbeReport:
    """Probe canonical targets and report every routing/execution outcome.

    When PostgreSQL is enabled, each batch's credentials / findings are spilled
    to ``scan_candidates`` / ``scan_probe_events`` and released from RAM. The
    returned report then has ``spilled=True`` and empty credential/finding
    tuples (reload via candidate_store). Outcomes stay in-memory (small).
    """
    if not targets:
        return ProbeReport(credentials=(), outcomes=())

    assignments, rejected = _build_assignments(targets, allowed_products)
    if not assignments:
        return ProbeReport(credentials=(), outcomes=tuple(rejected))

    from aipocket.core.db import current_run_id
    from aipocket.services.candidate_store import spill_enabled

    run_id = current_run_id.get()
    use_spill = spill_enabled() and bool(run_id)

    concurrency = _prober_concurrency()
    batch_size = _prober_batch_size()
    total = len(assignments)
    batch_total = (total + batch_size - 1) // batch_size
    log.info(
        "Prober plan: %d hosts, concurrency=%d, batch_size=%d → %d batch(es) spill=%s",
        total,
        concurrency,
        batch_size,
        batch_total,
        use_spill,
    )

    sem = asyncio.Semaphore(concurrency)
    collected_creds: list[Credential] = []
    outcomes = list(rejected)
    all_findings: list[Finding] = []
    all_nodes: list[NodeOutcome] = []
    spilled_cred_count = 0
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
        batch_creds: list[Credential] = []
        batch_outcomes: list[ProbeTargetOutcome] = []
        batch_findings: list[Finding] = []
        batch_nodes: list[NodeOutcome] = []
        for credentials, outcome, findings, nodes in batch_results:
            batch_creds.extend(credentials)
            batch_outcomes.append(outcome)
            batch_findings.extend(findings)
            batch_nodes.extend(nodes)

        # Outcomes are tiny (hash + status + counts) — keep for dedup marking.
        outcomes.extend(batch_outcomes)

        if use_spill and run_id:
            n = await asyncio.to_thread(
                _spill_batch_to_pg,
                run_id,
                credentials=batch_creds,
                outcomes=batch_outcomes,
                findings=batch_findings,
                node_outcomes=batch_nodes,
            )
            spilled_cred_count += n
            # Explicitly drop batch payloads so GC can reclaim before next wave.
            del batch_creds, batch_findings, batch_nodes, batch_outcomes, batch_results
        else:
            collected_creds.extend(batch_creds)
            all_findings.extend(batch_findings)
            all_nodes.extend(batch_nodes)

        hosts_done += len(batch)

    if use_spill:
        log.info(
            "Prober spilled %d credential rows across %d batches (outcomes=%d kept in RAM)",
            spilled_cred_count,
            batch_total,
            len(outcomes),
        )
        return ProbeReport(
            credentials=(),
            outcomes=tuple(outcomes),
            findings=(),
            node_outcomes=(),
            spilled=True,
            credential_count=spilled_cred_count,
        )

    all_creds = _dedupe_creds(collected_creds)
    node_summary = _summarize_node_outcomes(all_nodes)
    confirmed = sum(1 for f in all_findings if f.confirmed)
    log.info(
        "Prober extracted %d credentials from %d attempted assignments (%d batches); "
        "findings=%d (confirmed=%d); nodes=%s",
        len(all_creds),
        total,
        batch_total,
        len(all_findings),
        confirmed,
        node_summary or "{}",
    )
    return ProbeReport(
        credentials=tuple(all_creds),
        outcomes=tuple(outcomes),
        findings=tuple(all_findings),
        node_outcomes=tuple(all_nodes),
        spilled=False,
        credential_count=len(all_creds),
    )
