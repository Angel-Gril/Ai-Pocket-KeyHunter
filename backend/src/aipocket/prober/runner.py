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

from .base import PROBE_TIMEOUT, Prober

log = logging.getLogger(__name__)


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


async def probe_hosts(hits: list[dict[str, Any]]) -> list[Credential]:
    """Probe all hits for exposed credentials.

    Each hit is fingerprinted against all registered probers. Matching probers
    run concurrently (bounded by a semaphore). Returns de-duplicated
    credentials tagged ``source_type="fingerprint"``.
    """
    if not hits:
        return []

    prober_classes = _all_probers()

    # Pre-group hits by detected product to avoid scanning every hit N times.
    assignments: list[tuple[type[Prober], dict[str, Any]]] = []
    unmatched_hits: list[dict[str, Any]] = []
    for hit in hits:
        selected = _select_prober(hit, prober_classes)
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
    limits = httpx.Limits(max_connections=concurrency * 2)

    all_creds: list[Credential] = []
    async with httpx.AsyncClient(
        timeout=PROBE_TIMEOUT, limits=limits, follow_redirects=True
    ) as client:
        tasks: list[asyncio.Task[list[Credential]]] = []
        for cls, hit in assignments:
            prober = cls(client, sem)
            host_label = hit.get("host", "?")[:40]

            async def _run(
                p: Prober = prober, h: dict[str, Any] = hit, hl: str = host_label
            ) -> list[Credential]:
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
