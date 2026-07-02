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

from ..config import settings
from ..models import Credential
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
        GenericPageProber,
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
        matched = False
        for cls in prober_classes:
            try:
                if cls.identify(hit):
                    assignments.append((cls, hit))
                    matched = True
                    break  # one prober per hit is enough
            except Exception:  # noqa: BLE001 — identify must never crash the run
                continue
        if not matched:
            unmatched_hits.append(hit)

    # Route unmatched hosts to GenericPageProber — fetches index + .env + common
    # config paths to catch keys (especially Claude/Anthropic) in page bodies.
    from .probers import GenericPageProber

    for hit in unmatched_hits:
        assignments.append((GenericPageProber, hit))

    log.info(
        "Prober: %d hits → %d probe tasks (product=%d, generic=%d)",
        len(hits), len(assignments), len(assignments) - len(unmatched_hits), len(unmatched_hits),
    )

    if not assignments:
        return []

    concurrency = _prober_concurrency()
    log.info("Prober concurrency: %d", concurrency)
    sem = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_connections=concurrency * 2)

    all_creds: list[Credential] = []
    async with httpx.AsyncClient(timeout=PROBE_TIMEOUT, limits=limits, follow_redirects=True) as client:
        tasks: list[asyncio.Task[list[Credential]]] = []
        for cls, hit in assignments:
            prober = cls(client, sem)
            host_label = hit.get("host", "?")[:40]

            async def _run(p: Prober = prober, h: dict[str, Any] = hit, hl: str = host_label) -> list[Credential]:
                try:
                    return await p.probe(h)
                except Exception as e:  # noqa: BLE001
                    log.debug("prober %s on %s crashed: %s", p.product_name, hl, type(e).__name__)
                    return []

            tasks.append(asyncio.ensure_future(_run()))

        results = await asyncio.gather(*tasks)

    seen: set[tuple[str, str]] = set()
    for batch in results:
        for cred in batch:
            key = (cred.apikey, cred.host)
            if key not in seen:
                seen.add(key)
                all_creds.append(cred)

    log.info("Prober extracted %d credentials from %d hosts", len(all_creds), len(assignments))
    return all_creds
