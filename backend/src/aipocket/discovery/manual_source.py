"""Manual host discovery — user-supplied relay/gateway URLs (+ optional FOFA/Shodan enrich)."""

from __future__ import annotations

import logging
from typing import Any

from aipocket.core.models import ScanMode
from aipocket.core.scan_policy import ScanPolicy
from aipocket.discovery.base import SourceBudgets, SourceFetchResult
from aipocket.services.manual_enrich import enrich_manual_hits, normalize_enrich_engines
from aipocket.services.manual_target_store import load_enabled_urls
from aipocket.services.url_sanitize import urls_to_host_hits

log = logging.getLogger(__name__)


class ManualSource:
    """Discovery adapter that reads persisted manual targets as host hits.

    Always reports ``is_configured() == False`` so it is **opt-in only**:
    full/all scans never pull manual URLs unless the operator explicitly
    selects ``source=manual`` (dedicated page). The registry still retains
    an unconfigured-but-requested source so ``fetch`` can load targets or
    return a clear error.

    Optional ``manual_enrich`` (fofa / shodan) reverse-looks up each hostname
    to attach title/header/banner so product probers can identify gateways.
    """

    name = "manual"

    def is_configured(self) -> bool:
        # Never auto-include in "all" — manual is a dedicated lane.
        return False

    async def fetch(
        self,
        *,
        budgets: SourceBudgets,
        mode: ScanMode,
        policy: ScanPolicy | None = None,
        skip_direct: bool = False,
        **kwargs: Any,
    ) -> SourceFetchResult:
        urls = load_enabled_urls()
        if not urls:
            msg = (
                "Manual source requested but no enabled targets are stored. "
                "Add relay/gateway URLs on the「自定义狩猎」page first "
                "(requires DATABASE_URL)."
            )
            # Always surface the error for explicit source=manual (strict or not).
            return SourceFetchResult(source=self.name, errors=(msg,))

        hits = urls_to_host_hits(urls)
        for h in hits:
            if isinstance(h, dict):
                h.setdefault("_source", self.name)

        engines = normalize_enrich_engines(
            kwargs.get("manual_enrich") or (budgets.extra or {}).get("manual_enrich") or ()
        )
        usage: tuple = ()
        soft_errors: tuple[str, ...] = ()
        if engines:
            log.info(
                "Manual source: enriching %d seed hit(s) via %s",
                len(hits),
                ",".join(sorted(engines)),
            )
            hits, usage, soft_errors = enrich_manual_hits(hits, engines=engines)
            for h in hits:
                if isinstance(h, dict):
                    h.setdefault("_source", self.name)

        log.info(
            "Manual source: %d host hit(s) from stored targets%s",
            len(hits),
            f" (enrich={','.join(sorted(engines))})" if engines else "",
        )
        # Soft enrich errors (missing keys / per-host failures) are warnings —
        # seed targets still proceed. Surface them in the result for the console.
        return SourceFetchResult(
            source=self.name,
            host_hits=tuple(hits),
            host_hit_count=len(hits),
            query_usage=usage,
            errors=soft_errors,
        )
