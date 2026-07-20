"""FOFA host discovery adapter (wraps existing _fetch_fofa body)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from aipocket.core.config import settings
from aipocket.core.metrics import QueryUsage
from aipocket.core.models import ScanMode
from aipocket.core.scan_policy import ScanPolicy
from aipocket.discovery.base import SourceBudgets, SourceFetchResult

log = logging.getLogger(__name__)


class FofaSource:
    name = "fofa"

    def is_configured(self) -> bool:
        return bool(settings.keys)

    async def fetch(
        self,
        *,
        budgets: SourceBudgets,
        mode: ScanMode,
        policy: ScanPolicy | None = None,
        skip_direct: bool = False,
        **kwargs: Any,
    ) -> SourceFetchResult:
        if not self.is_configured():
            return SourceFetchResult(source=self.name, errors=("fofa keys not configured",))

        from aipocket.core.db import current_run_id
        from aipocket.services.scanner import _fetch_fofa

        run_id = current_run_id.get() or str(kwargs.get("run_id") or "")
        hits, used, total = await asyncio.to_thread(
            _fetch_fofa, budgets.fofa, skip_direct=skip_direct, run_id=run_id
        )
        for h in hits:
            if isinstance(h, dict):
                h.setdefault("_source", self.name)
        usage = tuple(u if isinstance(u, QueryUsage) else QueryUsage(query=str(u)) for u in used)
        from aipocket.services.candidate_store import spill_enabled

        spilled = spill_enabled() and bool(run_id) and total > 0
        return SourceFetchResult(
            source=self.name,
            host_hits=tuple(hits),
            query_usage=usage,
            host_hit_count=total,
            spilled=spilled,
        )
