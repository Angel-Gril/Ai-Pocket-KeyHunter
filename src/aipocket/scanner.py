from __future__ import annotations

import logging
from datetime import UTC, datetime

from .config import settings
from .extractor import extract_credentials
from .fofa_client import FofaClient
from .models import ScanRunResult, ValidationResult
from .queries import build_queries
from .validator import validate_all

log = logging.getLogger(__name__)


async def run_scan(max_queries: int | None = None) -> ScanRunResult:
    started = datetime.now(UTC).isoformat()
    queries = build_queries()
    if max_queries:
        queries = queries[:max_queries]

    log.info("Built %d FOFA queries from CVE map", len(queries))

    all_hits: list[dict] = []
    queries_used: list[str] = []
    with FofaClient() as fofa:
        for i, q in enumerate(queries, 1):
            log.info("[%d/%d] %s | %s", i, len(queries), q["cve_id"], q["query"][:80])
            hits = fofa.search(q["query"], pages=settings.fofa_max_pages)
            if hits:
                for h in hits:
                    if isinstance(h, dict):
                        h.setdefault("_cve", q["cve_id"])
                        h.setdefault("_product", q["product"])
                all_hits.extend(hits)
                queries_used.append(q["query"])
            log.info("  accumulated %d hits", len(all_hits))

    log.info("Total hits: %d. Extracting credentials...", len(all_hits))
    creds = extract_credentials(all_hits)
    log.info("Extracted %d candidate credentials", len(creds))

    if not creds:
        return ScanRunResult(
            started_at=started,
            finished_at=datetime.now(UTC).isoformat(),
            total_hosts=len(all_hits),
            total_credentials=0,
            total_valid=0,
            queries_used=queries_used,
            results=[],
            raw_hits=_trim_hits(all_hits),
        )

    log.info("Validating %d credentials (concurrency=%d)...", len(creds), settings.validate_concurrency)
    results: list[ValidationResult] = await validate_all(creds)
    valid = [r for r in results if r.valid]
    log.info("Validation done: %d valid / %d total", len(valid), len(results))

    return ScanRunResult(
        started_at=started,
        finished_at=datetime.now(UTC).isoformat(),
        total_hosts=len(all_hits),
        total_credentials=len(creds),
        total_valid=len(valid),
        queries_used=queries_used,
        results=results,
        raw_hits=_trim_hits(all_hits),
    )


def _trim_hits(hits: list[dict], limit: int = 500) -> list[dict]:
    if len(hits) <= limit:
        return hits
    return hits[:limit]
