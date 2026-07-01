"""Resume a crashed scan from saved raw_hits — skip FOFA/Shodan fetch.

Usage:
    uv run python scripts/resume_from_rawhits.py [raw_hits_file.json]
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

from aipocket.analyzer import extract_with_gpt, recheck_all_with_gpt
from aipocket.config import settings
from aipocket.extractor import extract_credentials
from aipocket.models import ScanRunResult
from aipocket.scanner import _sample_hits_for_gpt, _trim_hits
from aipocket.validator import validate_all
from aipocket.writer import write_result

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger(__name__)


async def main():
    raw_file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results/raw_hits_20260630T175521Z.json")
    if not raw_file.exists():
        print(f"File not found: {raw_file}")
        sys.exit(1)

    log.info("Loading raw hits from %s ...", raw_file)
    with raw_file.open(encoding="utf-8") as f:
        data = json.load(f)
    all_hits = data["hits"]
    log.info("Loaded %d hits (fofa=%d, shodan=%d)",
             len(all_hits),
             sum(1 for h in all_hits if h.get("_source") == "fofa"),
             sum(1 for h in all_hits if h.get("_source") == "shodan"))

    started = datetime.now(UTC).isoformat()
    sources_used = sorted(set(h.get("_source", "") for h in all_hits if h.get("_source")))
    hits_by_source: dict[str, int] = {}
    for s in sources_used:
        hits_by_source[s] = sum(1 for h in all_hits if h.get("_source") == s)

    # --- Extract (regex) ---
    creds = extract_credentials(all_hits)
    log.info("Extracted %d candidate credentials (regex)", len(creds))

    # --- Extract (GPT) ---
    sampled = _sample_hits_for_gpt(all_hits)
    fofa_s = sum(1 for h in sampled if h.get("_source") == "fofa")
    shodan_s = sum(1 for h in sampled if h.get("_source") == "shodan")
    log.info("GPT sampling: %d hits (fofa=%d, shodan=%d)", len(sampled), fofa_s, shodan_s)

    gpt_creds = await extract_with_gpt(sampled)
    if gpt_creds:
        existing_keys = {(c.apikey, c.apiurl) for c in creds}
        for gc in gpt_creds:
            if (gc.apikey, gc.apiurl) not in existing_keys:
                creds.append(gc)
                existing_keys.add((gc.apikey, gc.apiurl))
        log.info("After GPT enrichment: %d candidate credentials", len(creds))

    if not creds:
        log.error("No credentials extracted — nothing to do.")
        return

    # --- Validate ---
    log.info("Validating %d credentials (concurrency=%d)...", len(creds), settings.validate_concurrency)
    results = await validate_all(creds)

    if settings.gpt_key:
        results = list(await recheck_all_with_gpt(results))

    valid = [r for r in results if r.valid]
    log.info("Validation done: %d valid / %d total", len(valid), len(results))

    # Save partial result before balance (in case balance crashes).
    partial = ScanRunResult(
        started_at=started,
        finished_at=datetime.now(UTC).isoformat(),
        sources=sources_used,
        hits_by_source=hits_by_source,
        total_hosts=len(all_hits),
        total_credentials=len(creds),
        total_valid=len(valid),
        queries_used=[],
        results=results,
        raw_hits=[],
    )
    partial_path = settings.results_path / "partial_validated.json"
    partial_path.write_text(partial.model_dump_json(indent=2), encoding="utf-8")
    log.info("Partial result (pre-balance) saved to %s", partial_path)

    # --- Balance ---
    if valid:
        from aipocket.balance import enrich_results
        log.info("Querying balance for %d valid credentials...", len(valid))
        results = await enrich_results(results)
        valid = [r for r in results if r.valid]
        log.info("Balance enrichment done.")

    # --- Write ---
    result = ScanRunResult(
        started_at=started,
        finished_at=datetime.now(UTC).isoformat(),
        sources=sources_used,
        hits_by_source=hits_by_source,
        total_hosts=len(all_hits),
        total_credentials=len(creds),
        total_valid=len(valid),
        queries_used=[],
        results=results,
        raw_hits=_trim_hits(all_hits),
    )

    path = write_result(result)
    log.info("Result written to %s", path)
    log.info("=== SUMMARY: %d hits → %d creds → %d valid ===", len(all_hits), len(creds), len(valid))


if __name__ == "__main__":
    asyncio.run(main())
