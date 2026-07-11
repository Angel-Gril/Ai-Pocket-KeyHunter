"""Run balance enrichment on a saved partial_validated.jsonl — no re-scan needed."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

from aipocket.core.models import ScanRunResult, ValidationResult
from aipocket.services.balance import enrich_results
from aipocket.services.writer import write_result

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


async def main():
    partial_path = (
        Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results/partial_validated.jsonl")
    )
    if not partial_path.exists():
        print(f"File not found: {partial_path}")
        sys.exit(1)

    log.info("Loading partial results from %s ...", partial_path)
    lines = partial_path.read_text(encoding="utf-8").splitlines()
    meta = json.loads(lines[0])
    results = [
        ValidationResult.model_validate(json.loads(line)) for line in lines[1:] if line.strip()
    ]
    valid = [r for r in results if r.valid]
    log.info("Loaded %d results (%d valid)", len(results), len(valid))

    if valid:
        log.info("Querying balance for %d valid credentials...", len(valid))
        results = await enrich_results(results)
        valid = [r for r in results if r.valid]
        log.info("Balance enrichment done. %d still valid after recheck.", len(valid))

    result = ScanRunResult(
        started_at=meta.get("started_at", ""),
        finished_at=datetime.now(UTC).isoformat(),
        sources=meta.get("sources", []),
        hits_by_source=meta.get("hits_by_source", {}),
        total_hosts=meta.get("total_hosts", 0),
        total_credentials=meta.get("total_credentials", len(results)),
        total_valid=len(valid),
        queries_used=meta.get("queries_used", []),
        results=results,
        raw_hits=[],
    )

    path = write_result(result)
    log.info("Final result written to %s", path)
    log.info("=== FINAL: %d creds → %d valid ===", len(results), len(valid))


if __name__ == "__main__":
    asyncio.run(main())
