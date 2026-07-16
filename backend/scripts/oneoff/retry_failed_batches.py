"""Retry failed GPT batches from a run directory (CLI thin wrapper).

Recovered credentials are **appended** to PostgreSQL (source of truth) via
``aipocket.services.retry_gpt_failed.retry_gpt_failed``. JSONL dual-write only
when configured.

Usage:
    uv run python scripts/oneoff/retry_failed_batches.py <run_dir_or_run_id>

    # Docker
    docker compose exec backend uv run python scripts/oneoff/retry_failed_batches.py \\
      /data/aipocket/results/run_2026_07_15_14-44-29
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

from aipocket.services.retry_gpt_failed import retry_gpt_failed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def _resolve_run_id(arg: str) -> str:
    """Accept either a run id or a path ending in run_YYYY_MM_DD_HH-MM-SS."""
    p = Path(arg)
    if p.is_dir():
        return p.name
    return arg.rstrip("/").rsplit("/", 1)[-1]


async def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: uv run python scripts/oneoff/retry_failed_batches.py <run_dir_or_run_id>")
        sys.exit(1)

    run_id = _resolve_run_id(sys.argv[1])
    try:
        report = await retry_gpt_failed(run_id)
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        log.error("%s", e)
        sys.exit(1)

    log.info("=== RETRY SUMMARY ===")
    log.info("  run_id: %s", report.run_id)
    log.info("  Failed batches: %d", report.failed_files)
    log.info("  Failed hits: %d", report.failed_hits)
    log.info("  Credentials found: %d", report.credentials_found)
    log.info("  Valid appended (DB): %d", report.valid_appended)
    log.info("  Suspicious appended (DB): %d", report.suspicious_appended)
    log.info("  High-value: %d", report.high_value_final)
    log.info("  Archived: %s", ", ".join(report.archived_files) or "(none)")
    log.info("  %s", report.message)


if __name__ == "__main__":
    asyncio.run(main())
