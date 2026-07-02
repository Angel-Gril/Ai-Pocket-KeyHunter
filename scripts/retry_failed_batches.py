"""Retry failed GPT batches from a run directory.

Reads all gpt_failed_batch_*.json files, re-runs GPT extraction,
validates new credentials, and appends valid results to the existing valid_*.json.

Usage:
    uv run python scripts/retry_failed_batches.py <run_dir>
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path


from aipocket.analyzer import extract_with_gpt, set_run_dir
from aipocket.config import settings
from aipocket.extractor import extract_credentials
from aipocket.validator import validate_all

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


async def main():
    if len(sys.argv) < 2:
        print("Usage: uv run python scripts/retry_failed_batches.py <run_dir>")
        sys.exit(1)

    run_dir = Path(sys.argv[1])
    if not run_dir.is_dir():
        print(f"Not a directory: {run_dir}")
        sys.exit(1)

    # --- 1. Find all failed batch files ---
    failed_files = sorted(run_dir.glob("gpt_failed_batch_*.json"))
    if not failed_files:
        print("No gpt_failed_batch_*.json files found — nothing to retry.")
        sys.exit(0)

    log.info("Found %d failed batch files", len(failed_files))

    # --- 2. Extract all hits from failed batches into one list ---
    all_failed_hits: list[dict] = []
    for f in failed_files:
        data = json.loads(f.read_text(encoding="utf-8"))
        hits = data.get("hits", [])
        all_failed_hits.extend(hits)
        log.info("  %s: %d hits (batch_idx=%s)", f.name, len(hits), data.get("batch_idx"))

    log.info("Total failed hits to retry: %d", len(all_failed_hits))

    # --- 3. Save consolidated failed hits file for reference ---
    consolidated_path = run_dir / "retry_failed_hits_consolidated.json"
    consolidated_path.write_text(
        json.dumps(
            {"saved_at": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
             "total": len(all_failed_hits),
             "source_files": [f.name for f in failed_files],
             "hits": all_failed_hits},
            indent=2, ensure_ascii=False, default=str,
        ),
        encoding="utf-8",
    )
    log.info("Consolidated failed hits saved to %s", consolidated_path)

    # --- 4. Find and backup existing valid JSON ---
    valid_files = sorted(run_dir.glob("valid_*.json"))
    if not valid_files:
        print("No valid_*.json found in run dir — cannot append results.")
        sys.exit(1)

    valid_path = valid_files[-1]  # Use the latest one
    backup_path = valid_path.with_suffix(".json.bak")
    shutil.copy2(valid_path, backup_path)
    log.info("Backed up %s → %s", valid_path.name, backup_path.name)

    # --- 5. Run GPT extraction on failed hits ---
    set_run_dir(run_dir)

    # First: regex extraction
    regex_creds = extract_credentials(all_failed_hits)
    log.info("Regex extraction from failed hits: %d credentials", len(regex_creds))

    # Then: GPT extraction
    log.info("Running GPT extraction on %d failed hits...", len(all_failed_hits))
    gpt_creds = await extract_with_gpt(all_failed_hits)
    log.info("GPT extraction: %d new credentials", len(gpt_creds))

    # Merge regex + GPT (deduplicate)
    all_creds = list(regex_creds)
    seen = {(c.apikey, c.apiurl) for c in all_creds}
    for c in gpt_creds:
        if (c.apikey, c.apiurl) not in seen:
            all_creds.append(c)
            seen.add((c.apikey, c.apiurl))

    log.info("Total unique credentials from retry: %d", len(all_creds))

    if not all_creds:
        log.info("No credentials found in retry — valid file unchanged.")
        return

    # --- 6. Validate ---
    log.info("Validating %d credentials (concurrency=%d)...", len(all_creds), settings.validate_concurrency)
    results = await validate_all(all_creds)
    valid_results = [r for r in results if r.valid]
    log.info("Validation done: %d valid / %d total", len(valid_results), len(results))

    if not valid_results:
        log.info("No valid credentials from retry — valid file unchanged.")
        return

    # --- 7. Append to existing valid JSON ---
    existing_data = json.loads(valid_path.read_text(encoding="utf-8"))
    existing_creds = existing_data.get("credentials", [])
    existing_keys = {
        (c["credential"]["apikey"], c["credential"]["apiurl"])
        for c in existing_creds
    }

    new_entries = []
    for r in valid_results:
        entry = r.model_dump()
        key = (entry["credential"]["apikey"], entry["credential"]["apiurl"])
        if key not in existing_keys:
            new_entries.append(entry)
            existing_keys.add(key)

    log.info("New valid credentials to append (after dedup): %d", len(new_entries))

    if not new_entries:
        log.info("All valid results already exist — no changes.")
        return

    existing_creds.extend(new_entries)
    existing_data["credentials"] = existing_creds
    existing_data["total_valid"] = len(existing_creds)

    # Sanitize unicode line terminators (same as writer.py)
    _UNSAFE = str.maketrans({"\u2028": " ", "\u2029": " "})
    output_text = json.dumps(existing_data, indent=2, ensure_ascii=False, default=str)
    output_text = output_text.translate(_UNSAFE)
    valid_path.write_text(output_text, encoding="utf-8")

    log.info("Appended %d new valid credentials to %s (total now: %d)",
             len(new_entries), valid_path.name, existing_data["total_valid"])

    # --- 8. Summary ---
    log.info("=== RETRY SUMMARY ===")
    log.info("  Failed batches retried: %d", len(failed_files))
    log.info("  Total hits re-processed: %d", len(all_failed_hits))
    log.info("  Credentials found: %d", len(all_creds))
    log.info("  Valid after validation: %d", len(valid_results))
    log.info("  New entries appended: %d", len(new_entries))
    log.info("  Backup at: %s", backup_path)


if __name__ == "__main__":
    asyncio.run(main())
