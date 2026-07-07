"""Retry failed GPT batches from a run directory.

Reads all gpt_failed_batch_*.jsonl files, re-runs GPT extraction,
validates new credentials, and appends valid results to the existing valid_*.jsonl.

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


from aipocket.services.analyzer import extract_with_gpt, set_run_dir
from aipocket.core.config import settings
from aipocket.services.extractor import extract_credentials
from aipocket.services.validator import validate_all

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
    failed_files = sorted(run_dir.glob("gpt_failed_batch_*.jsonl"))
    if not failed_files:
        print("No gpt_failed_batch_*.jsonl files found — nothing to retry.")
        sys.exit(0)

    log.info("Found %d failed batch files", len(failed_files))

    # --- 2. Extract all hits from failed batches into one list ---
    all_failed_hits: list[dict] = []
    for f in failed_files:
        lines = f.read_text(encoding="utf-8").splitlines()
        if not lines:
            continue
        meta = json.loads(lines[0])
        hits = [json.loads(l) for l in lines[1:] if l.strip()]
        all_failed_hits.extend(hits)
        log.info("  %s: %d hits (batch_idx=%s)", f.name, len(hits), meta.get("batch_idx"))

    log.info("Total failed hits to retry: %d", len(all_failed_hits))

    # --- 3. Save consolidated failed hits file for reference ---
    consolidated_path = run_dir / "retry_failed_hits_consolidated.jsonl"
    _UNSAFE = str.maketrans({"\u2028": " ", "\u2029": " "})
    with consolidated_path.open("w", encoding="utf-8") as cf:
        meta_line = json.dumps(
            {"saved_at": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
             "total": len(all_failed_hits),
             "source_files": [f.name for f in failed_files]},
            ensure_ascii=False, default=str,
        ).translate(_UNSAFE) + "\n"
        cf.write(meta_line)
        for hit in all_failed_hits:
            cf.write(json.dumps(hit, ensure_ascii=False, default=str).translate(_UNSAFE) + "\n")
    log.info("Consolidated failed hits saved to %s", consolidated_path)

    # --- 4. Find and backup existing valid JSONL ---
    valid_files = sorted(run_dir.glob("valid_*.jsonl"))
    if not valid_files:
        print("No valid_*.jsonl found in run dir — cannot append results.")
        sys.exit(1)

    valid_path = valid_files[-1]  # Use the latest one
    backup_path = valid_path.with_suffix(".jsonl.bak")
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

    # --- 7. Append to existing valid JSONL ---
    existing_entries = [json.loads(line) for line in valid_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    existing_keys = {
        (c["credential"]["apikey"], c["credential"]["apiurl"])
        for c in existing_entries
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

    existing_entries.extend(new_entries)

    # Rewrite as JSONL (one result per line)
    _UNSAFE = str.maketrans({"\u2028": " ", "\u2029": " "})
    output_lines = []
    for entry in existing_entries:
        output_lines.append(json.dumps(entry, ensure_ascii=False, default=str).translate(_UNSAFE) + "\n")
    valid_path.write_text("".join(output_lines), encoding="utf-8")

    log.info("Appended %d new valid credentials to %s (total now: %d)",
             len(new_entries), valid_path.name, len(existing_entries))

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
