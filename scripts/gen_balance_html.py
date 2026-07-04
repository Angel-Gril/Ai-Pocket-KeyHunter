"""Export latest balance JSONL as preview/data.js for the dashboard HTML.

Loads valid_*.jsonl (and the matching suspicious_*.jsonl from the same run, if
present) and writes preview/data.js as `window.BALANCE_DATA`.

Usage:
    uv run python scripts/gen_balance_html.py [valid_or_run_dir]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
OUTPUT_JS = RESULTS_DIR.parent / "preview" / "data.js"


def find_latest_valid() -> Path | None:
    """Find the most recent valid_*.jsonl across all run directories."""
    candidates = sorted(RESULTS_DIR.glob("run_*/valid_*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def find_latest_valid() -> Path | None:
    """Find the most recent valid_*.jsonl across all run directories."""
    candidates = sorted(RESULTS_DIR.glob("run_*/valid_*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def find_matching_suspicious(valid_path: Path) -> Path | None:
    """Find the suspicious_*.jsonl that pairs with a given valid_*.jsonl.

    Pairs by the shared timestamp stem, e.g. valid_20260704T041501Z.jsonl ↔
    suspicious_20260704T041501Z.jsonl, within the same run directory. Falls back
    to the newest suspicious_*.jsonl in the same dir if the exact pair is absent.
    """
    run_dir = valid_path.parent
    # Exact-pair match: same timestamp token after valid_/suspicious_
    suffix = valid_path.name[len("valid_"):]  # e.g. 20260704T041501Z.jsonl
    pair = run_dir / f"suspicious_{suffix}"
    if pair.exists():
        return pair
    candidates = sorted(run_dir.glob("suspicious_*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def main():
    json_path = None
    if len(sys.argv) > 1:
        arg = Path(sys.argv[1])
        # Accept either a valid_*.jsonl path or a run directory.
        if arg.is_dir():
            cands = sorted(arg.glob("valid_*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
            json_path = cands[0] if cands else None
        else:
            json_path = arg
    else:
        json_path = find_latest_valid()

    if not json_path or not json_path.exists():
        print("No valid_*.jsonl found in results/")
        sys.exit(1)

    print(f"Using valid: {json_path}")

    entries = [json.loads(line) for line in json_path.read_text("utf-8").splitlines() if line.strip()]

    # Load matching suspicious entries (honeypots / quarantined hosts), if any.
    suspicious_entries: list[dict] = []
    suspicious_path = find_matching_suspicious(json_path)
    if suspicious_path and suspicious_path.exists():
        suspicious_entries = [json.loads(line) for line in suspicious_path.read_text("utf-8").splitlines() if line.strip()]
        print(f"Using suspicious: {suspicious_path} ({len(suspicious_entries)} entries)")

    # De-dup by (apikey, apiurl); valid entries win over suspicious.
    seen: set[tuple[str, str]] = set()
    merged: list[dict] = []
    for e in entries:
        c = e.get("credential", {})
        key = (c.get("apikey", ""), c.get("apiurl", ""))
        if key in seen:
            continue
        seen.add(key)
        merged.append(e)
    for e in suspicious_entries:
        c = e.get("credential", {})
        key = (c.get("apikey", ""), c.get("apiurl", ""))
        if key in seen:
            continue
        seen.add(key)
        merged.append(e)

    data = {
        "total_valid": len(entries),
        "total_suspicious": len(suspicious_entries),
        "credentials": merged,
        "_source_file": json_path.name,
        "_suspicious_file": suspicious_path.name if suspicious_path else "",
    }

    OUTPUT_JS.parent.mkdir(parents=True, exist_ok=True)
    js_content = f"window.BALANCE_DATA = {json.dumps(data, ensure_ascii=False, indent=2)};\n"
    OUTPUT_JS.write_text(js_content, encoding="utf-8")

    print(f"Data exported to: {OUTPUT_JS} (valid={len(entries)}, suspicious={len(suspicious_entries)}, merged={len(merged)})")


if __name__ == "__main__":
    main()
