"""Export high-value keys JSONL as preview/highvalue.js for the dashboard HTML.

Loads results/high_value_keys/keys.jsonl (the running append-only log of keys
that passed validation with a usable status — high-signal leaked keys) and
writes preview/highvalue.js as `window.HIGHVALUE_DATA`.

Usage:
    uv run python scripts/gen_highvalue_html.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
INPUT_JSONL = RESULTS_DIR / "high_value_keys" / "keys.jsonl"
OUTPUT_JS = RESULTS_DIR.parent / "preview" / "highvalue.js"


def main() -> None:
    try:
        gen()
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)


def gen(jsonl_path: Path | None = None) -> Path:
    """Generate preview/highvalue.js from keys.jsonl.

    Reads the full append-only log (dedups by apikey, keeping the newest entry
    per key). Returns the output path. Raises FileNotFoundError if the input
    is missing. Designed to be called from cli.py after a scan.
    """
    if jsonl_path is None:
        jsonl_path = INPUT_JSONL
    if not jsonl_path.exists():
        raise FileNotFoundError(f"No high-value keys file at {jsonl_path}")

    # Append-only log → keep the newest record per apikey (last write wins).
    latest_by_key: dict[str, dict] = {}
    for line in jsonl_path.read_text("utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        apikey = entry.get("apikey", "")
        if apikey:
            latest_by_key[apikey] = entry

    entries = list(latest_by_key.values())
    # Newest saved_at first (matches the balance dashboard's recency ordering).
    entries.sort(key=lambda e: e.get("saved_at", ""), reverse=True)

    providers: dict[str, int] = {}
    for e in entries:
        p = e.get("provider") or "unknown"
        providers[p] = providers.get(p, 0) + 1

    data = {
        "total_keys": len(entries),
        "providers": providers,
        "keys": entries,
        "_source_file": jsonl_path.name,
    }

    OUTPUT_JS.parent.mkdir(parents=True, exist_ok=True)
    js_content = f"window.HIGHVALUE_DATA = {json.dumps(data, ensure_ascii=False, indent=2)};\n"
    OUTPUT_JS.write_text(js_content, encoding="utf-8")

    print(f"High-value keys: {len(entries)} unique → {OUTPUT_JS}")
    return OUTPUT_JS


if __name__ == "__main__":
    main()
