"""Export latest balance JSON as preview/data.js for the dashboard HTML."""

from __future__ import annotations

import json
import sys
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
OUTPUT_JS = RESULTS_DIR.parent / "preview" / "data.js"


def find_latest_valid_json() -> Path | None:
    """Find the most recent valid_*.json across all run directories."""
    candidates = sorted(RESULTS_DIR.glob("run_*/valid_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def main():
    json_path = None
    if len(sys.argv) > 1:
        json_path = Path(sys.argv[1])
    else:
        json_path = find_latest_valid_json()

    if not json_path or not json_path.exists():
        print("No valid_*.json found in results/")
        sys.exit(1)

    print(f"Using: {json_path}")

    data = json.loads(json_path.read_text(encoding="utf-8"))
    data["_source_file"] = json_path.name

    OUTPUT_JS.parent.mkdir(parents=True, exist_ok=True)
    js_content = f"window.BALANCE_DATA = {json.dumps(data, ensure_ascii=False, indent=2)};\n"
    OUTPUT_JS.write_text(js_content, encoding="utf-8")

    print(f"Data exported to: {OUTPUT_JS}")


if __name__ == "__main__":
    main()
