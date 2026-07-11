#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

# How to run:
#   uv run scripts/oneoff/reconcile_high_value.py FINAL_RUN.jsonl [--apply]

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import TypedDict


class Record(TypedDict):
    apikey: str
    valid: bool
    suspicious: bool
    status_code: int


def secret_fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def load_records(path: Path) -> list[Record]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("final_run", type=Path)
    parser.add_argument(
        "--high-value", type=Path, default=Path("results/high_value_keys/keys.jsonl")
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    existing = load_records(args.high_value) if args.high_value.exists() else []
    final = load_records(args.final_run)
    final_fingerprints = {
        secret_fingerprint(record["apikey"])
        for record in final
        if record.get("valid") and not record.get("suspicious") and record.get("status_code") == 200
    }
    stale_fingerprints = sorted(
        secret_fingerprint(record["apikey"])
        for record in existing
        if secret_fingerprint(record["apikey"]) not in final_fingerprints
    )
    print(
        json.dumps(
            {
                "existing": len(existing),
                "final": len(final_fingerprints),
                "stale": stale_fingerprints,
            }
        )
    )

    if args.apply:
        retained = [
            record
            for record in existing
            if secret_fingerprint(record["apikey"]) in final_fingerprints
        ]
        args.high_value.write_text(
            "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in retained),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
