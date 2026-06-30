from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import settings
from .models import ScanRunResult

log = logging.getLogger(__name__)


def load_latest() -> dict[str, Any] | None:
    p = settings.results_path / "latest_valid.json"
    if not p.exists():
        log.warning("No latest_valid.json found at %s", p)
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:
        log.error("Failed to read latest_valid.json: %s", e)
        return None


def write_raw_hits(hits: list[dict[str, Any]]) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = settings.results_path
    path = out_dir / f"raw_hits_{ts}.json"
    path.write_text(
        json.dumps({"saved_at": ts, "total": len(hits), "hits": hits}, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    log.info("Raw hits written: %s (total=%d)", path, len(hits))
    return path


async def write_result(result: ScanRunResult) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = settings.results_path

    full_path = out_dir / f"scan_{ts}.json"
    valid_path = out_dir / f"valid_{ts}.json"

    full_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    log.info("Full result written: %s", full_path)

    valid_only = [r.model_dump() for r in result.results if r.valid]
    valid_payload = {
        "scan_time": ts,
        "total_valid": len(valid_only),
        "credentials": valid_only,
    }
    valid_path.write_text(json.dumps(valid_payload, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Valid credentials written: %s", valid_path)

    _update_latest(out_dir, valid_path, full_path)
    return full_path


def _update_latest(out_dir: Path, valid_path: Path, full_path: Path):
    latest_valid = out_dir / "latest_valid.json"
    latest_full = out_dir / "latest_scan.json"
    try:
        if latest_valid.exists():
            latest_valid.unlink()
        if latest_full.exists():
            latest_full.unlink()
        latest_valid.symlink_to(valid_path.name)
        latest_full.symlink_to(full_path.name)
    except OSError:
        latest_valid.write_text(valid_path.read_text(encoding="utf-8"), encoding="utf-8")
        latest_full.write_text(full_path.read_text(encoding="utf-8"), encoding="utf-8")
