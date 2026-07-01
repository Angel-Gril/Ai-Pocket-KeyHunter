from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import settings
from .models import ScanRunResult

log = logging.getLogger(__name__)

# Unicode 行/段分隔符：JSON 语法允许其以裸字节出现在字符串里，但 VSCode 的 JSON
# 语言服务会把它们当作行终止符，导致整个文件无法解析（弹窗 "unusual line terminators"）。
# 纯写入时统一替换成普通空格；中文、emoji 等正常字符不受影响。
_UNSAFE_LINE_TERMINATORS = str.maketrans({"\u2028": " ", "\u2029": " "})


def _sanitize_json_text(text: str) -> str:
    return text.translate(_UNSAFE_LINE_TERMINATORS)


def _dump_json(obj: Any, *, indent: int = 2) -> str:
    return _sanitize_json_text(
        json.dumps(obj, indent=indent, ensure_ascii=False, default=str)
    )


def _run_dir_name(when: datetime | None = None) -> str:
    """Folder name for one scan run: run_YYYY_MM_DD_HH-MM-SS."""
    ts = (when or datetime.now(UTC)).strftime("%Y_%m_%d_%H-%M-%S")
    return f"run_{ts}"


def new_run_dir(base: Path | None = None) -> Path:
    """Create and return a fresh run directory under results/."""
    root = base or settings.results_path
    d = root / _run_dir_name()
    d.mkdir(parents=True, exist_ok=True)
    log.info("Run directory: %s", d)
    return d


def load_latest() -> dict[str, Any] | None:
    """Load the most recent run's valid result.

    Per-run folders mean there's no shared ``latest_valid.json`` at the root;
    resolve the newest ``run_*/valid_*.json`` instead.
    """
    root = settings.results_path
    runs = sorted(
        (p for p in root.glob("run_*") if p.is_dir()),
        key=lambda p: p.name,
        reverse=True,
    )
    for run in runs:
        for vf in sorted(run.glob("valid_*.json"), reverse=True):
            try:
                return json.loads(vf.read_text(encoding="utf-8"))
            except (ValueError, OSError) as e:
                log.warning("Failed to read %s: %s", vf, e)
    log.warning("No run_*/valid_*.json found under %s", root)
    return None


def write_raw_hits(hits: list[dict[str, Any]], run_dir: Path | None = None) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = run_dir or settings.results_path
    path = out_dir / f"raw_hits_{ts}.json"
    path.write_text(
        _dump_json({"saved_at": ts, "total": len(hits), "hits": hits}),
        encoding="utf-8",
    )
    log.info("Raw hits written: %s (total=%d)", path, len(hits))
    return path


def write_result(result: ScanRunResult, run_dir: Path | None = None) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = run_dir or settings.results_path

    full_path = out_dir / f"scan_{ts}.json"
    valid_path = out_dir / f"valid_{ts}.json"

    full_path.write_text(_sanitize_json_text(result.model_dump_json(indent=2)), encoding="utf-8")
    log.info("Full result written: %s", full_path)

    valid_only = [r.model_dump() for r in result.results if r.valid]
    valid_payload = {
        "scan_time": ts,
        "total_valid": len(valid_only),
        "credentials": valid_only,
    }
    valid_path.write_text(_dump_json(valid_payload), encoding="utf-8")
    log.info("Valid credentials written: %s", valid_path)

    return full_path
