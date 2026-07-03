from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import settings
from .models import ScanRunResult, ValidationResult

log = logging.getLogger(__name__)

# Unicode 行/段分隔符：JSON 语法允许其以裸字节出现在字符串里，但 VSCode 的 JSON
# 语言服务会把它们当作行终止符，导致整个文件无法解析（弹窗 "unusual line terminators"）。
# 纯写入时统一替换成普通空格；中文、emoji 等正常字符不受影响。
_UNSAFE_LINE_TERMINATORS = str.maketrans({"\u2028": " ", "\u2029": " "})


def _sanitize_json_text(text: str) -> str:
    return text.translate(_UNSAFE_LINE_TERMINATORS)


def _jsonl_line(obj: Any) -> str:
    """Serialize one object to a sanitized JSONL line (with trailing newline)."""
    return _sanitize_json_text(
        json.dumps(obj, ensure_ascii=False, default=str)
    ) + "\n"


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


# ---------------------------------------------------------------------------
# JSONL writers
# ---------------------------------------------------------------------------


def write_scan_metadata(metadata: dict, run_dir: Path) -> Path:
    """Write first line of scan_<ts>.jsonl — the metadata header."""
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = run_dir / f"scan_{ts}.jsonl"
    path.write_text(_jsonl_line(metadata), encoding="utf-8")
    log.info("Scan metadata written: %s", path)
    return path


def append_scan_result(result: ValidationResult, scan_path: Path) -> None:
    """Append one ValidationResult as a JSONL line."""
    with scan_path.open("a", encoding="utf-8") as f:
        f.write(_jsonl_line(result.model_dump()))


def write_valid_results(results: list[ValidationResult], run_dir: Path) -> Path:
    """Write valid_<ts>.jsonl — each line is one valid result."""
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = run_dir / f"valid_{ts}.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(_jsonl_line(r.model_dump()))
    log.info("Valid results written: %s (count=%d)", path, len(results))
    return path


def write_suspicious_results(results: list[ValidationResult], run_dir: Path) -> Path:
    """Write suspicious_<ts>.jsonl — quarantined results for manual review.

    These passed validation but sit on a host flagged by verify_no_auth
    (forged-key 429 = open-proxy signal, or 200-non-completion = not-a-real-
    gateway). They keep valid=True but are split out of valid_*.jsonl so they
    don't consume balance-enrichment budget or pollute the high-confidence set.
    """
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = run_dir / f"suspicious_{ts}.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(_jsonl_line(r.model_dump()))
    log.info("Suspicious results written: %s (count=%d)", path, len(results))
    return path


def write_raw_hits(hits: list[dict[str, Any]], run_dir: Path | None = None) -> Path:
    """Write raw_hits_<ts>.jsonl — each line is one hit."""
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = run_dir or settings.results_path
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"raw_hits_{ts}.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for hit in hits:
            f.write(_jsonl_line(hit))
    log.info("Raw hits written: %s (total=%d)", path, len(hits))
    return path


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------


def load_latest() -> list[dict] | None:
    """Load the most recent valid_*.jsonl, return list of result dicts.

    Returns None if no valid_*.jsonl is found.
    """
    root = settings.results_path
    runs = sorted(
        (p for p in root.glob("run_*") if p.is_dir()),
        key=lambda p: p.name,
        reverse=True,
    )
    for run in runs:
        for vf in sorted(run.glob("valid_*.jsonl"), reverse=True):
            try:
                lines = vf.read_text(encoding="utf-8").splitlines()
                return [json.loads(line) for line in lines if line.strip()]
            except (ValueError, OSError) as e:
                log.warning("Failed to read %s: %s", vf, e)
    log.warning("No run_*/valid_*.jsonl found under %s", root)
    return None


# ---------------------------------------------------------------------------
# Backward-compat wrapper
# ---------------------------------------------------------------------------


def write_result(result: ScanRunResult, run_dir: Path | None = None) -> Path:
    """Write full scan as JSONL (metadata + results) and valid_*.jsonl.

    Backward-compat entry point: writes metadata as first line, then each
    ValidationResult, and also produces a valid_*.jsonl summary file.
    Returns the scan_*.jsonl path.
    """
    out_dir = run_dir or settings.results_path
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build metadata dict (everything except results and raw_hits)
    metadata = result.model_dump(exclude={"results", "raw_hits"})

    scan_path = write_scan_metadata(metadata, out_dir)

    # Append each result
    for r in result.results:
        append_scan_result(r, scan_path)

    # Write valid-only summary
    valid = [r for r in result.results if r.valid]
    write_valid_results(valid, out_dir)

    return scan_path
