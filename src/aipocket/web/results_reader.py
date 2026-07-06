"""Read scan results off disk for the web API.

The CLI's :func:`aipocket.writer.load_latest` only reads the newest run; the web
API needs to browse ALL runs by id, so this module reads the ``results/run_*``
tree directly. It reuses the same on-disk layout the writer produces:

    results/
      run_YYYY_MM_DD_HH-MM-SS/
        valid_*.jsonl        # one ValidationResult.model_dump() per line
        suspicious_*.jsonl   # same shape + suspicious_reason
        run.log              # full execution log

Records are returned as plain dicts (the JSONL shape). Callers mask apikeys via
:mod:`aipocket.web.masking` before returning them to clients.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import settings
from .errors import ApiError
from .masking import mask_apikey

log = logging.getLogger(__name__)

# run_YYYY_MM_DD_HH-MM-SS — anchored so nothing but a real run id validates.
_RUN_ID_RE = re.compile(r"^run_\d{4}_\d{2}_\d{2}_\d{2}-\d{2}-\d{2}$")


def _validate_run_id(run_id: str) -> str:
    """Reject anything that isn't a well-formed run id (blocks path traversal)."""
    if not _RUN_ID_RE.match(run_id):
        raise ApiError(f"invalid run id: {run_id}", status_code=400, code="bad_request")
    return run_id


def _run_dir(run_id: str) -> Path:
    _validate_run_id(run_id)
    d = settings.results_path / run_id
    if not d.is_dir():
        raise ApiError(f"run not found: {run_id}", status_code=404, code="not_found")
    return d


def _day_from_run_id(run_id: str) -> str:
    """`run_2026_07_06_14-35-22` → `2026-07-06`."""
    m = re.match(r"^run_(\d{4})_(\d{2})_(\d{2})_", run_id)
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else "unknown"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                log.warning("skip malformed jsonl line in %s: %s", path.name, line[:80])
    except OSError as e:
        log.warning("failed reading %s: %s", path, e)
    return out


def list_runs() -> list[dict[str, Any]]:
    """All runs, grouped by day (newest first).

    Returns ``[{"day": "2026-07-06", "runs": [{"run_id", "started_at",
    "valid_count", "suspicious_count"}, ...]}, ...]``.
    """
    root = settings.results_path
    if not root.is_dir():
        return []

    runs = sorted(
        (p for p in root.glob("run_*") if p.is_dir() and _RUN_ID_RE.match(p.name)),
        key=lambda p: p.name,
        reverse=True,
    )

    by_day: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        valid_files = list(run.glob("valid_*.jsonl"))
        susp_files = list(run.glob("suspicious_*.jsonl"))
        entry = {
            "run_id": run.name,
            "started_at": _run_id_to_iso(run.name),
            "valid_count": sum(_count_lines(f) for f in valid_files),
            "suspicious_count": sum(_count_lines(f) for f in susp_files),
            "has_log": (run / "run.log").exists(),
        }
        by_day.setdefault(_day_from_run_id(run.name), []).append(entry)

    return [{"day": day, "runs": entries} for day, entries in by_day.items()]


def _run_id_to_iso(run_id: str) -> str:
    m = re.match(r"^run_(\d{4})_(\d{2})_(\d{2})_(\d{2})-(\d{2})-(\d{2})$", run_id)
    if not m:
        return ""
    try:
        dt = datetime(*(int(g) for g in m.groups()))  # type: ignore[arg-type]
        return dt.isoformat()
    except ValueError:
        return ""


def _count_lines(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except OSError:
        return 0


def _load_kind(run_id: str, kind: str) -> list[dict[str, Any]]:
    """Load raw (unmasked) records for a run's ``valid`` or ``suspicious`` file."""
    d = _run_dir(run_id)
    glob = "valid_*.jsonl" if kind == "valid" else "suspicious_*.jsonl"
    records: list[dict[str, Any]] = []
    for f in sorted(d.glob(glob)):
        records.extend(_read_jsonl(f))
    return records


def _mask_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy with the credential apikey masked."""
    out = dict(rec)
    cred = rec.get("credential")
    if isinstance(cred, dict) and cred.get("apikey"):
        masked_cred = dict(cred)
        masked_cred["apikey"] = mask_apikey(cred["apikey"])
        out["credential"] = masked_cred
    return out


def load_run_records(run_id: str, kind: str) -> list[dict[str, Any]]:
    """Masked records for a run's valid/suspicious list (safe to return to client)."""
    return [_mask_record(r) for r in _load_kind(run_id, kind)]


def load_run_records_plain(run_id: str, kind: str) -> list[dict[str, Any]]:
    """Unmasked records — used only by export/reveal, never by list endpoints."""
    return _load_kind(run_id, kind)


def read_run_log(run_id: str) -> str:
    d = _run_dir(run_id)
    log_path = d / "run.log"
    if not log_path.exists():
        raise ApiError(f"no log for run {run_id}", status_code=404, code="not_found")
    try:
        return log_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ApiError(f"failed reading log: {e}", status_code=500, code="internal_error") from e


def reveal_apikey(
    run_id: str,
    kind: str = "valid",
    *,
    masked: str | None = None,
    apiurl: str | None = None,
    index: int | None = None,
) -> dict[str, str]:
    """Re-read the run file to recover ONE plaintext apikey.

    Matching precedence:
    1. ``index`` (0-based line index into the file), if provided;
    2. else ``masked`` (+ optional ``apiurl`` to disambiguate) matched against the
       server-side re-masking of each key.

    Returns ``{"apikey": <plaintext>, "apiurl": ...}``.
    """
    records = _load_kind(run_id, kind)

    if index is not None:
        if index < 0 or index >= len(records):
            raise ApiError("index out of range", status_code=404, code="not_found")
        cred = records[index].get("credential") or {}
        return {"apikey": str(cred.get("apikey", "")), "apiurl": str(cred.get("apiurl", ""))}

    if not masked:
        raise ApiError("provide index or masked", status_code=400, code="bad_request")

    for rec in records:
        cred = rec.get("credential") or {}
        apikey = str(cred.get("apikey", ""))
        if not apikey:
            continue
        if mask_apikey(apikey) != masked:
            continue
        if apiurl is not None and str(cred.get("apiurl", "")) != apiurl:
            continue
        return {"apikey": apikey, "apiurl": str(cred.get("apiurl", ""))}

    raise ApiError("key not found in run", status_code=404, code="not_found")
